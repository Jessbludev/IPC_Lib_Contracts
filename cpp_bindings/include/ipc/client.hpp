#pragma once

/**
 * Cliente IPC para comunicación con procesos Rust/Go/Kotlin
 */

#include "ipc/contract.hpp"
#include <functional>
#include <future>
#include <mutex>
#include <queue>

namespace ipc {

// ============================================================================
// MODOS DE EJECUCIÓN
// ============================================================================

enum class ExecutionMode {
    MESSAGE_RESPONSE,   // Solicitud espera acción, sesión activa
    MULTIPLEXING,       // Varias comunicaciones del mismo estado
    FIRE_AND_FORGET,    // Realiza acción y olvida
    REAL_TIME           // Conexión constante para streaming
};

// ============================================================================
// RESULTADO DE OPERACIÓN
// ============================================================================

class OperationResult {
public:
    enum class Type { SUCCESS, ERROR, TIMEOUT, STREAM_FRAME };

    OperationResult() : type_(Type::SUCCESS), data_() {}
    explicit OperationResult(Type type) : type_(type), data_() {}
    explicit OperationResult(std::vector<uint8_t> data) : type_(Type::SUCCESS), data_(std::move(data)) {}
    explicit OperationResult(int error_code, std::string message)
        : type_(Type::ERROR), error_code_(error_code), error_message_(std::move(message)) {}

    [[nodiscard]] Type type() const { return type_; }
    [[nodiscard]] bool is_success() const { return type_ == Type::SUCCESS; }
    [[nodiscard]] bool is_error() const { return type_ == Type::ERROR; }
    [[nodiscard]] bool is_timeout() const { return type_ == Type::TIMEOUT; }

    [[nodiscard]] const std::vector<uint8_t>& data() const { return data_; }
    [[nodiscard]] int error_code() const { return error_code_; }
    [[nodiscard]] const std::string& error_message() const { return error_message_; }

    static OperationResult timeout() { return OperationResult(Type::TIMEOUT); }

private:
    Type type_;
    std::vector<uint8_t> data_;
    int error_code_ = 0;
    std::string error_message_;
};

// ============================================================================
// ESTADOS DE SESIÓN
// ============================================================================

enum class SessionState {
    INIT,
    HANDSHAKING,
    AUTHENTICATING,
    ACTIVE,
    PAUSED,
    CLOSING,
    CLOSED,
    ERROR
};

// ============================================================================
// CALL DE OPERACIÓN
// ============================================================================

class OperationCall {
public:
    OperationCall(OperationId operation_id, std::vector<uint8_t> payload, uint32_t channel_id = 0)
        : operation_id_(operation_id), payload_(std::move(payload)), channel_id_(channel_id) {}

    [[nodiscard]] OperationId operation_id() const { return operation_id_; }
    [[nodiscard]] const std::vector<uint8_t>& payload() const { return payload_; }
    [[nodiscard]] uint32_t channel_id() const { return channel_id_; }

    void complete(OperationResult result) {
        std::lock_guard<std::mutex> lock(mutex_);
        result_ = std::move(result);
        cv_.notify_all();
    }

    /**
     * Esperar el resultado de la llamada.
     *
     * Lanza `std::runtime_error` si se agota el timeout sin resultado: un
     * `OperationResult` vacío habría hecho que el llamante creyera que la
     * operación devolvió éxito con payload vacío.
     */
    [[nodiscard]] OperationResult wait(uint64_t timeout_ms) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (timeout_ms > 0) {
            if (!cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                              [this] { return result_.has_value(); })) {
                throw std::runtime_error("timeout esperando el resultado de la operacion");
            }
        } else {
            cv_.wait(lock, [this] { return result_.has_value(); });
        }
        return result_.value();
    }

    [[nodiscard]] bool is_completed() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return result_.has_value();
    }

private:
    OperationId operation_id_;
    std::vector<uint8_t> payload_;
    uint32_t channel_id_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::optional<OperationResult> result_;
};

// ============================================================================
// LISTENER DE SESIÓN
// ============================================================================

class SessionListener {
public:
    virtual ~SessionListener() = default;
    virtual void on_state_changed(SessionState old_state, SessionState new_state) {}
    virtual void on_error(const std::exception& error) {}
    virtual void on_frame_received(const Frame& frame) {}
    virtual void on_frame_sent(const Frame& frame) {}
    virtual void on_channel_opened(uint32_t channel_id) {}
    virtual void on_channel_closed(uint32_t channel_id) {}
};

// ============================================================================
// CANAL
// ============================================================================

class Channel {
public:
    explicit Channel(uint32_t id) : id_(id), is_open_(true), is_paused_(false) {}

    [[nodiscard]] uint32_t id() const { return id_; }
    [[nodiscard]] bool is_open() const { return is_open_; }
    [[nodiscard]] bool is_paused() const { return is_paused_; }

    void send(const Frame& frame) {
        if (!is_open_) throw ContractException("Channel is closed");
        std::lock_guard<std::mutex> lock(queue_mutex_);
        frame_queue_.push(frame);
    }

    bool receive(Frame& frame, uint64_t timeout_ms = 0) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        if (timeout_ms > 0) {
            return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                              [this] { return !frame_queue_.empty(); }) &&
                   !frame_queue_.empty();
        }
        if (frame_queue_.empty()) return false;
        frame = frame_queue_.front();
        frame_queue_.pop();
        return true;
    }

    void pause() { is_paused_ = true; }
    void resume() { is_paused_ = false; }
    void close() { is_open_ = false; cv_.notify_all(); }

private:
    uint32_t id_;
    bool is_open_;
    bool is_paused_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::queue<Frame> frame_queue_;
};

// ============================================================================
// SESIÓN DE CONTRATO
// ============================================================================

class ContractSession {
public:
    ContractSession(std::shared_ptr<Contract> contract, ContractRole role, uint64_t session_id = 0);

    [[nodiscard]] SessionState state() const { return state_; }
    [[nodiscard]] uint64_t session_id() const { return session_id_; }

    /// Adoptar el session_id negociado por el servidor.
    ///
    /// El servidor es quien asigna la identidad de sesión durante el
    /// handshake. Sin esto, el cliente seguía usando la suya y las respuestas
    /// se correlacionarían contra un id que el servidor nunca vio.
    void set_session_id(uint64_t session_id) { session_id_ = session_id; }
    [[nodiscard]] std::shared_ptr<Contract> contract() const { return contract_; }

    void set_state(SessionState state);
    [[nodiscard]] uint64_t next_sequence();

    void set_listener(std::shared_ptr<SessionListener> listener);

    [[nodiscard]] uint32_t create_channel(OperationRole role = OperationRole::REQUEST_RESPONSE);
    [[nodiscard]] std::shared_ptr<Channel> get_channel(uint32_t channel_id);
    void close_channel(uint32_t channel_id);

    void receive_frame(const Frame& frame);

    void close();

    // -----------------------------------------------------------------------
    // Llamadas pendientes
    // -----------------------------------------------------------------------

    /// Registrar una llamada en vuelo, indexada por su número de secuencia.
    ///
    /// API pública: el mapa interno está protegido por mutex y no debe
    /// tocarse desde fuera de la sesión.
    void add_pending_call(uint64_t sequence, std::shared_ptr<OperationCall> call) {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_calls_[sequence] = std::move(call);
    }

    /// Resolver una llamada pendiente con el frame de respuesta.
    ///
    /// Devuelve `false` si no había ninguna llamada para esa secuencia, lo que
    /// ocurre con respuestas tardías o con frames manipulados.
    bool complete_pending_call(uint64_t sequence, OperationResult result) {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        auto it = pending_calls_.find(sequence);
        if (it == pending_calls_.end()) {
            return false;
        }
        if (it->second) {
            it->second->complete(std::move(result));
        }
        pending_calls_.erase(it);
        return true;
    }

private:
    std::shared_ptr<Contract> contract_;
    ContractRole role_;
    uint64_t session_id_;
    uint64_t sequence_ = 0;
    SessionState state_ = SessionState::INIT;

    std::shared_ptr<SessionListener> listener_;
    std::mutex channels_mutex_;
    std::map<uint32_t, std::shared_ptr<Channel>> channels_;
    uint32_t next_channel_id_ = 1;

    std::mutex pending_mutex_;
    std::map<uint64_t, std::shared_ptr<OperationCall>> pending_calls_;
};

// ============================================================================
// TRANSPORT
// ============================================================================

class Transport {
public:
    virtual ~Transport() = default;
    virtual void send(const Frame& frame) = 0;
    virtual Frame receive() = 0;
    virtual void close() = 0;
    [[nodiscard]] virtual bool is_connected() const = 0;
};

// ============================================================================
// LISTENER DE EVENTOS
// ============================================================================

/**
 * Punto de extensión para quien usa la librería.
 *
 * Ningún método imprime ni registra nada: la política zero-log deja la
 * observabilidad en manos de la aplicación anfitriona.
 */
class IpcEventListener {
public:
    virtual ~IpcEventListener() = default;
    virtual void on_frame_received(const Frame& frame) {}
    virtual void on_frame_sent(const Frame& frame) {}
    virtual void on_error(const std::exception& error) {}
    virtual void on_state_changed(SessionState old_state, SessionState new_state) {}
    virtual void on_channel_opened(uint32_t channel_id) {}
    virtual void on_channel_closed(uint32_t channel_id) {}
    virtual void on_disconnect() {}
    virtual void on_reconnect() {}
};

// ============================================================================
// CLIENTE IPC
// ============================================================================

class IpcClient {
public:
    IpcClient(std::shared_ptr<Transport> transport, std::shared_ptr<Contract> contract,
              const std::vector<uint8_t>& seed, ExecutionMode mode = ExecutionMode::MESSAGE_RESPONSE);
    ~IpcClient();

    // No copying
    IpcClient(const IpcClient&) = delete;
    IpcClient& operator=(const IpcClient&) = delete;

    // Conexión
    void connect();
    void disconnect();

    // Operaciones
    [[nodiscard]] OperationResult request(OperationId operation_id, const std::vector<uint8_t>& payload);
    [[nodiscard]] OperationResult request(const std::string& operation_name, const std::vector<uint8_t>& payload);

    template<typename T>
    [[nodiscard]] OperationResult request_serialized(const std::string& operation_name, const T& data);

    void send_one_way(OperationId operation_id, const std::vector<uint8_t>& payload);

    // Multiplexing
    [[nodiscard]] uint32_t create_multiplexed_channel();
    [[nodiscard]] std::shared_ptr<Channel> get_channel(uint32_t channel_id);

    // Real-time streaming
    [[nodiscard]] uint32_t start_streaming(OperationId operation_id);
    void send_to_stream(uint32_t channel_id, const std::vector<uint8_t>& data, bool last_frame = false);
    void pause_stream(uint32_t channel_id);
    void resume_stream(uint32_t channel_id);
    void end_stream(uint32_t channel_id);

    // Estado
    [[nodiscard]] bool is_connected() const { return is_connected_; }
    [[nodiscard]] std::shared_ptr<ContractSession> session() const { return session_; }

    // Heartbeat
    bool ping();

    // Listener
    void set_event_listener(std::shared_ptr<IpcEventListener> listener);

    /// Procesar un frame entrante. Público para que el adaptador de eventos
    /// pueda reenviarlo sin friendship.
    void handle_incoming_frame(const Frame& frame);

private:
    void receive_loop();

    std::shared_ptr<Transport> transport_;
    std::shared_ptr<Contract> contract_;
    std::vector<uint8_t> seed_;
    ExecutionMode mode_;

    std::shared_ptr<ContractSession> session_;
    std::shared_ptr<SessionListener> session_listener_;
    std::shared_ptr<IpcEventListener> event_listener_;

    std::atomic<bool> is_running_{false};
    std::atomic<bool> is_connected_{false};
    std::thread receive_thread_;

    std::mutex streaming_mutex_;
    std::map<uint32_t, std::shared_ptr<Channel>> streaming_channels_;
};

// ============================================================================
// BUILDER
// ============================================================================

// ============================================================================
// ADAPTADOR DE LISTENER
// ============================================================================

/**
 * Reenvía los eventos de la sesión al `IpcEventListener` del cliente.
 *
 * `SessionListener` expone callbacks virtuales, no un registro de funciones.
 * Esta clase es la que conecta realmente ambos, y aplica la política
 * zero-log: no imprime nada ante un error, sólo lo propaga al oyente.
 */
class EventForwardingListener : public SessionListener {
public:
    EventForwardingListener(std::shared_ptr<IpcEventListener> sink, IpcClient* client)
        : sink_(std::move(sink)), client_(client) {}

    void on_state_changed(SessionState old_state, SessionState new_state) override {
        if (sink_) sink_->on_state_changed(old_state, new_state);
    }

    void on_error(const std::exception& error) override {
        if (sink_) sink_->on_error(error);
    }

    void on_frame_received(const Frame& frame) override {
        if (client_) client_->handle_incoming_frame(frame);
        if (sink_) sink_->on_frame_received(frame);
    }

    void on_frame_sent(const Frame& frame) override {
        if (sink_) sink_->on_frame_sent(frame);
    }

    void on_channel_opened(uint32_t channel_id) override {
        if (sink_) sink_->on_channel_opened(channel_id);
    }

    void on_channel_closed(uint32_t channel_id) override {
        if (sink_) sink_->on_channel_closed(channel_id);
    }

private:
    std::shared_ptr<IpcEventListener> sink_;
    IpcClient* client_ = nullptr;
};

class IpcClientBuilder {
public:
    IpcClientBuilder& contract(const std::string& path);
    IpcClientBuilder& contract(std::shared_ptr<Contract> contract);
    IpcClientBuilder& unix_socket(const std::string& path);
    IpcClientBuilder& tcp(const std::string& host, uint16_t port);
    IpcClientBuilder& seed(const std::vector<uint8_t>& seed);
    IpcClientBuilder& seed(const std::string& seed);
    IpcClientBuilder& mode(ExecutionMode mode);
    IpcClientBuilder& event_listener(std::shared_ptr<IpcEventListener> listener);

    [[nodiscard]] std::unique_ptr<IpcClient> build();

private:
    std::string contract_path_;
    std::shared_ptr<Contract> contract_;
    std::string socket_path_;
    std::string host_;
    uint16_t port_ = 0;
    std::vector<uint8_t> seed_;
    ExecutionMode mode_ = ExecutionMode::MESSAGE_RESPONSE;
    std::shared_ptr<IpcEventListener> event_listener_;
};

}  // namespace ipc
