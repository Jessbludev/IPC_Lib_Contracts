/**
 * Cliente IPC - Implementación
 */

#include "ipc/client.hpp"
#include "ipc/security.hpp"
#include <chrono>
#include <thread>

namespace ipc {

/// ID reservado para frames de continuación de un stream.
///
/// El rango 0x0001-0x00FF queda para operaciones de control del runtime
/// (handshake, auth, health, error), igual que en Rust.
constexpr uint16_t CONTINUATION_OPERATION_ID = 0x0000;

// ============================================================================
// SESIÓN DE CONTRATO
// ============================================================================

ContractSession::ContractSession(std::shared_ptr<Contract> contract, ContractRole role, uint64_t session_id)
    : contract_(std::move(contract))
    , role_(role)
    , session_id_(session_id > 0 ? session_id : static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch().count()))
    , listener_(std::make_shared<SessionListener>()) {}

void ContractSession::set_state(SessionState state) {
    auto old_state = state_;
    state_ = state;
    if (listener_) {
        listener_->on_state_changed(old_state, state);
    }
}

uint64_t ContractSession::next_sequence() {
    return ++sequence_;
}

void ContractSession::set_listener(std::shared_ptr<SessionListener> listener) {
    listener_ = std::move(listener);
}

uint32_t ContractSession::create_channel(OperationRole role) {
    std::lock_guard<std::mutex> lock(channels_mutex_);
    auto channel_id = next_channel_id_++;
    auto channel = std::make_shared<Channel>(channel_id);
    channels_[channel_id] = channel;
    if (listener_) {
        listener_->on_channel_opened(channel_id);
    }
    return channel_id;
}

std::shared_ptr<Channel> ContractSession::get_channel(uint32_t channel_id) {
    std::lock_guard<std::mutex> lock(channels_mutex_);
    auto it = channels_.find(channel_id);
    if (it != channels_.end()) {
        return it->second;
    }
    return nullptr;
}

void ContractSession::close_channel(uint32_t channel_id) {
    std::lock_guard<std::mutex> lock(channels_mutex_);
    auto it = channels_.find(channel_id);
    if (it != channels_.end()) {
        it->second->close();
        channels_.erase(it);
        if (listener_) {
            listener_->on_channel_closed(channel_id);
        }
    }
}

void ContractSession::receive_frame(const Frame& frame) {
    if (listener_) {
        listener_->on_frame_received(frame);
    }

    // Responder a llamada pendiente
    std::lock_guard<std::mutex> lock(pending_mutex_);
    auto it = pending_calls_.find(frame.sequence());
    if (it != pending_calls_.end()) {
        if (frame.packet_type() == PacketType::ERROR) {
            int error_code = FrameUtils::get_error_code(frame);
            std::string error_msg = FrameUtils::get_error_message(frame);
            it->second->complete(OperationResult(error_code, error_msg));
        } else {
            it->second->complete(OperationResult(frame.payload()));
        }
        pending_calls_.erase(it);
    }

    // Notificar a canal
    auto channel_id = frame.channel_id();
    if (channel_id > 0) {
        std::lock_guard<std::mutex> lock(channels_mutex_);
        auto it = channels_.find(channel_id);
        if (it != channels_.end()) {
            it->second->send(frame);
        }
    }
}

void ContractSession::close() {
    set_state(SessionState::CLOSING);
    {
        std::lock_guard<std::mutex> lock(channels_mutex_);
        for (auto& [id, channel] : channels_) {
            channel->close();
        }
        channels_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        pending_calls_.clear();
    }
    set_state(SessionState::CLOSED);
}

// ============================================================================
// CLIENTE IPC
// ============================================================================

IpcClient::IpcClient(std::shared_ptr<Transport> transport, std::shared_ptr<Contract> contract,
                     const std::vector<uint8_t>& seed, ExecutionMode mode)
    : transport_(std::move(transport))
    , contract_(std::move(contract))
    , seed_(seed)
    , mode_(mode)
    , session_(std::make_shared<ContractSession>(contract_, contract_->role()))
    , event_listener_(std::make_shared<IpcEventListener>()) {

    // Adaptador: SessionListener define callbacks virtuales, de modo que el
    // cliente implementa una subclase que reenvía al IpcEventListener del
    // llamador. Invocar `on_frame_received(...)` directamente no registraba
    // ningún callback: el cliente nunca habría.notificado nada.
    session_listener_ = std::make_shared<EventForwardingListener>(event_listener_, this);
    session_listener_->on_state_changed(
        static_cast<SessionState>(session_->state()),
        static_cast<SessionState>(session_->state()));
    session_->set_listener(session_listener_);
}

IpcClient::~IpcClient() {
    disconnect();
}

void IpcClient::connect() {
    if (is_running_.load()) return;

    // Iniciar handshake
    session_->set_state(SessionState::HANDSHAKING);

    auto handshake_frame = FrameUtils::create_handshake_frame(contract_->get_contract_hash());
    transport_->send(handshake_frame);

    // Esperar respuesta de handshake
    auto response = transport_->receive();
    if (!FrameUtils::is_valid_handshake(response)) {
        throw ContractException("Invalid handshake response");
    }

    auto [version, session_id] = FrameUtils::parse_handshake_response(response);

    // Validar la versión antes de continuar: ignorarla permitiría hablar un
    // protocolo distinto al acordado durante el resto de la sesión.
    if (version != protocol::PROTOCOL_VERSION) {
        throw ContractException("Handshake version mismatch");
    }
    session_->set_session_id(session_id);

    // Autenticación si es requerida
    if (contract_->security_policy().is_authentication_required()) {
        session_->set_state(SessionState::AUTHENTICATING);

        // Token de autenticación = subclave auth derivada del secreto de
        // sesión (P0.4: mismo dominio que en Rust y Kotlin, así que el token
        // es idéntico en los tres bindings para la misma entrada).
        //
        // `derive_auth_token` no existía en la v2.1: era una llamada a una
        // función que nadie había escrito, de modo que esta ruta nunca pudo
        // compilar ni ejecutarse.
        auto contract_hash = contract_->get_contract_hash();
        ipc::security::KeyDerivation kd(seed_);
        auto auth_token = kd.derive_auth_key(
            kd.derive_session_key(contract_hash, session_->session_id()));

        auto auth_frame = FrameUtils::create_auth_frame(session_->session_id(), auth_token,
                                                         contract_hash);
        transport_->send(auth_frame);
    }

    session_->set_state(SessionState::ACTIVE);
    is_running_.store(true);
    is_connected_.store(true);

    // Iniciar thread de recepción
    receive_thread_ = std::thread([this]() { receive_loop(); });
}

void IpcClient::disconnect() {
    if (!is_running_.load()) return;

    is_running_.store(false);
    is_connected_.store(false);

    session_->close();
    transport_->close();

    if (receive_thread_.joinable()) {
        receive_thread_.join();
    }

    // Limpiar canales de streaming
    std::lock_guard<std::mutex> lock(streaming_mutex_);
    streaming_channels_.clear();

    if (event_listener_) {
        event_listener_->on_disconnect();
    }
}

OperationResult IpcClient::request(OperationId operation_id, const std::vector<uint8_t>& payload) {
    if (!is_connected_.load()) {
        return OperationResult(0x40, "Session not connected");
    }

    auto call = std::make_shared<OperationCall>(operation_id, payload);

    // La secuencia del frame es la que correlaciona request y response: se
    // reserva ANTES de construir el frame y se registra bajo esa misma clave.
    // Reservarla por dentro de add_pending_call() generaba una secuencia
    // distinta y la respuesta nunca habría encontrado su llamada.
    const uint64_t sequence = session_->next_sequence();
    session_->add_pending_call(sequence, call);

    auto frame = Frame(
        session_->session_id(),
        session_->next_sequence(),
        0,
        operation_id,
        PacketType::DATA,
        payload
    );
    frame.set_role(contract_->role());

    transport_->send(frame);

    // Esperar resultado
    return call->wait(30000);  // 30s timeout
}

OperationResult IpcClient::request(const std::string& operation_name, const std::vector<uint8_t>& payload) {
    auto op = contract_->get_operation_by_name(operation_name);
    if (!op) {
        return OperationResult(0x24, "Operation not found: " + operation_name);
    }
    return request(OperationId(op->operation_id), payload);
}

void IpcClient::send_one_way(OperationId operation_id, const std::vector<uint8_t>& payload) {
    if (!is_connected_.load()) return;

    Frame frame(
        session_->session_id(),
        session_->next_sequence(),
        0,
        operation_id,
        PacketType::DATA,
        payload
    );
    frame.set_role(contract_->role());
    frame.mark_as_last_frame();

    transport_->send(frame);
}

uint32_t IpcClient::create_multiplexed_channel() {
    return session_->create_channel(OperationRole::REQUEST_RESPONSE);
}

std::shared_ptr<Channel> IpcClient::get_channel(uint32_t channel_id) {
    return session_->get_channel(channel_id);
}

uint32_t IpcClient::start_streaming(OperationId operation_id) {
    if (mode_ != ExecutionMode::REAL_TIME) {
        throw ContractException("Streaming only available in REAL_TIME mode");
    }

    auto channel_id = session_->create_channel(OperationRole::STREAM_START);
    auto channel = session_->get_channel(channel_id);

    {
        std::lock_guard<std::mutex> lock(streaming_mutex_);
        streaming_channels_[channel_id] = channel;
    }

    // Enviar frame de inicio
    Frame frame(
        session_->session_id(),
        session_->next_sequence(),
        channel_id,
        operation_id,
        PacketType::DATA,
        {}
    );
    frame.set_role(contract_->role());
    auto flags = frame.flags();
    flags.streaming = true;
    frame.set_flags(flags);
    transport_->send(frame);

    return channel_id;
}

void IpcClient::send_to_stream(uint32_t channel_id, const std::vector<uint8_t>& data, bool last_frame) {
    std::lock_guard<std::mutex> lock(streaming_mutex_);
    auto it = streaming_channels_.find(channel_id);
    if (it == streaming_channels_.end()) {
        throw ContractNotFoundException("Stream channel not found");
    }

    Frame frame(
        session_->session_id(),
        session_->next_sequence(),
        channel_id,
        OperationId(CONTINUATION_OPERATION_ID),
        PacketType::DATA,
        data
    );
    frame.set_role(contract_->role());
    auto flags = frame.flags();
    flags.streaming = true;
    flags.last_frame = last_frame;
    frame.set_flags(flags);

    transport_->send(frame);
}

void IpcClient::pause_stream(uint32_t channel_id) {
    std::lock_guard<std::mutex> lock(streaming_mutex_);
    auto it = streaming_channels_.find(channel_id);
    if (it != streaming_channels_.end()) {
        it->second->pause();
    }
}

void IpcClient::resume_stream(uint32_t channel_id) {
    std::lock_guard<std::mutex> lock(streaming_mutex_);
    auto it = streaming_channels_.find(channel_id);
    if (it != streaming_channels_.end()) {
        it->second->resume();
    }
}

void IpcClient::end_stream(uint32_t channel_id) {
    {
        std::lock_guard<std::mutex> lock(streaming_mutex_);
        streaming_channels_.erase(channel_id);
    }
    session_->close_channel(channel_id);
}

bool IpcClient::ping() {
    if (!is_connected_.load()) return false;

    Frame frame(
        session_->session_id(),
        session_->next_sequence(),
        0,
        OperationId::ping(),
        PacketType::HEARTBEAT,
        {}
    );
    frame.set_role(contract_->role());

    transport_->send(frame);
    return true;
}

void IpcClient::set_event_listener(std::shared_ptr<IpcEventListener> listener) {
    event_listener_ = std::move(listener);
}

void IpcClient::receive_loop() {
    while (is_running_.load()) {
        try {
            auto frame = transport_->receive();
            session_->receive_frame(frame);
            handle_incoming_frame(frame);
        } catch (const std::exception& e) {
            if (is_running_.load()) {
                if (event_listener_) {
                    event_listener_->on_error(e);
                }
            }
        }
    }
}

void IpcClient::handle_incoming_frame(const Frame& frame) {
    if (event_listener_) {
        event_listener_->on_frame_received(frame);
    }
}

// ============================================================================
// TRANSPORT PLACEHOLDERS
// ============================================================================

class UnixSocketTransport : public Transport {
public:
    explicit UnixSocketTransport(const std::string& path) : path_(path) {}

    void send(const Frame& frame) override {
        // Placeholder - requiere implementación nativa
        throw ContractException("UnixSocketTransport requires native implementation");
    }

    Frame receive() override {
        throw ContractException("UnixSocketTransport requires native implementation");
    }

    void close() override {
        connected_ = false;
    }

    [[nodiscard]] bool is_connected() const override { return connected_; }

private:
    std::string path_;
    bool connected_ = false;
};

class TcpTransport : public Transport {
public:
    TcpTransport(const std::string& host, uint16_t port) : host_(host), port_(port) {}

    void send(const Frame& frame) override {
        throw ContractException("TcpTransport requires native implementation");
    }

    Frame receive() override {
        throw ContractException("TcpTransport requires native implementation");
    }

    void close() override {
        connected_ = false;
    }

    [[nodiscard]] bool is_connected() const override { return connected_; }

private:
    std::string host_;
    uint16_t port_;
    bool connected_ = false;
};

// ============================================================================
// IpcClientBuilder
// ============================================================================

// BUILDER
// ============================================================================

IpcClientBuilder& IpcClientBuilder::contract(const std::string& path) {
    contract_path_ = path;
    return *this;
}

IpcClientBuilder& IpcClientBuilder::contract(std::shared_ptr<Contract> contract) {
    contract_ = std::move(contract);
    return *this;
}

IpcClientBuilder& IpcClientBuilder::unix_socket(const std::string& path) {
    socket_path_ = path;
    return *this;
}

IpcClientBuilder& IpcClientBuilder::tcp(const std::string& host, uint16_t port) {
    host_ = host;
    port_ = port;
    return *this;
}

IpcClientBuilder& IpcClientBuilder::seed(const std::vector<uint8_t>& seed) {
    seed_ = seed;
    return *this;
}

IpcClientBuilder& IpcClientBuilder::seed(const std::string& seed) {
    seed_ = std::vector<uint8_t>(seed.begin(), seed.end());
    return *this;
}

IpcClientBuilder& IpcClientBuilder::mode(ExecutionMode mode) {
    mode_ = mode;
    return *this;
}

IpcClientBuilder& IpcClientBuilder::event_listener(std::shared_ptr<IpcEventListener> listener) {
    event_listener_ = std::move(listener);
    return *this;
}

std::unique_ptr<IpcClient> IpcClientBuilder::build() {
    auto c = contract_;
    if (!c && !contract_path_.empty()) {
        c = Contract::load(contract_path_);
    }
    if (!c) {
        throw ContractException("Contract is required");
    }

    std::shared_ptr<Transport> transport;
    if (!socket_path_.empty()) {
        transport = std::make_shared<UnixSocketTransport>(socket_path_);
    } else if (!host_.empty() && port_ > 0) {
        transport = std::make_shared<TcpTransport>(host_, port_);
    } else {
        throw ContractException("Transport not configured");
    }

    auto client = std::make_unique<IpcClient>(transport, c, seed_, mode_);
    if (event_listener_) {
        client->set_event_listener(event_listener_);
    }
    return client;
}

// ============================================================================
}  // namespace ipc
