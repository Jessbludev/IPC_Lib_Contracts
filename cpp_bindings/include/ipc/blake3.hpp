#pragma once

/**
 * BLAKE3-256 portable para los bindings C++.
 *
 * P0.1: `contract_hash` de un contrato CBC es BLAKE3-256 en Rust, Kotlin y
 * C++. OpenSSL 3.0 no expone BLAKE3, así que se incluye una implementación
 * propia en lugar de degradar la identidad a SHA-256.
 *
 * Alcance: implementación completa del árbol de sub-chunks, sin límite de
 * tamaño. Las entradas de cualquier tamaño se reducen al mismo árbol canónico
 * de la especificación BLAKE3, incluido el modo keyed.
 */

#include <array>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>

namespace ipc::blake3 {

constexpr size_t OUT_LEN = 32;
constexpr size_t KEY_LEN = 32;

/** Hash BLAKE3-256 sin clave. */
std::array<uint8_t, OUT_LEN> hash(const uint8_t* data, size_t len);
std::array<uint8_t, OUT_LEN> hash(const std::vector<uint8_t>& data);

/**
 * Hash BLAKE3-256 en modo keyed (PRF).
 *
 * Es la primitiva que usan la derivación de claves y la derivación de nonces
 * (P0.4): liga el resultado a un secreto de sesión.
 */
std::array<uint8_t, OUT_LEN> keyed_hash(const uint8_t key[KEY_LEN],
                                        const uint8_t* data,
                                        size_t len);
std::array<uint8_t, OUT_LEN> keyed_hash(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& data);

/**
 * Hasher incremental de BLAKE3.
 *
 * Equivale a `hash()` por construcción, pero acepta los datos troceados. El
 * resultado no depende de cómo se particione la entrada, que es la propiedad
 * que exigen los tests de conformidad: `update(a); update(b)` debe coincidir
 * con `hash(a ++ b)`.
 *
 * Uso:
 * @code
 *     ipc::blake3::Blake3Hasher h;          // sin clave
 *     // ipc::blake3::Blake3Hasher h{true};  // keyed, con clave en key()
 *     h.update(data, len);
 *     auto digest = h.digest();
 * @endcode
 */
class Blake3Hasher {
public:
    /// Hasher sin clave.
    Blake3Hasher();

    /**
     * @param keyed  Si es `true`, el hasher trabaja en modo keyed usando la
     *               clave de 32 bytes establecida con `set_key`.
     */
    explicit Blake3Hasher(bool keyed);

    Blake3Hasher(const Blake3Hasher& other);
    Blake3Hasher& operator=(const Blake3Hasher& other);
    ~Blake3Hasher();

    /// Fijar la clave de 32 bytes del modo keyed. Debe llamarse antes de
    /// `update`. Lanza `std::invalid_argument` si la clave no tiene 32 bytes.
    void set_key(const uint8_t key[KEY_LEN]);
    void set_key(const std::vector<uint8_t>& key);

    /// Volver al estado inicial, conservando el modo keyed.
    void reset();

    /// Absorber más entrada. El hasher se puede llamar tantas veces como haga
    /// falta; el resultado es independiente de la partición.
    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);

    /// Digest final de 32 bytes. No consume el hasher: se puede seguir
    /// absorbiendo después, como en la especificación de BLAKE3.
    std::array<uint8_t, OUT_LEN> finalize() const;
    std::array<uint8_t, OUT_LEN> digest() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ipc::blake3
