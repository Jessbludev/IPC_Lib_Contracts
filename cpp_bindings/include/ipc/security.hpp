#pragma once

/**
 * Primitivas criptográficas del protocolo CBC.
 *
 * P0.1  BLAKE3-256 es el único digest de identidad de contrato.
 * P0.2  Ed25519 real para firmas de contrato.
 * P0.3  Ventana anti-replay por (session_id, direction), idéntica a Rust.
 * P0.4  Nonce derivado de material secreto con BLAKE3 en modo keyed.
 *
 * Estas primitivas son la referencia de conformidad cross-language: deben
 * producir exactamente los mismos bytes que la implementación Rust.
 */

#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <chrono>
#include <stdexcept>
#include <algorithm>

namespace ipc::security {

// ============================================================================
// CONSTANTES
// ============================================================================

constexpr size_t CHACHA20_KEY_SIZE = 32;
constexpr size_t CHACHA20_NONCE_SIZE = 12;
constexpr size_t AEAD_TAG_SIZE = 16;

constexpr size_t ED25519_PRIVATE_KEY_SIZE = 32;
constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
constexpr size_t ED25519_SIGNATURE_SIZE = 64;

constexpr size_t BLAKE3_HASH_SIZE = 32;
constexpr size_t BLAKE3_KEY_SIZE = 32;

class ContractSecurityException : public std::runtime_error {
public:
    explicit ContractSecurityException(const std::string& what)
        : std::runtime_error(what) {}
};

// ============================================================================
// GENERACIÓN
// ============================================================================

/**
 * Bytes aleatorios criptográficos.
 *
 * NO usar para el nonce de un frame AEAD: la unicidad del nonce viene de
 * `derive_nonce`, ligada a la clave de sesión. Reservar para desafíos de un
 * solo uso (handshake, identificadores de sesión).
 */
std::vector<uint8_t> generate_nonce(size_t size = CHACHA20_NONCE_SIZE);

std::vector<uint8_t> generate_key(size_t size = CHACHA20_KEY_SIZE);

// ============================================================================
// HASHING (P0.1)
// ============================================================================

/** BLAKE3-256. Único digest con el que se calcula `contract_hash`. */
std::vector<uint8_t> blake3_hash(const std::vector<uint8_t>& data);

/** BLAKE3-256 en modo keyed (PRF). */
std::vector<uint8_t> blake3_keyed_hash(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& data);

// ============================================================================
// KEY DERIVATION
// ============================================================================

/**
 * Subclave con separación de dominio.
 *
 * KDF propia sobre BLAKE3 (NO es HKDF):
 *
 *     subkey = BLAKE3_keyed(secret, domain || material || session_id_le)
 */
std::vector<uint8_t> derive_subkey(const std::vector<uint8_t>& secret,
                                   const std::string& domain,
                                   const std::vector<uint8_t>& material,
                                   uint64_t session_id);

class KeyDerivation {
public:
    explicit KeyDerivation(const std::vector<uint8_t>& secret);

    /** Clave dedicada a la derivación de nonces (P0.4). */
    std::vector<uint8_t> derive_nonce_key(
        const std::vector<uint8_t>& contract_hash, uint64_t session_id) const;

    std::vector<uint8_t> derive_session_key(
        const std::vector<uint8_t>& contract_hash, uint64_t session_id) const;

    std::vector<uint8_t> derive_auth_key(
        const std::vector<uint8_t>& session_key) const;

    std::vector<uint8_t> derive_encryption_key(
        const std::vector<uint8_t>& session_key) const;

private:
    std::vector<uint8_t> secret_;
};

// ============================================================================
// NONCE (P0.4)
// ============================================================================

enum class Direction : uint8_t {
    Tx = 0x01,
    Rx = 0x02,
};

/**
 * Nonce AEAD de 96 bits derivado de la clave de sesión.
 *
 *     nonce = BLAKE3_keyed(
 *         key  = nonce_key,
 *         data = "ipc-cbc2-nonce-v1" || direction || session_id_le || sequence_le
 *     )[0..12]
 */
std::array<uint8_t, CHACHA20_NONCE_SIZE> derive_nonce(
    const std::vector<uint8_t>& nonce_key,
    uint64_t session_id,
    uint64_t sequence,
    Direction direction);

// ============================================================================
// AEAD
// ============================================================================

std::vector<uint8_t> encrypt_chacha20poly1305(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& plaintext);

/** Lanza `ContractSecurityException` si el tag no valida. */
std::vector<uint8_t> decrypt_chacha20poly1305(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& ciphertext);

// ============================================================================
// FIRMA Ed25519 (P0.2)
// ============================================================================

struct KeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
};

KeyPair generate_keypair();

std::vector<uint8_t> sign(const std::vector<uint8_t>& data,
                          const std::vector<uint8_t>& private_key);

bool verify_signature(const std::vector<uint8_t>& data,
                      const std::vector<uint8_t>& signature,
                      const std::vector<uint8_t>& public_key);

// ============================================================================
// UTILIDADES
// ============================================================================

bool constant_time_equals(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

std::string to_hex(const std::vector<uint8_t>& data);

// ============================================================================
// ANTI-REPLAY (P0.3)
// ============================================================================

enum class ReplayResult {
    Accepted,
    Replay,
    OutOfWindow,
};

struct SessionDirectionKey {
    uint64_t session_id;
    Direction direction;

    bool operator<(const SessionDirectionKey& other) const {
        if (session_id != other.session_id) return session_id < other.session_id;
        return static_cast<uint8_t>(direction) < static_cast<uint8_t>(other.direction);
    }
};

/**
 * Ventana deslizante de secuencias de una sesión y dirección.
 *
 * Índice 0 = secuencia más alta. Debe comportarse exactamente igual que
 * `ReplayWindow` en Rust (misma máquina de estados, mismos límites).
 */
class ReplayWindow {
public:
    static constexpr size_t MAX_WINDOW = 1u << 20;
    static constexpr size_t MIN_WINDOW = 64;

    explicit ReplayWindow(size_t window_size = 1024);

    static size_t normalize_window(size_t window_size);

    ReplayResult check_and_mark(uint64_t sequence);

    size_t bitmap_size() const { return bitmap_.size(); }
    uint64_t highest() const { return highest_; }
    bool initialized() const { return initialized_; }
    const std::vector<uint64_t>& bitmap() const { return bitmap_; }

    std::chrono::steady_clock::time_point last_activity() const { return last_activity_; }

private:
    void shift_left(size_t shift);
    bool is_bit_set(size_t offset) const;
    void set_bit(size_t offset);

    uint64_t highest_ = 0;
    bool initialized_ = false;
    std::vector<uint64_t> bitmap_;
    std::chrono::steady_clock::time_point last_activity_;
};

class AntiReplay {
public:
    explicit AntiReplay(size_t window_size = 1024);

    ReplayResult check(uint64_t session_id, Direction direction, uint64_t sequence);

    void remove_session(uint64_t session_id);

    void cleanup(uint64_t max_idle_secs);

    size_t active_sessions() const;

    size_t window_size() const { return window_size_; }

private:
    size_t window_size_;
    std::map<SessionDirectionKey, ReplayWindow> windows_;
    mutable std::mutex mutex_;
};

} // namespace ipc::security
