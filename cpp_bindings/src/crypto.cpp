/**
 * Primitivas criptográficas del binding C++.
 *
 * P0.1 / P0.2 / P0.3 / P0.4:
 *  - BLAKE3-256 como único digest de identidad de contrato.
 *  - Ed25519 real para firmas (antes: `public_key = SHA256(private_key)` y
 *    firma = HMAC, que no es una firma).
 *  - Ventana anti-replay por (session_id, direction), idéntica a Rust.
 *  - Nonce derivado de un secreto de sesión con BLAKE3 en modo keyed.
 *
 * Estas funciones son la referencia de conformidad: `conformance_test.cpp`
 * verifica que producen exactamente los mismos bytes que la implementación
 * Rust para las mismas entradas.
 */

#include "ipc/security.hpp"
#include "ipc/blake3.hpp"

#include <cstring>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <mutex>
#include <array>
#include <chrono>
#include <algorithm>

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#else
#error "Los bindings C++ requieren OpenSSL 3.0+ (USE_OPENSSL) para Ed25519 y ChaCha20-Poly1305"
#endif

namespace ipc::security {

namespace {

constexpr size_t ED25519_KEY_LEN = 32;
constexpr size_t ED25519_SIG_LEN = 64;

/// Bytes aleatorios criptográficos
std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> out(n);
    if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
        throw ContractSecurityException("fallo de la CSPRNG del sistema");
    }
    return out;
}

} // namespace

// ============================================================================
// GENERACIÓN
// ============================================================================

std::vector<uint8_t> generate_nonce(size_t size) {
    // Los nonces de frame NO deben generarse así: la unicidad viene de la
    // derivación con material de sesión (ver `derive_nonce`). Esta función
    // queda para nonces de un solo uso (desafíos de handshake), no para AEAD.
    return random_bytes(size);
}

std::vector<uint8_t> generate_key(size_t size) {
    return random_bytes(size);
}

// ============================================================================
// HASHING
// ============================================================================

std::vector<uint8_t> blake3_hash(const std::vector<uint8_t>& data) {
    const auto digest = ipc::blake3::hash(data);
    return std::vector<uint8_t>(digest.begin(), digest.end());
}

std::vector<uint8_t> blake3_keyed_hash(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& data) {
    const auto digest = ipc::blake3::keyed_hash(key, data);
    return std::vector<uint8_t>(digest.begin(), digest.end());
}

// ============================================================================
// KEY DERIVATION
// ============================================================================
//
// KDF propia sobre BLAKE3 con separación de dominio. NO es HKDF y no se
// documenta como tal (revisión previa, punto 11).
//
// La derivación debe producir los mismos bytes que `KeyDerivation` en Rust:
//
//     subkey = BLAKE3_keyed(secret, domain || material || session_id_le)
//
// donde `domain` es uno de los contextos de la tabla siguiente.

std::vector<uint8_t> derive_subkey(const std::vector<uint8_t>& secret,
                                   const std::string& domain,
                                   const std::vector<uint8_t>& material,
                                   uint64_t session_id) {
    if (secret.size() != 32) {
        throw ContractSecurityException("el secreto raíz debe tener 32 bytes");
    }

    std::vector<uint8_t> ctx;
    ctx.reserve(domain.size() + material.size() + 8);
    ctx.insert(ctx.end(), domain.begin(), domain.end());
    ctx.insert(ctx.end(), material.begin(), material.end());
    for (int i = 0; i < 8; ++i) {
        ctx.push_back(static_cast<uint8_t>((session_id >> (8 * i)) & 0xFF));
    }

    return blake3_keyed_hash(secret, ctx);
}

KeyDerivation::KeyDerivation(const std::vector<uint8_t>& secret) {
    if (secret.size() != 32) {
        throw ContractSecurityException("el secreto raíz debe tener 32 bytes");
    }
    secret_ = secret;
}

std::vector<uint8_t> KeyDerivation::derive_nonce_key(
    const std::vector<uint8_t>& contract_hash, uint64_t session_id) const {
    return derive_subkey(secret_, "ipc-cbc2-nonce-key-v1", contract_hash, session_id);
}

std::vector<uint8_t> KeyDerivation::derive_session_key(
    const std::vector<uint8_t>& contract_hash, uint64_t session_id) const {
    return derive_subkey(secret_, "ipc-cbc2-session-v1", contract_hash, session_id);
}

std::vector<uint8_t> KeyDerivation::derive_auth_key(
    const std::vector<uint8_t>& session_key) const {
    return derive_subkey(secret_, "ipc-cbc2-auth-v1", session_key, 0);
}

std::vector<uint8_t> KeyDerivation::derive_encryption_key(
    const std::vector<uint8_t>& session_key) const {
    return derive_subkey(secret_, "ipc-cbc2-encrypt-v1", session_key, 0);
}

// ============================================================================
// NONCE (P0.4)
// ============================================================================
//
//     nonce = BLAKE3_keyed(
//         key  = nonce_key,
//         data = "ipc-cbc2-nonce-v1" || direction || session_id_le || sequence_le
//     )[0..12]
//
// La versión anterior de v2.1 usaba
// `BLAKE3("CBC2-NONCE" || session_id || sequence || direction)`, sin ningún
// secreto, y los tres bindings generaban además nonces aleatorios por frame.
// Ahora el nonce es una PRF ligada a la clave de sesión.

std::array<uint8_t, 12> derive_nonce(const std::vector<uint8_t>& nonce_key,
                                    uint64_t session_id,
                                    uint64_t sequence,
                                    Direction direction) {
    if (nonce_key.size() != 32) {
        throw ContractSecurityException("la clave de nonce debe tener 32 bytes");
    }

    std::vector<uint8_t> data;
    const char* domain = "ipc-cbc2-nonce-v1";
    data.insert(data.end(), domain, domain + std::strlen(domain));
    data.push_back(static_cast<uint8_t>(direction));
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>((session_id >> (8 * i)) & 0xFF));
    }
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>((sequence >> (8 * i)) & 0xFF));
    }

    const auto digest = ipc::blake3::keyed_hash(nonce_key.data(), data.data(), data.size());
    std::array<uint8_t, 12> out{};
    std::copy_n(digest.begin(), 12, out.begin());
    return out;
}

// ============================================================================
// AEAD: ChaCha20-Poly1305
// ============================================================================

std::vector<uint8_t> encrypt_chacha20poly1305(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& plaintext) {

    if (key.size() != 32) {
        throw ContractSecurityException("la clave ChaCha20 debe tener 32 bytes");
    }
    if (nonce.size() != 12) {
        throw ContractSecurityException("el nonce debe tener 12 bytes");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw ContractSecurityException("no se pudo crear el contexto AEAD");

    struct Guard {
        EVP_CIPHER_CTX* c;
        ~Guard() { if (c) EVP_CIPHER_CTX_free(c); }
    } guard{ctx};

    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr)) {
        throw ContractSecurityException("fallo al inicializar ChaCha20-Poly1305");
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                 static_cast<int>(nonce.size()), nullptr)) {
        throw ContractSecurityException("no se pudo fijar la longitud del nonce");
    }
    if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data())) {
        throw ContractSecurityException("fallo al inicializar la clave");
    }

    int len = 0;
    std::vector<uint8_t> out(plaintext.size() + 16);
    if (!aad.empty()) {
        if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                                   static_cast<int>(aad.size()))) {
            throw ContractSecurityException("fallo al procesar el AAD");
        }
    }
    if (!plaintext.empty()) {
        if (1 != EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(),
                                   static_cast<int>(plaintext.size()))) {
            throw ContractSecurityException("fallo al cifrar");
        }
    }
    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, out.data() + len, &final_len)) {
        throw ContractSecurityException("fallo al finalizar el cifrado");
    }

    out.resize(static_cast<size_t>(len + final_len + 16));
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                 out.data() + len + final_len)) {
        throw ContractSecurityException("fallo al obtener el tag");
    }
    return out;
}

std::vector<uint8_t> decrypt_chacha20poly1305(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& ciphertext) {

    if (key.size() != 32) {
        throw ContractSecurityException("la clave ChaCha20 debe tener 32 bytes");
    }
    if (nonce.size() != 12) {
        throw ContractSecurityException("el nonce debe tener 12 bytes");
    }
    constexpr size_t TAG_LEN = 16;
    if (ciphertext.size() < TAG_LEN) {
        throw ContractSecurityException("el ciphertext es menor que el tag");
    }

    const size_t ct_len = ciphertext.size() - TAG_LEN;
    std::vector<uint8_t> tag(ciphertext.begin() + static_cast<long>(ct_len),
                             ciphertext.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw ContractSecurityException("no se pudo crear el contexto AEAD");
    struct Guard {
        EVP_CIPHER_CTX* c;
        ~Guard() { if (c) EVP_CIPHER_CTX_free(c); }
    } guard{ctx};

    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr)) {
        throw ContractSecurityException("fallo al inicializar ChaCha20-Poly1305");
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                 static_cast<int>(nonce.size()), nullptr)) {
        throw ContractSecurityException("no se pudo fijar la longitud del nonce");
    }
    if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data())) {
        throw ContractSecurityException("fallo al inicializar la clave");
    }

    int len = 0;
    if (!aad.empty()) {
        if (1 != EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                                   static_cast<int>(aad.size()))) {
            throw ContractSecurityException("fallo al procesar el AAD");
        }
    }

    std::vector<uint8_t> out(ct_len);
    if (ct_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext.data(),
                                   static_cast<int>(ct_len))) {
            throw ContractSecurityException("fallo al descifrar");
        }
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(TAG_LEN),
                                 tag.data())) {
        throw ContractSecurityException("fallo al fijar el tag");
    }

    int final_len = 0;
    // Devuelve 0 si el tag no valida: es exactamente el caso de autenticación
    // fallida, y se traduce en excepción sin revelar el motivo al exterior.
    if (1 != EVP_DecryptFinal_ex(ctx, out.data() + len, &final_len)) {
        throw ContractSecurityException("autenticación AEAD fallida");
    }
    out.resize(static_cast<size_t>(len + final_len));
    return out;
}

// ============================================================================
// FIRMA Ed25519 (P0.2)
// ============================================================================

KeyPair generate_keypair() {
    // Ed25519 real. La versión anterior usaba
    // `public_key = sha256(private_key)`, que no es una clave pública válida y
    // hacía que la "firma" fuera verificable por cualquiera que conociera la
    // clave privada.
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) throw ContractSecurityException("no se pudo crear EVP_PKEY");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw ContractSecurityException("no se pudo crear el contexto de clave");
    }

    KeyPair pair;
    try {
        if (1 != EVP_PKEY_keygen_init(ctx)) {
            throw ContractSecurityException("fallo al inicializar la generación");
        }
        if (1 != EVP_PKEY_keygen(ctx, &pkey)) {
            throw ContractSecurityException("fallo al generar el par Ed25519");
        }

        size_t len = ED25519_KEY_LEN;
        pair.private_key.resize(len);
        if (1 != EVP_PKEY_get_raw_private_key(pkey, pair.private_key.data(), &len)) {
            throw ContractSecurityException("no se pudo exportar la clave privada");
        }

        len = ED25519_KEY_LEN;
        pair.public_key.resize(len);
        if (1 != EVP_PKEY_get_raw_public_key(pkey, pair.public_key.data(), &len)) {
            throw ContractSecurityException("no se pudo exportar la clave pública");
        }
    } catch (...) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return pair;
}

std::vector<uint8_t> sign(const std::vector<uint8_t>& data,
                          const std::vector<uint8_t>& private_key) {
    if (private_key.size() != ED25519_KEY_LEN) {
        throw ContractSecurityException("la clave privada Ed25519 debe tener 32 bytes");
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size());
    if (!pkey) throw ContractSecurityException("clave privada Ed25519 inválida");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw ContractSecurityException("no se pudo crear el contexto de firma");
    }

    std::vector<uint8_t> sig(ED25519_SIG_LEN);
    size_t sig_len = sig.size();
    bool ok = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
              EVP_DigestSign(ctx, sig.data(), &sig_len, data.data(), data.size()) == 1;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (!ok) throw ContractSecurityException("fallo al firmar");
    sig.resize(sig_len);
    return sig;
}

bool verify_signature(const std::vector<uint8_t>& data,
                      const std::vector<uint8_t>& signature,
                      const std::vector<uint8_t>& public_key) {
    if (public_key.size() != ED25519_KEY_LEN || signature.size() != ED25519_SIG_LEN) {
        return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
              EVP_DigestVerify(ctx, signature.data(), signature.size(),
                               data.data(), data.size()) == 1;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// ============================================================================
// UTILIDADES
// ============================================================================

bool constant_time_equals(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

std::string to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// ============================================================================
// ANTI-REPLAY (P0.3)
// ============================================================================
//
// Máquina de estados idéntica a la de Rust, indexada por
// (session_id, direction). La versión anterior de v2.1 mantenía un
// `unordered_set` de nonces vistos que crecía sin límite y colapsaba el
// nonce de 96 bits a 64.

ReplayWindow::ReplayWindow(size_t window_size) {
    size_t words = (normalize_window(window_size) + 63) / 64;
    highest_ = 0;
    initialized_ = false;
    bitmap_.assign(words, 0);
    last_activity_ = std::chrono::steady_clock::now();
}

size_t ReplayWindow::normalize_window(size_t window_size) {
    constexpr size_t MIN_WINDOW = 64;
    constexpr size_t MAX_WINDOW = 1u << 20;
    return std::clamp(window_size, MIN_WINDOW, MAX_WINDOW);
}

void ReplayWindow::shift_left(size_t shift) {
    const size_t word_shift = shift / 64;
    const size_t bit_shift = shift % 64;

    if (word_shift >= bitmap_.size()) {
        std::fill(bitmap_.begin(), bitmap_.end(), uint64_t{0});
        return;
    }

    for (size_t i = bitmap_.size(); i-- > 0;) {
        uint64_t v = bitmap_[i - word_shift] << bit_shift;
        if (bit_shift > 0 && i > word_shift) {
            v |= bitmap_[i - word_shift - 1] >> (64 - bit_shift);
        }
        bitmap_[i] = v;
    }
}

bool ReplayWindow::is_bit_set(size_t offset) const {
    const size_t word = offset / 64;
    const size_t bit = offset % 64;
    return word < bitmap_.size() && (bitmap_[word] & (1ULL << bit)) != 0;
}

void ReplayWindow::set_bit(size_t offset) {
    const size_t word = offset / 64;
    const size_t bit = offset % 64;
    if (word < bitmap_.size()) {
        bitmap_[word] |= 1ULL << bit;
    }
}

ReplayResult ReplayWindow::check_and_mark(uint64_t sequence) {
    last_activity_ = std::chrono::steady_clock::now();
    const size_t window = bitmap_.size() * 64;

    if (!initialized_) {
        initialized_ = true;
        highest_ = sequence;
        std::fill(bitmap_.begin(), bitmap_.end(), uint64_t{0});
        set_bit(0);
        return ReplayResult::Accepted;
    }

    if (sequence > highest_) {
        const size_t gap = static_cast<size_t>(sequence - highest_);
        shift_left(gap);
        highest_ = sequence;
        set_bit(0);
        if (gap >= window) {
            std::fill(bitmap_.begin(), bitmap_.end(), uint64_t{0});
            set_bit(0);
        }
        return ReplayResult::Accepted;
    }

    const size_t offset = static_cast<size_t>(highest_ - sequence);
    if (offset >= window) {
        return ReplayResult::OutOfWindow;
    }
    if (is_bit_set(offset)) {
        return ReplayResult::Replay;
    }
    set_bit(offset);
    return ReplayResult::Accepted;
}

AntiReplay::AntiReplay(size_t window_size)
    : window_size_(ReplayWindow::normalize_window(window_size)) {}

ReplayResult AntiReplay::check(uint64_t session_id, Direction direction, uint64_t sequence) {
    std::lock_guard<std::mutex> lock(mutex_);
    const SessionDirectionKey key{session_id, direction};

    // `try_emplace` construye la ventana con `window_size_` en la primera
    // visita. Usar `operator[]` default-construiría con el valor por defecto
    // (1024) en lugar del tamaño configurado, de modo que la ventana real
    // no coincidiría con la de Rust.
    auto& state = windows_.try_emplace(key, window_size_).first->second;
    return state.check_and_mark(sequence);
}

void AntiReplay::remove_session(uint64_t session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    windows_.erase(SessionDirectionKey{session_id, Direction::Tx});
    windows_.erase(SessionDirectionKey{session_id, Direction::Rx});
}

void AntiReplay::cleanup(uint64_t max_idle_secs) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    for (auto it = windows_.begin(); it != windows_.end();) {
        const auto idle = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_activity()).count();
        if (static_cast<uint64_t>(idle) >= max_idle_secs) {
            it = windows_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t AntiReplay::active_sessions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return windows_.size();
}

} // namespace ipc::security
