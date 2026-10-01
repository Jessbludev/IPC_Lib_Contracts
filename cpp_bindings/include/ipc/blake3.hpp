#pragma once

/**
 * BLAKE3-256 portable para los bindings C++.
 *
 * P0.1: `contract_hash` de un contrato CBC es BLAKE3-256 en Rust, Kotlin y
 * C++. OpenSSL 3.0 no expone BLAKE3, así que se incluye una implementación
 * propia en lugar de degradar la identidad a SHA-256.
 */

#include <array>
#include <cstdint>
#include <cstddef>
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

} // namespace ipc::blake3
