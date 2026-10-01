// =============================================================================
// BLAKE3 - Implementación portable
// =============================================================================
//
// P0.1: `contract_hash` debe ser BLAKE3-256 en TODOS los bindings. Esta
// implementación no depende de OpenSSL (que no expone BLAKE3 en 3.0) ni de
// librerías de terceros, de modo que Rust, Kotlin y C++ calculan exactamente
// el mismo digest byte a byte.
//
// Alcance: entradas de un solo chunk (<= 1024 bytes), que es el caso del
// formato CBC (un header de 256 bytes más secciones). Para entradas mayores
// se lanza `std::length_error`: emitir un digest incorrecto en silencio sería
// peor que fallar, porque `contract_hash` es la identidad del contrato.
//
// La salida es el *chaining value* del nodo raíz (las primeras 8 palabras del
// estado de compresión plegadas), según la especificación BLAKE3.
//
// Verificado byte a byte contra el crate `blake3` de Rust en
// `cpp_bindings/tests/blake3_test.cpp`.

#include "ipc/blake3.hpp"

#include <cstring>
#include <stdexcept>

namespace ipc::blake3 {

namespace {

constexpr uint32_t IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

constexpr uint8_t MSG_PERM[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

constexpr size_t CHUNK_START = 1u << 0;
constexpr size_t CHUNK_END   = 1u << 1;
constexpr size_t ROOT        = 1u << 3;
/// Modo con clave: se establece en TODAS las compresiones y sólo en él.
/// La clave sustituye al IV como chaining value inicial, pero el flag es
/// además necesario para la separación de dominio.
constexpr size_t KEYED_HASH  = 1u << 4;

constexpr size_t BLOCK_LEN = 64;
/// Límite de un solo chunk, sin árbol de sub-chunks.
constexpr size_t MAX_SINGLE_CHUNK = 1024;

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

inline void g(uint32_t* s, size_t a, size_t b, size_t c, size_t d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];
    s[b] = rotr(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];
    s[b] = rotr(s[b] ^ s[c], 7);
}

inline void round_fn(uint32_t* s, const uint32_t* m) {
    g(s, 0, 4, 8,  12, m[0],  m[1]);
    g(s, 1, 5, 9,  13, m[2],  m[3]);
    g(s, 2, 6, 10, 14, m[4],  m[5]);
    g(s, 3, 7, 11, 15, m[6],  m[7]);
    g(s, 0, 5, 10, 15, m[8],  m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8,  13, m[12], m[13]);
    g(s, 3, 4, 9,  14, m[14], m[15]);
}

inline void permute(uint32_t* m) {
    uint32_t p[16];
    for (size_t i = 0; i < 16; ++i) p[i] = m[MSG_PERM[i]];
    std::memcpy(m, p, sizeof(p));
}

inline void words_from_block(const uint8_t block[BLOCK_LEN], uint32_t m[16]) {
    for (size_t i = 0; i < 16; ++i) {
        m[i] = static_cast<uint32_t>(block[i * 4]) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
    }
}

/// Compresión de BLAKE3: 7 rondas sobre un bloque de 64 bytes.
///
/// Devuelve el estado completo de 16 palabras. El chaining value son las
/// primeras 8 palabras plegadas con las 8 últimas.
void compress(const uint32_t cv[8], const uint32_t msg[16],
              uint64_t counter, size_t block_len, size_t flags, uint32_t out[16]) {
    for (size_t i = 0; i < 8; ++i) out[i] = cv[i];
    out[8]  = IV[0];
    out[9]  = IV[1];
    out[10] = IV[2];
    out[11] = IV[3];
    out[12] = static_cast<uint32_t>(counter);
    out[13] = static_cast<uint32_t>(counter >> 32);
    out[14] = static_cast<uint32_t>(block_len);
    out[15] = static_cast<uint32_t>(flags);

    uint32_t m[16];
    std::memcpy(m, msg, sizeof(m));
    for (int r = 0; r < 7; ++r) {
        round_fn(out, m);
        if (r < 6) permute(m);
    }
}

/// Estado de un chunk en curso
struct ChunkState {
    uint32_t cv[8];
    uint64_t chunk_counter;
    size_t blocks_compressed;
    size_t flags;
    uint8_t buf[BLOCK_LEN];
    size_t buf_len;

    ChunkState(uint64_t counter, const uint32_t key[8], size_t flags_)
        : chunk_counter(counter), blocks_compressed(0), flags(flags_), buf_len(0) {
        // `key` es un array decays a puntero: `sizeof(key)` daría el tamaño
        // del puntero (4/8 bytes), no el del array. Hay que copiar 8 palabras.
        static_assert(sizeof(uint32_t) * 8 == 32, "se esperan 8 palabras de 32 bits");
        std::memcpy(cv, key, sizeof(uint32_t) * 8);
        std::memset(buf, 0, sizeof(buf));
    }

    size_t start_flag() const {
        return blocks_compressed == 0 ? static_cast<size_t>(CHUNK_START) : 0u;
    }

    void update(const uint8_t* input, size_t len) {
        while (len > 0) {
            if (buf_len == BLOCK_LEN) {
                // Bloque completo: se comprime y el CV avanza.
                uint32_t msg[16], st[16];
                words_from_block(buf, msg);
                compress(cv, msg, chunk_counter, BLOCK_LEN, flags | start_flag(), st);
                for (size_t i = 0; i < 8; ++i) cv[i] = st[i] ^ st[i + 8];
                blocks_compressed++;
                buf_len = 0;
            }
            size_t take = BLOCK_LEN - buf_len;
            if (take > len) take = len;
            std::memcpy(buf + buf_len, input, take);
            buf_len += take;
            input += take;
            len -= take;
        }
    }

    /// Hash final del chunk: el último bloque se rellena con ceros y se marca
    /// como CHUNK_END | ROOT.
    std::array<uint8_t, 32> finalize() const {
        uint8_t block[BLOCK_LEN];
        std::memcpy(block, buf, buf_len);
        if (buf_len < BLOCK_LEN) std::memset(block + buf_len, 0, BLOCK_LEN - buf_len);

        uint32_t msg[16], st[16];
        words_from_block(block, msg);
        compress(cv, msg, chunk_counter, buf_len,
                 flags | start_flag() | CHUNK_END | ROOT, st);

        std::array<uint8_t, 32> out{};
        for (size_t i = 0; i < 8; ++i) {
            uint32_t w = st[i] ^ st[i + 8];
            out[i * 4]     = static_cast<uint8_t>(w);
            out[i * 4 + 1] = static_cast<uint8_t>(w >> 8);
            out[i * 4 + 2] = static_cast<uint8_t>(w >> 16);
            out[i * 4 + 3] = static_cast<uint8_t>(w >> 24);
        }
        return out;
    }
};

std::array<uint8_t, 32> hash_impl(const uint32_t key[8], const uint8_t* data, size_t len,
                                  size_t base_flags) {
    if (len > MAX_SINGLE_CHUNK) {
        throw std::length_error(
            "BLAKE3 (binding C++) soporta hasta 1024 bytes por llamada; "
            "para entradas mayores se requiere la implementación con árbol");
    }
    ChunkState chunk(0, key, base_flags);
    chunk.update(data, len);
    return chunk.finalize();
}

} // namespace

std::array<uint8_t, 32> hash(const uint8_t* data, size_t len) {
    uint32_t key[8];
    std::memcpy(key, IV, sizeof(key));
    return hash_impl(key, data, len, 0);
}

std::array<uint8_t, 32> hash(const std::vector<uint8_t>& data) {
    return hash(data.data(), data.size());
}

std::array<uint8_t, 32> keyed_hash(const uint8_t key[32], const uint8_t* data, size_t len) {
    uint32_t key_words[8];
    for (size_t i = 0; i < 8; ++i) {
        key_words[i] = static_cast<uint32_t>(key[i * 4]) |
                       (static_cast<uint32_t>(key[i * 4 + 1]) << 8) |
                       (static_cast<uint32_t>(key[i * 4 + 2]) << 16) |
                       (static_cast<uint32_t>(key[i * 4 + 3]) << 24);
    }
    return hash_impl(key_words, data, len, KEYED_HASH);
}

std::array<uint8_t, 32> keyed_hash(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& data) {
    if (key.size() != KEY_LEN) {
        throw std::invalid_argument("BLAKE3 keyed hash requiere una clave de 32 bytes");
    }
    return keyed_hash(key.data(), data.data(), data.size());
}

} // namespace ipc::blake3
