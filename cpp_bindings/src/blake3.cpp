// =============================================================================
// BLAKE3 - Implementación portable
// =============================================================================
//
// P0.1: `contract_hash` debe ser BLAKE3-256 en TODOS los bindings. Esta
// implementación no depende de OpenSSL (que no expone BLAKE3 en 3.0) ni de
// librerías de terceros, de modo que Rust, Kotlin y C++ calculan exactamente
// el mismo digest byte a byte.
//
// Implementa el árbol de sub-chunks completo de la especificación, sin límite
// de tamaño. La estructura sigue a la implementación de referencia:
//
//   - `ChunkState` mantiene el CV y el bloque en curso de un chunk.
//   - Al llenarse un chunk, su chaining value se apila y se empieza otro.
//   - La pila mantiene sub-chunks con número de chunks completados
//     estrictamente decreciente de abajo hacia arriba.
//   - `add_chunk_chaining_value` colapsa la pila de izquierda a derecha,
//    normalizando el árbol cuando el número de chunks es par.
//   - Al finalizar, los sub-chunks pendientes se combinan de derecha a
//     izquierda con el último chunk, y el nodo resultante se comprime con
//     ROOT.
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
constexpr size_t PARENT      = 1u << 2;
constexpr size_t ROOT        = 1u << 3;
/// Modo con clave: se establece en TODAS las compresiones y sólo en él.
/// La clave sustituye al IV como chaining value inicial, pero el flag es
/// además necesario para la separación de dominio.
constexpr size_t KEYED_HASH  = 1u << 4;

constexpr size_t BLOCK_LEN = 64;
constexpr size_t CHUNK_LEN = 1024;

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
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
}

void compress(const uint32_t cv[8], const uint32_t msg[16], uint64_t counter,
              size_t block_len, size_t flags, uint32_t out[16]) {
    // El estado inicial es: CV en las palabras 0..8, el IV en 8..12, y en las
    // últimas cuatro el contador, la longitud del bloque y los flags.
    //
    // Las cuatro últimas se ASIGNAN, no se Xorean con el IV: BLAKE3 las
    // inicializa directamente. Un `^=`在这里 parte de IV[4..8] y produce un
    // hash distinto que parece plausible y sólo se detecta comparando con la
    // referencia.
    uint32_t s[16];
    for (size_t i = 0; i < 8; ++i) s[i] = cv[i];
    for (size_t i = 0; i < 4; ++i) s[8 + i] = IV[i];
    s[12] = static_cast<uint32_t>(counter);
    s[13] = static_cast<uint32_t>(counter >> 32);
    s[14] = static_cast<uint32_t>(block_len);
    s[15] = static_cast<uint32_t>(flags);

    uint32_t m[16];
    for (size_t i = 0; i < 16; ++i) m[i] = msg[i];

    for (size_t r = 0; r < 7; ++r) {
        round_fn(s, m);
        if (r < 6) {
            uint32_t permuted[16];
            for (size_t i = 0; i < 16; ++i) permuted[i] = m[MSG_PERM[i]];
            std::memcpy(m, permuted, sizeof(m));
        }
    }
    // `out` recibe el estado completo de 16 palabras, sin plegar. El plegado a
    // chaining value (`s[i] ^ s[i+8]`) y la lectura del digest raíz son
    // responsabilidade de quien llama: son operaciones distintas según se
    // trate de un chunk intermedio o del nodo raíz.
    for (size_t i = 0; i < 8; ++i) {
        out[i] = s[i];
        out[8 + i] = s[8 + i];
    }
}

inline void words_from_block(const uint8_t* block, uint32_t words[16]) {
    for (size_t i = 0; i < 16; ++i) {
        words[i] = static_cast<uint32_t>(block[i * 4]) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
    }
}

inline void words_to_bytes(const uint32_t words[8], uint8_t out[32]) {
    for (size_t i = 0; i < 8; ++i) {
        out[i * 4]     = static_cast<uint8_t>(words[i]);
        out[i * 4 + 1] = static_cast<uint8_t>(words[i] >> 8);
        out[i * 4 + 2] = static_cast<uint8_t>(words[i] >> 16);
        out[i * 4 + 3] = static_cast<uint8_t>(words[i] >> 24);
    }
}

/**
 * Estado de un chunk en curso.
 *
 * Guarda el chaining value, el contador de chunk, los flags heredados y el
 * bloque a medio llenar. El último bloque de un chunk se comprime con CHUNK_END;
 * el resultado es el chaining value que se usa para encadenar el siguiente
 * chunk, o el nodo raíz si es el último.
 */
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

    /// Longitud total absorbida por este chunk.
    size_t length() const { return BLOCK_LEN * blocks_compressed + buf_len; }

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

    /// Nodo de salida: la información necesaria para comprimir este chunk,
    /// tanto como padre en el árbol como como raíz.
    struct Output {
        uint32_t input_cv[8];
        uint32_t block_words[16];
        uint64_t counter;
        size_t block_len;
        size_t flags;
    };

    Output output() const {
        uint8_t block[BLOCK_LEN];
        std::memcpy(block, buf, buf_len);
        if (buf_len < BLOCK_LEN) std::memset(block + buf_len, 0, BLOCK_LEN - buf_len);

        Output o{};
        std::memcpy(o.input_cv, cv, sizeof(o.input_cv));
        words_from_block(block, o.block_words);
        o.counter = chunk_counter;
        o.block_len = buf_len;
        o.flags = flags | start_flag() | CHUNK_END;
        return o;
    }

    /// Los 32 bytes del digest de este chunk, marcado como raíz.
    ///
    /// El digest se obtiene plegando el estado: `st[i] ^ st[i+8]`. Es lo que
    /// usa el core de Rust y lo verifican los vectores oficiales.
    std::array<uint8_t, 32> root_bytes() const {
        auto o = output();
        uint32_t st[16];
        compress(o.input_cv, o.block_words, o.counter, o.block_len,
                 o.flags | static_cast<size_t>(ROOT), st);
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

    /// Chaining value del chunk: se usa para encadenar el siguiente chunk y
    /// como entrada de los padres en el árbol.
    std::array<uint32_t, 8> chaining_value() const {
        auto o = output();
        uint32_t st[16];
        compress(o.input_cv, o.block_words, o.counter, o.block_len, o.flags, st);
        std::array<uint32_t, 8> out{};
        for (size_t i = 0; i < 8; ++i) out[i] = st[i] ^ st[i + 8];
        return out;
    }
};

/// Construye el nodo padre a partir de dos chaining values hijos.
ChunkState::Output parent_output(const std::array<uint32_t, 8>& left,
                                 const std::array<uint32_t, 8>& right,
                                 const uint32_t key[8], size_t key_flags) {
    ChunkState::Output o{};
    std::memcpy(o.input_cv, key, sizeof(uint32_t) * 8);
    for (size_t i = 0; i < 8; ++i) o.block_words[i] = left[i];
    for (size_t i = 0; i < 8; ++i) o.block_words[8 + i] = right[i];
    o.counter = 0;
    o.block_len = BLOCK_LEN;
    o.flags = key_flags | static_cast<size_t>(PARENT);
    return o;
}

/// Chaining value de un nodo padre.
std::array<uint32_t, 8> parent_cv(const std::array<uint32_t, 8>& left,
                                  const std::array<uint32_t, 8>& right,
                                  const uint32_t key[8], size_t key_flags) {
    auto o = parent_output(left, right, key, key_flags);
    uint32_t st[16];
    compress(o.input_cv, o.block_words, o.counter, o.block_len, o.flags, st);
    std::array<uint32_t, 8> out{};
    for (size_t i = 0; i < 8; ++i) out[i] = st[i] ^ st[i + 8];
    return out;
}

/// Comprime un Output como raíz y devuelve los 32 bytes.
std::array<uint8_t, 32> output_root_bytes(const ChunkState::Output& o) {
    uint32_t st[16];
    compress(o.input_cv, o.block_words, o.counter, o.block_len,
             o.flags | static_cast<size_t>(ROOT), st);
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

} // namespace

/// Estado interno del hasher. Se define fuera del namespace anónimo porque es
/// un tipo anidado declarado en el encabezado público, y se separa de la clase
/// para que el encabezado no exponga la maquinaria del árbol.
struct Blake3Hasher::Impl {
    uint32_t key[8];
    size_t key_flags;
    ChunkState chunk;
    /// Sub-chunks completados pendientes de combines.
    ///
    /// El invariante es que el número de chunks que representa cada entrada es
    /// estrictamente decreciente de abajo hacia arriba, lo que garantiza que la
    /// forma final sea el árbol canónico de la especificación.
    std::vector<std::array<uint32_t, 8>> cv_stack;

    Impl() : key_flags(0), chunk(0, IV, 0) {
        std::memcpy(key, IV, sizeof(key));
    }

    void push_cv(std::array<uint32_t, 8> cv) {
        cv_stack.push_back(cv);
    }

    /// Añade el chaining value de un chunk completado y normaliza el árbol.
    ///
    /// Mientras el número total de chunks sea par, el sub-chunk nuevo se
    /// combina con el de la cima, y el resultado se vuelve a comprobar. Así el
    /// stack mantiene su forma canónica sin tener que reconstruir el árbol
    /// entero al finalizar.
    void add_chunk_chaining_value(std::array<uint32_t, 8> new_cv, uint64_t total_chunks) {
        while ((total_chunks & 1) == 0) {
            std::array<uint32_t, 8> left = cv_stack.back();
            cv_stack.pop_back();
            new_cv = parent_cv(left, new_cv, key, key_flags);
            total_chunks >>= 1;
        }
        push_cv(new_cv);
    }
};


// ---------------------------------------------------------------------------
// Blake3Hasher
// ---------------------------------------------------------------------------

Blake3Hasher::Blake3Hasher() { impl_ = std::make_unique<Impl>(); }

Blake3Hasher::Blake3Hasher(bool keyed) : impl_(std::make_unique<Impl>()) {
    if (keyed) impl_->key_flags = KEYED_HASH;
}

Blake3Hasher::Blake3Hasher(const Blake3Hasher& other) {
    impl_ = std::make_unique<Impl>(*other.impl_);
}

Blake3Hasher& Blake3Hasher::operator=(const Blake3Hasher& other) {
    if (this != &other) impl_ = std::make_unique<Impl>(*other.impl_);
    return *this;
}

Blake3Hasher::~Blake3Hasher() = default;

void Blake3Hasher::set_key(const uint8_t key[KEY_LEN]) {
    bool was_keyed = impl_->key_flags != 0;
    std::memcpy(impl_->key, key, KEY_LEN);
    impl_->key_flags = KEYED_HASH;
    // La clave fija el chaining value inicial, así que hay que reiniciar el
    // chunk en curso. Se conserva el modo para no perder el estado de "keyed".
    impl_->chunk = ChunkState(0, impl_->key, impl_->key_flags);
    impl_->cv_stack.clear();
    (void)was_keyed;
}

void Blake3Hasher::set_key(const std::vector<uint8_t>& key) {
    if (key.size() != KEY_LEN) {
        throw std::invalid_argument("BLAKE3 requiere una clave de 32 bytes");
    }
    set_key(key.data());
}

void Blake3Hasher::reset() {
    impl_->chunk = ChunkState(0, impl_->key, impl_->key_flags);
    impl_->cv_stack.clear();
}

void Blake3Hasher::update(const uint8_t* data, size_t len) {
    while (len > 0) {
        if (impl_->chunk.length() == CHUNK_LEN) {
            auto cv = impl_->chunk.chaining_value();
            uint64_t total = impl_->chunk.chunk_counter + 1;
            impl_->add_chunk_chaining_value(cv, total);
            impl_->chunk = ChunkState(total, impl_->key, impl_->key_flags);
        }
        size_t want = CHUNK_LEN - impl_->chunk.length();
        size_t take = want < len ? want : len;
        impl_->chunk.update(data, take);
        data += take;
        len -= take;
    }
}

void Blake3Hasher::update(const std::vector<uint8_t>& data) {
    update(data.data(), data.size());
}

std::array<uint8_t, 32> Blake3Hasher::finalize() const {
    // Caso trivial: un solo chunk, sin combine pendientes.
    if (impl_->cv_stack.empty()) {
        return impl_->chunk.root_bytes();
    }

    // Se combinan los sub-chunks pendientes de derecha a izquierda, empezando
    // por el chunk en curso, que es la hoja más a la derecha del árbol.
    ChunkState::Output out = impl_->chunk.output();
    for (size_t i = impl_->cv_stack.size(); i > 0; --i) {
        uint32_t st[16];
        compress(out.input_cv, out.block_words, out.counter, out.block_len,
                 out.flags, st);
        std::array<uint32_t, 8> right{};
        for (size_t k = 0; k < 8; ++k) right[k] = st[k] ^ st[k + 8];
        out = parent_output(impl_->cv_stack[i - 1], right, impl_->key, impl_->key_flags);
    }
    return output_root_bytes(out);
}

std::array<uint8_t, 32> Blake3Hasher::digest() const { return finalize(); }

// ---------------------------------------------------------------------------
// API one-shot
// ---------------------------------------------------------------------------

/// Hash one-shot.
///
/// Se apoya en `Blake3Hasher` en vez de duplicar el bucle del árbol. No es
/// sólo cuestión de evitar código repetido: garantiza por construcción que la
/// API incremental y la one-shot no pueden divergir, que es exactamente la
/// propiedad que comprueban los tests de partición.
std::array<uint8_t, 32> hash_impl(const uint32_t key_words[8], const uint8_t* data, size_t len,
                                  bool keyed) {
    uint8_t key_bytes[KEY_LEN];
    for (size_t i = 0; i < 8; ++i) {
        key_bytes[i * 4]     = static_cast<uint8_t>(key_words[i]);
        key_bytes[i * 4 + 1] = static_cast<uint8_t>(key_words[i] >> 8);
        key_bytes[i * 4 + 2] = static_cast<uint8_t>(key_words[i] >> 16);
        key_bytes[i * 4 + 3] = static_cast<uint8_t>(key_words[i] >> 24);
    }

    Blake3Hasher hasher(keyed);
    if (keyed) hasher.set_key(key_bytes);
    hasher.update(data, len);
    return hasher.finalize();
}

std::array<uint8_t, 32> hash(const uint8_t* data, size_t len) {
    uint32_t key[8];
    std::memcpy(key, IV, sizeof(key));
    return hash_impl(key, data, len, false);
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
    return hash_impl(key_words, data, len, true);
}

std::array<uint8_t, 32> keyed_hash(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& data) {
    if (key.size() != KEY_LEN) {
        throw std::invalid_argument("BLAKE3 keyed hash requiere una clave de 32 bytes");
    }
    return keyed_hash(key.data(), data.data(), data.size());
}

} // namespace ipc::blake3
