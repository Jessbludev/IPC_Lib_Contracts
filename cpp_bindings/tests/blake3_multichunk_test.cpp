// BLAKE3 multi-chunk: conformidad con la referencia de Rust.
//
// La v2.1 limitaba C++ a 1024 bytes por llamada y lanzaba excepción más allá.
// Estos vectores comprueban que el árbol de sub-chunks reproduce exactamente el
// mismo digest que el crate `blake3` de Rust para entradas de cualquier tamaño,
// incluido el modo keyed, y que el resultado no depende de la partición.

#include "ipc/blake3.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int g_checks = 0;
int g_failures = 0;

void check_hex(const char* name, const std::array<uint8_t, 32>& got, const char* expected) {
    ++g_checks;
    char buf[65];
    for (size_t i = 0; i < 32; ++i) std::sprintf(buf + i * 2, "%02x", got[i]);
    if (std::strcmp(buf, expected) == 0) {
        std::printf("  ok   %s\n", name);
    } else {
        std::printf("  FAIL %s\n    esperado %s\n    obtenido %s\n", name, expected, buf);
        ++g_failures;
    }
}

void check_bool(const char* name, bool cond) {
    ++g_checks;
    if (cond) {
        std::printf("  ok   %s\n", name);
    } else {
        std::printf("  FAIL %s\n", name);
        ++g_failures;
    }
}

/// Entrada determinista de `n` bytes.
///
/// Usa un PRNG xorshift con semilla fija: los vectores son reproducibles entre
/// máquinas y versiones del compilador, a diferencia de `rand()`.
std::vector<uint8_t> data(size_t n, uint64_t seed = 0x9E3779B97F4A7C15ull) {
    std::vector<uint8_t> v(n);
    uint64_t x = seed;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v[i] = static_cast<uint8_t>(x >> 24);
    }
    return v;
}

std::vector<uint8_t> zeros(size_t n) { return std::vector<uint8_t>(n, 0); }

/// Comprobar que la API incremental coincide con la one-shot para una
/// partición dada.
void check_partition(const char* name, const std::vector<uint8_t>& d,
                     const std::vector<size_t>& parts) {
    ipc::blake3::Blake3Hasher h;
    size_t off = 0;
    for (size_t p : parts) {
        size_t take = p > d.size() - off ? d.size() - off : p;
        if (take == 0) break;
        h.update(d.data() + off, take);
        off += take;
    }
    if (off < d.size()) h.update(d.data() + off, d.size() - off);

    ++g_checks;
    if (h.finalize() == ipc::blake3::hash(d)) {
        std::printf("  ok   %s\n", name);
    } else {
        std::printf("  FAIL %s (streaming != one-shot)\n", name);
        ++g_failures;
    }
}

const uint8_t KEY[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

} // namespace

int main() {
    std::printf("BLAKE3 multi-chunk: vectores de conformance_vectors (Rust)\n");

    // --- Baseline: no debe cambiar con multi-chunk ------------------------
    std::printf("\n=== baseline <= 1024 bytes ===\n");
    check_hex("vacio", ipc::blake3::hash(zeros(0)),
              "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    check_hex("abc", ipc::blake3::hash(std::vector<uint8_t>{'a', 'b', 'c'}),
              "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
    check_hex("63 ceros", ipc::blake3::hash(zeros(63)), "990a6d20859d8f43865abd59d92a07aaef1c25c2257d017db07710152d06c0d5");
    check_hex("64 ceros", ipc::blake3::hash(zeros(64)), "4d006976636a8696d909a630a4081aad4d7c50f81afdee04020bf05086ab6a55");
    check_hex("65 ceros", ipc::blake3::hash(zeros(65)), "a6f791da7707e3a05a7742248eefe43f9ad4626fc21b63675367c3d1d69ec91c");
    check_hex("1023 ceros", ipc::blake3::hash(zeros(1023)), "5b10416d32f16b046bf4f2a8867960a16e99280dfd694e9a809a6bf849531697");
    check_hex("1024 ceros", ipc::blake3::hash(zeros(1024)), "d6fd9de5bccf223f523b316c9cd1cf9a9d87ea42473d68e011dad13f09bf8917");
    check_hex("1024 aleatorio", ipc::blake3::hash(data(1024)), "2e71b2b3dd40f43c87c5df81fba91f50750e356308a03480bf5bb0ecd7993d16");

    // --- Modo keyed dentro del limite -------------------------------------
    std::printf("\n=== keyed, <= 1024 bytes ===\n");
    std::vector<uint8_t> kv(KEY, KEY + 32);
    check_hex("keyed 0", ipc::blake3::keyed_hash(kv, zeros(0)), "73492b19995d71cdb1e9d74decc09809eb732f1b00bc95c27cb15f9dd4d6478f");
    check_hex("keyed abc", ipc::blake3::keyed_hash(kv, std::vector<uint8_t>{'a','b','c'}),
              "6da54495d8152f2bcba87bd7282df70901cdb66b4448ed5f4c7bd2852b8b5532");
    check_hex("keyed 64", ipc::blake3::keyed_hash(kv, zeros(64)), "253a1c323ffc166d90b6552796fbf6c92fd1ec4a2fab1de53ba58fc17c309c4c");
    check_hex("keyed 1024", ipc::blake3::keyed_hash(kv, zeros(1024)), "e8e16ce483f39f5f4345d278dc1f28d47cad1727919263eaec5743f88de623b3");

    // --- Multi-chunk: longitudes criticas ---------------------------------
    // La v2.1 lanzaba std::length_error a partir de 1025 bytes. Estos casos no
    // existian: son precisamente los que fallarian si el arbol estivesse mal.
    std::printf("\n=== multi-chunk: longitudes criticas ===\n");
    check_hex("1025 ceros", ipc::blake3::hash(zeros(1025)), "d2beb49d87e59db174cb3ff1440f1899422968df670d060fd7ce759e8cc160e7");
    check_hex("2047 ceros", ipc::blake3::hash(zeros(2047)), "5bea1ede30f4389bdeac72799d266dd054d35a3eb89e154d217bd582a21fd0c2");
    check_hex("2048 ceros", ipc::blake3::hash(zeros(2048)), "be2a8de3dcf46c94ce85cdc8e07ac308f4d8a95490d956c38d780fd610db0813");
    check_hex("2049 ceros", ipc::blake3::hash(zeros(2049)), "b982335435308f3f5f5f51f5d45ecae6194641975e7b0bcaa1facd48ebabb28e");
    check_hex("3072 ceros", ipc::blake3::hash(zeros(3072)), "aae9f164c4ba4a3f9bae88f07bc4df6042b4d7d08e079aa01bba465a7872d1a5");
    check_hex("4096 ceros", ipc::blake3::hash(zeros(4096)), "b6fb73fc46938c981e2b0b4b1ef282adcfc89854d01bfe3972fdc4785b41b2c7");
    check_hex("4097 ceros", ipc::blake3::hash(zeros(4097)), "84e5fa82c1670822633b16214c3c808824025289006d86489d9b05a63d087f0c");
    check_hex("8192 ceros", ipc::blake3::hash(zeros(8192)), "128daa44a4f7badaed2244bb6fe009d5e7803177414e01d7d9df80c190e14906");
    check_hex("1 MiB ceros", ipc::blake3::hash(zeros(1024 * 1024)), "488de202f73bd976de4e7048f4e1f39a776d86d582b7348ff53bf432b987fca8");
    check_hex("1025 aleatorio", ipc::blake3::hash(data(1025)), "dd65c61678d7bb631db28da97fd7f5aa716c4815d2e5cd11ea82953ceef35457");
    check_hex("2048 aleatorio", ipc::blake3::hash(data(2048)), "cdb7045064cdc5b8f3f803b7f4e7a1e62ac79cde91419b559e29b0805c3c5c9d");

    // --- Keyed multi-chunk -------------------------------------------------
    std::printf("\n=== keyed multi-chunk ===\n");
    check_hex("keyed 1025", ipc::blake3::keyed_hash(kv, zeros(1025)), "aebd057842fabbdc4e2ddaba7206c6eb717335eebb8891067ec0dd57adc5e183");
    check_hex("keyed 2048", ipc::blake3::keyed_hash(kv, zeros(2048)), "c3263f17f24d825859f6a2c6b6386f7b90fae91ccfc407a661848aa8e2669657");
    check_hex("keyed 4096", ipc::blake3::keyed_hash(kv, zeros(4096)), "68277efeb7544248fc8434b543846721e02fca36952d6f91a31022d06469b6aa");
    check_hex("keyed 1 MiB", ipc::blake3::keyed_hash(kv, zeros(1024 * 1024)), "96f15c0fffe8d85d2b98b3010e5be74dfcefd40cd11c3a0c22b340fb99b09fbb");
    check_hex("keyed 1025 aleatorio", ipc::blake3::keyed_hash(kv, data(1025)), "9b2b190782294f69b5142763abdaecbb0dcc876f41971ea3c6b2f4febeaece8b");

    // --- Particiones de streaming -----------------------------------------
    std::printf("\n=== particiones de streaming ===\n");
    auto d1025 = data(1025);
    check_partition("1025 en 1+1024", d1025, {1, 1024});
    check_partition("1025 en 63+962", d1025, {63, 962});
    check_partition("1025 en 1024+1", d1025, {1024, 1});
    check_partition("1025 en 512+513", d1025, {512, 513});
    check_partition("1025 en 65 bytes", d1025, {65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 5});

    auto d2048 = data(2048);
    check_partition("2048 en 1024+1024", d2048, {1024, 1024});
    check_partition("2048 en 1+2047", d2048, {1, 2047});
    check_partition("2048 en 777+1271", d2048, {777, 1271});

    auto d1m = data(1024 * 1024, 0xDEADBEEF);
    check_partition("1 MiB en trozos de 1024", d1m, std::vector<size_t>(1024, 1024));
    check_partition("1 MiB en trozos de 7", d1m, std::vector<size_t>(1024 * 1024 / 7 + 1, 7));

    // --- Vector de clave con tamano incorrecto ----------------------------
    std::printf("\n=== validacion ===\n");
    bool threw = false;
    try {
        ipc::blake3::keyed_hash(std::vector<uint8_t>(31, 0), zeros(10));
    } catch (const std::invalid_argument &) {
        threw = true;
    }
    check_bool("clave de 31 bytes lanza excepcion", threw);

    // --- Continuidad del hasher -------------------------------------------
    std::printf("\n=== continuidad ===\n");
    {
        // Tras un digest intermedio se puede seguir absorbiendo: el resultado
        // final debe coincidir con hashear todo de una vez.
        auto d = data(3000);
        ipc::blake3::Blake3Hasher h;
        h.update(d.data(), 1000);
        (void)h.finalize();          // digest intermedio, no consume
        h.update(d.data() + 1000, 1000);
        h.update(d.data() + 2000, 1000);
        check_bool("digest intermedio no consume el hasher", h.finalize() == ipc::blake3::hash(d));
    }
    {
        // reset() debe devolver el hasher al estado inicial.
        ipc::blake3::Blake3Hasher h;
        h.update(data(5000).data(), 5000);
        h.reset();
        h.update(data(10).data(), 10);
        check_bool("reset() vuelve al estado inicial", h.finalize() == ipc::blake3::hash(data(10)));
    }

    std::printf("\nBLAKE3 multi-chunk: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
