// Vectores de prueba oficiales de BLAKE3 (trimmed) para verificar la
// implementación C++ antes de usarla en la identidad de contratos.
#include "ipc/blake3.hpp"
#include <cstdio>
#include <string>
#include <vector>

using namespace ipc;

static std::string hex(const std::vector<uint8_t>& v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (auto b : v) { s += d[b >> 4]; s += d[b & 0xF]; }
    return s;
}
static std::string hex(const std::array<uint8_t,32>& v) {
    return hex(std::vector<uint8_t>(v.begin(), v.end()));
}

int main() {
    int failures = 0;
    auto check = [&](const char* label, const std::string& got, const std::string& want) {
        if (got != want) {
            printf("FAIL %s\n  got  %s\n  want %s\n", label, got.c_str(), want.c_str());
            ++failures;
        } else {
            printf("ok   %s\n", label);
        }
    };

    // Vector oficial: hash del string vacio
    check("empty",
          hex(blake3::hash(std::vector<uint8_t>{})),
          "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");

    // Vector oficial: hash de "abc"
    check("abc",
          hex(blake3::hash(std::vector<uint8_t>{'a','b','c'})),
          "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");

    // Vector oficial: entrada de exactamente 1 byte 0x00
    {
        std::vector<uint8_t> in(1, 0x00);
        check("1x00", hex(blake3::hash(in)),
              "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
    }

    // Vector oficial: 1024 bytes -> fuerza el uso del flag CHUNK_END con
    // block_len completo y counter > 0
    {
        std::vector<uint8_t> in(1024, 0x00);
        // El hash de 1024 ceros segun el vector oficial es:
        check("1024x00", hex(blake3::hash(in)),
              "d6fd9de5bccf223f523b316c9cd1cf9a9d87ea42473d68e011dad13f09bf8917");
    }

    // Vector adicional
    {
        std::string hw = "hello world";
        check("hello-world", hex(blake3::hash(std::vector<uint8_t>(hw.begin(), hw.end()))),
              "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
    }

    // Vector keyed: key = 000102...1f, input = 000102...3f (64 bytes)
    {
        std::vector<uint8_t> key(32), data(64);
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
        for (int i = 0; i < 64; ++i) data[i] = (uint8_t)i;
        check("keyed-64", hex(blake3::keyed_hash(key, data)),
              "cfaf838ff320e0d87301dcba02b1a4bb397d65119f57403df2817a51d4025f9b");
    }

    // Vector oficial keyed: input de 0 bytes
    {
        std::vector<uint8_t> key(32);
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
        check("keyed-empty", hex(blake3::keyed_hash(key, std::vector<uint8_t>{})),
              "73492b19995d71cdb1e9d74decc09809eb732f1b00bc95c27cb15f9dd4d6478f");
    }

    printf("\n%s (%d failures)\n", failures == 0 ? "ALL PASS" : "FAILURES", failures);
    return failures == 0 ? 0 : 1;
}
