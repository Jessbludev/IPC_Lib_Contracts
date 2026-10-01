# Get Started

Instalación, primer contrato y primer frame verificado.

## Requisitos

| Herramienta | Versión mínima | Verificada con |
|---|---|---|
| Rust | 1.75 (estable) | 1.98.1 |
| OpenSSL | 3.0 | 3.0.20 |
| Compilador C++ | C++20 | GCC 12.2 |
| CMake | 3.20 | 3.25.1 |
| JDK | 17 | 17.0.20 |
| Kotlin | 1.9 | 1.9.24 |
| kotlinx-coroutines | 1.8 | 1.8.1 |

### Requisitos por lenguaje

- **Sólo Rust**: no necesitas nada más. Es la dependencia mínima y la única
  forma de usar el sistema hoy de extremo a extremo.
- **C++**: requiere OpenSSL 3.0+. La versión 3.0 es el mínimo porque las
  versiones anteriores no exponen `EVP_PKEY_ED25519`, y Ed25519 no se puede
  sustituir por HMAC (ver [ADR-0004](adr.md#adr-0004-ed25519-real)).
- **Kotlin**: requiere JDK 15+ por `SunEC`, que trae Ed25519 nativo sin
  dependencias externas. En Android, el mismo motor está disponible desde
  Android 8 (API 26).

### Verificar el toolchain

```bash
rustc --version        # rustc 1.98.1
g++ --version          # g++ 12.2.0
cmake --version        # cmake version 3.25.1
java -version          # openjdk 17.0.20
```

## Instalación

### Rust (core y CLI)

```bash
git clone <repo> ipc-lib-contracts
cd ipc-lib-contracts

cargo build --release --features clap
```

El binario queda en `target/release/contractc`.

### C++ (bindings)

```bash
cmake -S cpp_bindings -B build/cpp -DCMAKE_BUILD_TYPE=Release -DIPC_BUILD_TESTS=ON
cmake --build build/cpp -j
cd build/cpp && ctest --output-on-failure
```

Compila `libipc_contract.a`, `libipc_security.a` y `libipc_client.a`. Los
headers están en `cpp_bindings/include/ipc/`.

Para enlazar en tu proyecto:

```cmake
add_subdirectory(cpp_bindings)
target_link_libraries(mi_app PRIVATE ipc::contract ipc::security)
```

Si `find_package(OpenSSL)` falla, instala `libssl-dev`.

### Kotlin (bindings)

```bash
kotlinc -cp kotlinx-coroutines-core-jvm-1.8.1.jar \
        kotlin_bindings/src/main/kotlin/com/ipc/contract/*.kt \
        -d build/kotlin
```

Para un proyecto Gradle, declara `kotlinx-coroutines-core` como dependencia
única. No hay dependencias criptográficas externas: Ed25519 viene del JDK.

## Verificar la instalación

```bash
./run_all_tests.sh
```

Nueve gates: compilación y tests de Rust (53, incluidos fuzzing de parsers),
C++ con `-Wall`, build por CMake con `ctest`, y conformidad cross-language de
C++ (18 comprobaciones) y Kotlin (39) contra los vectores dorados.

```
[ok] cargo check (0 errores)
[ok] cargo test (53 tests)
[ok] librería estática construida
[ok] BLAKE3 coincide con los vectores oficiales
[ok] C++ conformidad (18 checks)
[ok] CMake build + ctest
[ok] bindings Kotlin compilados
[ok] Kotlin conformidad (39 checks)
Todos los gates pasaron.
```

Si un gate falla, el mensaje indica el binding concreto. Un fallo de
conformidad significa que ese binding calcula algo distinto a Rust: es el
error más grave posible, porque rompe la identidad del contrato.

## Tu primer contrato

### 1. Escribir el contrato

El formato de fuente es el DSL del proyecto:

```
contract "image_processor" {
    version   "1.0.0"
    namespace "demo.contracts"
    role      mutual

    type PixelBuffer {
        data:   bytes,
        width:  u32,
        height: u32
    }

    operation resize {
        input  PixelBuffer,
        output PixelBuffer,
        timeout_ms 5000
    }
}
```

### 2. Compilarlo

```bash
mkdir -p build
cargo run --features clap --bin contractc -- \
    -o build compile --sign --sign-key claves/mi_clave.key \
    contracts/image_processor.contract
```

Genera `build/image_processor.cbc`. Ojo con el orden de los argumentos: `-o`
es una opción **global** y va antes del subcomando; `--sign` y `--sign-key`
son de `compile` y van después.

El contrato de ejemplo declara `authentication required`, y la política por
defecto tiene `SignaturePolicy::Required`: un contrato sin firma **se rechaza
al cargarlo**, con el error
`Autenticación requerida pero no proporcionada`. Es intencionado — un
contrato sin firma no tiene identidad verificable. Si necesitas compilar sin
firmar para pruebas, cambia la política en el DSL de forma explícita; ver
[Uso → Políticas](usage.md#políticas-de-seguridad).

El parser del DSL cubre la cabecera (nombre, namespace, versión, política de
seguridad) pero no los bloques `type` ni `operation`: un contrato compilado
ahora reporta `Types: 0` / `Operations: 0`. El `contract_hash` resultante es
estable y verificable, pero noyet describe la superficie de tipos. Es una
limitación conocida, no un fallo silencioso; ver
[Hoja de ruta](roadmap.md).

### 3. Verificarlo

```bash
cargo run --features clap --bin contractc -- verify --check-signature \
    --verify-key claves/mi_clave.pub build/image_processor.cbc
```

Salida esperada:

```
CBC VALID

Format:       1
Protocol:     2
Contract:     1.0.0

Hash:
b3:f604e7ea99a4b898a470e43bb2de391ae619348d9fe1b75deaddb26727d264bc
```

`contract verify` comprueba, en orden: magic, versión de formato, tamaño de
header, bounds de sección, solapamientos, UTF-8, codificación canónica del
header, `contract_hash` recalculado y firma.

### 4. Inspeccionarlo

```bash
cargo run --features clap --bin contractc -- inspect build/image_processor.cbc
```

### 5. Firmarlo

```bash
# 32 bytes: hex de 64 caracteres, o binario crudo
cargo run --features clap --bin contractc -- compile \
    --sign --sign-key claves/mi_clave.key \
    -o build contracts/image_processor.contract
```

## Tu primer frame

Un frame es la unidad de tráfico. Tiene 64 bytes de header fijo.

### En Rust

```rust
use ipc_contract_system::{
    AeadAlgorithm, AeadCipher, Direction, Frame, KeyDerivation, OperationId,
    PacketType, ContractRole, TypeId,
};

let mut kd_secret = [0u8; 32];
rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut kd_secret);
let kd = KeyDerivation::new(&kd_secret);

let contract_hash = [0x42u8; 32];
let session_id = 1u64;

let session_key = kd.derive_session_key(&contract_hash, session_id);
let encryption_key = kd.derive_encryption_key(&session_key.0);
let nonce_key = kd.derive_nonce_key(&contract_hash, session_id);

let mut frame = Frame::new(
    PacketType::Request,
    ContractRole::Mutual,
    session_id,
    0,                          // sequence
    0,                          // channel_id
    OperationId(0x0100),        // operation_id
    TypeId(0x0001),             // schema_id
    &contract_hash[..12].try_into().unwrap(),
    b"contenido secreto".to_vec(),
);

// El nonce se deriva de la clave de sesión, no es aleatorio (P0.4).
let cipher = AeadCipher::new(AeadAlgorithm::ChaCha20Poly1305);
ipc_contract_system::WireProtocol::send(
    &mut frame, &nonce_key.0, &encryption_key.0, Direction::Tx, &cipher,
)?;

let bytes = frame.to_bytes();   // 64 + len(payload)
```

Para recibirlo:

```rust
use ipc_contract_system::security::AntiReplay;

let anti_replay = AntiReplay::new(1024);
let received = Frame::from_bytes(&bytes_from_socket)?;

let plaintext = ipc_contract_system::WireProtocol::receive(
    &received,
    &contract_hash[..12].try_into().unwrap(),
    &encryption_key.0,
    &cipher,
    &anti_replay,
)?;
```

`WireProtocol::receive` hace la verificación en el orden correcto: valida el
frame, comprueba el prefijo del contrato, verifica el AEAD y **sólo entonces**
registra la secuencia en la ventana anti-replay. Ese orden importa: si un
atacante sin la clave pudiera avanzar la ventana, bloquearía tráfico válido.

### En C++

```cpp
#include "ipc/contract.hpp"
#include "ipc/security.hpp"

using namespace ipc;

security::KeyDerivation kd(secret32);
auto session_key   = kd.derive_session_key(contract_hash, session_id);
auto encryption_key= kd.derive_encryption_key(session_key);
auto nonce_key     = kd.derive_nonce_key(contract_hash, session_id);

auto nonce = security::derive_nonce(nonce_key, session_id, sequence,
                                    security::Direction::Tx);

std::vector<uint8_t> aad = /* 48 bytes del header, ver Frame::header_aad */;
auto ciphertext = security::encrypt_chacha20poly1305(
    encryption_key, std::vector<uint8_t>(nonce.begin(), nonce.end()),
    aad, plaintext);
```

### En Kotlin

```kotlin
val kd = KeyDerivation(secret32)
val sessionKey    = kd.deriveSessionKey(contractHash, sessionId)
val encryptionKey = kd.deriveEncryptionKey(sessionKey)
val nonceKey      = kd.deriveNonceKey(contractHash, sessionId)

val nonce = SecurityUtils.deriveNonce(nonceKey, sessionId, sequence, Direction.TX)
val aad   = frame.headerAad()
val ct    = SecurityUtils.encryptChaCha20(encryptionKey, nonce, aad, plaintext)

val antiReplay = AntiReplay(1024)
```

## Comprobar la conformidad entre lenguajes

Los vectores dorados viven en `tests/vectors/crypto.json`. Si cambias la
identidad del contrato, la derivación de claves o la máquina de estados
anti-replay, tienes que regenerarlos y volver a validar los tres lenguajes:

```bash
cargo run --example conformance_vectors > tests/vectors/crypto.json
./run_all_tests.sh
```

Los tests de conformidad de Rust, C++ y Kotlin fallarán si algún binding
diverge. Ese es el mecanismo que mantiene el sistema honesto: no basta con que
cada implementación funcione por separado, tiene que producir los mismos
bytes.

## Siguientes pasos

- [Uso](usage.md) — referencia completa de la CLI y las APIs
- [Integración](integration.md) — insertar esto en tu aplicación
- [Implementación](implementation.md) — cómo funciona por dentro
- [Seguridad](security.md) — las políticas y qué las respalda
