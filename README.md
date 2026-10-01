# IPC Contract System v2.1.1

**Sistema de contratos binarios canónicos con seguridad criptográfica real para comunicación inter-procesos.**

## Verificación

```bash
./run_all_tests.sh
```

Nueve gates: compilación y tests de Rust (incluye fuzzing de parsers),
compilación de C++ con `-Wall`, build por CMake con `ctest`, y conformidad
cross-language de C++ (17 comprobaciones) y Kotlin (39) contra los vectores
dorados de `tests/vectors/crypto.json`.

El mismo contrato, hash, firma, nonce, frame y estado anti-replay producen
**bytes idénticos** en los tres lenguajes. Ese es el criterio de madurez del
sistema.

Ver [`docs/SECURITY.md`](docs/SECURITY.md) para las políticas aplicadas
(zero-trust, zero-knowledge, zero-log) y qué comprobación las respalda.

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      CONTRACT DEFINITION (DSL)                           │
│                         Formato humano-legible                            │
│
│   contract "image_processor" {                                          │
│       role mutual                                                        │
│       type Image { data: bytes, width: u32, height: u32 }               │
│       operation resize { input Image, output Image }                     │
│   }                                                                     │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │ contractc compile
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│               CANONICAL BINARY CONTRACT (CBC)                           │
│
│   ┌────────┬────────┬────────┬────────┬────────┬────────┐                  │
│   │ MAGIC  │HEADER  │ TYPES │  OPS   │SECURITY│ SIG    │                  │
│   │ CBC1   │(256B)  │ IDs   │  IDs   │ POLICY │(64B)  │                  │
│   └────────┴────────┴────────┴────────┴────────┴────────┘                  │
│                    BLAKE3-256 Hash (única identidad)                     │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
    ┌─────────┐             ┌─────────┐             ┌─────────┐
    │   Rust  │             │ Kotlin  │             │   TS    │
    │ Bindings│             │ Bindings│             │ Bindings│
    └────┬────┘             └────┬────┘             └────┬────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
                    ┌─────────────────────────┐
                    │    IPC ENGINE v2        │
                    │  (ChaCha20-Poly1305)    │
                    └─────────────────────────┘
```

## Características

### Contrato Binario Canónico

- **Header fijo de 256 bytes** con offsets a secciones
- **Hash BLAKE3-256** sobre la representación canónica sin firma (única identidad del contrato; SHA-256 queda como digest legacy, nunca como `contract_hash`)
- **Firma Ed25519** opcional para distribución
- **Tipos con IDs numéricos** (no más strings en runtime)
- **Operaciones con IDs numéricos** (reducen overhead)

### Seguridad Criptográfica Real

| Componente | Algoritmo |
|------------|-----------|
| Integridad | **BLAKE3-256** (SHA-256 sólo legacy) |
| Autenticidad | HMAC-SHA256 |
| Confidencialidad | ChaCha20-Poly1305 / AES-256-GCM |
| Anti-replay | Nonces únicos + ventana deslizante |

### Roles de Contrato

| Rol | Descripción |
|-----|-------------|
| `child` | Proceso subordinado/controlado |
| `mutual` | Ambos extremos pueden iniciar operaciones |
| `peer` | Comunicación simétrica |
| `mux` | Múltiples canales lógicos |
| `stream` | Flujo persistente |
| `oneway` | Unidireccional |

### Protocolo Wire v2

Frame de **64 bytes** con:
- Magic + Version + Flags
- Session ID + Sequence (anti-replay)
- Operation ID (numérico)
- Contract Hash Prefix (12 bytes)
- Nonce (12 bytes para AEAD)

## Instalación

```bash
# Clonar repositorio
git clone https://github.com/Jessbludev/IPC_Lib_Contracts.git
cd IPC_Lib_Contracts

# Compilar
cargo build --release

# Instalar CLI
cargo install --path . --bin contractc
```

## Uso

### 1. Definir Contrato (DSL)

```dsl
contract "image_processor" {

    version 1.0.0
    namespace "com.example"
    role mutual

    security {
        authentication required
        encryption required
        replay_protection required
    }

    type Image {
        data: bytes
        width: u32
        height: u32
        format: string
    }

    operation resize {
        input {
            image: Image
            target_width: u32
            target_height: u32
        }
        output Image
        timeout 15s
        idempotent true
    }
}
```

### 2. Compilar a Binario

```bash
contractc compile image_processor.contract -o output/
```

### 3. Generar Bindings

```bash
# Rust
contractc generate output/image_processor.cbc --target rust -o generated/rust/

# Kotlin
contractc generate output/image_processor.cbc --target kotlin -o generated/kotlin/

# TypeScript
contractc generate output/image_processor.cbc --target typescript -o generated/ts/
```

### 4. Usar en Runtime

**Rust:**
```rust
use image_processor::*;

let mut session = ContractSession::new(contract, session_id);
let resized = session.resize(&input_data)?;
```

**Kotlin:**
```kotlin
val session = ContractSession(sessionId, contract)
val resized = session.resize(inputData)
```

**TypeScript:**
```typescript
const session = new ImageProcessorSession(sessionId);
const resized = await session.resize(inputData);
```

## Comparación v1 vs v2

| Aspecto | v1 | v2 |
|---------|----|----|
| Formato | YAML | Binario CBC |
| Tipos | Strings ("array<f32>") | IDs numéricos |
| Operaciones | Strings ("resize") | IDs numéricos |
| Seguridad | XOR (NO seguro) | ChaCha20-Poly1305 |
| Checksum | xxHash64 | BLAKE3-256 |
| Anti-replay | Básico | Ventana deslizante |
| Handshake | Simple | Con autenticación |

## Estructura del Proyecto

```
ipc-kotlin-rust-v2/
├── src/                           # Core Rust
│   ├── lib.rs                     # Exports principales
│   ├── binary_contract.rs         # Formato CBC
│   ├── types.rs                  # Sistema de tipos
│   ├── operations.rs              # Sistema de operaciones
│   ├── security.rs                # Criptografía
│   ├── protocol.rs                # Wire protocol v2
│   ├── error.rs                  # Manejo de errores
│   ├── generators/               # Generadores de código
│   │   └── mod.rs
│   └── bin/
│       ├── contractc.rs           # CLI del compilador
│       └── ipc_engine_v2.rs      # Motor de runtime
│
├── kotlin_bindings/               # Bindings Kotlin/JVM
│   ├── src/main/kotlin/com/ipc/contract/
│   │   ├── Contract.kt          # Tipos base y contrato
│   │   ├── Serializer.kt        # Serialización
│   │   ├── Frame.kt             # Frame wire
│   │   ├── Session.kt           # Sesión de contrato
│   │   ├── Client.kt            # Cliente IPC
│   │   └── Security.kt          # Utilidades de seguridad
│   └── build.gradle.kts
│
├── cpp_bindings/                  # Bindings C++ (feature)
│   ├── include/ipc/
│   │   ├── contract.hpp         # Tipos base
│   │   ├── client.hpp           # Cliente IPC
│   │   └── security.hpp         # Utilidades de seguridad
│   ├── src/
│   │   ├── contract.cpp
│   │   ├── client.cpp
│   │   └── security.cpp
│   └── CMakeLists.txt
│
├── contracts/                     # Contratos de ejemplo
│   └── image_processor.contract
│
├── docs/                          # Documentación técnica
│   ├── CONTRACTS.md             # Sistema de contratos
│   ├── PROTOCOL.md              # Protocolo wire
│   ├── SECURITY.md              # Seguridad criptográfica
│   └── ADR.md                   # Architecture Decision Records
│
├── DSL.md                        # Documentación del DSL
├── Cargo.toml
└── README.md
```

## Bindings Disponibles

### Kotlin (JVM/Android)

```kotlin
// Gradle
implementation("com.ipc:contract-system:1.0.0")

// Uso
val client = IpcClientBuilder()
    .contract("/path/to/contract.cbc")
    .unixSocket("/tmp/ipc.sock")
    .seed("my-secret-seed")
    .mode(ExecutionMode.MESSAGE_RESPONSE)
    .build()

client.connect()
val result = client.request("resize", payload)
```

### C++ (requiere CMake)

```cmake
# CMakeLists.txt
find_package(ipc REQUIRED)
target_link_libraries(my_app ipc::client ipc::security)

# Código
#include <ipc/client.hpp>

auto client = ipc::IpcClientBuilder()
    .contract("/path/to/contract.cbc")
    .unix_socket("/tmp/ipc.sock")
    .seed("my-secret-seed")
    .build();

client->connect();
auto result = client->request("resize", payload);
```

### Rust

```rust
use ipc_contract_system::{Contract, ContractSession};

let contract = Contract::load("contract.cbc")?;
let mut session = ContractSession::new(contract, session_id);
let result = session.call("resize", payload)?;
```

## Documentación

- [Sitio documental publicado](https://ipc-lib-contracts-docs.netlify.app) — HTML estático desplegado independientemente en Netlify
- Para regenerar localmente: `python3 tools/render_docs.py`

- [DSL.md](DSL.md) - Gramática y ejemplos del DSL
- [docs/CONTRACTS.md](docs/CONTRACTS.md) - Sistema de contratos binarios
- [docs/PROTOCOL.md](docs/PROTOCOL.md) - Protocolo wire v2
- [docs/SECURITY.md](docs/SECURITY.md) - Seguridad criptográfica
- [docs/ADR.md](docs/ADR.md) - Architecture Decision Records

## License

MIT OR Apache-2.0
