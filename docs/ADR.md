# Architecture Decision Records (ADR)

## IPC Kotlin-Rust v2 - Sistema de Contratos Binarios Canónicos

---

## ADR-001: Comunicación Inter-Proceso Sin FFI

**Estado**: Aceptado
**Fecha**: 2025-09-23
**Decisor**: Sistema de diseño

### Contexto

Se requiere comunicación entre aplicaciones Kotlin (Android/JVM) y procesos Rust/CPP/Zig para procesamiento de bajo nivel, evitando:
- FFI (Foreign Function Interface)
- Librerías compartidas (.so, .dll, .dylib)
- Memoria compartida

### Decisión

Usar **Unix Domain Sockets** como transporte principal con el protocolo CBC (Canonical Binary Contract):

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ARQUITECTURA DE COMUNICACIÓN                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌─────────────────┐              ┌─────────────────┐              │
│   │   KOTLIN APP    │              │   RUST/CPP/ZIG  │              │
│   │                 │              │                 │              │
│   │  ┌───────────┐  │    SOCKET    │  ┌───────────┐  │              │
│   │  │  Client   │──┼──────────────┼──│  Server   │  │              │
│   │  │  (JVM)    │  │  Unix Domain │  │  (Native) │  │              │
│   │  └───────────┘  │   Socket    │  └───────────┘  │              │
│   │                 │              │                 │              │
│   └─────────────────┘              └─────────────────┘              │
│                                                                      │
│   Protocolo: CBC (Canonical Binary Contract)                        │
│   Serialización: Binaria con tipos numéricos                         │
│   Seguridad: AEAD (ChaCha20-Poly1305 / AES-256-GCM)                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Consecuencias

**Positivas**:
- Aislamiento completo entre procesos
- No hay memory leaks entre límites de lenguaje
- Seguridad de memoria garantizada por el runtime de cada proceso
- Facilidad de debugging (procesos separados)

**Negativas**:
- Overhead de serialización/deserialización
- Latencia mayor que memoria compartida
- Requiere sistema de archivos para Unix Sockets

---

## ADR-002: Contratos Binarios Canónicos (CBC)

**Estado**: Aceptado
**Fecha**: 2025-09-23

### Contexto

Se necesita un formato de contrato que sea:
- Inmutable una vez compilado
- Verificable criptográficamente
- Rápido de parsear en runtime
- Portable entre lenguajes

### Decisión

Crear formato CBC (Canonical Binary Contract) con header fijo de 256 bytes:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FORMATO CBC (256 bytes)                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Offset 0-3:    MAGIC (4 bytes) - "CBC1"                            │
│  Offset 4:      Format Version (1 byte)                              │
│  Offset 5-8:    Flags (4 bytes)                                      │
│  Offset 9-10:   Header Size (2 bytes) - 256                          │
│  Offset 11-18:  Contract ID (8 bytes)                                │
│  Offset 19-24:  Version (3 x uint16)                                 │
│  Offset 25-56:  Contract Hash BLAKE3-256 (32 bytes)                  │
│  Offset 57-88:  Types Section Offset/Size                            │
│  Offset 89-120: Operations Section Offset/Size                       │
│  Offset 121-136: Security Policy Offset/Size                         │
│  Offset 137-138: Name/Namespace Lengths                              │
│  Offset 139-202: Name (64 bytes)                                     │
│  Offset 203-266: Namespace (64 bytes)                                 │
│  Offset 267-384: Reserved                                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Beneficios

1. **Parsing O(1)**: Header de tamaño fijo permite acceso directo a campos
2. **Verificable**: Hash BLAKE3-256 de todo el contrato (excepto firma) - identidad primaria
3. **Portable**: Formato big-endian, sin padding específico de arquitectura
4. **Firmable**: 64 bytes al final para firma Ed25519

---

## ADR-003: Sistema de Tipos con IDs Numéricos

**Estado**: Aceptado
**Fecha**: 2025-09-23

### Contexto

Se necesita eliminar parsing de strings en runtime para maximizar performance.

### Decisión

Usar IDs numéricos de 16 bits para tipos y operaciones:

```rust
// Tipos primitivos
pub enum PrimitiveType {
    U8 = 0x0001,
    U16 = 0x0002,
    U32 = 0x0003,
    U64 = 0x0004,
    // ...
    String = 0x000C,
    Bytes = 0x000D,
}

// Operaciones reservadas
pub const OP_HANDSHAKE: u16 = 0x0000;
pub const OP_AUTH: u16 = 0x0001;
pub const OP_PING: u16 = 0x0002;
```

### Beneficios

- Eliminación de string comparison en hot paths
- Serialización más compacta
- Lookup O(1) en hashmap
- Prevención de typos en tiempo de compilación (enum en Rust)

---

## ADR-004: Seguridad Criptográfica Real

**Estado**: Aceptado
**Fecha**: 2025-09-23
**Revisado**: Reemplazó XOR "encryption" (inseguro)

### Decisión Anterior (Descartada)

```rust
// ❌ NO USAR - XOR no es encriptación
fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect()
}
```

### Decisión Actual

**AEAD con ChaCha20-Poly1305** (preferido) o AES-256-GCM:

```rust
// ✅ AEAD real con autenticación
pub struct AeadCipher;

impl AeadCipher {
    pub fn encrypt_chacha20(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        // ChaCha20-Poly1305 proporciona:
        // - Confidencialidad (encriptación)
        // - Autenticidad (verificación de integridad)
        // - Anti-replay (con nonce único)
    }
}
```

### Hash Criptográfico

```rust
// ❌ NO USAR - xxHash no es criptográfico
// ✅ USAR - BLAKE3-256 (SHA-256 sólo como digest legacy opcional)
pub fn calculate_contract_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}
```

---

## ADR-005: Key Derivation desde Seed

**Estado**: Aceptado
**Fecha**: 2025-09-23

### Contexto

El usuario solicitó "semilla de emisor receptor único" similar a SSH/mTLS.

### Decisión

Derivar claves usando HKDF-like construction:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    KEY DERIVATION CHAIN                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Seed ─────────┬──────────────────────────────────────────┐        │
│                 │                                                  │        │
│                 ▼                                                  │        │
│         Session Key ◄── HMAC-SHA256(seed, contract_hash || id)      │        │
│                 │                                                  │        │
│        ┌────────┴────────┐                                         │        │
│        │                 │                                         │        │
│        ▼                 ▼                                         │        │
│   Auth Key          Encryption Key                                  │        │
│   (HMAC)            (AEAD)                                         │        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Implementación

```rust
pub fn derive_session_key(seed: &[u8], contract_hash: &[u8; 32], session_id: u64) -> [u8; 32] {
    let info = format!("session{}{:016x}", hex::encode(contract_hash), session_id);
    hmac_sha256(seed, info.as_bytes())
}
```

---

## ADR-006: Modos de Ejecución

**Estado**: Aceptado
**Fecha**: 2025-09-23

### Decisión

Soportar 4 modos de ejecución:

| Modo | Descripción | Sesión | Respuesta |
|------|-------------|--------|-----------|
| `MESSAGE_RESPONSE` | Request-Response clásico | Persistente | Sí |
| `MULTIPLEXING` | Múltiples operaciones concurrentes | Persistente | Sí |
| `FIRE_AND_FORGET` | Enviar y olvidar | Temporal | No |
| `REAL_TIME` | Streaming continuo | Persistente | Sí |

```
┌─────────────────────────────────────────────────────────────────────┐
│                         MODOS DE EJECUCIÓN                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  MESSAGE_RESPONSE:                                                   │
│  ┌──────┐  request(id=1)  ┌──────┐  response(id=1)  ┌──────┐      │
│  │Client│ ───────────────► │Server│ ────────────────► │Client│      │
│  └──────┘                 └──────┘                  └──────┘      │
│                                                                      │
│  FIRE_AND_FORGET:                                                    │
│  ┌──────┐  event ─────────► ┌──────┐                                │
│  │Client│ ───────────────► │Server│                                 │
│  └──────┘                 └──────┘                                 │
│                                                                      │
│  REAL_TIME (Streaming):                                              │
│  ┌──────┐  start ─────────► ┌──────┐  stream ─────────► ┌──────┐   │
│  │Client│ ◄─────────────── │Server│ ◄─────────────── │Client│   │
│  │      │   data frames    │      │   data frames    │      │   │
│  │      │ ◄─────────────── │      │ ◄─────────────── │      │   │
│  └──────┘  end ───────────► └──────┘                  └──────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ADR-007: Roles de Contrato

**Estado**: Aceptado
**Fecha**: 2025-09-23

### Decisión

Definir 6 roles de contrato:

| Rol | Valor | Descripción |
|-----|-------|-------------|
| `CHILD` | 0x01 | Proceso subordinado/controlado |
| `MUTUAL` | 0x02 | Ambos pueden iniciar operaciones |
| `PEER` | 0x03 | Comunicación simétrica P2P |
| `MUX` | 0x04 | Múltiples canales lógicos |
| `STREAM` | 0x05 | Flujo persistente |
| `ONEWAY` | 0x06 | Solo envío |

---

## ADR-008: Anti-Replay Protection

**Estado**: Aceptado
**Fecha**: 2025-09-23

### Decisión

Implementar ventana deslizante para detectar ataques de replay:

```rust
pub struct AntiReplay {
    seen_nonces: HashMap<u64, u64>,  // nonce -> timestamp
    window_size: usize,
}

impl AntiReplay {
    pub fn check_and_mark(&mut self, nonce: u64) -> bool {
        // Si nonce ya fue usado, es replay
        if self.seen_nonces.contains_key(&nonce) {
            return false;
        }
        // Registrar nonce
        self.seen_nonces.insert(nonce, now());
        true
    }
}
```

### Consideraciones

- Nonce: 96 bits (12 bytes) para evitar colisiones
- Limpieza periódica de nonces antiguos (>1 minuto)
- Almacenamiento en memoria (no persistente entre reinicios)

---

## ADR-009: DSL para Definición de Contratos

**Estado**: Aceptado
**Fecha**: 2025-09-23

### Decisión

Crear DSL para authoring de contratos con output binario:

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
    }

    operation resize {
        input { image: Image, width: u32, height: u32 }
        output Image
        timeout 15s
        idempotent true
    }
}
```

### Beneficios

- Legible por humanos para debugging
- Validación en tiempo de compilación
- Output: archivo `.cbc` binario
- Generadores de código para Rust, Kotlin, TypeScript

---

## ADR-010: Generadores de Código por Lenguaje

**Estado**: Aceptado
**Fecha**: 2025-09-23

### Decisión

Generar bindings tipados para cada lenguaje:

```
contracts/image_processor.cbc
        │
        ├──► generator_rust ──► image_processor.rs
        │                          ├── struct Image
        │                          ├── fn resize(...)
        │                          └── impl Contract
        │
        ├──► generator_kotlin ─► ImageProcessorContract.kt
        │                          ├── data class Image
        │                          ├── suspend fun resize(...)
        │                          └── class ContractSession
        │
        └──► generator_typescript ─► image-processor.ts
                                    ├── interface Image
                                    ├── async function resize(...)
                                    └── class ContractClient
```

### Beneficios

- Type safety en todos los lenguajes
- API idiomática por lenguaje
- Compilación separada de contrato

---

## ADR-011: Bug de Buffer Overflow Corregido

**Estado**: Corregido
**Fecha**: 2025-09-23
**Issue**: Header de paquete con tamaño incorrecto

### Problema Original

```rust
// ❌ Código original con bug
pub struct PacketHeader {
    magic: [u8; 4],      // offset 0-3
    version: u8,          // offset 4
    timestamp: u64,      // offset 5-12 (8 bytes)
    // ...
}

impl PacketHeader {
    pub const SIZE: usize = 40;  // ❌ INCORRECTO

    pub fn timestamp(&self) -> u64 {
        u64::from_be_bytes(self.bytes[5..13].try_into().unwrap())
        //                                     ^^
        //                         Buffer overflow! 13 > 40
    }
}
```

### Corrección

```rust
// ✅ Código corregido
pub struct Frame {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: FrameFlags,
    pub packet_type: PacketType,
    pub role: ContractRole,
    pub session_id: u64,
    pub sequence: u64,
    pub channel_id: u32,
    pub operation_id: OperationId,
    pub payload_length: u32,
    pub schema_id: TypeId,
    pub contract_hash_prefix: [u8; 12],
    pub nonce: [u8; 12],
}

impl Frame {
    pub const HEADER_SIZE: usize = 64;  // ✅ CORRECTO
}
```

---

## ADR-012: v2.1 Security/Protocol Correctness

**Estado**: Aceptado
**Fecha**: 2025-09-23
**Revisión**: Basado en revision-2.txt

### Cambios de Protocolo

#### 1. PacketType Sin Colisión

```
Close          0x00
Hello          0x01
HelloAck       0x02
HelloNack      0x03

Auth           0x10
AuthOk         0x11
AuthNok        0x12

Request        0x20
Response       0x21
ResponseError  0x22

StreamStart    0x30
StreamData     0x31
StreamEnd      0x32
StreamPause    0x33
StreamResume   0x34

Error          0xE0  ← Corregido (antes 0xFF)
ProtocolError  0xE1
SecurityError  0xE2
TimeoutError   0xE3

Heartbeat      0xF0
HeartbeatAck   0xF1

Ping           0xFE
Pong           0xFF
```

#### 2. Anti-Replay con Ventana Deslizante

```
AntiReplay
└── session_id
    ├── highest_sequence: u64
    ├── bitmap: Vec<u64>  (ventana configurable)
    └── last_cleanup: Instant

Lógica:
- sequence <= highest - window → reject
- sequence already received → reject
- otherwise → accept y actualizar bitmap
```

#### 3. Nonce Vinculado a Sesión

```rust
pub fn derive_nonce(&self, direction: u8) -> [u8; 12] {
    // nonce = BLAKE3(session_id || sequence || direction)
    let mut hasher = Hasher::new();
    hasher.update(b"CBC2-NONCE");
    hasher.update(&self.session_id.to_le_bytes());
    hasher.update(&self.sequence.to_le_bytes());
    hasher.update(&[direction]);
    let mut output = [0u8; 12];
    output.copy_from_slice(&hasher.finalize().as_bytes()[..12]);
    output
}
```

#### 4. AAD Expandido (48 bytes)

```
magic (4) | version (1) | flags (1) | packet_type (1) | role (1)
session_id (8) | sequence (8) | channel_id (4) | operation_id (2)
payload_length (4) | schema_id (2) | contract_hash_prefix (12)
```

#### 5. BLAKE3-256 como Identidad Primaria

- **Primario**: `contract_hash = BLAKE3-256(canonical_contract)`
- **Compatibilidad**: SHA-256 disponible como digest legacy, nunca como `contract_hash`

### Cambios de Seguridad

- Eliminación completa de `unwrap()` en parsing de datos remotos
- Validación explícita de `MAX_PAYLOAD_SIZE = 16 MB`
- FrameFlags con validación de bits desconocidos (reject-by-default)
- HMAC con implementación formal usando crate `hmac`

### Errores de Protocolo Expandidos

```rust
pub enum ProtocolError {
    FrameTooShort,
    InvalidMagic,
    IncompatibleVersion(u8),
    InvalidPacketType(u8),
    InvalidRole(u8),
    PayloadTooShort,
    PayloadTooLarge { declared: u32, maximum: u32 },
    FrameSizeMismatch { expected: usize, actual: usize },
    DecryptionFailed,
    AuthenticationFailed,
    AntiReplayDetected,
    ParseError(&'static str),
    InvalidNonce,
}
```

---

## ADR-013: Herramientas CLI de Verificación

**Estado**: Aceptado
**Fecha**: 2025-09-23

### contractc verify

Verifica integridad de un archivo `.cbc`:

```
contractc verify image_processor.cbc

CBC VALID

Format:       1
Protocol:     2
Contract:     1.0.0

Hash:
b3:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Signature:
Ed25519 / VALID

Sections:
schema    VALID
types     VALID
operations VALID
security  VALID
```

### contractc inspect

Muestra información estructurada de un contrato:

```
contractc inspect contract.cbc

Contract: image_processor
Namespace: com.example
Version: 1.0.0
ID: 550e8400-e29b-41d4-a716-446655440000

Types: 5
  - Image (0x0001)
  - Rectangle (0x0002)
  - ...

Operations: 3
  - resize (0x0001)
  - crop (0x0002)
  - ...

Security Policy:
  authentication: required
  encryption: required
  replay_protection: required
```

### contractc hash

Calcula y muestra el hash del contrato:

```
contractc hash contract.cbc

Contract Hash (BLAKE3-256):
b3:a1b2c3d4e5f6...7890abcdef
```

### contractc dump

Dump hexadecimal del contrato:

```
contractc dump contract.cbc

00000000: 4342 4331 0101 0000 ...  (header)
00000100: 696d 6167 655f 7072 ...  (types)
...
```

### contractc generate

Genera bindings para un target:

```
contractc generate contract.cbc --target rust
contractc generate contract.cbc --target kotlin
contractc generate contract.cbc --target cpp
```

---

## Resumen de Decisiones

| ADR | Título | Estado |
|-----|--------|--------|
| 001 | Comunicación Sin FFI | Aceptado |
| 002 | Contratos Binarios Canónicos | Aceptado |
| 003 | IDs Numéricos para Tipos | Aceptado |
| 004 | Seguridad Criptográfica Real | Aceptado |
| 005 | Key Derivation desde Seed | Aceptado |
| 006 | Modos de Ejecución | Aceptado |
| 007 | Roles de Contrato | Aceptado |
| 008 | Anti-Replay Protection | Aceptado |
| 009 | DSL de Contratos | Aceptado |
| 010 | Generadores de Código | Aceptado |
| 011 | Bug Buffer Overflow | Corregido |
| 012 | v2.1 Security/Protocol Correctness | Aceptado |
| 013 | Herramientas CLI de Verificación | Aceptado |
| 0006 | Verificación de firma en el tipo | Aceptado |
| 0007 | BLAKE3 con árbol de sub-chunks completo | Aceptado |

## ADR-0006: Verificacion de firma en el tipo

**Estado**: Aceptado (2.1.2)
**Fecha**: 2026-09-30

### Contexto

`ContractReader::from_bytes` comprobaba la integridad del contrato (el
`contract_hash` recalculado coincidía) y comprobaba que la firma **estuviera
presente** cuando la política la exigía. No la verificaba
criptográficamente, porque no recibía una clave pública.

La causa era correcta: el lector no tiene un ancla de confianza. Una clave
pública incluida dentro del propio contrato no sirve como ancla, porque un
atacante puede sustituir contrato y clave simultáneamente, y ambos pasarían la
comprobación.

El problema era la **superficie de la API**. Devolver un `Contract` normal
desde `from_bytes` permite que un integrador lo trate como verificado:

```rust
// Antes: compila, y parece que el contrato está verificado.
let contract = ContractReader::from_bytes(&bytes)?;
start_session(contract);
```

La separación real estaba en otra función, `ContractSigner::verify`, que sí
recibe la clave. Nada en el sistema de tipos impedía saltarse el paso, y el
nombre `from_bytes` no sugiere que falte verificación.

### Alternativas consideradas

1. **Documentarlo y confiar en el integrador.** Es lo que había. Un error de
   uso pasa inadvertido y no lo detecta ni el compilador ni los tests.

2. **Añadir un parámetro `Option<VerifyingKey>` a `from_bytes`.** Mismo
   problema: `None` es indistinguible de un contrato verificado.

3. **Tipos separados.** `from_bytes` devuelve `UnverifiedContract`, que no
   expone los datos del contrato más que para inspección, y sólo
   `verify` con una clave externa produce un `VerifiedContract`.

### Decisión

Separar los dos estados en el sistema de tipos.

```rust
let candidate = ContractReader::parse(&bytes)?;      // UnverifiedContract
let verified  = candidate.verify(&trusted_key)?;      // VerifiedContract
```

Atajo equivalente:

```rust
let verified = ContractReader::from_bytes_verified(&bytes, &trusted_key)?;
```

`UnverifiedContract` no implementa `Deref<Target = Contract>` a propósito: sin
eso, `&*unverified` daría acceso directo a los campos. El contrato sólo es
accesible vía `inspect()`, que documenta en el punto de llamada que se está
mirando algo sin verificar.

### Ancla de confianza

La clave pública debe venir del anfitrión, nunca del contrato:

- fijada en configuración;
- almacén local de claves autorizadas;
- rotación identificada por `key_id`;
- PKI externa, si el despliegue lo requiere.

Se añade `key_id` al header CBC1, en el offset 224, que hasta ahora era zona
reservada. No cambia el tamaño del header ni desplaza ningún offset. Al estar
dentro del header canónico, queda cubierto por `contract_hash` y por la firma,
de modo que alterarlo invalida ambas cosas.

`key_id` **no** es un ancla de confianza por sí mismo: sólo sirve para elegir
qué clave de un almacén externo usar.

La firma cubre el preimagen canónico completo: header con el hash a cero,
tipos, operaciones y política de seguridad. `ContractSigner::signing_payload`
ya hacía esa normalización.

### Consecuencias

- `from_bytes` pasa a devolver `UnverifiedContract`. Es un cambio de API
  incompatible, y deliberado: la v2.1.1 exponía un uso que parecía seguro.
- Los comandos de inspección de `contractc` usan `inspect()` explícitamente.
- `contractc verify --check-signature` sin `--verify-key` ya no imprime
  `Ed25519 / VALID`: dice que la firma no se ha verificado. Antes, sin clave y
  sin el flag `SIGNED`, imprimía `VALID` sin haber validado nada.
- El espacio reservado 228..255 pasa a exigirse cero, por el mismo motivo que
  el relleno de los campos de texto.

### Bug encontrado al escribir los tests

El test que recorre todas las posiciones del archivo y altera un byte en cada
una destapó una ambigüedad de representación: con `schema_size == 0`, tanto
`schema_offset == 0` como `schema_offset == 256` describen el mismo contrato.
Como el preimagen pone los offsets a cero, alternar entre ambos no cambiaba ni
el hash ni la firma: el mismo contrato tenía dos formas byte-distintas.

`finalize()` ahora escribe `schema_offset = 0` y el lector exige ese valor.
Un contrato no puede representarse de dos maneras.

Este caso no estaba en la especificación de PR1. Lo encontró el criterio de
aceptación, que pedía exactamente "byte modificado en cualquier sección:
rechazo".

## ADR-0007: BLAKE3 con arbol de sub-chunks completo

**Estado**: Aceptado (2.1.2)
**Fecha**: 2026-09-30

### Contexto

Las implementaciones de BLAKE3 en C++ y Kotlin soportaban **un solo chunk**
(1024 bytes) y lanzaban excepción más allá. El motivo era preferible a lo
contrario —devolver un digest incorrecto en silencio habría sido peor— pero
dejaba el sistema incompleto: un contrato CBC con header, tipos, operaciones
y política **supera 1024 bytes con facilidad**, y ningún test lo detectaba
porque todos los vectores eran pequeños.

Eliminar la excepción sin implementar el árbol habría producido hashes
incorrectos.

### Decisión

Implementar el árbol de sub-chunks completo según la especificación oficial de
BLAKE3, más una API incremental.

```
Blake3Hasher h;
h.update(a);
h.update(b);
auto digest = h.finalize();
```

El resultado no depende de la partición, que es la propiedad que comprueban los
tests: `update(a); update(b)` debe coincidir con `hash(a ++ b)`.

### Estructura

Se sigue a la implementación de referencia:

- `ChunkState` mantiene el chaining value, el contador y el bloque en curso.
- Al llenarse un chunk (1024 bytes), su chaining value se apila y se empieza
  otro con el contador siguiente.
- La pila mantiene sub-chunks cuyo número de chunks completados es
  **estrictamente decreciente de abajo hacia arriba**. Ese invariante es lo que
  garantiza que la forma final sea el árbol canónico.
- Al añadir un chunk se colapsa la pila de izquierda a derecha mientras el
  número total de chunks sea par.
- Al finalizar, los sub-chunks pendientes se combinan de derecha a izquierda
  con el chunk en curso, y el nodo resultante se comprime con el flag `ROOT`.

El digest es el resultado de esa compresión raíz. El *chaining value* de un
nodo intermedio es una operación distinta: se usa para encadenar, no como
salida.

### Modo keyed

El flag `KEYED_HASH` se propaga a **todas** las compresiones, incluidas las de
los nodos padre del árbol. Es el mismo requisito que ya exigía el modo de un
solo chunk.

### Límite eliminado

No se fija un nuevo límite. El criterio de aceptación es que `contract_hash`
pueda calcularse para cualquier contrato dentro del límite global razonable
del protocolo, sin que 1024 bytes sea un límite artificial de los bindings.
Subir el límite a 16 MiB sin implementar el árbol sólo habría desplazado el
fallo.

### Vectores

Regenerables con:

```bash
cargo run --example blake3_multichunk_vectors
```

Cubren longitudes 0, 1, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025, 2047,
2048, 2049, 3072, 4096, 4097, 8192 y 1 MiB, con datos a cero y pseudoaleatorios
deterministas, en modo normal y keyed.

Se incluyen casos que no son potencia de dos a propósito: son los que
descubren errores en el colapso de la pila.

Los vectores existentes de hasta 1024 bytes **no cambian**: añadir soporte
multi-chunk no altera los hashes previos.

### Dos errores que costaron tiempo

1. **Plegar el estado dentro de la primitiva.** Al reescribir `compress` para
   soportar el árbol, se hizo que devolviera el chaining value
   (`s[i] xor s[i+8]`) en lugar del estado completo de 16 palabras. El
   resultado era un hash incorrecto pero plausible que sólo aparecía al
   comparar con la referencia, y afectaba incluso a la entrada vacía.

2. **XOR en lugar de asignación.** Las cuatro últimas palabras del estado
   inicial (contador, longitud, flags) se inicializan **asignando**, no
   XOREando con el IV. Con `^=` el estado arranca en `IV[4..8]` y el hash
   cambia de forma igualmente silenciosa.

En los dos casos el código compilaba, los tests de conformidad fallaban, y el
detalle aparecía comparando palabra a palabra con la implementación de
referencia. Es exactamente el motivo por el que ningún binding delega en otro.

---

## Referencias

- Protocolo: `docs/PROTOCOL.md`
- Seguridad: `docs/SECURITY.md`
- Contratos: `docs/CONTRACTS.md`
- DSL: `DSL.md`
