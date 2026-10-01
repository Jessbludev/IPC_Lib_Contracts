# Sistema de Contratos Binarios Canónicos

## Conceptos Fundamentales

El sistema de contratos binarios canónicos (CBC) proporciona un mecanismo para definir interfaces de comunicación entre procesos de forma inmutable, versionada y criptográficamente verificable.

### Inmutabilidad del Contrato

Un contrato, una vez compilado y distribuido, **no puede ser modificado**. Cualquier cambio en la definición del contrato genera un nuevo hash de contrato, lo que invalida cualquier sesión existente.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CICLO DE VIDA DEL CONTRATO                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐      contractc       ┌──────────────────────┐    │
│   │  image_      │ ─────────────────>  │   image_processor.   │    │
│   │  processor.  │                     │   cbc                │    │
│   │  contract    │                     │                      │    │
│   └──────────────┘                     │  Hash: BLAKE3-256   │    │
│                                         │   {hash_prefix}     │    │
│                                         └──────────┬───────────┘    │
│                                                    │                │
│                                         ┌──────────▼───────────┐    │
│                                         │  Contrato Inmutable   │    │
│                                         │  - No editable        │    │
│                                         │  - No extensible      │    │
│                                         │  - Distribuido        │    │
│                                         └───────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### Versionado Semántico

Los contratos siguen versionado semántico (SemVer):

| Formato | Descripción |
|---------|-------------|
| `major.minor.patch` | Ejemplo: `1.2.3` |
| `major` | Cambios incompatibles en la API |
| `minor` | Nuevas funcionalidades compatibles |
| `patch` | Correcciones compatibles |

**Reglas de Compatibilidad:**

- Cambio en `patch`: Compatible hacia atrás
- Cambio en `minor`: Compatible hacia atrás, nuevo `minor` requiere nuevo contrato
- Cambio en `major`: Incompatible, requiere nuevo contrato

## Formato CBC (Canonical Binary Contract)

### Estructura General

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FORMATO BINARIO DEL CONTRATO                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────┬─────────────┬────────────┬─────────────┬────────────┐  │
│  │  MAGIC  │   HEADER    │   TYPES    │  OPERATIONS │   SIG     │  │
│  │  (4B)   │   (256B)    │   (var)    │   (var)    │   (64B)   │  │
│  └─────────┴─────────────┴────────────┴─────────────┴────────────┘  │
│                                                                      │
│  Hash BLAKE3-256: representación canónica sin firma, hash y offsets │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Header (256 bytes)

```rust
pub struct ContractHeader {
    // Identificación (16 bytes)
    pub magic: [u8; 4],              // "CBC1"
    pub format_version: u8,            // 0x01
    pub flags: ContractFlags,
    pub header_size: u16,             // 256

    // Identificador único (16 bytes)
    pub contract_id: u64,             // ID único del contrato
    pub version: ContractVersion,

    // Hash del contrato (32 bytes)
    pub contract_hash: [u8; 32],      // BLAKE3-256 de la forma canónica

    // Offsets y tamaños (24 bytes)
    pub types_offset: u32,
    pub types_size: u32,
    pub operations_offset: u32,
    pub operations_size: u32,
    pub security_policy_offset: u32,
    pub security_policy_size: u16,

    // Metadatos (variable, hasta offset 128)
    pub name_length: u8,
    pub namespace_length: u8,
    pub name: [u8; 64],              // Nombre del contrato
    pub namespace: [u8; 64],         // Namespace (ej: "com.example")

    // Reserved (hasta 256 bytes)
    reserved: [u8; 128],
}
```

### Sección de Tipos

Cada tipo tiene un ID numérico único asignado por el compilador:

```rust
pub struct TypeDefinition {
    pub type_id: u16,           // 0x0001 - 0xFFFF
    pub name_length: u8,
    pub name: String,
    pub kind: TypeKind,
    pub fields: Vec<FieldDefinition>,
}

pub enum TypeKind {
    Primitive(PrimitiveType),
    Array { element_type: u16, length: u32 },
    Struct,
    Enum,
    Map { key_type: u16, value_type: u16 },
}
```

**IDs de Tipos Primitivos:**

| ID | Tipo | Descripción |
|----|------|-------------|
| 0x0001 | U8 | Entero sin signo 8-bit |
| 0x0002 | U16 | Entero sin signo 16-bit |
| 0x0003 | U32 | Entero sin signo 32-bit |
| 0x0004 | U64 | Entero sin signo 64-bit |
| 0x0005 | I8 | Entero con signo 8-bit |
| 0x0006 | I16 | Entero con signo 16-bit |
| 0x0007 | I32 | Entero con signo 32-bit |
| 0x0008 | I64 | Entero con signo 64-bit |
| 0x0009 | F32 | Flotante 32-bit IEEE 754 |
| 0x000A | F64 | Flotante 64-bit IEEE 754 |
| 0x000B | Bool | Booleano |
| 0x000C | String | String UTF-8 |
| 0x000D | Bytes | Datos binarios |

### Sección de Operaciones

```rust
pub struct OperationDefinition {
    pub operation_id: u16,       // 0x0001 - 0xFFFF
    pub name_length: u8,
    pub name: String,
    pub input_type_id: u16,     // Tipo del input
    pub output_type_id: u16,    // Tipo del output
    pub timeout_ms: u32,
    pub role: OperationRole,
    pub flags: OperationFlags,
}

pub enum OperationRole {
    RequestResponse = 0x01,
    OneWay = 0x02,
    StreamStart = 0x03,
    StreamData = 0x04,
    StreamEnd = 0x05,
}
```

## Roles de Contrato

El rol define el patrón de comunicación entre los extremos:

### Child (0x01)

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ROL CHILD                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐                         ┌──────────────┐        │
│   │   PARENT     │                         │    CHILD     │        │
│   │   PROCESS    │                         │   PROCESS    │        │
│   │              │                         │              │        │
│   │  ┌────────┐  │──── REQUEST ─────────>  │              │        │
│   │  │Server  │  │                         │  ┌────────┐  │        │
│   │  └────────┘  │<──── RESPONSE ──────────│  │Client  │  │        │
│   │              │                         │  └────────┘  │        │
│   └──────────────┘                         └──────────────┘        │
│                                                                      │
│   Características:                                                    │
│   - Solo el padre inicia operaciones                                  │
│   - El hijo solo responde a requests                                  │
│   - Típico para workers/slaves                                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Mutual (0x02)

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ROL MUTUAL                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐                         ┌──────────────┐        │
│   │   PROCESS A  │                         │  PROCESS B   │        │
│   │              │                         │              │        │
│   │  ┌────────┐  │                         │  ┌────────┐  │        │
│   │  │Server  │  │<────── REQUEST ──────────│  │Client  │  │        │
│   │  │Client  │  │─────── RESPONSE ────────>│  │Server  │  │        │
│   │  └────────┘  │                         │  └────────┘  │        │
│   │              │────── REQUEST ──────────>│              │        │
│   │              │<────── RESPONSE ──────────│              │        │
│   └──────────────┘                         └──────────────┘        │
│                                                                      │
│   Características:                                                    │
│   - Ambos procesos pueden iniciar                                    │
│   - Cada uno tiene servidor y cliente                                │
│   - Simétrico bidireccional                                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Peer (0x03)

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ROL PEER                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐                         ┌──────────────┐        │
│   │    PEER A    │                         │   PEER B     │        │
│   │              │                         │              │        │
│   │   DHT-style  │<────── ANNOUNCE ────────│  DHT-style  │        │
│   │              │─────── LOOKUP ──────────>│              │        │
│   │              │<─────── RESULT ──────────│              │        │
│   │              │                         │              │        │
│   └──────────────┘                         └──────────────┘        │
│                                                                      │
│   Características:                                                    │
│   - Sin relación cliente/servidor                                    │
│   - Comunicación simétrica                                           │
│   - Típico para sistemas DHT, P2P                                    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Mux (0x04)

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ROL MUX                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐                         ┌──────────────┐        │
│   │   PROCESS    │                         │   PROCESS    │        │
│   │              │                         │              │        │
│   │  Channel 1   │<───────────────────────│  Channel 1   │        │
│   │  Channel 2   │<───────────────────────│  Channel 2   │        │
│   │  Channel 3   │<───────────────────────│  Channel 3   │        │
│   │     ...      │                         │     ...      │        │
│   └──────────────┘                         └──────────────┘        │
│                                                                      │
│   Características:                                                    │
│   - Múltiples canales lógicos                                       │
│   - Cada canal tiene su propio Channel ID                           │
│   - Isolación entre canales                                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Stream (0x05)

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ROL STREAM                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐                         ┌──────────────┐        │
│   │   PROCESS    │                         │   PROCESS    │        │
│   │              │                         │              │        │
│   │  ┌────────┐  │                         │  ┌────────┐  │        │
│   │  │Stream  │  │                         │  │Stream  │  │        │
│   │  │Handler │  │                         │  │Handler │  │        │
│   │  └────────┘  │                         │  └────────┘  │        │
│   │              │                         │              │        │
│   └──────────────┘                         └──────────────┘        │
│          │                                        │                 │
│          ▼                                        ▼                 │
│   ┌─────────────────────────────────────────────────────┐           │
│   │                    STREAM FLOW                        │           │
│   ├─────────────────────────────────────────────────────┤           │
│   │  START ──> [DATA] ──> [DATA] ──> [DATA] ──> END   │           │
│   │           pause/resume en cualquier punto            │           │
│   └─────────────────────────────────────────────────────┘           │
│                                                                      │
│   Características:                                                    │
│   - Conexión persistente                                            │
│   - Flujo de datos en tiempo real                                   │
│   - Control de flujo (pause/resume)                                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### OneWay (0x06)

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ROL ONEWAY                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐                         ┌──────────────┐        │
│   │   SENDER     │ ──────── DATA ─────────>│   RECEIVER   │        │
│   │              │ ──────── DATA ─────────>│              │        │
│   │              │ ──────── DATA ─────────>│              │        │
│   │              │ ──────── CLOSE ────────>│              │        │
│   └──────────────┘                         └──────────────┘        │
│                                                                      │
│   Características:                                                    │
│   - Sin respuesta esperada                                            │
│   - Fire-and-forget                                                  │
│   - Eventos, logs, métricas                                          │
│   - No requiere ACK                                                  │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Ejemplo: Compilación de Contrato

### Entrada (DSL)

```dsl
contract "calculator" {
    version 1.0.0
    namespace "com.example"
    role mutual

    security {
        authentication required
        encryption required
        replay_protection required
    }

    type Operation {
        left: f64
        right: f64
        operator: string  // "+", "-", "*", "/"
    }

    operation compute {
        input Operation
        output f64
        timeout 5s
        idempotent true
    }
}
```

### Salida (CBC Binario)

```
$ contractc compile calculator.contract -o output/

[INFO] Compilando: calculator.contract
[INFO] Nombre: calculator
[INFO] Namespace: com.example
[INFO] Versión: 1.0.0
[INFO] Rol: Mutual
[INFO] Seguridad: auth + enc + replay
[INFO] Tipos compilados: 2
       - Operation (ID: 0x0001)
       - Result (ID: 0x0002)
[INFO] Operaciones compiladas: 1
       - compute (ID: 0x0001)
[INFO] Hash del contrato: a3f8b2c1d4e5...
[INFO] Contrato binario: output/calculator.cbc
[INFO] Tamaño total: 1,247 bytes
```

### Contenido Binario

```hex
# Magic (4 bytes)
43 42 43 31                                        # "CBC1"

# Header (256 bytes)
01 01 00 00 ...                                    # version, flags, sizes

# Contract Hash (32 bytes)
a3 f8 b2 c1 d4 e5 f6 ...                           # BLAKE3-256

# Tipos
01 09 4f 70 65 72 61 74 69 6f 6e                 # Type: Operation
02 06 52 65 73 75 6c 74                           # Type: Result

# Operaciones
01 07 63 6f 6d 70 75 74 65                       # Op: compute
```

## Validación de Contrato

### Hash del Contrato

El hash se calcula sobre todo el contrato excepto la firma:

```rust
pub fn calculate_contract_hash(contract: &[u8]) -> [u8; 32] {
    // Excluir últimos 64 bytes (firma)
    let data_to_hash = &contract[..contract.len() - 64];
    sha256(data_to_hash)
}
```

### Firma Digital (Opcional)

```rust
use ed25519_dalek::{Signer, SigningKey};

//Firmar contrato
let signing_key = SigningKey::from_bytes(&key_bytes);
let signature = signing_key.sign(contract_hash);

let mut final_contract = contract.to_vec();
final_contract[contract.len() - 64..].copy_from_slice(&signature.to_bytes());
```

### Verificación en Runtime

```rust
pub fn verify_contract(contract: &[u8], public_key: &[u8; 32]) -> Result<()> {
    // 1. Verificar magic
    if &contract[..4] != b"CBC1" {
        return Err(ContractError::InvalidMagic);
    }

    // 2. Extraer hash del header
    let stored_hash = extract_hash_from_header(&contract[16..48]);

    // 3. Calcular hash de datos
    let calculated_hash = calculate_contract_hash(contract);

    // 4. Comparar
    if stored_hash != calculated_hash {
        return Err(ContractError::HashMismatch);
    }

    // 5. Verificar firma (si existe)
    if has_signature(contract) {
        let signature = extract_signature(contract);
        verify_signature(&stored_hash, &signature, public_key)?;
    }

    Ok(())
}
```

## Integración con Runtime

### Carga de Contrato

```rust
use std::fs;
use std::path::Path;

pub struct ContractLoader {
    verification_key: Option<[u8; 32]>,
}

impl ContractLoader {
    pub fn load<P: AsRef<Path>>(&self, path: P) -> Result<Contract> {
        let data = fs::read(path)?;
        self.verify(&data)?;
        self.parse(&data)
    }

    pub fn load_from_bytes(&self, data: &[u8]) -> Result<Contract> {
        self.verify(data)?;
        self.parse(data)
    }
}
```

### Sesión de Contrato

```rust
pub struct ContractSession {
    contract: Contract,
    session_id: u64,
    role: ContractRole,
    channel_id: u32,
    sequence: u64,
    security: SecurityContext,
}

impl ContractSession {
    pub fn new(contract: Contract, session_id: u64) -> Result<Self> {
        Ok(Self {
            contract,
            session_id,
            role: Contract::role(),
            channel_id: 0,
            sequence: 0,
            security: SecurityContext::new(),
        })
    }

    pub fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence;
        self.sequence += 1;
        seq
    }
}
```

## Best Practices

### 1. Versionado Correcto

```dsl
# INCORRECTO: Cambiar operación sin incrementar versión
contract "service" {
    version 1.0.0
    operation old_op { ... }  // Cambiar a new_op
}

# CORRECTO: Nueva versión del contrato
contract "service" {
    version 2.0.0
    operation new_op { ... }  // Nuevo contrato
}
```

### 2. Tipos Descriptivos

```dsl
# INCORRECTO: Tipos genéricos
type Request { data: bytes }
type Response { data: bytes }

# CORRECTO: Tipos específicos del dominio
type ImageResizeRequest { image: Image, width: u32, height: u32 }
type ImageResizeResponse { result: Image, processing_time_ms: u64 }
```

### 3. Timeouts Razonables

```dsl
# Operación rápida
operation ping { output bool, timeout 100ms }

# Operación que puede tomar tiempo
operation process_video { input Video, output Video, timeout 300s }
```

### 4. Idempotencia Documentada

```dsl
# Idempotente: seguro repetir
operation get_balance { input AccountId, output Balance, idempotent true }

# No idempotente: efectos secundarios
operation transfer_funds { input Transfer, output Receipt, idempotent false }
```

## Comparación de Formatos

| Aspecto | YAML | JSON | CBC (Binario) |
|---------|------|------|---------------|
| Legible por humanos | Si | Si | No |
| Tamaño | Grande | Medio | Pequeño |
| Parseo | Lento | Medio | Rápido |
| Validación de tipos | Runtime | Runtime | Compile-time |
| IDs numéricos | No | No | Si |
| Hash criptográfico | No | No | Si |
| Firma digital | No | No | Si |

## Próximos Pasos

1. **Compilar contrato de ejemplo:**
   ```bash
   contractc compile contracts/image_processor.contract -o output/
   ```

2. **Generar bindings:**
   ```bash
   contractc generate output/image_processor.cbc --target rust -o generated/
   contractc generate output/image_processor.cbc --target kotlin -o generated/
   ```

3. **Verificar contrato:**
   ```bash
   contractc validate output/image_processor.cbc --verify-signature
   ```

4. **Usar en runtime:**
   ```rust
   use ipc_contract_system::{Contract, ContractSession};

   let contract = Contract::load("output/image_processor.cbc")?;
   let mut session = ContractSession::new(contract, session_id)?;
   ```
