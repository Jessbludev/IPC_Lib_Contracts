# Uso

Referencia de la CLI y de las APIs públicas.

## contractc

La CLI vive en `src/bin/contractc.rs` y requiere la feature `clap`:

```bash
cargo build --release --features clap
```

Opciones **globales** (antes del subcomando):

| Opción | Descripción |
|---|---|
| `-o, --output <DIR>` | Directorio de salida. Por defecto, el directorio actual |
| `-v, --verbose` | Salida detallada |
| `-q, --quiet` | Sólo errores |

### compile

```bash
contractc [-o DIR] compile [--sign] [--sign-key RUTA] <ENTRADA>
```

| Opción | Descripción |
|---|---|
| `--sign` | Firmar el contrato con Ed25519 |
| `--sign-key <RUTA>` | Clave privada. 32 bytes en crudo, o 64 caracteres hex |

Si `--sign` se pasa sin `--sign-key`, `contractc` genera una clave aleatoria
y la deja en `contract.key`. Es cómodo para desarrollo y **no debe usarse en
producción**: la clave queda en disco junto al contrato.

El formato de entrada es el DSL textual. YAML no está soportado, y la razón
está documentada en el propio parser: `serde_yaml` nunca estuvo declarado en
`Cargo.toml`, así que esa ruta jamás compiló, y además `YAML -> struct ->
binario` convierte detalles accidentales de serde en semántica del formato.

### verify

```bash
contractc verify [--check-signature] [--verify-key RUTA] <CONTRATO>
```

Imprime `CBC VALID` o `CBC INVALID`, y después un resumen. Con
`--check-signature` valida además la firma Ed25519 contra la clave pública.

El orden de comprobación es deliberado y es el que hace que el error sea
informativo:

1. Magic `CBC1`
2. Versión de formato
3. Tamaño de header
4. Bounds de cada sección
5. Solapamientos entre secciones
6. UTF-8 válido en los campos de texto
7. Codificación canónica del header
8. `contract_hash` recalculado
9. Firma, si se solicitó

El paso 7 es el que evita el ataque que encontró el fuzzer: el relleno tras
el NUL de los campos de texto quedaba fuera del preimagen del hash, así que
se podía alterar sin romper nada. El lector ahora exige que el header
re-serializado sea idéntico a los bytes leídos.

### inspect

```bash
contractc inspect <CONTRATO>
```

Imprime nombre, namespace, versión, ID, recuento de tipos y operaciones, y
la política de seguridad completa.

### hash

```bash
contractc hash <CONTRATO>
```

Imprime sólo el `contract_hash`, en hex. Es el valor que los tres
lenguajes deben producir idéntico.

### dump

```bash
contractc dump <CONTRADO>
```

Volcado hexadecimal del binario completo, útil para comparar con un
`hexdump`.

### generate

```bash
contractc generate
```

Genera una estructura de proyecto de ejemplo.

## API de Rust

### Crear y compilar un contrato

```rust
use ipc_contract_system::{
    Contract, ContractVersion, TypeId,
    binary_contract::ContractSigner,
    types::TypeKind,
};
use ed25519_dalek::SigningKey;

let mut contract = Contract::new("image_processor", "com.example", ContractVersion::new(1, 0, 0));

contract.types.register(
    "PixelBuffer",
    TypeKind::Array { element_type: TypeId(0x0003), max_length: 4096 },
);
contract.operations.register_auto(
    "resize", "resize image", TypeId(1), TypeId(1),
);

contract.finalize()?;          // calcula contract_hash

let signing_key = SigningKey::from_bytes(&[7u8; 32]);
ContractSigner::sign(&mut contract, &signing_key)?;

let bytes = contract.to_binary()?;
```

`finalize()` debe ir **después** de registrar todos los tipos y operaciones:
calcula el hash sobre el contenido final. Si añades contenido después, el
hash queda obsoleto y `verify` fallará.

### Cargar y verificar

```rust
use ipc_contract_system::binary_contract::ContractReader;

let contract = ContractReader::from_bytes(&bytes)?;
let verifying_key = signing_key.verifying_key();
ContractSigner::verify(&contract, &verifying_key)?;
```

`ContractReader::from_bytes` rechaza el contrato si la política exige firma y
no la hay, si el header no es canónico, si alguna sección se sale de rango o
si el `contract_hash` recalculado no coincide.

**Atención a un límite conocido:** el lector comprueba que la firma *está
presente* y que el `contract_hash` cuadra, pero no verifica la firma
criptográficamente, porque no recibe una clave pública confiable. La
verificación real se hace con `ContractSigner::verify`, que sí la exige. Si
aceptas contratos de una fuente no confiable, usa siempre `verify`, no sólo
`from_bytes`. Está en la [hoja de ruta](roadmap.md).

### Frames

```rust
let mut frame = Frame::new(
    PacketType::Request,
    ContractRole::Mutual,
    session_id, 0, 0, OperationId(0x0100), TypeId(0x0001),
    &contract_hash[..12].try_into()?,
    payload.to_vec(),
);
WireProtocol::send(&mut frame, &nonce_key, &encryption_key, Direction::Tx, &cipher)?;
let wire = frame.to_bytes();
```

```rust
let anti_replay = AntiReplay::new(1024);
let frame = Frame::from_bytes(&wire)?;
let plaintext = WireProtocol::receive(
    &frame, &expected_prefix, &encryption_key, &cipher, &anti_replay,
)?;
```

`Direction` importa: las ventanas de TX y RX son independientes. Usar el
sentido equivocado al recibir rechaza el frame.

### Handshake

```rust
let hello = HandshakeHello::new(contract_hash, &version_string, &nonce)?;
let bytes = hello.to_bytes();
```

`HandshakeHello` lleva el `contract_hash` **completo** (32 bytes), no un
prefijo. El prefijo de 12 bytes aparece después, como discriminador rápido
en cada frame, y no es identidad autoritativa.

## Políticas de seguridad

```rust
use ipc_contract_system::security::{AeadAlgorithm, SecurityPolicy, SignaturePolicy};

let policy = SecurityPolicy {
    authentication_required: true,
    confidentiality_required: true,
    anti_replay: true,
    signature_policy: SignaturePolicy::Required,
    aead: AeadAlgorithm::ChaCha20Poly1305,
    ..Default::default()
};
```

| Campo | Efecto |
|---|---|
| `authentication_required` | El handshake exige identidad verificada |
| `confidentiality_required` | El tráfico va cifrado; no hay modo claro |
| `anti_replay` | Ventana sliding activa por sesión y dirección |
| `signature_policy` | `Required` rechaza contratos sin firma. `Optional` lo permite |
| `aead` | `ChaCha20Poly1305` o `Aes256Gcm` |

`SignaturePolicy::Required` es el valor por defecto y es **fail-closed**: sin
firma, se rechaza. Relajarlo es una decisión explícita y auditable.

## Frame

64 bytes de header, fijo, little-endian:

| Offset | Tamaño | Campo |
|---|---|---|
| 0 | 1 | Versión de formato |
| 1 | 1 | Tipo de paquete |
| 2 | 1 | Rol del contrato |
| 3 | 1 | Flags |
| 4 | 4 | Longitud del payload |
| 8 | 8 | `session_id` |
| 16 | 8 | Número de secuencia |
| 24 | 4 | `channel_id` |
| 28 | 2 | `operation_id` |
| 30 | 2 | `schema_id` |
| 32 | 12 | Prefijo de `contract_hash` |
| 44 | 4 | Longitud del nombre de la operación |
| 48 | 16 | Reservado, debe ser cero |

El AAD del AEAD son los bytes 0..48. Los bytes 48..64 no se autentican,
porque contienen longitud de nombre y relleno.

`Frame::from_bytes` rechaza: versión desconocida, tipo de paquete o rol
inválido, flags con bits desconocidos, longitud declarada distinta de la
real, y prefijo de contrato que no coincide con el esperado.

## Siguiente

[Integración](integration.md) para insertarlo en una aplicación, o
[Implementación](implementation.md) para el detalle interno.
