# Seguridad Criptográfica

## Principios

El sistema de contratos implementa tres propiedades criptográficas separadas:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SEGURIDAD                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   INTEGRIDAD              AUTENTICIDAD           CONFIDENCIALIDAD     │
│        │                       │                      │               │
│        ▼                       ▼                      ▼               │
│   ┌─────────┐            ┌──────────┐          ┌─────────┐       │
│   │BLAKE3   │            │ Ed25519  │          │ AEAD    │       │
│   │  -256   │            │ (firma)  │          │ChaCha20 │       │
│   └─────────┘            └──────────┘          │AES-GCM  │       │
│                                                 └─────────┘       │
│                                                                      │
│   Detecta              Verifica               Cifra                 │
│   modificación          identidad             contenido             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 1. Integridad

### Hash del Contrato (P0.1)

BLAKE3-256 es el **único** algoritmo con el que un contrato obtiene su
identidad. La v2.1 usaba SHA-256 en el binding Kotlin y BLAKE3 en Rust, de modo
que el mismo contrato CBC1 producía dos `contract_hash` distintos y la
comparación de identidad del handshake fallaba siempre entre esos dos
lenguajes.

```rust
// Preimagen canónico: header de 256 B con contract_hash = 0 y todos los
// offsets/tamaños de sección a cero, seguido de las secciones. Los offsets no
// forman parte de la identidad semántica: dependen del empaquetado, no del
// contenido.
contract_hash = BLAKE3-256(
    header_canonical[256] ||
    types_binary ||
    operations_binary ||
    security_policy_binary
)
```

SHA-256 sigue implementado en los tres bindings como digest de compatibilidad,
pero **no puede ser `contract_hash`**. Declararlo en la política de seguridad
como algoritmo de identidad es un error de configuración.

### Checksum de Paquetes

```rust
// En cada paquete, el payload incluye checksum
payload_with_checksum = payload || BLAKE3(payload)
```

## 2. Autenticidad

### HMAC para Mensajes

```rust
// Cada mensaje incluye HMAC
mac = HMAC-SHA256(auth_key, frame.header || payload)
```

### Firma Digital (P0.2)

La firma se calcula sobre el **mismo preimagen canónico** que alimenta
`contract_hash`, no sobre una serialización auxiliar que pudiera cambiar.

```rust
payload = header_canonical[256] || types || operations || security_policy
signature = Ed25519::sign(signing_key, payload)
```

En v2.1 los bindings Kotlin y C++ no implementaban Ed25519:

- Kotlin: `MessageDigest("SHA-256").digest(data + privateKey)` — no es una
  firma, es un hash al que se le concatena la clave privada. Cualquiera que
  conociera la clave privada podía "firmar", y la "verificación"
  (`SHA256(data + publicKey)`) no comprueba nada.
- C++: `public_key = SHA256(private_key)` y firma = `HMAC(private_key, data)`,
  que sólo puede verificar quien ya tiene la clave privada.

Ambos están sustituidos por Ed25519 real: `ed25519-dalek` en Rust, OpenSSL 3
(`EVP_PKEY_ED25519`) en C++ y el proveedor JCA `SunEC` en Kotlin. Los tres
verifican los mismos vectores en `tests/vectors/crypto.json`.

**Política de firma.** `SignaturePolicy` es `NONE`, `OPTIONAL` o `REQUIRED`, y
el valor por defecto es `REQUIRED`: un contrato sin firma se rechaza al
cargarlo. El flag `SIGNED` del header se activa **antes** de calcular el
preimagen; si no, la firma cubriría un header con `flags = 0` mientras el hash
final usaría `flags = SIGNED`, y la firma no validaría nunca.

## 3. Confidencialidad

### AEAD con ChaCha20-Poly1305

```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

let cipher = ChaCha20Poly1305::new(key.into());
let nonce = Nonce::from_slice(&frame.nonce);

let ciphertext = cipher
    .encrypt(nonce, Payload { msg: plaintext, aad })
    .map_err(|_| AeadError::EncryptionFailed)?;
```

### Nonce (P0.4)

El nonce **no** es aleatorio. Es una PRF ligada a la clave de sesión:

```rust
nonce = BLAKE3_keyed(
    key  = nonce_key,                 // secreto derivado de la sesión
    data = "ipc-cbc2-nonce-v1" || direction || session_id_le || sequence_le
)[0..12]
```

Esto da dos garantías que la v2.1 no tenía:

1. **Unicidad estructural**: la tupla `(direction, session_id, sequence)` es
   única por construcción, y la máquina de estados anti-replay rechaza
   reutilizaciones. No depende de que la CSPRNG no colisione.
2. **Imposibilidad de adivinanza**: sin `nonce_key`, un atacante que controle
   el canal no puede calcular el nonce de un frame que aún no ha observado,
   ni elegir una secuencia cuyo nonce le resulte válido.

La v2.1 derivaba el nonce **sin ningún secreto**:

```text
BLAKE3("CBC2-NONCE" || session_id || sequence || direction)[0..12]
```

cualquier observador podía recalcularlo. Y los tres bindings usaban además
nonces aleatorios distintos (`RAND_bytes`, `SecureRandom`), de modo que dos
extremos de la misma versión no producían el mismo nonce ni podían compartir
vectores de prueba.

La KDF es propia sobre BLAKE3, **no es HKDF**:

```text
subkey = BLAKE3_keyed(secret, domain || material || session_id_le)
```

con un `domain` distinto por propósito (`ipc-cbc2-session-v1`,
`ipc-cbc2-nonce-key-v1`, `ipc-cbc2-auth-v1`, `ipc-cbc2-encrypt-v1`). La
separación de dominio implica que comprometer una subclave no revela las demás
ni reconstruye la clave raíz.

## 4. Anti-Replay (P0.3)

La ventana deslizante está indexada por **`(session_id, direction)`**, no por
el nonce. Los tres bindings implementan exactamente esta máquina de estados:

```
(session_id, direction, sequence)
    │
    ├── sequence > highest  → shift_left(gap), highest = sequence, bit 0 = 1
    ├── offset = highest - sequence
    │     ├── offset >= window  → RECHAZAR (out_of_window)
    │     └── bit[offset] == 1  → RECHAZAR (replay)
    └── en otro caso, marcar el bit y ACEPTAR
```

```rust
pub enum AntiReplayError {
    Replay { sequence: u64 },
    SequenceOutOfWindow { sequence: u64, highest: u64, window: usize },
}

impl AntiReplay {
    pub fn check(
        &self,
        session_id: u64,
        direction: Direction,
        sequence: u64,
    ) -> Result<(), AntiReplayError>
}
```

Tres defectos de la v2.1 que esta versión corrige:

1. **El bitmap nunca se desplazaba.** `shift_and_expand()` sólo hacía
   `resize`, con lo que los offsets guardados dejaban de corresponder a
   secuencias reales y la ventana no olvidaba nada.
2. **Dos convenciones de índice mezcladas** en la misma función:
   `set_bit(highest - sequence)` en una ruta y `set_bit(window_size - 1)` en
   otra.
3. **`highest_sequence == 0` como centinela de "sin frames"**, lo que
   confundía la secuencia 0 con el estado vacío. Se sustituye por un flag
   `initialized`.

En Kotlin y C++ la v2.1 usaba además conjuntos de nonces vistos que crecían
sin límite; Kotlin colapsaba el nonce de 96 bits a 64 con
`ByteBuffer.wrap(nonce).order(BIG_ENDIAN).long`, lo que hace trivial una
colisión.

**`Direction` aísla TX de RX**: un frame reflejado no puede aceptarse como
nuevo en la dirección opuesta.

El tamaño de ventana se normaliza al rango `[64, 2^20]`. Una ventana de 1
elemento no distinguiría un replay inmediato, y una ventana enorme permitiría
agotar la memoria desde un contrato malicioso.

## 5. Derivación de Claves

KDF propia sobre BLAKE3 con separación de dominio. **No es HKDF** y no se
documenta como tal: la v2.1 lo llamaba "HKDF-like derivation" sin que lo fuera.

```rust
pub struct KeyDerivation {
    secret: [u8; 32],          // secreto raíz, nunca un "salt" público
}

impl KeyDerivation {
    // BLAKE3 en modo keyed: el secreto raíz es la clave, y el `domain`
    // separa los dominios de forma no colisionable.
    fn subkey(&self, domain: &[u8], material: &[u8; 32], session_id: u64) -> [u8; 32] {
        let mut h = blake3::Hasher::new_keyed(&self.secret);
        h.update(domain);
        h.update(material);
        h.update(&session_id.to_le_bytes());
        *h.finalize().as_bytes()
    }

    pub fn derive_session_key(&self, contract_hash: &[u8; 32], session_id: u64) -> SessionKey {
        SessionKey(self.subkey(b"ipc-cbc2-session-v1", contract_hash, session_id))
    }

    pub fn derive_nonce_key(&self, contract_hash: &[u8; 32], session_id: u64) -> SessionKey {
        SessionKey(self.subkey(b"ipc-cbc2-nonce-key-v1", contract_hash, session_id))
    }

    pub fn derive_auth_key(&self, session_key: &[u8; 32]) -> SessionKey {
        SessionKey(self.subkey(b"ipc-cbc2-auth-v1", session_key, 0))
    }

    pub fn derive_encryption_key(&self, session_key: &[u8; 32]) -> SessionKey {
        SessionKey(self.subkey(b"ipc-cbc2-encrypt-v1", session_key, 0))
    }
}
```

La v2.1 usaba `salt = [0u8; 32]` en el motor de runtime, con lo que todas las
claves de todas las sesiones e instancias se derivaban de un secreto público y
conocido. El secreto raíz sale ahora de la CSPRNG del sistema.

Las subclaves se envuelven en `SessionKey`, que sobrescribe el material al
soltar (`write_volatile` + fence) y **no implementa `Debug` en claro**: un
`{:?}` no puede volcar una clave a un log.

## Niveles de Seguridad

### Level 1: Integridad Only

```yaml
security:
  authentication_required: false
  confidentiality_required: false
  anti_replay: false
```

Solo checksum, sin cifrado. Para debugging o redes seguras.

### Level 2: Autenticado

```yaml
security:
  authentication_required: true
  confidentiality_required: false
  anti_replay: true
```

MAC en cada mensaje. Para entornos donde el contenido no es sensible.

### Level 3: Encriptado (Producción)

```yaml
security:
  authentication_required: true
  confidentiality_required: true
  anti_replay: true
```

AEAD completo con ChaCha20-Poly1305. **Recomendado para producción.**

## Comparación Algoritmos

| Algoritmo | Velocidad | Seguridad | Notes |
|-----------|-----------|-----------|-------|
| ChaCha20-Poly1305 | Rápido | ★★★★★ | Recomendado |
| AES-256-GCM | Rápido | ★★★★★ | Requiere AES-NI |
| AES-128-GCM | Rápido | ★★★★☆ | Aceptable |
| XOR | - | ★☆☆☆☆ | NO USAR |
| RC4 | - | ☆☆☆☆☆ | Inseguro |

## Recomendaciones

1. **Siempre usar AEAD** en producción
2. **Nunca hardcodear claves** - usar KeyDerivation
3. **Regenerar nonces** para cada paquete
4. **Validar tamaño de nonce** - debe ser exactamente 12 bytes
5. **Mantener salts únicos** por aplicación

## 6. Políticas aplicadas: zero-trust, zero-knowledge, zero-log

Estas políticas no son recomendaciones: están codificadas y verificadas.

### Zero trust

Nada se acepta por suposición. Todo lo que llega de un peer remoto pasa por
una comprobación explícita antes de usarse:

| Comprobación | Dónde | Comportamiento ante fallo |
|---|---|---|
| Bounds de sección y solapamientos | `ContractHeader::validate_sections` | `Err`, nunca panic |
| Bytes reservados ≠ 0 | `Frame::from_bytes` | `Err(NonZeroReserved)` |
| Bits de flag desconocidos | `Frame::from_bytes`, `ContractHeader::from_bytes` | `Err(UnknownFlags)` (fail-closed) |
| Bytes UTF-8 inválidos | header, operaciones | `Err` |
| Valores de enum desconocidos (política, rol, packet type) | decodificadores | `Err`, nunca degradar a un valor por defecto |
| Longitudes declaradas > bytes disponibles | todos los parsers | `Err` antes de reservar memoria |
| Tamaño de payload > máximo | `Frame::from_bytes` | `Err(PayloadTooLarge)` |
| `contract_hash` recalculado | `ContractReader::from_bytes` | `Err(HashMismatch)` |
| Firma obligatoria ausente | `ContractReader::from_bytes` | `Err(AuthenticationRequired)` |
| Versión de protocolo | frame y HELLO | `Err(IncompatibleVersion)` |

**Regla estructural**: *bytes remotos → parser fallible → `Result<T, Error>`*.
Nunca `unwrap()`, nunca `panic!`, nunca una excepción no capturada. Hay tests
con `catch_unwind` que recorren todos los prefijos posibles de un header
válido y comprueban que ninguno entra en panic.

El orden de verificación en recepción también es parte de la política:

```text
1. validar el frame estructuralmente
2. comprobar el prefijo de contract_hash   (discriptor rápido, barato)
3. verificar AEAD sobre el AAD del header  (autenticidad)
4. sólo entonces registrar la secuencia en la ventana anti-replay
```

El paso 4 va después del 3 a propósito: si un atacante sin la clave pudiera
avanzar la ventana de un emisor legítimo, podría bloquear tráfico válido.

### Zero knowledge

- El payload se cifra con AEAD antes de salir. El frame nunca transporta el
  texto plano cuando la política exige confidencialidad.
- El canal no expone metadatos de la operación más allá de lo necesario:
  `operation_id` y `schema_id` son identificadores numéricos, no nombres.
- Recepción sin cifrar sólo se acepta si la política lo permite
  explícitamente; con `authentication_required` o `confidentiality_required`
  se rechaza el frame.

### Zero log

- El motor de runtime **no** inicializa `tracing_subscriber`. Qué se registra y
  con qué granularidad es una decisión del proceso anfitrión; los sinks por
  defecto escriben en `stdout`/`stderr`, que en un runtime móvil acaba en
  `logcat` y es legible por otras aplicaciones con el permiso correspondiente.
- `SessionKey` no implementa `Debug` en claro: no se puede volcar material de
  clave a un log por accidente.
- Las claves se sobrescriben al soltar la sesión (`write_volatile` + fence de
  compilación) para reducir la ventana de exposición en memoria.
- Los mensajes de error son genéricos en la frontera criptográfica: un fallo
  de autenticación AEAD produce la misma excepción que cualquier otro, sin
  revelar si el tag, el nonce o la clave fueron el problema.
- `contractc` sí escribe en stdout: es una herramienta de línea de comandos
  cuyo resultado *es* su salida, y no contiene material de clave.

## 7. Verificación

```bash
./run_all_tests.sh
```

Ejecuta el gate completo en los tres lenguajes:

| Gate | Qué demuestra |
|---|---|
| `cargo check --all-targets --all-features` | El crate compila, incluidos los binarios y los tests |
| `cargo test --all-features` | 53 tests: unitarios, conformidad y fuzzing |
| `g++ -Wall` sobre los 4 TUs | Los bindings C++ compilan sin warnings |
| Vectores BLAKE3 en C++ | BLAKE3 propio coincide con la referencia |
| `conformance_test` (C++) | 17 comprobaciones contra los vectores dorados |
| CMake + `ctest` | El mismo build que consume el producto |
| `kotlinc` | Los bindings Kotlin compilan |
| `KotlinConformanceTest` | 39 comprobaciones contra los vectores dorados |

### Fuzzing de los parsers

`tests/fuzz_parsers.rs` ejecuta generación aleatoria sobre los parsers de
datos externos. Reglas que verifica:

- Ningún blob arbitrario provoca un panic en `Frame::from_bytes`,
  `ContractHeader::from_bytes` ni `ContractReader::from_bytes`.
- Truncamientos en cualquier punto dan `Err`, nunca panic.
- `payload_length` absurdo se rechaza antes de reservar memoria.
- Bytes de relleno del header y `schema_offset` alterados invalidan el
  contrato.
- El round-trip de un contrato firmado es estable.
- **Ningún byte del archivo escapa a la comprobación de integridad**: el test
  `test_no_byte_of_the_file_escapes_integrity` recorre todas las posiciones de
  un contrato firmado y exige que modificar cualquiera de ellas haga fallar el
  lector o la firma.

Ese último test existe porque el fuzzer encontró un fallo real: el relleno
posterior al NUL del campo `name` y el `schema_offset` no formaban parte del
preimagen del hash (que se reconstruye desde la struct parseada), de modo que
podían alterarse sin romper la integridad. Hoy el header se exige canónico y la
sección `schema` se rechaza si no está vacía.

Los vectores viven en `tests/vectors/crypto.json` y se regeneran con:

```bash
cargo run --example conformance_vectors > tests/vectors/crypto.json
```

Si un binding diverge en un solo byte, los tests de conformidad del binding
afectado fallan. Ése es el criterio de madurez del sistema: no que cada
implementación funcione por separado, sino que el mismo contrato, hash, firma,
nonce, frame y estado anti-replay sean **idénticos** en los tres lenguajes.
