# Integración

Cómo usar este sistema desde tu aplicación.

## Elegir por dónde empezar

| Situación | Recomendación |
|---|---|
| Aplicación nueva, un solo lenguaje | **Rust.** Es el único camino completo hoy |
| Integrar un componente existente en C++ | Bindings C++ para contrato y criptografía. El transporte lo escribes tú |
| App Android o JVM | Bindings Kotlin. Cripto vía JCA, sin dependencias externas |
| Multi-lenguaje con identidad compartida | Los tres, con los vectores dorados como contrato entre ellos |

**El transporte todavía no existe.** Los bindings te dan contrato,
criptografía y framing; abrir un canal es trabajo tuyo. Ver
[Hoja de ruta](roadmap.md).

## Rust

```toml
[dependencies]
ipc-contract-system = { path = "../ipc-lib-contracts" }
ed25519-dalek = "2"
```

### Generar y proteger el secreto raíz

Es lo más importante que hagas bien. `kd_secret` es la raíz de toda la
jerarquía de claves.

```rust
use rand::RngCore;

fn generate_kd_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
}
```

En móvil, sella el secreto con el Keystore:

- **Android**: `AndroidKeyStore`, con `setUserAuthenticationRequired(true)` si
  quieres exigir biometría.
- **iOS**: `Secure Enclave` vía Keychain, con `kSecAccessControl`.

No lo guardes en `SharedPreferences` en claro ni en el bundle.

### Estructura típica

```rust
pub struct SecureChannel {
    contract: Contract,
    kd: KeyDerivation,
    session_id: u64,
    encryption_key: [u8; 32],
    nonce_key: [u8; 32],
    anti_replay: AntiReplay,
    cipher: AeadCipher,
}

impl SecureChannel {
    pub fn new(contract_bytes: &[u8], kd_secret: [u8; 32]) -> anyhow::Result<Self> {
        let contract = ContractReader::from_bytes(contract_bytes)?;
        let kd = KeyDerivation::new(&kd_secret);
        let session_id = random_session_id();
        let session_key = kd.derive_session_key(&contract.header.contract_hash, session_id);
        Ok(Self {
            encryption_key: kd.derive_encryption_key(&session_key.0),
            nonce_key: kd.derive_nonce_key(&contract.header.contract_hash, session_id),
            contract, kd, session_id,
            anti_replay: AntiReplay::new(1024),
            cipher: AeadCipher::new(AeadAlgorithm::ChaCha20Poly1305),
        })
    }

    pub fn seal(&mut self, op: OperationId, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut frame = Frame::new(
            PacketType::Request, ContractRole::Mutual,
            self.session_id, self.next_sequence()?, 0,
            op, TypeId(0x0001),
            &self.contract.header.contract_hash[..12].try_into()?,
            payload.to_vec(),
        );
        WireProtocol::send(&mut frame, &self.nonce_key, &self.encryption_key,
                           Direction::Tx, &self.cipher)?;
        Ok(frame.to_bytes())
    }

    pub fn open(&mut self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        let frame = Frame::from_bytes(wire)?;
        WireProtocol::receive(
            &frame,
            &self.contract.header.contract_hash[..12].try_into()?,
            &self.encryption_key, &self.cipher, &self.anti_replay,
        )
    }
}
```

`next_sequence()` debe ser monótono y persistente. Si se reinicia a cero
bajo la misma clave de sesión, los nonces se repiten y AEAD se rompe. Ante
duda, deriva una clave de sesión nueva.

### Zero-log en tu aplicación

La librería no registra nada, y eso es deliberado. La observabilidad la
instalas tú:

```rust
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::Info)
    .with_filter(/* nunca claves, hashes completos ni payloads */)
    .init();
```

Nunca registres: material de clave, `contract_hash` completo, plaintext ni
ciphertext. El prefijo de 12 bytes sí es apto para trazas, precisamente
porque no es identidad.

## C++

```cmake
add_subdirectory(ipc-lib-contracts/cpp_bindings)
target_link_libraries(mi_app PRIVATE ipc::contract ipc::security)
```

### Cargar y verificar un contrato

```cpp
#include "ipc/contract.hpp"
#include "ipc/security.hpp"

ipc::Contract contract;
if (!contract.load_from_bytes(raw)) {
    throw std::runtime_error("contrato inválido");
}

if (!contract.verify()) {
    throw std::runtime_error("contract_hash incorrecto");
}
```

`Contract::calculate_hash` es BLAKE3-256 sobre el preimagen canónico y
produce el mismo valor que Rust. El test de conformidad lo comprueba con un
contrato real generado por el core.

### Cifrar un frame

```cpp
using namespace ipc::security;

KeyDerivation kd(secret32);
auto session_key = kd.derive_session_key(contract_hash, session_id);
auto enc_key     = kd.derive_encryption_key(session_key);
auto nonce_key   = kd.derive_nonce_key(contract_hash, session_id);

auto nonce = derive_nonce(nonce_key, session_id, sequence, Direction::Tx);

std::vector<uint8_t> ciphertext = encrypt_chacha20poly1305(
    enc_key,
    std::vector<uint8_t>(nonce.begin(), nonce.end()),
    aad,        // bytes 0..48 del header
    plaintext
);

AntiReplayWindow window(1024);
if (!window.check_and_update(session_id, Direction::Rx, sequence)) {
    throw std::runtime_error("replay");
}
```

Compara claves y hashes con `constant_time_equals`, nunca con `==` ni
`memcmp`.

### El transporte lo escribes tú

`UnixSocketTransport` y `TcpTransport` existen en la interfaz pero lanzan
excepción. Es deliberado: una implementación de socket móvil tiene
implicaciones de plataforma que no conviene inventar aquí. En Android
necesitarás un socket nativo vía JNI, o un transporte basado en
`ParcelFileDescriptor`.

## Kotlin / Android

```kotlin
val kd = KeyDerivation(kdSecret)   // de Android Keystore, idealmente
val sessionKey = kd.deriveSessionKey(contract.contractHash, sessionId)
val encKey = kd.deriveEncryptionKey(sessionKey)
val nonceKey = kd.deriveNonceKey(contract.contractHash, sessionId)
```

Sin dependencias criptográficas externas: Ed25519 viene de `SunEC` en JDK 15+
(Android 8+), y ChaCha20-Poly1305 y AES-GCM de JCA.

### Guardar el secreto en Android

```kotlin
val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
val key = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    .apply {
        init(
            KeyGenParameterSpec.Builder(
                "ipc_kd_secret",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setUserAuthenticationRequired(true)   // biometría
                .build()
        )
    }
    .generateKey()
```

La clave privada Ed25519 para firmar contratos debería vivir en el mismo
keystore, no en un archivo.

### Verificar un contrato

```kotlin
val contract = Contract.parse(cbcBytes)   // lanza si el header no es canónico
val hash = contract.calculateContractHash(cbcBytes)

if (!SecurityUtils.constantTimeEquals(contract.contractHash, hash)) {
    throw SecurityException("contract_hash incorrecto")
}
```

Para validar la firma, usa la clave pública que el anfitrión
proporciona por un canal confiable. No verifiques contra una clave que venga del propio contrato:
eso sería Trusted Third Party, y el modelo no lo permite.

## Contrato entre lenguajes

Si tu sistema tiene componentes en varios lenguajes, el punto de anclaje es
`tests/vectors/crypto.json`. Los tres deben producir los mismos bytes para:

- BLAKE3-256 con clave
- Ed25519 (firma y verificación)
- HKDF-Expand
- derivación de clave de sesión
- nonces
- AEAD
- estado de la ventana anti-replay

Un fallo de conformidad es un fallo de seguridad: significa que un
componente acepta algo que otro rechaza.

## Migración de v2.0 a v2.1

- `contract_hash` pasa de SHA-256 a **BLAKE3-256**. Los contratos v2.0
  necesitan recompilarse; no hay migración en caliente porque la identidad
  cambia por completo.
- La firma ahora es Ed25519 real. Las firmas v2.0 (HMAC) no son válidas.
- Se exige `HandshakeHello` con el `contract_hash` completo. Un extremo v2.0
  que sólo envie el prefijo de 12 bytes será rechazado.
- Los nonces se derivan de la clave de sesión, no son aleatorios por frame.
  Los dos extremos deben estar actualizados a la vez.
- El motor ya no deriva claves de un secreto fijo. Debe pasarse
  `kd_secret` explícitamente al construirlo.
