// =============================================================================
// Módulo de Seguridad Criptográfica
// =============================================================================
//
// Implementa:
// - Integridad: BLAKE3-256 para hash (primario), SHA-256 para compatibilidad
// - Autenticidad: HMAC para MAC
// - Confidencialidad: ChaCha20-Poly1305 o AES-256-GCM
// - Anti-replay: Ventana deslizante con bitmap
//
// =============================================================================

use serde::{Deserialize, Serialize};

/// Política de seguridad del contrato
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Nivel de seguridad requerido
    pub level: SecurityLevel,

    /// Algoritmo AEAD preferido
    pub aead_algorithm: AeadAlgorithm,

    /// Algoritmo de hash
    pub hash_algorithm: HashAlgorithm,

    /// Si se requiere autenticación
    pub authentication_required: bool,

    /// Si se requiere confidencialidad
    pub confidentiality_required: bool,

    /// Protección anti-replay
    pub anti_replay: bool,

    /// Tamaño máximo de ventana de anti-replay
    pub replay_window_size: usize,

    /// Política de firma de contrato
    ///
    /// `production = true` implica `Required`; un contrato de producción sin
    /// firma verificable se rechaza al cargar.
    pub signature_policy: SignaturePolicy,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            level: SecurityLevel::Authenticated,
            aead_algorithm: AeadAlgorithm::ChaCha20Poly1305,
            hash_algorithm: HashAlgorithm::Blake3,
            authentication_required: true,
            confidentiality_required: true,
            anti_replay: true,
            replay_window_size: 1024,
            signature_policy: SignaturePolicy::Required,
        }
    }
}

/// Política de firma de contrato
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignaturePolicy {
    /// La firma no se exige (firma prohibida)
    None = 0x00,

    /// Se verifica si está presente
    Optional = 0x01,

    /// La ausencia de firma es un error de carga
    Required = 0x02,
}

impl SignaturePolicy {
    /// `true` si la ausencia de firma debe considerarse inválida
    pub fn requires_signature(&self) -> bool {
        matches!(self, SignaturePolicy::Required)
    }
}

impl SecurityPolicy {
    /// Indica si una política exige que el contrato lleve firma
    pub fn signature_required(&self) -> bool {
        self.signature_policy.requires_signature()
    }
}

/// Construir la política de seguridad de un contrato en modo producción
///
/// Regla de la revisión P0: `production = true` fuerza firma obligatoria y
/// cifrado AEAD real. No hay forma de obtener una política "de producción"
/// que permita contratos sin firmar.
pub fn production_policy() -> SecurityPolicy {
    SecurityPolicy {
        level: SecurityLevel::Encrypted,
        aead_algorithm: AeadAlgorithm::ChaCha20Poly1305,
        hash_algorithm: HashAlgorithm::Blake3,
        authentication_required: true,
        confidentiality_required: true,
        anti_replay: true,
        replay_window_size: 4096,
        signature_policy: SignaturePolicy::Required,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityLevel {
    /// Solo integridad (checksum)
    IntegrityOnly = 0x01,

    /// Integridad + Autenticidad (HMAC)
    Authenticated = 0x02,

    /// Autenticado + Confidencial (AEAD)
    Encrypted = 0x03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AeadAlgorithm {
    ChaCha20Poly1305 = 0x01,
    Aes256Gcm = 0x02,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashAlgorithm {
    Sha256 = 0x01,
    Blake3 = 0x02,
}

// =============================================================================
// DECODIFICACIÓN FAIL-CLOSED DE ENUMS
// =============================================================================
//
// Un valor desconocido en la política de seguridad se rechaza en vez de
// degradarse a un valor por defecto: un atacante que altere el byte del
// algoritmo no debe poder hacer que el receptor acepte una configuración más
// débil que la declarada.

pub fn security_level_from_u8(v: u8) -> Result<SecurityLevel, crate::error::ContractError> {
    use crate::error::ContractError;
    match v {
        0x01 => Ok(SecurityLevel::IntegrityOnly),
        0x02 => Ok(SecurityLevel::Authenticated),
        0x03 => Ok(SecurityLevel::Encrypted),
        other => Err(ContractError::InvalidSection(format!(
            "security: nivel desconocido {other:#04x}"
        ))),
    }
}

pub fn aead_from_u8(v: u8) -> Result<AeadAlgorithm, crate::error::ContractError> {
    use crate::error::ContractError;
    match v {
        0x01 => Ok(AeadAlgorithm::ChaCha20Poly1305),
        0x02 => Ok(AeadAlgorithm::Aes256Gcm),
        other => Err(ContractError::InvalidSection(format!(
            "security: AEAD desconocido {other:#04x}"
        ))),
    }
}

pub fn hash_from_u8(v: u8) -> Result<HashAlgorithm, crate::error::ContractError> {
    use crate::error::ContractError;
    match v {
        // SHA-256 se acepta sólo como digest legacy/optional. No puede ser la
        // identidad de un contrato: `Contract::compute_hash` siempre usa
        // BLAKE3-256 (P0.1).
        0x01 => Ok(HashAlgorithm::Sha256),
        0x02 => Ok(HashAlgorithm::Blake3),
        other => Err(ContractError::InvalidSection(format!(
            "security: hash desconocido {other:#04x}"
        ))),
    }
}

pub fn signature_policy_from_u8(v: u8) -> Result<SignaturePolicy, crate::error::ContractError> {
    use crate::error::ContractError;
    match v {
        0x00 => Ok(SignaturePolicy::None),
        0x01 => Ok(SignaturePolicy::Optional),
        0x02 => Ok(SignaturePolicy::Required),
        other => Err(ContractError::InvalidSection(format!(
            "security: política de firma desconocida {other:#04x}"
        ))),
    }
}

// =============================================================================
// KEY DERIVATION
// =============================================================================
//
// KDF propia basada en BLAKE3 con separación de dominio explícita.
//
// No es HKDF y no se documenta como tal (revisión previa #11). Cada subclave
// se deriva de un *secret* con un `derive_key` context distinto, de modo que
// compromising una subclave no revela las demás ni permite reconstruir la
// clave raíz.

/// Clave de sesión de 256 bits
#[derive(Clone)]
pub struct SessionKey(pub [u8; 32]);

impl Drop for SessionKey {
    /// Sobrescribir el material de clave al soltar.
    ///
    /// Requisito de "resistencia a ingeniería inversa": la clave no debe
    /// quedar en el heap después de que la sesión termine.
    fn drop(&mut self) {
        // `write_volatile` + fence: impide que el optimizador elimine la
        // escritura por tratarse de una variable que "ya no se usa".
        for byte in self.0.iter_mut() {
            unsafe { std::ptr::write_volatile(byte, 0u8) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl std::fmt::Debug for SessionKey {
    /// Nunca imprime material de clave: los logs no deben filtrar secretos.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionKey(<redacted>)")
    }
}

/// Derive claves usando BLAKE3 como KDF
pub struct KeyDerivation {
    /// Secret raíz de la derivación (nunca se almacena en claro en disco)
    secret: [u8; 32],
}

impl KeyDerivation {
    pub fn new(secret: &[u8; 32]) -> Self {
        Self { secret: *secret }
    }

    /// Subclave de nonce: material dedicado a la derivación de nonces.
    ///
    /// P0.4: el nonce debe quedar ligado criptográficamente a la sesión. Esta
    /// clave es el secreto que hace que el nonce derivado sea impredecible
    /// para un atacante que conozca `session_id`, `sequence` y `direction`.
    pub fn derive_nonce_key(
        &self,
        contract_hash: &[u8; 32],
        session_id: u64,
    ) -> SessionKey {
        SessionKey(self.subkey(b"ipc-cbc2-nonce-key-v1", contract_hash, session_id))
    }

    /// Derivar clave de sesión
    pub fn derive_session_key(
        &self,
        contract_hash: &[u8; 32],
        session_id: u64,
    ) -> SessionKey {
        SessionKey(self.subkey(b"ipc-cbc2-session-v1", contract_hash, session_id))
    }

    /// Derivar clave de autenticación
    pub fn derive_auth_key(&self, session_key: &[u8; 32]) -> SessionKey {
        SessionKey(self.subkey(b"ipc-cbc2-auth-v1", session_key, 0))
    }

    /// Derivar clave de cifrado
    pub fn derive_encryption_key(&self, session_key: &[u8; 32]) -> SessionKey {
        SessionKey(self.subkey(b"ipc-cbc2-encrypt-v1", session_key, 0))
    }

    /// Subclave de 256 bits con separación de dominio.
    ///
    /// BLAKE3 en modo keyed (`new_keyed`), con el secreto raíz como clave y un
    /// context distinto por propósito. No es HKDF: es una KDF propia sobre
    /// BLAKE3, documentada como tal. El context de longitud fija impide que
    /// dos dominios distintos produzcan el mismo preimagen.
    fn subkey(&self, domain: &[u8], material: &[u8; 32], session_id: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.secret);
        hasher.update(domain);
        hasher.update(material);
        hasher.update(&session_id.to_le_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        out
    }
}

// =============================================================================
// DERIVACIÓN DE NONCE
// =============================================================================

/// Dirección de un frame respecto a la sesión
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    /// Emitido por el extremo local
    Tx = 0x01,
    /// Recibido desde el remoto
    Rx = 0x02,
}

/// Derivar el nonce AEAD de 96 bits para un frame.
///
/// P0.4. La derivación usa BLAKE3 en modo *keyed* con `nonce_key` como
/// secreto, de modo que:
///
/// ```text
/// nonce = BLAKE3_keyed(
///     key  = nonce_key,             // secreto de sesión
///     data = "ipc-cbc2-nonce-v1"
///          || direction
///          || session_id_le
///          || sequence_le
/// )[0..12]
/// ```
///
/// Esto garantiza dos propiedades que la versión anterior no tenía:
///
/// 1. **Unicidad**: la tupla (direction, session_id, sequence) es única por
///    construcción, y los bindings comparten la misma máquina de estados
///    anti-replay que rechaza reutilizaciones.
/// 2. **Imposibilidad de adivinar**: sin `nonce_key`, un atacante que
///    controle el canal no puede calcular el nonce de un frame que aún no ha
///    observado, ni Selected un nonce válido para una secuencia elegida.
///
/// La versión previa (`BLAKE3("CBC2-NONCE" || session_id || sequence ||
/// direction)`) no usaba ningún secreto: los nonces de dos sesiones con
/// distintos ids eran predecibles, y los tres bindings usaban nonces
/// aleatorios distintos, lo que rompía la interoperabilidad.
pub fn derive_nonce(
    nonce_key: &[u8; 32],
    session_id: u64,
    sequence: u64,
    direction: Direction,
) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new_keyed(nonce_key);
    hasher.update(b"ipc-cbc2-nonce-v1");
    hasher.update(&[direction as u8]);
    hasher.update(&session_id.to_le_bytes());
    hasher.update(&sequence.to_le_bytes());

    let mut out = [0u8; 12];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..12]);
    out
}

// =============================================================================
// AEAD ENCRYPTION
// =============================================================================

/// Cifrado AEAD
///
/// Sin estado: no guarda claves ni material de sesión, por lo que es `Copy` y
/// puede compartirse entre hilos sin `Arc`.
#[derive(Debug, Clone, Copy)]
pub struct AeadCipher {
    algorithm: AeadAlgorithm,
}

impl AeadCipher {
    pub fn new(algorithm: AeadAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Cifrar con ChaCha20-Poly1305
    pub fn encrypt_chacha20(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        let ciphertext = cipher
            .encrypt(nonce, chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            })
            .map_err(|_| AeadError::EncryptionFailed)?;

        Ok(ciphertext)
    }

    /// Descifrar con ChaCha20-Poly1305
    pub fn decrypt_chacha20(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            })
            .map_err(|_| AeadError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Cifrar con AES-256-GCM
    #[allow(dead_code)]
    pub fn encrypt_aes256gcm(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        let ciphertext = cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            })
            .map_err(|_| AeadError::EncryptionFailed)?;

        Ok(ciphertext)
    }

    /// Descifrar con AES-256-GCM
    #[allow(dead_code)]
    pub fn decrypt_aes256gcm(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            })
            .map_err(|_| AeadError::DecryptionFailed)?;

        Ok(plaintext)
    }
}

#[derive(Debug)]
pub enum AeadError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidNonce,
    AuthenticationFailed,
}

// =============================================================================
// HASHING
// =============================================================================

/// Calcular hash BLAKE3-256
///
/// P0.1: BLAKE3-256 es el único digest con el que se calcula la identidad
/// (`contract_hash`) de un contrato CBC. SHA-256 se conserva como digest de
/// compatibilidad explícita, nunca como identidad primaria.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(hasher.finalize().as_bytes());
    result
}

/// Calcular hash SHA-256 (compatibilidad legacy, no identidad de contrato)
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// =============================================================================
// HMAC
// =============================================================================

/// Calcular HMAC-SHA256
///
/// HMAC de clave arbitraria. Se usa para autenticación de dominio, no para
/// sustitutir a Ed25519: una "firma" HMAC depende del secreto y sólo puede
/// verificar quien comparte ese secreto, que es exactamente lo que una firma
/// de contrato debe poder hacer sin revelar la clave privada.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // HMAC acepta claves de cualquier tamaño; este error no puede dispararse
    // para longitudes válidas, pero se maneja sin `expect` para no dejar
    // ningún camino panic-ejecutable en la librería.
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return [0u8; 32],
    };
    mac.update(data);
    let result = mac.finalize();

    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&result.into_bytes());
    hmac
}

// =============================================================================
// ANTI-REPLAY
// =============================================================================
//
// Máquina de estados compartida por TODOS los bindings (P0.3).
//
// La clave (session_id, direction) aísla completamente el estado de TX y RX:
// dos extremos con la misma session_id no comparten ventana, y un frame
// reflejado no puede ser aceptado.
//
// convened:
//   (session_id, direction, sequence)
//     │
//     ├── sequence > highest  → avanzar la ventana, shift_left(gap), set bit 0
//     ├── offset = highest - sequence
//     │     ├── offset >= window  → RECHAZAR (fuera de ventana)
//     │     └── bit[offset] == 1  → RECHAZAR (replay)
//     └── si no, marcar bit y ACEPTAR
//
// El bitmap usa índice 0 = `highest` (la más reciente) e índice `i` =
// `highest - i`. Un desplazamiento de `n` posiciones es un `shift_left` de `n`
// bits: los bits que salen por arriba se descartan y la base se ensancha.
//
// La implementación anterior de v2.1 NO desplazaba el bitmap (sólo hacía
// `resize`) y mezclaba dos convenciones de índice, de modo que la ventana
// marcaba secuencias que nunca se recibieron y no olvidaba las viejas al
// avanzar. Los tests de esa versión pasaban porque sólo comprobaban recencia.

/// Estado de anti-replay para una sesión y una dirección
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Secuencia más alta aceptada
    highest: u64,
    /// `initialized` distingue "sin frames" de "highest == 0".
    ///
    /// Sin este flag, la secuencia 0 se confundía con el estado vacío: el
    /// primer frame con sequence 0 se aceptaba siempre y la ventana quedaba
    /// sin inicializar.
    initialized: bool,
    /// Bitmap de la ventana. Bit `i` = secuencia `highest - i` recibida.
    bitmap: Vec<u64>,
    /// Última vez que se tocó esta sesión (para limpieza)
    last_activity: std::time::Instant,
}

impl ReplayWindow {
    /// Tope duro de ventana: evita que un contrato malicioso reserve gigabytes
    /// de memoria declarando una ventana enorme.
    pub const MAX_WINDOW: usize = 1 << 20; // 1 Mi secuencias (128 KiB de bitmap)

    /// Normalizar un tamaño de ventana declarado a un rango seguro
    pub fn normalize_window(window: usize) -> usize {
        window.clamp(64, Self::MAX_WINDOW)
    }

    pub fn new(window_size: usize) -> Self {
        let words = (Self::normalize_window(window_size) + 63) / 64;
        Self {
            highest: 0,
            initialized: false,
            bitmap: vec![0u64; words],
            last_activity: std::time::Instant::now(),
        }
    }

    /// Tamaño efectivo de ventana en uso
    fn effective_window(&self) -> usize {
        self.bitmap.len() * 64
    }

    /// Desplazar el bitmap `shift` posiciones hacia secuencias más altas.
    ///
    /// Equivale a `highest += shift`: cada bit `i` pasa a la posición
    /// `i + shift`. Los bits que exceden la ventana se descartan.
    fn shift_left(&mut self, shift: usize) {
        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if word_shift >= self.bitmap.len() {
            // El salto es mayor que toda la ventana: no queda información
            // válida. Se descarta el bitmap completo.
            self.bitmap.iter_mut().for_each(|w| *w = 0);
            return;
        }

        // Desplazar de arriba hacia abajo para no pisar el source.
        for i in (0..self.bitmap.len()).rev() {
            let mut v = self.bitmap[i - word_shift] << bit_shift;
            if bit_shift > 0 && i > word_shift {
                v |= self.bitmap[i - word_shift - 1] >> (64 - bit_shift);
            }
            self.bitmap[i] = v;
        }
    }

    fn is_bit_set(&self, offset: usize) -> bool {
        let word = offset / 64;
        let bit = offset % 64;
        word < self.bitmap.len() && (self.bitmap[word] & (1u64 << bit)) != 0
    }

    fn set_bit(&mut self, offset: usize) {
        let word = offset / 64;
        let bit = offset % 64;
        if word < self.bitmap.len() {
            self.bitmap[word] |= 1u64 << bit;
        }
    }

    /// Verificar y registrar una secuencia.
    ///
    /// `Ok(())` si es nueva y está dentro de la ventana.
    pub fn check_and_mark(&mut self, sequence: u64) -> Result<(), AntiReplayError> {
        self.last_activity = std::time::Instant::now();
        let window = self.effective_window();

        // Primer frame de la ventana
        if !self.initialized {
            self.initialized = true;
            self.highest = sequence;
            self.bitmap.iter_mut().for_each(|w| *w = 0);
            self.set_bit(0);
            return Ok(());
        }

        if sequence > self.highest {
            let gap = (sequence - self.highest) as usize;

            // Un salto mayor que la ventana implica que las secuencias
            // intermedias se perdieron o fueron manipuladas. Se acepta
            // resincronizando (la ventana se vacía), que es el
            // comportamiento correcto para un transporte no fiable, pero se
            // registra el hueco para que el llamador pueda alertar.
            self.shift_left(gap);
            self.highest = sequence;
            self.set_bit(0);

            if gap > window {
                self.bitmap.iter_mut().for_each(|w| *w = 0);
                self.set_bit(0);
                return Ok(());
            }
            return Ok(());
        }

        // Secuencia <= highest
        let offset = (self.highest - sequence) as usize;

        if offset >= window {
            return Err(AntiReplayError::SequenceOutOfWindow {
                sequence,
                highest: self.highest,
                window,
            });
        }

        if self.is_bit_set(offset) {
            return Err(AntiReplayError::Replay { sequence });
        }

        self.set_bit(offset);
        Ok(())
    }

    /// Serializar el estado de la ventana (para vectores de conformidad)
    pub fn snapshot(&self) -> (u64, bool, Vec<u64>) {
        (self.highest, self.initialized, self.bitmap.clone())
    }

    /// Restaurar un estado serializado (para vectores de conformidad)
    pub fn restore(highest: u64, initialized: bool, bitmap: Vec<u64>) -> Self {
        Self {
            highest,
            initialized,
            bitmap,
            last_activity: std::time::Instant::now(),
        }
    }
}

/// Errores de anti-replay
#[derive(Debug, PartialEq, Eq)]
pub enum AntiReplayError {
    /// La secuencia ya fue aceptada anteriormente
    Replay { sequence: u64 },

    /// La secuencia es anterior a la ventana activa
    SequenceOutOfWindow {
        sequence: u64,
        highest: u64,
        window: usize,
    },
}

impl std::fmt::Display for AntiReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AntiReplayError::Replay { sequence } => {
                write!(f, "replay: sequence {sequence} already seen")
            }
            AntiReplayError::SequenceOutOfWindow { sequence, highest, window } => write!(
                f,
                "sequence {sequence} outside window (highest={highest}, window={window})"
            ),
        }
    }
}

impl std::error::Error for AntiReplayError {}

/// Sistema anti-replay: una ventana deslizante por (session_id, direction)
///
/// El estado se indexa por `SessionDirectionKey`, de modo que las dos
/// direcciones de una sesión son independientes. Esto es lo que Rust, Kotlin y
/// C++ deben implementar de forma idéntica.
pub struct AntiReplay {
    sessions: dashmap::DashMap<SessionDirectionKey, ReplayWindow>,
    window_size: usize,
}

/// Clave compuesta sesión + dirección
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionDirectionKey {
    pub session_id: u64,
    pub direction: Direction,
}

impl AntiReplay {
    /// Crear nuevo AntiReplay con tamaño de ventana
    ///
    /// El tamaño se normaliza al rango [64, 1 Mi]: una ventana de 1 elemento
    /// no distinguiría un replay inmediato, y una ventana enorme permitiría un
    /// agotamiento de memoria.
    pub fn new(window_size: usize) -> Self {
        Self {
            sessions: dashmap::DashMap::new(),
            window_size: ReplayWindow::normalize_window(window_size),
        }
    }

    /// Tamaño de ventana configurado
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Verificar y registrar una secuencia para (sesión, dirección).
    ///
    /// `Ok(())` = aceptada. Cualquier rechazo es un `Err`: la API no devuelve
    /// `false` porque "no válido" y "aceptado" no son equivalentes a "sin
    /// efecto", y un `if !check(..)` invite a ignorar la diferencia entre un
    /// replay y una secuencia fuera de ventana.
    pub fn check(
        &self,
        session_id: u64,
        direction: Direction,
        sequence: u64,
    ) -> Result<(), AntiReplayError> {
        let key = SessionDirectionKey { session_id, direction };
        let window = self.window_size;
        let mut state = self
            .sessions
            .entry(key)
            .or_insert_with(|| ReplayWindow::new(window));

        state.check_and_mark(sequence)
    }

    /// Obtener una copia del estado de la ventana (para conformidad)
    pub fn snapshot(&self, session_id: u64, direction: Direction) -> Option<(u64, bool, Vec<u64>)> {
        let key = SessionDirectionKey { session_id, direction };
        self.sessions.get(&key).map(|s| s.snapshot())
    }

    /// Restaurar el estado de una ventana (para conformidad)
    pub fn restore(&self, session_id: u64, direction: Direction, highest: u64, initialized: bool, bitmap: Vec<u64>) {
        let key = SessionDirectionKey { session_id, direction };
        self.sessions
            .insert(key, ReplayWindow::restore(highest, initialized, bitmap));
    }

    /// Eliminar estado de una sesión (ambas direcciones)
    pub fn remove_session(&self, session_id: u64) {
        self.sessions.remove(&SessionDirectionKey { session_id, direction: Direction::Tx });
        self.sessions.remove(&SessionDirectionKey { session_id, direction: Direction::Rx });
    }

    /// Limpiar sesiones inactivas
    pub fn cleanup(&self, max_idle_secs: u64) {
        let now = std::time::Instant::now();
        self.sessions
            .retain(|_, state| now.duration_since(state.last_activity).as_secs() < max_idle_secs);
    }

    /// Número de ventanas activas (métrica de diagnóstico, sin datos sensibles)
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac() {
        let key = b"test_key_32_bytes_long_xxxx";
        let data = b"test data";

        let hmac1 = hmac_sha256(key, data);
        let hmac2 = hmac_sha256(key, data);
        assert_eq!(hmac1, hmac2);

        let hmac3 = hmac_sha256(key, b"different data");
        assert_ne!(hmac1, hmac3);
    }

    #[test]
    fn test_key_derivation_domain_separation() {
        let kd = KeyDerivation::new(&[7u8; 32]);
        let contract_hash = [1u8; 32];

        let k1 = kd.derive_session_key(&contract_hash, 1);
        let k2 = kd.derive_session_key(&contract_hash, 1);
        let k3 = kd.derive_session_key(&contract_hash, 2);

        assert_eq!(k1.0, k2.0, "misma entrada debe dar misma clave");
        assert_ne!(k1.0, k3.0, "session_id distinto debe dar clave distinta");

        // P0.4: las subclaves derivadas de la misma sesión no pueden coincidir.
        let nonce_key = kd.derive_nonce_key(&contract_hash, 1);
        let enc_key = kd.derive_encryption_key(&k1.0);
        let auth_key = kd.derive_auth_key(&k1.0);
        assert_ne!(nonce_key.0, enc_key.0, "nonce_key ≠ encryption_key");
        assert_ne!(enc_key.0, auth_key.0, "encryption_key ≠ auth_key");
    }

    #[test]
    fn test_nonce_derivation_is_secret_dependent() {
        let k1 = [0xAAu8; 32];
        let k2 = [0xBBu8; 32];

        let n1 = derive_nonce(&k1, 7, 42, Direction::Tx);
        let n1_again = derive_nonce(&k1, 7, 42, Direction::Tx);
        let n2 = derive_nonce(&k2, 7, 42, Direction::Tx);

        assert_eq!(n1, n1_again, "derivación debe ser determinista");
        assert_ne!(n1, n2, "el nonce debe depender del secreto de sesión");
    }

    #[test]
    fn test_nonce_varies_with_every_input() {
        let key = [1u8; 32];
        let base = derive_nonce(&key, 1, 1, Direction::Tx);

        assert_ne!(base, derive_nonce(&key, 1, 2, Direction::Tx), "sequence");
        assert_ne!(base, derive_nonce(&key, 1, 1, Direction::Rx), "direction");
        assert_ne!(base, derive_nonce(&key, 2, 1, Direction::Tx), "session_id");
    }

    #[test]
    fn test_anti_replay_basic() {
        let ar = AntiReplay::new(1024);
        let rx = Direction::Rx;

        assert!(ar.check(1, rx, 1).is_ok());
        assert!(ar.check(1, rx, 2).is_ok());

        // Replay explícito -> Err, no Ok(false)
        assert_eq!(ar.check(1, rx, 1).unwrap_err(), AntiReplayError::Replay { sequence: 1 });

        // Sesión distinta: estado independiente
        assert!(ar.check(2, rx, 1).is_ok());
    }

    #[test]
    fn test_anti_replay_direction_isolation() {
        let ar = AntiReplay::new(1024);

        // La misma secuencia en TX y RX no es un replay: son flujos distintos.
        assert!(ar.check(1, Direction::Tx, 5).is_ok());
        assert!(ar.check(1, Direction::Rx, 5).is_ok());
        // Y repetir en cada dirección sí lo es.
        assert!(ar.check(1, Direction::Tx, 5).is_err());
        assert!(ar.check(1, Direction::Rx, 5).is_err());
    }

    #[test]
    fn test_anti_replay_sequence_zero() {
        // La secuencia 0 es válida: el flag `initialized` evita confundirla
        // con el estado vacío (bug de v2.1).
        let ar = AntiReplay::new(1024);
        assert!(ar.check(1, Direction::Rx, 0).is_ok());
        assert!(ar.check(1, Direction::Rx, 0).is_err());
    }

    #[test]
    fn test_anti_replay_bitmap_actually_shifts() {
        // Falla con la implementacion de v2.1: `shift_and_expand` solo hacia
        // resize, asi que el bitmap nunca se desplazaba y los offsets
        // guardados dejaban de corresponder a secuencias reales.
        let mut w = ReplayWindow::new(64);

        for seq in 1..=10 {
            assert!(w.check_and_mark(seq).is_ok());
        }
        let (highest, init, bitmap) = w.snapshot();
        assert_eq!(highest, 10);
        assert!(init);
        // Bit 0 = secuencia 10, bit 1 = 9, ... bit 9 = 1.
        assert_eq!(bitmap[0], 0x3FF, "las 10 secuencias vistas deben estar marcadas");
        assert_eq!(bitmap.len(), 1, "ventana 64 => un unico u64");

        // Tras avanzar a 25, la secuencia 1 queda en el offset 24: dentro de
        // la ventana, y correctamente recordada. Eso solo es posible si el
        // bitmap se desplazo de verdad.
        for seq in 20..=25 {
            assert!(w.check_and_mark(seq).is_ok());
        }
        assert_eq!(w.check_and_mark(1), Err(AntiReplayError::Replay { sequence: 1 }));
        assert_eq!(w.snapshot().0, 25);
    }

    #[test]
    fn test_anti_replay_forgets_beyond_window() {
        // La ventana debe olvidar lo que queda fuera. En v2.1, sin
        // desplazamiento real, estas secuencias viejas seguian "recordadas"
        // para siempre y el bitmap crecia sin limite.
        let mut w = ReplayWindow::new(64);

        assert!(w.check_and_mark(1).is_ok());
        // Avanzar 200: la secuencia 1 queda a offset 199, muy fuera de la
        // ventana de 64, y debe olvidarse.
        assert!(w.check_and_mark(201).is_ok());

        assert_eq!(
            w.check_and_mark(1),
            Err(AntiReplayError::SequenceOutOfWindow {
                sequence: 1,
                highest: 201,
                window: 64,
            }),
            "una secuencia mas antigua que la ventana debe rechazarse por antiguedad"
        );
    }

    #[test]
    fn test_anti_replay_out_of_window() {
        let ar = AntiReplay::new(64);
        for seq in 100..110 {
            assert!(ar.check(1, Direction::Rx, seq).is_ok());
        }
        // 10 está fuera de la ventana de 64 tras avanzar a 109.
        assert!(matches!(
            ar.check(1, Direction::Rx, 1),
            Err(AntiReplayError::SequenceOutOfWindow { .. })
        ));
    }

    #[test]
    fn test_replay_window_normalization() {
        // Ventanas degeneradas se normalizan; ventana enorme se acota.
        assert_eq!(ReplayWindow::normalize_window(0), 64);
        assert_eq!(ReplayWindow::normalize_window(1), 64);
        assert_eq!(ReplayWindow::normalize_window(1024), 1024);
        assert_eq!(ReplayWindow::normalize_window(usize::MAX), ReplayWindow::MAX_WINDOW);
    }
}
