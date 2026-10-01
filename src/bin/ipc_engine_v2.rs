// =============================================================================
// IPC Engine v2 - Motor de Runtime
// =============================================================================

use std::sync::Arc;
use parking_lot::RwLock;
use ipc_contract_system::{
    AeadCipher, AntiReplay, Contract, ContractError, ContractRole,
    Direction, Frame, HandshakeHello, KeyDerivation, OperationId, PacketType, SecurityPolicy,
    SessionKey, TypeId, WireProtocol,
};

type Result<T> = std::result::Result<T, ContractError>;

// Los errores de AEAD se convierten en errores de contrato para poder
// propagarlos con `?` sin `map_err` en cada sitio.
/// Estado del engine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Uninitialized,
    HandshakePending,
    Ready,
    Running,
    Closed,
}

/// Session IPC
pub struct Session {
    pub id: u64,
    pub role: ContractRole,
    pub state: EngineState,
    pub sequence: u64,
    pub keys: SessionKeys,
    pub created_at: std::time::Instant,
    pub last_activity: std::time::Instant,
}

/// Claves de una sesión.
///
/// Se envuelven en `SessionKey`, que sobrescribe el material al soltar y no
/// implementa `Debug` en claro: una sesión cerrada no debe dejar claves en el
/// heap ni permitir que un `{:?}` las vuelque en un log.
pub struct SessionKeys {
    pub session_key: SessionKey,
    pub auth_key: SessionKey,
    pub encryption_key: SessionKey,
    /// Clave dedicada a la derivación de nonces (P0.4)
    pub nonce_key: SessionKey,
}

impl SessionKeys {
    fn zeroed() -> Self {
        Self {
            session_key: SessionKey([0u8; 32]),
            auth_key: SessionKey([0u8; 32]),
            encryption_key: SessionKey([0u8; 32]),
            nonce_key: SessionKey([0u8; 32]),
        }
    }
}

impl Session {
    pub fn new(id: u64, role: ContractRole) -> Self {
        Self {
            id,
            role,
            state: EngineState::HandshakePending,
            sequence: 0,
            keys: SessionKeys::zeroed(),
            created_at: std::time::Instant::now(),
            last_activity: std::time::Instant::now(),
        }
    }

    pub fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence;
        self.sequence += 1;
        self.last_activity = std::time::Instant::now();
        seq
    }

    pub fn is_expired(&self, timeout_ms: u64) -> bool {
        self.last_activity.elapsed().as_millis() as u64 > timeout_ms
    }
}

/// Engine de runtime
pub struct IpcEngineV2 {
    state: RwLock<EngineState>,
    contract: Option<Contract>,
    security_policy: SecurityPolicy,
    key_derivation: KeyDerivation,
    sessions: dashmap::DashMap<u64, Arc<RwLock<Session>>>,
    anti_replay: AntiReplay,
    aead_cipher: AeadCipher,
    next_session_id: std::sync::atomic::AtomicU64,
}

impl IpcEngineV2 {
    /// Crear el motor con un secreto raíz aleatorio.
    ///
    /// La versión anterior usaba `salt = [0u8; 32]`, con lo que todas las
    /// claves de todas las sesiones e instancias eran derivadas de un secreto
    /// público y conocido. Ahora el secreto viene de la CSPRNG del sistema.
    pub fn new(security_policy: SecurityPolicy) -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        let window = security_policy.replay_window_size;
        let aead = security_policy.aead_algorithm;

        Self {
            state: RwLock::new(EngineState::Uninitialized),
            contract: None,
            security_policy,
            key_derivation: KeyDerivation::new(&secret),
            sessions: dashmap::DashMap::new(),
            anti_replay: AntiReplay::new(window),
            aead_cipher: AeadCipher::new(aead),
            next_session_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn load_contract(&mut self, contract: Contract) -> Result<()> {
        self.contract = Some(contract);
        *self.state.write() = EngineState::Ready;
        Ok(())
    }

    pub fn get_contract(&self) -> Option<&Contract> {
        self.contract.as_ref()
    }

    // -------------------------------------------------------------------------
    // Session Management
    // -------------------------------------------------------------------------

    pub fn create_session(&self, role: ContractRole) -> u64 {
        let id = self.next_session_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let session = Arc::new(RwLock::new(Session::new(id, role)));
        self.sessions.insert(id, session);
        id
    }

    pub fn get_session(&self, id: u64) -> Option<Arc<RwLock<Session>>> {
        self.sessions.get(&id).map(|s| Arc::clone(&s.value()))
    }

    pub fn close_session(&self, id: u64) {
        self.sessions.remove(&id);
    }

    // -------------------------------------------------------------------------
    // Handshake
    // -------------------------------------------------------------------------

    /// Procesar un HELLO entrante.
    ///
    /// P0.6: se compara el `contract_hash[32]` completo contra el contrato
    /// local. El prefijo de 12 bytes del frame sólo se usa como discriminador
    /// rápido; la identidad autoritativa es la que viaja en el payload.
    pub fn process_hello(&self, frame: &Frame) -> Result<Frame> {
        let contract = self
            .contract
            .as_ref()
            .ok_or(ContractError::Internal("No contract loaded".into()))?;

        let local_hash = contract.header.contract_hash;

        // 1. Prefijo: rechazo barato antes de tocar criptografía
        let local_prefix: [u8; 12] = local_hash[..12]
            .try_into()
            .map_err(|_| ContractError::Internal("prefijo de hash inválido".into()))?;
        if frame.contract_hash_prefix != local_prefix {
            return Err(ContractError::ContractMismatch);
        }

        // 2. Identidad completa del payload HELLO
        let hello = HandshakeHello::from_bytes(&frame.payload)
            .map_err(|e| ContractError::HandshakeFailed(e.to_string()))?;
        if !hello.matches_contract(&local_hash) {
            return Err(ContractError::ContractMismatch);
        }

        // 3. Política: el mínimo se negocia hacia arriba, nunca hacia abajo
        if (hello.security_level as u8) < (self.security_policy.level as u8) {
            return Err(ContractError::HandshakeFailed(
                "nivel de seguridad insuficiente".into(),
            ));
        }

        // 4. Crear sesión y derivar claves
        let session_id = self.create_session(frame.role);
        let session = self
            .get_session(session_id)
            .ok_or(ContractError::Internal("no se pudo crear la sesión".into()))?;

        {
            let mut s = session.write();
            s.keys.session_key = self.key_derivation.derive_session_key(&local_hash, session_id);
            s.keys.auth_key = self.key_derivation.derive_auth_key(&s.keys.session_key.0);
            s.keys.encryption_key =
                self.key_derivation.derive_encryption_key(&s.keys.session_key.0);
            s.keys.nonce_key = self.key_derivation.derive_nonce_key(&local_hash, session_id);
            s.state = EngineState::Ready;
        }

        // 5. HelloAck con nuestro HELLO como payload (identidad completa)
        let ack_payload = HandshakeHello::from_contract(&local_hash, &self.security_policy).to_bytes();

        let mut response = Frame::new(
            PacketType::HelloAck,
            frame.role,
            session_id,
            0,
            0,
            OperationId::HANDSHAKE,
            TypeId(0),
            &local_prefix,
            ack_payload,
        );

        self.seal(&mut response)?;
        Ok(response)
    }

    /// Cifrar un frame de salida con la clave de su sesión.
    ///
    /// P0.4: el nonce se deriva de la clave de sesión
    /// (`BLAKE3_keyed(nonce_key, direction || session_id || sequence)`), no de
    /// la CSPRNG. La versión anterior generaba nonces aleatorios por frame,
    /// lo que rompe la reproducibilidad de los vectores de conformidad y
    /// elimina la garantía estructural de unicidad.
    fn seal(&self, response: &mut Frame) -> Result<()> {
        if !self.security_policy.confidentiality_required {
            return Ok(());
        }

        let session = self
            .get_session(response.session_id)
            .ok_or(ContractError::SessionNotFound(response.session_id))?;
        let guard = session.read();

        let cipher = self.aead_cipher;
        WireProtocol::send(
            response,
            &guard.keys.nonce_key.0,
            &guard.keys.encryption_key.0,
            Direction::Tx,
            &cipher,
        )
        .map_err(|e| ContractError::EncryptionError(e.to_string()))?;

        response.flags = response.flags.with_encrypted(true);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Message Processing
    // -------------------------------------------------------------------------

    /// Procesar un frame de datos entrante.
    ///
    /// Orden de verificación (zero trust):
    /// 1. La sesión existe y está lista
    /// 2. Discriminador `contract_hash_prefix`
    /// 3. AEAD (autenticidad del header y del payload)
    /// 4. Anti-replay, sólo después de autenticar
    pub fn process_frame(&self, frame: &Frame) -> Result<Frame> {
        let session = self
            .get_session(frame.session_id)
            .ok_or(ContractError::SessionNotFound(frame.session_id))?;

        {
            let guard = session.read();
            if guard.state != EngineState::Ready {
                return Err(ContractError::SessionNotFound(frame.session_id));
            }

            // Discriminador rápido contra el contrato cargado
            if let Some(contract) = self.contract.as_ref() {
                let prefix: [u8; 12] = contract.header.contract_hash[..12]
                    .try_into()
                    .map_err(|_| ContractError::Internal("prefijo inválido".into()))?;
                if frame.contract_hash_prefix != prefix {
                    return Err(ContractError::ContractMismatch);
                }
            }
        }

        // Descifrar + anti-replay en el orden correcto
        let payload = if frame.flags.is_encrypted() {
            let guard = session.read();
            let cipher = self.aead_cipher;
            WireProtocol::receive(
                frame,
                &frame.contract_hash_prefix,
                &guard.keys.encryption_key.0,
                &cipher,
                &self.anti_replay,
            )
            .map_err(|e| match e {
                ipc_contract_system::ProtocolError::AntiReplayDetected => {
                    ContractError::AntiReplayDetected
                }
                ipc_contract_system::ProtocolError::DecryptionFailed => {
                    ContractError::DecryptionError("AEAD".into())
                }
                other => ContractError::Internal(other.to_string()),
            })?
        } else {
            // Sin cifrado no hay integridad garantizada por AEAD: sólo se acepta
            // si la política lo permite explícitamente.
            if self.security_policy.authentication_required
                || self.security_policy.confidentiality_required
            {
                return Err(ContractError::AuthenticationRequired);
            }

            // Aun sin AEAD, la ventana anti-replay sigue aplicando.
            if self.security_policy.anti_replay {
                self.anti_replay
                    .check(frame.session_id, Direction::Rx, frame.sequence)
                    .map_err(|_| ContractError::AntiReplayDetected)?;
            }
            frame.payload.clone()
        };

        let role = { session.read().role };

        let response = match frame.packet_type {
            PacketType::Request => self.process_request(&session, &role, frame, &payload)?,
            PacketType::StreamStart => self.process_stream(&session, &role, frame, PacketType::StreamStart, vec![])?,
            PacketType::StreamData => self.process_stream(&session, &role, frame, PacketType::StreamData, payload)?,
            PacketType::StreamEnd => self.process_stream(&session, &role, frame, PacketType::StreamEnd, vec![])?,
            PacketType::Heartbeat => self.process_heartbeat(&role)?,
            PacketType::Ping => self.process_ping()?,
            PacketType::Close => {
                self.close_session(frame.session_id);
                self.anti_replay.remove_session(frame.session_id);
                return Ok(Frame::new(
                    PacketType::Close,
                    role,
                    frame.session_id,
                    0,
                    0,
                    OperationId::ERROR,
                    TypeId(0),
                    &frame.contract_hash_prefix,
                    vec![],
                ));
            }
            _ => return Err(ContractError::Internal("Unknown packet type".into())),
        };

        Ok(response)
    }

    fn process_request(
        &self,
        session: &Arc<RwLock<Session>>,
        role: &ContractRole,
        frame: &Frame,
        payload: &[u8],
    ) -> Result<Frame> {
        // Parsear request. Todo error de serde se traduce a ContractError:
        // no hay `From<serde_json::Error>` implícito, así que un `?` directo
        // no compila y no puede quedar como panic.
        let request: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|e| ContractError::Internal(format!("Invalid request JSON: {e}")))?;

        let operation = request["operation"].as_str().unwrap_or("").to_string();
        let data = request.get("data").cloned().unwrap_or(serde_json::Value::Null);

        // Buscar operación en el contrato local
        let contract = self
            .contract
            .as_ref()
            .ok_or(ContractError::Internal("no contract loaded".into()))?;
        let op_id = contract
            .operations
            .get_by_name(&operation)
            .ok_or(ContractError::OperationNotFound(0))?;

        // El ID de operación del frame debe existir en el contrato. Sin esta
        // comprobación, un emisor podría invocar una operación arbitraria.
        if frame.operation_id != op_id {
            return Err(ContractError::OperationNotFound(frame.operation_id.0));
        }

        // Eco (en producción, delegar en un handler registrado)
        let result = serde_json::json!({
            "status": "success",
            "operation": operation,
            "echo": data,
        });
        let response_payload = serde_json::to_vec(&result)
            .map_err(|e| ContractError::Internal(format!("respuesta no serializable: {e}")))?;

        let prefix: [u8; 12] = contract.header.contract_hash[..12]
            .try_into()
            .map_err(|_| ContractError::Internal("prefijo inválido".into()))?;

        let seq = { session.write().next_sequence() };

        let mut response = Frame::new(
            PacketType::Response,
            *role,
            frame.session_id,
            seq,
            frame.channel_id,
            op_id,
            TypeId(0),
            &prefix,
            response_payload,
        );

        self.seal(&mut response)?;
        Ok(response)
    }

    fn process_stream(
        &self,
        session: &Arc<RwLock<Session>>,
        role: &ContractRole,
        frame: &Frame,
        kind: PacketType,
        payload: Vec<u8>,
    ) -> Result<Frame> {
        let seq = { session.write().next_sequence() };
        Ok(Frame::new(
            kind,
            *role,
            frame.session_id,
            seq,
            frame.channel_id,
            frame.operation_id,
            TypeId(0),
            &frame.contract_hash_prefix,
            payload,
        ))
    }

    fn process_heartbeat(&self, role: &ContractRole) -> Result<Frame> {
        Ok(Frame::new(
            PacketType::HeartbeatAck,
            *role,
            0,
            0,
            0,
            OperationId::HEALTH_CHECK,
            TypeId(0),
            &[0u8; 12],
            vec![],
        ))
    }

    fn process_ping(&self) -> Result<Frame> {
        Ok(Frame::new(
            PacketType::Pong,
            ContractRole::Mutual,
            0,
            0,
            0,
            OperationId::HEALTH_CHECK,
            TypeId(0),
            &[0u8; 12],
            vec![],
        ))
    }
}

fn main() {
    // Política zero-log: el motor no inicializa `tracing_subscriber`.
    //
    // Una librería de IPC no debe emitir trazas por su cuenta: qué se registra
    // y con qué granularidad es una decisión del proceso que la aloja, y los
    // sinks por defecto escriben en stdout/stderr, que en un runtime móvil
    // suele acabar en `logcat` y es legible por otras apps con el permiso
    // correspondiente. Si el proceso anfitrión quiere trazas, debe instalar
    // su propio subscriber con un filtro explícito.
    //
    // La salida por stdout que queda es deliberada: es la misma que un
    // operador vería al arrancar el binario a mano, y no contiene material
    // de clave, hashes completos ni payloads.

    let engine = IpcEngineV2::new(SecurityPolicy::default());
    let _ = engine;

    println!("IPC Engine v2 - {}", ipc_contract_system::version_info());
    println!("Engine initialized. Waiting for connections...");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_contract() -> Contract {
        use ipc_contract_system::ContractVersion;
        let mut c = Contract::new("demo", "test", ContractVersion::new(1, 0, 0));
        c.finalize().expect("finalize");
        c
    }

    #[test]
    fn engine_uses_random_root_secret() {
        // Con la versión anterior (salt = [0;32]) dos motores distintos
        // derivaban las mismas claves. Ahora cada instancia tiene secreto raíz
        // propio.
        let a = IpcEngineV2::new(SecurityPolicy::default());
        let b = IpcEngineV2::new(SecurityPolicy::default());

        let hash = [7u8; 32];
        let ka = a.key_derivation.derive_session_key(&hash, 1);
        let kb = b.key_derivation.derive_session_key(&hash, 1);

        assert_ne!(ka.0, kb.0, "cada motor debe tener un secreto raíz distinto");
    }

    #[test]
    fn hello_rejects_wrong_contract_identity() {
        let engine = IpcEngineV2::new(SecurityPolicy::default());
        let contract = demo_contract();
        let local_hash = contract.header.contract_hash;

        // Peer con un contrato totalmente distinto
        let other_hash = [0xAAu8; 32];
        let other_prefix: [u8; 12] = other_hash[..12].try_into().unwrap();

        let mut hello = HandshakeHello::from_contract(&other_hash, &SecurityPolicy::default());
        hello.client_challenge = 1;

        let frame = Frame::new(
            PacketType::Hello,
            ContractRole::Mutual,
            0,
            0,
            0,
            OperationId::HANDSHAKE,
            TypeId(0),
            &other_prefix,
            hello.to_bytes(),
        );

        // Prefijo ya no coincide con el contrato local -> rechazo inmediato
        let mut e = engine;
        e.load_contract(contract).unwrap();
        assert!(matches!(
            e.process_hello(&frame),
            Err(ContractError::ContractMismatch)
        ));

        // Y con el prefijo correcto pero hash completo distinto también
        let local_prefix: [u8; 12] = local_hash[..12].try_into().unwrap();
        let mut f2 = frame.clone();
        f2.contract_hash_prefix = local_prefix;
        assert!(matches!(
            e.process_hello(&f2),
            Err(ContractError::ContractMismatch)
        ));
    }

    #[test]
    fn hello_accepts_matching_identity() {
        let mut engine = IpcEngineV2::new(SecurityPolicy::default());
        let contract = demo_contract();
        let local_hash = contract.header.contract_hash;
        engine.load_contract(contract).unwrap();

        let hello = HandshakeHello::from_contract(&local_hash, &SecurityPolicy::default());
        let frame = Frame::new(
            PacketType::Hello,
            ContractRole::Mutual,
            0,
            0,
            0,
            OperationId::HANDSHAKE,
            TypeId(0),
            &local_hash[..12].try_into().unwrap(),
            hello.to_bytes(),
        );

        assert!(engine.process_hello(&frame).is_ok());
    }
}
