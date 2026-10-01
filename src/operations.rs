// =============================================================================
// Sistema de Operaciones con IDs Numéricos
// =============================================================================
//
// En lugar de enviar "operation_name" como string, usamos operation_id:
// - Reduce overhead de red
// - Elimina parsing de strings
// - Permite verificación en compile-time
//
// =============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::types::TypeId;

/// ID numérico para operaciones
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(pub u16);

impl OperationId {
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// Reservado para handshake
    pub const HANDSHAKE: OperationId = OperationId(0x0000);
    pub const AUTH: OperationId = OperationId(0x0001);
    pub const HEALTH_CHECK: OperationId = OperationId(0x0002);
    pub const ERROR: OperationId = OperationId(0xFFFF);
}

/// Rol de operación
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OperationRole {
    /// Operación síncrona request-response
    RequestResponse = 0x01,

    /// Operación de streaming unidireccional
    OneWay = 0x02,

    /// Operación que inicia streaming
    StreamStart = 0x03,

    /// Chunk de stream
    StreamData = 0x04,

    /// Fin de stream
    StreamEnd = 0x05,
}

/// Definición de una operación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    /// Nombre único (para debugging/sourcemaps)
    pub name: String,

    /// ID numérico único (asignado por compilador)
    pub id: OperationId,

    /// Descripción
    pub description: String,

    /// Schema de entrada
    pub input_schema: TypeId,

    /// Schema de salida
    pub output_schema: TypeId,

    /// Schema de error (opcional)
    pub error_schema: Option<TypeId>,

    /// Timeout en milisegundos
    pub timeout_ms: u32,

    /// Si la operación es idempotente
    pub idempotent: bool,

    /// Rol de la operación
    pub role: OperationRole,
}

/// Registro de operaciones
#[derive(Debug, Clone, Default)]
pub struct OperationRegistry {
    /// Mapa de ID a operación
    operations: HashMap<OperationId, Operation>,

    /// Mapa de nombre a ID
    by_name: HashMap<String, OperationId>,

    /// Próximo ID disponible
    next_id: u16,
}

impl OperationRegistry {
    pub fn new() -> Self {
        let mut registry = Self::default();
        registry.next_id = 0x0100; // Empezar después de reservados
        registry
    }

    /// Registrar una operación
    ///
    /// Los IDs reservados (handshake, auth, health-check, error) no pueden ser
    /// asignados a operaciones de usuario: un contrato podría inyectar una
    /// operación con el ID de un paquete de control y alterar la semántica del
    /// protocolo. Si el ID solicitado está reservado o ya existe, se reasigna
    /// desde el rango de usuario.
    pub fn register(&mut self, op: Operation) -> OperationId {
        let requested = op.id;

        let is_reserved = requested == OperationId::ERROR
            || requested == OperationId::HANDSHAKE
            || requested == OperationId::AUTH
            || requested == OperationId::HEALTH_CHECK;

        let final_id = if is_reserved || self.operations.contains_key(&requested) {
            let new_id = OperationId(self.next_id);
            self.next_id = self
                .next_id
                .checked_add(1)
                .filter(|n| *n < OperationId::ERROR.0)
                .unwrap_or(self.next_id);
            new_id
        } else {
            requested
        };

        let mut op = op;
        op.id = final_id;

        self.by_name.insert(op.name.clone(), final_id);
        self.operations.insert(final_id, op);

        final_id
    }

    /// Registrar con ID automático
    pub fn register_auto(&mut self, name: &str, description: &str, input: TypeId, output: TypeId) -> OperationId {
        let id = OperationId(self.next_id);
        self.next_id += 1;

        let op = Operation {
            name: name.to_string(),
            id,
            description: description.to_string(),
            input_schema: input,
            output_schema: output,
            error_schema: None,
            timeout_ms: 30000,
            idempotent: false,
            role: OperationRole::RequestResponse,
        };

        self.operations.insert(id, op.clone());
        self.by_name.insert(name.to_string(), id);

        id
    }

    /// Obtener operación por ID
    pub fn get(&self, id: OperationId) -> Option<&Operation> {
        self.operations.get(&id)
    }

    /// Buscar por nombre
    pub fn get_by_name(&self, name: &str) -> Option<OperationId> {
        self.by_name.get(name).copied()
    }

    /// Iterar sobre todas las operaciones
    pub fn iter(&self) -> impl Iterator<Item = &Operation> {
        self.operations.values()
    }

    /// Serializar a binario
    ///
    /// Canónica: operaciones ordenadas por ID. `HashMap::values()` itera en
    /// orden arbitrario, con lo que el mismo contrato generaría un
    /// `contract_hash` distinto en cada compilación.
    pub fn to_binary(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Número de operaciones
        let count = self.operations.len() as u16;
        buf.extend_from_slice(&count.to_le_bytes());

        let mut ordered: Vec<&Operation> = self.operations.values().collect();
        ordered.sort_by_key(|op| op.id.0);

        for op in ordered {
            // ID
            buf.extend_from_slice(&op.id.0.to_le_bytes());

            // Nombre (u16 length)
            let name_bytes = op.name.as_bytes();
            buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(name_bytes);

            // Descripción (u16 length)
            let desc_bytes = op.description.as_bytes();
            buf.extend_from_slice(&(desc_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(desc_bytes);

            // Schemas. `error_schema` usa 0xFFFF como "ausente" porque 0x0000
            // es un TypeId válido (no está en el rango de primitivos, pero
            // nada impide registrarlo).
            buf.extend_from_slice(&op.input_schema.0.to_le_bytes());
            buf.extend_from_slice(&op.output_schema.0.to_le_bytes());
            let error_id = op.error_schema.map(|s| s.0).unwrap_or(0xFFFF);
            buf.extend_from_slice(&error_id.to_le_bytes());

            // Timeout, idempotent, role
            buf.extend_from_slice(&op.timeout_ms.to_le_bytes());
            buf.extend_from_slice(&[u8::from(op.idempotent), op.role as u8]);
        }

        buf
    }

    /// Deserializar de binario
    ///
    /// Parser totalmente fallible: `from_utf8(...).unwrap()` sobre bytes
    /// remotos se eliminó. Un nombre o descripción con bytes UTF-8 inválidos
    /// produce `Err`, no un panic que tumbe el proceso que escucha el socket.
    pub fn from_binary(data: &[u8]) -> std::io::Result<Self> {
        use std::io::Read;

        fn read_array<const N: usize>(
            cursor: &mut std::io::Cursor<&[u8]>,
            field: &'static str,
        ) -> std::io::Result<[u8; N]> {
            let mut buf = [0u8; N];
            cursor.read_exact(&mut buf).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("{field}: {e}"))
            })?;
            Ok(buf)
        }

        /// Leer un bloque con prefijo de longitud u16, validado contra los
        /// bytes restantes antes de reservar.
        fn read_block(
            cursor: &mut std::io::Cursor<&[u8]>,
            data: &[u8],
            field: &'static str,
        ) -> std::io::Result<String> {
            let len = u16::from_le_bytes(read_array::<2>(cursor, field)?) as usize;
            let remaining = data.len().saturating_sub(cursor.position() as usize);
            if len > remaining {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{field}: declared length exceeds remaining bytes"),
                ));
            }
            let mut buf = vec![0u8; len];
            cursor.read_exact(&mut buf).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e)
            })?;
            String::from_utf8(buf).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{field}: invalid UTF-8"))
            })
        }

        let mut cursor = std::io::Cursor::new(data);
        let mut registry = Self::new();

        let count = u16::from_le_bytes(read_array::<2>(&mut cursor, "operation count")?) as usize;

        const MAX_OPERATION_ENTRIES: usize = 65_535;
        if count > MAX_OPERATION_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "operation count exceeds limit",
            ));
        }

        for _ in 0..count {
            let id = OperationId(u16::from_le_bytes(read_array::<2>(&mut cursor, "operation id")?));
            let name = read_block(&mut cursor, data, "operation name")?;
            let description = read_block(&mut cursor, data, "operation description")?;

            let input_schema = TypeId(u16::from_le_bytes(read_array::<2>(&mut cursor, "input schema")?));
            let output_schema = TypeId(u16::from_le_bytes(read_array::<2>(&mut cursor, "output schema")?));
            let error_id = u16::from_le_bytes(read_array::<2>(&mut cursor, "error schema")?);
            let error_schema = if error_id == 0xFFFF { None } else { Some(TypeId(error_id)) };

            let timeout_ms = u32::from_le_bytes(read_array::<4>(&mut cursor, "timeout")?);
            let flags = read_array::<2>(&mut cursor, "flags")?;
            // Un byte de flags distinto de 0/1 significa corrupción o manipulación.
            if flags[0] > 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid idempotent flag",
                ));
            }
            let idempotent = flags[0] == 1;
            // Role desconocido: se rechaza en vez de degradar silenciosamente
            // a RequestResponse, que cambiaría la semántica del frame.
            let role = OperationRole::try_from(flags[1]).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid operation role")
            })?;

            let op = Operation {
                name,
                id,
                description,
                input_schema,
                output_schema,
                error_schema,
                timeout_ms,
                idempotent,
                role,
            };

            registry.by_name.insert(op.name.clone(), id);
            registry.operations.insert(id, op);
        }

        if (cursor.position() as usize) != data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trailing bytes in operations section",
            ));
        }

        registry.next_id = registry
            .operations
            .keys()
            .map(|id| id.0)
            .max()
            .map_or(0x0100, |max| max.saturating_add(1));

        Ok(registry)
    }
}

impl TryFrom<u8> for OperationRole {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(OperationRole::RequestResponse),
            0x02 => Ok(OperationRole::OneWay),
            0x03 => Ok(OperationRole::StreamStart),
            0x04 => Ok(OperationRole::StreamData),
            0x05 => Ok(OperationRole::StreamEnd),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_registry() {
        let mut registry = OperationRegistry::new();

        let id = registry.register_auto(
            "process_data",
            "Procesa datos",
            TypeId(0x0003), // U32
            TypeId(0x0004), // U64
        );

        assert_eq!(registry.get_by_name("process_data"), Some(id));
        assert!(registry.get(id).is_some());
    }

    #[test]
    fn test_binary_roundtrip() {
        let mut registry = OperationRegistry::new();
        registry.register_auto("test", "Test op", TypeId(0x0001), TypeId(0x0002));

        let binary = registry.to_binary();
        let restored = OperationRegistry::from_binary(&binary).unwrap();

        assert_eq!(registry.iter().count(), restored.iter().count());
    }
}
