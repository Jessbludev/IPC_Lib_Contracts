// =============================================================================
// Sistema de Tipos con IDs Numéricos Estables
// =============================================================================
//
// En lugar de enviar strings como "array<float32>", usamos IDs numéricos:
// - Esto elimina parsing de strings en runtime
// - Garantiza interoperabilidad entre lenguajes
// - Reduce tamaño del payload
//
// =============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ID numérico para tipos
///
/// Se serializa de forma transparente como un entero u16 para mantener
/// compatibilidad con las representaciones JSON canónicas usadas dentro de
/// las secciones del contrato.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TypeId(pub u16);

impl TypeId {
    pub const fn new(id: u16) -> Self {
        Self(id)
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

// =============================================================================
// TIPOS PRIMITIVOS
// =============================================================================

/// Tipos primitivos predefinidos (IDs 0x0001 - 0x00FF)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum PrimitiveType {
    // Enteros sin signo
    U8 = 0x0001,
    U16 = 0x0002,
    U32 = 0x0003,
    U64 = 0x0004,
    U128 = 0x0005,

    // Enteros con signo
    I8 = 0x0011,
    I16 = 0x0012,
    I32 = 0x0013,
    I64 = 0x0014,
    I128 = 0x0015,

    // Flotantes
    F32 = 0x0021,
    F64 = 0x0022,

    // Booleanos
    Bool = 0x0030,

    // Bytes
    Byte = 0x0031,

    // String (UTF-8)
    String = 0x0040,

    // Timestamp (u64 epoch ms)
    Timestamp = 0x0041,

    // Duración (u64 nanosegundos)
    Duration = 0x0042,
}

impl PrimitiveType {
    /// Obtener TypeId para este tipo primitivo
    pub fn type_id(&self) -> TypeId {
        TypeId(*self as u16)
    }

    /// Tamaño en bytes (0 = variable)
    pub fn size(&self) -> Option<usize> {
        match self {
            PrimitiveType::U8 | PrimitiveType::I8 | PrimitiveType::Bool | PrimitiveType::Byte => Some(1),
            PrimitiveType::U16 | PrimitiveType::I16 => Some(2),
            PrimitiveType::U32 | PrimitiveType::I32 | PrimitiveType::F32 => Some(4),
            PrimitiveType::U64 | PrimitiveType::I64 | PrimitiveType::F64 | PrimitiveType::Timestamp | PrimitiveType::Duration => Some(8),
            PrimitiveType::U128 | PrimitiveType::I128 => Some(16),
            PrimitiveType::String => None, // Variable
        }
    }

    /// Verificar si es entero
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            PrimitiveType::U8 | PrimitiveType::U16 | PrimitiveType::U32 | PrimitiveType::U64 | PrimitiveType::U128 |
            PrimitiveType::I8 | PrimitiveType::I16 | PrimitiveType::I32 | PrimitiveType::I64 | PrimitiveType::I128
        )
    }

    /// Verificar si es flotante
    pub fn is_float(&self) -> bool {
        matches!(self, PrimitiveType::F32 | PrimitiveType::F64)
    }
}

// =============================================================================
// TIPOS COMPUESTOS
// =============================================================================

/// Tipos compuestos definidos por el usuario (IDs 0x0100 - 0xFFFF)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeKind {
    /// Tipo primitivo
    Primitive(PrimitiveType),

    /// Arreglo de un tipo
    Array {
        element_type: TypeId,
        max_length: u32,
    },

    /// Objeto con campos
    Object {
        fields: Vec<FieldDef>,
    },

    /// Enum con variantes
    Enum {
        variants: Vec<VariantDef>,
    },

    /// Optional de un tipo
    Optional(TypeId),

    /// Map<clave, valor>
    Map {
        key_type: TypeId,
        value_type: TypeId,
    },

    /// Tipo referencia (forward declaration)
    Reference(String),
}

impl TypeKind {
    /// Calcular ID determinista basado en el contenido
    ///
    /// Se usa BLAKE3-256 (no `DefaultHasher`): `DefaultHasher` no tiene
    /// garantía de estabilidad entre versiones de Rust ni entre procesos, por
    /// lo que no puede participar en una identidad canónica. Los 8 bytes
    /// devueltos son los primeros del digest BLAKE3 del tipo serializado.
    pub fn content_hash(&self) -> u64 {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        let digest = crate::security::blake3_hash(&bytes);
        u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]))
    }
}

/// Definición de campo en objeto
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub type_id: TypeId,
    pub constraints: Vec<Constraint>,
}

/// Definición de variante en enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariantDef {
    pub name: String,
    pub discriminant: u32,
    pub fields: Vec<FieldDef>,
}

/// Restricciones de validación
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Constraint {
    /// Valor mínimo (para numéricos)
    Min(u64),
    /// Valor máximo (para numéricos)
    Max(u64),
    /// Longitud mínima (para strings/arrays)
    MinLength(usize),
    /// Longitud máxima (para strings/arrays)
    MaxLength(usize),
    /// Patrón regex (para strings)
    Pattern(String),
    /// Valor requerido
    Required,
    /// Valor por defecto
    Default(String),
}

// =============================================================================
// REGISTRO DE TIPOS
// =============================================================================

/// Registro de tipos de un contrato
#[derive(Debug, Clone, Default)]
pub struct TypeRegistry {
    /// Tipos primitivos siempre disponibles
    primitives: HashMap<TypeId, PrimitiveType>,

    /// Tipos compuestos (definidos por el usuario)
    compounds: HashMap<TypeId, TypeKind>,

    /// Mapa de nombres a IDs para tipos con nombre
    named_types: HashMap<String, TypeId>,

    /// Próximo ID disponible para tipos compuestos
    next_type_id: u16,
}

impl TypeRegistry {
    pub fn new() -> Self {
        let mut registry = Self::default();

        // Registrar todos los tipos primitivos
        for variant in [
            PrimitiveType::U8, PrimitiveType::U16, PrimitiveType::U32, PrimitiveType::U64, PrimitiveType::U128,
            PrimitiveType::I8, PrimitiveType::I16, PrimitiveType::I32, PrimitiveType::I64, PrimitiveType::I128,
            PrimitiveType::F32, PrimitiveType::F64,
            PrimitiveType::Bool, PrimitiveType::Byte,
            PrimitiveType::String,
            PrimitiveType::Timestamp, PrimitiveType::Duration,
        ] {
            let id = variant.type_id();
            registry.primitives.insert(id, variant);
        }

        registry.next_type_id = 0x0100; // Empezar después de primitivos
        registry
    }

    /// Registrar un tipo compuesto
    pub fn register(&mut self, name: &str, kind: TypeKind) -> TypeId {
        let id = TypeId(self.next_type_id);
        self.next_type_id += 1;

        self.compounds.insert(id, kind);
        if name.is_empty() == false {
            self.named_types.insert(name.to_string(), id);
        }

        id
    }

    /// Obtener tipo primitivo por ID
    pub fn get_primitive(&self, id: TypeId) -> Option<PrimitiveType> {
        self.primitives.get(&id).copied()
    }

    /// Obtener tipo compuesto por ID
    pub fn get_compound(&self, id: TypeId) -> Option<&TypeKind> {
        self.compounds.get(&id)
    }

    /// Buscar tipo por nombre
    pub fn get_by_name(&self, name: &str) -> Option<TypeId> {
        self.named_types.get(name).copied()
    }

    /// Obtener todos los tipos compuestos
    pub fn compounds(&self) -> impl Iterator<Item = (&TypeId, &TypeKind)> {
        self.compounds.iter()
    }

    /// Serializar a formato binario
    ///
    /// La sección de tipos es canónica: los IDs se emiten en orden ascendente
    /// para que el hash del contrato sea reproducible. Un `HashMap` itera en
    /// orden arbitrario, lo que haría que el mismo contrato produjese hashes
    /// distintos en cada ejecución.
    pub fn to_binary(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Número de tipos compuestos
        let count = self.compounds.len() as u16;
        buf.extend_from_slice(&count.to_le_bytes());

        // Tipos en orden ascendente de ID (determinista)
        let mut ordered: Vec<(&TypeId, &TypeKind)> = self.compounds.iter().collect();
        ordered.sort_by_key(|(id, _)| id.0);

        for (id, kind) in ordered {
            buf.extend_from_slice(&id.0.to_le_bytes());
            let kind_bytes = serde_json::to_vec(kind).unwrap_or_default();
            // Longitud en u32: un truncamiento silencioso a u16 rompería
            // contratos con definiciones grandes.
            buf.extend_from_slice(&(kind_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&kind_bytes);
        }

        buf
    }

    /// Deserializar de formato binario
    ///
    /// Parser fallible: cualquier byte remoto malformado produce `Err`, nunca
    /// un panic. Las longitudes declaradas se validan contra los bytes
    /// realmente disponibles antes de reservar memoria, para que un atacante no
    /// pueda provocar una asignación enorme con una cabecera falsificada.
    pub fn from_binary(data: &[u8]) -> std::io::Result<Self> {
        use std::io::Read;

        /// Extraer un entero de `N` bytes en little-endian sin indexación directa
        fn read_array<const N: usize>(
            cursor: &mut std::io::Cursor<&[u8]>,
            field: &'static str,
        ) -> std::io::Result<[u8; N]> {
            let mut buf = [0u8; N];
            cursor
                .read_exact(&mut buf)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("{field}: {e}")))?;
            Ok(buf)
        }

        let mut cursor = std::io::Cursor::new(data);
        let mut registry = Self::new();

        // Leer número de tipos
        let count = u16::from_le_bytes(read_array::<2>(&mut cursor, "count")?) as usize;

        // Tope de seguridad: evita reservar memoria a partir de un conteo
        // arbitrario declarado por el emisor.
        const MAX_TYPE_ENTRIES: usize = 65_535;
        if count > MAX_TYPE_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "compound type count exceeds limit",
            ));
        }

        for _ in 0..count {
            let id = TypeId(u16::from_le_bytes(read_array::<2>(&mut cursor, "type id")?));
            let len = u32::from_le_bytes(read_array::<4>(&mut cursor, "type length")?) as usize;

            // La longitud declarada no puede exceder lo que queda en el buffer.
            let remaining = data.len().saturating_sub(cursor.position() as usize);
            if len > remaining {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "declared type length exceeds remaining bytes",
                ));
            }

            let mut kind_bytes = vec![0u8; len];
            cursor
                .read_exact(&mut kind_bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e))?;
            let kind: TypeKind = serde_json::from_slice(&kind_bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            registry.compounds.insert(id, kind);
        }

        // El emisor debe consumir exactamente la sección: bytes sobrantes
        // indicarían ambigüedad en el framing.
        if (cursor.position() as usize) != data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trailing bytes in types section",
            ));
        }

        // `named_types` no se reconstruye desde el binario: solo se usa para
        // generación de código, y el hash canónico se calcula sobre
        // `compounds`, por lo que esto no altera la identidad del contrato.
        registry.next_type_id = registry
            .compounds
            .keys()
            .map(|id| id.0)
            .max()
            .map_or(0x0100, |max| max.saturating_add(1));

        Ok(registry)
    }
}

// =============================================================================
// TRAITS PARA SERIALIZACIÓN
// =============================================================================

/// Trait para valores que pueden serializarse según el sistema de tipos
pub trait TypedSerialize {
    fn serialize(&self, type_id: TypeId, registry: &TypeRegistry) -> Vec<u8>;

    fn deserialize(data: &[u8], type_id: TypeId, registry: &TypeRegistry) -> Option<Self>
    where Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_type_ids() {
        assert_eq!(PrimitiveType::U32.type_id(), TypeId(0x0003));
        assert_eq!(PrimitiveType::String.type_id(), TypeId(0x0040));
    }

    #[test]
    fn test_primitive_sizes() {
        assert_eq!(PrimitiveType::U32.size(), Some(4));
        assert_eq!(PrimitiveType::String.size(), None);
    }

    #[test]
    fn test_type_registry() {
        let mut registry = TypeRegistry::new();

        let id = registry.register("MyArray", TypeKind::Array {
            element_type: PrimitiveType::U32.type_id(),
            max_length: 1024,
        });

        assert_eq!(registry.get_by_name("MyArray"), Some(id));
        assert!(matches!(
            registry.get_compound(id),
            Some(TypeKind::Array { .. })
        ));
    }

    #[test]
    fn test_binary_serialization() {
        let mut registry = TypeRegistry::new();

        registry.register("Test", TypeKind::Object {
            fields: vec![
                FieldDef {
                    name: "id".to_string(),
                    type_id: PrimitiveType::U64.type_id(),
                    constraints: vec![],
                },
            ],
        });

        let binary = registry.to_binary();
        let restored = TypeRegistry::from_binary(&binary).unwrap();

        assert_eq!(registry.compounds().count(), restored.compounds().count());
    }
}
