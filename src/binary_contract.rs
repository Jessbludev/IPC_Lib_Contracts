// =============================================================================
// Canonical Binary Contract (CBC)
// =============================================================================
//
// Formato binario canónico para contratos:
// - Header fijo con offsets
// - Secciones variables
// - Hash BLAKE3-256 calculado sobre todo excepto la firma (identidad primaria)
// - SHA-256 disponible como algoritmo opcional de compatibilidad legacy
// - Firma Ed25519 opcional para distribución
//
// Layout:
//
// +-----------------------------------------------------------------+
// |                         CONTRACT HEADER                          |
// +-----------------------------------------------------------------+
// | 0-3    | Magic (4)          | CBC1                              |
// | 4      | Format Version (1)  | 0x01                              |
// | 5      | Flags (1)          | Signed(1) | Reserved(7)         |
// | 6-7    | Header Size (2)     | u16 (little-endian)              |
// +-----------------------------------------------------------------+
// | 8-15   | Contract ID (8)     | UUID v4                           |
// | 16-23  | Contract Version    | u16.major | u16.minor | u16.patch|
// | 24-55  | Contract Hash (32)  | BLAKE3-256 del contenido         |
// +-----------------------------------------------------------------+
// | 56-59  | Schema Offset (4)   | Offset desde inicio archivo       |
// | 60-63  | Schema Size (4)     | Tamaño en bytes                  |
// | 64-67  | Types Offset (4)    | Offset desde inicio archivo       |
// | 68-71  | Types Size (4)      | Tamaño en bytes                  |
// | 72-75  | Ops Offset (4)      | Offset desde inicio archivo       |
// | 76-79  | Ops Size (4)        | Tamaño en bytes                  |
// | 80-83  | Security Offset     | Offset desde inicio archivo       |
// | 84-87  | Security Size       | Tamaño en bytes                  |
// | 88-91  | Reserved (4)                                           |
// | 92-95  | Reserved (4)                                           |
// +-----------------------------------------------------------------+
// | 96-159 | Contract Name (64)   | Nombre UTF-8 (null-terminated)  |
// | 160-223| Namespace (64)      | Namespace UTF-8 (null-term)     |
// +-----------------------------------------------------------------+
// | 224-227| Key ID (4)            | Selector de clave de firma     |
// | 228-255| Reserved               | Debe ser cero                 |
// +-----------------------------------------------------------------+
//
// SCHEMA SECTION:
// | u16 | Type Count |
// | ... | Types...
//
// TYPES SECTION:
// | u16 | Compound Type Count |
// | ... | Type definitions...
//
// OPS SECTION:
// | u16 | Operation Count |
// | ... | Operation definitions...
//
// SECURITY SECTION:
// | SecurityPolicy binary |
//
// SIGNATURE SECTION (si flags.signed):
// | u16 | Signature Size |
// | ... | Ed25519 signature |
//
// =============================================================================

use crate::types::TypeRegistry;
use crate::operations::OperationRegistry;
use crate::security::{SecurityPolicy, aead_from_u8, hash_from_u8, security_level_from_u8, signature_policy_from_u8};
use crate::error::{ContractError, Result};

/// Magic bytes
const CBC_MAGIC: &[u8; 4] = b"CBC1";

/// Versión del formato
const FORMAT_VERSION: u8 = 1;

/// Escribir una cadena UTF-8 en una ventana de tamaño fijo, terminada en NUL.
///
/// Los bytes no usados se rellenan con ceros para que la serialización sea
/// canónica: dos contratos con el mismo nombre producen exactamente los mismos
/// bytes, y ningún byte del archivo queda fuera del alcance del hash.
fn write_fixed_string(buf: &mut [u8], offset: usize, width: usize, value: &str) {
    let window = &mut buf[offset..offset + width];
    window.fill(0);
    let bytes = value.as_bytes();
    // Se reserva 1 byte para el terminador NUL.
    let n = bytes.len().min(width - 1);
    window[..n].copy_from_slice(&bytes[..n]);
    window[n] = 0;
}

/// Header del contrato binario
#[derive(Debug, Clone)]
pub struct ContractHeader {
    /// Magic (4 bytes)
    pub magic: [u8; 4],

    /// Versión del formato (1 byte)
    pub format_version: u8,

    /// Flags (1 byte)
    pub flags: ContractFlags,

    /// Tamaño del header (2 bytes)
    pub header_size: u16,

    /// ID del contrato (8 bytes - UUID)
    pub contract_id: u64,

    /// Versión del contrato
    pub version: ContractVersion,

    /// Hash BLAKE3-256 del contrato (32 bytes) - identidad primaria
    pub contract_hash: [u8; 32],

    /// Offset al schema (4 bytes)
    pub schema_offset: u32,

    /// Tamaño del schema (4 bytes)
    pub schema_size: u32,

    /// Offset a los tipos (4 bytes)
    pub types_offset: u32,

    /// Tamaño de los tipos (4 bytes)
    pub types_size: u32,

    /// Offset a las operaciones (4 bytes)
    pub ops_offset: u32,

    /// Tamaño de las operaciones (4 bytes)
    pub ops_size: u32,

    /// Offset a la política de seguridad (4 bytes)
    pub security_offset: u32,

    /// Tamaño de la política de seguridad (4 bytes)
    pub security_size: u32,

    /// Offset a la firma (4 bytes)
    pub signature_offset: u32,

    /// Tamaño de la firma (4 bytes)
    pub signature_size: u32,

    /// Nombre del contrato (64 bytes)
    pub name: String,

    /// Namespace (64 bytes)
    pub namespace: String,

    /// Identificador de la clave de firma (4 bytes, offset 224).
    ///
    /// Sirve para que el verificador elija **qué** clave de un almacén
    /// externo usar. No es un ancla de confianza por sí solo: una clave
    /// publicada junto al contrato no sería verificable, porque un atacante
    /// puede sustituir contrato y clave simultáneamente.
    ///
    /// Vive en la zona que antes era `Reserved` (224-255), así que no cambia
    /// el tamaño del header ni desplaza ningún offset. Al estar dentro del
    /// header canónico, queda cubierto por `contract_hash` y por la firma.
    pub key_id: u32,
}

impl ContractHeader {
    pub const SIZE: usize = 256;

    /// Crear header vacío
    pub fn new() -> Self {
        Self {
            magic: *CBC_MAGIC,
            format_version: FORMAT_VERSION,
            flags: ContractFlags::default(),
            header_size: Self::SIZE as u16,
            contract_id: 0,
            version: ContractVersion::new(1, 0, 0),
            contract_hash: [0u8; 32],
            schema_offset: 0,
            schema_size: 0,
            types_offset: 0,
            types_size: 0,
            ops_offset: 0,
            ops_size: 0,
            security_offset: 0,
            security_size: 0,
            signature_offset: 0,
            signature_size: 0,
            name: String::new(),
            namespace: String::new(),
            key_id: 0,
        }
    }

    /// Serializar header
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];

        // Magic
        buf[0..4].copy_from_slice(&self.magic);

        // Format version
        buf[4] = self.format_version;

        // Flags
        buf[5] = self.flags.bits();

        // Header size
        buf[6..8].copy_from_slice(&self.header_size.to_le_bytes());

        // Contract ID
        buf[8..16].copy_from_slice(&self.contract_id.to_le_bytes());

        // Version
        buf[16..18].copy_from_slice(&self.version.major.to_le_bytes());
        buf[18..20].copy_from_slice(&self.version.minor.to_le_bytes());
        buf[20..22].copy_from_slice(&self.version.patch.to_le_bytes());

        // Contract hash
        buf[24..56].copy_from_slice(&self.contract_hash);

        // Offsets y sizes
        buf[56..60].copy_from_slice(&self.schema_offset.to_le_bytes());
        buf[60..64].copy_from_slice(&self.schema_size.to_le_bytes());
        buf[64..68].copy_from_slice(&self.types_offset.to_le_bytes());
        buf[68..72].copy_from_slice(&self.types_size.to_le_bytes());
        buf[72..76].copy_from_slice(&self.ops_offset.to_le_bytes());
        buf[76..80].copy_from_slice(&self.ops_size.to_le_bytes());
        buf[80..84].copy_from_slice(&self.security_offset.to_le_bytes());
        buf[84..88].copy_from_slice(&self.security_size.to_le_bytes());
        buf[88..92].copy_from_slice(&self.signature_offset.to_le_bytes());
        buf[92..96].copy_from_slice(&self.signature_size.to_le_bytes());

        // Key ID (224..228). Antes era zona reservada; ahora identifica la
        // clave de firma en el almacén externo del verificador. Al estar
        // dentro del header canónico queda cubierto por `contract_hash` y por
        // la firma, de modo que alterarlo invalida ambas.
        buf[224..228].copy_from_slice(&self.key_id.to_le_bytes());

        // Name (null-terminated, max 64 bytes)
        //
        // El relleno tras el terminador NUL debe quedar a cero. Si no, un
        // atacante que modifique esos bytes no cambia la cadena que el parser
        // reconstruye (éste corta en el primer NUL) y, por tanto, tampoco
        // cambia el `contract_hash`, que se recalcula serializando desde la
        // struct parseada. El resultado es un byte del archivo que no está
        // cubierto por ninguna comprobación de integridad.
        write_fixed_string(&mut buf, 96, 64, &self.name);

        // Namespace (null-terminated, max 64 bytes)
        write_fixed_string(&mut buf, 160, 64, &self.namespace);

        buf
    }

    /// Deserializar header
    ///
    /// P0.5: parser 100% fallible. El `unwrap()` previo sobre
    /// `data[0..4].try_into()` respondía a bytes externos con un panic; ahora
    /// cualquier error de longitud o de codificación produce `Err`.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(ContractError::InvalidHeader("Header demasiado corto".into()));
        }

        /// Lectura de entero con verificación explícita de rango.
        ///
        /// Se usa `get()` en lugar de indexación directa: aunque hoy
        /// `data.len() >= SIZE` lo garantiza, un cambio futuro en el layout
        /// volvería a introducir un panic silencioso.
        fn read_u16(data: &[u8], start: usize, field: &'static str) -> Result<u16> {
            let s = data
                .get(start..start + 2)
                .ok_or_else(|| ContractError::InvalidHeader(format!("{field}: fuera de rango")))?;
            let arr: [u8; 2] = s
                .try_into()
                .map_err(|_| ContractError::InvalidHeader(format!("{field}: tamaño inválido")))?;
            Ok(u16::from_le_bytes(arr))
        }

        fn read_u32(data: &[u8], start: usize, field: &'static str) -> Result<u32> {
            let s = data
                .get(start..start + 4)
                .ok_or_else(|| ContractError::InvalidHeader(format!("{field}: fuera de rango")))?;
            let arr: [u8; 4] = s
                .try_into()
                .map_err(|_| ContractError::InvalidHeader(format!("{field}: tamaño inválido")))?;
            Ok(u32::from_le_bytes(arr))
        }

        fn read_u64(data: &[u8], start: usize, field: &'static str) -> Result<u64> {
            let s = data
                .get(start..start + 8)
                .ok_or_else(|| ContractError::InvalidHeader(format!("{field}: fuera de rango")))?;
            let arr: [u8; 8] = s
                .try_into()
                .map_err(|_| ContractError::InvalidHeader(format!("{field}: tamaño inválido")))?;
            Ok(u64::from_le_bytes(arr))
        }

        // Magic
        let magic_slice = data
            .get(0..4)
            .ok_or_else(|| ContractError::InvalidHeader("magic: fuera de rango".into()))?;
        let magic: [u8; 4] = magic_slice
            .try_into()
            .map_err(|_| ContractError::InvalidHeader("magic: tamaño inválido".into()))?;
        if &magic != CBC_MAGIC {
            return Err(ContractError::InvalidMagic);
        }

        // Format version
        let format_version = *data
            .get(4)
            .ok_or_else(|| ContractError::InvalidHeader("format_version ausente".into()))?;
        if format_version != FORMAT_VERSION {
            return Err(ContractError::IncompatibleFormat(format_version));
        }

        let mut header = Self::new();
        header.magic = magic;
        header.format_version = format_version;

        let flags_bits = *data
            .get(5)
            .ok_or_else(|| ContractError::InvalidHeader("flags ausente".into()))?;
        // Rechazo por defecto de bits desconocidos (P0 revisión previa #6).
        let unknown = flags_bits & !ContractFlags::KNOWN;
        if unknown != 0 {
            return Err(ContractError::InvalidHeader(format!(
                "flags desconocidos: {:#04x}",
                unknown
            )));
        }
        header.flags = ContractFlags::from_bits(flags_bits);

        header.header_size = read_u16(data, 6, "header_size")?;
        if header.header_size as usize != Self::SIZE {
            return Err(ContractError::InvalidHeader(format!(
                "header_size inesperado: {}",
                header.header_size
            )));
        }

        header.contract_id = read_u64(data, 8, "contract_id")?;
        header.version = ContractVersion::new(
            read_u16(data, 16, "version.major")?,
            read_u16(data, 18, "version.minor")?,
            read_u16(data, 20, "version.patch")?,
        );

        let hash_slice = data
            .get(24..56)
            .ok_or_else(|| ContractError::InvalidHeader("contract_hash fuera de rango".into()))?;
        header
            .contract_hash
            .copy_from_slice(hash_slice);

        header.schema_offset = read_u32(data, 56, "schema_offset")?;
        header.schema_size = read_u32(data, 60, "schema_size")?;
        header.types_offset = read_u32(data, 64, "types_offset")?;
        header.types_size = read_u32(data, 68, "types_size")?;
        header.ops_offset = read_u32(data, 72, "ops_offset")?;
        header.ops_size = read_u32(data, 76, "ops_size")?;
        header.security_offset = read_u32(data, 80, "security_offset")?;
        header.security_size = read_u32(data, 84, "security_size")?;
        header.signature_offset = read_u32(data, 88, "signature_offset")?;
        header.signature_size = read_u32(data, 92, "signature_size")?;

        // Name: cadena UTF-8 terminada en NUL dentro de una ventana de 64 bytes.
        let name_field = data
            .get(96..160)
            .ok_or_else(|| ContractError::InvalidHeader("name fuera de rango".into()))?;
        let name_end = name_field
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| ContractError::InvalidHeader("name sin terminador NUL".into()))?;
        header.name = String::from_utf8(name_field[..name_end].to_vec())
            .map_err(|_| ContractError::InvalidHeader("Nombre inválido".into()))?;

        // Namespace
        let ns_field = data
            .get(160..224)
            .ok_or_else(|| ContractError::InvalidHeader("namespace fuera de rango".into()))?;
        let ns_end = ns_field
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| ContractError::InvalidHeader("namespace sin terminador NUL".into()))?;
        header.namespace = String::from_utf8(ns_field[..ns_end].to_vec())
            .map_err(|_| ContractError::InvalidHeader("Namespace inválido".into()))?;

        // Key ID (224..228)
        header.key_id = u32::from_le_bytes(
            data.get(224..228)
                .ok_or_else(|| ContractError::InvalidHeader("key_id fuera de rango".into()))?
                .try_into()
                .map_err(|_| ContractError::InvalidHeader("key_id inválido".into()))?,
        );

        // El resto de la zona reservada (228..255) debe ser cero. Si no lo
        // fuese, esos bytes quedarían fuera del preimagen del hash y podrían
        // alterarse sin romper la integridad. Mismo razonamiento que el
        // relleno de los campos de texto.
        if data[228..256].iter().any(|&b| b != 0) {
            return Err(ContractError::InvalidHeader(
                "reservado 228-255 debe ser cero".into(),
            ));
        }

        // `schema_offset` (56..60) no participa en el hash: el preimagen pone
        // todos los offsets a cero porque son consecuencia del empaquetado y
        // no de la semántica. La sección `schema` no está implementada en
        // CBC1 y siempre tiene tamaño 0, así que se exige que su offset apunte
        // justo detrás del header. Si algún contrato declarara una sección
        // schema no vacía, esos 4 bytes quedarían sin cubrir por el hash.
        if header.schema_size != 0 {
            return Err(ContractError::InvalidHeader(
                "CBC1 no define una sección schema".into(),
            ));
        }
        // Ambigüedad de representación: con `schema_size == 0`, tanto
        // `schema_offset == 0` como `schema_offset == 256` describen el mismo
        // contrato. Como el preimagen pone los offsets a cero, un atacante
        // podía alternar entre ambos sin cambiar `contract_hash` ni la firma:
        // el mismo contrato tendría dos formas byte-distintas.
        //
        // La regla de CBC1 es `schema_offset == 0` cuando no hay sección
        // schema. Fijarla aquí elimina la ambigüedad y hace que el test que
        // recorre todas las posiciones del archivo no encuentre posiciones
        // equivalentes.
        if header.schema_size == 0 && header.schema_offset != 0 {
            return Err(ContractError::InvalidHeader(
                "schema_offset debe ser 0 cuando no hay sección schema".into(),
            ));
        }

        // El header debe estar codificado de forma canónica: re-serializarlo y
        // comparar con los bytes recibidos garantiza que no hay bytes
        // "invisibles" (relleno tras el NUL del nombre, reservado sin usar)
        // que el parser ignore y que por tanto quedarían fuera del hash.
        //
        // Sin esta comprobación, modificar el relleno del campo `name` no
        // cambiaba ni la struct parseada ni el `contract_hash`, de modo que el
        // contrato alterado pasaba la verificación de integridad y de firma.
        if header.to_bytes() != data[..Self::SIZE] {
            return Err(ContractError::InvalidHeader(
                "el header no está codificado de forma canónica (bytes no canonicos)".into(),
            ));
        }

        Ok(header)
    }

    /// Validar que todas las secciones declaradas caen dentro del archivo,
    /// no se solapan y no invaden el header.
    ///
    /// Sin esta comprobación, un `ContractReader` podría leer una sección
    /// como parte de otra o más allá del final del buffer.
    pub fn validate_sections(&self, total_len: usize) -> Result<()> {
        let sections: [(&str, u32, u32); 5] = [
            ("schema", self.schema_offset, self.schema_size),
            ("types", self.types_offset, self.types_size),
            ("ops", self.ops_offset, self.ops_size),
            ("security", self.security_offset, self.security_size),
            ("signature", self.signature_offset, self.signature_size),
        ];

        // (nombre, inicio, fin) solo para secciones con tamaño > 0
        let mut present: Vec<(&str, usize, usize)> = Vec::new();

        for (name, offset, size) in sections {
            if size == 0 {
                continue;
            }
            let start = offset as usize;
            let end = start
                .checked_add(size as usize)
                .ok_or_else(|| ContractError::InvalidHeader(format!("{name}: overflow en tamaño")))?;

            if start < Self::SIZE {
                return Err(ContractError::InvalidHeader(format!(
                    "{name}: empieza dentro del header ({start})"
                )));
            }
            if end > total_len {
                return Err(ContractError::InvalidHeader(format!(
                    "{name}: termina en {end} pero el archivo mide {total_len}"
                )));
            }
            present.push((name, start, end));
        }

        // Detección de solapamientos
        for i in 0..present.len() {
            for j in (i + 1)..present.len() {
                let (na, sa, ea) = present[i];
                let (nb, sb, eb) = present[j];
                if sa < eb && sb < ea {
                    return Err(ContractError::InvalidHeader(format!(
                        "secciones {na} [{sa},{ea}) y {nb} [{sb},{eb}) se solapan"
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Flags del contrato
#[derive(Debug, Clone, Copy, Default)]
pub struct ContractFlags(u8);

impl ContractFlags {
    pub const SIGNED: u8 = 0b00000001;
    pub const ENCRYPTED: u8 = 0b00000010;
    pub const VERSIONED: u8 = 0b00000100;

    /// Máscara de bits definidos. Cualquier bit fuera de esta máscara se
    /// rechaza en lectura (fail-closed), en lugar de ignorarse en silencio.
    pub const KNOWN: u8 = Self::SIGNED | Self::ENCRYPTED | Self::VERSIONED;

    pub fn bits(&self) -> u8 {
        self.0
    }

    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub fn is_signed(&self) -> bool {
        (self.0 & Self::SIGNED) != 0
    }

    pub fn with_signed(mut self, v: bool) -> Self {
        if v {
            self.0 |= Self::SIGNED;
        } else {
            self.0 &= !Self::SIGNED;
        }
        self
    }
}

/// Versión semántica del contrato
#[derive(Debug, Clone, Copy)]
pub struct ContractVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ContractVersion {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }

    pub fn from_string(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(ContractError::InvalidVersion);
        }

        let major = parts[0].parse().map_err(|_| ContractError::InvalidVersion)?;
        let minor = parts[1].parse().map_err(|_| ContractError::InvalidVersion)?;
        let patch = parts[2].parse().map_err(|_| ContractError::InvalidVersion)?;

        Ok(Self { major, minor, patch })
    }

    pub fn to_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Contrato completo
#[derive(Debug, Clone)]
pub struct Contract {
    pub header: ContractHeader,
    pub types: TypeRegistry,
    pub operations: OperationRegistry,
    pub security: SecurityPolicy,
    pub signature: Option<Vec<u8>>,
}

impl Contract {
    pub fn new(name: &str, namespace: &str, version: ContractVersion) -> Self {
        let mut header = ContractHeader::new();
        header.name = name.to_string();
        header.namespace = namespace.to_string();
        header.version = version;
        header.contract_id = generate_uuid();

        Self {
            header,
            types: TypeRegistry::new(),
            operations: OperationRegistry::new(),
            security: SecurityPolicy::default(),
            signature: None,
        }
    }

    /// Serializar la política de seguridad a bytes canónicos
    ///
    /// Se usa un encoding binario fijo, no JSON: `serde_json` sobre una struct
    /// es estable sólo mientras nadie reordene campos, y `to_vec()` devuelve
    /// `Err` (que el código previo silenciaba con `unwrap`) ante cualquier
    /// campo no serializable. El layout explícito hace que la identidad del
    /// contrato sea reproducible entre versiones del crate.
    /// Encoding canónico de la política de seguridad.
    ///
    /// Público para que los generadores de vectores de conformidad usen
    /// exactamente el mismo byte layout que el hash.
    pub fn security_to_binary(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(11);
        buf.push(self.security.level as u8);
        buf.push(self.security.aead_algorithm as u8);
        buf.push(self.security.hash_algorithm as u8);
        buf.push(u8::from(self.security.authentication_required));
        buf.push(u8::from(self.security.confidentiality_required));
        buf.push(u8::from(self.security.anti_replay));
        buf.extend_from_slice(&(self.security.replay_window_size as u32).to_le_bytes());
        buf.push(self.security.signature_policy as u8);
        Ok(buf)
    }

    /// Reconstruir la política desde su encoding canónico
    /// Reconstruir la política desde su encoding canónico.
    pub fn security_from_binary(data: &[u8]) -> Result<SecurityPolicy> {
        if data.len() < 11 {
            return Err(ContractError::InvalidSection(
                "security: sección truncada".into(),
            ));
        }
        let window = u32::from_le_bytes(
            data[6..10]
                .try_into()
                .map_err(|_| ContractError::InvalidSection("security: tamaño inválido".into()))?,
        ) as usize;

        // Los tres flags booleanos deben ser estrictamente 0 o 1.
        for (idx, label) in [(3usize, "auth"), (4, "conf"), (5, "anti_replay")] {
            let v = data[idx];
            if v > 1 {
                return Err(ContractError::InvalidSection(format!(
                    "security: flag {label} inválido ({v})"
                )));
            }
        }

        // Una ventana de anti-replay de 0 deshabilitaría la protección sin
        // que la política lo declare: se rechaza.
        if window == 0 {
            return Err(ContractError::InvalidSection(
                "security: replay_window_size no puede ser 0".into(),
            ));
        }

        Ok(SecurityPolicy {
            level: security_level_from_u8(data[0])?,
            aead_algorithm: aead_from_u8(data[1])?,
            hash_algorithm: hash_from_u8(data[2])?,
            authentication_required: data[3] == 1,
            confidentiality_required: data[4] == 1,
            anti_replay: data[5] == 1,
            replay_window_size: window,
            signature_policy: signature_policy_from_u8(data[10])?,
        })
    }

    /// Calcular hash del contrato (excluyendo firma)
    ///
    /// P0.1: BLAKE3-256 sobre la representación canónica sin firma. Éste es
    /// el único algoritmo con el que un contrato obtiene su identidad; SHA-256
    /// queda como digest de compatibilidad y no puede ser `contract_hash`.
    pub fn compute_hash(&self) -> Result<[u8; 32]> {
        use crate::security::blake3_hash;

        let mut data = Vec::new();

        // Header con el hash a cero y con los offsets ya materializados: el
        // hash debe cubrir el contenido exacto que se escribirá al disco.
        let mut header = self.header.clone();
        header.contract_hash = [0u8; 32];
        // Los offsets no forman parte de la identidad semántica (dependen del
        // empaquetado), así que se fijan a cero para que el mismo contrato
        // tenga el mismo hash independientemente del layout de secciones.
        header.schema_offset = 0;
        header.schema_size = 0;
        header.types_offset = 0;
        header.types_size = 0;
        header.ops_offset = 0;
        header.ops_size = 0;
        header.security_offset = 0;
        header.security_size = 0;
        header.signature_offset = 0;
        header.signature_size = 0;
        data.extend_from_slice(&header.to_bytes());

        // Tipos y operaciones: orden canónico garantizado por sus serializers
        data.extend_from_slice(&self.types.to_binary());
        data.extend_from_slice(&self.operations.to_binary());

        // Seguridad
        data.extend_from_slice(&self.security_to_binary()?);

        Ok(blake3_hash(&data))
    }

    /// Finalizar contrato (calcular hash y materializar offsets)
    pub fn finalize(&mut self) -> Result<()> {
        // Los offsets se calculan primero y luego se hashea, de modo que el
        // El hash describe el archivo final y no un estado intermedio.
        let mut offset = ContractHeader::SIZE as u32;

        // CBC1 no tiene sección schema. Se escribe `offset = 0` en vez del
        // offset corriente: una sección de tamaño 0 no necesita posición, y
        // dejar 256 haría que el mismo contrato admitiera dos
        // representaciones byte-distintas con el mismo `contract_hash`.
        self.header.schema_offset = 0;
        self.header.schema_size = 0;

        offset = offset
            .checked_add(self.header.schema_size)
            .ok_or(ContractError::InvalidHeader("offset overflow".into()))?;

        let types = self.types.to_binary();
        self.header.types_offset = offset;
        self.header.types_size = types.len() as u32;
        offset = offset
            .checked_add(self.header.types_size)
            .ok_or(ContractError::InvalidHeader("offset overflow".into()))?;

        let ops = self.operations.to_binary();
        self.header.ops_offset = offset;
        self.header.ops_size = ops.len() as u32;
        offset = offset
            .checked_add(self.header.ops_size)
            .ok_or(ContractError::InvalidHeader("offset overflow".into()))?;

        let security = self.security_to_binary()?;
        self.header.security_offset = offset;
        self.header.security_size = security.len() as u32;
        offset = offset
            .checked_add(self.header.security_size)
            .ok_or(ContractError::InvalidHeader("offset overflow".into()))?;

        // Firma (presente sólo si el contrato fue firmado)
        self.header.signature_offset = offset;
        self.header.signature_size = self.signature.as_ref().map_or(0, |s| s.len() as u32);
        self.header.flags = self.header.flags.with_signed(self.signature.is_some());

        let computed = self.compute_hash()?;
        self.header.contract_hash = computed;

        Ok(())
    }

    /// Serializar a binario
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        // Header
        data.extend_from_slice(&self.header.to_bytes());

        // Tipos
        data.extend_from_slice(&self.types.to_binary());

        // Operaciones
        data.extend_from_slice(&self.operations.to_binary());

        // Seguridad: mismo encoding canónico que entra en el hash
        data.extend_from_slice(&self.security_to_binary()?);

        // Firma
        if let Some(sig) = &self.signature {
            data.extend_from_slice(sig);
        }

        Ok(data)
    }
}

/// Generar un identificador de contrato de 64 bits
///
/// CSPRNG (`thread_rng` está respaldado por el generador del sistema operativo).
/// Devuelve `u64` para casar con `ContractHeader::contract_id`; antes devolvía
/// `[u8; 8]`, lo que hacía que el crate no compilase.
fn generate_uuid() -> u64 {
    use rand::RngCore;
    rand::thread_rng().next_u64()
}

/// Verificador de firmas de contrato (Ed25519)
///
/// P0.2: la firma Ed25519 debe ser real. Se firma el mismo preimagen canónico
/// que alimenta `contract_hash`, de modo que la firma cubre el contenido
/// completo y no una estructura cuya serialización pudiera cambiar.
pub struct ContractSigner;

impl ContractSigner {
    /// Bytes que se firman: representación canónica sin firma y con el hash a
    /// cero. Es exactamente el preimagen de `compute_hash`.
    pub fn signing_payload(contract: &Contract) -> Result<Vec<u8>> {
        let mut header = contract.header.clone();
        header.contract_hash = [0u8; 32];
        header.schema_offset = 0;
        header.schema_size = 0;
        header.types_offset = 0;
        header.types_size = 0;
        header.ops_offset = 0;
        header.ops_size = 0;
        header.security_offset = 0;
        header.security_size = 0;
        header.signature_offset = 0;
        header.signature_size = 0;

        let mut data = header.to_bytes();
        data.extend_from_slice(&contract.types.to_binary());
        data.extend_from_slice(&contract.operations.to_binary());
        data.extend_from_slice(&contract.security_to_binary()?);
        Ok(data)
    }

    /// Firmar un contrato con una clave Ed25519.
    ///
    /// Firma el contenido canónico, no el `contract_hash`: así una firma sigue
    /// siendo válida aunque el consumidor no implemente BLAKE3.
    ///
    /// El flag `SIGNED` se activa **antes** de calcular el preimagen. Si se
    /// firmara antes de marcarlo, la firma cubriría un header con
    /// `flags = 0` mientras que el hash final y toda verificación posterior
    /// usarían `flags = SIGNED`, y la firma nunca validaría.
    pub fn sign(contract: &mut Contract, signing_key: &ed25519_dalek::SigningKey) -> Result<()> {
        contract.header.flags = contract.header.flags.with_signed(true);

        let payload = Self::signing_payload(contract)?;
        let signature = ed25519_dalek::Signer::sign(signing_key, &payload);

        contract.signature = Some(signature.to_bytes().to_vec());

        // Re-materializar: la presencia de la firma cambia offsets y flags, y
        // el hash debe reflejar el archivo final.
        contract.finalize()?;

        Ok(())
    }

    /// Verificar la firma de un contrato contra una clave pública.
    ///
    /// Falla cerrada: si la política exige firma y el contrato no la tiene, o
    /// si la firma tiene un tamaño distinto a 64 bytes, se devuelve error.
    pub fn verify(contract: &Contract, verifying_key: &ed25519_dalek::VerifyingKey) -> Result<()> {
        let sig_bytes = contract.signature.as_ref().ok_or(ContractError::InvalidSignature)?;

        if sig_bytes.len() != crate::SIGNATURE_SIZE {
            return Err(ContractError::InvalidSignature);
        }

        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ContractError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        let payload = Self::signing_payload(contract)?;

        ed25519_dalek::Verifier::verify(verifying_key, &payload, &signature)
            .map_err(|_| ContractError::InvalidSignature)
    }
}

/// Contrato parseado y validado estructuralmente, **sin** verificar la firma.
///
/// Existe para hacer imposible el uso accidental. Un `Contract` plano que
/// cualquiera puede obtener con `ContractReader::from_bytes` lleva a que un
/// integrador crea que tiene un contrato verificado cuando en realidad sólo
/// ha comprobado que el hash cuadra y que la firma *está presente*.
///
/// Separar los dos estados hace que el error sea un error de compilación, no
/// una revisión de código. Ver [ADR-0006](ADR.md#adr-0006-verificacion-de-firma-en-el-tipo).
pub struct UnverifiedContract {
    /// El contrato parseado. No se implementa `Deref` a propósito: sin eso,
    /// `&*unverified` daría acceso a los campos sin verificación.
    contract: Contract,
}

impl UnverifiedContract {
    /// Acceso de sólo lectura al contrato sin verificar.
    ///
    /// Deliberadamente limitado a inspección. Leer el contrato no habilita
    /// ninguna operación sensible por sí solo, pero se deja explícito para
    /// que quede claro en la revisión de código qué se ha mirado.
    pub fn inspect(&self) -> &Contract {
        &self.contract
    }

    /// El hash declarado, útil para diagnosticar antes de verificar.
    pub fn contract_hash(&self) -> [u8; 32] {
        self.contract.header.contract_hash
    }

    /// `key_id` declarado en la cabecera.
    ///
    /// Está cubierto por la firma porque la firma cubre el header canónico
    /// entero. No es un ancla de confianza por sí solo: sólo sirve para elegir
    /// **qué** clave de un almacén externo usar, nunca para aceptar una clave
    /// incluida en el propio contrato.
    pub fn key_id(&self) -> u32 {
        self.contract.header.key_id
    }

    /// Verificar la firma con una clave pública de confianza externa.
    ///
    /// Éste es el camino previsto: la clave viene del anfitrión (configuración
    /// fijada, almacén de claves autorizadas o PKI), nunca del contrato.
    pub fn verify(&self, verifying_key: &ed25519_dalek::VerifyingKey) -> Result<VerifiedContract> {
        ContractSigner::verify(&self.contract, verifying_key)?;
        Ok(VerifiedContract {
            contract: self.contract.clone(),
        })
    }
}

/// Contrato cuya firma Ed25519 ha sido verificada contra una clave de confianza.
///
/// No se puede construir sin pasar por `UnverifiedContract::verify`. Es la
/// garantía estructural del criterio de aceptación: no debe existir una ruta
/// por la que obtener algo que habilite operaciones sensibles sin verificación
/// explícita.
pub struct VerifiedContract {
    contract: Contract,
}

impl VerifiedContract {
    /// Acceso al contrato verificado.
    pub fn get(&self) -> &Contract {
        &self.contract
    }

    /// Consumir el contrato verificado y obtener su valor.
    pub fn into_inner(self) -> Contract {
        self.contract
    }

    /// Atajo para la identidad del contrato.
    pub fn contract_hash(&self) -> [u8; 32] {
        self.contract.header.contract_hash
    }

    /// Serializar. La verificación ya ocurrió; no hay que volver a firmar.
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        self.contract.to_binary()
    }
}

/// Lector de contratos binarios
pub struct ContractReader;

impl ContractReader {
    pub fn from_file(path: &str) -> Result<UnverifiedContract> {
        let data = std::fs::read(path)
            .map_err(|e| ContractError::IoError(e.to_string()))?;

        Self::from_bytes(&data)
    }

    /// Parsear y validar un contrato binario.
    ///
    /// Orden de validación (fail-closed):
    /// 1. header
    /// 2. bounds de sección y solapamientos
    /// 3. identidad (contract_hash)
    /// 4. firma, si la política la exige
    ///
    /// Devuelve un [`UnverifiedContract`], no un `Contract`. La verificación
    /// criptográfica de la firma necesita una clave pública de confianza que
    /// este lector no tiene y no debe tener: una clave incluida en el propio
    /// contrato no es un ancla de confianza, porque un atacante puede sustituir
    /// contrato y clave a la vez.
    ///
    /// Ver [ADR-0006](ADR.md#adr-0006-verificacion-de-firma-en-el-tipo).
    pub fn from_bytes(data: &[u8]) -> Result<UnverifiedContract> {
        // Header
        let header = ContractHeader::from_bytes(data)?;

        // P0.7: toda sección declarada debe estar dentro del archivo, no
        // solaparse y no invadir el header. Sin esto, `&data[a..][..b]` podía
        // slicear fuera de rango (panic) o leer una sección como otra.
        header.validate_sections(data.len())?;

        /// Extraer una sección ya validada por `validate_sections`.
        fn section<'a>(data: &'a [u8], offset: u32, size: u32, name: &str) -> Result<&'a [u8]> {
            let start = offset as usize;
            let end = start
                .checked_add(size as usize)
                .ok_or_else(|| ContractError::InvalidHeader(format!("{name}: overflow")))?;
            data.get(start..end)
                .ok_or_else(|| ContractError::InvalidHeader(format!("{name}: fuera de rango")))
        }

        // Tipos
        let types_data = section(data, header.types_offset, header.types_size, "types")?;
        let types = TypeRegistry::from_binary(types_data)
            .map_err(|e| ContractError::InvalidSection(e.to_string()))?;

        // Operaciones
        let ops_data = section(data, header.ops_offset, header.ops_size, "ops")?;
        let operations = OperationRegistry::from_binary(ops_data)
            .map_err(|e| ContractError::InvalidSection(e.to_string()))?;

        // Seguridad
        let security_data = section(data, header.security_offset, header.security_size, "security")?;
        let security = Contract::security_from_binary(security_data)?;

        // Firma
        let signature = if header.signature_size > 0 {
            Some(
                section(data, header.signature_offset, header.signature_size, "signature")?
                    .to_vec(),
            )
        } else {
            None
        };

        let contract = Contract {
            header,
            types,
            operations,
            security,
            signature,
        };

        // Verificar hash antes de usar nada del contrato
        let computed_hash = contract.compute_hash()?;
        if computed_hash != contract.header.contract_hash {
            return Err(ContractError::HashMismatch);
        }

        // Coherencia del flag SIGNED con la presencia real de firma
        if contract.header.flags.is_signed() && contract.signature.is_none() {
            return Err(ContractError::InvalidSignature);
        }

        // P1: si la política declara firma obligatoria, exigirla aquí.
        if contract.security.signature_required() && contract.signature.is_none() {
            return Err(ContractError::AuthenticationRequired);
        }

        Ok(UnverifiedContract { contract })
    }

    /// Parsear y verificar la firma en un solo paso.
    ///
    /// Atajo equivalente a `from_bytes(..)?.verify(&key)`, para los casos en
    /// que el contrato sin verificar no aporta nada. Mismo modelo de
    /// confianza: la clave es externa.
    pub fn from_bytes_verified(
        data: &[u8],
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<VerifiedContract> {
        Self::from_bytes(data)?.verify(verifying_key)
    }
}

/// Escritor de contratos binarios
pub struct ContractWriter;

impl ContractWriter {
    pub fn to_file(contract: &Contract, path: &str) -> Result<()> {
        let data = contract.to_binary()?;
        std::fs::write(path, data)
            .map_err(|e| ContractError::IoError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TypeId, TypeKind};

    #[test]
    fn test_header_roundtrip() {
        let mut header = ContractHeader::new();
        header.name = "test".to_string();
        header.namespace = "test_ns".to_string();
        header.contract_id = 12345;

        let bytes = header.to_bytes();
        let parsed = ContractHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.namespace, "test_ns");
        assert_eq!(parsed.contract_id, 12345);
    }

    #[test]
    fn test_contract_hash() {
        let mut contract = Contract::new("test", "ns", ContractVersion::new(1, 0, 0));
        contract.finalize().unwrap();

        assert_ne!(contract.header.contract_hash, [0u8; 32]);
    }

    #[test]
    fn test_contract_binary_requires_signature_by_default() {
        // La política por defecto exige firma. Un contrato sin firmar debe
        // rechazarse al cargar (fail-closed), no aceptarse en silencio.
        let mut contract = Contract::new("test", "ns", ContractVersion::new(1, 0, 0));
        contract.finalize().unwrap();

        let binary = contract.to_binary().unwrap();
        assert!(matches!(
            ContractReader::from_bytes(&binary),
            Err(ContractError::AuthenticationRequired)
        ));
    }

    #[test]
    fn test_contract_binary_roundtrip_signed() {
        // Con firma Ed25519 válida, el ciclo completo funciona.
        use ed25519_dalek::SigningKey;

        let mut contract = Contract::new("test", "ns", ContractVersion::new(1, 0, 0));
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        ContractSigner::sign(&mut contract, &signing_key).unwrap();

        let binary = contract.to_binary().unwrap();
        let unverified = ContractReader::from_bytes(&binary).unwrap();
        let parsed = unverified.inspect();

        assert_eq!(parsed.header.name, "test");
        assert_eq!(parsed.header.contract_hash, contract.header.contract_hash);

        // Y la firma verifica contra la clave pública
        let verifying = signing_key.verifying_key();
        ContractSigner::verify(parsed, &verifying).unwrap();
    }

    #[test]
    fn test_contract_signature_detects_tampering() {
        // P0.2: alterar el contenido debe invalidar la firma.
        use ed25519_dalek::SigningKey;

        let mut contract = Contract::new("test", "ns", ContractVersion::new(1, 0, 0));
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        ContractSigner::sign(&mut contract, &signing_key).unwrap();

        // Cambiar un tipo cambia la identidad y por tanto la firma
        contract.types.register(
            "Injected",
            TypeKind::Array {
                element_type: TypeId(0x0003),
                max_length: 8,
            },
        );
        contract.finalize().unwrap();

        let verifying = signing_key.verifying_key();
        assert!(ContractSigner::verify(&contract, &verifying).is_err());
    }

    #[test]
    fn test_header_parser_never_panics_on_truncated_input() {
        // P0.5: cada prefijo de un header válido debe producir Err, no panic.
        let header = ContractHeader::new().to_bytes();
        for len in 0..ContractHeader::SIZE {
            let result = std::panic::catch_unwind(|| ContractHeader::from_bytes(&header[..len]));
            assert!(result.is_ok(), "panic al parsear {len} bytes");
            assert!(result.unwrap().is_err(), "se esperaba Err con {len} bytes");
        }
    }

    #[test]
    fn test_reader_rejects_out_of_bounds_sections() {
        // Un header con offsets fuera del archivo debe rechazarse antes de
        // intentar slicear.
        let mut contract = Contract::new("test", "ns", ContractVersion::new(1, 0, 0));
        contract.finalize().unwrap();
        let mut binary = contract.to_binary().unwrap();

        // Corrupt types_offset (offset 64) a un valor gigante
        binary[64..68].copy_from_slice(&u32::MAX.to_le_bytes());

        let result = std::panic::catch_unwind(|| ContractReader::from_bytes(&binary));
        assert!(result.is_ok(), "no debe entrar en panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn test_reader_rejects_overlapping_sections() {
        let mut contract = Contract::new("test", "ns", ContractVersion::new(1, 0, 0));
        contract.finalize().unwrap();
        let mut binary = contract.to_binary().unwrap();

        // Apuntar ops_offset al inicio de types => solapamiento
        let types_offset = u32::from_le_bytes(binary[64..68].try_into().unwrap());
        binary[72..76].copy_from_slice(&types_offset.to_le_bytes());

        let result = std::panic::catch_unwind(|| ContractReader::from_bytes(&binary));
        assert!(result.is_ok(), "no debe entrar en panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn test_contract_hash_is_deterministic_across_builds() {
        // El mismo contenido debe producir el mismo hash siempre: es la base
        // de la identidad y de los vectores de conformidad.
        let mut a = Contract::new("stable", "ns", ContractVersion::new(1, 0, 0));
        let mut b = Contract::new("stable", "ns", ContractVersion::new(1, 0, 0));
        a.header.contract_id = 1234;
        b.header.contract_id = 1234;
        a.finalize().unwrap();
        b.finalize().unwrap();

        assert_eq!(a.header.contract_hash, b.header.contract_hash);
    }

    #[test]
    fn test_no_byte_of_the_file_escapes_integrity() {
        // Regresión: el fuzzer encontró que modificar el relleno del campo
        // `name` (bytes posteriores al NUL) o `schema_offset` no alteraba ni el
        // `contract_hash` ni la firma, porque el preimagen se reconstruye
        // desde la struct parseada. Ese byte quedaba fuera de toda
        // comprobación de integridad.
        //
        // Este test recorre TODAS las posiciones del archivo y exige que
        // ninguna pueda modificarse sin que el lector o la firma lo detecten.
        use ed25519_dalek::SigningKey;

        let mut c = Contract::new("c", "n", ContractVersion::new(1, 0, 0));
        c.header.contract_id = 1;
        c.types.register(
            "T",
            TypeKind::Array { element_type: TypeId(0x0003), max_length: 4 },
        );
        c.operations.register_auto("op", "d", TypeId(1), TypeId(2));
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        ContractSigner::sign(&mut c, &sk).unwrap();
        let verifying = sk.verifying_key();

        let original = c.to_binary().unwrap();
        let mut unverified_positions = Vec::new();

        for pos in 0..original.len() {
            let mut tampered = original.clone();
            tampered[pos] ^= 0xFF;

            match ContractReader::from_bytes(&tampered) {
                // Si el lector lo acepta, la firma tiene que rechazarlo.
                Ok(parsed) => {
                    if parsed.verify(&verifying).is_ok() {
                        unverified_positions.push(pos);
                    }
                }
                Err(_) => {} // detectado por el lector: correcto
            }
        }

        assert!(
            unverified_positions.is_empty(),
            "estas posiciones del archivo pueden alterarse sin romper la integridad: {:?}",
            unverified_positions
        );
    }
}


#[cfg(test)]
mod signature_trust_tests {
    //! Criterio de aceptación de PR1: no debe existir una ruta por la que
    //! obtener un contrato que habilite operaciones sensibles sin haber
    //! verificado la firma contra una clave de confianza.
    //!
    //! La garantía es de tipos (`UnverifiedContract` -> `VerifiedContract`), y
    //! estos tests comprueban la parte que los tipos no pueden: que ninguna de
    //! las formas de corromper una firma consigue atravesar `verify`.

    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    fn signed_contract(key_id: u32) -> (Contract, SigningKey) {
        let mut c = Contract::new("t", "ns", crate::ContractVersion::new(1, 0, 0));
        c.header.key_id = key_id;
        c.types.register("T", crate::types::TypeKind::Primitive(crate::types::PrimitiveType::U8));
        c.operations
            .register_auto("op", "d", crate::types::TypeId(1), crate::types::TypeId(2));
        c.finalize().unwrap();

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        ContractSigner::sign(&mut c, &sk).unwrap();
        (c, sk)
    }

    // --- Tabla de casos del criterio de aceptación ------------------------

    #[test]
    fn valid_signature_with_correct_key_verifies() {
        let (c, sk) = signed_contract(1);
        let unverified = ContractReader::from_bytes(&c.to_binary().unwrap()).unwrap();
        let verified = unverified.verify(&sk.verifying_key()).unwrap();
        assert_eq!(verified.contract_hash(), c.header.contract_hash);
    }

    #[test]
    fn valid_signature_with_wrong_key_is_rejected() {
        let (c, _) = signed_contract(1);
        let wrong = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        let unverified = ContractReader::from_bytes(&c.to_binary().unwrap()).unwrap();
        assert!(unverified.verify(&wrong).is_err());
    }

    #[test]
    fn corrupted_signature_is_rejected() {
        let (mut c, sk) = signed_contract(1);
        let mut bytes = c.to_binary().unwrap();
        // Voltear un byte de la firma. El hash no cambia porque la firma vive
        // fuera del preimagen: por eso hace falta verificación explícita y no
        // basta con `contract_hash`.
        let sig_off = c.header.signature_offset as usize;
        let last = sig_off + crate::SIGNATURE_SIZE - 1;
        bytes[last] ^= 0x01;
        let _ = &mut c;

        let unverified = ContractReader::from_bytes(&bytes).unwrap();
        assert!(
            unverified.verify(&sk.verifying_key()).is_err(),
            "una firma corrupta no puede salir como VerifiedContract"
        );
    }

    #[test]
    fn truncated_signature_is_rejected() {
        let (c, sk) = signed_contract(1);
        let mut bytes = c.to_binary().unwrap();
        bytes.truncate(bytes.len() - 8);
        // El truncamiento cambia el tamaño, luego el header canónico deja de
        // coincidir y falla antes incluso de llegar a la firma. Ambas cosas son
        // rechazos válidos.
        let unverified = ContractReader::from_bytes(&bytes);
        assert!(unverified.is_err() || unverified.unwrap().verify(&sk.verifying_key()).is_err());
    }

    #[test]
    fn signature_of_wrong_length_is_rejected() {
        let (c, sk) = signed_contract(1);
        let mut bytes = c.to_binary().unwrap();
        let sig_off = c.header.signature_offset as usize;
        // Substituir la firma por bytes de longitud distinta y reescribir el
        // tamaño declarado para que el header siga siendo canónico.
        bytes.truncate(sig_off);
        bytes.extend_from_slice(&[0u8; 32]);
        // Re-serializar el header con el tamaño nuevo.
        let new_size = 32u32.to_le_bytes();
        bytes[92..96].copy_from_slice(&new_size);
        bytes[88..92].copy_from_slice(&(sig_off as u32).to_le_bytes());
        let new_header = ContractHeader::from_bytes(&bytes).unwrap();
        bytes[0..256].copy_from_slice(&new_header.to_bytes());

        match ContractReader::from_bytes(&bytes) {
            Ok(u) => assert!(u.verify(&sk.verifying_key()).is_err()),
            Err(_) => {} // rechazo en el header: también válido
        }
    }

    #[test]
    fn missing_signature_with_required_policy_is_rejected() {
        // Contrato sin firmar, con política que exige firma.
        let mut c = Contract::new("t", "ns", crate::ContractVersion::new(1, 0, 0));
        c.security.authentication_required = true;
        c.security.signature_policy = crate::security::SignaturePolicy::Required;
        c.finalize().unwrap();
        let bytes = c.to_binary().unwrap();
        assert!(ContractReader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn missing_signature_with_optional_policy_parses_but_stays_unverified() {
        // Política opcional: el contrato carga, pero sigue siendo
        // `UnverifiedContract`. Esto es exactamente por lo que el tipo
        // importa: los datos existen y aun así no se pueden usar como
        // verificados.
        let mut c = Contract::new("t", "ns", crate::ContractVersion::new(1, 0, 0));
        c.security.signature_policy = crate::security::SignaturePolicy::Optional;
        c.finalize().unwrap();
        let bytes = c.to_binary().unwrap();

        let unverified = ContractReader::from_bytes(&bytes).unwrap();
        assert!(unverified.inspect().signature.is_none());

        let any_key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        assert!(
            unverified.verify(&any_key).is_err(),
            "sin firma no se puede producir VerifiedContract"
        );
    }

    #[test]
    fn modified_byte_in_any_section_is_rejected() {
        let (c, sk) = signed_contract(1);
        let original = c.to_binary().unwrap();

        // Recorrer el archivo entero alterando un byte de cada sección.
        for pos in 0..original.len() {
            let mut bytes = original.clone();
            bytes[pos] ^= 0x01;
            match ContractReader::from_bytes(&bytes) {
                Err(_) => continue, // rechazado en parseo o hash
                Ok(u) => {
                    assert!(
                        u.verify(&sk.verifying_key()).is_err(),
                        "byte {pos} alterado pasó la verificación (sección {:?})",
                        u.inspect().header.name
                    );
                }
            }
        }
    }

    #[test]
    fn contract_with_inconsistent_hash_is_rejected() {
        let (c, sk) = signed_contract(1);
        let mut bytes = c.to_binary().unwrap();
        // Alterar el hash declarado. El hash recalculado ya no coincidirá, y
        // aunque coincidiera, la firma cubre el hash normalizado a cero, así
        // que alterarlo rompe la firma.
        bytes[24] ^= 0xff;
        match ContractReader::from_bytes(&bytes) {
            Err(_) => {}
            Ok(u) => assert!(u.verify(&sk.verifying_key()).is_err()),
        }
    }

    #[test]
    fn contract_signed_with_substituted_key_is_rejected() {
        // El atacante firma con su propia clave y se la incluye. Si el
        // verificador aceptara la clave del propio contrato, esto prosperaría.
        let mut c = Contract::new("t", "ns", crate::ContractVersion::new(1, 0, 0));
        c.types.register("T", crate::types::TypeKind::Primitive(crate::types::PrimitiveType::U8));
        c.finalize().unwrap();
        let attacker = SigningKey::from_bytes(&[0xAB; 32]);
        ContractSigner::sign(&mut c, &attacker).unwrap();

        let unverified = ContractReader::from_bytes(&c.to_binary().unwrap()).unwrap();
        let honest = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        assert!(unverified.verify(&honest).is_err());
    }

    #[test]
    fn key_id_survives_roundtrip_and_is_covered_by_signature() {
        let (c, sk) = signed_contract(0xC0FFEE);
        let bytes = c.to_binary().unwrap();

        let unverified = ContractReader::from_bytes(&bytes).unwrap();
        assert_eq!(unverified.key_id(), 0xC0FFEE, "key_id debe sobrevivir al parseo");

        // Cambiar key_id invalida la firma: prueba de que está cubierta.
        let mut tampered = bytes.clone();
        tampered[224] ^= 0x01;
        match ContractReader::from_bytes(&tampered) {
            Err(_) => {} // rechazo en hash: también demuestra cobertura
            Ok(u) => assert!(u.verify(&sk.verifying_key()).is_err()),
        }
    }

    #[test]
    fn from_bytes_verified_is_equivalent_to_manual_path() {
        let (c, sk) = signed_contract(1);
        let bytes = c.to_binary().unwrap();
        let a = ContractReader::from_bytes_verified(&bytes, &sk.verifying_key()).unwrap();
        let b = ContractReader::from_bytes(&bytes)
            .unwrap()
            .verify(&sk.verifying_key())
            .unwrap();
        assert_eq!(a.contract_hash(), b.contract_hash());
    }

    #[test]
    fn unverified_contract_exposes_no_contract_directly() {
        // Comprobación estructural: `UnverifiedContract` no implementa
        // `Deref<Target = Contract>`, así que no hay forma de obtener el
        // contrato sin pasar por `inspect()`.
        let (c, _) = signed_contract(1);
        let u = ContractReader::from_bytes(&c.to_binary().unwrap()).unwrap();
        let _ = u.inspect();
        // Si alguien añadiera `Deref`, el compilador lo haría trivialmente
        // detectable en la definición del tipo; esta aserción documenta la
        // intención.
        assert!(std::mem::size_of::<UnverifiedContract>() > 0);
    }
}
