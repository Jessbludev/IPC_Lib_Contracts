// =============================================================================
// Generadores de Código
// =============================================================================
//
// Generan bindings para diferentes lenguajes desde un contrato binario:
// - Rust: structs, traits, impl
// - Kotlin: data classes, interfaces
// - TypeScript: interfaces, types
//
// =============================================================================

use crate::binary_contract::Contract;
use crate::types::{PrimitiveType, TypeKind};
use crate::error::Result;

// =============================================================================
// TRAIT COMÚN
// =============================================================================

/// Trait para generadores de código
pub trait CodeGenerator {
    /// Nombre del lenguaje
    fn language_name(&self) -> &str;

    /// Extensión de archivo
    fn file_extension(&self) -> &str;

    /// Generar archivo de tipos
    fn generate_types(&self, contract: &Contract) -> GeneratedFile;

    /// Generar archivo de operaciones
    fn generate_operations(&self, contract: &Contract) -> GeneratedFile;

    /// Generar archivo principal del contrato
    fn generate_contract(&self, contract: &Contract) -> GeneratedFile;

    /// Generar archivo binario del contrato
    ///
    /// Devuelve `Result`: la serialización canónica puede fallar (sección de
    /// seguridad no representable, offsets desbordados) y un generador no debe
    /// producir un `.cbc` silenciosamente truncado.
    fn generate_binary(&self, contract: &Contract) -> Result<Vec<u8>>;
}

/// Archivo generado
#[derive(Debug, Clone)]
pub struct GeneratedFile {
    pub name: String,
    pub extension: String,
    pub content: String,
}

impl GeneratedFile {
    pub fn filename(&self) -> String {
        format!("{}.{}", self.name, self.extension)
    }
}

// =============================================================================
// GENERADOR RUST
// =============================================================================

pub struct RustGenerator;

impl RustGenerator {
    pub fn new() -> Self {
        Self
    }

    fn type_to_rust(primitive: PrimitiveType) -> &'static str {
        match primitive {
            PrimitiveType::U8 => "u8",
            PrimitiveType::U16 => "u16",
            PrimitiveType::U32 => "u32",
            PrimitiveType::U64 => "u64",
            PrimitiveType::U128 => "u128",
            PrimitiveType::I8 => "i8",
            PrimitiveType::I16 => "i16",
            PrimitiveType::I32 => "i32",
            PrimitiveType::I64 => "i64",
            PrimitiveType::I128 => "i128",
            PrimitiveType::F32 => "f32",
            PrimitiveType::F64 => "f64",
            PrimitiveType::Bool => "bool",
            PrimitiveType::Byte => "u8",
            PrimitiveType::String => "String",
            PrimitiveType::Timestamp => "u64",
            PrimitiveType::Duration => "u64",
        }
    }
}

impl Default for RustGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeGenerator for RustGenerator {
    fn language_name(&self) -> &str {
        "rust"
    }

    fn file_extension(&self) -> &str {
        "rs"
    }

    fn generate_types(&self, contract: &Contract) -> GeneratedFile {
        let mut code = String::new();

        code.push_str("// =============================================================================\n");
        code.push_str(&format!("// {} - Tipos generados\n", contract.header.name));
        code.push_str("// =============================================================================\n\n");

        code.push_str("use serde::{Deserialize, Serialize};\n\n");

        // Tipos primitivos como aliases
        code.push_str("/// IDs de tipos primitivos\n");
        code.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
        code.push_str("#[repr(u16)]\n");
        code.push_str("pub enum PrimitiveTypeId {\n");
        for variant in [
            (PrimitiveType::U8, "U8"),
            (PrimitiveType::U16, "U16"),
            (PrimitiveType::U32, "U32"),
            (PrimitiveType::U64, "U64"),
            (PrimitiveType::I8, "I8"),
            (PrimitiveType::I16, "I16"),
            (PrimitiveType::I32, "I32"),
            (PrimitiveType::I64, "I64"),
            (PrimitiveType::F32, "F32"),
            (PrimitiveType::F64, "F64"),
            (PrimitiveType::Bool, "Bool"),
            (PrimitiveType::String, "String"),
        ] {
            code.push_str(&format!("    {} = {},\n", variant.1, variant.0 as u16));
        }
        code.push_str("}\n\n");

        // Tipos compuestos
        for (id, kind) in contract.types.compounds() {
            code.push_str(&format!("/// Tipo compuesto ID: {}\n", id.0));
            match kind {
                TypeKind::Object { fields } => {
                    let struct_name = format!("Type_{:04x}", id.0);
                    code.push_str(&format!("#[derive(Debug, Clone, Serialize, Deserialize)]\n"));
                    code.push_str(&format!("pub struct {} {{\n", struct_name));
                    for field in fields {
                        code.push_str(&format!("    pub {}: {},\n", field.name, "serde_json::Value"));
                    }
                    code.push_str("}\n\n");
                }
                TypeKind::Array { element_type, max_length } => {
                    code.push_str(&format!("pub type Array_{:04x} = Vec<serde_json::Value>; // max: {}\n\n", id.0, max_length));
                }
                _ => {}
            }
        }

        GeneratedFile {
            name: "types".to_string(),
            extension: "rs".to_string(),
            content: code,
        }
    }

    fn generate_operations(&self, contract: &Contract) -> GeneratedFile {
        let mut code = String::new();

        code.push_str("// =============================================================================\n");
        code.push_str(&format!("// {} - Operaciones generadas\n", contract.header.name));
        code.push_str("// =============================================================================\n\n");

        code.push_str("use super::*;\n\n");

        // IDs de operaciones
        code.push_str("/// IDs de operaciones\n");
        code.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
        code.push_str("#[repr(u16)]\n");
        code.push_str("pub enum OperationId {\n");

        for op in contract.operations.iter() {
            let name = op.name.to_uppercase().replace(" ", "_");
            code.push_str(&format!("    {} = {},\n", name, op.id.0));
        }

        code.push_str("}\n\n");

        // Trait del contrato
        let trait_name = format!("{}Contract", contract.header.name.replace("-", "_"));

        code.push_str(&format!(
            "/// Trait para implementar el contrato '{}'\n",
            contract.header.name
        ));
        code.push_str(&format!("pub trait {} {{\n", trait_name));

        for op in contract.operations.iter() {
            let func_name = op.name.replace("-", "_");
            code.push_str(&format!(
                "    /// {} - {}\n",
                func_name,
                op.description
            ));
            code.push_str(&format!(
                "    fn {}(&mut self, input: &[u8]) -> Result<Vec<u8>>;\n\n",
                func_name
            ));
        }

        code.push_str("}\n");

        GeneratedFile {
            name: "operations".to_string(),
            extension: "rs".to_string(),
            content: code,
        }
    }

    fn generate_contract(&self, contract: &Contract) -> GeneratedFile {
        let mut code = String::new();

        code.push_str("// =============================================================================\n");
        code.push_str(&format!("// {} - Contrato binario\n", contract.header.name));
        code.push_str("// =============================================================================\n\n");

        code.push_str("/// Hash del contrato\n");
        code.push_str("pub const CONTRACT_HASH: &[u8; 32] = &[\n");
        for chunk in contract.header.contract_hash.chunks(8) {
            code.push_str("    ");
            for &byte in chunk {
                code.push_str(&format!("0x{:02x}, ", byte));
            }
            code.push_str("\n");
        }
        code.push_str("];\n\n");

        code.push_str("/// Nombre del contrato\n");
        code.push_str(&format!(
            "pub const CONTRACT_NAME: &str = \"{}\";\n\n",
            contract.header.name
        ));

        code.push_str("/// Namespace del contrato\n");
        code.push_str(&format!(
            "pub const CONTRACT_NAMESPACE: &str = \"{}\";\n\n",
            contract.header.namespace
        ));

        code.push_str("/// Versión del contrato\n");
        code.push_str(&format!(
            "pub const CONTRACT_VERSION: &str = \"{}\";\n\n",
            contract.header.version.to_string()
        ));

        code.push_str("// =============================================================================\n");
        code.push_str("// Imports\n");
        code.push_str("// =============================================================================\n\n");

        code.push_str("use ipc_contract_system::{\n");
        code.push_str("    Contract, ContractReader,\n");
        code.push_str("    ProtocolVersion, PacketType, ContractRole,\n");
        code.push_str("    types::TypeId, operations::OperationId,\n");
        code.push_str("};\n\n");

        // Wrapper de sesión
        code.push_str("// =============================================================================\n");
        code.push_str("// Wrapper de sesión\n");
        code.push_str("// =============================================================================\n\n");

        code.push_str("pub struct Session {\n");
        code.push_str("    session_id: u64,\n");
        code.push_str("    sequence: u64,\n");
        code.push_str("    contract: &'static Contract,\n");
        code.push_str("}\n\n");

        code.push_str("impl Session {\n");
        code.push_str("    pub fn new(contract: &'static Contract, session_id: u64) -> Self {\n");
        code.push_str("        Self {\n");
        code.push_str("            session_id,\n");
        code.push_str("            sequence: 0,\n");
        code.push_str("            contract,\n");
        code.push_str("        }\n");
        code.push_str("    }\n\n");

        // Métodos para cada operación
        for op in contract.operations.iter() {
            let func_name = op.name.replace("-", "_");
            code.push_str(&format!(
                "    /// Ejecutar operación {} (ID: {})\n",
                op.name, op.id.0
            ));
            code.push_str(&format!(
                "    pub fn {}(&mut self, input: &[u8]) -> Result<Vec<u8>> {{\n",
                func_name
            ));
            code.push_str(&format!(
                "        self.sequence += 1;\n",
            ));
            code.push_str("        // Construir frame y enviar...\n");
            code.push_str("        todo!()\n");
            code.push_str("    }\n\n");
        }

        code.push_str("}\n");

        GeneratedFile {
            name: "contract".to_string(),
            extension: "rs".to_string(),
            content: code,
        }
    }

    fn generate_binary(&self, contract: &Contract) -> Result<Vec<u8>> {
        contract.to_binary()
    }
}

// =============================================================================
// GENERADOR KOTLIN
// =============================================================================

pub struct KotlinGenerator;

impl KotlinGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KotlinGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeGenerator for KotlinGenerator {
    fn language_name(&self) -> &str {
        "kotlin"
    }

    fn file_extension(&self) -> &str {
        "kt"
    }

    fn generate_types(&self, contract: &Contract) -> GeneratedFile {
        let mut code = String::new();

        code.push_str("// =============================================================================\n");
        code.push_str(&format!("// {} - Tipos generados\n", contract.header.name));
        code.push_str("// =============================================================================\n\n");

        code.push_str("package com.ipc.contract\n\n");

        code.push_str("/// IDs de tipos primitivos\n");
        code.push_str("enum class PrimitiveTypeId(val value: Int) {\n");
        for variant in [
            (PrimitiveType::U8, "U8"),
            (PrimitiveType::U16, "U16"),
            (PrimitiveType::U32, "U32"),
            (PrimitiveType::U64, "U64"),
            (PrimitiveType::I8, "I8"),
            (PrimitiveType::I16, "I16"),
            (PrimitiveType::I32, "I32"),
            (PrimitiveType::I64, "I64"),
            (PrimitiveType::F32, "F32"),
            (PrimitiveType::F64, "F64"),
            (PrimitiveType::Bool, "BOOL"),
            (PrimitiveType::String, "STRING"),
        ] {
            code.push_str(&format!("    {}({}),\n", variant.1, variant.0 as u16));
        }
        code.push_str("}\n\n");

        // Tipos compuestos
        for (id, kind) in contract.types.compounds() {
            match kind {
                TypeKind::Object { fields } => {
                    let class_name = format!("Type_{:04x}", id.0);
                    code.push_str(&format!("data class {}(\n", class_name));
                    for field in fields {
                        code.push_str(&format!("    val {}: Any?,\n", field.name));
                    }
                    code.push_str(")\n\n");
                }
                _ => {}
            }
        }

        GeneratedFile {
            name: "Types".to_string(),
            extension: "kt".to_string(),
            content: code,
        }
    }

    fn generate_operations(&self, contract: &Contract) -> GeneratedFile {
        let mut code = String::new();

        code.push_str("// =============================================================================\n");
        code.push_str(&format!("// {} - Operaciones generadas\n", contract.header.name));
        code.push_str("// =============================================================================\n\n");

        code.push_str("package com.ipc.contract\n\n");

        // IDs de operaciones
        code.push_str("/// IDs de operaciones\n");
        code.push_str("enum class OperationId(val value: Int) {\n");

        for op in contract.operations.iter() {
            let name = op.name.to_uppercase().replace(" ", "_");
            code.push_str(&format!("    {}({}),\n", name, op.id.0));
        }

        code.push_str("}\n\n");

        // Interfaz del contrato
        let iface_name = format!("{}Contract", contract.header.name.replace("-", "_"));

        code.push_str(&format!(
            "/// Interfaz para implementar el contrato '{}'\n",
            contract.header.name
        ));
        code.push_str(&format!("interface {} {{\n", iface_name));

        for op in contract.operations.iter() {
            let func_name = to_camel_case(&op.name);
            code.push_str(&format!(
                "    /// {} - {}\n",
                func_name,
                op.description
            ));
            code.push_str(&format!(
                "    suspend fun {}(input: ByteArray): ByteArray\n\n",
                func_name
            ));
        }

        code.push_str("}\n");

        GeneratedFile {
            name: "Operations".to_string(),
            extension: "kt".to_string(),
            content: code,
        }
    }

    fn generate_contract(&self, contract: &Contract) -> GeneratedFile {
        let mut code = String::new();

        code.push_str("// =============================================================================\n");
        code.push_str(&format!("// {} - Contrato binario\n", contract.header.name));
        code.push_str("// =============================================================================\n\n");

        code.push_str("package com.ipc.contract\n\n");

        code.push_str("/// Hash del contrato\n");
        code.push_str("val CONTRACT_HASH: ByteArray = byteArrayOf(\n");
        for (i, &byte) in contract.header.contract_hash.iter().enumerate() {
            if i % 8 == 0 && i > 0 {
                code.push_str(",\n");
            }
            code.push_str(&format!("    {},", byte));
        }
        code.push_str("\n)\n\n");

        code.push_str("/// Nombre del contrato\n");
        code.push_str(&format!(
            "const val CONTRACT_NAME = \"{}\"\n\n",
            contract.header.name
        ));

        code.push_str("/// Namespace del contrato\n");
        code.push_str(&format!(
            "const val CONTRACT_NAMESPACE = \"{}\"\n\n",
            contract.header.namespace
        ));

        code.push_str("/// Versión del contrato\n");
        code.push_str(&format!(
            "const val CONTRACT_VERSION = \"{}\"\n\n",
            contract.header.version.to_string()
        ));

        // Wrapper de sesión
        code.push_str("// =============================================================================\n");
        code.push_str("// Wrapper de sesión\n");
        code.push_str("// =============================================================================\n\n");

        code.push_str("class ContractSession(\n");
        code.push_str("    private val sessionId: Long,\n");
        code.push_str("    private val contract: Contract\n");
        code.push_str(") {\n");
        code.push_str("    private var sequence = 0L\n\n");

        for op in contract.operations.iter() {
            let func_name = to_camel_case(&op.name);
            code.push_str(&format!(
                "    /// Ejecutar operación {} (ID: {})\n",
                op.name, op.id.0
            ));
            code.push_str(&format!(
                "    suspend fun {}(input: ByteArray): ByteArray {{\n",
                func_name
            ));
            code.push_str("        sequence++\n");
            code.push_str("        // Construir frame y enviar...\n");
            code.push_str("        throw NotImplementedError()\n");
            code.push_str("    }\n\n");
        }

        code.push_str("}\n");

        GeneratedFile {
            name: "Contract".to_string(),
            extension: "kt".to_string(),
            content: code,
        }
    }

    fn generate_binary(&self, contract: &Contract) -> Result<Vec<u8>> {
        contract.to_binary()
    }
}

// =============================================================================
// GENERADOR TYPESCRIPT
// =============================================================================

pub struct TypeScriptGenerator;

impl TypeScriptGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypeScriptGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeGenerator for TypeScriptGenerator {
    fn language_name(&self) -> &str {
        "typescript"
    }

    fn file_extension(&self) -> &str {
        "ts"
    }

    fn generate_types(&self, contract: &Contract) -> GeneratedFile {
        let mut code = String::new();

        code.push_str("// =============================================================================\n");
        code.push_str(&format!("// {} - Tipos generados\n", contract.header.name));
        code.push_str("// =============================================================================\n\n");

        // Tipos primitivos
        code.push_str("/**\n");
        code.push_str(" * IDs de tipos primitivos\n");
        code.push_str(" */\n");
        code.push_str("export enum PrimitiveTypeId {\n");
        for variant in [
            (PrimitiveType::U8, "U8"),
            (PrimitiveType::U16, "U16"),
            (PrimitiveType::U32, "U32"),
            (PrimitiveType::U64, "U64"),
            (PrimitiveType::I8, "I8"),
            (PrimitiveType::I16, "I16"),
            (PrimitiveType::I32, "I32"),
            (PrimitiveType::I64, "I64"),
            (PrimitiveType::F32, "F32"),
            (PrimitiveType::F64, "F64"),
            (PrimitiveType::Bool, "BOOL"),
            (PrimitiveType::String, "STRING"),
        ] {
            code.push_str(&format!("    {} = {},\n", variant.1, variant.0 as u16));
        }
        code.push_str("}\n\n");

        // Tipos compuestos
        for (id, kind) in contract.types.compounds() {
            match kind {
                TypeKind::Object { fields } => {
                    let type_name = format!("Type_{:04x}", id.0);
                    code.push_str(&format!("export interface {} {{\n", type_name));
                    for field in fields {
                        code.push_str(&format!("    {}: unknown;\n", field.name));
                    }
                    code.push_str("}\n\n");
                }
                _ => {}
            }
        }

        GeneratedFile {
            name: "types".to_string(),
            extension: "ts".to_string(),
            content: code,
        }
    }

    fn generate_operations(&self, contract: &Contract) -> GeneratedFile {
        let mut code = String::new();

        code.push_str("// =============================================================================\n");
        code.push_str(&format!("// {} - Operaciones generadas\n", contract.header.name));
        code.push_str("// =============================================================================\n\n");

        // IDs de operaciones
        code.push_str("/**\n");
        code.push_str(" * IDs de operaciones\n");
        code.push_str(" */\n");
        code.push_str("export enum OperationId {\n");

        for op in contract.operations.iter() {
            let name = to_upper_snake_case(&op.name);
            code.push_str(&format!("    {} = {},\n", name, op.id.0));
        }

        code.push_str("}\n\n");

        // Interfaz del contrato
        let iface_name = format!("{}Contract", contract.header.name.replace("-", ""));

        code.push_str(&format!(
            "/**\n"
        ));
        code.push_str(&format!(" * Interfaz para implementar el contrato '{}'\n", contract.header.name));
        code.push_str(" */\n");
        code.push_str(&format!("export interface {} {{\n", iface_name));

        for op in contract.operations.iter() {
            let func_name = to_camel_case(&op.name);
            code.push_str(&format!(
                "    /** {} - {} */\n",
                func_name,
                op.description
            ));
            code.push_str(&format!(
                "    {}(input: Uint8Array): Promise<Uint8Array>;\n\n",
                func_name
            ));
        }

        code.push_str("}\n");

        GeneratedFile {
            name: "operations".to_string(),
            extension: "ts".to_string(),
            content: code,
        }
    }

    fn generate_contract(&self, contract: &Contract) -> GeneratedFile {
        let mut code = String::new();

        code.push_str("// =============================================================================\n");
        code.push_str(&format!("// {} - Contrato binario\n", contract.header.name));
        code.push_str("// =============================================================================\n\n");

        code.push_str("/**\n");
        code.push_str(" * Hash del contrato\n");
        code.push_str(" */\n");
        code.push_str("export const CONTRACT_HASH = new Uint8Array([\n");
        for chunk in contract.header.contract_hash.chunks(16) {
            code.push_str("    ");
            for &byte in chunk {
                code.push_str(&format!("{}, ", byte));
            }
            code.push_str("\n");
        }
        code.push_str("]);\n\n");

        code.push_str("/**\n");
        code.push_str(" * Nombre del contrato\n");
        code.push_str(" */\n");
        code.push_str(&format!(
            "export const CONTRACT_NAME = \"{}\";\n\n",
            contract.header.name
        ));

        code.push_str("/**\n");
        code.push_str(" * Namespace del contrato\n");
        code.push_str(" */\n");
        code.push_str(&format!(
            "export const CONTRACT_NAMESPACE = \"{}\";\n\n",
            contract.header.namespace
        ));

        code.push_str("/**\n");
        code.push_str(" * Versión del contrato\n");
        code.push_str(" */\n");
        code.push_str(&format!(
            "export const CONTRACT_VERSION = \"{}\";\n\n",
            contract.header.version.to_string()
        ));

        // Clase de sesión
        let class_name = format!("{}Session", contract.header.name.replace("-", ""));

        code.push_str("/**\n");
        code.push_str(" * Wrapper de sesión\n");
        code.push_str(" */\n");
        code.push_str(&format!("export class {} {{\n", class_name));
        code.push_str("    private sessionId: bigint;\n");
        code.push_str("    private sequence = 0n;\n\n");
        code.push_str("    constructor(sessionId: bigint) {\n");
        code.push_str("        this.sessionId = sessionId;\n");
        code.push_str("    }\n\n");

        for op in contract.operations.iter() {
            let func_name = to_camel_case(&op.name);
            code.push_str(&format!(
                "    /** Ejecutar operación {} (ID: {}) */\n",
                op.name, op.id.0
            ));
            code.push_str(&format!(
                "    async {}(input: Uint8Array): Promise<Uint8Array> {{\n",
                func_name
            ));
            code.push_str("        this.sequence++;\n");
            code.push_str("        // Construir frame y enviar...\n");
            code.push_str("        throw new Error('Not implemented');\n");
            code.push_str("    }\n\n");
        }

        code.push_str("}\n");

        GeneratedFile {
            name: "contract".to_string(),
            extension: "ts".to_string(),
            content: code,
        }
    }

    fn generate_binary(&self, contract: &Contract) -> Result<Vec<u8>> {
        contract.to_binary()
    }
}

// =============================================================================
// HELPERS
// =============================================================================

fn to_camel_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = false;

    for c in s.chars() {
        if c == '_' || c == '-' || c == ' ' {
            capitalize_next = true;
        } else if capitalize_next {
            result.extend(c.to_uppercase());
            capitalize_next = false;
        } else {
            result.extend(c.to_lowercase());
        }
    }

    result
}

fn to_upper_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut was_upper = false;

    for c in s.chars() {
        if c.is_uppercase() && !was_upper && !result.is_empty() {
            result.push('_');
        }
        result.extend(c.to_uppercase());
        was_upper = c.is_uppercase();
    }

    result.replace("-", "_")
}

// =============================================================================
// FACTORY
// =============================================================================

pub fn create_generator(language: &str) -> Box<dyn CodeGenerator> {
    match language.to_lowercase().as_str() {
        "rust" => Box::new(RustGenerator::new()),
        "kotlin" | "java" => Box::new(KotlinGenerator::new()),
        "typescript" | "ts" => Box::new(TypeScriptGenerator::new()),
        _ => panic!("Unsupported language: {}", language),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_camel_case() {
        assert_eq!(to_camel_case("hello_world"), "helloWorld");
        assert_eq!(to_camel_case("hello-world"), "helloWorld");
        assert_eq!(to_camel_case("hello world"), "helloWorld");
    }

    #[test]
    fn test_to_upper_snake_case() {
        assert_eq!(to_upper_snake_case("helloWorld"), "HELLO_WORLD");
        assert_eq!(to_upper_snake_case("hello-world"), "HELLO_WORLD");
    }
}
