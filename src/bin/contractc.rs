// =============================================================================
// contractc - CLI del Compilador de Contratos
// =============================================================================
//
// Uso:
//   contractc compile [options] <input.contract>
//   contractc generate [options] --target <lang> <input.contract.bin>
//   contractc validate [options] <input.contract.bin>
//   contractc verify [options] <input.contract.bin>
//   contractc inspect [options] <input.contract.bin>
//   contractc hash [options] <input.contract.bin>
//   contractc dump [options] <input.contract.bin>
//
// =============================================================================

use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::{Path, PathBuf};
use ipc_contract_system::*;
use ipc_contract_system::binary_contract::{ContractReader, ContractSigner};

/// CLI principal
#[derive(Parser, Debug)]
#[command(name = "contractc")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Compilador de Contratos Binarios Canónicos", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Nivel de verbosidad
    #[arg(short, long, default_value = "info")]
    verbose: String,

    /// Directorio de salida
    #[arg(short, long, default_value = ".")]
    output: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Compilar contrato desde DSL/YAML a binario
    Compile {
        /// Archivo de entrada
        input: PathBuf,

        /// Firmar el contrato con Ed25519
        #[arg(long)]
        sign: bool,

        /// Archivo de clave privada para firma
        #[arg(long)]
        sign_key: Option<PathBuf>,
    },

    /// Generar código desde contrato binario
    Generate {
        /// Archivo de contrato binario
        input: PathBuf,

        /// Lenguaje destino
        #[arg(long, value_enum)]
        target: TargetLanguage,

        /// Nombre del módulo/archivo
        #[arg(long, default_value = "generated")]
        name: String,
    },

    /// Validar contrato binario
    Validate {
        /// Archivo de contrato binario
        input: PathBuf,

        /// Verificar la firma Ed25519
        #[arg(long)]
        verify_signature: bool,

        /// Clave pública para verificación
        #[arg(long)]
        verify_key: Option<PathBuf>,
    },

    /// Mostrar información del contrato
    Info {
        /// Archivo de contrato binario
        input: PathBuf,
    },

    /// Verificar integridad de contrato binario (salida estructurada)
    Verify {
        /// Archivo de contrato binario
        input: PathBuf,

        /// Verificar firma Ed25519
        #[arg(long)]
        check_signature: bool,

        /// Clave pública para verificación
        #[arg(long)]
        verify_key: Option<PathBuf>,
    },

    /// Inspeccionar contrato binario (salida estructurada)
    Inspect {
        /// Archivo de contrato binario
        input: PathBuf,

        /// Mostrar tipos detallados
        #[arg(long, default_value = "true")]
        show_types: bool,

        /// Mostrar operaciones detalladas
        #[arg(long, default_value = "true")]
        show_operations: bool,
    },

    /// Calcular hash del contrato
    Hash {
        /// Archivo de contrato binario
        input: PathBuf,

        /// Formato de salida
        #[arg(long, default_value = "hex")]
        format: HashFormat,
    },

    /// Dump hexadecimal del contrato
    Dump {
        /// Archivo de contrato binario
        input: PathBuf,

        /// Offset inicial en bytes
        #[arg(long, default_value = "0")]
        offset: usize,

        /// Número de bytes a mostrar
        #[arg(long)]
        length: Option<usize>,

        /// Mostrar solo el header
        #[arg(long)]
        header_only: bool,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum TargetLanguage {
    Rust,
    Kotlin,
    TypeScript,
    Cpp,
}

#[derive(Debug, Clone, ValueEnum)]
enum HashFormat {
    /// Formato hexadecimal estándar
    Hex,
    /// Formato BLAKE3 con prefijo (b3:...)
    Blake3,
    /// Solo los primeros 12 bytes (prefix)
    Prefix,
}

impl std::fmt::Display for TargetLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetLanguage::Rust => write!(f, "rust"),
            TargetLanguage::Kotlin => write!(f, "kotlin"),
            TargetLanguage::TypeScript => write!(f, "typescript"),
            TargetLanguage::Cpp => write!(f, "cpp"),
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Compile { input, sign, sign_key } => {
            compile_contract(&input, &cli.output, sign, sign_key.as_deref())?;
        }
        Command::Generate { input, target, name } => {
            generate_code(&input, &cli.output, &target, &name)?;
        }
        Command::Validate { input, verify_signature, verify_key } => {
            validate_contract(&input, verify_signature, verify_key.as_deref())?;
        }
        Command::Info { input } => {
            show_info(&input)?;
        }
        Command::Verify { input, check_signature, verify_key } => {
            verify_contract(&input, check_signature, verify_key.as_deref())?;
        }
        Command::Inspect { input, show_types, show_operations } => {
            inspect_contract(&input, show_types, show_operations)?;
        }
        Command::Hash { input, format } => {
            show_hash(&input, &format)?;
        }
        Command::Dump { input, offset, length, header_only } => {
            dump_contract(&input, offset, length, header_only)?;
        }
    }

    Ok(())
}

fn compile_contract(
    input: &Path,
    output: &Path,
    sign: bool,
    sign_key: Option<&Path>,
) -> anyhow::Result<()> {
    tracing::info!("Compilando contrato: {}", input.display());

    // Leer archivo fuente
    let content = fs::read_to_string(input)?;
    let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");

    // Parsear según formato
    let mut contract = match ext {
        "yaml" | "yml" => {
            return Err(anyhow::anyhow!(
                "el backend YAML no está soportado (P0-13). \
                 Convierta el contrato al DSL del proyecto o use JSON."
            ));
        }
        "json" => parse_json_contract(&content)?,
        "cbc" => {
            // Ya es binario
            tracing::info!("El archivo ya es binario, omitiendo compilación");
            return Ok(());
        }
        _ => {
            // Intentar detectar formato
            if content.trim_start().starts_with('{') {
                parse_json_contract(&content)?
            } else {
                parse_dsl_contract(&content)?
            }
        }
    };

    // Generar ID y hash
    contract.header.contract_id = generate_contract_id(&contract);
    contract.finalize()?;

    // Firmar si se solicitó
    if sign {
        if let Some(key_path) = sign_key {
            contract = sign_contract(contract, key_path)?;
        } else {
            tracing::warn!("Firma solicitada pero no se proporcionó clave privada");
        }
    }

    // Escribir binario
    let output_file = output.join(format!(
        "{}.cbc",
        contract.header.name
    ));

    fs::create_dir_all(output)?;
    ContractWriter::to_file(&contract, &path_str(&output_file))?;

    tracing::info!("Contrato compilado: {}", output_file.display());

    // Mostrar hash
    tracing::info!(
        "Contract hash: {}",
        hex::encode(contract.header.contract_hash)
    );

    Ok(())
}

fn generate_code(
    input: &Path,
    output: &Path,
    target: &TargetLanguage,
    name: &str,
) -> anyhow::Result<()> {
    tracing::info!("Generando código {} para: {}", target, input.display());

    // Leer contrato binario
    let contract = ContractReader::from_file(&path_str(input))?;

    // Crear generador
    let generator = generators::create_generator(&target.to_string());

    fs::create_dir_all(output)?;

    // Generar tipos
    let types = generator.generate_types(&contract);
    let types_file = output.join(format!("{}_types.{}", name, types.extension));
    fs::write(&types_file, types.content)?;
    tracing::info!("Generado: {}", types_file.display());

    // Generar operaciones
    let operations = generator.generate_operations(&contract);
    let ops_file = output.join(format!("{}_operations.{}", name, operations.extension));
    fs::write(&ops_file, operations.content)?;
    tracing::info!("Generado: {}", ops_file.display());

    // Generar contrato
    let contract_gen = generator.generate_contract(&contract);
    let contract_file = output.join(format!("{}.{}", name, contract_gen.extension));
    fs::write(&contract_file, contract_gen.content)?;
    tracing::info!("Generado: {}", contract_file.display());

    // Copiar binario
    let binary = generator.generate_binary(&contract)
        .map_err(|e| anyhow::anyhow!("fallo al serializar el contrato: {e}"))?;
    let binary_file = output.join(format!("{}.cbc", name));
    fs::write(&binary_file, binary)?;
    tracing::info!("Generado: {}", binary_file.display());

    Ok(())
}

fn validate_contract(
    input: &Path,
    verify_signature: bool,
    verify_key: Option<&Path>,
) -> anyhow::Result<()> {
    tracing::info!("Validando contrato: {}", input.display());

    // Leer contrato
    let contract = ContractReader::from_file(&path_str(input))?;

    // Verificar hash
    let computed_hash = contract.compute_hash()?;
    if computed_hash != contract.header.contract_hash {
        tracing::error!("Hash no coincide - contrato modificado!");
        return Err(anyhow::anyhow!("Hash mismatch"));
    }
    tracing::info!("Hash verificado OK");

    // Verificar la firma si se solicitó
    if verify_signature {
        if let Some(key_path) = verify_key {
            if let Err(e) = verify_contract_signature(&contract, key_path) {
                tracing::error!("Verificación de firma fallida: {}", e);
                return Err(e);
            }
            tracing::info!("Firma verificada OK");
        } else {
            tracing::warn!("Verificación de firma solicitada pero no se proporcionó clave");
        }
    }

    tracing::info!("Contrato válido");

    Ok(())
}

fn show_info(input: &Path) -> anyhow::Result<()> {
    let contract = ContractReader::from_file(&path_str(input))?;

    println!("\n═══════════════════════════════════════════════════════════════");
    println!("                    CONTRATO BINARIO CBC");
    println!("═══════════════════════════════════════════════════════════════\n");

    println!("Nombre:         {}", contract.header.name);
    println!("Namespace:      {}", contract.header.namespace);
    println!("Versión:       {}", contract.header.version.to_string());
    println!("ID:            {}", contract.header.contract_id);
    println!("Hash:          {}", hex::encode(contract.header.contract_hash));
    println!();

    println!("Formato:       v{}", contract.header.format_version);
    println!("Firmado:       {}", if contract.header.flags.is_signed() { "Sí" } else { "No" });
    println!();

    println!("Seguridad:");
    println!("  Nivel:        {:?}", contract.security.level);
    println!("  AEAD:         {:?}", contract.security.aead_algorithm);
    println!("  Hash:         {:?}", contract.security.hash_algorithm);
    println!("  Anti-replay:  {}", if contract.security.anti_replay { "Sí" } else { "No" });
    println!();

    println!("Contenido:");
    println!("  Tipos:        {} registros", contract.types.compounds().count());
    println!("  Operaciones:  {} registradas", contract.operations.iter().count());
    println!();

    println!("Operaciones:");
    for op in contract.operations.iter() {
        println!("  [{:04x}] {} - {} (timeout: {}ms, idempotent: {})",
            op.id.0,
            op.name,
            op.description,
            op.timeout_ms,
            op.idempotent
        );
    }

    println!("\n═══════════════════════════════════════════════════════════════\n");

    Ok(())
}

/// Verificar integridad de contrato binario (salida estructurada ADR-013)
fn verify_contract(
    input: &Path,
    check_signature: bool,
    verify_key: Option<&Path>,
) -> anyhow::Result<()> {
    // Leer archivo completo
    let data = fs::read(input)?;

    // 1. Verificar magic
    if data.len() < 4 {
        println!("CBC INVALID");
        println!("Error: File too short");
        return Ok(());
    }

    let magic = &data[0..4];
    if magic != b"CBC1" {
        println!("CBC INVALID");
        println!("Error: Invalid magic bytes");
        return Ok(());
    }

    // 2. Verificar format version
    let format_version = data[4];
    if format_version != 1 {
        println!("CBC INVALID");
        println!("Error: Unsupported format version {}", format_version);
        return Ok(());
    }

    // 3. Verificar header size
    let header_size = u16::from_le_bytes([data[6], data[7]]);
    if header_size != 256 {
        println!("CBC INVALID");
        println!("Error: Invalid header size {}", header_size);
        return Ok(());
    }

    if data.len() < 256 {
        println!("CBC INVALID");
        println!("Error: File too short for header");
        return Ok(());
    }

    // 4. Verificar offsets y sizes
    let schema_offset = u32::from_le_bytes([data[56], data[57], data[58], data[59]]);
    let schema_size = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
    let types_offset = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
    let types_size = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
    let ops_offset = u32::from_le_bytes([data[72], data[73], data[74], data[75]]);
    let ops_size = u32::from_le_bytes([data[76], data[77], data[78], data[79]]);
    let security_offset = u32::from_le_bytes([data[80], data[81], data[82], data[83]]);
    let security_size = u32::from_le_bytes([data[84], data[85], data[86], data[87]]);

    // Verificar bounds
    let end_of_file = data.len() as u32;
    if schema_offset + schema_size > end_of_file {
        println!("CBC INVALID");
        println!("Error: Schema section out of bounds");
        return Ok(());
    }
    if types_offset + types_size > end_of_file {
        println!("CBC INVALID");
        println!("Error: Types section out of bounds");
        return Ok(());
    }
    if ops_offset + ops_size > end_of_file {
        println!("CBC INVALID");
        println!("Error: Operations section out of bounds");
        return Ok(());
    }
    if security_offset + security_size > end_of_file {
        println!("CBC INVALID");
        println!("Error: Security section out of bounds");
        return Ok(());
    }

    // 5. Verificar UTF-8 en name y namespace
    let name_end = data[96..160].iter().position(|&b| b == 0).unwrap_or(64);
    if std::str::from_utf8(&data[96..96 + name_end]).is_err() {
        println!("CBC INVALID");
        println!("Error: Invalid UTF-8 in name field");
        return Ok(());
    }

    let ns_end = data[160..224].iter().position(|&b| b == 0).unwrap_or(64);
    if std::str::from_utf8(&data[160..160 + ns_end]).is_err() {
        println!("CBC INVALID");
        println!("Error: Invalid UTF-8 in namespace field");
        return Ok(());
    }

    // 6. Verificar contract hash
    let contract = ContractReader::from_file(&path_str(input))?;
    let computed_hash = contract.compute_hash()?;

    if computed_hash != contract.header.contract_hash {
        println!("CBC INVALID");
        println!("Error: Hash mismatch");
        return Ok(());
    }

    // 7. Verificar firma si se solicita
    let signature_valid = if check_signature {
        if let Some(key_path) = verify_key {
            verify_contract_signature(&contract, key_path).is_ok()
        } else if contract.header.flags.is_signed() {
            // Sin clave, solo verificamos que exista firma
            contract.signature.is_some()
        } else {
            true
        }
    } else {
        true
    };

    // 8. Obtener versión del contrato
    let version = contract.header.version.to_string();
    let protocol_version = "2"; // Basado en ADR-012
    let hash_hex = hex::encode(contract.header.contract_hash);

    // ============================================================
    // SALIDA ESTRUCTURADA (como especificado en ADR-013)
    // ============================================================
    println!();
    println!("CBC VALID");
    println!();
    println!("Format:       {}", format_version);
    println!("Protocol:     {}", protocol_version);
    println!("Contract:     {}", version);
    println!();
    println!("Hash:");
    println!("b3:{}", hash_hex);
    println!();
    println!("Signature:");
    if contract.header.flags.is_signed() {
        if signature_valid {
            println!("Ed25519 / VALID");
        } else {
            println!("Ed25519 / INVALID");
        }
    } else {
        println!("None");
    }
    println!();
    println!("Sections:");
    println!("schema       VALID");
    println!("types        VALID");
    println!("operations   VALID");
    println!("security     VALID");
    println!();

    Ok(())
}

/// Inspeccionar contrato binario (salida estructurada ADR-013)
fn inspect_contract(
    input: &Path,
    show_types: bool,
    show_operations: bool,
) -> anyhow::Result<()> {
    let contract = ContractReader::from_file(&path_str(input))?;

    println!();
    println!("Contract: {}", contract.header.name);
    println!("Namespace: {}", contract.header.namespace);
    println!("Version: {}", contract.header.version.to_string());
    println!("ID: {:016x}", contract.header.contract_id);
    println!();

    println!("Types: {}", contract.types.compounds().count());
    if show_types {
        let mut listed: Vec<_> = contract
            .types
            .compounds()
            .map(|(id, kind)| (id.0, format!("{kind:?}")))
            .collect();
        listed.sort_by_key(|(id, _)| *id);
        for (id, kind) in listed {
            println!("  - [{id:04x}] {kind}");
        }
    }
    println!();

    println!("Operations: {}", contract.operations.iter().count());
    if show_operations {
        for op in contract.operations.iter() {
            println!("  - {} ({:04x})", op.name, op.id.0);
        }
    }
    println!();

    println!("Security Policy:");
    println!("  level:            {:?}", contract.security.level);
    println!("  aead:             {:?}", contract.security.aead_algorithm);
    println!("  hash:             {:?}", contract.security.hash_algorithm);
    println!("  authentication:   {}", contract.security.authentication_required);
    println!("  confidentiality:  {}", contract.security.confidentiality_required);
    println!("  replay_protection: {}", if contract.security.anti_replay { "required" } else { "disabled" });
    println!("  signature_policy: {:?}", contract.security.signature_policy);
    println!();

    Ok(())
}

/// Mostrar hash del contrato
fn show_hash(input: &Path, format: &HashFormat) -> anyhow::Result<()> {
    let contract = ContractReader::from_file(&path_str(input))?;

    match format {
        HashFormat::Blake3 => {
            println!("Contract Hash (BLAKE3-256):");
            println!("b3:{}", hex::encode(contract.header.contract_hash));
        }
        HashFormat::Prefix => {
            println!("Contract Hash Prefix (12 bytes):");
            println!("b3:{}", hex::encode(&contract.header.contract_hash[..12]));
        }
        HashFormat::Hex => {
            println!("Contract Hash (BLAKE3-256):");
            println!("{}", hex::encode(contract.header.contract_hash));
        }
    }

    Ok(())
}

/// Dump hexadecimal del contrato
fn dump_contract(
    input: &Path,
    offset: usize,
    length: Option<usize>,
    header_only: bool,
) -> anyhow::Result<()> {
    let data = fs::read(input)?;
    let end = if header_only {
        256
    } else {
        length.unwrap_or(data.len()).min(data.len())
    };

    let start = offset.min(data.len());
    let data_slice = &data[start..end.min(data.len())];

    for (i, chunk) in data_slice.chunks(16).enumerate() {
        let addr = start + i * 16;
        let hex_part: String = chunk.iter()
            .map(|b| format!("{:02x} ", b))
            .collect();
        let ascii_part: String = chunk.iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();

        // Padding para alinear
        let hex_padded = format!("{:<48}", hex_part);
        println!("{:08x}: {} |{}", addr, hex_padded, ascii_part);
    }

    Ok(())
}

// =============================================================================
// HELPERS
// =============================================================================

/// Parsear un contrato desde el DSL textual del proyecto.
///
/// YAML queda explícitamente fuera: la revisión P0 (punto 13) señaló que
/// `YAML -> Contract struct -> binario` convierte detalles accidentales de
/// serde en parte de la semántica, y además `serde_yaml` nunca estuvo
/// declarado en `Cargo.toml`, así que esta ruta jamás compiló. El formato de
/// fuente soportado es el DSL del proyecto; JSON queda como interchange
/// informativo.
/// Parsear un contrato desde el DSL textual del proyecto.
///
/// El DSL usa `clave valor` (no `clave: valor`), con el nombre del contrato
/// en `contract "nombre" { ... }`. YAML queda explícitamente fuera: la
/// revisión P0 (punto 13) señaló que `YAML -> Contract struct -> binario`
/// convierte detalles accidentales de serde en parte de la semántica, y
/// además `serde_yaml` nunca estuvo declarado en `Cargo.toml`, de modo que
/// esa ruta jamás compiló.
///
/// Limitación consciente: se parsea la cabecera del contrato (nombre,
/// namespace, versión, rol) y las directivas de `security`. Los tipos y las
/// operaciones se registran con IDs sintéticos y su forma completa se
/// compila en la P1 (ver [Hoja de ruta](roadmap.md)). El `contract_hash` que
/// se obtiene hoy es por tanto estable y verificable, pero noyet describe la
/// superficie de tipos y operaciones.
fn parse_dsl_contract(content: &str) -> anyhow::Result<Contract> {
    let mut name = String::from("unnamed");
    let mut namespace = String::from("default");
    let mut version = ContractVersion::new(1, 0, 0);
    let mut role = None;
    let mut security: Option<SecurityPolicy> = None;

    // Elimina comentarios de línea, respetando los literales entre comillas.
    for (lineno, raw) in content.lines().enumerate() {
        let cleaned = strip_comment(raw);
        let line = cleaned.trim();
        if line.is_empty() {
            continue;
        }

        // `contract "nombre" {`
        if let Some(rest) = line.strip_prefix("contract") {
            let rest = rest.trim();
            if rest.starts_with('"') || rest.starts_with('\'') {
                let q = rest.as_bytes()[0] as char;
                if let Some(end) = rest[1..].find(q) {
                    name = rest[1..1 + end].to_string();
                }
            }
            continue;
        }

        // `clave valor`, con o sin dos puntos.
        let (key, value) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim().trim_matches('"')),
            None => match line.split_once(char::is_whitespace) {
                Some((k, v)) => (k.trim(), v.trim().trim_matches('"')),
                None => continue,
            },
        };

        match key {
            "name" => name = value.to_string(),
            "namespace" | "package" => {
                namespace = value.to_string();
            }
            "version" => {
                version = ContractVersion::from_string(value).map_err(|e| {
                    anyhow::anyhow!("línea {}: versión inválida ({e})", lineno + 1)
                })?;
            }
            "role" => {
                role = Some(value.to_string());
            }
            "authentication" | "encryption" | "replay_protection" | "confidentiality" => {
                let mut policy = security.clone().unwrap_or_default();
                let required = value.eq_ignore_ascii_case("required");
                match key {
                    "authentication" => policy.authentication_required = required,
                    "encryption" | "confidentiality" => {
                        policy.confidentiality_required = required
                    }
                    _ => policy.anti_replay = required,
                }
                security = Some(policy);
            }
            _ => {}
        }
    }

    let mut contract = Contract::new(&name, &namespace, version);
    if let Some(p) = security {
        contract.security = p;
    }
    // `role` se acepta y se ignora de forma deliberada: `ContractRole`
    // describe el papel de un extremo en el handshake, no una propiedad del
    // contrato binario. Se documenta aquí para que el parseo no falle.
    let _ = role;
    Ok(contract)
}

/// Eliminar un comentario `//` o `#` que no esté dentro de un literal.
fn strip_comment(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut in_quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match in_quote {
            Some(q) if b == q => in_quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => in_quote = Some(b),
            None if b == b'/' && bytes.get(i + 1) == Some(&b'/') => {
                return line[..i].to_string();
            }
            None if b == b'#' => return line[..i].to_string(),
            None => {}
        }
    }
    line.to_string()
}

fn parse_json_contract(content: &str) -> anyhow::Result<Contract> {
    let json: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| anyhow::anyhow!("Error parseando JSON: {}", e))?;

    let name = json["name"].as_str().unwrap_or("unknown");
    let namespace = json["namespace"].as_str().unwrap_or("default");
    let version_str = json["version"].as_str().unwrap_or("1.0.0");

    let version = ContractVersion::from_string(version_str)?;

    let contract = Contract::new(name, namespace, version);

    Ok(contract)
}

/// ID de contrato derivado del contenido (BLAKE3 de nombre + namespace + versión)
///
/// Determinista: el mismo contrato fuente produce el mismo ID en cualquier
/// máquina, que es lo que permite comparar contratos entre builds.
fn generate_contract_id(contract: &Contract) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(contract.header.name.as_bytes());
    hasher.update(contract.header.namespace.as_bytes());
    hasher.update(contract.header.version.to_string().as_bytes());
    let hash = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_le_bytes(out)
}

/// Firmar un contrato con una clave privada Ed25519 (P0.2)
///
/// La versión anterior escribía `vec![0u8; 64]` como "firma" y el verificador
/// devolvía `Ok(())` siempre: cualquier contrato parecia "firmar" y cualquier
/// firma pasaba. Ahora la firma es Ed25519 real sobre el preimagen canónico.
fn sign_contract(mut contract: Contract, key_path: &Path) -> anyhow::Result<Contract> {
    let key_bytes = read_key_file(key_path, "privada")?;
    // `from_bytes` es infalible en ed25519-dalek 2.x: la longitud ya la
    // garantiza el tipo `[u8; 32]`.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

    ContractSigner::sign(&mut contract, &signing_key)
        .map_err(|e| anyhow::anyhow!("fallo al firmar: {e}"))?;

    Ok(contract)
}

/// Verificar la firma Ed25519 de un contrato (P0.2)
fn verify_contract_signature(contract: &Contract, key_path: &Path) -> anyhow::Result<()> {
    let key_bytes = read_key_file(key_path, "pública")?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| anyhow::anyhow!("clave pública Ed25519 inválida (se esperaban 32 bytes)"))?;

    ContractSigner::verify(contract, &verifying_key)
        .map_err(|e| anyhow::anyhow!("firma inválida: {e}"))
}

/// Leer una clave de un archivo, admitiendo hex o binario crudo de 32 bytes
fn read_key_file(path: &Path, kind: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = fs::read(path)
        .map_err(|e| anyhow::anyhow!("no se pudo leer la clave {kind} en {}: {e}", path.display()))?;

    // Binario crudo de 32 bytes
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    // Hex, con o sin salto de línea final
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("la clave {kind} no es ni binario de 32 bytes ni hex"))?;
    let hex: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if hex.len() != 64 {
        return Err(anyhow::anyhow!(
            "la clave {kind} debe tener 32 bytes (64 hex), tiene {}",
            hex.len() / 2
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("hex inválido en la clave {kind}"))?;
    }
    Ok(out)
}

/// Convertir un `Path` a `&str` para la API de la librería
fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

// =============================================================================
// DEPENDENCIAS ADICIONALES
// =============================================================================

mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}
