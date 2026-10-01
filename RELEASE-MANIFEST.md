# IPC Lib Contracts v2.1.2 — Release Manifest

Estado: **pre-release (0.3.0-pre)**

## Distribución canónica

- Archivo: `ipc_lib_contracts_v2.1.2-reviewed-2-reproducible.zip`
- SHA-256: `c57fcdc92a49aed16bd98b72f53bf00dc30463de85a074f8e4ca96e761d0349f`
- Tamaño: `231606` bytes
- Archivos del paquete: `60`
- Fuentes HTML: `docs/` y `tools/render_docs.py`
- Sitio publicado: <https://ipc-lib-contracts-docs.netlify.app>
- Páginas generadas: 15, incluida `index.html`
- Enlaces internos y anclas rotos: 0

El artefacto fuente se construye con rutas ordenadas y marcas de tiempo
normalizadas, excluyendo únicamente este manifiesto y `docs/site/`, que es
salida generada y se publica por separado en Netlify. El hash se calcula sobre
el ZIP externo y no se copia dentro de él; así no existe autorreferencia.

## Cambios de 2.1.2

### PR1 — Verificación de firma en el tipo (ADR-0006)

`ContractReader::from_bytes` devuelve `UnverifiedContract`. Sólo
`verify(&clave_externa)` produce un `VerifiedContract`. `key_id` ocupa el
offset 224 del header CBC1, cubierto por hash y firma, y selecciona la clave
del almacén externo sin ser un ancla de confianza. `finalize()` canoniza
`schema_offset` a 0 cuando `schema_size == 0`.

### PR2 — BLAKE3 con árbol de sub-chunks completo (ADR-0007)

C++ y Kotlin implementan el árbol completo de BLAKE3 con API incremental y sin
el límite artificial de 1024 bytes. La conformidad cubre 19 longitudes hasta
1 MiB, modo normal, keyed y particiones de streaming contra Rust.

## Compatibilidad de identidad

`key_id` cambia el `contract_hash` cuando es distinto de 0. Los contratos con
`key_id = 0` explícito conservan la identidad de 2.1.1. Ver
`docs/wiki/snapshots.md`.

## Componentes

- Core Rust: CBC, protocolo wire v2, seguridad, operaciones y CLI `contractc`.
- C++ bindings: BLAKE3 multi-chunk, contrato, cliente, seguridad y conformidad.
- Kotlin bindings: BLAKE3 multi-chunk, contrato, serialización, frame, sesión y conformidad.
- Vectores dorados: `tests/vectors/crypto.json`.
- Generador documental determinista: `tools/render_docs.py`.

## Verificación registrada

Los diez gates se ejecutaron y pasaron el 2026-09-30 contra una extracción
limpia del árbol revisado, con toolchain completo:

| Gate | Resultado |
|---|---|
| `cargo check --all-targets --all-features` | 0 errores |
| `cargo test --all-features` | 66 tests, 0 fallos |
| g++ `-Wall` sobre los bindings | 0 warnings |
| Vectores BLAKE3 oficiales | coinciden |
| BLAKE3 multi-chunk C++ | 41 checks, 0 fallos |
| Conformidad C++ | 18 checks, 0 fallos |
| CMake + ctest | 100% tests passed (3 tests) |
| Compilación Kotlin | correcta |
| Conformidad Kotlin | 74 checks, 0 fallos |

Toolchain usado: Rust 1.98.1, GCC 12.2, CMake 3.25.1, OpenSSL 3.0.20,
JDK 17.0.2, Kotlin 1.9.24, kotlinx-coroutines 1.8.1.

## Riesgos restantes

La capa de transporte todavía no está implementada de extremo a extremo. La
versión continúa siendo pre-release y no declara APIs estables.
