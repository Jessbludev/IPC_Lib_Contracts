# IPC Lib Contracts v2.1.1 — Release Manifest

Estado: **pre-release**

## Distribución canónica

- Archivo: `ipc_lib_contracts_v2.1.1-reviewed-2-reproducible.zip`
- SHA-256: `d2a9ab38e5673d549bf994b03ed014332196b5c6de9a9cb4a9bb2834a2a6c106`
- Tamaño: `271988` bytes
- Archivos del paquete: `71`
- Documentación estática: `docs/site/` (14 páginas, incluida `index.html`)
- Generación del sitio: `python3 tools/render_docs.py` — determinista y sin dependencias externas
- Enlaces internos y anclas rotos: 0

El archivo canónico se construye con las rutas ordenadas, marcas de tiempo
normalizadas y el contenido del árbol publicado, excluyendo únicamente este
manifiesto. Se excluye para evitar una autorreferencia imposible al calcular su
propio SHA-256; el manifiesto versionado en Git es la metadata de distribución.

## Componentes

- Core Rust: CBC, protocolo wire v2, seguridad, operaciones y CLI `contractc`.
- C++ bindings: BLAKE3, contrato, cliente, seguridad y conformidad.
- Kotlin bindings: contrato, serialización, frame, sesión, anti-replay y conformidad.
- Vectores dorados: `tests/vectors/crypto.json`.
- Contrato de ejemplo: `contracts/image_processor.contract`.
- Documentación normativa: `docs/`, `docs/wiki/`.
- Sitio offline: `docs/site/`, regenerable con `tools/render_docs.py`.
- Generador de documentación: `tools/render_docs.py`.

## Reproducibilidad y versiones

- La fuente de verdad es el árbol completo de `main`; no se reconstruye el
  proyecto desde un manifiesto.
- La segunda ejecución consecutiva del generador produjo exactamente los
  mismos bytes que la primera.
- El sitio publicado usa únicamente los nombres actuales (`get-started.html`,
  `implementation.html`, `integration.html`, `roadmap.html`,
  `security-wiki.html` y `usage.html`); no se conservan las páginas con slugs
  transliterados incorrectamente.
- `run_all_tests.sh` falla explícitamente cuando falta una herramienta y el
  gate de CMake exige que `ctest` encuentre tests reales.
- No se mantienen hashes ni nombres de artefactos anteriores en la versión
  canónica.

## Verificación registrada

Los nueve gates se ejecutaron y pasaron el 2026-09-30 contra una extracción
limpia del árbol revisado, con toolchain completo:

| Gate | Resultado |
|---|---|
| `cargo check --all-targets --all-features` | 0 errores |
| `cargo test --all-features` | 53 tests, 0 fallos |
| g++ `-Wall` sobre los bindings | 0 warnings |
| Vectores BLAKE3 oficiales | coinciden |
| Conformidad C++ | 18 checks, 0 fallos |
| CMake + ctest | 100% tests passed (2 tests) |
| Compilación Kotlin | correcta |
| Conformidad Kotlin | 39 checks, 0 fallos |

Toolchain usado: Rust 1.98.1, GCC 12.2, CMake 3.25.1, OpenSSL 3.0.20,
JDK 17.0.2, Kotlin 1.9.24, kotlinx-coroutines 1.8.1.

## Riesgos abiertos

La verificación no resuelve dos asuntos documentados en el proyecto:

1. `ContractReader::from_bytes` todavía no verifica la firma.
2. BLAKE3 lanza una excepción al superar 1 KiB.

Ambos quedan fuera de esta publicación y deben corregirse antes de declarar una
versión estable.
