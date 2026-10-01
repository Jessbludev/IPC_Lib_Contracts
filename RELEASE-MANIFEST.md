# IPC Lib Contracts v2.1.1 — Release Manifest

Estado: **pre-release**

## Distribución validada

- Archivo: `ipc_lib_contracts_v2.1.1-final.zip`
- SHA-256: `7c964f4d8e7bdca5402dc06306bd7f91f6c06bbcf92d34160b29e1ff1e4bb43d`
- Tamaño aproximado: 304 KiB
- Archivos del paquete: 72
- Documentación estática: `docs/site/`
- Páginas HTML verificadas: 14
- Enlaces internos rotos: 0

## Componentes

- Core Rust: CBC, protocolo wire v2, seguridad, operaciones y CLI `contractc`.
- C++ bindings: BLAKE3, contrato, cliente, seguridad y conformidad.
- Kotlin bindings: contrato, serialización, frame, sesión, anti-replay y conformidad.
- Vectores dorados: `tests/vectors/crypto.json`.
- Contrato de ejemplo: `contracts/image_processor.contract`.
- Documentación normativa: `docs/`, `docs/wiki/`.
- Sitio offline: `docs/site/`.

## Verificación registrada

La distribución fue validada previamente con gates de Rust, C++, BLAKE3, conformidad C++ y Kotlin. La publicación actual del repositorio debe considerarse una etapa de distribución separada de esa ejecución de pruebas.

## Nota de publicación

El conector GitHub disponible permite crear blobs y archivos de texto, pero no expone una operación de carga directa del ZIP binario local ni de assets de release. Por ello, este manifiesto registra el artefacto y su identidad criptográfica sin afirmar que el ZIP esté almacenado actualmente en este repositorio.

La fuente de verdad prevista sigue siendo el árbol completo del proyecto; no se debe reconstruir el ZIP desde este manifiesto.
