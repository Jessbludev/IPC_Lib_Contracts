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

## Recuperación de la carga fallida

La publicación de `main` reutiliza este manifiesto y recupera el árbol completo desde el archivo recibido `ipc_lib_contracts_v2.1.1-final-download.zip`. Ese archivo descargado no es byte a byte el artefacto identificado en la sección anterior: su SHA-256 es `4dae81ac90f4a0482dff2051aa0bd1c45e716f262e39f8452b3ea68ea9238fe2` y contiene 70 archivos del proyecto (sin contar este manifiesto ni la metadata del repositorio). Por tanto, no se sustituye la identidad criptográfica histórica ni se presenta el ZIP descargado como el artefacto original.

La comprobación `cargo test --all-features` no pudo ejecutarse en el entorno de publicación porque `cargo` no está instalado. La compilación completa de C++ tampoco pudo ejecutarse porque faltan las cabeceras de OpenSSL; el vector aislado de BLAKE3 sí terminó con `ALL PASS (0 failures)`. La revisión estática no detectó archivos con nombres de credenciales (`.env`, claves, certificados o tokens) dentro del ZIP.
