# IPC Contract System

Sistema de contratos binarios canónicos para comunicación inter-procesos con
autenticación criptográfica end-to-end, sin FFI ni NDK.

**Estado: 2.1.1 — pre-release (`0.2.0`)**

---

## Qué es

Un contrato es un artefacto firmado que define *qué operaciones existen entre
dos procesos, con qué tipos y bajo qué política de seguridad*. El runtime IPC
verifica ese contrato antes de permitir tráfico: si un extremo sirve un
contrato distinto al que espera, la sesión no se establece.

La idea central es que la **identidad del contrato** (`contract_hash`,
BLAKE3-256) es la misma en los tres lenguajes. Un contrato compilado en Rust
tiene exactamente el mismo hash en C++ y en Kotlin, byte a byte. Eso es lo que
permite que un proceso escrito en un lenguaje y otro escrito en otro negocien
y se autentiquen sin intermediarios.

## Estado real del proyecto

Conviene ser explícito sobre qué está terminado y qué no, porque el alcance
varía mucho entre(binding.

| Componente | Estado | Notas |
|---|---|---|
| Core Rust (`src/`) | **Funcional** | CBC, protocolo de frames, criptografía, verificación |
| CLI `contractc` | **Funcional** | `compile`, `verify`, `inspect`, `hash`, `dump`, `generate` |
| Criptografía C++ | **Funcional** | Ed25519, BLAKE3-256, ChaCha20-Poly1305, anti-replay |
| Parser de contratos C++ | **Funcional** | Lee CBC1, calcula y verifica `contract_hash` |
| Contratos Kotlin | **Funcional** | BLAKE3, Ed25519, anti-replay, encoding canónico |
| Transport C++ | **No implementado** | `UnixSocketTransport` y `TcpTransport` lanzan excepción |
| Transport Kotlin | **No implementado** | `UnixSocketTransport` es un stub |
| Runtime de red Rust | **No implementado** | El engine gestiona estado y claves, no conecta sockets |
| Generación de código | **Parcial** | Genera estructura de tipos y operaciones |

En resumen: **la capa de contrato y criptografía está completa y verificada;
el transporte está sin escribir.** Los bindings C++ y Kotlin son útiles para
verificar contratos y operar sobre frames, pero no abren un canal de
comunicación por sí mismos.

Esto es deliberado y no un descuido: la corrección del protocolo es la parte
difícil de acertar, y se ha hecho con pruebas de conformidad cruzadas. El
transporte es mecánica. Ver [Hoja de ruta](roadmap.md).

## Empezar

```bash
git clone <repo>
cd ipc-lib-contracts

# Verificar que todo está bien (compila y pasa los tests en los 3 lenguajes)
./run_all_tests.sh
```

Ese comando ejecuta nueve gates. Si termina con
`Todos los gates pasaron`, el código está en el estado que describe este
documento.

Para generar y examinar un contrato:

```bash
cargo run --features clap --bin contractc -- compile contracts/image_processor.contract
cargo run --features clap --bin contractc -- verify build/image_processor.cbc
cargo run --features clap --bin contractc -- inspect build/image_processor.cbc
```

Continúa en [Get Started](get-started.md).

## Documentación

| Documento | Para quién | Contenido |
|---|---|---|
| [Get Started](get-started.md) | Todos | Instalación, primer contrato, primer frame |
| [Uso](usage.md) | Usuarios | Referencia de la CLI y de las APIs |
| [Implementación](implementation.md) | Mantenedores | Formato CBC1, protocolo de frames, criptografía |
| [Integración](integration.md) | Integradores | Cómo usar cada binding desde tu aplicación |
| [Seguridad](security.md) | Auditores | Políticas zero-trust, zero-knowledge, zero-log |
| [Hoja de ruta](roadmap.md) | Todos | Qué falta y en qué orden |
| [ADR](adr.md) | Mantenedores | Decisiones de arquitectura y su porqué |

## Requisitos

| Herramienta | Versión | Para qué |
|---|---|---|
| Rust | 1.75 o superior (estable) | Core y CLI |
| OpenSSL | 3.0 o superior | Ed25519 y ChaCha20-Poly1305 en C++ |
| C++ | C++20 (GCC 12+ / Clang 15+) | Bindings C++ |
| CMake | 3.20 o superior | Build de los bindings C++ |
| JDK | 17 o superior | Bindings Kotlin (Ed25519 nativo vía `SunEC`) |
| Kotlin | 1.9 o superior | Compilación de los bindings |
| kotlinx-coroutines | 1.8 o superior | Runtime asíncrono de Kotlin |

Detalles y alternativas en [Get Started → Requisitos](get-started.md#requisitos).

## Licencia

Por definir antes de publicar el repositorio.
