# Hoja de ruta

Estado real del proyecto, y el orden en que creo que conviene seguir.

## Lo que funciona

- **Core Rust**: CBC1, frames, handshake, criptografía, verificación.
  `cargo test` pasa 53 tests, incluidos 11 de fuzzing de parsers.
- **`contractc`**: `compile`, `verify`, `inspect`, `hash`, `dump`, `generate`.
- **C++**: BLAKE3, Ed25519 (OpenSSL 3), ChaCha20-Poly1305, anti-replay,
  `contract_hash` canónico. 18 checks de conformidad.
- **Kotlin**: BLAKE3, Ed25519 (`SunEC` del JDK), AEAD vía JCA, anti-replay.
  39 checks de conformidad.
- **Conformidad cruzada**: los tres lenguajes producen bytes idénticos,
  verificado contra vectores dorados.

## Lo que no funciona

### 1. El transporte

`UnixSocketTransport` y `TcpTransport` en C++ lanzan
`requires native implementation`. `UnixSocketTransport` en Kotlin es un stub
que marca `connected = true` y no envía nada. El motor Rust gestiona estado y
claves pero **no abre sockets**: `main` inicializa el engine e imprime una
línea.

Consecuencia: **no hay dos procesos hablando todavía.** Hay un canal completo y
falta el tubo.

Es lo primero que queda, y es la razón por la que el proyecto todavía no
declararse listo para producción.

### 2. El parser del DSL cubre sólo la cabecera

`contractc compile` lee nombre, namespace, versión y política de seguridad.
**No** lee los bloques `type` ni `operation`: un contrato compila con
`Types: 0`.

El `contract_hash` resultante es estable y verificable, pero no describe la
superficie de tipos y operaciones. Dos contratos con tipos distintos pueden
producir el mismo hash. Es una debilidad real de identidad.

### 3. Generación de código parcial

Genera estructura de tipos y operaciones, pero no stubs de serialización,
clientes ni tests.

## Resueltos en 2.1.2

### Verificación de firma en el tipo — cerrado

`ContractReader::from_bytes` devuelve `UnverifiedContract`. Sólo
`verify(&clave_externa)` produce un `VerifiedContract`, y no hay forma de
obtener ese tipo sin pasar por una clave de confianza externa.

Añadido `key_id` en el offset 224 del header (zona antes reservada, sin
cambiar el formato), cubierto por el hash y por la firma.

Ver [ADR-0006](adr.md#adr-0006-verificacion-de-firma-en-el-tipo).

13 tests nuevos cubren la tabla del criterio de aceptación. El que recorre
todas las posiciones del archivo destapó una ambigüedad que no estaba en la
especificación: con `schema_size == 0`, `schema_offset` podía ser 0 o 256 y
describir el mismo contrato con el mismo hash. `finalize()` ahora canoniza a 0.

### BLAKE3 multi-chunk — cerrado

C++ y Kotlin implementan el árbol de sub-chunks completo según la
especificación oficial, con API incremental. Sin límite de tamaño.

Verificado byte a byte contra Rust para longitudes 0 a 1 MiB, incluidos los
casos que no son potencia de dos (1025, 2047, 2049, 3072, 4097), en modo
normal y keyed, y con particiones de streaming arbitrarias.

Ver [ADR-0007](adr.md#adr-0007-blake3-con-arbol-de-sub-chunks-completo).

## Orden sugerido

**Antes de anunciar que "funciona":**

1. Un transporte real en Rust, con un test end-to-end entre dos procesos.
2. El mismo en C++ y Kotlin, o un wrapper sobre el de Rust.
3. `kp_server` / `kp_client` como ejecutables de referencia.
4. El parser del DSL completo, o documentar formalmente que `contractc
   compile` es experimental y no usar su `contract_hash` como identidad de
   contrato de producción.

**Antes de una API estable:**

5. Congelar el formato CBC1. `key_id` ha ocupado la zona reservada 224-228; las
   formally-stable no admiten cambios incompatibles y este header ya ha
   cambiado una vez.

**Opcional:**

6. FFI Rust para bindings nativos, si el transporte resulta inviable de
   escribir tres veces.
7. YAML como formato de entrada, si alguien lo necesita de verdad.

## Sobre publicar ahora

Mi lectura: **los dos riesgos de seguridad están cerrados. Queda el
transporte.**

A favor:

- La verificación de firma ya no se puede saltarse por accidente: es un error
  de compilación, no una revisión de código.
- BLAKE3 calcula `contract_hash` para cualquier contrato real. El primer
  contrato de producción ya no rompe.
- 10 gates en verde, con conformidad verificada en los tres lenguajes hasta
  1 MiB.

En contra:

- Sin transporte no se puede hacer nada útil de extremo a extremo. Eso sigue
  siendo un bloqueante para llamarlo estable, aunque no es un bloqueante de
  seguridad.

Si publicas, publícalo como `0.3.0-pre`, con la tabla de estado del
[README del wiki](README.md#estado-real-del-proyecto) como primera sección, y
sin declarar APIs estables.
