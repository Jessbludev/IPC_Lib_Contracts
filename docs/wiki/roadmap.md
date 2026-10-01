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

### 1. El transporte (P0 para uso real)

`UnixSocketTransport` y `TcpTransport` en C++ lanzan
`requires native implementation`. `UnixSocketTransport` en Kotlin es un stub
que marca `connected = true` y no envía nada. El motor Rust gestiona estado y
claves pero **no abre sockets**: `main` inicializa el engine e imprime una
línea.

Consecuencia: **no hay dos procesos hablando todavía.** Hay un canal
completo y falta el tubo.

Es lo primero que hay que escribir, y es la razón por la que el proyecto
todavía no debería anunciarse como listo para producción.

### 2. `ContractReader` no verifica la firma (P0 de seguridad)

Comprueba que la firma **está presente** y que el `contract_hash` cuadra, pero
no la valida criptográficamente, porque no recibe una clave pública confiable
— no debería recibirla: eso sería Trusted Third Party y el modelo de seguridad
lo prohíbe.

Así que hoy la verificación de firma vive en `ContractSigner::verify`, que sí
recibe la clave. El riesgo es que un integrador use `from_bytes` y crea que
obtuvo un contrato verificado.

Dos opciones, y hay que elegir una:

- **Hacer el tipo explícito**: que `from_bytes` devuelva un tipo
  `UnverifiedContract` que no expona los datos, y que sólo
  `ContractSigner::verify` libere un `VerifiedContract`. El sistema de tipos
  impide el error. Es lo correcto.
- **Documentarlo y trust-on-first-use**: más rápido, pero deja un pie de
  hongo.

Recomiendo la primera.

### 3. BLAKE3 limitado a 1024 bytes por llamada (C++ y Kotlin)

Ambos lanzan excepción más allá de 1024 bytes. Es explícito y nunca devuelve
un digest incorrecto, que es lo importante. Pero un contrato real con header,
tipos, operaciones y política **supera 1024 bytes con facilidad**: el vector
de conformidad de Rust ya mide 341 bytes sólo en contenido.

Ninguno de los tests actuales lo detecta, porque los vectores son pequeños.
Es un fallo latente que aparecerá en el primer contrato de producción.

Antes de escribir los tests hay que decidir el enfoque: implementar el árbol
BLAKE3 completo (2 KiB de bloques, fanout de 7, compresión de padres), o
enrutar a una implementación probada sin FFI.

### 4. El parser del DSL cubre sólo la cabecera

`contractc compile` lee nombre, namespace, versión y política de seguridad.
**No** lee los bloques `type` ni `operation`: un contrato compila con
`Types: 0`.

El `contract_hash` resultante es estable y verificable, pero no describe la
superficie de tipos y operaciones. Dos contratos con tipos distintos pueden
producir el mismo hash. Eso es una weakness real de identidad.

### 5. Generación de código parcial

Genera estructura de tipos y operaciones, pero no stubs de serialización,
clientes ni tests.

## Orden sugerido

**Antes de publicar como estable:**

1. Validación de firma en el tipo (`UnverifiedContract` → `VerifiedContract`).
   Es un fallo de seguridad y es barato de arreglar.
2. BLAKE3 multi-chunk. Los contratos reales no caben en 1024 bytes y ningún
   test lo detecta todavía.
3. Parser del DSL completo, o documentar formalmente que `contractc compile`
   es experimental y no usar el `contract_hash` resultante como identidad de
   contrato de producción.
4. Tests que fallen hoy: un contrato de > 1 KiB, y un contrato con firma
   corrupta cargado por `from_bytes`.

**Antes de anunciar que "funciona":**

5. Un transporte real en Rust, con un test end-to-end entre dos procesos.
6. El mismo en C++ y Kotlin, o un wrapper sobre el de Rust.
7. `kp_server` / `kp_client` como ejecutables de referencia.

**Opcional:**

8. FFI Rust para bindings nativos, si el transporte resulta inviable de
   escribir tres veces.
9. YAML como formato de entrada, si alguien lo necesita de verdad.

## Sobre publicar ahora

Mi lectura: **es publicable como pre-release, no como estable.**

A favor de publicarlo ya:

- El trabajo de criptografía y conformidad es lo difícil, y está verificado
  con tests cruzados, no con inspecciones.
- La v2.1 original no compilaba en ningún lenguaje. Publicar la v2.1.1 deja
  de manifiesto una diferencia enorme de calidad.
- Todo el que se acerque ahora recibe algo verificable desde el primer día.

En contra:

- El transporte no existe, así que no se puede hacer nada útil de extremo a
  extremo.
- Hay un pie de hongo de seguridad (`from_bytes` sin verificar firma) y otro
  funcional (BLAKE3 > 1 KiB) que ningún test cubre.

Si publicas, publícalo etiquetado `0.2.0-pre`, con la tabla de estado del
[README del wiki](README.md#estado-real-del-proyecto) como primera sección, y
sin declarar APIs estables.

Mi recomendación concreta: arregla los puntos 1 y 2 — son horas, no días — y
luego publica. El punto 1 es un fallo de seguridad y el 2-rompe en producción
al primer contrato real.
