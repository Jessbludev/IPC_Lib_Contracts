# Seguridad

Políticas, qué las respalda, y qué modelo de amenaza asumimos.

## Modelo de amenaza

Asumimos que el atacante controla el canal de transporte y puede leer,
modificar, reordenar, reenviar e inyectar frames. No asumimos que el
anfitrión esté comprometido: si lo estuviera, no hay nada que hacer desde
aquí.

**No** protegemos contra un atacante con acceso a la clave del anfitrión, ni
contra roots de análisis en tiempo de ejecución. Lo que sí protegemos es el
tráfico y los contratos.

## Zero trust

Nada se acepta porque "normalmente es correcto". Toda entrada se valida
explícitamente, y el fallo es un error, nunca un valor por defecto.

| Comprobación | Dónde |
|---|---|
| Magic y versión de formato | `ContractHeader::from_bytes` |
| Header canónico byte a byte | `ContractHeader::from_bytes` |
| Bounds y solapamientos de sección | `ContractHeader::from_bytes` |
| UTF-8 en campos de texto | validación de header |
| Enums y flags con bits desconocidos | `Frame::from_bytes` |
| `contract_hash` recalculado | `Contract::verify` |
| Longitudes de todas las variables | cada parser |
| Prefijo de contrato por frame | `WireProtocol::receive` |

### Fallar de forma ruidosa

Un contrato malformado **no** se carga parcialmente. Se rechaza entero. Un
parser que adivine es un parser que somebody va a exploitear.

## Zero knowledge / isolation

Lo que la librería **no** necesita saber:

- **No conoce tu payload.** Solo ve bytes cifrados. No inspecciona, no
  registra, no transforma.
- **No conoce tu clave.** `kd_secret` se le pasa ya derivado. La librería
  nunca lo ve en más de una llamada, y `SessionKey` implementa `Drop` para
  sobrescribir el material al destruirse.
- **No conoce tu identidad.** No pide ni almacena información del usuario.
  La autorización es de la aplicación.
- **No tiene estado global.** Cada `AntiReplay` y cada `Contract` es
  explícito. Dos instancias no comparten nada.

### Gestión de material de clave

- El secreto raíz es lo único que hay que proteger. Todo lo demás se deriva.
- Las claves de sesión se derivan por sesión y se pueden descartar. No hace
  falta almacenarlas.
- Al destruir una clave, se sobrescribe antes de liberar. `SessionKey`
  implementa `Drop` justamente para esto.
- Las claves privadas de firma deberían vivir en el keystore del sistema
  (Android Keystore, Secure Enclave), no en ficheros de la app.

## Zero log

**La librería no registra nada. No inicializa sinks.**

Esto no es una omisión: es una decisión de diseño, y está en el código. El
motor Rust no llama a `tracing_subscriber::init()`, y no hay `println!` con
datos de sesión.

Por qué: en un runtime móvil, un sink por defecto escribe en `logcat`, que
es legible por otras apps con el permiso correspondiente. Una librería de IPC
que emite trazas por su cuenta filtra la política de observabilidad del
anfitrión a cualquier app instalada.

**Lo que sí sale por stdout** es deliberado y está acotado: el arranque del
binario (`IPC Engine v2 — <versión>`). Es lo mismo que verías ejecutando el
binario a mano, y no contiene claves, hashes completos ni payloads.

La observabilidad la instala el proceso anfitrión, con un filtro explícito.

### Qué nunca debe registrarse

- Material de clave, ni siquiera un prefijo
- `contract_hash` completo (el prefijo de 12 bytes sí es apto, precisamente
  porque no es identidad)
- Plaintext ni ciphertext
- Nombres de operaciones, si pueden revelar comportamiento del usuario

## Anti-replay

Ventana sliding de 1024 secuencias por `(session_id, direction)`.

TX y RX tienen ventanas **independientes**: un frame reflejado nunca puede ser
procesado dos veces. Esto no es cosmético: un endpoint con la misma clave en
ambas direcciones es un escenario normal.

La comprobación del AEAD va **antes** que el registro de secuencia. Si no, un
atacante sin la clave podría hacer avanzar la ventana y bloquear tráfico
válido: denegación de servicio sin conocer ningún secreto.

## Integridad del contrato

Todo byte del archivo está cubierto por `contract_hash`, o el contrato se
rechaza. La regla es: si un byte no está en el preimagen, no puede estar en
el archivo.

Esto se traduce en una defensa concreta: el parser exige que el header
re-serializado sea idéntico a los bytes leídos, de modo que el relleno tras
los NUL no puede variar. El fuzzing encontró exactamente ese fallo en v2.1
—ver [Implementación](implementation.md#fallo-de-integridad-encontrado-por-fuzzing)—.

## Firma

Ed25519 real en los tres lenguajes:

| Lenguaje | Implementación | Notas |
|---|---|---|
| Rust | `ed25519-dalek` | Referencia |
| C++ | OpenSSL 3 | `EVP_PKEY_ED25519` |
| Kotlin | `SunEC` (JDK 15+) | Sin dependencias externas |

**Por qué no HMAC ni `SHA-256(private_key)`, que es lo que hacía v2.1:** no son
firma. Una clave derivada de un secreto no demuestra identidad: cualquiera que
conozca el secreto puede "firmar". La firma tiene que demostrar que quien
firmó posee una clave privada que el verificador no tiene.

`SignaturePolicy::Required` es el valor por defecto y es **fail-closed**: sin
firma, se rechaza.

### Confianza de la clave

`ContractReader::from_bytes` comprueba presencia de firma y `contract_hash`,
pero **no verifica la firma criptográficamente** porque no recibe una clave
pública confiable — no debería recibirla: eso sería Trusted Third Party.

La verificación real está en `ContractSigner::verify`, que sí recibe la clave.
Mientras tanto, usar `from_bytes` sin `verify` es un pie de hongo documentado
en la [hoja de ruta](roadmap.md).

## Nonces

`nonce = BLAKE3_keyed(nonce_key, dominio ‖ direction ‖ session_id ‖ sequence)[0..12]`

Determinista y sin negociación: los tres lenguajes calculan los mismos 12
bytes. No es aleatorio, así que **la seguridad depende de que la secuencia no
se repita** bajo la misma clave de sesión.

`AntiReplay` cubre la repetición dentro de una sesión. Si persistes el
contador, un reinicio a cero bajo la misma clave reutiliza nonces. Ante la
duda, deriva una clave de sesión nueva.

## Resistente a ingeniería inversa

- Claves redacted en logs y errores: nunca se imprime material de clave.
- `SessionKey` implementa `Drop` y sobrescribe al destruirse.
- Sin-reflection ni serialización de estado interno.

**Límite honesto:** esto protege contra volcados de memoria posteriores a la
limpieza, y contra fugas por logs. No protege contra un atacante con acceso al
proceso mientras la clave está en uso — para eso hace falta el keystore del
sistema, que la librería no puede imponer.

## Verificación

Cada política de esta tabla tiene un test que la respalda:

| Política | Test |
|---|---|
| Sin panics en parsers | `tests/fuzz_parsers.rs`, 11 property tests |
| Integridad total | `test_no_byte_of_the_file_escapes_integrity` |
| Contrato canónico | rejection test de header no canónico |
| Anti-replay correcto | `tests/conformance.rs`, ventana sliding |
| AEAD antes de anti-replay | orden en `WireProtocol::receive` |
| BLAKE3 correcto | vectores oficiales de BLAKE3 |
| BLAKE3 keyed correcto | `tests/vectors/crypto.json` |
| Ed25519 correcto | `tests/vectors/crypto.json`, 3 lenguajes |
| Conformidad C++ | 18 checks |
| Conformidad Kotlin | 39 checks |

```bash
./run_all_tests.sh
```

## Lo que este documento no cubre

- Auditoría externa de las implementaciones criptográficas propias (BLAKE3
  en C++ y Kotlin están escritas a mano y verificadas contra vectores, no
  auditadas).
- Seguridad del transporte: no existe todavía.
- Gestión del ciclo de vida de `kd_secret` en la aplicación anfitriona.
- resistancia a ingeniería inversa con herramientas de instrumentación de
  runtime.
