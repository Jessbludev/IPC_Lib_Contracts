# Implementación

Cómo funciona por dentro. Esta es la referencia para quien mantenga el
código o tenga que reimplementar un binding.

## Principles

1. **Todo byte del archivo está cubierto por el hash o se rechaza.** Si un
   byte del contrato no está en el preimagen, un atacante puede alterarlo sin
   romper la integridad. No es negociable.
2. **Ningún parser hace panic.** Una librería que aborta el proceso del
   anfitrión por un input hostile es un denegación de servicio, no un bug.
3. **Sin degradación silenciosa.** Si algo no valida, se rechaza con un
   error explícito. Nunca se continúa con un valor por defecto.
4. **La identidad es BLAKE3-256.** SHA-256 queda como compatibilidad legacy y
   no se usa para identidad.

## Formato CBC1

Contrato binario canónico. Todo little-endian, sin relleno ni alineación
implicita.

```
┌──────────────────────────────────────────┐ 0
│ Header — 256 bytes fijos                 │
│   magic              [4]  "CBC1"         │
│   format_version     [1]  1              │
│   flags              [1]                 │
│   header_size        [2]  256            │
│   contract_id        [8]                 │
│   version            [3]  major/minor/pat│
│   contract_hash     [32]  BLAKE3-256     │
│   schema_offset     [4]  schema_size  [4]│
│   types_offset      [4]  types_size   [4]│
│   ops_offset        [4]  ops_size     [4]│
│   policy_offset     [4]  policy_size  [4]│
│   contract_id_2      [8]                 │
│   name             [64]  NUL-terminated  │
│   namespace        [64]  NUL-terminated  │
│   description     [128]  NUL-terminated  │
│   padding          [60]  debe ser cero   │
├──────────────────────────────────────────┤ 256
│ Sección de tipos                          │
├──────────────────────────────────────────┤
│ Sección de operaciones                    │
├──────────────────────────────────────────┤
│ Política de seguridad                     │
├──────────────────────────────────────────┤
│ Firma Ed25519 (64 bytes) — opcional      │
└──────────────────────────────────────────┘
```

Los offsets son absolutos desde el inicio del archivo. Deben estar alineados,
dentro de rango y no solaparse.

### Preimagen del hash

```
BLAKE3-256(
    header[0..256]  con contract_hash = 0
                    y todos los offsets/tamaños = 0
  ++ tipos
  ++ operaciones
  ++ política
)
```

El relleno del header después de los NUL **debe ser cero** y forma parte del
preimagen. `ContractHeader::to_bytes` lo garantiza, y
`ContractHeader::from_bytes` rechaza cualquier header cuya re-serialización
no sea idéntica a los bytes recibidos. Esa es la defensa contra el ataque que
encontró el fuzzer (ver más abajo).

### Firmado

Al firmar, `flags` incluye `SIGNED`. El preimagen de la firma es el mismo
preimagen del hash con ese flag ya activo. El orden importa: activar el flag
después de calcular el preimagen produce una firma que cubre un documento
distinto del que se va a verificar. Ese bug existía en v2.1.

## Protocolo de frames

64 bytes de header, ver [Uso → Frame](usage.md#frame). El AAD del AEAD son los
bytes 0..48.

El prefijo de 12 bytes del contrato viaja en cada frame como discriminador
rápido. No es identidad: la identidad autoritativa es el `contract_hash`
completo de 32 bytes, que viaja en el `HandshakeHello`.

## Handshake

```
Extremo A                          Extremo B
   │                                    │
   │──── HandshakeHello ───────────────>│   contract_hash[32]
   │                                    │   versión, nonce
   │                                    │
   │  B verifica:                       │
   │   · hash conocido y correcto       │
   │   · política de firma satisfecha   │
   │   · versión soportada              │
   │                                    │
   │<──── HandshakeHello ───────────────│
   │                                    │
   │  Verificación de firma mutua (si el │
   │  rol es Mutual)                    │
   │                                    │
   │════ sesiones de claves derivadas ══│
```

El `nonce` del hello es aleatorio y de un solo uso: es la única aleatoriedad
del protocolo. Todo lo demás se deriva.

## Criptografía

### Derivación de claves

```
kd_secret        32 bytes, alta entropía, único por instalación
      │
      ├── HKDF-Expand(prk = kd_secret, info = "ipc-v2 kdf", len=32)
      │     └── base_key
      │
      │   base_key + session_material
      │     = BLAKE3(base_key ‖ b"ipc-v2 session" ‖ contract_hash ‖ session_id_le)
      │     └── session_key
      │
      │   session_key → HKDF-Expand(info="enc", 32)  → encryption_key
      │   session_key → HKDF-Expand(info="nonce", 32) → nonce_key
```

`kd_secret` es lo único que hay que proteger. Todo lo demás se deriva y no
debe almacenarse.

**Por qué BLAKE3 y no HKDF para la derivación de sesión:** HKDF-Expand exige
`PRK` y `salt` con longitudes mínimas (`hash_len` y `hash_len`), y usarlos con
32 bytes de clave cruda sin pasar por `Extract` rompe el contrato. Se usa
BLAKE3 como PRF con clave. Está documentado en
[ADR-0003](adr.md#adr-0003-kdf-basada-en-blake3).

### Nonce

```
nonce = BLAKE3_keyed(nonce_key, 
                     b"ipc-v2 nonce" ‖ direction ‖ session_id_le ‖ sequence_le)[0..12]
```

**No es aleatorio.** Es una función pseudoaleatoria con clave, y por eso es
determinista: los tres lenguajes pueden calcularlo y obtener los mismos 12
bytes sin negociar nada.

La seguridad depende de que `(session_id, sequence, direction)` no se repita
bajo la misma `nonce_key`. `AntiReplay` garantiza que una secuencia no se
procese dos veces, y `direction` separa TX de RX, así que la reutilización
exige un fallo simultáneo en ambas protecciones.

**Consecuencia práctica:** un contador reiniciado bajo la misma clave de
sesión reutiliza nonces. Si haces checkpoint/restart, deriva una clave de
sesión nueva.

### Anti-replay

Ventana sliding de 1024 secuencias por `(session_id, direction)`:

```rust
struct AntiReplay {
    highest: u64,
    bitmap: u64,      // bit N = sequence (highest - N) visto
    window_size: u64,
}
```

- `sequence > highest` → desplazar y aceptar
- `highest - sequence < window_size` → comprobar bit; ya visto = rechazar
- más atrás que la ventana → rechazar

**Detalle de implementación que costó un bug:** al desplazar hay que mover el
bitmap (`bitmap <<= delta`), no sólo redimensionarlo. La implementación v2.1
hacía `resize` sin desplazar, de modo que la ventana nunca olvidaba nada y
mixed dos convenciones de índice a mitad de la función. Los tests pasaban
porque sólo comprobaban recencia.

### Orden de validación

```
receive():
  1. parsear frame          → error estructural
  2. comprobar prefijo      → contrato equivocado
  3. verificar AEAD         → mensaje alterado
  4. registrar secuencia    → anti-replay
```

El AEAD va **antes** que el anti-replay, a propósito. Si un atacante sin la
clave de descifrado pudiera hacer avanzar la ventana, podría bloquear tráfico
válido: denegación de servicio sin进程中 ningún secreto. Autenticar primero
significa que sólo quien tiene la clave puede avanzar la ventana.

## Bugs reales encontrados en v2.1

No están en la especificación P0. Se listan porque son la razón de que
existan los tests actuales.

### Ventana anti-replay rota (Rust)

`shift_and_expand()` redimensionaba sin desplazar, y la función mezclaba dos
convenciones de índice. La ventana no olvidaba.

### `sign()` firmaba el preimagen equivocado

El flag `SIGNED` se activaba **después** de calcular el preimagen. La firma
cubría un header con `flags=0` mientras el hash usaba `flags=SIGNED`, así que
ninguna firma validaba jamás.

### Fallo de integridad encontrado por fuzzing

El relleno tras el NUL del campo `name` (byte 98 en adelante) y el de
`schema_offset` (56..59) **no formaban parte del preimagen**, porque
`compute_hash()` lo reconstruía desde la struct *parseada*. Se podían alterar
sin cambiar ni `contract_hash` ni la firma.

Causa raíz: el hash se calculaba desde la representación en memoria en vez de
desde los bytes del archivo. Un archivo no canónico producía el mismo hash que
su versión canónica.

Arreglo:
1. `to_bytes` rellena con ceros tras el NUL
2. `ContractHeader::from_bytes` exige `header.to_bytes() == data[..256]`
3. Se rechaza una sección `schema` no vacía

Regresión: `test_no_byte_of_the_file_escapes_integrity`, que recorre **todas**
las posiciones del archivo y comprueba que alterarlas cambia el hash.

### Hash de contrato con implementación placeholder (C++)

```cpp
std::vector<uint8_t> Contract::calculate_hash(const std::vector<uint8_t>&) {
    std::vector<uint8_t> hash(protocol::HASH_SIZE, 0);  // 32 ceros
    return hash;
}
```

`Contract::verify()` compara ese resultado con el hash declarado, así que
**devolvía `false` para todos los contratos**: la comprobación de integridad
no verificaba nada y fallaba en silencio, que es peor que no tenerla.

Corregido con BLAKE3-256 sobre el preimagen canónico, más test de conformidad
que exige que C++ produzca el mismo `contract_hash` que Rust.

### Claves derivadas de un secreto público (Rust)

El motor usaba `salt = [0u8; 32]`. Todas las claves derivadas de cualquier
secreto eran idénticas entre instalaciones. Corregido: `kd_secret` se recibe
al construir el engine y se 要求 caller que lo genere con entropía real.

## Conformidad entre lenguajes

`tests/vectors/crypto.json` es la fuente de verdad. Lo genera:

```bash
cargo run --example conformance_vectors > tests/vectors/crypto.json
```

Contiene vectores para BLAKE3, Ed25519, HKDF, derivación de sesión, nonces,
AEAD y anti-replay. Los tests de conformidad de los tres lenguajes los
consumen.

El punto importante: **ningún binding delega en la implementación de
referencia.** BLAKE3 y el anti-replay están escritos a mano en C++ y Kotlin;
Ed25519 en C++ usa OpenSSL y en Kotlin el `SunEC` del JDK. La conformidad se
alcanza por bytes idénticos, no por compartir código.

Esto significa que un cambio en la referencia **no** propaga el error a los
bindings: cada uno puede divergir de forma independiente, y por eso los tests
de conformidad tienen que ejecutarse siempre.

## Notas de implementación de BLAKE3

Si escribes un binding nuevo, esto es lo que costó tiempo:

- La salida raíz es el **chaining value del nodo raíz**: las primeras 8
  palabras plegadas, con el bloque de entrada del nodo raíz, no CV‖IV.
- El modo keyed exige el flag `KEYED_HASH (0x10)` en **todas** las
  compresiones. Sin él el digest es silenciosamente incorrecto.
- `memcpy(cv, key, sizeof(key))` con `key` como array decae a puntero y copia
  4 u 8 bytes, no 32. Este bug hizo fallar todos los vectores a la vez.
- Las implementaciones actuales de C++ y Kotlin soportan hasta 1024 bytes por
  llamada y lanzan excepción más allá. Es explícito, nunca un digest
  incorrecto; ver [Hoja de ruta](roadmap.md).

## Tests

```bash
cargo test --all-features        # 53: 8 conformidad + 11 fuzzing
./run_all_tests.sh               # los 9 gates, los 3 lenguajes
```

El fuzzing de parsers usa `proptest!` y tiene semillas de regresión
persistidas en `tests/fuzz_parsers.proptest-regressions`, que incluyen los dos
casos reducidos del fallo de integridad.
