# Especificación de snapshots

Qué es un snapshot en este proyecto, cuándo se toma, y cómo se verifica.

## Qué es

Un snapshot es un conjunto de vectores dorados que fija la identidad
criptográfica del sistema en un momento dado. Responde a una pregunta
concreta: *¿este contrato produce el mismo hash que en la versión anterior?*

No es un golden file de outputs de tests. Los tests de conformidad usan
vectores explícitos que se pueden regenerar; un snapshot es el artefacto que
compara **dos revisiones del proyecto entre sí**.

## Dónde vive

| Fichero | Contenido |
|---|---|
| `tests/vectors/crypto.json` | Vectores dorados del protocolo |
| `tests/snapshots/` | Snapshots de contrato, por versión |

## Qué cubre

Cada snapshot registra, para un contrato concreto:

- Los bytes exactos del `.cbc` (hex).
- Su `contract_hash`.
- Su firma, si la tiene.
- La toolchain con la que se generó.
- La versión del formato (`format_version`).

## Cuándo se toma

Un snapshot se toma **al cambiar cualquier cosa que altere la identidad**:

- Cambio en el preimagen del hash.
- Cambio en la serialización canónica.
- Cambio en el layout del header CBC1.
- Cambio en la derivación de claves o de nonces.
- Cambio en la primitiva criptográfica usada.

No se toma un snapshot por cambios que no alteren la identidad:(parseo más
estricto, documentación, tests nuevos).

## Cómo se genera

```bash
cargo run --example conformance_vectors > tests/vectors/crypto.json
cargo run --example blake3_multichunk_vectors > /tmp/b3.txt
```

Para un snapshot de contrato:

```bash
# Compilar el contrato de referencia
cargo run --features clap --bin contractc -- \
    -o build compile --sign --sign-key tests/fixtures/test.key \
    contracts/image_processor.contract

# Registrar bytes y hash
cargo run --features clap --bin contractc -- dump build/image_processor.cbc
cargo run --features clap --bin contractc -- hash  build/image_processor.cbc
```

## Cómo se verifica

Un snapshot pasa si el hash actual **coincide exactamente** con el registrado.

Si no coincide, la comprobación responde a dos preguntas, en este orden:

1. ¿El cambio es intencionado? Si sí, es un cambio de identidad y hay que
   actualizar el snapshot, declarar en el changelog que es incompatible.
2. ¿Es un bug? Si el cambio no debería alterar la identidad, un hash distinto
   es un fallo de integridad, no un snapshot que actualizar.

**Esa distinción es el propósito del snapshot.** Sin él, "el hash cambió"
es ambiguo.

## Compatibilidad de 2.1.1 → 2.1.2

| Elemento | 2.1.1 | 2.1.2 | Compatible |
|---|---|---|---|
| Header CBC1 | 256 B | 256 B + `key_id` en 224 | No — cambia la identidad |
| `contract_hash` | BLAKE3-256 | BLAKE3-256 | No, por `key_id` |
| BLAKE3 ≤ 1024 B | correcto | correcto | Sí |
| BLAKE3 > 1024 B | excepción | correcto | Antes fallaba |
| Derive-key | sin cambio | sin cambio | Sí |
| Nonce | sin cambio | sin cambio | Sí |
| Anti-replay | sin cambio | sin cambio | Sí |

`key_id` ocupó la zona que antes era `Reserved` (224-255), así que el tamaño
del header no cambia y ningún offset se desplaza. Pero **sí cambia la
identidad**: los contratos de 2.1.1 tienen `key_id = 0` implícito y los de
2.1.2 pueden tener otro valor, de modo que el `contract_hash` difiere.

Los contratos con `key_id = 0` explícito producen el mismo hash que en 2.1.1.
Eso da una ruta de migración: recompilar con `key_id = 0` mantiene la
identidad.

## Regla de release

Mientras el formato no esté congelado, cada cambio incompatible de
identidad debe:

1. Actualizar el snapshot.
2. Declararse en `RELEASE-MANIFEST.md` como cambio incompatible.
3. Documentar la ruta de migración.

Un cambio de identidad sin snapshot actualizado es un cambio de identidad sin
registro, que es exactamente lo que el resto del sistema de pruebas intenta
evitar.
