# Especificación del Protocolo Wire v2

## Frame Layout

```
Offset  Size    Campo                Descripción
─────────────────────────────────────────────────────────────────
0       4       Magic                "CBC1"
4       1       Version              0x02
5       1       Flags               Compressed(1) | Encrypted(2) | Priority(4) | NoAck(8)
6       1       Packet Type          HELLO, REQUEST, RESPONSE, etc.
7       1       Role                 CHILD, MUTUAL, PEER, MUX, STREAM

8       8       Session ID          u64 - Identificador de sesión
16      8       Sequence            u64 - Para ordenamiento y anti-replay
24      4       Channel ID           u32 - Para multiplexación

28      4       Operation ID         u16 + 2 bytes reserved
32      4       Payload Length      u32
36      4       Schema ID           u16 type + 2 reserved
40      12      Contract Hash Prefix Primeros 12 bytes de BLAKE3-256

52      12      Nonce               Para AEAD (ChaCha20/AES-GCM)

─────────────────────────────────────────────────────────────────
64      N       Payload             Datos cifrados o plaintext
─────────────────────────────────────────────────────────────────
```

## Packet Types

### Control

| Tipo | Valor | Descripción |
|------|-------|-------------|
| `Close` | 0x00 | Cierre de sesión |
| `Hello` | 0x01 | Inicio de handshake |
| `HelloAck` | 0x02 | Confirmación de handshake |
| `HelloNack` | 0x03 | Rechazo de handshake |

### Authentication

| Tipo | Valor | Descripción |
|------|-------|-------------|
| `Auth` | 0x10 | Inicio de autenticación |
| `AuthOk` | 0x11 | Autenticación exitosa |
| `AuthNok` | 0x12 | Autenticación fallida |

### Operations

| Tipo | Valor | Descripción |
|------|-------|-------------|
| `Request` | 0x20 | Solicitud de operación |
| `Response` | 0x21 | Respuesta exitosa |
| `ResponseError` | 0x22 | Respuesta de error |

### Streaming

| Tipo | Valor | Descripción |
|------|-------|-------------|
| `StreamStart` | 0x30 | Inicio de stream |
| `StreamData` | 0x31 | Datos de stream |
| `StreamEnd` | 0x32 | Fin de stream |
| `StreamPause` | 0x33 | Pausar stream |
| `StreamResume` | 0x34 | Reanudar stream |

### System

| Tipo | Valor | Descripción |
|------|-------|-------------|
| `Heartbeat` | 0xF0 | Keepalive |
| `HeartbeatAck` | 0xF1 | Ack de heartbeat |
| `Ping` | 0xFE | Ping |
| `Pong` | 0xFF | Pong |

## Handshake Protocol

```
CLIENT                         SERVER
  │                              │
  │──── HELLO ──────────────────>│
  │     protocol_version: 0x02   │
  │     contract_hash_prefix     │
  │     client_nonce             │
  │                              │
  │<──── HELLO_ACK ──────────────│
  │     session_id               │
  │     server_nonce             │
  │     session_key (encrypted)  │
  │                              │
  │──── AUTH ────────────────────>│
  │     auth_data (encrypted)    │
  │                              │
  │<──── AUTH_OK ───────────────│
  │     session_ready            │
  │                              │
  │──── REQUEST ────────────────>│
```

## AAD (Additional Authenticated Data)

El AAD autentica la identidad del paquete:

```
AAD = protocol_version (1)
    + flags (1)
    + operation_id (2)
    + session_id (8)
    + sequence (8)
    + channel_id (4)
```

## Encriptación

```rust
// Cifrar payload
ciphertext = ChaCha20Poly1305::new(&encryption_key)
    .encrypt(
        Nonce::from_slice(&frame.nonce),
        Payload {
            msg: &payload,
            aad: &frame.get_aad(),
        }
    )
```

## Anti-Replay

- Cada paquete incluye un nonce único de 12 bytes
- El receptor mantiene ventana de nonces vistos
- Paquetes con nonces repetidos o muy antiguos son rechazados
