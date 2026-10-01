# DSL de Definición de Contratos

## Gramática del Lenguaje

```
contract           := "contract" IDENTIFIER "{" declarations "}"
declarations       := declaration*
declaration       := version_decl
                   | namespace_decl
                   | role_decl
                   | security_decl
                   | type_decl
                   | operation_decl

version_decl       := "version" VERSION
namespace_decl     := "namespace" STRING
role_decl         := "role" ROLE
security_decl      := "security" "{" security_options "}"
security_options   := ("authentication" | "encryption" | "replay_protection") ("required" | "optional")*

type_decl         := "type" IDENTIFIER "=" type_def
type_def          := primitive_type
                   | array_type
                   | object_type
                   | enum_type

primitive_type     := "u8" | "u16" | "u32" | "u64"
                   | "i8" | "i16" | "i32" | "i64"
                   | "f32" | "f64"
                   | "bool" | "string" | "bytes"

array_type        := "array" "<" type_def "," NATURAL ">"
object_type       := "{" field_decl* "}"
field_decl        := IDENTIFIER ":" type_def ("?" | constraint*)

enum_type         := "enum" "{" variant_decl* "}"
variant_decl      := IDENTIFIER ("(" type_def ")")?

operation_decl     := "operation" IDENTIFIER "{" operation_body "}"
operation_body    := ("input" ":" type_def)?
                   | ("output" ":" type_def)?
                   | ("timeout" ":" NATURAL "ms")?
                   | ("idempotent" ":" BOOLEAN)?
                   | ("role" ":" ROLE)?
```

## Ejemplos

### Contrato Básico

```dsl
contract "image_processor" {

    version 1.0.0
    namespace "com.example"
    role mutual

    security {
        authentication required
        encryption required
        replay_protection required
    }

    // Tipos
    type Image {
        data: bytes
        width: u32
        height: u32
        format: string
    }

    // Operaciones
    operation resize {
        input {
            image: Image
            target_width: u32
            target_height: u32
            algorithm: string
        }
        output Image
        timeout 15s
        idempotent true
    }

    operation apply_filter {
        input {
            image: Image
            filter: string
            intensity: f32
        }
        output Image
        timeout 10s
        idempotent true
    }
}
```

### Contrato con Tipos Compuestos

```dsl
contract "data_pipeline" {

    version 2.1.0
    namespace "com.example.data"
    role mux

    security {
        authentication required
        encryption optional
        replay_protection required
    }

    // Arrays
    type DataPoint {
        timestamp: u64
        value: f64
    }

    type TimeSeries = array<DataPoint, 10000>

    // Enum
    type Status {
        Pending
        Processing
        Completed
        Failed(ErrorCode)
    }

    type ErrorCode = u16

    // Operaciones
    operation ingest {
        input TimeSeries
        output Status
        timeout 60s
    }

    operation aggregate {
        input {
            series: TimeSeries
            window_ms: u64
            function: string  // "sum", "avg", "min", "max"
        }
        output DataPoint
        timeout 30s
        idempotent true
    }
}
```

### Contrato de Streaming

```dsl
contract "video_processor" {

    version 1.0.0
    namespace "com.example.video"
    role stream

    security {
        authentication required
        encryption required
        replay_protection required
    }

    type Frame {
        data: bytes
        width: u32
        height: u32
        format: string
        pts: u64  // presentation timestamp
    }

    operation start_stream {
        input {
            source: string
            format: string
            options: map<string, string>
        }
        output {
            stream_id: u64
            status: string
        }
        timeout 5s
    }

    operation process_frame {
        input Frame
        output Frame
        timeout 1s
    }

    operation end_stream {
        input {
            stream_id: u64
        }
        output {
            status: string
            frames_processed: u64
        }
        timeout 10s
    }
}
```

## Roles Disponibles

| Rol | Descripción |
|-----|-------------|
| `child` | Proceso subordinado/controlado por otro |
| `mutual` | Ambos extremos pueden iniciar operaciones |
| `peer` | Comunicación simétrica entre pares |
| `mux` | Múltiples canales lógicos |
| `stream` | Flujo persistente (streaming) |
| `oneway` | Comunicación unidireccional |

## Tipos Primitivos

| Tipo | Descripción | Tamaño |
|------|-------------|---------|
| `u8`, `u16`, `u32`, `u64` | Enteros sin signo | 1-8 bytes |
| `i8`, `i16`, `i32`, `i64` | Enteros con signo | 1-8 bytes |
| `f32`, `f64` | Flotantes | 4-8 bytes |
| `bool` | Booleano | 1 byte |
| `string` | String UTF-8 | Variable |
| `bytes` | Datos binarios | Variable |

## Restricciones de Campo

```dsl
type ConstrainedExample {
    id: u32 (min: 1, max: 1000000)
    name: string (min_length: 1, max_length: 255)
    email: string (pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")
    optional_field: string?
}
```

## Compilación

```bash
# Compilar contrato DSL a binario
contractc compile input.contract -o output/

# Generar bindings Rust
contractc generate output/contract.cbc --target rust -o generated/rust/

# Generar bindings Kotlin
contractc generate output/contract.cbc --target kotlin -o generated/kotlin/

# Generar bindings TypeScript
contractc generate output/contract.cbc --target typescript -o generated/ts/
```

## Salida del Compilador

```
$ contractc compile image_processor.contract -o output/
[INFO] Compilando contrato: image_processor.contract
[INFO] Nombre: image_processor
[INFO] Versión: 1.0.0
[INFO] Tipos: 1
[INFO] Operaciones: 2
[INFO] Contrato compilado: output/image_processor.cbc
[INFO] Contract hash: a1b2c3d4e5f6...
```
