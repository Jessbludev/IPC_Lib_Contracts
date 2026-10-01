//! Genera los vectores de BLAKE3 multi-chunk que consumen los bindings C++ y
//! Kotlin.
//!
//! Uso:
//!     cargo run --example blake3_multichunk_vectors > /tmp/b3.txt
//!
//! Es la referencia: los bindings no delegan en el crate `blake3` para calcular
//! sus tests, sólo para obtener los valores esperados. Si un binding calcula
//! algo distinto, el test de conformidad falla.

use std::fmt::Write as _;

/// xorshift64*, idéntico al generador de los tests de C++ y Kotlin para que
/// los tres generen los mismos bytes de entrada.
fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut x = seed;
    for _ in 0..n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x >> 24) as u8);
    }
    v
}

fn hex(d: &[u8]) -> String {
    let mut s = String::new();
    for b in d {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn main() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);

    // Longitudes: 0 y 1 Boundary, limites de bloque y chunk, y绕树的 Cases que
    // no son potencia de dos.
    let lengths = [
        0usize, 1, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025, 2047, 2048, 2049, 3072, 4096,
        4097, 8192, 1024 * 1024,
    ];

    println!("# BLAKE3 multi-chunk vectors");
    println!("# generado por cargo run --example blake3_multichunk_vectors");
    println!("# key = 00 01 02 ... 1f");

    for &n in &lengths {
        let z = vec![0u8; n];
        println!("PLAIN_ZEROS {}", n);
        println!("  {}", hex(blake3::hash(&z).as_bytes()));

        let d = data(n, 0x9E37_79B9_7F4A_7C15);
        println!("PLAIN_DATA {}", n);
        println!("  {}", hex(blake3::hash(&d).as_bytes()));

        println!("KEYED_ZEROS {}", n);
        println!("  {}", hex(blake3::keyed_hash(&key, &z).as_bytes()));

        println!("KEYED_DATA {}", n);
        println!("  {}", hex(blake3::keyed_hash(&key, &d).as_bytes()));
    }
}
