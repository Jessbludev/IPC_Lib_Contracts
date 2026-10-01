package com.ipc.contract

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.MessageDigest

/**
 * Conformidad cross-language de los bindings Kotlin.
 *
 * Los valores esperados son los mismos que verifica Rust
 * (`tests/conformance.rs`) y C++ (`cpp_bindings/tests/conformance_test.cpp`),
 * generados desde `tests/vectors/crypto.json`. Si Kotlin diverge en un byte,
 * la identidad del contrato o la derivación de claves no son interoperables.
 */
public object KotlinConformanceTest {

    private var failures = 0
    private var checks = 0

    private fun check(label: String, got: String, want: String) {
        checks++
        if (got != want) {
            println("FAIL $label")
            println("  got  $got")
            println("  want $want")
            failures++
        } else {
            println("ok   $label")
        }
    }

    private fun hex(b: ByteArray): String =
        b.joinToString("") { String.format("%02x", it) }

    private fun fromHex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) or
            Character.digit(s[it * 2 + 1], 16)).toByte() }

    @JvmStatic
    public fun main(args: Array<String>) {
        println("=== BLAKE3 (P0.1) ===")
        check(
            "blake3(empty)", hex(SecurityUtils.blake3Hash(ByteArray(0))),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        )
        check(
            "blake3(abc)", hex(SecurityUtils.blake3Hash("abc".toByteArray())),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        )
        check(
            "blake3(256 zeros)", hex(SecurityUtils.blake3Hash(ByteArray(256))),
            "bdc73c75432532814ec2d008761b965a6d8e4193f4e2a3cf4ff2d9701c6c607c"
        )
        check(
            "blake3(seq 1..64)", hex(SecurityUtils.blake3Hash(ByteArray(64) { (it + 1).toByte() })),
            "dfea3ddc725b9faf208d92c178a6d17a7fcbe80f73358c5bd1a86b82d47d4da3"
        )
        check(
            "blake3(1024 zeros)", hex(SecurityUtils.blake3Hash(ByteArray(1024))),
            "d6fd9de5bccf223f523b316c9cd1cf9a9d87ea42473d68e011dad13f09bf8917"
        )
        check(
            "blake3(utf8)", hex(SecurityUtils.blake3Hash("contrato-espanol-nihon".toByteArray())),
            "1c0fc87ced022b342db5f9b23a7124a3e5c4130f91c5a42890876118282492d3"
        )

        println()
        println("=== Key derivation (P0.4) ===")
        val secret = ByteArray(32) { it.toByte() }
        val contractHash = ByteArray(32) { (0x20 + it).toByte() }
        val kd = KeyDerivation(secret)
        val sessionKey = kd.deriveSessionKey(contractHash, 42L)
        check("session_key", hex(sessionKey),
            "91e23d6da9bf9def48499d71da7619bad750f206f79ec636ddc05ef884c816ea")
        check("nonce_key", hex(kd.deriveNonceKey(contractHash, 42L)),
            "a082eb8e3a4559bd32d6bc9ec8169345d98fe2c2b3bf8ea0b142ebc74712e140")
        check("encryption_key", hex(kd.deriveEncryptionKey(sessionKey)),
            "60facea5b3b9b00b29e9c4edfe0b51da5e218b25c98ed34f22cd6ea964071b74")
        check("auth_key", hex(kd.deriveAuthKey(sessionKey)),
            "6cdca2bfc664f4e79452b96740d9d094bf13018f25c5ea39779f78257412ee88")

        println()
        println("=== Nonce derivation (P0.4) ===")
        val nonceKey = fromHex("a082eb8e3a4559bd32d6bc9ec8169345d98fe2c2b3bf8ea0b142ebc74712e140")
        check("tx_s42_q7", hex(SecurityUtils.deriveNonce(nonceKey, 42L, 7L, Direction.TX)),
            "1ca97636f101c7e24a90325e")
        check("rx_s42_q7", hex(SecurityUtils.deriveNonce(nonceKey, 42L, 7L, Direction.RX)),
            "cdb82c4286478d9c89b440e5")
        check("tx_s42_q8", hex(SecurityUtils.deriveNonce(nonceKey, 42L, 8L, Direction.TX)),
            "76ab3058c1513cf392cca482")
        check("tx_s43_q7", hex(SecurityUtils.deriveNonce(nonceKey, 43L, 7L, Direction.TX)),
            "49edb554ae818f0b142709c3")
        check("tx_s42_q0", hex(SecurityUtils.deriveNonce(nonceKey, 42L, 0L, Direction.TX)),
            "2319d26ed1a627734eeba2e8")

        println()
        println("=== Ed25519 (P0.2) ===")
        val sk = fromHex("030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc")
        val msg = fromHex("6970632d636f6e74726163742d636263312d63616e6f6e6963616c2d7061796c6f6164")
        val expectedSig =
            "ba79b398c34b9a8887755f8646fc3e28c2eba4c9abec33fc820cdd921b440b6a6083ef027963269ae3c94f33515a32f28086d9cefe817599892896d7acf16b0f"
        val expectedPub = "755c4cb9256ca7cdc4acfdc6cfeeda849017e5b9f9514e99191bd67e0b0d4276"

        val sig = SecurityUtils.sign(msg, sk)
        check("ed25519 signature", hex(sig), expectedSig)
        check("ed25519 signature length", sig.size.toString(), "64")

        // La firma del vector debe verificar contra la clave pública que
        // corresponde a esa misma semilla. Se comprueba de forma
        // independiente: el JDK firma con la semilla y extraemos su clave
        // pública, que debe ser la del vector.
        val kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val rawPub = SecurityUtils.extractRawPublicKey(kp.public)
        val rawSeed = SecurityUtils.extractRawPrivateSeed(kp.private)

        // Firma propia contra firma del JDK para la misma clave.
        val jdkSig = Signature.getInstance("Ed25519").run {
            initSign(kp.private)
            update(msg)
            sign()
        }
        val ourSig = SecurityUtils.sign(msg, rawSeed)
        check("ed25519 matches JDK for same key", hex(ourSig), hex(jdkSig))

        checks++
        if (!SecurityUtils.verify(msg, ourSig, rawPub)) {
            println("FAIL ed25519 verify")
            failures++
        } else {
            println("ok   ed25519 verify")
        }

        // Firma manipulada debe rechazarse
        val tampered = sig.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        checks++
        if (SecurityUtils.verify(msg, tampered, fromHex(expectedPub))) {
            println("FAIL ed25519 rejects tampered signature")
            failures++
        } else {
            println("ok   ed25519 rejects tampered signature")
        }

        // Mensaje manipulado debe rechazarse
        val badMsg = msg.copyOf().also { it[0] = (it[0].toInt() xor 0xFF).toByte() }
        checks++
        if (SecurityUtils.verify(badMsg, sig, fromHex(expectedPub))) {
            println("FAIL ed25519 rejects tampered message")
            failures++
        } else {
            println("ok   ed25519 rejects tampered message")
        }

        println()
        println("=== Anti-replay (P0.3) ===")
        val ar = AntiReplay(64)
        val transcript = listOf(
            10L to ReplayResult.ACCEPTED,
            11L to ReplayResult.ACCEPTED,
            12L to ReplayResult.ACCEPTED,
            11L to ReplayResult.REPLAY,
            13L to ReplayResult.ACCEPTED,
            40L to ReplayResult.ACCEPTED,
            1L to ReplayResult.ACCEPTED,
            12L to ReplayResult.REPLAY,
            200L to ReplayResult.ACCEPTED,
            1L to ReplayResult.OUT_OF_WINDOW
        )
        for ((seq, expected) in transcript) {
            val got = ar.check(7L, Direction.RX, seq)
            check("replay seq=$seq", got.name, expected.name)
        }
        val snap = ar.snapshot(7L, Direction.RX)!!
        check("replay final highest", snap.first.toString(), "200")
        check("replay final bitmap", snap.third.joinToString(",") { String.format("%016x", it) },
            "0000000000000001")

        // TX es independiente de RX
        checks++
        if (ar.check(7L, Direction.TX, 999L) != ReplayResult.ACCEPTED) {
            println("FAIL tx window is independent")
            failures++
        } else {
            println("ok   tx window is independent")
        }

        println()
        println("=== Security policy encoding ===")
        val policy = SecurityPolicy()
        val roundTrip = SecurityPolicy.fromByteArray(policy.toByteArray())
        check("policy roundtrip level", roundTrip.level.name, policy.level.name)
        check("policy roundtrip window", roundTrip.replayWindowSize.toString(),
            policy.replayWindowSize.toString())
        check("policy roundtrip signature", roundTrip.signaturePolicy.name,
            policy.signaturePolicy.name)

        println()
        println("=== constant-time compare ===")
        val a = ByteArray(32) { it.toByte() }
        val b = a.copyOf()
        checks++
        if (!SecurityUtils.constantTimeEquals(a, b)) {
            println("FAIL constantTimeEquals equal")
            failures++
        } else {
            println("ok   constantTimeEquals equal")
        }
        b[31] = (b[31].toInt() xor 1).toByte()
        checks++
        if (SecurityUtils.constantTimeEquals(a, b)) {
            println("FAIL constantTimeEquals different")
            failures++
        } else {
            println("ok   constantTimeEquals different")
        }

        // =====================================================================
        // BLAKE3 multi-chunk (PR2)
        //
        // La v2.1 limitaba Kotlin a 1024 bytes por llamada. Estos vectores
        // comprueban que el árbol reproduce exactamente la referencia de Rust
        // para entradas de cualquier tamaño, y que el resultado no depende de
        // la partición.
        // =====================================================================
        println()
        println("=== BLAKE3 multi-chunk ===")

        val key = ByteArray(32) { it.toByte() }

        fun zerosOf(n: Int) = ByteArray(n)

        // Generador xorshift idéntico al de Rust y C++ para que los tres
        // generen los mismos bytes de entrada.
        fun dataOf(n: Int, seed: Long = -0x61C8864680B583EBL): ByteArray {
            val v = ByteArray(n)
            var x = seed
            for (i in 0 until n) {
                x = x xor (x shl 13)
                x = x xor (x ushr 7)
                x = x xor (x shl 17)
                v[i] = (x ushr 24).toByte()
            }
            return v
        }

        // Baseline: no debe cambiar con multi-chunk.
        check("blake3 vacio", hex(Blake3.hash(zerosOf(0))), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        check("blake3 abc", hex(Blake3.hash("abc".toByteArray(Charsets.US_ASCII))),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
        check("blake3 63 ceros", hex(Blake3.hash(zerosOf(63))), "990a6d20859d8f43865abd59d92a07aaef1c25c2257d017db07710152d06c0d5")
        check("blake3 64 ceros", hex(Blake3.hash(zerosOf(64))), "4d006976636a8696d909a630a4081aad4d7c50f81afdee04020bf05086ab6a55")
        check("blake3 65 ceros", hex(Blake3.hash(zerosOf(65))), "a6f791da7707e3a05a7742248eefe43f9ad4626fc21b63675367c3d1d69ec91c")
        check("blake3 1023 ceros", hex(Blake3.hash(zerosOf(1023))), "5b10416d32f16b046bf4f2a8867960a16e99280dfd694e9a809a6bf849531697")
        check("blake3 1024 ceros", hex(Blake3.hash(zerosOf(1024))), "d6fd9de5bccf223f523b316c9cd1cf9a9d87ea42473d68e011dad13f09bf8917")
        check("blake3 1024 aleatorio", hex(Blake3.hash(dataOf(1024))), "2e71b2b3dd40f43c87c5df81fba91f50750e356308a03480bf5bb0ecd7993d16")

        // Keyed dentro del limite.
        check("keyed 0", hex(Blake3.keyedHash(key, zerosOf(0))), "73492b19995d71cdb1e9d74decc09809eb732f1b00bc95c27cb15f9dd4d6478f")
        check("keyed 64", hex(Blake3.keyedHash(key, zerosOf(64))), "253a1c323ffc166d90b6552796fbf6c92fd1ec4a2fab1de53ba58fc17c309c4c")
        check("keyed 1024", hex(Blake3.keyedHash(key, zerosOf(1024))), "e8e16ce483f39f5f4345d278dc1f28d47cad1727919263eaec5743f88de623b3")

        // Multi-chunk: longitudes criticas.
        check("blake3 1025 ceros", hex(Blake3.hash(zerosOf(1025))), "d2beb49d87e59db174cb3ff1440f1899422968df670d060fd7ce759e8cc160e7")
        check("blake3 2047 ceros", hex(Blake3.hash(zerosOf(2047))), "5bea1ede30f4389bdeac72799d266dd054d35a3eb89e154d217bd582a21fd0c2")
        check("blake3 2048 ceros", hex(Blake3.hash(zerosOf(2048))), "be2a8de3dcf46c94ce85cdc8e07ac308f4d8a95490d956c38d780fd610db0813")
        check("blake3 2049 ceros", hex(Blake3.hash(zerosOf(2049))), "b982335435308f3f5f5f51f5d45ecae6194641975e7b0bcaa1facd48ebabb28e")
        check("blake3 3072 ceros", hex(Blake3.hash(zerosOf(3072))), "aae9f164c4ba4a3f9bae88f07bc4df6042b4d7d08e079aa01bba465a7872d1a5")
        check("blake3 4096 ceros", hex(Blake3.hash(zerosOf(4096))), "b6fb73fc46938c981e2b0b4b1ef282adcfc89854d01bfe3972fdc4785b41b2c7")
        check("blake3 4097 ceros", hex(Blake3.hash(zerosOf(4097))), "84e5fa82c1670822633b16214c3c808824025289006d86489d9b05a63d087f0c")
        check("blake3 8192 ceros", hex(Blake3.hash(zerosOf(8192))), "128daa44a4f7badaed2244bb6fe009d5e7803177414e01d7d9df80c190e14906")
        check("blake3 1 MiB ceros", hex(Blake3.hash(zerosOf(1024 * 1024))), "488de202f73bd976de4e7048f4e1f39a776d86d582b7348ff53bf432b987fca8")
        check("blake3 1025 aleatorio", hex(Blake3.hash(dataOf(1025))), "dd65c61678d7bb631db28da97fd7f5aa716c4815d2e5cd11ea82953ceef35457")
        check("blake3 2048 aleatorio", hex(Blake3.hash(dataOf(2048))), "cdb7045064cdc5b8f3f803b7f4e7a1e62ac79cde91419b559e29b0805c3c5c9d")

        // Keyed multi-chunk.
        check("keyed 1025", hex(Blake3.keyedHash(key, zerosOf(1025))), "aebd057842fabbdc4e2ddaba7206c6eb717335eebb8891067ec0dd57adc5e183")
        check("keyed 2048", hex(Blake3.keyedHash(key, zerosOf(2048))), "c3263f17f24d825859f6a2c6b6386f7b90fae91ccfc407a661848aa8e2669657")
        check("keyed 4096", hex(Blake3.keyedHash(key, zerosOf(4096))), "68277efeb7544248fc8434b543846721e02fca36952d6f91a31022d06469b6aa")
        check("keyed 1 MiB", hex(Blake3.keyedHash(key, zerosOf(1024 * 1024))), "96f15c0fffe8d85d2b98b3010e5be74dfcefd40cd11c3a0c22b340fb99b09fbb")
        check("keyed 1025 aleatorio", hex(Blake3.keyedHash(key, dataOf(1025))), "9b2b190782294f69b5142763abdaecbb0dcc876f41971ea3c6b2f4febeaece8b")

        // Particiones de streaming: el resultado no depende del troceado.
        fun checkPartition(label: String, d: ByteArray, parts: IntArray) {
            val h = Blake3.Blake3Hasher()
            var off = 0
            for (p in parts) {
                if (off >= d.size) break
                val take = minOf(p, d.size - off)
                h.update(d, off, take)
                off += take
            }
            if (off < d.size) h.update(d, off, d.size - off)
            check(label, hex(h.finalize()), hex(Blake3.hash(d)))
        }

        checkPartition("streaming 1025 en 1+1024", dataOf(1025), intArrayOf(1, 1024))
        checkPartition("streaming 1025 en 63+962", dataOf(1025), intArrayOf(63, 962))
        checkPartition("streaming 1025 en 1024+1", dataOf(1025), intArrayOf(1024, 1))
        checkPartition("streaming 2048 en 1024+1024", dataOf(2048), intArrayOf(1024, 1024))
        checkPartition("streaming 2048 en 1+2047", dataOf(2048), intArrayOf(1, 2047))
        checkPartition("streaming 1 MiB en 7 bytes", dataOf(1024 * 1024), IntArray(1024 * 1024 / 7 + 1) { 7 })

        // Continuidad: un digest intermedio no consume el hasher.
        run {
            val d = dataOf(3000)
            val h = Blake3.Blake3Hasher()
            h.update(d, 0, 1000)
            h.finalize()
            h.update(d, 1000, 1000)
            h.update(d, 2000, 1000)
            check("digest intermedio no consume", hex(h.finalize()), hex(Blake3.hash(d)))
        }
        run {
            val h = Blake3.Blake3Hasher()
            h.update(dataOf(5000))
            h.reset()
            h.update(dataOf(10))
            check("reset() vuelve al estado inicial", hex(h.finalize()), hex(Blake3.hash(dataOf(10))))
        }

        println()
        println()
        println(if (failures == 0) "ALL PASS" else "FAILURES")
        println("$checks checks, $failures failures")
        if (failures != 0) throw AssertionError("$failures conformance failures")
    }
}
