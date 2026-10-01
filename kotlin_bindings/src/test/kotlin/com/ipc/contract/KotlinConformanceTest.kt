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

        println()
        println(if (failures == 0) "ALL PASS" else "FAILURES")
        println("$checks checks, $failures failures")
        if (failures != 0) throw AssertionError("$failures conformance failures")
    }
}
