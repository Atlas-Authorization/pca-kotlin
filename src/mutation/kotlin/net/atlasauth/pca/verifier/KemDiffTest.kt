package net.atlasauth.pca.verifier

import java.security.MessageDigest
import org.bouncycastle.crypto.digests.SHA3Digest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays every case of the reference oracle for the hybrid KEM module (X25519 + ML-KEM-768/1024, X-Wing draft-09, FIPS 203 key checks):
 * 464 cases, every fn dispatched, an unhandled fn fails the test. The randomised entry points replay through the derandomised test hooks
 * with the corpus' pinned stream; a reference throw needs the native to throw (an argument a typed API cannot even receive counts as that
 * refusal). Keygen cases compare sha256 of the expanded secret key, which proves the dk layout.
 */
@Suppress("UNCHECKED_CAST")
class KemDiffTest {
    private val mod = "ref-kem"

    /** An argument no statically typed native can receive (the reference's JavaScript type confusion). */
    private class Unrepresentable(m: String) : RuntimeException(m)

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun dec(v: Any?): Any? = when (v) {
        is List<*> -> v.map { dec(it) }
        is Map<*, *> -> {
            if (v.size == 1 && v["\$bytes"] is String) Keys.unb64u(v["\$bytes"] as String)
            else LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = dec(x) }
        }
        else -> v
    }

    private fun bytes(o: Any?): ByteArray? = if (o == null || o is ByteArray) o as ByteArray? else throw Unrepresentable("not bytes")

    /** Bytes or null: a non-bytes value reads as "not a Uint8Array" in the key checks. */
    private fun bytesOrNull(o: Any?): ByteArray? = o as? ByteArray

    private fun cat(vararg parts: ByteArray): ByteArray = parts.fold(ByteArray(0)) { a, b -> a + b }

    /** The corpus' pinned random stream: one byte string or a list of parts to concatenate. */
    private fun stream(o: Any?): ByteArray = when (o) {
        is ByteArray -> o
        is List<*> -> cat(*o.map { bytes(it)!! }.toTypedArray())
        else -> throw Unrepresentable("not a stream")
    }

    private fun intOf(o: Any?): Int {
        if (o == "768" || o == "1024") return (o as String).toInt()
        val d = IntentJs.num(o)
        if (d == null || d != Math.rint(d) || Math.abs(d) > Int.MAX_VALUE) throw Unrepresentable("not an integer")
        return d.toInt()
    }

    private fun expandedDk(level: Int, d: ByteArray, z: ByteArray): ByteArray {
        val rng = cat(ByteArray(32), d, z)
        val sk = (if (level == 768) Kem.hybridKemKeygenDerand(rng) else Kem.hybridKem1024KeygenDerand(rng)).secretKey
        return sk.copyOfRange(32, sk.size)
    }

    private fun applySet(b: ByteArray, set: Any?) {
        if (set == null) return
        for (p in l(set)) b[intOf(l(p)[0])] = intOf(l(p)[1]).toByte()
    }

    /** {"$hybridSk"}: x || expandedDk(level, d || z), then trim, pad, set. */
    private fun hybridSk(s: Map<String, Any?>): ByteArray {
        val level = intOf(s["level"])
        var sk = cat(bytes(s["x"])!!, expandedDk(level, bytes(s["d"])!!, bytes(s["z"])!!))
        if (s["trim"] != null) sk = sk.copyOf(sk.size - intOf(s["trim"]))
        if (s["pad"] != null) sk = sk.copyOf(sk.size + intOf(s["pad"]))
        applySet(sk, s["set"])
        return sk
    }

    /** {"$mlkemDk"}: the expanded dk of d || z, patched by set, then optionally with H(ek) rewritten to match the patched embedded ek. */
    private fun mlkemDk(s: Map<String, Any?>): ByteArray {
        val level = intOf(s["level"])
        val k = if (level == 768) 3 else 4
        val dk = expandedDk(level, bytes(s["d"])!!, bytes(s["z"])!!)
        applySet(dk, s["set"])
        if (s["rehash"] == true) {
            val h = SHA3Digest(256)
            h.update(dk, 384 * k, 384 * k + 32)
            h.doFinal(dk, 768 * k + 32)
        }
        return dk
    }

    private fun secretOf(o: Any?): ByteArray? = when {
        o is Map<*, *> && o.containsKey("\$hybridSk") -> hybridSk(m(m(o)["\$hybridSk"]))
        o is Map<*, *> && o.containsKey("\$mlkemDk") -> mlkemDk(m(m(o)["\$mlkemDk"]))
        else -> bytes(o)
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun keyOut(kp: Kem.KeyPair): Map<String, Any?> = linkedMapOf(
        "publicKey" to kp.publicKey,
        "secretKeySha256" to hex(MessageDigest.getInstance("SHA-256").digest(kp.secretKey)),
        "secretKeyLen" to kp.secretKey.size,
    )

    private fun encOut(e: Kem.Encapsulation): Map<String, Any?> = linkedMapOf("ciphertext" to e.ciphertext, "sharedSecret" to e.sharedSecret)

    private fun constants(): Map<String, Any?> = linkedMapOf(
        "HYBRID_PUBLIC_KEY_LEN" to Kem.HYBRID_PUBLIC_KEY_LEN,
        "HYBRID_CIPHERTEXT_LEN" to Kem.HYBRID_CIPHERTEXT_LEN,
        "HYBRID_SHARED_SECRET_LEN" to Kem.HYBRID_SHARED_SECRET_LEN,
        "HYBRID_KEM_SUITE" to Kem.HYBRID_KEM_SUITE,
        "XWING_SUITE" to Kem.XWING_SUITE,
        "XWING_SEED_LEN" to Kem.XWING_SEED_LEN,
        "XWING_SECRET_KEY_LEN" to Kem.XWING_SECRET_KEY_LEN,
        "XWING_PUBLIC_KEY_LEN" to Kem.XWING_PUBLIC_KEY_LEN,
        "XWING_CIPHERTEXT_LEN" to Kem.XWING_CIPHERTEXT_LEN,
        "XWING_SHARED_SECRET_LEN" to Kem.XWING_SHARED_SECRET_LEN,
        "XWING_ESEED_LEN" to Kem.XWING_ESEED_LEN,
        "XWING_LABEL" to Kem.xwingLabel(),
        "HYBRID1024_PUBLIC_KEY_LEN" to Kem.HYBRID1024_PUBLIC_KEY_LEN,
        "HYBRID1024_CIPHERTEXT_LEN" to Kem.HYBRID1024_CIPHERTEXT_LEN,
        "HYBRID1024_SHARED_SECRET_LEN" to Kem.HYBRID1024_SHARED_SECRET_LEN,
        "HYBRID1024_KEM_SUITE" to Kem.HYBRID1024_KEM_SUITE,
    )

    private fun str(o: Any?): String = o as? String ?: throw Unrepresentable("not a string")

    private fun call(fn: String, a: List<Any?>): Any? {
        val a0 = a.getOrNull(0)
        val a1 = a.getOrNull(1)
        return when (fn) {
            "constants" -> constants()
            "hybridKemKeygen" -> keyOut(Kem.hybridKemKeygenDerand(stream(a0)))
            "hybridKem1024Keygen" -> keyOut(Kem.hybridKem1024KeygenDerand(stream(a0)))
            "hybridEncapsulate" -> encOut(Kem.hybridEncapsulateDerand(bytes(a0)!!, stream(a1)))
            "hybridEncapsulate1024" -> encOut(Kem.hybridEncapsulate1024Derand(bytes(a0)!!, stream(a1)))
            "hybridDecapsulate" -> Kem.hybridDecapsulate(bytes(a0)!!, secretOf(a1)!!)
            "hybridDecapsulate1024" -> Kem.hybridDecapsulate1024(bytes(a0)!!, secretOf(a1)!!)
            "xwingKeygen" -> keyOut(Kem.xwingKeygen(bytes(a0)!!))
            "xwingEncapsulateDerand", "xwingEncapsulate" -> encOut(Kem.xwingEncapsulateDerand(bytes(a0)!!, stream(a1)))
            "xwingDecapsulate" -> Kem.xwingDecapsulate(bytes(a0)!!, bytes(a1)!!)
            "encodeHybridPublicKey" -> Kem.encodeHybridPublicKey(bytes(a0)!!)
            "encodeHybridCiphertext" -> Kem.encodeHybridCiphertext(bytes(a0)!!)
            "encodeXWingPublicKey" -> Kem.encodeXWingPublicKey(bytes(a0)!!)
            "encodeXWingCiphertext" -> Kem.encodeXWingCiphertext(bytes(a0)!!)
            "decodeHybridPublicKey" -> Kem.decodeHybridPublicKey(str(a0))
            "decodeHybridCiphertext" -> Kem.decodeHybridCiphertext(str(a0))
            "decodeXWingPublicKey" -> Kem.decodeXWingPublicKey(str(a0))
            "decodeXWingCiphertext" -> Kem.decodeXWingCiphertext(str(a0))
            "mlKemEncapsulationKeyCheck" -> Kem.mlKemEncapsulationKeyCheck(intOf(a0), bytesOrNull(a1))
            "mlKemDecapsulationKeyCheck" -> Kem.mlKemDecapsulationKeyCheck(intOf(a0), if (a1 is Map<*, *>) secretOf(a1) else bytesOrNull(a1))
            else -> throw AssertionError("unhandled fn $fn")
        }
    }

    private val handled = setOf(
        "constants", "hybridKemKeygen", "hybridKem1024Keygen", "hybridEncapsulate", "hybridEncapsulate1024", "hybridDecapsulate", "hybridDecapsulate1024",
        "xwingKeygen", "xwingEncapsulateDerand", "xwingEncapsulate", "xwingDecapsulate", "encodeHybridPublicKey", "decodeHybridPublicKey",
        "encodeHybridCiphertext", "decodeHybridCiphertext", "encodeXWingPublicKey", "decodeXWingPublicKey", "encodeXWingCiphertext",
        "decodeXWingCiphertext", "mlKemEncapsulationKeyCheck", "mlKemDecapsulationKeyCheck",
    )

    /** The oracle holds exactly the fns this test dispatches (a new fn in the corpus fails here, never passes unreplayed). */
    @Test fun everyFnIsHandled() {
        assertEquals(handled, BaseOracle.fns("$mod.json.gz"))
        assertEquals(464, handled.sumOf { OracleCases.of(mod, it).size })
    }

    @Test fun replayAllCases() {
        for (fn in handled) OracleCases.each(mod, fn) { a -> call(fn, dec(a) as List<Any?>) }
    }

    /** The no-argument randomised calls are not in the corpus: keygen, encapsulate, decapsulate must agree, and two calls must differ. */
    @Test fun randomisedRoundTrips() {
        val h = Kem.hybridKemKeygen()
        val he = Kem.hybridEncapsulate(h.publicKey)
        assertArrayEquals(he.sharedSecret, Kem.hybridDecapsulate(he.ciphertext, h.secretKey))
        assertFalse(h.publicKey.contentEquals(Kem.hybridKemKeygen().publicKey))
        val h2 = Kem.hybridKem1024Keygen()
        val he2 = Kem.hybridEncapsulate1024(h2.publicKey)
        assertArrayEquals(he2.sharedSecret, Kem.hybridDecapsulate1024(he2.ciphertext, h2.secretKey))
        val x = Kem.xwingKeygen()
        val xe = Kem.xwingEncapsulate(x.publicKey)
        assertArrayEquals(xe.sharedSecret, Kem.xwingDecapsulate(xe.ciphertext, x.secretKey))
        assertFalse(xe.ciphertext.contentEquals(Kem.xwingEncapsulate(x.publicKey).ciphertext))
        assertTrue(Kem.mlKemEncapsulationKeyCheck(768, h.publicKey.copyOfRange(32, h.publicKey.size)))
    }
}
