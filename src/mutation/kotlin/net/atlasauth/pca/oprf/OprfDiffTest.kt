package net.atlasauth.pca.oprf

import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

@Suppress("UNCHECKED_CAST")
class OprfDiffTest {
    private val M = "ref-oprf"

    /** A byte argument: {"$bytes"} decodes; anything else (null, a string, a number) is what the reference refuses with a TypeError. */
    private fun by(o: Any?): ByteArray {
        if (o is Map<*, *> && o["\$bytes"] is String) return Keys.unb64u(o["\$bytes"] as String)
        throw IllegalArgumentException("expected a byte array")
    }

    /** An optional trailing byte argument: absent is null; present must be bytes. */
    private fun opt(a: List<Any?>, i: Int): ByteArray? = if (i < a.size) by(a[i]) else null

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun str(o: Any?): String {
        if (o !is String) throw IllegalArgumentException("expected a string")
        return o
    }

    private fun m(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = linkedMapOf(*kv)

    private fun seed(label: String): ByteArray = OracleCases.seed(label)

    @Test fun genCorpusIsPresent() = net.atlasauth.pca.verifier.BaseOracle.requireGen(M)

    @Test fun deriveKeyPair() = OracleCases.each(M, "deriveKeyPair") { a ->
        val k = Oprf.deriveKeyPair(by(a[0]), by(a[1]), str(a[2]))
        m("secretKey" to k.secretKey, "publicKey" to k.publicKey)
    }

    @Test fun publicKeyFor() = OracleCases.each(M, "publicKeyFor") { a -> Oprf.publicKeyFor(by(a[0])) }
    @Test fun deserializeScalar() = OracleCases.each(M, "deserializeScalar") { a -> Oprf.deserializeScalar(by(a[0])).toString() }
    @Test fun serializeScalar() = OracleCases.each(M, "serializeScalar") { a -> Oprf.serializeScalar(BigInteger(str(a[0]))) }
    @Test fun hashToGroup() = OracleCases.each(M, "hashToGroup") { a -> Oprf.serializeElement(Oprf.hashToGroup(by(a[0]), str(a[1]))) }
    @Test fun deserializeElement() = OracleCases.each(M, "deserializeElement") { a -> Oprf.serializeElement(Oprf.deserializeElement(by(a[0]))) }

    @Test fun blind() = OracleCases.each(M, "blind") { a ->
        val b = Oprf.blind(by(a[0]), str(a[1]), opt(a, 2))
        m("blind" to b.blind, "blindedElement" to b.blindedElement)
    }

    private fun ev(r: Oprf.EvaluateResult): Map<String, Any?> {
        val out = m("evaluatedElement" to r.evaluatedElement)
        if (r.proof != null) out["proof"] = r.proof
        return out
    }

    /** The reference reads pk / proof-nonce as "absent" only when the argument is missing; a present null is a TypeError. */
    @Test fun blindEvaluate() = OracleCases.each(M, "blindEvaluate") { a -> ev(Oprf.blindEvaluate(by(a[0]), by(a[1]), str(a[2]), opt(a, 3), opt(a, 4))) }

    @Test fun evaluate() = OracleCases.each(M, "evaluate") { a -> Oprf.evaluate(by(a[0]), by(a[1]), str(a[2])) }

    @Test fun finalizeOprf() = OracleCases.each(M, "finalize") { a ->
        val o = if (a.size > 4) map(a[4]) else null
        var proof: ByteArray? = null
        var pk: ByteArray? = null
        var blinded: ByteArray? = null
        if (o != null) {
            proof = if (o.containsKey("proof")) by(o["proof"]) else null
            pk = if (o.containsKey("publicKey")) by(o["publicKey"]) else null
            blinded = if (o.containsKey("blindedElement")) by(o["blindedElement"]) else null
        }
        Oprf.finalizeOprf(by(a[0]), by(a[1]), by(a[2]), str(a[3]), proof, pk, blinded)
    }

    @Test fun blindPoprf() = OracleCases.each(M, "blindPoprf") { a ->
        val b = Oprf.blindPoprf(by(a[0]), by(a[1]), by(a[2]), opt(a, 3))
        m("blind" to b.blind, "blindedElement" to b.blindedElement, "tweakedKey" to b.tweakedKey)
    }

    @Test fun blindEvaluatePoprf() = OracleCases.each(M, "blindEvaluatePoprf") { a -> ev(Oprf.blindEvaluatePoprf(by(a[0]), by(a[1]), by(a[2]), opt(a, 3))) }
    @Test fun evaluatePoprf() = OracleCases.each(M, "evaluatePoprf") { a -> Oprf.evaluatePoprf(by(a[0]), by(a[1]), by(a[2])) }

    @Test fun finalizePoprf() = OracleCases.each(M, "finalizePoprf") { a ->
        val o = map(a[4])
        Oprf.finalizePoprf(by(a[0]), by(a[1]), by(a[2]), by(a[3]), if (o.containsKey("proof")) by(o["proof"]) else null, by(o["blindedElement"]), by(o["tweakedKey"]))
    }

    @Test fun toHex() = OracleCases.each(M, "toHex") { a -> Oprf.toHex(by(a[0])) }
    @Test fun bytesEqual() = OracleCases.each(M, "bytesEqual") { a -> Oprf.bytesEqual(by(a[0]), by(a[1])) }

    // ---- PCA layer ----

    private fun ids(o: Any?): List<String> = (o as List<Any?>).map { str(it) }

    @Test fun buildRevocationSet() = OracleCases.each(M, "buildRevocationSet") { a ->
        val s = OprfPca.buildRevocationSet(by(a[0]), ids(a[1]), str(a[2]))
        val out = m("outputs" to s.outputs.sorted(), "mode" to s.mode)
        // the duplicate-ids cases project only outputs and mode (the oracle's own projection); every other case also pins the public key
        if (s.publicKey != null && ids(a[1]).toSet().size == ids(a[1]).size) out["publicKey"] = s.publicKey
        out
    }

    @Test fun isRevokedPrivate() {
        val wrongKey = Oprf.deriveKeyPair(seed("ref-oprf/key-poprf"), byteArrayOf('k'.code.toByte()), "poprf").secretKey
        OracleCases.each(M, "isRevokedPrivate") { a ->
            if (a[0] !is String) throw IllegalArgumentException("capability id must be a string")
            val op = map(a[1])
            val sk = by(op["sk"])
            val mode = str(op["mode"])
            val lie = op["lie"]
            val set = OprfPca.buildRevocationSet(sk, ids(op["revoked"]), mode)
            val real = OprfPca.makeRevocationEvaluator(if (lie == "wrong-key") wrongKey else sk, mode)
            val e = if (lie == "no-proof") OprfPca.BlindEvaluator { blinded -> Oprf.EvaluateResult(real.evaluate(blinded).evaluatedElement, null) } else real
            OprfPca.isRevokedPrivate(a[0] as String, e, set)
        }
    }

    @Test fun rateToken() = OracleCases.each(M, "rateToken") { a -> OprfPca.rateToken(by(a[0]), str(a[1]), str(a[2])) }
    @Test fun rateTokenHex() = OracleCases.each(M, "rateTokenHex") { a -> OprfPca.rateTokenHex(by(a[0]), str(a[1]), str(a[2])) }

    @Test fun privateRateToken() = OracleCases.each(M, "privateRateToken") { a ->
        val op = map(a[2])
        val sk = by(op["sk"])
        val pk = if (op.containsKey("pk")) by(op["pk"]) else Oprf.publicKeyFor(sk)
        OprfPca.privateRateToken(str(a[0]), str(a[1]), OprfPca.makeRateEvaluator(sk), pk)
    }

    @Test fun rateCounter() = OracleCases.each(M, "rateCounter") { a ->
        val limit = Js.num(a[0])
        if (limit == null || limit != Math.floor(limit) || limit < 1) throw IllegalArgumentException("limit must be a positive integer")
        val c = OprfPca.RateWindowCounter(limit.toInt())
        val out = ArrayList<Any?>()
        for (step in a[1] as List<Any?>) {
            val s = step as List<Any?>
            when (s[0] as String) {
                "hit" -> { val h = c.hit(by(s[1])); out.add(m("count" to h.first, "allowed" to h.second)) }
                "count" -> out.add(c.count(by(s[1])))
                else -> { c.reset(); out.add(null) }
            }
        }
        out
    }

    // ---- RFC 9497 Appendix A.1 (ristretto255-SHA512) known-answer tests ----

    private fun hx(h: String): ByteArray = ByteArray(h.length / 2) { i -> h.substring(2 * i, 2 * i + 2).toInt(16).toByte() }

    private fun split(s: String): List<String> = s.split(",")

    private fun fixture(): Map<String, Any?> = Json.parse(String(Files.readAllBytes(Path.of("test-data/rfc9497-ristretto255-sha512.json")), Charsets.UTF_8)) as Map<String, Any?>

    @Test fun rfc9497DeriveKeyPair() {
        val modes = map(fixture()["modes"])
        for (mode in listOf("OPRF", "VOPRF", "POPRF")) {
            val k = map(modes[mode])
            val kp = Oprf.deriveKeyPair(hx(k["Seed"] as String), hx(k["KeyInfo"] as String), mode.lowercase())
            assertEquals(mode, k["skSm"], Oprf.toHex(kp.secretKey))
            if (k["pkSm"] != null) assertEquals(mode, k["pkSm"], Oprf.toHex(kp.publicKey))
        }
        val o = map(modes["OPRF"])
        assertNotEquals(o["skSm"], Oprf.toHex(Oprf.deriveKeyPair(hx(o["Seed"] as String), hx(o["KeyInfo"] as String), "voprf").secretKey))
    }

    @Test fun rfc9497Vectors() {
        val fx = fixture()
        val modes = map(fx["modes"])
        var n = 0
        for (vo in fx["vectors"] as List<Any?>) {
            val v = map(vo)
            val mode = (v["mode"] as String).lowercase()
            val key = map(modes[v["mode"]])
            val sk = hx(key["skSm"] as String)
            val pk = if (key["pkSm"] == null) null else hx(key["pkSm"] as String)
            val info = if (v["Info"] == null) null else hx(v["Info"] as String)
            val inputs = split(v["Input"] as String)
            val blinds = split(v["Blind"] as String)
            val blinded = split(v["BlindedElement"] as String)
            val evald = split(v["EvaluationElement"] as String)
            val outs = split(v["Output"] as String)
            val single = Json.asLong(v["batch"]) == 1L
            for (i in inputs.indices) {
                n++
                val inp = hx(inputs[i])
                val bl = hx(blinds[i])
                val be = hx(blinded[i])
                val ee = hx(evald[i])
                if (mode == "poprf") {
                    val b = Oprf.blindPoprf(inp, info, pk, bl)
                    assertEquals(blinded[i], Oprf.toHex(b.blindedElement))
                    assertEquals(evald[i], Oprf.toHex(Oprf.blindEvaluatePoprf(sk, be, info, null).evaluatedElement))
                    assertEquals(outs[i], Oprf.toHex(Oprf.evaluatePoprf(sk, inp, info)))
                    if (single) {
                        val proof = hx(v["Proof"] as String)
                        assertEquals(v["Proof"], Oprf.toHex(Oprf.blindEvaluatePoprf(sk, be, info, hx(v["ProofRandomScalar"] as String)).proof!!))
                        assertEquals(outs[i], Oprf.toHex(Oprf.finalizePoprf(inp, b.blind, ee, info, proof, be, b.tweakedKey)))
                    }
                } else {
                    val b = Oprf.blind(inp, mode, bl)
                    assertEquals(blinded[i], Oprf.toHex(b.blindedElement))
                    assertEquals(evald[i], Oprf.toHex(Oprf.blindEvaluate(sk, be, mode, pk, null).evaluatedElement))
                    assertEquals(outs[i], Oprf.toHex(Oprf.evaluate(sk, inp, mode)))
                    if (mode == "oprf") assertEquals(outs[i], Oprf.toHex(Oprf.finalizeOprf(inp, b.blind, ee, "oprf", null, null, null)))
                    else if (single) {
                        val proof = hx(v["Proof"] as String)
                        assertEquals(v["Proof"], Oprf.toHex(Oprf.blindEvaluate(sk, be, "voprf", pk, hx(v["ProofRandomScalar"] as String)).proof!!))
                        assertEquals(outs[i], Oprf.toHex(Oprf.finalizeOprf(inp, b.blind, ee, "voprf", proof, pk, be)))
                    }
                }
            }
        }
        assertTrue(n >= 10)
    }

    @Test fun rfc9497NegativeProofs() {
        val fx = fixture()
        var v1: Map<String, Any?>? = null
        for (vo in fx["vectors"] as List<Any?>) {
            val v = map(vo)
            if ("VOPRF" == v["mode"] && Json.asLong(v["n"]) == 1L) v1 = v
        }
        val vv = v1!!
        val pk = hx(map(map(fx["modes"])["VOPRF"])["pkSm"] as String)
        val proof = hx(vv["Proof"] as String)
        val input = hx(vv["Input"] as String)
        val blind = hx(vv["Blind"] as String)
        val ee = hx(vv["EvaluationElement"] as String)
        val be = hx(vv["BlindedElement"] as String)
        assertEquals(vv["Output"], Oprf.toHex(Oprf.finalizeOprf(input, blind, ee, "voprf", proof, pk, be)))
        for (idx in intArrayOf(0, 31, 32, 63)) {
            val bad = proof.clone()
            bad[idx] = (bad[idx].toInt() xor 1).toByte()
            assertThrows(RuntimeException::class.java) { Oprf.finalizeOprf(input, blind, ee, "voprf", bad, pk, be) }
        }
        assertThrows(RuntimeException::class.java) { Oprf.finalizeOprf(input, blind, ee, "voprf", proof.copyOf(63), pk, be) }
        assertThrows(RuntimeException::class.java) { Oprf.finalizeOprf(input, blind, ee, "voprf", null, pk, be) }
    }

    @Test fun privateFlowsAgreeWithTheReference() {
        val sk = Oprf.deriveKeyPair(seed("ref-oprf/plain"), ByteArray(0), "poprf").secretKey
        val pk = Oprf.publicKeyFor(sk)
        val ev = OprfPca.makeRateEvaluator(sk)
        assertArrayEquals(OprfPca.rateToken(sk, "agent", "w1"), OprfPca.privateRateToken("agent", "w1", ev, pk))
        assertFalse(OprfPca.rateToken(sk, "agent", "w1").contentEquals(OprfPca.rateToken(sk, "agent", "w2")))
        val c = OprfPca.RateWindowCounter(2)
        val t = OprfPca.rateToken(sk, "agent", "w1")
        assertEquals(1, c.hit(t).first)
        assertTrue(c.hit(t).second)
        assertFalse(c.hit(t).second)
        assertEquals(3, c.count(t))
        c.reset()
        assertEquals(0, c.count(t))
    }
}
