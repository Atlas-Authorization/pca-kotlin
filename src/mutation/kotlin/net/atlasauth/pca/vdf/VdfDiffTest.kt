package net.atlasauth.pca.vdf

import java.math.BigInteger
import java.security.SecureRandom
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

@Suppress("UNCHECKED_CAST")
class VdfDiffTest {
    private val M = "ref-vdf"

    private fun b(o: Any?): BigInteger {
        if (o !is String) throw IllegalArgumentException("bigint arg")
        return BigInteger(o)
    }

    private fun s(v: BigInteger): String = v.toString()

    /** A JavaScript safe integer >= 0 as a long; anything else is what the reference refuses with a RangeError. */
    private fun lng(o: Any?): Long {
        val d = net.atlasauth.pca.jose.Js.num(o)
        if (d == null || d < 0 || d > 9007199254740991.0 || d != Math.floor(d)) throw IllegalArgumentException("not a safe step count")
        return d.toLong()
    }

    private fun dbl(o: Any?): Double = net.atlasauth.pca.jose.Js.num(o) ?: Double.NaN

    private fun verdict(v: Vdf.VdfVerdict): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = v.ok
        if (!v.ok) m["reason"] = v.reason
        return m
    }

    private fun pf(p: Vdf.VdfProof): Map<String, Any?> = linkedMapOf("y" to s(p.y), "pi" to s(p.pi))

    @Test fun isProbablePrime() = OracleCases.each(M, "isProbablePrime") { a -> Vdf.isProbablePrime(b(a[0])) }
    @Test fun isMillerRabinProbablePrime() = OracleCases.each(M, "isMillerRabinProbablePrime") { a -> Vdf.isMillerRabinProbablePrime(b(a[0])) }
    @Test fun isStrongLucasProbablePrime() = OracleCases.each(M, "isStrongLucasProbablePrime") { a -> Vdf.isStrongLucasProbablePrime(b(a[0])) }
    @Test fun modpow() = OracleCases.each(M, "modpow") { a -> s(Vdf.modpow(b(a[0]), b(a[1]), b(a[2]))) }
    @Test fun gcd() = OracleCases.each(M, "gcd") { a -> s(Vdf.gcd(b(a[0]), b(a[1]))) }
    @Test fun canonicalVdfOutput() = OracleCases.each(M, "canonicalVdfOutput") { a -> s(Vdf.canonicalVdfOutput(b(a[0]), b(a[1]))) }
    @Test fun bigIntToBytes() = OracleCases.each(M, "bigIntToBytes") { a -> Vdf.bigIntToBytes(b(a[0])) }
    @Test fun bytesRoundTrip() = OracleCases.each(M, "bytesRoundTrip") { a -> Vdf.bigIntToBytes(Vdf.bytesToBigInt(Keys.unb64u(a[0] as String))) }

    @Test fun hashToPrime() = OracleCases.each(M, "hashToPrime") { a ->
        if (a.size > 4) {
            val bits = net.atlasauth.pca.jose.Js.num(a[4])
            if (bits == null || bits != Math.floor(bits)) throw IllegalArgumentException("bits")
            s(Vdf.hashToPrime(b(a[0]), b(a[1]), lng(a[2]), b(a[3]), bits.toInt()))
        } else s(Vdf.hashToPrime(b(a[0]), b(a[1]), lng(a[2]), b(a[3])))
    }

    @Test fun sequentialSquare() = OracleCases.each(M, "sequentialSquare") { a -> s(Vdf.sequentialSquare(b(a[0]), lng(a[1]), b(a[2]))) }
    @Test fun vdfEval() = OracleCases.each(M, "vdfEval") { a -> pf(Vdf.vdfEval(b(a[0]), lng(a[1]), b(a[2]))) }
    @Test fun vdfEvalCanonical() = OracleCases.each(M, "vdfEvalCanonical") { a -> pf(Vdf.vdfEvalCanonical(b(a[0]), lng(a[1]), b(a[2]))) }

    @Test fun vdfVerifyDetailed() = OracleCases.each(M, "vdfVerifyDetailed") { a -> verdict(Vdf.vdfVerifyDetailed(b(a[0]), b(a[1]), b(a[2]), dbl(a[3]), b(a[4]))) }

    @Test fun vdfVerifyCanonicalDetailed() = OracleCases.each(M, "vdfVerifyCanonicalDetailed") { a ->
        verdict(Vdf.vdfVerifyCanonicalDetailed(b(a[0]), b(a[1]), b(a[2]), dbl(a[3]), b(a[4])))
    }

    @Test fun checkProductionModulus() = OracleCases.each(M, "checkProductionModulus") { a ->
        val c = Vdf.checkProductionModulus(b(a[0]))
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = c.ok
        if (!c.ok) m["reason"] = c.reason
        m
    }

    // ---- timelock wrappers (options arrive as a JSON object) ----

    private fun opts(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun allow(o: Map<String, Any?>): Boolean = o["allowInsecureDevModulus"] == true

    @Test fun deriveTimelockInput() = OracleCases.each(M, "deriveTimelockInput") { a -> s(Timelock.deriveTimelockInput(a[0], b(a[1]), a[2])) }

    @Test fun requireTimelock() = OracleCases.each(M, "requireTimelock") { a ->
        val o = opts(a[1])
        val q = Timelock.requireTimelock(a[0], lng(o["steps"]), b(o["N"]), o["beacon"], allow(o))
        linkedMapOf<String, Any?>("kind" to q.kind, "x" to s(q.x), "steps" to q.steps, "N" to s(q.N), "actionDigest" to q.actionDigest)
    }

    @Test fun proveTimelockElapsed() = OracleCases.each(M, "proveTimelockElapsed") { a ->
        val o = opts(a[3])
        val p = Timelock.proveTimelockElapsed(a[0], lng(a[1]), b(a[2]), o["beacon"], allow(o))
        linkedMapOf<String, Any?>("kind" to p.kind, "y" to s(p.y!!), "pi" to s(p.pi!!), "steps" to p.steps.toLong())
    }

    @Test fun verifyTimelock() = OracleCases.each(M, "verifyTimelock") { a ->
        val o = opts(a[2])
        var p: Timelock.TimelockProof? = null
        if (a[1] is Map<*, *>) {
            val pm = opts(a[1])
            p = Timelock.TimelockProof(
                pm["kind"] as? String, if (pm["y"] is String) b(pm["y"]) else null, if (pm["pi"] is String) b(pm["pi"]) else null, dbl(pm["steps"]),
            )
        }
        Timelock.verifyTimelock(a[0], p, dbl(o["steps"]), b(o["N"]), o["beacon"], allow(o))
    }

    // ---- plain tests the oracle cannot cover ----

    @Test fun knownPrimesAndPseudoprimes() {
        for (e in intArrayOf(89, 107, 127, 521, 607, 1279)) assertTrue("M$e", Vdf.isProbablePrime(BigInteger.valueOf(2).pow(e).subtract(BigInteger.ONE)))
        // Carmichael numbers, strong pseudoprimes to base 2, and Lucas pseudoprimes are all composite
        for (n in longArrayOf(561, 41041, 825265, 2047, 3277, 4033, 3215031751L, 5459, 5777, 10877)) assertFalse("n$n", Vdf.isProbablePrime(BigInteger.valueOf(n)))
        assertEquals(2048, Vdf.RSA_2048_CHALLENGE_MODULUS.bitLength())
        assertTrue(Vdf.checkProductionModulus(Vdf.RSA_2048_CHALLENGE_MODULUS).ok)
    }

    @Test fun isqrtIsExact() {
        for (n in listOf("0", "1", "2", "3", "4", "15", "16", "17", "99999999999999999999", "10000000000000000000000000000000000000000")) {
            val v = BigInteger(n)
            val r = Vdf.isqrt(v)
            assertTrue(n, r.multiply(r) <= v && r.add(BigInteger.ONE).pow(2) > v)
        }
    }

    @Test fun devSetupIsRefusedByTheTimelockLayer() {
        val st = Vdf.insecureDevSetup(256, SecureRandom())
        assertTrue(st.insecureDevOnly)
        assertEquals(st.N, st.p.multiply(st.q))
        assertFalse(Vdf.checkProductionModulus(st.N).ok)
        assertThrows(IllegalArgumentException::class.java) { Timelock.requireTimelock("a", 10, st.N, "beacon", false) }
        val p = Timelock.proveTimelockElapsed("a", 10, st.N, "beacon", true)
        assertFalse(Timelock.verifyTimelock("a", p, 10.0, st.N, "beacon", false))
        assertTrue(Timelock.verifyTimelock("a", p, 10.0, st.N, "beacon", true))
    }

    @Test fun productionDefaultEndToEnd() {
        val n = Vdf.RSA_2048_CHALLENGE_MODULUS
        val p = Timelock.proveTimelockElapsed("prod-action", 50, n, "test-beacon-0123456789abcdef", false)
        assertTrue(Timelock.verifyTimelock("prod-action", p, 50.0, n, "test-beacon-0123456789abcdef", false))
        assertFalse(Timelock.verifyTimelock("other-action", p, 50.0, n, "test-beacon-0123456789abcdef", false))
        val q = Vdf.vdfEval(BigInteger.valueOf(123456789), 20, n)
        assertTrue(Vdf.vdfVerify(BigInteger.valueOf(123456789), q.y, q.pi, 20, n))
        assertFalse(Vdf.vdfVerify(BigInteger.valueOf(123456789), BigInteger.ZERO, BigInteger.ZERO, 1_000_000_000, n))
    }
}
