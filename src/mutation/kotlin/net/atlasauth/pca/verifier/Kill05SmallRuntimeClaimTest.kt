package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** Kill tests for RuntimeClaim.verifiedClass and K3Sig (k05 small group): one guard broken per case, every claim validly signed. */
class Kill05SmallRuntimeClaimTest {
    private val pd = "mPJkgmL6Cj0aXkA2Skta2S67xBI5VCGcCjJ_l2PR-D8"
    private val att = IntentTestKit.pub("k05-runtime-claim-attestor")
    private fun n(s: String) = Json.Num(s)

    private fun claim(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val c = LinkedHashMap<String, Any?>()
        c["v"] = n("1"); c["class"] = "wasi_no_ambient"; c["passport_digest"] = pd; c["evidence_digest"] = "ev1"
        c["iat"] = n("100"); c["exp"] = n("200"); c["attestor"] = att
        for ((k, v) in over) c[k] = v
        c["sig"] = IntentTestKit.sign("k05-runtime-claim-attestor", IntentJs.message(RuntimeClaim.DOMAIN, LinkedHashMap(c)))
        return c
    }

    private fun cls(c: Any?, now: Any? = n("150"), passport: String = pd, ev: List<String> = listOf("ev1")): String =
        RuntimeClaim.verifiedClass(c, listOf(att), passport, ev, now)

    @Test fun acceptsAndWindowBoundaries() {
        assertEquals("wasi_no_ambient", cls(claim()))
        assertEquals("os_confined", cls(claim("class" to "os_confined")))
        assertEquals("wasi_no_ambient", cls(claim(), n("100"))) // now == iat is inside
        assertEquals("wasi_no_ambient", cls(claim(), n("199")))
        assertEquals("none", cls(claim(), n("200"))) // now == exp is outside
        assertEquals("none", cls(claim(), n("99")))
    }

    @Test fun eachGuardRefusesASignedClaim() {
        assertEquals("none", cls(claim("class" to "root")))
        assertEquals("none", cls(claim("class" to n("1"))))
        assertEquals("none", cls(claim("v" to n("2"))))
        // a negative or fractional time member is refused although its truncated value would sit inside the window
        assertEquals("none", cls(claim("iat" to n("-1"))))
        assertEquals("none", cls(claim("iat" to n("100.5"))))
        assertEquals("none", cls(claim("exp" to n("200.5"))))
        assertEquals("none", cls(claim(), n("150.5")))
        assertEquals("none", cls(claim(), "150"))
    }

    @Test fun digestLengthCapsAndEmptyStrings() {
        val p128 = "p".repeat(128)
        val p129 = "p".repeat(129)
        assertEquals("wasi_no_ambient", cls(claim("passport_digest" to p128), passport = p128))
        assertEquals("none", cls(claim("passport_digest" to p129), passport = p129))
        assertEquals("none", cls(claim("passport_digest" to ""), passport = ""))
        val e128 = "e".repeat(128)
        val e129 = "e".repeat(129)
        assertEquals("wasi_no_ambient", cls(claim("evidence_digest" to e128), ev = listOf(e128)))
        assertEquals("none", cls(claim("evidence_digest" to e129), ev = listOf(e129)))
        assertEquals("none", cls(claim("evidence_digest" to ""), ev = listOf("")))
    }

    @Test fun aThrowingClaimIsNone() {
        val base = claim()
        val boom = object : LinkedHashMap<String, Any?>(base) {
            override fun get(key: String): Any? = if (key == "v") throw IllegalStateException("boom") else super.get(key)
        }
        assertEquals("none", cls(boom))
    }

    @Test fun k3SigVerifyBodyAndJsText() {
        val body = LinkedHashMap<String, Any?>(); body["a"] = n("1")
        val sig = IntentTestKit.sign("k05-runtime-claim-attestor", IntentJs.message("d\u0000", body))
        assertEquals(true, K3Sig.verifyBody("d\u0000", body, att, sig))
        assertFalse(K3Sig.verifyBody("e\u0000", body, att, sig))
        assertFalse(K3Sig.verifyBody("d\u0000", body, att, null))
        // a body the strict canonicalizer refuses throws inside; the answer is false, never true
        val bad = LinkedHashMap<String, Any?>(); bad["a"] = n("1e5")
        assertFalse(K3Sig.verifyBody("d\u0000", bad, att, sig))
        assertEquals("5", K3Sig.jsText(n("5"), true))
        assertEquals("-0.5", K3Sig.jsText(n("-0.5"), true))
        assertEquals("undefined", K3Sig.jsText(n("5"), false))
        assertEquals("null", K3Sig.jsText(null, true))
        assertEquals("x", K3Sig.jsText("x", true))
    }
}
