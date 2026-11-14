package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** Mutation kills for Passport.kt: the stack-overflow refusal and the fatal-error rethrow from the revocation source and the attester. */
@Suppress("UNCHECKED_CAST")
class Kill08K1PassportTest {
    private val nbf = 500_000L
    private val exp = 2_000_000L
    private val now = 1_000_000L
    private val label = "k08k1-passport-issuer"
    private val iss = IntentTestKit.pub(label)
    private val sub = IntentTestKit.pub("k08k1-passport-subject")

    private fun identity(hw: Boolean): LinkedHashMap<String, Any?> =
        linkedMapOf("model_id" to "m1", "operator" to "op", "hardware_rooted" to hw, "weights_digest" to "wd", "weights_measured" to true)

    private fun signed(hw: Boolean): LinkedHashMap<String, Any?> {
        val p = identity(hw)
        val pp = LinkedHashMap(p)
        pp["id"] = Passport.fingerprint(p)
        val b = linkedMapOf<String, Any?>("typ" to "atlas-pca/passport", "ver" to 1L, "passport" to pp, "iss" to iss, "sub" to sub, "iat" to nbf, "nbf" to nbf, "exp" to exp)
        if (hw) b["evidence"] = mapOf("document" to mapOf("nonce" to "n1"), "at" to now)
        val out = LinkedHashMap(b)
        out["sig"] = IntentTestKit.sign(label, IntentJs.message(Passport.SIG_DOMAIN, b))
        return out
    }

    private fun opts(
        issuers: List<String> = listOf(iss), attest: HardwareAttester? = null,
        revoked: ((String, String, String) -> Boolean)? = { _, _, _ -> false },
    ) = Passport.Options(issuers, now, null, null, null, null, attest, null, revoked)

    @Test fun aStackOverflowInsideTheVerifierIsAMalformedVerdictNamingIt() {
        val boom = object : AbstractList<String>() {
            override val size: Int get() = 1
            override fun get(index: Int): String = iss
            override fun contains(element: String): Boolean { throw StackOverflowError() }
        }
        val v = Passport.verify(signed(false), opts(issuers = boom))
        assertNotNull(v)
        assertFalse(v.ok)
        assertEquals("malformed", v.reason)
        assertEquals("StackOverflowError", v.detail)
    }

    @Test fun aFatalErrorFromTheRevocationSourceOrTheAttesterIsRethrown() {
        val fatalRevoked: ((String, String, String) -> Boolean) = { _, _, _ -> throw OutOfMemoryError("fatal") }
        assertThrows(OutOfMemoryError::class.java) { Passport.verify(signed(false), opts(revoked = fatalRevoked)) }
        val fatalAttester: HardwareAttester = { _, _ -> throw OutOfMemoryError("fatal") }
        assertThrows(OutOfMemoryError::class.java) { Passport.verify(signed(true), opts(attest = fatalAttester)) }
        // an ordinary failure is still a refusal
        val flaky: ((String, String, String) -> Boolean) = { _, _, _ -> throw IllegalStateException("down") }
        assertEquals("revocation_unavailable", Passport.verify(signed(false), opts(revoked = flaky)).reason)
        val badAttester: HardwareAttester = { _, _ -> throw IllegalStateException("no") }
        assertEquals("hardware_attestation_failed", Passport.verify(signed(true), opts(attest = badAttester)).reason)
    }
}
