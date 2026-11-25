package net.atlasauth.pca.webauthn

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays the TypeScript-reference vectors of the WebAuthn step-up verifier: the COSE_Key reader, authenticatorData header, step-up and
 * approval challenges, Secure Payment Confirmation and the full assertion verifier. A verifyAssertion refusal reason is compared
 * exactly, except the two engine-message tails.
 */
@Suppress("UNCHECKED_CAST")
class WebauthnDiffTest {
    private val m = "ref-webauthn"

    /** {"$bytes": b64u} members (at any depth) become ByteArray. */
    private fun rev(v: Any?): Any? = when (v) {
        is List<*> -> v.map { rev(it) }
        is Map<*, *> -> {
            if (v.size == 1 && v["\$bytes"] is String) Keys.unb64u(v["\$bytes"] as String)
            else LinkedHashMap<String, Any?>().also { o -> for ((k, x) in v) o[k as String] = rev(x) }
        }
        else -> v
    }

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf(
            "MAX_AUTHENTICATOR_DATA_BYTES" to Webauthn.MAX_AUTHENTICATOR_DATA_BYTES, "MAX_CLIENT_DATA_BYTES" to Webauthn.MAX_CLIENT_DATA_BYTES,
            "MAX_SIGNATURE_BYTES" to Webauthn.MAX_SIGNATURE_BYTES,
        )
    }

    @Test fun coseKeyToJwk() = OracleCases.each(m, "coseKeyToJwk") {
        Webauthn.coseKeyToJwk(rev(it[0]) as? ByteArray ?: throw IllegalArgumentException("coseKeyToJwk: expected a Uint8Array"))
    }

    @Test fun parseAuthenticatorData() = OracleCases.each(m, "parseAuthenticatorData") { Webauthn.parseAuthenticatorData(rev(it[0]) as? ByteArray)?.toMap() }

    @Test fun buildStepUpChallenge() = OracleCases.each(m, "buildStepUpChallenge") { Webauthn.buildStepUpChallenge(rev(it[0])) }

    @Test fun stepUpChallengeB64u() = OracleCases.each(m, "stepUpChallengeB64u") { Webauthn.stepUpChallengeB64u(rev(it[0])) }

    @Test fun buildApprovalChallenge() = OracleCases.each(m, "buildApprovalChallenge") { Webauthn.buildApprovalChallenge(rev(it[0]), it[1]) }

    @Test fun approvalChallengeForActn() = OracleCases.each(m, "approvalChallengeForActn") { Webauthn.approvalChallengeForActn(rev(it[0]), it[1]) }

    @Test fun spcPaymentError() = OracleCases.each(m, "spcPaymentError") { Webauthn.spcPaymentError(it[0], it[1] as? Map<String, Any?>, it[2] as? String) }

    @Test fun verifyAssertion() = OracleCases.each(m, "verifyAssertion") { a ->
        val assertion = rev(a[0]) as Map<String, Any?>
        val expect = LinkedHashMap(rev(a[1]) as Map<String, Any?>)
        val calls = ArrayList<Any?>()
        if (expect.remove("hook") != null) expect["onSignCountRegression"] = { info: Map<String, Any?> -> calls.add(info); Unit }
        val result = LinkedHashMap(Webauthn.verifyAssertion(assertion, expect))
        (result["reason"] as? String)?.let {
            result["reason"] = it.replace(Regex("(?s)^(public key could not be resolved|verification error \\(fail closed\\)):.*$"), "$1")
        }
        linkedMapOf("result" to result, "hook" to calls)
    }

    // ---- what the oracle does not pin ----

    @Test fun neverThrowsOnNonsense() {
        val r = Webauthn.verifyAssertion(emptyMap(), emptyMap())
        assertFalse(r["ok"] as Boolean)
        assertEquals("authenticatorData is not bytes", r["reason"])
    }

    @Test fun stepUpChallengeIsStableForABody() {
        val body = linkedMapOf<String, Any?>("ver" to Json.Num("2"), "aud" to "rs")
        val a = Webauthn.buildStepUpChallenge(body)
        assertTrue("sig is not part of the challenge", a.contentEquals(Webauthn.buildStepUpChallenge(body + ("sig" to "x"))))
        assertEquals(32, a.size)
    }
}
