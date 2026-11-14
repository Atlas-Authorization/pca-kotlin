package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Kill tests for Escalation (k05 small group); reasons and the request shape follow packages/pca/src/escalation.ts. */
class Kill05SmallEscalationTest {
    private fun n(s: String) = Json.Num(s)
    private val d32 = "qK9bTlJxvo3zLOQ4msAVS7_odp-g75Kfsu_Z7L47sqQ"
    private val bind = Escalation.Binding(d32, d32, d32)

    private fun answer(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val a = LinkedHashMap<String, Any?>()
        a["v"] = n("1"); a["kind"] = "pca-escalation-answer"; a["principal"] = IntentTestKit.pub("k05-escalation")
        a["policy_digest"] = d32; a["action_digest"] = d32; a["history_head"] = d32; a["decision"] = "allow"
        a["iat"] = n("1000"); a["expires_at"] = n("2000"); a["nonce"] = Pca.b64(ByteArray(16)); a["sig"] = "s"
        for ((k, v) in over) a[k] = v
        return a
    }

    @Test fun historyHeadBindsTheCounter() {
        assertEquals(Pca.hashCanonical(linkedMapOf("d" to Escalation.HISTORY_DOMAIN, "last_counter" to n("5"))), Escalation.historyHead(5L))
        assertEquals(Pca.hashCanonical(linkedMapOf<String, Any?>("d" to Escalation.HISTORY_DOMAIN, "last_counter" to null)), Escalation.historyHead(null))
    }

    @Test fun buildRequestExactShape() {
        val grant = mapOf("issuer" to "g")
        val action = LinkedHashMap<String, Any?>(); action["verb"] = "read"
        val pcactn = LinkedHashMap<String, Any?>(); pcactn["action"] = action
        val got = Escalation.buildRequest(null, grant, pcactn, 7L, listOf("r1"), 1000L, renderDigest = d32)
        val want = LinkedHashMap<String, Any?>()
        want["v"] = n("1"); want["kind"] = "pca-escalation-request"; want["aud"] = ""
        want["policy_digest"] = Escalation.policyDigest(grant); want["action_digest"] = Escalation.actionDigest(pcactn)
        want["history_head"] = Escalation.historyHead(7L); want["verb"] = "read"; want["resource"] = "undefined"
        want["reasons"] = arrayListOf<Any?>("r1"); want["expires_at"] = n("3601000"); want["render_digest"] = d32
        assertEquals(want, got)
        val noRender = Escalation.buildRequest("rs", grant, pcactn, null, emptyList(), 0L, 5L)
        assertEquals("rs", noRender["aud"])
        assertEquals(n("5"), noRender["expires_at"])
        assertEquals(false, noRender.containsKey("render_digest"))
    }

    @Test fun shapeReasons() {
        assertNull(Escalation.answerShapeError(answer()))
        assertEquals("principal must be canonical base64url (32 bytes)", Escalation.answerShapeError(answer("principal" to "A".repeat(42))))
        assertEquals("principal must be canonical base64url (32 bytes)", Escalation.answerShapeError(answer("principal" to n("1"))))
        assertEquals("nonce must be canonical base64url of at least 16 bytes", Escalation.answerShapeError(answer("nonce" to "!!")))
        assertEquals("nonce must be canonical base64url of at least 16 bytes", Escalation.answerShapeError(answer("nonce" to n("1"))))
        assertEquals("nonce must be canonical base64url of at least 16 bytes", Escalation.answerShapeError(answer("nonce" to Pca.b64(ByteArray(15)))))
    }

    @Test fun verifierClockBounds() {
        val clock = "the verifier clock is not a safe integer (fail closed)"
        assertEquals("malformed escalation answer: not an object", Escalation.verifyAnswer(null, emptyList(), bind, 9007199254740991L).reason)
        assertEquals("malformed escalation answer: not an object", Escalation.verifyAnswer(null, emptyList(), bind, -9007199254740991L).reason)
        assertEquals(clock, Escalation.verifyAnswer(null, emptyList(), bind, 9007199254740992L).reason)
        assertEquals(clock, Escalation.verifyAnswer(null, emptyList(), bind, -9007199254740992L).reason)
    }

    private class Throwing(base: Map<String, Any?>, val t: Throwable) : LinkedHashMap<String, Any?>(base) {
        override fun get(key: String): Any? = throw t
    }

    @Test fun errorsFailClosedWithTheirMessage() {
        val p = listOf(Escalation.Principal(IntentTestKit.pub("k05-escalation")))
        val boom = Escalation.verifyAnswer(Throwing(answer(), IllegalStateException("boom")), p, bind, 1500L)
        assertEquals(false, boom.ok)
        assertNull(boom.decision)
        assertEquals("escalation answer error (fail closed): boom", boom.reason)
        assertEquals("escalation answer error (fail closed): unknown", Escalation.verifyAnswer(Throwing(answer(), IllegalStateException()), p, bind, 1500L).reason)
        assertEquals("escalation answer error (fail closed): unknown", Escalation.verifyAnswer(Throwing(answer(), StackOverflowError()), p, bind, 1500L).reason)
        assertEquals("Escalation.Verdict(ok=false, decision=null, reason=escalation answer error (fail closed): boom)", boom.toString())
    }
}
