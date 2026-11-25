package net.atlasauth.pca.a2a

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the TypeScript-reference vectors of the A2A adapter through the native port. */
@Suppress("UNCHECKED_CAST")
class A2aDiffTest {
    private val m = "ref-a2a"
    private val libReason = Regex("^(signature \\d+ did not verify|could not resolve verification key|malformed payment mandate or PCActn): ")

    private fun map(o: Any?) = o as Map<String, Any?>

    private fun strs(o: Any?) = o as List<String>

    /** Reasons that quote the JOSE library, or a runtime message, are compared up to the first colon. */
    private fun norm(r: Map<String, Any?>): Any? {
        val reason = r["reason"]
        if (reason is String) {
            val mt = libReason.find(reason)
            if (mt != null) return LinkedHashMap(r).also { it["reason"] = mt.groupValues[1] }
        }
        return r
    }

    private fun opts(o: Any?): A2aPca.VerifyOptions {
        val x = map(o)
        val v = A2aPca.VerifyOptions()
        v.aud = x["aud"] as String?
        if (x["now"] != null) v.now = Json.asLong(x["now"])
        v.grant = if (x["grant"] == null) null else map(x["grant"])
        v.expectedRootIssuer = x["expectedRootIssuer"] as String?
        v.requireProof = x["require"] != false
        if (x["humanSignerSet"] is List<*>) v.humanSignerSet = x["humanSignerSet"] as List<Any?>
        if (x.containsKey("context")) {
            val ctx = map(x["context"])
            v.context = { _ -> ctx }
        }
        return v
    }

    private fun seed(label: String): ByteArray = OracleCases.seed(label)

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf<String, Any?>(
            "PCA_A2A_EXTENSION_URI" to A2aPca.PCA_A2A_EXTENSION_URI,
            "TASK_STATE_AUTH_REQUIRED" to A2aPca.TASK_STATE_AUTH_REQUIRED,
            "TASK_STATE_INPUT_REQUIRED" to A2aPca.TASK_STATE_INPUT_REQUIRED,
            "A2A_AP2_CONTEXT" to ArrayList<Any?>(A2aPca.A2A_AP2_CONTEXT),
            "A2A_RECEIPT_DOMAIN" to A2aPca.A2A_RECEIPT_DOMAIN,
            "RECEIPT_KEY" to A2aPca.RECEIPT_KEY,
        )
    }

    @Test fun jcsBytes() = OracleCases.each(m, "jcsBytes") { a -> A2aPca.jcsBytes(a[0]) }
    @Test fun validateAgentCard1() = OracleCases.each(m, "validateAgentCard1") { a -> A2aPca.validateAgentCard1(a[0]) }
    @Test fun attachPcaToA2ATask() = OracleCases.each(m, "attachPcaToA2ATask") { a -> A2aPca.attachPcaToA2ATask(a[0], a[1]) }
    @Test fun attachPcaToA2AMessage() = OracleCases.each(m, "attachPcaToA2AMessage") { a -> A2aPca.attachPcaToA2AMessage(a[0], a[1]) }
    @Test fun extractPca() = OracleCases.each(m, "extractPca") { a -> A2aPca.extractPca(a[0]) }
    @Test fun extractPcaFromMessage() = OracleCases.each(m, "extractPcaFromMessage") { a -> A2aPca.extractPcaFromMessage(a[0]) }

    @Test fun verifyA2ATask() = OracleCases.each(m, "verifyA2ATask") { a -> A2aPca.verifyA2ATask(a[0], opts(a[1])).toMap() }
    @Test fun middleware() = OracleCases.each(m, "middleware") { a -> A2aPca.pcaA2AMiddleware(opts(a[1])).check(a[0]).toMap() }
    @Test fun resumeAuthRequired() = OracleCases.each(m, "resumeAuthRequired") { a -> A2aPca.resumeAuthRequired(a[0], a[1], opts(a[2])) }

    @Test fun authRequiredStatus() = OracleCases.each(m, "authRequiredStatus") { a ->
        val o = map(a[1])
        A2aPca.authRequiredStatus(map(a[0]), o["messageId"], o["now"], o["text"] as String?)
    }

    @Test fun answerMessage() = OracleCases.each(m, "answerMessage") { a -> A2aPca.answerMessage(a[0], a[1], a[2]) }
    @Test fun readAuthRequiredNeed() = OracleCases.each(m, "readAuthRequiredNeed") { a -> A2aPca.readAuthRequiredNeed(a[0]) }
    @Test fun isAuthRequired() = OracleCases.each(m, "isAuthRequired") { a -> A2aPca.isAuthRequired(a[0]) }

    @Test fun resumeGate() = OracleCases.each(m, "resumeGate") { a ->
        val x = map(a[0])
        A2aPca.resumeGate(x["state"], x["needEncoded"], x["answerNeedDigest"], if (x.containsKey("proofAction")) x["proofAction"] else A2aPca.NO_PROOF)
    }

    @Test fun pcaExtensionDeclaration() = OracleCases.each(m, "pcaExtensionDeclaration") { a ->
        if (a.size > 1) A2aPca.pcaExtensionDeclaration(a[0], a[1] as Boolean) else A2aPca.pcaExtensionDeclaration(a[0])
    }

    @Test fun readPcaExtension() = OracleCases.each(m, "readPcaExtension") { a -> A2aPca.readPcaExtension(a[0]) }
    @Test fun clientOptsIntoPca() = OracleCases.each(m, "clientOptsIntoPca") { a -> A2aPca.clientOptsIntoPca(a[0]) }
    @Test fun checkChainExtension() = OracleCases.each(m, "checkChainExtension") { a -> A2aPca.checkChainExtension(a[0]) }
    @Test fun chainExtends() = OracleCases.each(m, "chainExtends") { a -> A2aPca.chainExtends(a[0] as List<*>, a[1] as List<*>) }

    @Test fun verifyA2ADelegation() = OracleCases.each(m, "verifyA2ADelegation") { a ->
        A2aPca.verifyA2ADelegation((a[0] as List<*>).map { h -> A2aPca.Hop(map(h)["task"], opts(map(h)["opts"])) })
    }

    @Test fun pcaPushToken() = OracleCases.each(m, "pcaPushToken") { a -> A2aPca.pcaPushToken(a[0], strs(a[1]), a[2]) }

    @Test fun checkPushNotification() = OracleCases.each(m, "checkPushNotification") { a ->
        val e = map(a[0])
        val d = map(a[1])
        A2aPca.checkPushNotification(e["taskId"] as String, strs(e["chainIds"]), e["salt"], d["token"], d["payload"])
    }

    @Test fun uniformTaskNotFound() = OracleCases.each(m, "uniformTaskNotFound") { A2aPca.uniformTaskNotFound() }

    @Test fun signTaskReceipt() = OracleCases.each(m, "signTaskReceipt") { a ->
        val o = map(a[1])
        A2aPca.signTaskReceipt(seed(a[0] as String), o["taskId"], o["state"], strs(o["chainIds"]), o["issuedAt"], if (o["prev"] == null) null else map(o["prev"]))
    }

    @Test fun verifyTaskReceipt() = OracleCases.each(m, "verifyTaskReceipt") { a -> A2aPca.verifyTaskReceipt(a[0], a[1] as String) }
    @Test fun receiptDigest() = OracleCases.each(m, "receiptDigest") { a -> A2aPca.receiptDigest(a[0]) }

    @Test fun checkReceiptChain() = OracleCases.each(m, "checkReceiptChain") { a ->
        val o = map(a[1])
        A2aPca.checkReceiptChain(a[0], o["signer"] as String, o["taskId"] as String, strs(o["chainIds"]))
    }

    @Test fun mayTriggerNext() = OracleCases.each(m, "mayTriggerNext") { a ->
        val o = map(a[1])
        A2aPca.mayTriggerNext(a[0], o["signer"] as String, o["taskId"] as String, strs(o["chainIds"]))
    }

    @Test fun attachReceipt() = OracleCases.each(m, "attachReceipt") { a -> A2aPca.attachReceipt(a[0], a[1]) }
    @Test fun receiptOfPayload() = OracleCases.each(m, "receiptOfPayload") { a -> A2aPca.receiptOfPayload(a[0]) }
    @Test fun extendedAgentCard() = OracleCases.each(m, "extendedAgentCard") { a -> A2aPca.extendedAgentCard(a[0], map(a[1])) }

    @Test fun issueSignedAgentCard() = OracleCases.each(m, "issueSignedAgentCard") { a ->
        val io = A2aPca.IssueOptions()
        if (a.size > 2) {
            val o = map(a[2])
            io.alg = o["alg"] as String?
            io.kid = o["kid"] as String?
            io.profile = o["profile"] as String?
            io.schema = o["schema"] as String?
            io.passport = if (o["passport"] == null) null else map(o["passport"])
        }
        A2aPca.issueSignedAgentCard(a[0], map(a[1]), io)
    }

    @Test fun verifyAgentCard() = OracleCases.each(m, "verifyAgentCard") { a ->
        val o = map(a[1])
        val vo = A2aPca.VerifyCardOptions()
        vo.jwks = o["jwks"]
        vo.key = o["key"]
        vo.alg = o["alg"] as String?
        vo.schema = o["schema"] as String?
        norm(A2aPca.verifyAgentCard(a[0], vo))
    }

    @Test fun a2aPaymentMandateFromPca() = OracleCases.each(m, "a2aPaymentMandateFromPca") { a -> A2aPca.a2aPaymentMandateFromPca(a[0], map(a[1])) }
    @Test fun pcaBindingFromA2APaymentMandate() = OracleCases.each(m, "pcaBindingFromA2APaymentMandate") { a -> A2aPca.pcaBindingFromA2APaymentMandate(a[0]) }

    @Test fun verifyA2APaymentMandate() = OracleCases.each(m, "verifyA2APaymentMandate") { a ->
        norm(A2aPca.verifyA2APaymentMandate(a[0], a[1], opts(a[2])).toMap())
    }

    /** What the oracle cannot cover: a PCActn that reaches the verifier is refused without a revocation predicate, and a plug-in verifier decides. */
    @Test fun verifierPlugAndDefaultRevocation() {
        val cap = linkedMapOf<String, Any?>("id" to "g1", "issuer" to "ROOT", "holder" to "H1")
        val pca = linkedMapOf<String, Any?>("cap_chain" to arrayListOf<Any?>(cap))
        val task = linkedMapOf<String, Any?>("metadata" to linkedMapOf<String, Any?>(A2aPca.PCA_A2A_EXTENSION_URI to pca))
        val o = A2aPca.VerifyOptions()
        o.aud = "rs"
        o.now = 1L
        o.expectedRootIssuer = "ROOT"
        assertFalse(A2aPca.verifyA2ATask(task, o).ok) // the core verifier refuses a PCActn with no signature
        o.verifier = A2aPca.PcaVerifier { _, _ -> A2aPca.Outcome(true, LinkedHashMap(), ArrayList()) }
        assertTrue(A2aPca.verifyA2ATask(task, o).ok)
        o.verifier = A2aPca.PcaVerifier { _, _ -> throw IllegalStateException("boom") }
        assertFalse(A2aPca.verifyA2ATask(task, o).ok) // a throwing verifier is a refusal
    }
}
