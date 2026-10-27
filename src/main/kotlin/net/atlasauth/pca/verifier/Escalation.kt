package net.atlasauth.pca.verifier

/**
 * Escalation on the wire (packages/pca/src/escalation.ts; security contract C-51). A decision of `escalate` is admitted only
 * with a principal-signed [answer][verifyAnswer] bound to (policy digest, action digest, history head), spent by the replay
 * counter, never upgrading a `deny`. Every signature suite this SDK verifies is accepted (Ed25519, and the post-quantum /
 * hybrid suites under the principal's PINNED `pq_pk`).
 */
object Escalation {
    const val ANSWER_DOMAIN = "atlas-pca/escalation-answer/v1\u0000"
    const val POLICY_DOMAIN = "atlas-pca/escalation-policy/v1"
    const val ACTION_DOMAIN = "atlas-pca/escalation-action/v1"
    const val HISTORY_DOMAIN = "atlas-pca/escalation-history/v1"

    /** An answer lives at most 24 hours. */
    const val MAX_LIFETIME_MS = 86_400_000L

    /** A pinned answering principal: its Ed25519 key (b64u) and, for a post-quantum / hybrid suite, its pinned `pq_pk`. */
    class Principal(val pk: String, val pqPk: String? = null)

    /** The digest of the policy in force: the stored grant. */
    fun policyDigest(grant: Any?): String = Pca.hashCanonical(linkedMapOf("d" to POLICY_DOMAIN, "grant" to grant))

    /** The digest of the exact PCActn (counter and signature included): one answer, one action. */
    fun actionDigest(pcactn: Any?): String = Pca.hashCanonical(linkedMapOf("d" to ACTION_DOMAIN, "pcactn" to pcactn))

    /** The head of the holder's history: its highest admitted replay counter (null = none yet). */
    fun historyHead(lastCounter: Long?): String =
        Pca.hashCanonical(linkedMapOf("d" to HISTORY_DOMAIN, "last_counter" to (if (lastCounter == null) null else IntentJs.ofLong(lastCounter))))

    /** The request a refused escalate carries for the principal (valid one hour unless [ttlMs]). */
    fun buildRequest(aud: String?, grant: Any?, pcactn: Map<String, Any?>, lastCounter: Long?, reasons: List<String>, now: Long, ttlMs: Long = 3_600_000L): Map<String, Any?> {
        val action = pcactn["action"]
        return linkedMapOf(
            "v" to IntentJs.ofLong(1),
            "kind" to "pca-escalation-request",
            "aud" to (aud ?: ""),
            "policy_digest" to policyDigest(grant),
            "action_digest" to actionDigest(pcactn),
            "history_head" to historyHead(lastCounter),
            "verb" to IntentRevocation.jsText(IntentJs.get(action, "verb"), IntentJs.own(action, "verb")),
            "resource" to IntentRevocation.jsText(IntentJs.get(action, "resource"), IntentJs.own(action, "resource")),
            "reasons" to ArrayList<Any?>(reasons.take(16).map { if (it.length > 512) it.substring(0, 512) else it }),
            "expires_at" to IntentJs.ofLong(now + ttlMs),
        )
    }

    private val REQUIRED = listOf("v", "kind", "principal", "policy_digest", "action_digest", "history_head", "decision", "iat", "expires_at", "nonce", "sig")
    private val OPTIONAL = listOf("alg", "pq_pk", "pq_sig")

    /** Null = well-formed (closed members, canonical digests, safe-integer times, sane lifetime, a suite this SDK knows). */
    fun answerShapeError(a: Any?): String? {
        if (a !is Map<*, *>) return "not an object"
        val m = IntentJs.obj(a)
        val e = IntentArtifacts.closedMembers(m, REQUIRED, OPTIONAL, "answer")
        if (e != null) return e
        if (IntentJs.num(m["v"]) != 1.0 || m["kind"] != "pca-escalation-answer") return "not a pca-escalation-answer v1"
        if (!IntentArtifacts.isBoundedString(m["principal"], 64) || Pca.decodeB64uStrict(m["principal"], 32) == null) return "principal must be canonical base64url (32 bytes)"
        for (k in listOf("policy_digest", "action_digest", "history_head")) if (!IntentArtifacts.isDigest(m[k])) return "$k must be canonical base64url (32 bytes)"
        if (m["decision"] != "allow" && m["decision"] != "deny") return "decision must be 'allow' or 'deny'"
        if (!(IntentJs.isInt(m["iat"]) && IntentJs.num(m["iat"])!! >= 0) || !(IntentJs.isInt(m["expires_at"]) && IntentJs.num(m["expires_at"])!! >= 0)) return "iat and expires_at must be non-negative safe integers"
        val iat = IntentJs.lng(m["iat"])
        val exp = IntentJs.lng(m["expires_at"])
        if (!(exp > iat)) return "expires_at must be greater than iat"
        if (exp - iat > MAX_LIFETIME_MS) return "an answer lives at most $MAX_LIFETIME_MS ms"
        val nb = if (m["nonce"] is String) Pca.decodeB64uStrict(m["nonce"], -1) else null
        if (nb == null || nb.size < 16) return "nonce must be canonical base64url of at least 16 bytes"
        if (m["sig"] !is String) return "sig must be a string"
        return IntentArtifacts.artifactSuiteError(m)
    }

    /** What an answer must be bound to. */
    class Binding(val policyDigest: String, val actionDigest: String, val historyHead: String)

    /** The result of [verifyAnswer]; a valid `deny` answer is `ok` with `decision == "deny"` (the caller must not admit it). */
    class Verdict(val ok: Boolean, val principal: String?, val decision: String?, val reason: String?) {
        override fun toString(): String = "Escalation.Verdict(ok=$ok, decision=$decision, reason=$reason)"
    }

    private fun no(r: String) = Verdict(false, null, null, r)

    /** Verify an answer against the verifier's pinned principals and the binding of THIS decision. Total. */
    fun verifyAnswer(answer: Any?, principals: List<Principal>, bind: Binding, now: Long): Verdict = try {
        if (Math.abs(now) > 9007199254740991L) no("the verifier clock is not a safe integer (fail closed)")
        else {
            val e = answerShapeError(answer)
            if (e != null) no("malformed escalation answer: $e")
            else {
                val a = IntentJs.obj(answer)
                val pin = principals.firstOrNull { it.pk == a["principal"] }
                when {
                    principals.isEmpty() -> no("no principal is pinned for escalation answers")
                    pin == null -> no("the answering principal is not pinned by this verifier")
                    !IntentArtifacts.verifyArtifactSig(ANSWER_DOMAIN, a, pin.pk, pin.pqPk) -> no("escalation answer signature invalid")
                    a["policy_digest"] != bind.policyDigest -> no("the answer is bound to another policy")
                    a["action_digest"] != bind.actionDigest -> no("the answer is bound to another action")
                    a["history_head"] != bind.historyHead -> no("the answer is bound to another state of the history")
                    now < IntentJs.lng(a["iat"]) -> no("the answer is from the future")
                    now > IntentJs.lng(a["expires_at"]) -> no("the answer has expired")
                    else -> Verdict(true, a["principal"] as String, a["decision"] as String, null)
                }
            }
        }
    } catch (e: RuntimeException) {
        no("escalation answer error (fail closed): ${e.message ?: "unknown"}")
    } catch (e: StackOverflowError) {
        no("escalation answer error (fail closed): unknown")
    }
}
