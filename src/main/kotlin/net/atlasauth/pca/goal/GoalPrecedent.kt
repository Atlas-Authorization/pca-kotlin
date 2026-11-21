package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Escalation
import net.atlasauth.pca.verifier.Pca

/**
 * Progressive authorization. Widening is only by an escalation request answered by a principal-signed answer; a verified answer
 * becomes an append-only hash-chained precedent bound to (policy digest, decision cell, the answered action's exact quantities
 * as a ceiling). A recorded cell decision is never flipped except by a principal-signed revocation; a deny is never turned into
 * an allow (precedents act only on escalate). Entries, answers and answered cases are parsed-JSON maps.
 */
@Suppress("UNCHECKED_CAST")
object GoalPrecedent {
    private fun mm(o: Any?): Map<String, Any?>? = G.m(o)

    private fun unitKey(q: Map<String, Any?>?): String {
        val u = mm(q?.get("u"))
        return if (G.kind(u) == "money") "money:" + G.jsStr(u!!["ccy"]) else G.kind(u)
    }

    /** Ceilings are keyed by parameter AND unit (kind + currency): a EUR answer never covers a GBP action. */
    @JvmStatic
    fun ceilingsOf(params: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for ((k, value) in params) {
            val v = mm(value)
            if (G.kind(v) == "q") {
                val q = mm(v!!["q"])
                out[k + "|" + unitKey(q)] = q!!["n"]
            }
        }
        return out
    }

    private fun caseOf(a: Map<String, Any?>): Map<String, Any?> {
        val act = mm(mm(a["pcactn"])!!["action"])!!
        return G.map("act" to GoalExamples.mkAct(act["verb"] as String?, act["resource"] as String?, mm(a["params"])), "rels" to a["rels"])
    }

    @JvmStatic
    fun signRevocation(p: Map<String, Any?>, seed: ByteArray): Map<String, Any?> = GoalSign.signPayload("precedent-revocation", p, seed)

    /** The answer body for a request: bound to the request's exact (policy, action, history head). Sign it with the escalation signer. */
    @JvmStatic
    fun answerBodyFor(req: Map<String, Any?>, principal: String, decision: String, iat: Any?, expiresAt: Any?, nonce: String): Map<String, Any?> =
        G.map(
            "v" to G.num(1), "kind" to "pca-escalation-answer", "principal" to principal, "policy_digest" to req["policy_digest"], "action_digest" to req["action_digest"],
            "history_head" to req["history_head"], "decision" to decision, "iat" to iat, "expires_at" to expiresAt, "nonce" to nonce,
        )

    private val GENESIS = "0".repeat(64)

    private fun entryDigest(e: Map<String, Any?>): String {
        val answered = e["answered"]
        var answeredOut: Any? = null
        if (G.truthy(answered)) {
            val a = LinkedHashMap(mm(answered)!!)
            if (a["lastCounter"] == null) a["lastCounter"] = null
            answeredOut = a
        }
        return Pca.hashCanonical(
            G.map(
                "d" to "atlas-pca/goal-precedent-entry/v1", "seq" to e["seq"], "prev" to e["prev"], "kind" to e["kind"],
                "answer" to e["answer"], "answered" to answeredOut, "cell" to e["cell"], "ceilings" to e["ceilings"], "revocation" to e["revocation"],
            ),
        )
    }

    private fun ok(entry: Any?): Map<String, Any?> = G.map("ok" to true, "entry" to entry)
    private fun no(reason: String?): Map<String, Any?> = G.map("ok" to false, "reason" to reason)

    /** The append-only precedent log of one verifier, which pins the principals allowed to answer and revoke. */
    class Log(private val principals: List<*>) {
        private val entries = ArrayList<MutableMap<String, Any?>>()

        fun entries(): MutableList<MutableMap<String, Any?>> = entries

        fun head(): String = if (entries.isEmpty()) GENESIS else entries[entries.size - 1]["digest"] as String

        private fun pinFor(pk: String): Any? {
            for (p in principals) if (pk == (if (p is String) p else G.get(p, "pk"))) return p
            return null
        }

        private fun escPrincipals(): List<Escalation.Principal> {
            val out = ArrayList<Escalation.Principal>()
            for (p in principals) {
                if (p is String) out.add(Escalation.Principal(p))
                else if (p is Map<*, *> && p["pk"] is String) out.add(Escalation.Principal(p["pk"] as String, p["pq_pk"] as? String))
            }
            return out
        }

        /** Everything about an answer that does not depend on the clock. Null = sound. */
        private fun answerFault(answer: Map<String, Any?>, answered: Map<String, Any?>): String? {
            if (Escalation.answerShapeError(answer) != null) return "malformed answer"
            val pin = pinFor(answer["principal"] as String)
            if (pin == null || !GoalSign.verifyArtifactSig(Escalation.ANSWER_DOMAIN, answer, pin)) return "bad signature"
            val pcactn = mm(answered["pcactn"])!!
            if (answer["action_digest"] != Escalation.actionDigest(pcactn)) return "answer is bound to another action"
            val lc = G.safeInt(answered["lastCounter"])
            if (answer["history_head"] != Escalation.historyHead(lc)) return "answer is bound to another history state"
            if (Pca.paramsDigest(answered["params"]) != mm(pcactn["action"])!!["params_digest"]) return "params do not match the signed action"
            return null
        }

        /** Recompute the whole chain, every signature and binding, and every derived cell and ceiling under [space]. */
        fun verifyChain(space: GoalExamples.Space): Boolean {
            try {
                var prev = GENESIS
                for (i in entries.indices) {
                    val e = entries[i]
                    val seq = G.safeInt(e["seq"])
                    if (seq == null || seq != i.toLong() || prev != e["prev"] || entryDigest(e) != e["digest"]) return false
                    if ("answer" == e["kind"]) {
                        val answer = mm(e["answer"])
                        val answered = mm(e["answered"])
                        if (answer == null || answered == null || answerFault(answer, answered) != null) return false
                        if (e["cell"] != GoalExamples.cellKey(space, caseOf(answered)) ||
                            G.stringify(e["ceilings"]) != G.stringify(ceilingsOf(mm(answered["params"])!!))
                        ) return false
                    } else if (!(G.truthy(e["revocation"]) && GoalSign.verifyPayload(mm(e["revocation"]), "precedent-revocation", principals))) return false
                    prev = e["digest"] as String
                }
                return true
            } catch (ex: RuntimeException) {
                return false
            }
        }

        private fun live(policy: Any?, cell: Any?, now: Double): Map<String, Any?>? {
            val revoked = HashSet<Any?>()
            for (e in entries) if ("revocation" == e["kind"]) revoked.add(mm(mm(e["revocation"])!!["payload"])!!["target_entry"])
            for (i in entries.indices.reversed()) {
                val e = entries[i]
                if ("answer" != e["kind"]) continue
                val a = mm(e["answer"])!!
                if (a["policy_digest"] == policy && e["cell"] == cell && G.toNum(a["expires_at"]) > now && !revoked.contains(e["digest"])) return e
            }
            return null
        }

        /** Verify the answer (pinned signer, bound to this grant's policy digest, this exact action and history, unexpired) and record it: {ok, entry | reason}. */
        fun append(answer: Map<String, Any?>, answered: Map<String, Any?>, grant: Map<String, Any?>, space: GoalExamples.Space, now: Long): Map<String, Any?> {
            val bind = Escalation.Binding(Escalation.policyDigest(grant), Escalation.actionDigest(mm(answered["pcactn"])), Escalation.historyHead(G.safeInt(answered["lastCounter"])))
            val v = Escalation.verifyAnswer(answer, escPrincipals(), bind, now)
            if (!v.ok) return no(v.reason)
            val fault = answerFault(answer, answered)
            if (fault != null) return no(fault)
            val cell = GoalExamples.cellKey(space, caseOf(answered))
            val existing = live(answer["policy_digest"], cell, now.toDouble())
            if (existing != null && mm(existing["answer"])!!["decision"] != answer["decision"]) return no("conflicts with a recorded decision; revoke it first")
            val fields = LinkedHashMap<String, Any?>()
            fields["kind"] = "answer"
            fields["answer"] = answer
            fields["answered"] = answered
            fields["cell"] = cell
            fields["ceilings"] = ceilingsOf(mm(answered["params"])!!)
            return ok(push(fields))
        }

        fun revoke(rev: Map<String, Any?>): Map<String, Any?> {
            if (!GoalSign.verifyPayload(rev, "precedent-revocation", principals)) return no("bad signature")
            val p = mm(rev["payload"])!!
            var found = false
            for (e in entries) {
                if ("answer" == e["kind"] && e["digest"] == p["target_entry"] && mm(e["answer"])!!["policy_digest"] == p["policy_digest"] && e["cell"] == p["cell"]) found = true
            }
            if (!found) return no("no such precedent")
            val fields = LinkedHashMap<String, Any?>()
            fields["kind"] = "revocation"
            fields["revocation"] = rev
            return ok(push(fields))
        }

        private fun push(fields: Map<String, Any?>): Map<String, Any?> {
            val base = LinkedHashMap<String, Any?>()
            base["seq"] = G.num(entries.size)
            base["prev"] = head()
            for ((k, v) in fields) if (v != null) base[k] = v
            val entry = LinkedHashMap(base)
            entry["digest"] = entryDigest(base)
            entries.add(entry)
            return entry
        }

        /** The recorded decision covering this case under this policy, or null: {decision, entry}. */
        fun lookup(policyDigest: String, space: GoalExamples.Space, c: Map<String, Any?>, now: Double): Map<String, Any?>? {
            val e = live(policyDigest, GoalExamples.cellKey(space, c), now) ?: return null
            val ceil = mm(e["ceilings"])!!
            val now2 = ceilingsOf(mm(mm(c["act"])!!["params"])!!)
            for ((k, value) in now2) {
                val cap = ceil[k]
                val limit = if (cap == null) Double.NEGATIVE_INFINITY else G.toNum(cap)
                if (G.toNum(value) > limit) return null
            }
            for (k in ceil.keys) if (!now2.containsKey(k)) return null
            return G.map("decision" to mm(e["answer"])!!["decision"], "entry" to e)
        }
    }

    /** Policy decision refined by precedents: {decision, via, precedent?}. Precedents act only on escalate; a recorded deny also tightens. */
    @JvmStatic
    fun authorizeWithPrecedents(goal: Map<String, Any?>, ont: Map<String, Any?>, policyDigest: String, log: Log, c: Map<String, Any?>, now: Double): Map<String, Any?> {
        val base = GoalExamples.decideCase(goal, ont, c)["decision"] as String
        if (base != "escalate") return G.map("decision" to base, "via" to "policy")
        val space = GoalExamples.buildSpace(listOf(goal), ArrayList())
        if (!log.verifyChain(space)) return G.map("decision" to "escalate", "via" to "policy")
        val hit = log.lookup(policyDigest, space, c, now) ?: return G.map("decision" to "escalate", "via" to "policy")
        return G.map("decision" to (if ("allow" == hit["decision"]) "allow" else "deny"), "via" to "precedent", "precedent" to hit["entry"])
    }
}
