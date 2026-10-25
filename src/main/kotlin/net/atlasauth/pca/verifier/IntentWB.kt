package net.atlasauth.pca.verifier

/**
 * The W-B checks of an Intent Layer v2 verifier (packages/pca/src/intent-env.ts `decideIntentWB`): rules 16 (`facts`),
 * 17 (`provenance`) and 18 (`classes`) in that order. Each is REPORTED only when its member is present or its policy is
 * active; the first failing check denies and later checks are not reported. A rule-17 `question` continues (outcome
 * `question`). Never throws.
 */
object IntentWB {
    /** The W-B result. `checks`: insertion order facts, provenance, classes; values pass / question / fail. */
    class Result {
        var outcome: String = "admit"
        val checks: LinkedHashMap<String, String> = LinkedHashMap()
        var world: Map<String, Any?>? = null
        var prov: Map<String, Any?>? = null
        var cls: Map<String, Any?>? = null
        var reason: String? = null
        var friction: String? = null
        var singleSource: List<String>? = null
    }

    /**
     * Run rules 16-18 over `input` = `{now, aud, session, action:{verb,resource,params}, intent_session:{facts?, offer_set?,
     * prov?, classes?, labels?}, artifacts?:{facts?, offer_set?, labels?, verdicts?}, policy:{world?, provenance?,
     * classifiers?}}` (already normalized; an absent key is undefined).
     */
    fun decide(input: Map<String, Any?>): Result {
        val out = Result()
        val ce = contextError(input)
        if (ce != null) return deny(out, "facts", "facts: the W-B context is malformed: $ce")
        val s = input["intent_session"]
        val a = IntentJs.opt(input, "artifacts", LinkedHashMap<String, Any?>())
        val policy = IntentJs.opt(input, "policy", LinkedHashMap<String, Any?>())
        val worldPolicy = IntentJs.opt(policy, "world", LinkedHashMap<String, Any?>())

        val committed = LinkedHashMap<String, Any?>()
        if (IntentJs.own(s, "facts")) committed["facts"] = IntentJs.get(s, "facts")
        if (IntentJs.own(s, "offer_set")) committed["offer_set"] = IntentJs.get(s, "offer_set")
        if (OracleFacts.intentWorldActive(committed, worldPolicy)) {
            val wi = LinkedHashMap<String, Any?>()
            wi["now"] = input["now"]
            wi["aud"] = input["aud"]
            wi["session"] = input["session"]
            wi["action"] = input["action"]
            wi["committed"] = committed
            if (IntentJs.own(a, "facts")) wi["facts"] = IntentJs.get(a, "facts")
            if (IntentJs.own(a, "offer_set")) wi["offer_set"] = IntentJs.get(a, "offer_set")
            wi["policy"] = worldPolicy
            val w = OracleFacts.decide(wi)
            if (!w.ok) return deny(out, "facts", w.reason!!)
            out.checks["facts"] = "pass"
            out.world = w.world
            if (w.singleSource!!.isNotEmpty()) out.singleSource = w.singleSource
        }
        val labels = IntentJs.get(s, "labels")
        if (provenanceActive(s, policy)) {
            val pi = LinkedHashMap<String, Any?>()
            if (input.containsKey("aud")) pi["aud"] = input["aud"]
            pi["session"] = input["session"]
            pi["action"] = input["action"]
            if (IntentJs.own(s, "prov")) pi["prov"] = IntentJs.get(s, "prov")
            if (IntentJs.own(s, "labels")) pi["committed_labels"] = labels
            if (IntentJs.own(a, "labels")) pi["labels"] = IntentJs.get(a, "labels")
            pi["policy"] = IntentJs.opt(policy, "provenance", linkedMapOf<String, Any?>("params" to LinkedHashMap<String, Any?>()))
            val p = ParamProvenance.decideNormalized(pi)
            if (p.outcome == "deny") return deny(out, "provenance", p.reason!!)
            out.checks["provenance"] = if (p.outcome == "question") "question" else "pass"
            out.prov = p.env
            if (p.outcome == "question") {
                out.outcome = "question"
                out.reason = p.reason
                out.friction = p.friction
            }
        }
        val clsPolicy = linkedMapOf<String, Any?>("classifiers" to IntentJs.opt(policy, "classifiers", ArrayList<Any?>()))
        val committedClasses = IntentJs.get(s, "classes")
        if (IntentClassifier.classifierCheckActive(committedClasses, clsPolicy)) {
            val ci = LinkedHashMap<String, Any?>()
            ci["session"] = input["session"]
            ci["action"] = input["action"]
            if (IntentJs.own(s, "classes")) ci["committed"] = committedClasses
            if (IntentJs.own(a, "verdicts")) ci["verdicts"] = IntentJs.get(a, "verdicts")
            ci["policy"] = clsPolicy
            val c = IntentClassifier.decideNormalized(ci)
            if (!c.ok) return deny(out, "classes", c.reason!!)
            out.checks["classes"] = "pass"
            out.cls = c.classes
        }
        return out
    }

    /**
     * The W-B context (absent = empty; present with null or the wrong JSON type = malformed): `intent_session` an object;
     * `artifacts` an object whose `facts`, `labels`, `verdicts` are arrays and `offer_set` an object; `policy` an object
     * whose `world`, `provenance` are objects and `classifiers` an array.
     */
    internal fun contextError(input: Map<String, Any?>): String? {
        if (input["intent_session"] !is Map<*, *>) return "intent_session must be an object"
        if (input.containsKey("artifacts")) {
            val a = input["artifacts"]
            if (a !is Map<*, *>) return "artifacts must be an object"
            val am = IntentArtifacts.closedMembers(IntentJs.obj(a), listOf(), listOf("facts", "labels", "verdicts", "offer_set"), "artifacts")
            if (am != null) return am
            for (k in listOf("facts", "labels", "verdicts")) if (IntentJs.own(a, k) && IntentJs.get(a, k) !is List<*>) return "artifacts.$k must be an array"
            if (IntentJs.own(a, "offer_set") && IntentJs.get(a, "offer_set") !is Map<*, *>) return "artifacts.offer_set must be an object"
        }
        if (input.containsKey("policy")) {
            val p = input["policy"]
            if (p !is Map<*, *>) return "policy must be an object"
            val pm = IntentArtifacts.closedMembers(IntentJs.obj(p), listOf(), listOf("world", "provenance", "classifiers"), "policy")
            if (pm != null) return pm
            for (k in listOf("world", "provenance")) if (IntentJs.own(p, k) && IntentJs.get(p, k) !is Map<*, *>) return "policy.$k must be an object"
            if (IntentJs.own(p, "classifiers") && IntentJs.get(p, "classifiers") !is List<*>) return "policy.classifiers must be an array"
        }
        return null
    }

    /** Rule 17 is active iff `prov` is present (any value), `labels` a non-empty array, or the policy a plain object. */
    fun provenanceActive(intentSession: Any?, policy: Any?): Boolean =
        IntentJs.own(intentSession, "prov") || OracleFacts.nonEmpty(IntentJs.get(intentSession, "labels")) || IntentJs.get(policy, "provenance") is Map<*, *>

    /** The `primitives.intent_wb_active` entry point: which of facts / provenance / classes are reported. */
    fun active(input: Any?): BooleanArray {
        val inp = IntentJs.obj(IntentJs.normalize(input))
        val s = IntentJs.opt(inp, "intent_session", LinkedHashMap<String, Any?>())
        val p = IntentJs.opt(inp, "policy", LinkedHashMap<String, Any?>())
        val committed = LinkedHashMap<String, Any?>()
        if (IntentJs.own(s, "facts")) committed["facts"] = IntentJs.get(s, "facts")
        if (IntentJs.own(s, "offer_set")) committed["offer_set"] = IntentJs.get(s, "offer_set")
        val clsPolicy = linkedMapOf<String, Any?>("classifiers" to IntentJs.get(p, "classifiers"))
        return booleanArrayOf(
            OracleFacts.intentWorldActive(committed, IntentJs.opt(p, "world", LinkedHashMap<String, Any?>())),
            provenanceActive(s, p),
            IntentClassifier.classifierCheckActive(IntentJs.get(s, "classes"), clsPolicy),
        )
    }

    private fun deny(out: Result, check: String, reason: String): Result {
        out.outcome = "deny"
        out.checks[check] = "fail"
        out.reason = reason
        out.world = null
        out.prov = null
        out.cls = null
        out.friction = null
        out.singleSource = null
        return out
    }
}
