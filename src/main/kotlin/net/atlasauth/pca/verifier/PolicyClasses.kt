package net.atlasauth.pca.verifier

/**
 * POLICY CLASSES (access is granted only if every consulted policy class allows it): the decision is the meet of the class answers,
 * and the record names who said no. Port of packages/pca/src/policy-classes.ts; replays packages/pca/conformance/policy-classes-vectors.json.
 * Total; never throws.
 */
object PolicyClasses {
    val CLASSES = listOf("constitution", "regulatory", "org", "blueprint", "user")
    private val DECISIONS = listOf("allow", "escalate", "deny")

    class Verdict(val cls: String, val revision: Long, val digest: String, val decision: String)

    class Result(val decision: String, val classes: List<Verdict>, val deniedBy: List<String>, val escalatedBy: List<String>, val reason: String? = null)

    /** Null = a well-formed list: closed members, known classes, each at most once. */
    @JvmStatic
    fun classVerdictsError(list: Any?): String? {
        val l = K3Sig.list(list) ?: return "policy classes must be an array"
        if (l.size > CLASSES.size) return "more than ${CLASSES.size} policy classes"
        val seen = HashSet<String>()
        for ((i, x) in l.withIndex()) {
            val v = K3Sig.map(x) ?: return "policy_classes[$i] must be an object"
            for (k in v.keys) if (k != "class" && k != "revision" && k != "digest" && k != "decision") return "policy_classes[$i] has unknown member '$k'"
            val c = v["class"]
            if (c !is String || c !in CLASSES) return "policy_classes[$i].class is not a known class"
            if (!seen.add(c)) return "policy class '$c' appears twice"
            if (!K3Sig.isSafeInt(v["revision"])) return "policy_classes[$i].revision must be a non-negative safe integer"
            if (!K3Sig.isStr(v["digest"], 128)) return "policy_classes[$i].digest invalid"
            if (v["decision"] !in DECISIONS) return "policy_classes[$i].decision must be allow, escalate or deny"
        }
        return null
    }

    @JvmStatic
    fun decideClasses(list: Any?): Result {
        try {
            if (list is List<*> && list.isEmpty()) return Result("deny", emptyList(), emptyList(), emptyList(), "no_policy_class")
            val e = classVerdictsError(list)
            if (e != null) return Result("deny", emptyList(), emptyList(), emptyList(), "malformed policy classes: $e")
            val classes = K3Sig.list(list)!!.map { x ->
                val v = K3Sig.map(x)!!
                Verdict(v["class"] as String, IntentJs.lng(v["revision"]), v["digest"] as String, v["decision"] as String)
            }.sortedBy { CLASSES.indexOf(it.cls) }
            var d = "allow"
            for (c in classes) d = PcaDecision.meet(d, c.decision)
            return Result(d, classes, classes.filter { it.decision == "deny" }.map { it.cls }, classes.filter { it.decision == "escalate" }.map { it.cls })
        } catch (e: RuntimeException) {
            return Result("deny", emptyList(), emptyList(), emptyList(), "evaluation error (fail closed)")
        }
    }
}
