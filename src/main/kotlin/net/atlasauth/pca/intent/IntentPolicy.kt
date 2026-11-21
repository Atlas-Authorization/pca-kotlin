package net.atlasauth.pca.intent

import net.atlasauth.pca.analyzer.Enumerate
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.AttestUtil

/** Policy plumbing: an outcome as the analyzer's concrete action, and the real evaluator as an admission oracle. */
@Suppress("UNCHECKED_CAST")
object IntentPolicy {
    /** Default resource string when the space has no resource dimension for a verb. */
    const val ANY_RESOURCE = "resource:any"

    /** {predicates, caveats} of a policy: a non-array member counts as empty. */
    fun normalizePolicy(p: Any?): MutableMap<String, Any?> {
        // `p && 'caveats' in p`: a truthy primitive makes `in` throw
        if (p != null && p !is Map<*, *> && p !is List<*> && net.atlasauth.pca.jose.Js.truthy(p)) throw IllegalArgumentException("Cannot use 'in' operator to search for 'caveats' in " + net.atlasauth.pca.jose.Js.template(p))
        val preds = if (p is Map<*, *>) p["predicates"] else null
        val cavs = if (p is Map<*, *>) p["caveats"] else null
        val out = LinkedHashMap<String, Any?>()
        out["predicates"] = if (preds is List<*>) preds else ArrayList<Any?>()
        out["caveats"] = if (cavs is List<*>) cavs else ArrayList<Any?>()
        return out
    }

    private fun setPath(root: MutableMap<String, Any?>, segs: List<String>, from: Int, value: Any?) {
        var cur = root
        for (i in from until segs.size - 1) {
            if (cur[segs[i]] !is Map<*, *>) cur[segs[i]] = LinkedHashMap<String, Any?>()
            cur = cur[segs[i]] as MutableMap<String, Any?>
        }
        cur[segs[segs.size - 1]] = value
    }

    internal fun jsString(v: Any?): String = if (v is Double) AttestUtil.jsNumString(v) else v.toString()

    /** The outcome as the analyzer's concrete action (params / env / subject trees, reversibility from the space). */
    fun outcomeToAction(vs: VerbSpace, o: Outcome): MutableMap<String, Any?> {
        val params = LinkedHashMap<String, Any?>()
        val env = LinkedHashMap<String, Any?>()
        val subject = LinkedHashMap<String, Any?>()
        var resource = ANY_RESOURCE
        for ((path, value) in o.values) {
            val segs = path.split(".")
            if (path == "action.resource") resource = jsString(value)
            else if (segs[0] == "action" && segs.size > 2 && segs[1] == "params") setPath(params, segs, 2, value)
            else if (segs[0] == "env" && segs.size > 1) setPath(env, segs, 1, value)
            else if (segs[0] == "subject" && segs.size > 1) setPath(subject, segs, 1, value)
        }
        val a = LinkedHashMap<String, Any?>()
        a["verb"] = o.verb
        a["resource"] = resource
        a["params"] = params
        a["reversibilityClass"] = vs.reversibility
        if (env.isNotEmpty()) a["env"] = env
        if (subject.isNotEmpty()) a["subject"] = subject
        return a
    }

    /** A compiled admission oracle for one policy (compile once, query many times). */
    fun interface Admitter {
        fun admits(vs: VerbSpace, o: Outcome): Boolean
    }

    fun admitter(policy: Any?): Admitter {
        val model = Enumerate.toModel(policy)
        return Admitter { vs, o -> Enumerate.admitsAction(model, outcomeToAction(vs, o)) }
    }

    fun vsOf(omega: Omega, o: Outcome): VerbSpace? = omega.verbs.firstOrNull { it.verb == o.verb }
}
