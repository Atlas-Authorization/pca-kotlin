package net.atlasauth.pca.research

import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.StoreJs

/**
 * Data-flow governance, DLP for agents: declare data classes (a resource matcher plus the maximum taint that may flow to them autonomously) and
 * evaluate an action's provenance against them. Pure and offline. An ADVISORY HEURISTIC: taint levels are labels something upstream attached; this
 * checks them against ceilings and never tracks data through a program.
 *
 * A policy is `{classes: [{name, resource, verbs?, maxTaintForAuto, hardDenyAbove?}], defaultMaxTaintForAuto?}`; a context is
 * `{verb, resource, taint, trustedRefs?}`; a result is `{outcome: allow|step_up|deny, class?, reason?}`.
 */
@Suppress("UNCHECKED_CAST")
object Dlp {
    private fun isNum(x: Any?): Boolean = IntentJs.num(x)?.let { !it.isNaN() } == true
    private fun d(x: Any?): Double = IntentJs.num(x)!!
    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>
    private fun jsNum(x: Double): String = AttestUtil.jsNumString(x)

    private fun truthy(v: Any?): Boolean {
        if (v == null) return false
        if (v is Boolean) return v
        if (v is String) return v.isNotEmpty()
        val x = IntentJs.num(v) ?: return true
        return !(x == 0.0 || x.isNaN())
    }

    // JavaScript String(v) of a parsed JSON value, for the few places a value is spliced into text
    private fun str(v: Any?): String = when (v) {
        null -> "null"
        is String -> v
        is Json.Num -> IntentJs.num(v)?.let { jsNum(it) } ?: v.raw
        is Boolean -> v.toString()
        is List<*> -> v.joinToString(",") { if (it == null) "" else str(it) }
        else -> "[object Object]"
    }

    private fun matches(pattern: Any?, resource: Any?): Boolean {
        if ("*" == pattern) return true
        if (pattern !is String) throw IllegalArgumentException("DLP: a class resource must be a string")
        if (pattern.endsWith("*")) {
            if (resource !is String) throw IllegalArgumentException("DLP: the resource must be a string")
            return resource.startsWith(pattern.substring(0, pattern.length - 1))
        }
        return pattern == resource
    }

    private fun specificity(pattern: String): Double {
        if (pattern == "*") return 0.0
        if (pattern.endsWith("*")) return (pattern.length - 1).toDouble()
        return (pattern.length + 1000).toDouble() // exact beats any prefix
    }

    // a malformed ceiling sorts first, so the policy then denies instead of picking a lenient sibling; an absent ceiling (unconstrained) sorts last
    private fun strictness(c: Map<String, Any?>): Double {
        val m = c["maxTaintForAuto"]
        if (m == null && !c.containsKey("maxTaintForAuto")) return Double.POSITIVE_INFINITY
        return if (isNum(m)) d(m) else Double.NEGATIVE_INFINITY
    }

    private fun verbMatches(c: Map<String, Any?>, verb: Any?): Boolean {
        val vs = c["verbs"]
        if (!truthy(vs)) return true
        if (vs is List<*>) return vs.contains(verb)
        if (vs is String) return vs.contains(if (verb is String) verb else str(verb))
        throw IllegalArgumentException("DLP: verbs must be a list")
    }

    private fun cmp(x: Double): Int = if (x.isNaN() || x == 0.0) 0 else if (x < 0) -1 else 1

    /** The most specific matching class (longest non-wildcard prefix wins, exact beats prefix); of equals the STRICTEST wins. Null for none. */
    private fun classFor(classes: List<*>, ctx: Map<String, Any?>): Map<String, Any?>? {
        val applicable = ArrayList<Map<String, Any?>>()
        for (o in classes) {
            val c = map(o) ?: throw IllegalArgumentException("DLP: a class must be an object")
            if (matches(c["resource"], ctx["resource"]) && verbMatches(c, ctx["verb"])) applicable.add(c)
        }
        if (applicable.isEmpty()) return null
        applicable.sortWith(Comparator { a, b ->
            val s = cmp(specificity(b["resource"] as String) - specificity(a["resource"] as String))
            if (s != 0) s else cmp(strictness(a) - strictness(b))
        })
        return applicable[0]
    }

    private fun has(m: Map<String, Any?>, k: String): Boolean = m[k] != null || m.containsKey(k)

    // A ceiling that is present but not a number would make every comparison false and allow everything.
    private fun malformed(policy: Map<String, Any?>, cls: Map<String, Any?>?): Boolean {
        if (cls != null) return (has(cls, "maxTaintForAuto") && !isNum(cls["maxTaintForAuto"])) || (has(cls, "hardDenyAbove") && !isNum(cls["hardDenyAbove"]))
        return has(policy, "defaultMaxTaintForAuto") && !isNum(policy["defaultMaxTaintForAuto"])
    }

    private fun result(outcome: String, cls: Map<String, Any?>?, reason: String?): Map<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["outcome"] = outcome
        if (cls != null && cls.containsKey("name")) r["class"] = cls["name"]
        if (reason != null) r["reason"] = reason
        return r
    }

    /**
     * Evaluate an action's data flow against the DLP policy. Fails CLOSED: a malformed policy or ceiling is a deny, and a taint that is not a
     * finite number is treated as maximally tainted so it can never beat a ceiling.
     */
    @JvmStatic
    fun evaluateDlp(policy: Map<String, Any?>?, ctx: Map<String, Any?>): Map<String, Any?> {
        if (policy == null || policy["classes"] !is List<*>) return result("deny", null, "malformed DLP policy")
        val cls = classFor(policy["classes"] as List<*>, ctx)
        if (malformed(policy, cls)) return result("deny", cls, "malformed DLP policy: ceilings must be numbers")
        val max = if (cls != null) cls["maxTaintForAuto"] else policy["defaultMaxTaintForAuto"]
        val hasMax = if (cls != null) has(cls, "maxTaintForAuto") else has(policy, "defaultMaxTaintForAuto")
        val bad = !IntentJs.isFinite(ctx["taint"])
        val taint = if (!bad) d(ctx["taint"]) else Double.POSITIVE_INFINITY
        if (!hasMax) return result("allow", cls, null) // no ceiling at all: nothing to compare against
        val m = d(max)
        val label = if (cls != null && cls["name"] != null) str(cls["name"]) else "<default>"
        if (cls != null && has(cls, "hardDenyAbove") && (bad || taint > d(cls["hardDenyAbove"])))
            return result("deny", cls, "taint " + jsNum(taint) + " exceeds hard ceiling " + jsNum(d(cls["hardDenyAbove"])) + " for '" + label + "'")
        if (bad || taint > m) return result("step_up", cls, "taint " + jsNum(taint) + " > " + jsNum(m) + " for '" + label + "' — needs human review")
        return result("allow", cls, null)
    }

    /** Preset with no options: no classes. */
    @JvmStatic
    fun defaultDlpPolicy(): Map<String, Any?> = defaultDlpPolicy(LinkedHashMap())

    /** Preset: PII resources accept only clean (taint 0) autonomously; secrets hard-deny any taint. [opts] is `{piiResource?, secretsResource?}`. */
    @JvmStatic
    fun defaultDlpPolicy(opts: Map<String, Any?>): Map<String, Any?> {
        val classes = ArrayList<Any?>()
        if (truthy(opts["piiResource"])) classes.add(cls("pii", opts["piiResource"], 0, 2))
        if (truthy(opts["secretsResource"])) classes.add(cls("secrets", opts["secretsResource"], 0, 0))
        val p = LinkedHashMap<String, Any?>()
        p["classes"] = classes
        return p
    }

    private fun cls(name: String, resource: Any?, max: Long, hard: Long): Map<String, Any?> {
        val c = LinkedHashMap<String, Any?>()
        c["name"] = name
        c["resource"] = resource
        c["maxTaintForAuto"] = StoreJs.num(max)
        c["hardDenyAbove"] = StoreJs.num(hard)
        return c
    }
}
