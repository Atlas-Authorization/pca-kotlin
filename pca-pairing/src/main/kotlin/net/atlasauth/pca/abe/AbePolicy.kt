package net.atlasauth.pca.abe

import java.math.BigDecimal
import java.util.TreeSet
import net.atlasauth.pca.verifier.Json

/**
 * Access structures over attributes: a monotone boolean formula as a threshold tree.
 *
 *  - `{"attr": a}`: leaf, the holder must own the key for attribute a
 *  - `{"allOf": [...]}`: AND (n-of-n)
 *  - `{"anyOf": [...]}`: OR (1-of-n)
 *  - `{"threshold": k, "of": [...]}`: k-of-n
 *
 * The normalised form is a JSON tree: `{"kind":"leaf","attr":a}` or `{"kind":"gate","t":k,"of":[...]}` with `t` a [Long].
 * Negation is not supported (ABE access structures are monotone).
 */
@Suppress("UNCHECKED_CAST")
object AbePolicy {
    /** Upper bound on total nodes in a policy tree (bounds work on untrusted input). */
    const val MAX_POLICY_NODES = 1024

    /**
     * Upper bound on gate nesting along any root-to-leaf path: the ciphertext header is authenticated as canonical JSON
     * (nesting capped at 32), each gate costs three JSON levels and the root sits at level 2, so 10 gates is the most
     * that can be authenticated. Enforcing it here makes "encryptable" imply "decryptable".
     */
    const val MAX_POLICY_DEPTH = 10

    /** Result of [normalize]: `tree` on success, else `reason`. */
    class Result internal constructor(val tree: Map<String, Any?>?, val reason: String?) {
        val ok: Boolean get() = tree != null

        /** The reference's JSON shape: `{ok:true, tree}` or `{ok:false, reason}`. */
        fun toJson(): Map<String, Any?> = linkedMapOf<String, Any?>("ok" to ok).also {
            if (ok) it["tree"] = tree else it["reason"] = reason
        }
    }

    private class Fail(reason: String) : RuntimeException(reason, null, false, false)

    fun leaf(attr: String): Map<String, Any?> = linkedMapOf("kind" to "leaf", "attr" to attr)

    fun gate(t: Long, of: List<Any?>): Map<String, Any?> = linkedMapOf("kind" to "gate", "t" to t, "of" to of)

    /** The value of a JSON number as JavaScript reads it (a double), or null when not a number. */
    internal fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Int, is Long, is Double, is Float -> (o as Number).toDouble()
        else -> null
    }

    /** JavaScript `typeof x === 'number' && Number.isInteger(x) && x > 0`. */
    internal fun isPosInt(o: Any?): Boolean {
        val d = num(o) ?: return false
        return !d.isInfinite() && !d.isNaN() && d == Math.rint(d) && d > 0
    }

    /** JavaScript's String(n) for a positive integral double. */
    internal fun jsInt(d: Double): String {
        if (d < 1e21) return BigDecimal(d).toPlainString()
        val s = d.toString() // e.g. 1.0E21
        val e = s.indexOf('E')
        var m = s.substring(0, e)
        if (m.endsWith(".0")) m = m.substring(0, m.length - 2)
        return m + "e+" + s.substring(e + 1)
    }

    /** Validate and normalise an access structure; fails closed with a reason on any malformed node or oversized tree. */
    fun normalize(policy: Any?): Result = try {
        Result(walk(policy, "policy", 0, IntArray(1)), null)
    } catch (f: Fail) {
        Result(null, f.message)
    }

    private fun walk(p: Any?, path: String, gates: Int, nodes: IntArray): Map<String, Any?> {
        if (++nodes[0] > MAX_POLICY_NODES) throw Fail("policy too large (> $MAX_POLICY_NODES nodes)")
        if (p !is Map<*, *>) throw Fail("$path: not an object")
        val m = p as Map<String, Any?>
        if (m.containsKey("attr")) {
            val a = m["attr"]
            if (a !is String || a.isEmpty()) throw Fail("$path: 'attr' must be a non-empty string")
            if (Json.hasLoneSurrogate(a)) throw Fail("$path: 'attr' is not well-formed UTF-16")
            if (listOf("allOf", "anyOf", "threshold", "of").any { m.containsKey(it) }) throw Fail("$path: a leaf must not mix 'attr' with a gate")
            return leaf(a)
        }
        val gateKeys = listOf("allOf", "anyOf", "threshold", "of").filter { m.containsKey(it) && !(it == "of" && m.containsKey("threshold")) }
        if (gateKeys.size > 1) throw Fail("$path: ambiguous node (${gateKeys.joinToString(", ")}); a gate must use exactly one of allOf/anyOf/threshold")
        if (gateKeys.size == 1 && gates + 1 > MAX_POLICY_DEPTH) throw Fail("$path: policy nested deeper than $MAX_POLICY_DEPTH gates")
        if (m.containsKey("allOf")) {
            val kids = children(m["allOf"], "allOf", path, gates, nodes)
            return gate(kids.size.toLong(), kids)
        }
        if (m.containsKey("anyOf")) return gate(1, children(m["anyOf"], "anyOf", path, gates, nodes))
        if (m.containsKey("threshold")) {
            val t = m["threshold"]
            if (!isPosInt(t)) throw Fail("$path: 'threshold' must be a positive integer")
            val kids = children(m["of"], "of", path, gates, nodes)
            val d = num(t)!!
            if (d > kids.size) throw Fail("$path: threshold ${jsInt(d)} exceeds the number of branches (${kids.size})")
            return gate(d.toLong(), kids)
        }
        throw Fail("$path: unknown policy node (expected attr/allOf/anyOf/threshold)")
    }

    private fun children(raw: Any?, key: String, path: String, gates: Int, nodes: IntArray): List<Any?> {
        if (raw !is List<*> || raw.isEmpty()) throw Fail("$path: '$key' must be a non-empty array")
        return raw.mapIndexed { i, c -> walk(c, "$path.$key[$i]", gates + 1, nodes) }
    }

    internal fun isLeaf(n: Map<String, Any?>): Boolean = n["kind"] == "leaf"

    internal fun of(n: Map<String, Any?>): List<Map<String, Any?>> = n["of"] as List<Map<String, Any?>>

    internal fun t(n: Map<String, Any?>): Int = num(n["t"])!!.toInt()

    /** Non-cryptographic prediction: does the attribute set satisfy the tree? (Enforcement is the cryptography.) */
    fun satisfies(tree: Map<String, Any?>, attrs: Set<String>): Boolean {
        if (isLeaf(tree)) return attrs.contains(tree["attr"] as String)
        return of(tree).count { satisfies(it, attrs) } >= t(tree)
    }

    /** Every attribute the tree names, sorted (UTF-16 code unit order, as the reference sorts). */
    fun policyAttributes(tree: Map<String, Any?>): List<String> {
        val out = TreeSet<String>()
        collect(tree, out)
        return out.toList()
    }

    private fun collect(tree: Map<String, Any?>, into: MutableCollection<String>) {
        if (isLeaf(tree)) into.add(tree["attr"] as String) else for (c in of(tree)) collect(c, into)
    }

    /** Leaf attributes in depth-first order (one span-program row each). */
    internal fun leaves(tree: Map<String, Any?>): List<String> = ArrayList<String>().also { collect(tree, it) }
}
