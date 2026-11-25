package net.atlasauth.pca.verifier

/**
 * L4 information-flow taint (spec section 6) and the `enforce.taint` gate: a port of packages/pca/src/taint.ts. The agent's own label is
 * never read: every declared provenance ref is re-classified from facts the SERVER holds (a trusted-input registry it populated, or its own
 * committed resource graph); a ref the server cannot vouch for is `agent` (the worst case). Malformed or absent provenance and any internal
 * error fail CLOSED to taint 1.
 */
@Suppress("UNCHECKED_CAST")
object Taint {
    val LEVELS = listOf("trusted", "first_party", "tool", "web", "agent")
    private val MAX_RANK = LEVELS.size - 1

    /** The server's trusted-input registry: digest -> label (`{kind, id?}`). Only the server populates it. */
    fun interface Registry {
        fun lookup(ref: String): Map<String, Any?>?
    }

    /** The server's committed resource graph: a node it knows is first-party. */
    fun interface ResourceGraph {
        fun node(ref: String): Any?
    }

    class InMemoryRegistry : Registry {
        private val m = HashMap<String, Map<String, Any?>>()

        /** Server-only. A digest that is not a non-empty string, or a label whose kind is not a level, is ignored (as the reference does). */
        @Synchronized
        fun record(digest: Any?, label: Any?): InMemoryRegistry {
            if (digest is String && digest.isNotEmpty() && label is Map<*, *> && isTaintLevel(label["kind"])) m[digest] = LinkedHashMap(label as Map<String, Any?>)
            return this
        }

        fun recordTrusted(digest: Any?) = record(digest, mapOf("kind" to "trusted"))
        fun recordFirstParty(digest: Any?) = record(digest, mapOf("kind" to "first_party"))
        fun recordTool(digest: Any?, id: Any?) = record(digest, mapOf("kind" to "tool", "id" to id))
        fun recordWeb(digest: Any?) = record(digest, mapOf("kind" to "web"))

        @Synchronized
        override fun lookup(ref: String): Map<String, Any?>? = m[ref]?.let { LinkedHashMap(it) }
        val size: Int @Synchronized get() = m.size
    }

    /** The `enforce.taint` option: the registry, the resource graph and the largest taint (0..1) the policy accepts. */
    class Gate @JvmOverloads constructor(val registry: Registry?, val maxTaint: Double?, val resourceGraph: ResourceGraph? = null)

    /** The empty registry: vouches for nothing (every ref falls through to the resource graph / worst case). */
    @JvmField
    val EMPTY_REGISTRY: Registry = Registry { null }

    /** Bottom of the lattice: the most-trusted label. */
    @JvmField
    val BOTTOM: Map<String, Any?> = mapOf("kind" to "trusted")

    /** Top of the lattice: the least-trusted label (fail-closed / worst case). */
    @JvmField
    val TOP: Map<String, Any?> = mapOf("kind" to "agent")

    /** True only for the five real level names (an own-member test: `constructor`, `__proto__`, `toString` are not levels). */
    fun isTaintLevel(kind: Any?): Boolean = kind is String && kind in LEVELS

    /** Rank of a label; an unknown, missing or non-string kind (or a label that is no object) is the WORST rank (fail closed). */
    fun labelRank(label: Any?): Int {
        val kind = (label as? Map<*, *>)?.get("kind")
        return if (isTaintLevel(kind)) LEVELS.indexOf(kind) else MAX_RANK
    }

    /** Normalized taint value of a label in [0,1]: trusted 0, first_party 0.25, tool 0.5, web 0.75, agent 1. */
    fun taintValue(label: Any?): Double = labelRank(label).toDouble() / MAX_RANK

    private val NO_ID = Any()

    /** `Object.hasOwn(l, 'id') ? l.id : undefined`; null / undefined labels throw as the reference does. */
    private fun labelId(l: Any?): Any? {
        if (l == null) throw IllegalArgumentException("Cannot convert undefined or null to object")
        if (l !is Map<*, *> || !l.containsKey("id")) return NO_ID
        return l["id"]
    }

    /** Least-upper-bound of two labels: the higher rank wins as it is; equal ranks keep the `id` only when both agree, else `{kind}`. A null label throws. */
    fun joinLabel(a: Any?, b: Any?): Any? {
        val ra = labelRank(a)
        val rb = labelRank(b)
        if (ra > rb) return a
        if (rb > ra) return b
        if (labelId(a) == labelId(b)) return a
        val m = LinkedHashMap<String, Any?>()
        if (a is Map<*, *> && a.containsKey("kind")) m["kind"] = a["kind"]
        return m
    }

    /** Join over a list of labels; the EMPTY lineage joins to the top (no verifiable trusted input is not "trusted"). */
    fun joinLabels(labels: List<Any?>): Any? = if (labels.isEmpty()) LinkedHashMap(TOP) else labels.reduce { acc, l -> joinLabel(acc, l) }

    /**
     * Independently classify ONE declared ref: server-vouched in [registry] gives the registered label; naming a node of [graph] gives
     * `first_party`; else `agent` (with the ref as id when it is at most 128 UTF-16 units). A non-string or empty ref is `agent`. A registry that
     * throws propagates (computeTaint reports it as invalid); a missing registry throws.
     */
    @JvmOverloads
    fun classifyRef(ref: Any?, registry: Registry?, graph: ResourceGraph? = null): Map<String, Any?> {
        if (ref !is String || ref.isEmpty()) return LinkedHashMap(TOP)
        val vouched = (registry ?: throw NullPointerException("Cannot read properties of undefined (reading 'lookup')")).lookup(ref)
        if (vouched != null && isTaintLevel(vouched["kind"])) return vouched
        try {
            if (graph != null && graph.node(ref) != null) return linkedMapOf("kind" to "first_party")
        } catch (e: Exception) {
            // worst case
        }
        return if (ref.length <= 128) linkedMapOf("kind" to "agent", "id" to ref) else linkedMapOf("kind" to "agent")
    }

    /** [refs] is the per-ref classification `[{ref, label}]` (audit / explanation), empty when invalid. */
    class Computed(val taint: Double, val label: Map<String, Any?>, val valid: Boolean, val reason: String? = null, val refs: List<Map<String, Any?>> = emptyList())

    private fun invalid(reason: String) = Computed(1.0, mapOf("kind" to "agent"), false, reason)

    /** The taint of a PCActn's provenance. Never throws. */
    fun computeTaint(provenance: Any?, registry: Registry?, graph: ResourceGraph? = null): Computed {
        try {
            val prov = provenance as? Map<*, *>
            var refs: List<String> = emptyList()
            if (registry != null && prov != null && prov.containsKey("trusted_refs")) {
                val raw = prov["trusted_refs"] as? List<*> ?: return invalid("taint: trusted_refs must be an array")
                if (!raw.all { it is String && it.isNotEmpty() }) return invalid("taint: trusted_refs must be non-empty strings")
                refs = raw.map { it as String }
            }
            if (registry == null) return invalid("taint: no trusted-input registry")
            if (prov == null) return invalid("taint: provenance is absent or malformed")
            val labels = refs.map { classifyRef(it, registry, graph) }
            val label = joinLabels(labels) as Map<String, Any?>
            return Computed(taintValue(label), label, true, null, refs.indices.map { linkedMapOf("ref" to refs[it], "label" to labels[it]) })
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return invalid("taint: evaluation error (fail closed): ${e.message}")
        }
    }

    /** The gate: null when the lineage is within `maxTaint`, else the refusal reason. A negative or non-numeric bound never passes. */
    fun gate(provenance: Any?, g: Gate): String? = try {
        val t = computeTaint(provenance, g.registry, g.resourceGraph)
        val max = g.maxTaint
        if (!t.valid) t.reason ?: "provenance lineage is not server-verifiable (fail closed)"
        else if (max == null || max.isNaN() || max.isInfinite() || max < 0) "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"
        else {
            val allowed = (0..MAX_RANK).filter { it.toDouble() / MAX_RANK <= max }.maxOrNull() ?: -1
            if (labelRank(t.label) <= allowed) null
            else "information-flow taint ${AttestUtil.jsNumString(t.taint)} exceeds policy max ${AttestUtil.jsNumString(max)}"
        }
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        "taint gate error (fail closed): ${e.message}"
    }
}
