package net.atlasauth.pca.verifier

/**
 * L4 information-flow taint (spec section 6) and the `enforce.taint` gate: a port of packages/pca/src/taint.ts. The agent's own label is
 * never read: every declared provenance ref is re-classified from facts the SERVER holds (a trusted-input registry it populated, or its own
 * committed resource graph); a ref the server cannot vouch for is `agent` (the worst case). Malformed or absent provenance and any internal
 * error fail CLOSED to taint 1.
 */
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

        @Synchronized
        fun record(digest: String, label: Map<String, Any?>): InMemoryRegistry {
            if (digest.isNotEmpty() && label["kind"] in LEVELS) m[digest] = LinkedHashMap(label)
            return this
        }

        fun recordTrusted(digest: String) = record(digest, mapOf("kind" to "trusted"))
        fun recordFirstParty(digest: String) = record(digest, mapOf("kind" to "first_party"))
        fun recordTool(digest: String, id: String) = record(digest, mapOf("kind" to "tool", "id" to id))
        fun recordWeb(digest: String) = record(digest, mapOf("kind" to "web"))

        @Synchronized
        override fun lookup(ref: String): Map<String, Any?>? = m[ref]?.let { LinkedHashMap(it) }
        val size: Int @Synchronized get() = m.size
    }

    /** The `enforce.taint` option: the registry, the resource graph and the largest taint (0..1) the policy accepts. */
    class Gate @JvmOverloads constructor(val registry: Registry?, val maxTaint: Double?, val resourceGraph: ResourceGraph? = null)

    private fun level(kind: Any?): Boolean = kind is String && kind in LEVELS

    private fun labelRank(label: Any?): Int {
        val kind = (label as? Map<*, *>)?.get("kind")
        return if (level(kind)) LEVELS.indexOf(kind) else MAX_RANK
    }

    private fun joinLabel(a: Map<String, Any?>, b: Map<String, Any?>): Map<String, Any?> {
        val ra = labelRank(a)
        val rb = labelRank(b)
        if (ra > rb) return a
        if (rb > ra) return b
        if (a["id"] == b["id"]) return a
        return mapOf("kind" to a["kind"])
    }

    private fun classifyRef(ref: String, registry: Registry, graph: ResourceGraph?): Map<String, Any?> {
        val vouched = registry.lookup(ref)
        if (vouched != null && level(vouched["kind"])) return vouched
        try {
            if (graph != null && graph.node(ref) != null) return mapOf("kind" to "first_party")
        } catch (e: Exception) {
            // worst case
        }
        return if (ref.length <= 128) mapOf("kind" to "agent", "id" to ref) else mapOf("kind" to "agent")
    }

    class Computed(val taint: Double, val label: Map<String, Any?>, val valid: Boolean, val reason: String? = null)

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
            val label = if (labels.isEmpty()) mapOf("kind" to "agent") else labels.reduce { acc, l -> joinLabel(acc, l) }
            return Computed(labelRank(label).toDouble() / MAX_RANK, label, true)
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
