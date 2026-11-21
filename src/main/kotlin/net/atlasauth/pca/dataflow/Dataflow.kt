package net.atlasauth.pca.dataflow

import net.atlasauth.pca.verifier.Json
import java.util.Collections

/**
 * The capability-tagged, positive data-flow model (CaMeL style): every value carries the provenance it was derived from and the
 * sinks it may reach; an interpreter decides each flow from the tags alone. Pure and deterministic. Non-exfiltration is
 * provable GIVEN CORRECT TAGGING AT THE BOUNDARIES: tag the genuine user query with [fromTrustedQuery] and everything a
 * tool or document returns with [fromToolOutput]; mis-tagged input voids the proof.
 */
object Dataflow {
    /** The genuine, trusted user query: the one source control flow may derive from. */
    const val TRUSTED_QUERY = "trusted-query"

    /** Marker for a hole in a tagged-argument list (an argument nobody tagged); a null element is an explicit "undefined". */
    @JvmField val HOLE: Any = object { override fun toString() = "<hole>" }

    /** Provenance tag for the output of a named tool. Always untrusted. */
    @JvmStatic fun toolProvenance(name: String): String = "tool:$name"

    // ---- capability + tagged value -----------------------------------------------------------------------------------------

    /** The data-flow label of a value: its lineage, whether every source is trusted, and an optional sink allow-list ([readers] null = unrestricted by the value). */
    class Capability(sources: Collection<String>, val isTrusted: Boolean, readers: Collection<String>?) {
        /** The provenance tags, in insertion order. Immutable. */
        val sources: Set<String> = Collections.unmodifiableSet(LinkedHashSet(sources))

        /** The sink allow-list in insertion order, or null. Immutable. */
        val readers: Set<String>? = readers?.let { Collections.unmodifiableSet(LinkedHashSet(it)) }
    }

    /** A value carrying its data-flow capability. Only this object's factories make one, so a look-alike is never a tagged value. */
    class Tagged<T> internal constructor(val value: T, val cap: Capability)

    /** True only for a value created by [tag], the `from*` constructors or [derive]. */
    @JvmStatic fun isTagged(x: Any?): Boolean = x is Tagged<*>

    /** Tag a raw value with an explicit capability (escape hatch; prefer the boundary constructors). Throws on a contradictory capability. */
    @JvmStatic fun <T> tag(value: T, cap: Capability?): Tagged<T> {
        requireNotNull(cap) { "tag: a capability needs a set of sources and a boolean isTrusted" }
        if (cap.isTrusted) {
            require(cap.sources.isNotEmpty()) { "tag: a trusted capability needs at least one source" }
            for (src in cap.sources) require(!src.startsWith("tool:")) { "tag: tool output can never be trusted" }
        }
        return Tagged(value, Capability(cap.sources, cap.isTrusted, cap.readers))
    }

    /** Tag a value as the genuine, trusted user query (a BOUNDARY assertion). */
    @JvmStatic fun <T> fromTrustedQuery(value: T, readers: Collection<String>?): Tagged<T> =
        tag(value, Capability(listOf(TRUSTED_QUERY), true, readers))

    /** Tag the output of a named tool. ALWAYS untrusted. */
    @JvmStatic fun <T> fromToolOutput(name: String, value: T, readers: Collection<String>?): Tagged<T> =
        tag(value, Capability(listOf(toolProvenance(name)), false, readers))

    /** Tag a value from an arbitrary source; untrusted unless the caller explicitly vouches for it. */
    @JvmStatic fun <T> fromSource(source: String, value: T, isTrusted: Boolean, readers: Collection<String>?): Tagged<T> =
        tag(value, Capability(listOf(source), isTrusted, readers))

    // ---- capability algebra ------------------------------------------------------------------------------------------------

    /** Union of the provenance sources of several capabilities (insertion order). */
    @JvmStatic fun unionSources(caps: List<Capability>): Set<String> {
        val out = LinkedHashSet<String>()
        for (c in caps) out.addAll(c.sources)
        return Collections.unmodifiableSet(out)
    }

    /**
     * Combine capabilities: sources = union, isTrusted = AND over the inputs (none = untrusted, fail closed), readers = the
     * intersection of the inputs that restrict readers.
     */
    @JvmStatic fun combineCaps(caps: List<Capability>): Capability {
        val trusted = caps.isNotEmpty() && caps.all { it.isTrusted }
        var readers: MutableSet<String>? = null
        for (c in caps) {
            val r = c.readers ?: continue
            readers = if (readers == null) LinkedHashSet(r) else readers.filterTo(LinkedHashSet()) { r.contains(it) }
        }
        return Capability(unionSources(caps), trusted, readers)
    }

    /**
     * Derive a new tagged value from existing ones: the capability is [combineCaps] over the inputs, so provenance propagates and
     * trust can only be lost. Every input must be a tagged value made by this object.
     */
    @JvmStatic fun <T> derive(inputs: List<*>?, combine: (List<Any?>) -> T): Tagged<T> {
        if (inputs == null || !inputs.all { isTagged(it) }) throw IllegalArgumentException("derive: every input must be a tagged value made by this module")
        val tagged = inputs.map { it as Tagged<*> }
        val value = combine(tagged.map { it.value })
        return Tagged(value, combineCaps(tagged.map { it.cap }))
    }

    // ---- sinks + the policy interpreter ------------------------------------------------------------------------------------

    const val ALLOW = "allow"
    const val STEP_UP = "step_up"
    const val DENY = "deny"

    /** What a sink accepts; every member optional (null = not set). */
    class FlowPolicy(val external: Boolean?, val requireTrusted: Boolean?, allowedSources: Collection<String>?, deniedSources: Collection<String>?) {
        val allowedSources: Set<String>? = allowedSources?.let { LinkedHashSet(it) }
        val deniedSources: Set<String>? = deniedSources?.let { LinkedHashSet(it) }
    }

    /** A place a value leaves the trusted interior. An invalid sink (null id / empty id / null policy) is refused, never allowed. */
    class Sink(val id: String?, val accepts: FlowPolicy?)

    /** The decision for one value-to-sink flow. [reason] / [path] are null when absent. */
    class FlowDecision internal constructor(val outcome: String, val reason: String?, val path: List<String>?)

    private fun sortedSources(cap: Capability): List<String> = cap.sources.sorted()

    /**
     * Classify one value-to-sink flow from the value's tags and the sink's declared policy, in order: the value's reader
     * allow-list, the sink's denied sources, its allow-list, the external-sink exfiltration rule, the trust requirement.
     * A value that is not a tagged value of this object, or an invalid sink, is a denial.
     */
    @JvmStatic fun classifyFlow(value: Any?, sink: Sink?): FlowDecision {
        if (value !is Tagged<*>) return FlowDecision(DENY, "value carries no provenance tag made by this module (fail closed)", ArrayList())
        val cap = value.cap
        val id = sink?.id
        val p = sink?.accepts
        if (id == null || id.isEmpty() || p == null) return FlowDecision(DENY, "the sink is not a valid sink (fail closed)", sortedSources(cap))
        val readers = cap.readers
        if (readers != null && !readers.contains(id)) {
            val list = readers.sorted().joinToString(", ")
            return FlowDecision(DENY, "value's readers capability [" + (if (list.isEmpty()) "∅" else list) + "] does not include sink '" + id + "'", sortedSources(cap))
        }
        val denied = p.deniedSources
        if (denied != null) {
            val bad = sortedSources(cap).filter { denied.contains(it) }
            if (bad.isNotEmpty()) return FlowDecision(DENY, "provenance [" + bad.joinToString(", ") + "] is forbidden at sink '" + id + "'", bad)
        }
        val allowed = p.allowedSources
        if (allowed != null) {
            val bad = sortedSources(cap).filter { !allowed.contains(it) }
            if (bad.isNotEmpty()) return FlowDecision(DENY, "provenance [" + bad.joinToString(", ") + "] is not in the allow-list of sink '" + id + "'", bad)
        }
        if (p.external == true && !cap.isTrusted) {
            return FlowDecision(DENY, "untrusted value (provenance [" + sortedSources(cap).joinToString(", ") + "]) may not flow to external-send sink '" +
                id + "' — exfiltration / prompt-injection path", sortedSources(cap))
        }
        if (p.requireTrusted == true && !cap.isTrusted) {
            return FlowDecision(STEP_UP, "sink '" + id + "' requires trusted provenance; value provenance [" + sortedSources(cap).joinToString(", ") +
                "] is untrusted — needs human review", sortedSources(cap))
        }
        return FlowDecision(ALLOW, null, null)
    }

    /** The boolean view of [classifyFlow]: ok only for a clean `allow` (a step-up is not ok without a human). */
    class CanFlow internal constructor(val ok: Boolean, val reason: String?)

    @JvmStatic fun canFlow(value: Any?, sink: Sink?): CanFlow {
        val d = classifyFlow(value, sink)
        return CanFlow(ALLOW == d.outcome, d.reason)
    }

    // ---- action gate --------------------------------------------------------------------------------------------------------

    /** The verb and resource of a PCActn's `action`. */
    class PcaStyleAction(val verb: String?, val resource: String?)

    /** Resolves which sink an action dispatches to. May throw: the action is then refused. */
    fun interface FlowGovernor { fun sinkFor(action: PcaStyleAction): Sink? }

    /** The decision for one action; [reason], [arg] (an argument index) and [path] are null when absent. */
    class ActionDecision internal constructor(val outcome: String, val sink: String, val reason: String?, val arg: Int?, val path: List<String>?)

    private fun severity(outcome: String): Int = if (ALLOW == outcome) 0 else if (STEP_UP == outcome) 1 else 2

    /**
     * Gate a PCA action by data flow: every tagged argument is checked against the sink the action dispatches to and the worst
     * outcome wins (deny over step_up over allow). [taggedArgs]: a null element is an explicit undefined (skipped), [HOLE] an
     * argument nobody tagged (a denial). [expectedArgs] (null = unknown) makes a count mismatch a refusal.
     */
    @JvmStatic fun checkAction(action: PcaStyleAction, taggedArgs: List<*>?, policy: FlowGovernor, expectedArgs: Double?): ActionDecision {
        val sink = try {
            policy.sinkFor(action)
        } catch (e: Exception) {
            return ActionDecision(DENY, "(unresolved)", "the sink for this action could not be resolved (fail closed)", null, null)
        }
        val id = sink?.id
        if (id == null || id.isEmpty()) return ActionDecision(DENY, "(unresolved)", "the sink for this action is not a valid sink (fail closed)", null, null)
        if (taggedArgs == null) return ActionDecision(DENY, id, "the tagged arguments are not a list (fail closed)", null, null)
        if (expectedArgs != null && taggedArgs.size.toDouble() != expectedArgs) {
            return ActionDecision(DENY, id, "expected " + jsNum(expectedArgs) + " tagged argument(s), got " + taggedArgs.size + " (fail closed)", null, null)
        }
        var worst = ActionDecision(ALLOW, id, null, null, null)
        for (i in taggedArgs.indices) {
            val arg = taggedArgs[i] ?: continue
            if (arg === HOLE) return ActionDecision(DENY, id, "an argument was not tagged (fail closed)", i, null)
            val d = classifyFlow(arg, sink)
            if (severity(d.outcome) > severity(worst.outcome)) worst = ActionDecision(d.outcome, id, d.reason, i, d.path)
        }
        return worst
    }

    private fun jsNum(d: Double): String = when {
        d.isNaN() -> "NaN"
        d.isInfinite() -> if (d > 0) "Infinity" else "-Infinity"
        else -> Json.esNumber(if (d == 0.0) 0.0 else d)
    }

    // ---- dual-context --------------------------------------------------------------------------------------------------------

    /** The result of [dualContext]: the plan and the capability-tagged quarantined result. */
    class DualResult<P, R> internal constructor(val plan: P, val result: Tagged<R>)

    /**
     * Run the dual-LLM separation: a PRIVILEGED planner that sees only the trusted query value, and a QUARANTINED handler that
     * processes untrusted content and returns only a capability-tagged result. Throws when the query is not a trusted tagged
     * value, or the handler returns something that is not tagged.
     */
    @Suppress("UNCHECKED_CAST")
    @JvmStatic fun <Q, P, R> dualContext(query: Any?, plan: (Q) -> P, quarantine: (P) -> Any?): DualResult<P, R> {
        require(query is Tagged<*>) { "dualContext: the query must be a tagged value made by this module" }
        val q = query as Tagged<Q>
        check(q.cap.isTrusted) { "dualContext: the privileged planner may only run on a TRUSTED query; got provenance [" + sortedSources(q.cap).joinToString(", ") + "]" }
        val p = plan(q.value)
        val result = quarantine(p)
        require(result is Tagged<*>) { "dualContext: the quarantined handler must return a tagged value made by this module" }
        return DualResult(p, result as Tagged<R>)
    }

    // ---- presets + the verifier's lattice ----------------------------------------------------------------------------------

    /** An external-send sink: exfiltrating, so untrusted values hard-deny. */
    @JvmStatic fun externalSendSink(id: String): Sink = Sink(id, FlowPolicy(true, null, null, null))

    /** A sensitive internal sink: untrusted values step up for human review. */
    @JvmStatic fun sensitiveSink(id: String): Sink = Sink(id, FlowPolicy(null, true, null, null))

    /** A tagged value's label in the verifier's provenance lattice: `trusted`, `tool` (every source a tool) or `agent`. */
    @JvmStatic fun levelOf(value: Any?): String {
        if (value !is Tagged<*>) return "agent"
        val cap = value.cap
        if (cap.isTrusted) return "trusted"
        if (cap.sources.isEmpty()) return "agent"
        return if (cap.sources.all { it.startsWith("tool:") }) "tool" else "agent"
    }
}
