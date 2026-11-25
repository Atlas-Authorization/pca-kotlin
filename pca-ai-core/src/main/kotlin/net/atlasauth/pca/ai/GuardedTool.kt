package net.atlasauth.pca.ai

/** What a tool says about itself: its name, an optional description and an optional parameter schema (kept as given). */
class ToolMetadata @JvmOverloads constructor(val name: String, val description: String? = null, val parameters: Any? = null)

/** The structural shape of an agent-framework function tool: metadata plus a `call` over the arguments. No framework is imported. */
interface Tool<out R> {
    val metadata: ToolMetadata
    fun call(input: Map<String, Any?>): R
}

/** How a tool call becomes a PCA action: the catalog [verb] and the [resource] (fixed, or derived from the call's arguments). */
class GuardToolSpec @JvmOverloads constructor(
    val verb: String,
    val resource: (Map<String, Any?>) -> String,
    /** Receives the proof before the tool runs, so the caller can forward it (for instance as request headers) to the resource server. */
    val onProof: ((Proof, Map<String, Any?>) -> Unit)? = null,
) {
    constructor(verb: String, resource: String) : this(verb, { resource })
}

/**
 * Wraps a [Tool] so every call first builds a proof through the [Prover] (a refusal throws [PcaDenied] and the tool never runs), hands it to
 * [GuardToolSpec.onProof], then runs the original tool; its result is recorded as untrusted. The metadata is the wrapped tool's own, so the
 * guarded tool slots in wherever the original did. The resource server's verifier still decides: this attaches a proof, it does not authorize.
 */
class GuardedTool<out R>(private val tool: Tool<R>, private val prover: Prover, private val spec: GuardToolSpec) : Tool<R> {
    override val metadata: ToolMetadata get() = tool.metadata

    override fun call(input: Map<String, Any?>): R =
        ToolGuard.run(prover, { _, args -> ToolGuard.Action(spec.verb, spec.resource(args)) }, tool.metadata.name, input) { args, proof ->
            spec.onProof?.invoke(proof, args)
            tool.call(args)
        }

    companion object {
        /** Guard every tool of a list with the spec its name maps to; a tool with no spec is refused when called (it is still returned, unguarded tools do not exist here). */
        @JvmStatic
        fun <R> wrapAll(tools: List<Tool<R>>, prover: Prover, specs: Map<String, GuardToolSpec>): List<Tool<R>> =
            tools.map { t ->
                val s = specs[t.metadata.name]
                if (s == null) object : Tool<R> {
                    override val metadata: ToolMetadata get() = t.metadata
                    override fun call(input: Map<String, Any?>): R = throw PcaDenied("no PCActn for unmapped tool \"${t.metadata.name}\"", null, null)
                } else GuardedTool(t, prover, s)
            }
    }
}
