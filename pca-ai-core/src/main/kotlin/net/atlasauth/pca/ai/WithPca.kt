package net.atlasauth.pca.ai

/**
 * Wrap a tool so each call builds and attaches a proof before it runs (the reference's `withPCA`): a refusal throws [PcaDenied], the tool never
 * runs, and [GuardToolSpec.onProof] receives the proof so the caller can forward it to the resource server.
 */
fun <R> withPCA(prover: Prover, spec: GuardToolSpec, tool: Tool<R>): Tool<R> = GuardedTool(tool, prover, spec)

/**
 * Wrap a whole tools map (the reference's `withPCATools`): each entry's spec is looked up by its key. A tool with no spec passes through unchanged,
 * as in the reference (it then carries no proof and the resource server refuses it); use [GuardedTool.wrapAll] to refuse an unmapped tool at the
 * call instead. The result keeps the order of [tools].
 */
fun <R> withPCATools(prover: Prover, tools: Map<String, Tool<R>>, specs: Map<String, GuardToolSpec>): Map<String, Tool<R>> {
    val out = LinkedHashMap<String, Tool<R>>()
    for ((name, tool) in tools) {
        val spec = specs[name]
        out[name] = if (spec != null) withPCA(prover, spec, tool) else tool
    }
    return out
}
