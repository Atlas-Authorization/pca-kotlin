package net.atlasauth.pca.langchain4j

import dev.langchain4j.agent.tool.ToolExecutionRequest
import dev.langchain4j.agent.tool.ToolSpecification
import dev.langchain4j.service.tool.ToolExecutor
import net.atlasauth.pca.ai.PcaDenied
import net.atlasauth.pca.ai.Proof
import net.atlasauth.pca.ai.Prover
import net.atlasauth.pca.ai.ToolGuard

/**
 * Wraps a LangChain4j [ToolExecutor] (which is what a `@Tool` method becomes): every execution is mapped to a PCA action, a proof
 * is built, and the real tool runs only under it. A refusal throws [PcaDenied] (or, with [deniedAsText], returns the refusal as the
 * tool result so the model sees it); the delegate never runs. The resource server's verifier still decides.
 */
class PcaToolExecutor @JvmOverloads constructor(
    private val delegate: ToolExecutor,
    private val prover: Prover,
    private val mapping: ToolGuard.ToolMapping,
    private val onProof: ((Proof, ToolExecutionRequest) -> Unit)? = null,
    private val deniedAsText: Boolean = false,
) : ToolExecutor {
    override fun execute(request: ToolExecutionRequest, memoryId: Any?): String =
        try {
            ToolGuard.runJson(prover, mapping, request.name(), request.arguments()) { _, proof ->
                onProof?.invoke(proof, request)
                delegate.execute(request, memoryId)
            }
        } catch (d: PcaDenied) {
            if (deniedAsText) "denied: " + d.message else throw d
        }

    companion object {
        /** Guard every executor of a tool map (the shape `AiServices.builder(...).tools(Map)` takes). */
        @JvmStatic
        @JvmOverloads
        fun wrapAll(
            tools: Map<ToolSpecification, ToolExecutor>, prover: Prover, mapping: ToolGuard.ToolMapping,
            onProof: ((Proof, ToolExecutionRequest) -> Unit)? = null, deniedAsText: Boolean = false,
        ): Map<ToolSpecification, ToolExecutor> {
            val out = LinkedHashMap<ToolSpecification, ToolExecutor>()
            for ((spec, ex) in tools) out[spec] = PcaToolExecutor(ex, prover, mapping, onProof, deniedAsText)
            return out
        }
    }
}
