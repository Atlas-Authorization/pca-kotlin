// Koog 0.5 runs a tool directly only through execute(args, enabler), an opt-in API: this adapter is that encapsulated path
@file:OptIn(InternalAgentToolsApi::class)

package net.atlasauth.pca.koog

import ai.koog.agents.core.tools.DirectToolCallsEnabler
import ai.koog.agents.core.tools.Tool
import ai.koog.agents.core.tools.annotations.InternalAgentToolsApi
import net.atlasauth.pca.ai.Proof
import net.atlasauth.pca.ai.Prover
import net.atlasauth.pca.ai.ToolGuard

/**
 * Koog adapter: run a Koog [Tool] under a built proof. The call is mapped to a PCA action, a proof is built, and `tool.execute(args)` runs
 * only under it; a refusal throws [PcaDenied] and the tool never runs. This does NOT authorize: the resource server's verifier decides.
 * [argsOf] turns the tool's typed arguments into the JSON object the proof binds (the same object the server derives its operation from).
 */
object KoogPca {
    /** Execute [tool] with [args] under a proof; [onProof] receives the proof (to forward as the `PCA-Action` header) before the tool runs. */
    suspend fun <A, R> execute(
        prover: Prover, mapping: ToolGuard.ToolMapping, tool: Tool<A, R>, args: A, argsOf: (A) -> Map<String, Any?>,
        onProof: ((Proof) -> Unit)? = null,
    ): R where A : Any, R : Any = ToolGuard.runSuspending(prover, mapping, tool.name, argsOf(args)) { _, proof ->
        onProof?.invoke(proof)
        tool.execute(args, UnderProof)
    }

    /** The enabler Koog requires for a direct call: only [execute] holds it, so the tool runs only under the proof built above. */
    private object UnderProof : DirectToolCallsEnabler
}
