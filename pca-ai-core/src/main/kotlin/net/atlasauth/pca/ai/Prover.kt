package net.atlasauth.pca.ai

import net.atlasauth.pca.verifier.Agent
import net.atlasauth.pca.verifier.Facade

/**
 * Builds the proof for one tool call. Implementations refuse by throwing [PcaDenied]; any other exception is also treated as a
 * refusal by [ToolGuard] (the tool never runs). [tool] / [retrieval] / [principal] feed the provenance recorder, when there is one.
 */
fun interface Prover {
    fun prove(verb: String, resource: String, params: Map<String, Any?>): Proof

    /** Record what a tool returned: it re-enters the model's context, so it is untrusted from here on. */
    fun tool(name: String, output: Any?) {}

    /** Record a document handed to the model: retrieved content is untrusted (it can carry an injected instruction). */
    fun retrieval(source: String, content: Any?) {}

    /** Record a principal (user) message. */
    fun principal(text: String) {}

    companion object {
        /** The facade handle as a prover: a failed local dry-run refuses (advisory pre-check, the server still decides), and tool results are recorded. */
        @JvmStatic
        fun of(h: Facade.Handle): Prover = object : Prover {
            override fun prove(verb: String, resource: String, params: Map<String, Any?>): Proof {
                val r = try {
                    h.act(verb, resource, params)
                } catch (e: RuntimeException) {
                    throw PcaDenied(e.message.toString(), verb, resource, e)
                }
                if (!r.dryRun.allowed) throw PcaDenied(r.dryRun.reason ?: "denied", verb, resource)
                return Proof(r.pcactn, r.encoded, r.headers)
            }

            override fun tool(name: String, output: Any?) { h.provenance.tool(name, output) }
            override fun retrieval(source: String, content: Any?) { h.provenance.retrieval(source, content) }
            override fun principal(text: String) { h.provenance.principal(text) }
        }

        /** A plain agent as a prover (no local dry-run and no provenance: the agent builds the proof, the server decides). */
        @JvmStatic
        fun of(a: Agent): Prover = object : Prover {
            override fun prove(verb: String, resource: String, params: Map<String, Any?>): Proof {
                val p = try {
                    a.act(verb, resource, params)
                } catch (e: RuntimeException) {
                    throw PcaDenied(e.message.toString(), verb, resource, e)
                }
                val enc = Agent.header(p)
                return Proof(p, enc, linkedMapOf(Agent.HEADER to enc))
            }
        }
    }
}
