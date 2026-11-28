package net.atlasauth.pca.openai

import com.aallam.openai.api.chat.ChatMessage
import com.aallam.openai.api.chat.ChatRole
import com.aallam.openai.api.chat.ToolCall
import com.aallam.openai.api.chat.ToolId
import net.atlasauth.pca.ai.PcaDenied
import net.atlasauth.pca.ai.Prover
import net.atlasauth.pca.ai.ToolGuard
import net.atlasauth.pca.verifier.Adapters
import net.atlasauth.pca.verifier.Facade

/**
 * Helpers for the openai-kotlin client (`com.aallam.openai`): turn a model's function tool call into a PCA action, run your handler under the
 * proof, and hand back the `tool` message for the next model turn. This does NOT authorize: it attaches a proof-carrying action and the
 * resource server's verifier decides. Deny fails closed: an unmapped tool, a non-function tool call, malformed arguments, or a refused
 * proof throw [PcaDenied] and the handler never runs.
 */
object OpenAiPca {
    /** One dispatched tool call: the `tool` message content and the call id it answers. */
    class ToolOutput(val toolCallId: String, val content: String) {
        /** The `tool` role chat message to append to the next request. */
        fun toMessage(): ChatMessage = ChatMessage(role = ChatRole.Tool, content = content, toolCallId = ToolId(toolCallId))
    }

    /**
     * Dispatch one function tool call given its id, name and JSON arguments: map it, build the proof, run `handlers[name]` under it, and
     * return the output. A tool with no handler returns the proof itself as the content (as the TypeScript adapter does). The result is
     * recorded as untrusted tool output.
     */
    @JvmStatic
    fun dispatch(
        prover: Prover, map: ToolGuard.ToolMapping, id: String, name: String, argumentsJson: String?,
        handlers: Map<String, ToolGuard.Body<Any?>>,
    ): ToolOutput {
        val args = ToolGuard.parseArguments(argumentsJson)
        var content = ""
        ToolGuard.run(prover, map, name, args) { a, proof ->
            val h = handlers[name]
            val result = h?.run(a, proof)
            content = ToolGuard.content(result, proof)
            content
        }
        return ToolOutput(id, content)
    }

    /** Dispatch one tool call of the client; a non-function tool call is refused (there is no argument object to bind a proof to). */
    @JvmStatic
    fun dispatchToolCall(prover: Prover, map: ToolGuard.ToolMapping, call: ToolCall, handlers: Map<String, ToolGuard.Body<Any?>>): ToolOutput {
        if (call !is ToolCall.Function) throw PcaDenied("only function tool calls can carry a PCActn", null, null)
        return dispatch(prover, map, call.id.id, call.function.name, call.function.arguments, handlers)
    }

    /** Dispatch every tool call of a turn in order; the first refusal stops the turn (nothing after it runs). */
    @JvmStatic
    fun dispatchToolCalls(prover: Prover, map: ToolGuard.ToolMapping, calls: List<ToolCall>, handlers: Map<String, ToolGuard.Body<Any?>>): List<ToolOutput> =
        calls.map { dispatchToolCall(prover, map, it, handlers) }

    /**
     * Provenance by default: wrap a chat-completions call that takes `{messages}` (each message a `{role, content}` map) so every model
     * turn first records the conversation's new messages in the agent's provenance chain (`user` turns are the principal, `tool` turns
     * untrusted). [dispatchToolCall] records every tool result.
     */
    fun <R> withPCACompletions(agent: Facade.Handle, create: (Map<String, Any?>) -> R): (Map<String, Any?>) -> R = { params ->
        (params["messages"] as? List<*>)?.let { Adapters.recordMessages(agent, it) }
        create(params)
    }
}
