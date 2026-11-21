package net.atlasauth.pca.ai

import net.atlasauth.pca.verifier.Adapters
import net.atlasauth.pca.verifier.Facade

/**
 * Anthropic (Claude) adapter for Proof-Carrying Authority, over the plain content blocks (maps), so no SDK is needed. Claude's tool use
 * is a conversation: an assistant message carries content blocks, and a `tool_use` block `{type, id, name, input}` asks your app to run
 * a tool; your app replies with a `tool_result` block `{type, tool_use_id, content, is_error?}`. This sits in that gap: it turns a
 * `tool_use` block into a PCActn, runs your handler with the proof in hand and hands back the `tool_result`, including the error-shaped
 * result Claude expects when a tool refuses. It does not authorize: the resource server's verifier decides.
 */
object AnthropicPca {
    /** Pull the `tool_use` blocks out of an assistant message's `content` list (ignoring text and other blocks). */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    fun extractToolUses(content: List<Map<String, Any?>>): List<Map<String, Any?>> = content.filter { it["type"] == "tool_use" }

    private fun result(id: Any?, content: String, isError: Boolean): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("type" to "tool_result", "tool_use_id" to id, "content" to content)
        if (isError) m["is_error"] = true
        return m
    }

    /**
     * Handle one `tool_use` block: build its PCActn through [prover], run the mapped handler and return the `tool_result`. A tool the
     * [map] declines, a tool with no handler, a local pre-check refusal and a handler that throws all answer an error-shaped result
     * (`is_error: true`) Claude can read; the handler never runs without a proof. A successful result's content is the canonical JSON of
     * what the handler returned (the proof when it returned nothing). Every result that re-enters Claude's context is recorded as
     * untrusted tool output.
     */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    fun handleToolUse(prover: Prover, block: Map<String, Any?>, map: ToolGuard.ToolMapping, handlers: Map<String, ToolGuard.Body<Any?>>): Map<String, Any?> {
        val id = block["id"]
        val name = block["name"] as? String ?: ""
        val input = (block["input"] as? Map<String, Any?>) ?: LinkedHashMap()
        val action = map.map(name, input) ?: return result(id, "No proof-carrying authority is mapped for tool \"$name\".", true)
        val proof = try {
            prover.prove(action.verb, action.resource, input)
        } catch (d: PcaDenied) {
            return result(id, d.message ?: "denied", true)
        } catch (e: RuntimeException) {
            return result(id, "proof could not be built: " + (e.message ?: "error"), true)
        }
        val handler = handlers[name] ?: return result(id, "No handler registered for tool \"$name\".", true)
        return try {
            val content = ToolGuard.content(handler.run(input, proof), proof)
            prover.tool(name, content)
            result(id, content, false)
        } catch (e: Exception) {
            val msg = e.message ?: e.toString()
            prover.tool(name, msg)
            result(id, msg, true)
        }
    }

    /** Handle many `tool_use` blocks (for example all of them from one assistant turn), preserving order; blocks of another type are skipped. */
    @JvmStatic
    fun handleToolUses(prover: Prover, blocks: List<Map<String, Any?>>, map: ToolGuard.ToolMapping, handlers: Map<String, ToolGuard.Body<Any?>>): List<Map<String, Any?>> =
        extractToolUses(blocks).map { handleToolUse(prover, it, map, handlers) }

    /**
     * Provenance by default: wrap `messages.create` (or any call taking `{messages}`) so every model turn first records the conversation's
     * new messages in the agent's provenance chain (user text is the principal; `tool_result` blocks are untrusted).
     */
    @JvmStatic
    fun <R> withPCAMessages(agent: Facade.Handle, create: (Map<String, Any?>) -> R): (Map<String, Any?>) -> R = { params ->
        (params["messages"] as? List<*>)?.let { Adapters.recordMessages(agent, it) }
        create(params)
    }
}
