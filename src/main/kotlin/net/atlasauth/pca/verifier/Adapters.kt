package net.atlasauth.pca.verifier

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.WeakHashMap

/**
 * The framework-agnostic adapter primitives (packages/pca/src/adapters.ts): the provenance header, recording the principal's messages and
 * tool results into the agent's provenance chain, splitting chat messages into trusted and untrusted segments, and bridging a framework
 * tool call into a PCActn. The typed per-framework modules sit on top of these. `guard` is NOT the authorization: it offers the local
 * non-authoritative dry run as a fast reject and hands the proof to the caller; the resource server decides.
 */
object Adapters {
    /** Largest bundle carried as a header (base64url characters); a larger one goes in the request body as `pca_provenance`. */
    const val PROV_HEADER_MAX = Issue.PROVENANCE_HEADER_MAX

    /** Thrown by [decodePcaHeader] for a `PCA-Action` value that is not strict unpadded base64url of UTF-8 text. */
    class PcaHeaderError(message: String) : RuntimeException(message) {
        val code: String = "invalid_pca_header"
    }

    /** `PCA-Provenance: <base64url JSON>` for a bundle that fits [PROV_HEADER_MAX]; empty otherwise (send it in the body). */
    fun provenanceHeaders(bundle: Any?): Map<String, String> {
        if (bundle == null) return emptyMap()
        val v = Pca.b64(Json.utf8(Json.canonicalizeStrict(bundle)))
        return if (v.length <= PROV_HEADER_MAX) linkedMapOf(ArgProvenance.HEADER to v) else emptyMap()
    }

    /**
     * Reverse of the `PCA-Action` header: strict unpadded base64url (no padding, no `+` or `/`, no whitespace, zero trailing bits) of
     * well-formed UTF-8, else [PcaHeaderError]. Nothing is normalized, so one PCActn has exactly one header spelling.
     */
    fun decodePcaHeader(value: String?): String {
        if (value == null || value.isEmpty()) throw PcaHeaderError("PCA-Action header is empty")
        val bytes = Pca.decodeB64uStrict(value, -1) ?: throw PcaHeaderError("PCA-Action header is not strict unpadded base64url")
        return try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (e: CharacterCodingException) {
            throw PcaHeaderError("PCA-Action header does not decode to UTF-8 text")
        }
    }

    private fun recorderOf(t: Any?): ArgProvenance.Recorder? = when (t) {
        is ArgProvenance.Recorder -> t
        is Facade.Handle -> t.provenance
        else -> null
    }

    /** Record the principal's own message in the agent's provenance chain (TRUSTED). Adapters call it for every user turn. */
    fun recordPrincipal(agent: Facade.Handle, text: String) { agent.provenance.principal(text) }

    /** Record a tool result entering the model's context (UNTRUSTED). Adapters call it for every tool result they hand back. */
    fun recordToolResult(agent: Facade.Handle, tool: String, output: Any?) { agent.provenance.tool(tool, output) }

    /** One context segment a chat message adds: [origin] is `principal` or `tool`. */
    class MessageSegment(val origin: String, val source: String, val content: Any?)

    private val PRINCIPAL_ROLES = setOf("user", "human")
    private val MODEL_ROLES = setOf("assistant", "ai", "model", "system", "developer")

    private fun roleOf(m: Map<*, *>): String = (m["role"] as? String) ?: (m["type"] as? String) ?: ""

    /** JavaScript `String(v)` of a JSON value: an object is `[object Object]`, an array joins its items with `,` (null items empty). */
    private fun str(v: Any?): String = when (v) {
        is Map<*, *> -> "[object Object]"
        is List<*> -> v.joinToString(",") { if (it == null) "" else str(it) }
        else -> AttestUtil.jsAnyString(v)
    }

    private fun firstNonNull(vararg v: Any?): Any? = v.firstOrNull { it != null }

    /**
     * The context segments a chat message adds, by the conversation's own roles: a user / human turn is the PRINCIPAL (its text, and its
     * other parts); a `tool_result` / `tool-result` part inside any turn, a `tool` / `function` turn, and a turn of an unknown role are
     * UNTRUSTED tool output; assistant / system turns add nothing (the model's output and the developer's prompt are not the principal's
     * choice, and their values never count as principal text).
     */
    fun messageSegments(m: Any?): List<MessageSegment> {
        // an array is an object with no members in the reference
        val msg: Map<*, *> = if (m is Map<*, *>) m else if (m is List<*>) emptyMap<Any?, Any?>() else return emptyList()
        val role = roleOf(msg).lowercase()
        if (role in MODEL_ROLES) return emptyList()
        val content = msg["content"]
        fun toolName(x: Map<*, *>): String =
            str(firstNonNull(x["toolName"], x["name"], x["tool_use_id"], x["toolCallId"], x["tool_call_id"], msg["name"], msg["tool_call_id"]) ?: "tool")
        if (role !in PRINCIPAL_ROLES) return listOf(MessageSegment("tool", toolName(msg), content ?: m))
        if (content !is List<*>) return listOf(MessageSegment("principal", "user", content ?: ""))
        val out = ArrayList<MessageSegment>()
        val text = ArrayList<String>()
        for (part in content) {
            val pt: Map<*, *> = if (part is Map<*, *>) part else if (part is List<*>) emptyMap<Any?, Any?>() else linkedMapOf<String, Any?>("type" to "text", "text" to str(part))
            val t = pt["type"] as? String ?: ""
            if (t == "tool_result" || t == "tool-result" || t == "function_call_output") {
                out.add(MessageSegment("tool", toolName(pt), firstNonNull(pt["content"], pt["result"], pt["output"]) ?: pt))
            } else if (pt["text"] is String) text.add(pt["text"] as String)
            else out.add(MessageSegment("principal", "user", if (part is List<*>) part else pt))
        }
        if (text.isNotEmpty()) out.add(0, MessageSegment("principal", "user", text.joinToString("\n")))
        return out
    }

    private val seenMessages = WeakHashMap<ArgProvenance.Recorder, Int>()

    /**
     * Record a conversation's new messages in the agent's provenance chain (call it with the whole message list before each model turn;
     * messages already recorded are skipped, a shorter list starts over). [target] is a facade handle or a recorder.
     */
    fun recordMessages(target: Any?, messages: List<*>?) {
        val rec = recorderOf(target) ?: return
        if (messages == null) return
        synchronized(seenMessages) {
            val from = seenMessages[rec] ?: 0
            val start = if (messages.size < from) 0 else from
            for (i in start until messages.size) {
                for (seg in messageSegments(messages[i])) {
                    if (seg.origin == "principal") rec.principal(if (seg.content is String) seg.content else Approvals.stringify(seg.content))
                    else rec.tool(seg.source, seg.content)
                }
            }
            seenMessages[rec] = messages.size
        }
    }

    /**
     * Record what the principal asked for: a string is the principal's message; a message list (or `{messages}`) is recorded with
     * [recordMessages]; an object's `input` / `prompt` / `query` / `question` / `message` / `text` string (or message list) is the
     * principal's message. Anything else records nothing (the gate then keeps the context at `agent`: fail closed).
     */
    fun recordInput(target: Any?, input: Any?) {
        val rec = recorderOf(target) ?: return
        when (input) {
            is String -> rec.principal(input)
            is List<*> -> recordMessages(rec, input)
            is Map<*, *> -> {
                (input["messages"] as? List<*>)?.let { recordMessages(rec, it) }
                for (k in listOf("input", "prompt", "query", "question", "message", "text")) {
                    val v = input[k]
                    if (v is String) rec.principal(v) else if (v is List<*>) recordMessages(rec, v)
                }
            }
            else -> {}
        }
    }

    /**
     * Wrap a framework entry point so its first argument, the principal's request, is recorded before it runs. The returned function
     * takes the same arguments.
     */
    fun <R> withPrincipalInput(target: Any?, fn: (List<Any?>) -> R): (List<Any?>) -> R = { args ->
        recordInput(target, args.firstOrNull())
        fn(args)
    }

    /**
     * A provenance bundle from wherever a framework carried it: the bundle object itself, its JSON text, or a `PCA-Provenance` header
     * value (base64url JSON). Null for anything else (the gate then treats the call as unlabelled: fail closed).
     */
    fun provenanceFrom(v: Any?): Any? {
        if (v == null) return null
        if (v is Map<*, *> || v is List<*>) return v
        if (v !is String || v.isEmpty()) return null
        return try {
            Json.parse(v)
        } catch (e: RuntimeException) {
            try { Json.parse(decodePcaHeader(v)) } catch (e2: RuntimeException) { null }
        }
    }

    /** What a guarded dispatch receives so it can carry the proof to the resource server. */
    class PcaCall(val encoded: String, val pcactn: Map<String, Any?>, val headers: Map<String, String>, val provenance: Map<String, Any?>? = null)

    /** A framework-agnostic tool call: `{name, arguments}`. */
    class ToolCall(val name: String, val arguments: Map<String, Any?>)

    /** How a framework tool name maps onto a PCA (verb, resource). */
    fun interface ToolMapping {
        /** The (verb, resource) of the call, or null to decline an unmapped tool. */
        fun map(call: ToolCall): Pair<String, String>?
    }

    /**
     * Bridge a single framework tool call into a PCActn using a name to (verb, resource) mapping. Null when the mapping declines the
     * call (an unmapped tool). The tool's result is not seen here: the caller records it with [recordToolResult].
     */
    @JvmOverloads
    fun bridgeToolCall(agent: Facade.Handle, call: ToolCall, map: ToolMapping, opts: Facade.ActOptions = Facade.ActOptions()): PcaCall? {
        val m = map.map(call) ?: return null
        val r = agent.act(m.first, m.second, call.arguments, opts)
        return PcaCall(r.encoded, r.pcactn, r.headers, r.provenance)
    }

    // ---- the default request readers of a resource-server guard ----

    /**
     * One header value by case-insensitive name (RFC 9110 5.1). A name carried in several spellings with DIFFERENT values is ambiguous:
     * the credential is treated as absent (null), never silently picked. A list value reads its first member.
     */
    private fun headerOf(headers: Map<String, *>, name: String): String? {
        val want = name.lowercase()
        var found: String? = null
        for ((k, raw) in headers) {
            if (k.lowercase() != want) continue
            val v = if (raw is List<*>) raw.firstOrNull() else raw
            if (v !is String) continue
            if (found != null && found != v) return null
            found = v
        }
        return found
    }

    /** A request body as a parsed value: text is parsed under the strict profile (unparseable text is null), anything else is as given. */
    private fun bodyValue(body: Any?): Any? = if (body is String) try { Json.parse(body) } catch (e: RuntimeException) { null } else body

    private fun bodyMember(body: Any?, name: String): Any? = (bodyValue(body) as? Map<*, *>)?.get(name)

    /**
     * The default PCActn reader: the `PCA-Action` header (strict unpadded base64url, a malformed value throws [PcaHeaderError]), else the
     * body member `pcactn` (a string or an object). Null when neither carries one. A body that a framework already parsed has lost its
     * spelling: send the PCActn as a string, or give the raw body text for strict handling.
     */
    @JvmStatic
    @JvmOverloads
    fun defaultExtract(headers: Map<String, *>, body: Any? = null): Any? {
        val h = headerOf(headers, "pca-action")
        if (h != null && h.isNotEmpty()) return decodePcaHeader(h)
        val x = bodyMember(body, "pcactn")
        return if (x is String || x is Map<*, *>) x else null
    }

    /** The default escalation-answer reader: header `PCA-Escalation-Answer` (strict base64url JSON), else body member `escalation_answer`. */
    @JvmStatic
    @JvmOverloads
    fun defaultEscalationAnswer(headers: Map<String, *>, body: Any? = null): Any? {
        val h = headerOf(headers, "pca-escalation-answer")
        if (h != null && h.isNotEmpty()) return Json.parse(decodePcaHeader(h))
        return bodyMember(body, "escalation_answer")
    }

    /** The default provenance-bundle reader: header `PCA-Provenance` (strict base64url JSON), else body member `pca_provenance`. Malformed header text throws. */
    @JvmStatic
    @JvmOverloads
    fun defaultProvenanceBundle(headers: Map<String, *>, body: Any? = null): Any? {
        val h = headerOf(headers, "pca-provenance")
        if (h != null && h.isNotEmpty()) return Json.parse(decodePcaHeader(h))
        return bodyMember(body, "pca_provenance")
    }

    /** The ternary decision of a guard result: `allow` when [ok], `escalate` when it says so, else `deny`. */
    @JvmStatic
    fun decisionOfResult(ok: Boolean, decision: String? = null): String = if (ok) "allow" else if (decision == "escalate") "escalate" else "deny"
}
