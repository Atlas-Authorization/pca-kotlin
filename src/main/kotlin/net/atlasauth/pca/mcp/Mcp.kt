package net.atlasauth.pca.mcp

import java.util.Locale
import net.atlasauth.pca.a2a.A2aPca
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.A2a
import net.atlasauth.pca.verifier.ActionSchema
import net.atlasauth.pca.verifier.Agent
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import okhttp3.Request

/**
 * The Model Context Protocol adapter for Proof-Carrying Authority: wrap a tool handler so every call carries a fresh PCActn, derive a site
 * action schema from the tools an MCP server lists and check a tool call against it, attach the proof to a client transport request, and the
 * client half of MCP authorization step-up. Values are parsed JSON (Map, List, String, Boolean, [Json.Num], null).
 *
 * This does not authorize: it attaches a proof-carrying action; the resource server's verifier decides. A bypassed wrapper just means
 * the action lacks a valid PCActn and fails server-side.
 *
 * Differences from the TypeScript package, by design: the [Agent] builds the proof and carries its own audience, so there is no
 * local dry-run fast-fail, no per-call audience override and no provenance recorder here; [withPca] turns a refused build
 * (the agent throws) into an MCP error result. The optional action-kit importer (`importActionDefsFromMcp`) is not ported (it needs an
 * optional experimental package); the v1 draft ([McpDraft]) is.
 */
@Suppress("UNCHECKED_CAST")
object Mcp {
    /** The header a proof travels in. */
    const val PCA_ACTION_HEADER = Agent.HEADER

    /** Key under which a tool result carries the encoded PCActn in its `_meta`. */
    const val RESULT_META_KEY = "x-pca-action"

    // ---- handlers ----

    /** An MCP tool handler: `(args, extra) -> result` where the result is an MCP tool result map (`content`, optional `isError`). */
    fun interface ToolHandler {
        @Throws(Exception::class)
        fun call(args: Map<String, Any?>, extra: Any?): Map<String, Any?>
    }

    /** Which PCA action a tool is: the catalog `verb`, the resource (fixed, or derived from the args), and the optional proof receiver. */
    class GuardToolSpec {
        var verb: String = ""
        var resource: String? = null
        var resourceOf: ((Map<String, Any?>) -> String)? = null

        /** Receives the PCActn so the proof can be forwarded (for example as a request header) to the resource server. */
        var onProof: ((Map<String, Any?>, Map<String, Any?>) -> Unit)? = null
    }

    /** The tool error [withPca] returns when the proof cannot be built: a text content item and `isError: true`. */
    @JvmStatic
    fun deniedResult(text: String): Map<String, Any?> {
        val item = linkedMapOf<String, Any?>("type" to "text", "text" to text)
        return linkedMapOf("content" to arrayListOf<Any?>(item), "isError" to true)
    }

    /**
     * Wrap a tool handler so each call builds a PCActn before the original handler runs. When the agent refuses to build the proof (it throws
     * IllegalArgumentException or IllegalStateException) the wrapper returns an MCP error result instead of throwing, so the model sees it.
     */
    @JvmStatic
    fun withPca(agent: Agent, spec: GuardToolSpec, handler: ToolHandler): ToolHandler = ToolHandler { args, extra ->
        val pca: Map<String, Any?>
        try {
            val of = spec.resourceOf
            val resource = if (of != null) of(args) else spec.resource
            pca = agent.act(spec.verb, resource!!, args)
        } catch (e: IllegalArgumentException) {
            return@ToolHandler deniedResult(e.message ?: "denied")
        } catch (e: IllegalStateException) {
            return@ToolHandler deniedResult(e.message ?: "denied")
        }
        spec.onProof?.invoke(pca, args)
        handler.call(args, extra)
    }

    /**
     * Attach the encoded PCActn into a result's `_meta` so a downstream gateway or resource server can read the proof off the tool
     * result. Additive: existing `content`, `isError` and `_meta` members are kept. [pca]: an object with `encoded`.
     */
    @JvmStatic
    fun guardToolResult(pca: Any?, result: Any?): Map<String, Any?> {
        val encoded = if (pca is Map<*, *>) pca["encoded"] else null
        val hasEncoded = pca is Map<*, *> && pca.containsKey("encoded")
        if (pca == null) throw IllegalStateException("TypeError: cannot read properties of null (reading 'encoded')")
        if (result == null) throw IllegalStateException("TypeError: cannot read properties of null (reading '_meta')")
        val prev = if (result is Map<*, *>) result["_meta"] else null
        val meta: LinkedHashMap<String, Any?> = if (Js.truthy(prev) && (prev is Map<*, *> || prev is List<*>)) A2aPca.spread(prev) else LinkedHashMap()
        // `{..., key: pca.encoded}` with encoded undefined overwrites a previous value with undefined, which JSON drops
        if (hasEncoded) meta[RESULT_META_KEY] = encoded else meta.remove(RESULT_META_KEY)
        val out = A2aPca.spread(result)
        out["_meta"] = meta
        return out
    }

    /** [guardToolResult] for a proof already encoded as its header value. */
    @JvmStatic
    fun guardToolResult(encoded: String, result: Map<String, Any?>): Map<String, Any?> = guardToolResult(linkedMapOf<String, Any?>("encoded" to encoded), result)

    /** The request headers a proof travels in: `{PCA-Action: base64url(UTF-8 of the encoded PCActn JSON)}` (the provenance header is not produced here). */
    @JvmStatic
    fun pcaHeaders(encoded: String): Map<String, String> = linkedMapOf(PCA_ACTION_HEADER to Keys.b64u(Json.utf8(encoded)))

    // ---- client transport ----

    /** Which PCA action an MCP tool call is: `(verb, resource)`; null = send the call without a proof. */
    fun interface ToolActionMap {
        fun map(tool: String, args: Map<String, Any?>): Pair<String, String>?
    }

    /** The `tools/call` a JSON-RPC body carries: `{name, arguments}` (arguments an object, `{}` when absent or not an object), else null. */
    @JvmStatic
    fun toolCallOf(body: Any?): Map<String, Any?>? {
        if (body !is String) return null
        val msg = try {
            Json.parseLenient(body)
        } catch (e: RuntimeException) {
            return null
        }
        if (msg !is Map<*, *> || msg["method"] != "tools/call") return null
        val params = msg["params"]
        val name = if (params is Map<*, *>) params["name"] else null
        val args = if (params is Map<*, *>) params["arguments"] else null
        if (name !is String) return null
        return linkedMapOf("name" to name, "arguments" to (if (args is Map<*, *>) args else LinkedHashMap<String, Any?>()))
    }

    /**
     * The agent side of an MCP server that requires a PCActn per tool call: for a JSON-RPC `tools/call` body, build a fresh proof for that call
     * (verb and resource from [toolAction], the arguments committed by digest, a new counter) and add it as the `PCA-Action` header.
     * Every other request is returned unchanged. It decides nothing: the server's verifier does.
     */
    @JvmStatic
    fun withProof(agent: Agent, toolAction: ToolActionMap, request: Request.Builder, body: String?): Request.Builder {
        val call = toolCallOf(body) ?: return request
        val args = call["arguments"] as Map<String, Any?>
        val act = toolAction.map(call["name"] as String, args) ?: return request
        return request.header(Agent.HEADER, Agent.header(agent.act(act.first, act.second, args)))
    }

    // ---- site action schema ----

    /** Anything that lists tools like an MCP client or server (`tools/list`): the result map carries `tools`. */
    fun interface ToolLister {
        fun listTools(): Map<String, Any?>
    }

    /**
     * Draft an action schema from an MCP tool list. [site]: `site`, `aud`, `version`, optional `verbPrefix`.
     * Every write verb is drafted `irreversible` (the fail-closed default); the result is `{schema, todo}`.
     */
    @JvmStatic
    fun draftActionSchemaFromMcp(tools: List<Any?>, site: Map<String, Any?>): Map<String, Any?> = McpDraft.draft(tools, site)

    /** As [draftActionSchemaFromMcp], listing the tools from a client or server first. */
    @JvmStatic
    fun draftActionSchemaFromMcp(source: ToolLister, site: Map<String, Any?>): Map<String, Any?> =
        McpDraft.draft(source.listTools()["tools"] as List<Any?>, site)

    private val INT_KEY = Regex("0|[1-9][0-9]{0,8}")

    /** `Object.entries(o)` order: array-index keys ascending, then the others in insertion order. */
    private fun entries(o: Any?): List<Pair<String, Any?>> {
        if (o == null) throw IllegalStateException("TypeError: cannot convert undefined or null to object")
        val keys = McpDraft.keysOf(o)
        val ints = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in keys) (if (INT_KEY.matches(k)) ints else rest).add(k)
        ints.sortWith(Comparator { a, b -> a.toLong().compareTo(b.toLong()) })
        val out = ArrayList<Pair<String, Any?>>()
        for (k in ints) out.add(k to McpDraft.valueOf(o, k))
        for (k in rest) out.add(k to McpDraft.valueOf(o, k))
        return out
    }

    /** `JSON.parse(JSON.stringify(v))` for parsed JSON: a deep copy where -0 becomes 0. */
    private fun copy(v: Any?): Any? {
        if (v is Map<*, *>) {
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in v) out[k as String] = copy(x)
            return out
        }
        if (v is List<*>) return ArrayList<Any?>(v.map { copy(it) })
        if (v is Json.Num && v.raw == "-0") return Json.Num("0")
        return v
    }

    /**
     * Record the developer's decisions on a draft (a new object). [d]: `verbs` (per verb `reversibility` and `params`: a partial
     * declaration per parameter path), optional `units`. A decision about a verb or parameter the draft does not have throws: the schema is
     * closed, so a typo must not silently publish a looser schema.
     */
    @JvmStatic
    fun applySchemaDecisions(draft: Any?, d: Map<String, Any?>): Map<String, Any?> {
        val out = copy(draft) as MutableMap<String, Any?>
        if (Js.truthy(d["units"])) {
            val u = out["units"]
            val merged = A2aPca.spread(u ?: LinkedHashMap<String, Any?>())
            merged.putAll(A2aPca.spread(d["units"]))
            out["units"] = merged
        }
        val verbs = out["verbs"]
        for ((verb, dv) in entries(d["verbs"])) {
            if (verbs !is List<*>) throw IllegalStateException("TypeError: out.verbs.find is not a function")
            var v: MutableMap<String, Any?>? = null
            for (x in verbs) {
                if (x == null) throw IllegalStateException("TypeError: cannot read properties of null (reading 'verb')")
                if (x is Map<*, *> && verb == x["verb"]) { v = x as MutableMap<String, Any?>; break }
            }
            if (v == null) throw IllegalArgumentException("applySchemaDecisions: the draft has no verb '$verb'")
            if (dv == null) throw IllegalStateException("TypeError: cannot read properties of null (reading 'reversibility')")
            val rev = if (dv is Map<*, *>) dv["reversibility"] else null
            if (Js.truthy(rev)) v["reversibility"] = rev
            val dp = if (dv is Map<*, *>) dv["params"] else null
            for ((pk, pv) in entries(dp ?: LinkedHashMap<String, Any?>())) {
                val params = v["params"]
                val p = if (params is Map<*, *>) params[pk] else null
                if (!Js.truthy(p)) throw IllegalArgumentException("applySchemaDecisions: verb '$verb' has no parameter '$pk'")
                if (p is Map<*, *>) (p as MutableMap<String, Any?>).putAll(A2aPca.spread(pv))
            }
        }
        return out
    }

    /** The first verb entry that maps a tool (`mcp.tool`), or null. A verbs member that is not an array throws, as the reference does. */
    private fun entryOfTool(schema: Any?, toolName: Any?): Map<String, Any?>? {
        val verbs = if (schema is Map<*, *>) schema["verbs"] else null
        if (schema == null) throw IllegalStateException("TypeError: cannot read properties of null (reading 'verbs')")
        if (verbs !is List<*>) throw IllegalStateException("TypeError: schema.verbs.find is not a function")
        for (v in verbs) {
            if (v == null) throw IllegalStateException("TypeError: cannot read properties of null (reading 'mcp')")
            val mcp = if (v is Map<*, *>) v["mcp"] else null
            val tool = if (mcp is Map<*, *>) mcp["tool"] else null
            if (tool != null && tool == toolName) return if (v is Map<*, *>) v as Map<String, Any?> else null
        }
        return null
    }

    /** The schema verb an MCP tool maps to (by `mcp.tool`), or null. */
    @JvmStatic
    fun verbOfTool(schema: Any?, toolName: Any?): String? {
        val e = entryOfTool(schema, toolName)
        return if (e != null && e["verb"] is String) e["verb"] as String else null
    }

    /** Closed-world check of a tool call against the site schema (an unmapped tool is an unknown verb): `{ok:true, verb}` or `{ok:false, code, path?, reason}`. */
    @JvmStatic
    fun conformToolCall(schema: Any?, toolName: String, args: Any?): Map<String, Any?> {
        val verb = verbOfTool(schema, toolName)
        val out = LinkedHashMap<String, Any?>()
        if (verb == null) {
            out["ok"] = false
            out["code"] = "unknown_verb"
            out["reason"] = "MCP tool '$toolName' is not declared by the site schema"
            return out
        }
        val c = ActionSchema.conform(schema, verb, args)
        if (c.ok) {
            out["ok"] = true
            for (v in (schema as Map<String, Any?>)["verbs"] as List<Any?>) {
                if (v is Map<*, *> && verb == v["verb"]) { out["verb"] = v; break }
            }
            return out
        }
        out["ok"] = false
        out["code"] = c.code
        if (c.path != null) out["path"] = c.path
        out["reason"] = c.reason
        return out
    }

    // ---- authorization step-up (client) ----

    private const val JS_WS = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
    private val NEED_PARAM = Regex("(?:^|[" + JS_WS + ",])pca_need=\"([^\"\\\\]*)\"")

    /** The need a `pca_need` auth-param carries, decoded (`{ok:true, need}` or `{ok:false, code}`); null when the header names none. */
    @JvmStatic
    fun pcaNeedFromChallenge(header: Any?): Map<String, Any?>? {
        if (header !is String) return null
        val m = NEED_PARAM.find(header) ?: return null
        val d = A2a.decodeNeed(m.groupValues[1])
        val out = LinkedHashMap<String, Any?>()
        out["ok"] = d.need != null
        if (d.need != null) out["need"] = d.need else out["code"] = d.code
        return out
    }

    /** Parse the value of a `WWW-Authenticate` header into its challenges (`scheme` lower-cased; `params` names lower-cased, quoted values unescaped, a repeated name keeps its first value). Never throws. */
    @JvmStatic
    fun parseChallenges(headerO: Any?): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        if (headerO !is String) return out
        val h: String = headerO
        val n = h.length
        var pos = 0
        var cur: LinkedHashMap<String, Any?>? = null

        fun skipWs() {
            while (pos < n && (h[pos] == ' ' || h[pos] == '\t' || h[pos] == ',')) pos++
        }

        fun token(): String {
            val s = pos
            while (pos < n && " \t,=\"".indexOf(h[pos]) < 0) pos++
            return h.substring(s, pos)
        }

        skipWs()
        while (pos < n) {
            val name = token()
            if (name.isEmpty()) { pos++; continue } // a stray quote or equals sign: skip it
            while (pos < n && (h[pos] == ' ' || h[pos] == '\t')) pos++
            if (pos < n && h[pos] == '=') {
                pos++
                while (pos < n && (h[pos] == ' ' || h[pos] == '\t')) pos++
                val value = StringBuilder()
                if (pos < n && h[pos] == '"') {
                    pos++
                    while (pos < n && h[pos] != '"') {
                        if (h[pos] == '\\' && pos + 1 < n) pos++
                        value.append(h[pos])
                        pos++
                    }
                    pos++ // closing quote
                } else value.append(token())
                val key = name.lowercase(Locale.ROOT)
                // the reference stores params in a plain object: names it already inherits are never (re)written
                val c = cur
                val params = if (c == null) null else c["params"] as MutableMap<String, Any?>
                if (c != null && params != null && !params.containsKey(key) && key != "constructor" && key != "__proto__") params[key] = value.toString()
            } else {
                val c = LinkedHashMap<String, Any?>()
                c["scheme"] = name.lowercase(Locale.ROOT)
                c["params"] = LinkedHashMap<String, Any?>()
                out.add(c)
                cur = c
            }
            skipWs()
        }
        return out
    }

    private fun splitScopes(s: Any?): List<String> {
        val out = ArrayList<String>()
        if (s !is String) return out
        for (x in s.split(" ")) if (x.isNotEmpty()) out.add(x)
        return out
    }

    /**
     * What to do with a response. Only `403` with `error="insufficient_scope"` on a Bearer challenge is a step-up. The new scope list is the UNION of
     * what was requested before and what the challenge names, sorted; with `pcaAware` a valid `pca_need` hands the typed requirement to the approval
     * flow and still carries the scope union as the fallback; a union that adds nothing (and no usable need) gives up instead of looping. The attempt counter
     * bounds every path. [state]: `requested` (scopes), `attempts`, optional `maxAttempts` (default 3) and `pcaAware`.
     * Result: `{action:"scope", scopes, attempts}`, `{action:"pca", need, fallbackScopes, attempts}` or `{action:"give_up", reason}`.
     */
    @JvmStatic
    fun planStepUp(status: Any?, wwwAuthenticate: Any?, state: Map<String, Any?>): Map<String, Any?> {
        val max = if (state["maxAttempts"] != null) numOf(state["maxAttempts"]) else 3.0
        var bearer: Map<String, Any?>? = null
        val st = Js.num(status)
        if (st != null && st == 403.0) for (c in parseChallenges(wwwAuthenticate)) if ("bearer" == c["scheme"]) { bearer = c; break }
        val bparams = if (bearer == null) null else bearer["params"] as Map<String, Any?>
        if (bearer == null || bparams == null || "insufficient_scope" != bparams["error"]) return giveUp("not_insufficient_scope")
        val attemptsIn = numOf(state["attempts"])
        if (!(attemptsIn.isFinite() && attemptsIn < max)) return giveUp("retry_limit")
        val requested = state["requested"] as List<Any?>
        val had = LinkedHashSet<Any?>(requested)
        val u = LinkedHashSet<String>()
        for (r in requested) u.add(r.toString())
        u.addAll(splitScopes(bparams["scope"]))
        val union = ArrayList<String>(u)
        union.sort()
        val attempts = attemptsIn + 1
        if (state["pcaAware"] == true) {
            val r = if (wwwAuthenticate is String) pcaNeedFromChallenge(wwwAuthenticate) else null
            if (r != null && r["ok"] == true) {
                val out = LinkedHashMap<String, Any?>()
                out["action"] = "pca"
                out["need"] = r["need"]
                out["fallbackScopes"] = ArrayList<Any?>(union)
                out["attempts"] = McpDraft.num(attempts)
                return out // a missing or malformed pca_need is not an error: it falls through to the stock behaviour below
            }
        }
        var allHad = true
        for (s in union) if (!had.contains(s)) { allHad = false; break }
        if (allHad) return giveUp("no_new_scope")
        val out = LinkedHashMap<String, Any?>()
        out["action"] = "scope"
        out["scopes"] = ArrayList<Any?>(union)
        out["attempts"] = McpDraft.num(attempts)
        return out
    }

    private fun numOf(o: Any?): Double = Js.num(o) ?: Double.NaN

    private fun giveUp(reason: String): Map<String, Any?> = linkedMapOf("action" to "give_up", "reason" to reason)

    /** The reason a present-but-unusable `pca_need` was ignored (for client logs), or null. */
    @JvmStatic
    fun pcaNeedProblem(wwwAuthenticate: Any?): String? {
        val r = pcaNeedFromChallenge(wwwAuthenticate)
        return if (r != null && r["ok"] == false) r["code"] as String? else null
    }

    /**
     * RFC 9207 section 2.4 as tabulated in the MCP authorization specification: compare a present `iss` with the recorded issuer by plain string comparison
     * (no case folding, default-port elision, trailing-slash or percent-encoding normalization); reject an absent `iss` only when the server advertised
     * `authorization_response_iss_parameter_supported: true`. Without a recorded issuer nothing can be checked and the response is refused.
     * [a]: `recordedIssuer`, `issParameterSupported`, `iss` (absent or null differ: null never equals the recorded issuer).
     */
    @JvmStatic
    fun checkAuthorizationResponseIss(a: Map<String, Any?>): Map<String, Any?> {
        val rec = a["recordedIssuer"]
        if (rec !is String || rec.isEmpty()) return iss(false, "no_recorded_issuer")
        if (!a.containsKey("iss")) return if (a["issParameterSupported"] == true) iss(false, "iss_missing") else iss(true, null)
        return if (rec == a["iss"]) iss(true, null) else iss(false, "iss_mismatch")
    }

    private fun iss(proceed: Boolean, reason: String?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["proceed"] = proceed
        if (reason != null) m["reason"] = reason
        return m
    }

    // ---- conformance matrix (client side of step-up) ----

    @JvmField
    val MCP_CLIENT_REVISIONS: List<String> = listOf("2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "draft")

    private fun row(id: String, requirement: String, section: String, a: String, b: String, c: String, d: String, e: String): Map<String, Any?> {
        val levels = LinkedHashMap<String, Any?>()
        val v = listOf(a, b, c, d, e)
        for (i in MCP_CLIENT_REVISIONS.indices) levels[MCP_CLIENT_REVISIONS[i]] = v[i]
        val r = LinkedHashMap<String, Any?>()
        r["id"] = id
        r["requirement"] = requirement
        r["levels"] = levels
        r["section"] = section
        return r
    }

    /** The MCP authorization conformance matrix for the client side of step-up: one row per requirement, the level per specification revision. */
    @JvmStatic
    fun mcpAuthClientRows(): List<Map<String, Any?>> = listOf(
        row("parse-www-authenticate", "Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.", "Protected Resource Metadata Discovery Requirements", "n/a", "MUST", "MUST", "MUST", "MUST"),
        row("step-up-on-insufficient-scope", "Respond to 403 insufficient_scope by re-authorizing with an increased scope set.", "Step-Up Authorization Flow", "n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"),
        row("scope-union", "The new scope set is the union of the previously requested set and the challenge scopes.", "Step-Up Authorization Flow, step 2", "n/a", "n/a", "n/a", "SHOULD", "SHOULD"),
        row("retry-limit", "Retry no more than a few times and track upgrade attempts per resource and operation.", "Step-Up Authorization Flow, step 4", "n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"),
        row("iss-validation-table", "Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.", "Authorization Response Validation", "n/a", "n/a", "n/a", "MUST", "MUST"),
        row("pca-need-ignored-by-stock-client", "A client that does not know pca_need behaves exactly as without it.", "RFC 9110 section 11.2 (unknown auth-params are ignored)", "EXT", "EXT", "EXT", "EXT", "EXT"),
    )
}
