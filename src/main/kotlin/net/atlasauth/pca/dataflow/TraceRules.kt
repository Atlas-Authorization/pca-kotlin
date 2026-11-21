package net.atlasauth.pca.dataflow

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.CaveatLang
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * Trace rules: Invariant-style "never B after A" guardrails compiled into K1 `derive` caveats the verifier already enforces over its
 * own signed action history. A caveat only removes authority, so a compiled rule is a restriction by construction. Compilation is
 * fail-strict: anything the target cannot express exactly is a [TraceRuleError]. Rules, selectors, verb tables and edges are JSON
 * trees (Maps / Lists), as on the wire.
 */
object TraceRules {
    const val MAX_TRACE_CAVEATS = 64
    private const val B_CHUNK = 8
    private const val WINDOW_MAX = CaveatLang.DERIVE_MAX_WINDOW_MS

    @JvmField val PRIVATE_READ_TRAITS: List<String> = listOf("pca.pii_access", "pca.financial_data_read", "pca.credential_access", "pca.regulated_data")
    @JvmField val EXTERNAL_SEND_TRAITS: List<String> = listOf("pca.external_communication", "pca.network_egress", "pca.data_export", "pca.public_exposure")

    /** A refusal to compile; [code] is the stable reason (id, syntax, duration, window, selector, unknown_tool, ...). */
    class TraceRuleError(val code: String, message: String) : RuntimeException(message)

    // JavaScript's \s and `.` (no dotAll), spelled for java.util.regex
    private const val WS = " \\t\\n\\u000B\\f\\r\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF"
    private const val DOT = "[^\\n\\r\\u2028\\u2029]"
    private val RULE_ID_RE = Regex("[a-z][a-z0-9_]{0,39}")
    private val VERB_RE = Regex("[A-Za-z0-9_.:/-]{1,256}")
    private val DURATION_RE = Regex("([1-9][0-9]{0,9})(ms|s|m|h|d)")
    private val RULE_RE = Regex("^[$WS]*never[$WS]+($DOT+?)[$WS]+after[$WS]+($DOT+?)[$WS]+within[$WS]+([^$WS]+)[$WS]*\\z")
    private val HEAD_RE = Regex("^raise[$WS]+(?:\"([^\"]*)\"|'([^']*)')[$WS]+if:\\z")
    private val FLOW_RE = Regex("^\\(([A-Za-z0-9_]+):[$WS]*(ToolCall|ToolOutput|Message)\\)[$WS]*->[$WS]*\\(([A-Za-z0-9_]+):[$WS]*(ToolCall|ToolOutput|Message)\\)\\z")
    private val IS_TOOL_RE = Regex("^([A-Za-z0-9_]+)[$WS]+is[$WS]+tool:([A-Za-z0-9_.:/-]+)(\\($DOT*\\))?\\z")

    private fun err(code: String, m: String) = TraceRuleError(code, m)

    /** String.prototype.trim's whitespace (WhiteSpace and LineTerminator). */
    private fun isWs(c: Char): Boolean =
        c == ' ' || c in '\t'..'\r' || c == ' ' || c == ' ' || c in ' '..' ' ||
            c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿'

    private fun trim(s: String): String = s.trim { isWs(it) }

    private fun n(v: Long) = Json.Num(v.toString())

    private fun duration(t: String): Long {
        val m = DURATION_RE.matchEntire(t) ?: throw err("duration", "'$t' is not a duration like 10m, 2h or 7d")
        val unit = when (m.groupValues[2]) {
            "ms" -> 1L
            "s" -> 1000L
            "m" -> 60_000L
            "h" -> 3_600_000L
            else -> 86_400_000L
        }
        val ms = m.groupValues[1].toLong() * unit
        if (ms > WINDOW_MAX) throw err("window", "a window of $t exceeds the 30-day history the verifier keeps")
        return ms
    }

    private fun selector(text: String, neverSide: Boolean): Map<String, Any?> {
        val tools = ArrayList<Any?>()
        val traits = ArrayList<Any?>()
        val resources = ArrayList<Any?>()
        var any = false
        for (raw in text.split(",")) {
            val a = trim(raw)
            if (a == "any") any = true
            else if (a.startsWith("tool:") && VERB_RE.matches(a.substring(5))) tools.add(a.substring(5))
            else if (a.startsWith("trait:") && VERB_RE.matches(a.substring(6))) traits.add(a.substring(6))
            else if (a.startsWith("resource:") && a.length > 9 && a.length <= 9 + 256) {
                if (neverSide) throw err("resource_on_effect", "a resource selector can only name the earlier action (the check reads the current verb)")
                resources.add(a.substring(9))
            } else throw err("selector", "'$a' is not tool:<verb>, trait:<id>, resource:<prefix> or any")
        }
        return linkedMapOf("tools" to tools, "traits" to traits, "resources" to resources, "any" to any)
    }

    private fun checkId(id: String) {
        if (!RULE_ID_RE.matches(id)) throw err("id", "rule id '$id' must match ^[a-z][a-z0-9_]{0,39}$")
    }

    /** Parse `never <B> after <A> within <duration>`. Throws [TraceRuleError]. */
    @JvmStatic fun parseTraceRule(id: String, text: String): Map<String, Any?> = parseImpl(id, text, false, null)

    /** As [parseTraceRule] with a reason (a JSON null reason is carried as a null member). */
    @JvmStatic fun parseTraceRule(id: String, text: String, reason: Any?): Map<String, Any?> = parseImpl(id, text, true, reason)

    private fun parseImpl(id: String, text: String, hasReason: Boolean, reason: Any?): Map<String, Any?> {
        checkId(id)
        val m = RULE_RE.find(text) ?: throw err("syntax", "expected 'never <selector> after <selector> within <duration>', got '$text'")
        val out = LinkedHashMap<String, Any?>()
        out["id"] = id
        out["never"] = selector(m.groupValues[1], true)
        out["after"] = selector(m.groupValues[2], false)
        out["within_ms"] = n(duration(m.groupValues[3]))
        if (hasReason) out["reason"] = reason
        return out
    }

    /**
     * Import the Invariant subset `raise "<msg>" if: (x: ToolCall|ToolOutput) -> (y: ToolCall)` plus `x is tool:<name>` lines.
     * `o.horizon` (a duration) is required; `o.dropUnsupported === true` turns an unsupported condition into a listed removal (a
     * weaker raise condition: strictly more refusals). Returns {rule, dropped}.
     */
    @JvmStatic fun parseInvariantRule(id: String, text: String, o: Map<String, Any?>?): Map<String, Any?> {
        checkId(id)
        val horizon = o?.get("horizon") as? String ?: throw err("horizon", "an Invariant rule has no window: pass the horizon explicitly")
        val withinMs = duration(horizon)
        val lines = text.split("\n").map { trim(it) }.filter { it.isNotEmpty() && !it.startsWith("#") }
        val head = HEAD_RE.find(lines.getOrElse(0) { "" }) ?: throw err("syntax", "the first line must be raise \"<message>\" if:")
        val flow = FLOW_RE.find(lines.getOrElse(1) { "" })
            ?: throw err("unsupported", "the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)")
        val a = flow.groupValues[1]
        val ta = flow.groupValues[2]
        val b = flow.groupValues[3]
        val tb = flow.groupValues[4]
        if (ta == "Message" || tb != "ToolCall") throw err("unsupported", "only a tool call or tool output followed by a tool call can be compiled")
        if (a == b) throw err("syntax", "the two events need distinct names")
        val tools = LinkedHashMap<String, MutableList<Any?>>()
        tools[a] = ArrayList()
        tools[b] = ArrayList()
        val dropped = ArrayList<Any?>()
        val drop = o?.get("dropUnsupported") == true
        for (l in lines.subList(Math.min(2, lines.size), lines.size)) {
            val m = IS_TOOL_RE.find(l)
            val v = m?.groupValues?.get(1)
            // an unmatched optional group is null in the match (groupValues would give "")
            if (m != null && tools.containsKey(v) && m.groups[3] == null) {
                tools[v]!!.add(m.groupValues[2])
                continue
            }
            if (drop) {
                // `x is tool:name({args})` keeps the tool and drops the argument pattern: a wider match, so more refusals
                if (m != null && tools.containsKey(v)) tools[v]!!.add(m.groupValues[2])
                dropped.add(l)
                continue
            }
            throw err("unsupported", "'$l' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead")
        }
        for (v in arrayOf(a, b)) {
            if (tools[v]!!.size > 1) throw err("unsatisfiable", "'$v' is constrained to two different tools, so the rule can never fire")
        }
        val rule = LinkedHashMap<String, Any?>()
        rule["id"] = id
        rule["never"] = sel(tools[b]!!)
        rule["after"] = sel(tools[a]!!)
        rule["within_ms"] = n(withinMs)
        rule["reason"] = head.groups[1]?.value ?: head.groups[2]?.value ?: ""
        return linkedMapOf("rule" to rule, "dropped" to dropped)
    }

    private fun sel(tools: List<Any?>): Map<String, Any?> =
        linkedMapOf("tools" to ArrayList(tools), "traits" to ArrayList<Any?>(), "resources" to ArrayList<Any?>(), "any" to tools.isEmpty())

    // ---- compile ------------------------------------------------------------------------------------------------------------

    @Suppress("UNCHECKED_CAST")
    private fun list(o: Any?, what: String): List<Any?> = o as? List<Any?> ?: throw IllegalArgumentException("TypeError: $what is not iterable")

    private fun expand(s: Map<*, *>, table: Map<*, *>, what: String): List<String> {
        val verbs = table.keys.map { it as String }.sorted()
        val out = LinkedHashSet<String>()
        if (Js.truthy(s["any"])) out.addAll(verbs)
        for (t in list(s["tools"], "tools")) {
            if (t !is String || !table.containsKey(t)) throw err("unknown_tool", what + ": tool '" + Js.template(t) + "' is not an action in the verb table")
            out.add(t)
        }
        for (tr in list(s["traits"], "traits")) {
            val hit = verbs.filter { list(Js.member(table[it], "traits"), "traits").contains(tr) }
            if (hit.isEmpty()) throw err("empty_selector", what + ": trait '" + Js.template(tr) + "' matches no action")
            out.addAll(hit)
        }
        return out.sorted()
    }

    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = linkedMapOf(*kv)

    internal fun isSafeInteger(o: Any?): Boolean = Detectors.isSafeInteger(o)

    /** Lower rules to K1 derive caveats over the verifier's history. Returns {caveats, edges, digest}; throws [TraceRuleError]. */
    @JvmStatic fun compileTraceRules(rules: Any?, table: Map<String, Any?>): Map<String, Any?> {
        val caveats = ArrayList<Any?>()
        val edges = ArrayList<Any?>()
        val ids = LinkedHashSet<Any?>()
        for (ro in list(rules, "rules")) {
            val r = ro as Map<*, *>
            // `RULE_ID_RE.test(r.id)` coerces: a missing id reads as the text "undefined", which is a valid id
            val id = if (r.containsKey("id")) Js.template(r["id"]) else "undefined"
            val idKey = if (r.containsKey("id")) r["id"] else "<missing>"
            if (!RULE_ID_RE.matches(id) || ids.contains(idKey)) throw err("id", "rule id '$id' is malformed or repeated")
            ids.add(idKey)
            val w = r["within_ms"]
            if (!(isSafeInteger(w) && Js.num(w)!! >= 1 && Js.num(w)!! <= WINDOW_MAX)) throw err("window", "rule '$id': within_ms must be 1..30 days")
            val never = r["never"] as Map<*, *>
            val after = r["after"] as Map<*, *>
            if (list(never["resources"], "resources").isNotEmpty()) throw err("resource_on_effect", "rule '$id': a resource selector cannot name the later action")
            val bs = expand(never, table, "rule '$id' never")
            val sides = ArrayList<Map<String, Any?>>()
            for (v in expand(after, table, "rule '$id' after")) sides.add(obj("verb" to v))
            val ps = LinkedHashSet<String>().also { set -> for (p in list(after["resources"], "resources")) set.add(p as String) }.sorted()
            for (p in ps) sides.add(obj("resource_prefix" to p))
            if (bs.isEmpty() || sides.isEmpty()) throw err("empty_selector", "rule '$id': a side matches nothing")
            var cnt = 0
            for (a in sides) {
                var i = 0
                while (i < bs.size) {
                    val orArgs = ArrayList<Any?>()
                    for (v in bs.subList(i, Math.min(i + B_CHUNK, bs.size))) orArgs.add(obj("op" to "eq", "a" to obj("ref" to "verb"), "b" to obj("const" to v)))
                    val isB = obj("op" to "or", "args" to orArgs)
                    val seen = obj("name" to "seen", "kind" to "count", "window_ms" to w)
                    seen.putAll(a)
                    val c = obj(
                        "type" to "derive",
                        "id" to "trace." + id + "." + (cnt++),
                        "defs" to arrayListOf<Any?>(seen, obj("name" to "verb", "kind" to "action", "field" to "verb"), obj("name" to "is_b", "kind" to "expr", "expr" to isB)),
                        "check" to obj("op" to "not", "arg" to obj("op" to "and", "args" to arrayListOf<Any?>(
                            obj("op" to "gt", "a" to obj("ref" to "seen"), "b" to obj("const" to n(0))), obj("ref" to "is_b")))),
                    )
                    val e = CaveatLang.deriveError(c)
                    if (e != null) throw err("internal", "rule '$id' compiled to an invalid caveat: $e")
                    caveats.add(c)
                    if (caveats.size > MAX_TRACE_CAVEATS) throw err("too_large", "more than $MAX_TRACE_CAVEATS caveats: split the rule set or narrow the selectors")
                    i += B_CHUNK
                }
                for (v in bs) {
                    edges.add(obj("rule" to id, "from" to (if (a.containsKey("verb")) obj("tool" to a["verb"]) else obj("resource" to a["resource_prefix"])), "to" to v, "within_ms" to w))
                }
            }
        }
        return obj("caveats" to caveats, "edges" to edges, "digest" to Pca.hashCanonical(obj("d" to "atlas-pca/trace-rules/v1", "caveats" to caveats)))
    }

    // ---- lethal trifecta lint -----------------------------------------------------------------------------------------------

    private fun has(def: Any?, traits: List<*>): Boolean = list(Js.member(def, "traits"), "traits").any { traits.contains(it) }

    private fun readOnly(def: Any?): Boolean {
        val ef = Js.get(def, "effects")
        val effects = if (ef == null) emptyList() else list(ef, "effects")
        return effects.isNotEmpty() && effects.all { it == "read" }
    }

    /**
     * The lethal trifecta: private data, untrusted content and a way out in one action set. A send is cut off when every untrusted
     * read, or every private read, has an edge rule to it. A lint: it reports, it does not enforce. [o] = {untrusted?,
     * untrusted_traits?}; a null [o] throws, as JavaScript does reading a member of null.
     */
    @JvmStatic fun lethalTrifecta(table: Map<String, Any?>, edges: List<Any?>?, o: Map<String, Any?>?): Map<String, Any?> {
        val verbs = table.keys.sorted()
        if (o == null) throw IllegalArgumentException("TypeError: cannot read 'untrusted' of null")
        val untrustedO = o["untrusted"]
        val untrustedTraitsO = o["untrusted_traits"]
        val untrustedL = if (untrustedO == null) emptyList() else list(untrustedO, "untrusted")
        val untrustedTraits = if (untrustedTraitsO == null) emptyList() else list(untrustedTraitsO, "untrusted_traits")
        val priv = ArrayList<Any?>()
        val untrusted = ArrayList<Any?>()
        val sends = ArrayList<Any?>()
        for (v in verbs) {
            val def = table[v]
            if (has(def, PRIVATE_READ_TRAITS)) priv.add(v)
            if (untrustedL.contains(v) || has(def, untrustedTraits) || (readOnly(def) && list(Js.member(def, "traits"), "traits").contains("pca.network_egress"))) untrusted.add(v)
            if (has(def, EXTERNAL_SEND_TRAITS) && !readOnly(def)) sends.add(v)
        }
        val findings = ArrayList<Any?>()
        if (priv.isNotEmpty() && untrusted.isNotEmpty() && sends.isNotEmpty()) {
            for (s in sends) {
                val fu = untrusted.filter { !ruled(edges, it, s) }
                val fp = priv.filter { !ruled(edges, it, s) }
                if (fu.isNotEmpty() && fp.isNotEmpty()) findings.add(obj("send" to s, "from_untrusted" to fu, "from_private" to fp))
            }
        }
        return obj("private_reads" to priv, "untrusted_reads" to untrusted, "sends" to sends, "findings" to findings)
    }

    private fun ruled(edges: List<Any?>?, from: Any?, to: Any?): Boolean {
        for (eo in list(edges, "edges")) {
            val f = Js.member(eo, "from")
            if (f is Map<*, *> && f.containsKey("tool") && from == f["tool"] && to == (eo as Map<*, *>)["to"]) return true
        }
        return false
    }
}
