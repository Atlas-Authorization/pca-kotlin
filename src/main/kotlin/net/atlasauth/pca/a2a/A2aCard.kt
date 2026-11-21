package net.atlasauth.pca.a2a

import net.atlasauth.pca.verifier.Json

/**
 * Two things A2A 1.0 section 8.4 needs from an Agent Card implementation: [jcsBytes] (RFC 8785 canonical JSON, the bytes a card
 * signature covers) and [validateAgentCard1] (the A2A 1.0 `AgentCard` message). Shared by the A2A and agent-card ports.
 * Values are parsed JSON (Map, List, String, Boolean, [Json.Num], null) or plain Kotlin numbers.
 */
object A2aCard {
    private const val MAX_DEPTH = 64

    /** RFC 8785 canonical UTF-8 bytes of a JSON value; IllegalArgumentException for a value with no JSON form (non-finite number, lone surrogate, nesting over 64). */
    @JvmStatic
    fun jcsBytes(value: Any?): ByteArray = jcs(value, 1).toByteArray(Charsets.UTF_8)

    private fun jcs(v: Any?, depth: Int): String {
        if (v == null) return "null"
        if (v is Boolean) return if (v) "true" else "false"
        if (v is Json.Num || v is Number) {
            val d = if (v is Json.Num) v.raw.toDouble() else (v as Number).toDouble()
            if (d.isNaN() || d.isInfinite()) throw IllegalArgumentException("jcs: non-finite number")
            return if (d == 0.0) "0" else Json.esNumber(d) // -0 prints 0, as RFC 8785 requires
        }
        if (v is String) return str(v, "jcs: lone surrogate in string")
        if (v !is Map<*, *> && v !is List<*>) throw IllegalArgumentException("jcs: unsupported type")
        if (depth > MAX_DEPTH) throw IllegalArgumentException("jcs: nesting too deep")
        val sb = StringBuilder()
        if (v is List<*>) {
            sb.append('[')
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                sb.append(jcs(x, depth + 1))
            }
            return sb.append(']').toString()
        }
        val m = v as Map<*, *>
        val keys = ArrayList<String>()
        for (k in m.keys) keys.add(k as String)
        keys.sort() // String.compareTo is UTF-16 code unit order, as the default JavaScript sort
        sb.append('{')
        var first = true
        for (k in keys) {
            if (!first) sb.append(',')
            first = false
            sb.append(str(k, "jcs: lone surrogate in key")).append(':').append(jcs(m[k], depth + 1))
        }
        return sb.append('}').toString()
    }

    /** JSON.stringify of a string (well-formed: a lone surrogate is refused first). */
    internal fun str(s: String, loneMsg: String): String {
        if (Json.hasLoneSurrogate(s)) throw IllegalArgumentException(loneMsg)
        val sb = StringBuilder("\"")
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000c' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c < ' ') sb.append(String.format(java.util.Locale.ROOT, "\\u%04x", c.code)) else sb.append(c)
            }
        }
        return sb.append('"').toString()
    }

    private fun isObj(v: Any?) = v is Map<*, *>
    private fun isStr(v: Any?) = v is String
    private fun get(o: Any?, k: String): Any? = (o as Map<*, *>)[k]
    private fun has(o: Any?, k: String): Boolean = (o as Map<*, *>).containsKey(k)

    private fun reqStr(p: MutableList<String>, o: Any?, k: String, at: String) {
        if (!isStr(get(o, k)) || "" == get(o, k)) p.add("$at.$k: required non-empty string")
    }

    private fun optStr(p: MutableList<String>, o: Any?, k: String, at: String) {
        if (has(o, k) && !isStr(get(o, k))) p.add("$at.$k: must be a string")
    }

    private fun optBool(p: MutableList<String>, o: Any?, k: String, at: String) {
        if (has(o, k) && get(o, k) !is Boolean) p.add("$at.$k: must be a boolean")
    }

    private fun strArray(p: MutableList<String>, v: Any?, at: String, nonEmpty: Boolean) {
        val ok = v is List<*> && v.all { isStr(it) }
        if (!ok) p.add("$at: must be an array of strings")
        else if (nonEmpty && (v as List<*>).isEmpty()) p.add("$at: must not be empty")
    }

    private fun objArray(p: MutableList<String>, o: Any?, k: String, at: String, required: Boolean, nonEmpty: Boolean, each: (Any?, String) -> Unit) {
        if (!has(o, k)) {
            if (required) p.add("$at.$k: required array")
            return
        }
        val v = get(o, k)
        if (v !is List<*>) { p.add("$at.$k: must be an array"); return }
        if (nonEmpty && v.isEmpty()) p.add("$at.$k: must not be empty")
        for (i in v.indices) {
            val ea = "$at.$k[$i]"
            if (isObj(v[i])) each(v[i], ea) else p.add("$ea: must be an object")
        }
    }

    /** Check an object against the A2A 1.0 `AgentCard` message. Returns the problems found, each with a JSON path (empty = valid). */
    @JvmStatic
    fun validateAgentCard1(card: Any?): List<String> {
        val p = ArrayList<String>()
        if (!isObj(card)) { p.add("\$: the agent card must be an object"); return p }
        reqStr(p, card, "name", "$")
        reqStr(p, card, "description", "$")
        reqStr(p, card, "version", "$")
        optStr(p, card, "documentationUrl", "$")
        optStr(p, card, "iconUrl", "$")
        objArray(p, card, "supportedInterfaces", "$", true, true) { e, at ->
            reqStr(p, e, "url", at)
            reqStr(p, e, "protocolBinding", at)
            reqStr(p, e, "protocolVersion", at)
            optStr(p, e, "tenant", at)
        }
        if (has(card, "provider")) {
            val pr = get(card, "provider")
            if (!isObj(pr)) p.add("\$.provider: must be an object")
            else {
                reqStr(p, pr, "url", "$.provider")
                reqStr(p, pr, "organization", "$.provider")
            }
        }
        if (!isObj(get(card, "capabilities"))) p.add("\$.capabilities: required object")
        else {
            val c = get(card, "capabilities")
            optBool(p, c, "streaming", "$.capabilities")
            optBool(p, c, "pushNotifications", "$.capabilities")
            optBool(p, c, "extendedAgentCard", "$.capabilities")
            objArray(p, c, "extensions", "$.capabilities", false, false) { e, at ->
                optStr(p, e, "uri", at)
                optStr(p, e, "description", at)
                optBool(p, e, "required", at)
                if (has(e, "params") && !isObj(get(e, "params"))) p.add("$at.params: must be an object")
            }
        }
        if (has(card, "securitySchemes") && !isObj(get(card, "securitySchemes"))) p.add("\$.securitySchemes: must be an object")
        if (has(card, "securityRequirements") && get(card, "securityRequirements") !is List<*>) p.add("\$.securityRequirements: must be an array")
        if (!has(card, "defaultInputModes")) p.add("\$.defaultInputModes: required array of strings")
        else strArray(p, get(card, "defaultInputModes"), "$.defaultInputModes", true)
        if (!has(card, "defaultOutputModes")) p.add("\$.defaultOutputModes: required array of strings")
        else strArray(p, get(card, "defaultOutputModes"), "$.defaultOutputModes", true)
        objArray(p, card, "skills", "$", true, false) { e, at ->
            reqStr(p, e, "id", at)
            reqStr(p, e, "name", at)
            reqStr(p, e, "description", at)
            if (!has(e, "tags")) p.add("$at.tags: required array of strings")
            else strArray(p, get(e, "tags"), "$at.tags", false)
            for (k in listOf("examples", "inputModes", "outputModes")) if (has(e, k)) strArray(p, get(e, k), "$at.$k", false)
            if (has(e, "securityRequirements") && get(e, "securityRequirements") !is List<*>) p.add("$at.securityRequirements: must be an array")
        }
        objArray(p, card, "signatures", "$", false, false) { e, at ->
            reqStr(p, e, "protected", at)
            reqStr(p, e, "signature", at)
            if (has(e, "header") && !isObj(get(e, "header"))) p.add("$at.header: must be an object")
        }
        return p
    }
}
