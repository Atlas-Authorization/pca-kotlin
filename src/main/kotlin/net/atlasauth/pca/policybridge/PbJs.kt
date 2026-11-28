package net.atlasauth.pca.policybridge

import net.atlasauth.pca.verifier.IntentJs

/**
 * JavaScript string semantics the policy translators depend on: the exact whitespace set of `\s` / `trim()`, ASCII word boundaries,
 * `slice`, `JSON.stringify` of strings, the top-level splitters, and the key order of `Object.entries`. Regex fragments are built so a
 * Java pattern matches what the JavaScript pattern matches.
 */
internal object PbJs {
    /** The characters of JavaScript `\s` (WhiteSpace and LineTerminator), as regex class content. */
    const val WS = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
    const val S = "[$WS]"
    const val NS = "[^$WS]"

    /** JavaScript `.` (no dotAll): everything but the four line terminators. */
    const val DOT = "[^\\n\\r\\u2028\\u2029]"

    /** JavaScript `\b` next to a `\w` character (`\w` is ASCII only). */
    const val WB_L = "(?<![A-Za-z0-9_])"
    const val WB_R = "(?![A-Za-z0-9_])"

    private val WS_RUN = java.util.regex.Pattern.compile("$S+")

    fun isWs(c: Char): Boolean = when (c) {
        '\t', '\n', '\u000B', '\u000C', '\r', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '　', '﻿' -> true
        else -> c in ' '..' '
    }

    /** `String.prototype.trim`. */
    fun trim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && isWs(s[a])) a++
        while (b > a && isWs(s[b - 1])) b--
        return s.substring(a, b)
    }

    /** `String.prototype.slice(from, to)`. */
    fun slice(s: String, from: Int, to: Int = s.length): String {
        val n = s.length
        val a = if (from < 0) Math.max(n + from, 0) else Math.min(from, n)
        val b = if (to < 0) Math.max(n + to, 0) else Math.min(to, n)
        return if (a >= b) "" else s.substring(a, b)
    }

    fun isAsciiLetter(c: Char): Boolean = (c in 'a'..'z') || (c in 'A'..'Z')
    fun isIdentStart(c: Char): Boolean = isAsciiLetter(c) || c == '_'
    fun isIdentPart(c: Char): Boolean = isIdentStart(c) || (c in '0'..'9')
    fun isDigit(c: Char): Boolean = c in '0'..'9'

    /** `truncate`: whitespace collapsed to one space, at most 80 UTF-16 units. */
    fun truncate(s: String): String {
        val one = trim(WS_RUN.matcher(s).replaceAll(" "))
        return if (one.length > 80) slice(one, 0, 77) + "..." else one
    }

    private fun hex4(c: Char): String = "\\u" + Integer.toHexString(c.code or 0x10000).substring(1)

    /** `JSON.stringify` of a string (well-formed: a lone surrogate is escaped). */
    fun jsonStr(s: String): String {
        val sb = StringBuilder(s.length + 2).append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\b' -> sb.append("\\b")
                c == '\u000C' -> sb.append("\\f")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' -> sb.append(hex4(c))
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> { sb.append(c).append(s[i + 1]); i++ }
                Character.isSurrogate(c) -> sb.append(hex4(c))
                else -> sb.append(c)
            }
            i++
        }
        return sb.append('"').toString()
    }

    /** `JSON.stringify` of a verb: a string or a list of strings. */
    fun jsonVerb(verb: Any?): String {
        if (verb is String) return jsonStr(verb)
        val sb = StringBuilder("[")
        var first = true
        for (o in verb as List<*>) {
            if (!first) sb.append(',')
            first = false
            sb.append(jsonStr(o as String))
        }
        return sb.append(']').toString()
    }

    /** A JavaScript number from its decimal text, as the JSON number the reference serializes. */
    fun number(text: String): Any? = IntentJs.normalize(java.lang.Double.valueOf(java.lang.Double.parseDouble(text)))

    private fun isIndexKey(k: String): Boolean {
        if (k.isEmpty() || k.length > 10) return false
        if (k.length > 1 && k[0] == '0') return false
        for (c in k) if (!isDigit(c)) return false
        return k.toLong() < 4294967295L
    }

    /** The own keys of an object in `Object.entries` order: array indices ascending, then insertion order. */
    fun entryKeys(m: Map<String, Any?>): List<String> {
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in m.keys) if (isIndexKey(k)) idx.add(k) else rest.add(k)
        idx.sortBy { it.toLong() }
        idx.addAll(rest)
        return idx
    }

    /** `Object.entries` of an object or array value (an array's keys are its indices); null for anything else. */
    @Suppress("UNCHECKED_CAST")
    fun entries(o: Any?): Map<String, Any?>? {
        val out = LinkedHashMap<String, Any?>()
        if (o is Map<*, *>) {
            val m = o as Map<String, Any?>
            for (k in entryKeys(m)) out[k] = m[k]
            return out
        }
        if (o is List<*>) {
            for (i in o.indices) out[i.toString()] = o[i]
            return out
        }
        return null
    }

    // ---- bracket and quote aware scanning (the structure is shared by the Cedar and Rego readers) ----

    /** Index of [token] at bracket/quote depth 0, or -1. */
    fun indexOfTopLevel(text: String, token: String): Int {
        var depth = 0
        var inStr = false
        for (i in text.indices) {
            val ch = text[i]
            if (inStr) { if (ch == '"') inStr = false; continue }
            if (ch == '"') { inStr = true; continue }
            if (ch == '(' || ch == '[' || ch == '{') depth++
            else if (ch == ')' || ch == ']' || ch == '}') depth--
            else if (depth == 0 && text.startsWith(token, i)) return i
        }
        return -1
    }

    /** Split on a delimiter (one or two characters) at bracket/quote depth 0. */
    fun splitTopLevel(text: String, delim: String): List<String> {
        val out = ArrayList<String>()
        var depth = 0
        var inStr = false
        var start = 0
        var i = 0
        while (i < text.length) {
            val ch = text[i]
            if (inStr) { if (ch == '"') inStr = false; i++; continue }
            if (ch == '"') { inStr = true; i++; continue }
            if (ch == '(' || ch == '[' || ch == '{') depth++
            else if (ch == ')' || ch == ']' || ch == '}') depth--
            if (depth == 0 && text.startsWith(delim, i)) {
                out.add(text.substring(start, i))
                i += delim.length - 1
                start = i + 1
            }
            i++
        }
        out.add(text.substring(Math.min(start, text.length)))
        return out
    }

    fun matchDelim(text: String, open: Int, o: Char, c: Char): Int {
        var depth = 0
        var inStr = false
        for (i in open until text.length) {
            val ch = text[i]
            if (inStr) { if (ch == '"') inStr = false; continue }
            if (ch == '"') inStr = true
            else if (ch == o) depth++
            else if (ch == c) { depth--; if (depth == 0) return i }
        }
        return -1
    }

    fun trimmedNonEmpty(parts: List<String>): List<String> {
        val out = ArrayList<String>()
        for (p in parts) { val t = trim(p); if (t.isNotEmpty()) out.add(t) }
        return out
    }

    /** A growable JSON object in insertion order: `obj("field", f, "op", o, ...)`. */
    fun obj(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }
}
