package net.atlasauth.pca.actions

import java.util.Collections
import java.util.IdentityHashMap
import java.util.regex.Pattern
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json

/**
 * A YAML 1.2 emitter for parsed JSON trees (Map, List, String, Boolean, number, null) that writes byte for byte what the `yaml` package's
 * default `stringify` writes: block collections with two-space indentation (sequences indented under their key), plain scalars unless they
 * would read back as another type (then quoted), literal or folded block scalars for multi-line text, double quotes with YAML escapes, and
 * lines folded at 80 columns. A direct port of that library's string, number, pair and collection stringifiers for the node kinds a JSON tree has.
 *
 * A Map or List that appears more than once in a tree (the same instance) is written once with an anchor (`&a1`, numbered in the
 * order the repeats are met) and then as an alias (`*a1`), as the reference does; a cycle becomes an alias too. Equal but distinct objects
 * are written in full. A non-finite number or a number that is not a JSON value is refused.
 */
internal object YamlEmit {
    private const val LINE_WIDTH = 80
    private const val MIN_CONTENT_WIDTH = 20
    private const val DQ_MIN_MULTILINE = 40
    private const val FLOW = "flow"
    private const val BLOCK = "block"
    private const val QUOTED = "quoted"

    /** The document text of `value`: the block-style YAML followed by a newline. */
    fun stringify(value: Any?): String = stringifyNode(value, Ctx(Anchors(value))) + "\n"

    /** The anchor names of the collections met more than once (numbered at the second sighting, as the reference does) and which are already written. */
    private class Anchors(root: Any?) {
        val names: MutableMap<Any?, String> = IdentityHashMap()
        val written: MutableSet<Any?> = Collections.newSetFromMap(IdentityHashMap<Any?, Boolean>())
        private val seen: MutableSet<Any?> = Collections.newSetFromMap(IdentityHashMap<Any?, Boolean>())
        private var count = 0

        init { walk(root) }

        private fun walk(v: Any?) {
            if (v !is Map<*, *> && v !is List<*>) return
            if (!seen.add(v)) {
                if (!names.containsKey(v)) names[v] = "a" + (++count)
                return
            }
            if (v is Map<*, *>) { for (k in jsKeys(v)) walk(v[k]) } else for (x in v as List<*>) walk(x)
        }

        /** True when `v` is a repeat of a collection whose anchor is already written (it is emitted as an alias). */
        fun isAlias(v: Any?): Boolean = written.contains(v)
    }

    private class Ctx(var anchors: Anchors) {
        var indent = ""
        var indentStep = "  "
        var indentAtStart: Int? = null
        var implicitKey = false
        var actualString = false
        var forceBlockIndent = false

        fun copy(): Ctx {
            val c = Ctx(anchors)
            c.indent = indent; c.indentStep = indentStep; c.indentAtStart = indentAtStart
            c.implicitKey = implicitKey; c.actualString = actualString; c.forceBlockIndent = forceBlockIndent
            return c
        }
    }

    // ---- nodes ---------------------------------------------------------------------------------------------------------------

    private fun stringifyNode(v: Any?, ctx: Ctx): String {
        if (v is Map<*, *> || v is List<*>) {
            val anchor = ctx.anchors.names[v]
            if (anchor != null && !ctx.anchors.written.add(v)) return "*$anchor"
            val props = if (anchor == null) null else "&$anchor"
            if (props != null) ctx.indentAtStart = (ctx.indentAtStart ?: 0) + props.length + 1
            val str = if (v is Map<*, *>) stringifyMap(v, ctx) else stringifySeq(v as List<*>, ctx)
            if (props == null) return str
            return if (str[0] == '{' || str[0] == '[') "$props $str" else props + "\n" + ctx.indent + str
        }
        if (v is String) { val c = ctx.copy(); c.actualString = true; return stringifyString(v, c) }
        if (v == null) return "null"
        if (v is Boolean) return v.toString()
        return stringifyNumber(v)
    }

    private fun stringifyNumber(v: Any?): String {
        val d: Double? = if (v is Json.Num) v.raw.toDoubleOrNull() else if (v is Number) v.toDouble() else null
        if (d == null || d.isNaN() || d.isInfinite()) throw IllegalArgumentException("YAML: not a JSON number: $v")
        if (d == 0.0 && 1.0 / d < 0) return "-0"
        return AttestUtil.jsNumString(d)
    }

    private val INDEX_KEY = Regex("0|[1-9][0-9]{0,9}")

    private fun jsKeys(m: Map<*, *>): List<String> {
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (o in m.keys) {
            val k = o as String
            if (INDEX_KEY.matches(k) && k.toLong() < 4294967295L) idx.add(k) else rest.add(k)
        }
        idx.sortWith { a, b -> a.toLong().compareTo(b.toLong()) }
        idx.addAll(rest)
        return idx
    }

    private fun stringifyMap(m: Map<*, *>, ctx: Ctx): String {
        val keys = jsKeys(m)
        val itemCtx = ctx.copy()
        itemCtx.indent = ctx.indent
        val lines = ArrayList<String>()
        for (k in keys) lines.add(stringifyPair(k, m[k], itemCtx))
        return join(lines, ctx.indent, "{}")
    }

    private fun stringifySeq(l: List<*>, ctx: Ctx): String {
        val itemCtx = ctx.copy()
        itemCtx.indent = ctx.indent + "  "
        val lines = ArrayList<String>()
        for (x in l) lines.add("- " + stringifyNode(x, itemCtx))
        return join(lines, ctx.indent, "[]")
    }

    private fun join(lines: List<String>, indent: String, empty: String): String {
        if (lines.isEmpty()) return empty
        val b = StringBuilder(lines[0])
        for (i in 1 until lines.size) {
            val line = lines[i]
            if (line.isNotEmpty()) b.append('\n').append(indent).append(line) else b.append('\n')
        }
        return b.toString()
    }

    private fun stringifyPair(key: String, value: Any?, ctx0: Ctx): String {
        val indent = ctx0.indent
        val ctx = ctx0.copy()
        ctx.indent = indent + ctx0.indentStep
        ctx.implicitKey = true
        var str = stringifyNode(key, ctx)
        val explicitKey = str.length > 1024
        str = if (explicitKey) "? $str\n$indent:" else "$str:"
        ctx.implicitKey = false
        val alias = ctx.anchors.isAlias(value)
        val collection = !alias && (value is Map<*, *> || value is List<*>)
        if (!explicitKey && !collection && !alias) ctx.indentAtStart = str.length + 1
        val valueStr = stringifyNode(value, ctx)
        var ws = " "
        if (!explicitKey && collection) {
            val hasNewline = valueStr.indexOf('\n') != -1
            val empty = if (value is Map<*, *>) value.isEmpty() else (value as List<*>).isEmpty()
            if (hasNewline || !empty) {
                val sp0 = valueStr.indexOf(' ')
                val propsLine = hasNewline && valueStr[0] == '&' && (sp0 == -1 || valueStr.indexOf('\n') < sp0) // "&a1" alone on its line
                if (!propsLine) ws = "\n" + ctx.indent
            }
        } else if (valueStr.isEmpty() || valueStr[0] == '\n') ws = ""
        return str + ws + valueStr
    }

    // ---- strings -------------------------------------------------------------------------------------------------------------

    private val DOC_MARKER = Pattern.compile("(?:^|[\\n\\r\\u2028\\u2029])(?:%|---|\\.\\.\\.)")
    private val PLAIN_FORBIDDEN = Pattern.compile("^[\\n\\t ,\\[\\]{}#&*!|>'\"%@`]|^[?-]\\z|^[?-][ \\t]|[\\n:][ \\t]|[ \\t]\\n|[\\n\\t ]#|[\\n\\t :]\\z")

    // the core schema's default tags that would read a plain scalar back as a non-string
    private val NON_STRING = arrayOf(
        Pattern.compile("^(?:~|[Nn]ull|NULL)?\\z"), Pattern.compile("^(?:[Tt]rue|TRUE|[Ff]alse|FALSE)\\z"), Pattern.compile("^0o[0-7]+\\z"), Pattern.compile("^[-+]?[0-9]+\\z"),
        Pattern.compile("^0x[0-9a-fA-F]+\\z"), Pattern.compile("^(?:[-+]?\\.(?:inf|Inf|INF)|\\.nan|\\.NaN|\\.NAN)\\z"), Pattern.compile("^[-+]?(?:\\.[0-9]+|[0-9]+(?:\\.[0-9]*)?)[eE][-+]?[0-9]+\\z"),
        Pattern.compile("^[-+]?(?:\\.[0-9]+|[0-9]+\\.[0-9]*)\\z"),
    )
    private val WS_AROUND_NL = Pattern.compile("[ \\t]\\n|\\n[ \\t]")
    private val NL_RUN = Pattern.compile("\\n+")

    private fun containsDocumentMarker(s: String): Boolean = DOC_MARKER.matcher(s).find()

    /** `s.replace(/\n+/g, '$&' + suffix)`: every newline run followed by `suffix`. */
    private fun afterNewlines(s: String, suffix: String): String {
        val m = NL_RUN.matcher(s)
        val b = StringBuilder()
        var last = 0
        while (m.find()) { b.append(s, last, m.end()).append(suffix); last = m.end() }
        return b.append(s, last, s.length).toString()
    }

    private fun forcesDoubleQuotes(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            val x = c.code
            if (x <= 0x08 || (x >= 0x0b && x <= 0x1f) || (x >= 0x7f && x <= 0x9f)) return true
            if (Character.isHighSurrogate(c)) { if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) i++ else return true }
            else if (Character.isLowSurrogate(c)) return true
            i++
        }
        return false
    }

    private fun stringifyString(value: String, ctx: Ctx): String =
        if (forcesDoubleQuotes(value)) doubleQuotedString(value, ctx) else plainString(value, ctx)

    private fun plainString(value: String, ctx: Ctx): String {
        val hasNl = value.indexOf('\n') >= 0
        if (ctx.implicitKey && hasNl) return quotedString(value, ctx)
        if (PLAIN_FORBIDDEN.matcher(value).find()) return if (ctx.implicitKey || !hasNl) quotedString(value, ctx) else blockString(value, ctx)
        if (!ctx.implicitKey && hasNl) return blockString(value, ctx) // the string has no explicit type: block style is preferred where allowed
        if (containsDocumentMarker(value)) {
            if (ctx.indent.isEmpty()) { ctx.forceBlockIndent = true; return blockString(value, ctx) }
            else if (ctx.implicitKey && ctx.indent == ctx.indentStep) return quotedString(value, ctx)
        }
        val str = afterNewlines(value, "\n" + ctx.indent)
        if (ctx.actualString) for (p in NON_STRING) if (p.matcher(str).find()) return quotedString(value, ctx)
        return if (ctx.implicitKey) str else foldFlowLines(str, ctx.indent, FLOW, ctx.indentAtStart, null)
    }

    private fun quotedString(value: String, ctx: Ctx): String {
        val hasDouble = value.indexOf('"') >= 0
        val hasSingle = value.indexOf('\'') >= 0
        return if (hasDouble && !hasSingle) singleQuotedString(value, ctx) else doubleQuotedString(value, ctx)
    }

    private fun singleQuotedString(value: String, ctx: Ctx): String {
        if ((ctx.implicitKey && value.indexOf('\n') >= 0) || WS_AROUND_NL.matcher(value).find()) return doubleQuotedString(value, ctx)
        val indent = if (ctx.indent.isNotEmpty()) ctx.indent else if (containsDocumentMarker(value)) "  " else ""
        val res = "'" + afterNewlines(value.replace("'", "''"), "\n" + indent) + "'"
        return if (ctx.implicitKey) res else foldFlowLines(res, indent, FLOW, ctx.indentAtStart, null)
    }

    private fun at(s: String, i: Int): Char = if (i >= 0 && i < s.length) s[i] else '\u0000'

    private fun doubleQuotedString(value: String, ctx: Ctx): String {
        val json = J.stringify(value)
        val indent = if (ctx.indent.isNotEmpty()) ctx.indent else if (containsDocumentMarker(value)) "  " else ""
        val str = StringBuilder()
        var start = 0
        var i = 0
        while (i < json.length) {
            var ch = json[i]
            if (ch == ' ' && at(json, i + 1) == '\\' && at(json, i + 2) == 'n') {
                // a space before a newline is escaped so it is not folded
                str.append(json, start, i).append("\\ ")
                i += 1
                start = i
                ch = '\\'
            }
            if (ch == '\\') {
                when (at(json, i + 1)) {
                    'u' -> {
                        str.append(json, start, i)
                        val code = json.substring(Math.min(i + 2, json.length), Math.min(i + 6, json.length))
                        when (code) {
                            "0000" -> str.append("\\0")
                            "0007" -> str.append("\\a")
                            "000b" -> str.append("\\v")
                            "001b" -> str.append("\\e")
                            "0085" -> str.append("\\N")
                            "00a0" -> str.append("\\_")
                            "2028" -> str.append("\\L")
                            "2029" -> str.append("\\P")
                            else -> if (code.startsWith("00")) str.append("\\x").append(code.substring(2)) else str.append(json, i, Math.min(i + 6, json.length))
                        }
                        i += 5
                        start = i + 1
                    }
                    'n' -> {
                        if (ctx.implicitKey || at(json, i + 2) == '"' || json.length < DQ_MIN_MULTILINE) {
                            i += 1
                        } else {
                            // folding eats the first newline
                            str.append(json, start, i).append("\n\n")
                            while (at(json, i + 2) == '\\' && at(json, i + 3) == 'n' && at(json, i + 4) != '"') { str.append('\n'); i += 2 }
                            str.append(indent)
                            // a space after a newline is escaped so it is not folded
                            if (at(json, i + 2) == ' ') str.append('\\')
                            i += 1
                            start = i + 1
                        }
                    }
                    else -> i += 1
                }
            }
            i++
        }
        val res = if (start != 0) str.append(json, Math.min(start, json.length), json.length).toString() else json
        return if (ctx.implicitKey) res else foldFlowLines(res, indent, QUOTED, ctx.indentAtStart, null)
    }

    private fun lineLengthOverLimit(str: String, lineWidth: Int, indentLength: Int): Boolean {
        val limit = lineWidth - indentLength
        val strLen = str.length
        if (strLen <= limit) return false
        var i = 0
        var start = 0
        while (i < strLen) {
            if (str[i] == '\n') {
                if (i - start > limit) return true
                start = i + 1
                if (strLen - start <= limit) return false
            }
            ++i
        }
        return true
    }

    private val BLOCK_END_NL = Pattern.compile("(^|(?<!\\n))\\n+(?!\\n|\\z)")
    private val TRAILING_WS_LINE = Pattern.compile("\\n[\\t ]+\\z")
    private val MORE_INDENTED = Pattern.compile("(?:^|\\n)([\\t ].*)(?:([\\n\\t ]*)\\n(?![\\n\\t ]))?")

    private fun blockString(value0: String, ctx: Ctx): String {
        var value = value0
        // a block cannot end in whitespace unless its last line is non-empty
        if (TRAILING_WS_LINE.matcher(value).find()) return quotedString(value, ctx)
        val indent = if (ctx.indent.isNotEmpty()) ctx.indent else if (ctx.forceBlockIndent || containsDocumentMarker(value)) "  " else ""
        val literal = !lineLengthOverLimit(value, LINE_WIDTH, indent.length)
        if (value.isEmpty()) return if (literal) "|\n" else ">\n"
        // chomping from the whitespace at the value's end
        val chomp: String
        var endStart = value.length
        while (endStart > 0) {
            val ch = value[endStart - 1]
            if (ch != '\n' && ch != '\t' && ch != ' ') break
            --endStart
        }
        var end = value.substring(endStart)
        val endNlPos = end.indexOf('\n')
        chomp = if (endNlPos == -1) "-" else if (value == end || endNlPos != end.length - 1) "+" else ""
        if (end.isNotEmpty()) {
            value = value.substring(0, value.length - end.length)
            if (end[end.length - 1] == '\n') end = end.substring(0, end.length - 1)
            end = replaceBlockEnd(end, indent)
        }
        // indent indicator from the whitespace at the value's start
        var startWithSpace = false
        var startEnd = 0
        var startNlPos = -1
        while (startEnd < value.length) {
            val ch = value[startEnd]
            if (ch == ' ') startWithSpace = true
            else if (ch == '\n') startNlPos = startEnd
            else break
            ++startEnd
        }
        var start = value.substring(0, if (startNlPos < startEnd) startNlPos + 1 else startEnd)
        if (start.isNotEmpty()) {
            value = value.substring(start.length)
            start = afterNewlines(start, indent)
        }
        val indentSize = if (indent.isNotEmpty()) "2" else "1" // the root is at -1
        val header = (if (startWithSpace) indentSize else "") + chomp
        if (!literal) {
            val foldedValue = afterNewlines(moreIndentedUnfolded(afterNewlinesPrefix(value)), indent)
            val overflow = booleanArrayOf(false)
            val body = foldFlowLines(start + foldedValue + end, indent, BLOCK, ctx.indent.length, overflow)
            if (!overflow[0]) return ">$header\n$indent$body"
        }
        value = afterNewlines(value, indent)
        return "|$header\n$indent$start$value$end"
    }

    /** `end.replace(blockEndNewlines, '$&' + indent)`. */
    private fun replaceBlockEnd(end: String, indent: String): String {
        val m = BLOCK_END_NL.matcher(end)
        val b = StringBuilder()
        var last = 0
        while (m.find()) { b.append(end, last, m.end()).append(indent); last = m.end() }
        return b.append(end, last, end.length).toString()
    }

    /** `value.replace(/\n+/g, '\n$&')`. */
    private fun afterNewlinesPrefix(s: String): String {
        val m = NL_RUN.matcher(s)
        val b = StringBuilder()
        var last = 0
        while (m.find()) { b.append(s, last, m.start()).append('\n').append(m.group()); last = m.end() }
        return b.append(s, last, s.length).toString()
    }

    /** `s.replace(/(?:^|\n)([\t ].*)(?:([\n\t ]*)\n(?![\n\t ]))?/g, '$1$2')`: more-indented lines are not folded. */
    private fun moreIndentedUnfolded(s: String): String {
        val m = MORE_INDENTED.matcher(s)
        val b = StringBuilder()
        var last = 0
        while (m.find()) {
            b.append(s, last, m.start()).append(m.group(1))
            if (m.group(2) != null) b.append(m.group(2))
            last = m.end()
        }
        return b.append(s, last, s.length).toString()
    }

    // ---- folding -------------------------------------------------------------------------------------------------------------

    private fun consumeMoreIndentedLines(text: String, i0: Int, indent: Int): Int {
        var i = i0
        var end = i
        var start = i + 1
        var ch = at(text, start)
        while (ch == ' ' || ch == '\t') {
            if (i < start + indent) {
                ch = at(text, ++i)
            } else {
                do { ch = at(text, ++i) } while (ch != '\u0000' && ch != '\n')
                end = i
                start = i + 1
                ch = at(text, start)
            }
        }
        return end
    }

    /**
     * Keeps text at up to the line width by splitting on spaces not followed by newlines or spaces (anywhere in quoted mode); lines end with a
     * newline and start with `indent`. `indentAtStart` is where the first line already starts (null = the indent).
     */
    private fun foldFlowLines(text: String, indent: String, mode: String, indentAtStart: Int?, overflowOut: BooleanArray?): String {
        val lineWidth = LINE_WIDTH
        var minContentWidth = MIN_CONTENT_WIDTH
        if (lineWidth < minContentWidth) minContentWidth = 0
        val endStep = Math.max(1 + minContentWidth, 1 + lineWidth - indent.length)
        if (text.length <= endStep) return text
        val folds = ArrayList<Int>()
        val escapedFolds = HashSet<Int>()
        var end = lineWidth - indent.length
        if (indentAtStart != null) {
            if (indentAtStart > lineWidth - Math.max(2, minContentWidth)) folds.add(0)
            else end = lineWidth - indentAtStart
        }
        var split: Int? = null
        var prev = '\u0000'
        var overflow = false
        var i = -1
        var escStart = -1
        var escEnd = -1
        if (mode == BLOCK) {
            i = consumeMoreIndentedLines(text, i, indent.length)
            if (i != -1) end = i + endStep
        }
        while (true) {
            i += 1
            var ch = at(text, i)
            if (ch == '\u0000') break
            if (mode == QUOTED && ch == '\\') {
                escStart = i
                when (at(text, i + 1)) {
                    'x' -> i += 3
                    'u' -> i += 5
                    'U' -> i += 9
                    else -> i += 1
                }
                escEnd = i
            }
            if (ch == '\n') {
                if (mode == BLOCK) i = consumeMoreIndentedLines(text, i, indent.length)
                end = i + indent.length + endStep
                split = null
            } else {
                if (ch == ' ' && prev != '\u0000' && prev != ' ' && prev != '\n' && prev != '\t') {
                    // a space surrounded by non-space can become a newline plus indent
                    val next = at(text, i + 1)
                    if (next != '\u0000' && next != ' ' && next != '\n' && next != '\t') split = i
                }
                if (i >= end) {
                    if (split != null) {
                        folds.add(split)
                        end = split + endStep
                        split = null
                    } else if (mode == QUOTED) {
                        // white space collected at the end may stretch past the line width
                        while (prev == ' ' || prev == '\t') {
                            prev = ch
                            i += 1
                            ch = at(text, i)
                            overflow = true
                        }
                        // account for the newline escape, but do not break a preceding escape
                        val j = if (i > escEnd + 1) i - 2 else escStart - 1
                        if (escapedFolds.contains(j)) return text
                        folds.add(j)
                        escapedFolds.add(j)
                        end = j + endStep
                        split = null
                    } else {
                        overflow = true
                    }
                }
            }
            prev = ch
        }
        if (overflowOut != null && overflow) overflowOut[0] = true
        if (folds.isEmpty()) return text
        var res = StringBuilder(text.substring(0, Math.min(folds[0], text.length)))
        for (k in folds.indices) {
            val fold = folds[k]
            val e = if (k + 1 < folds.size && folds[k + 1] != 0) folds[k + 1] else text.length
            if (fold == 0) {
                res = StringBuilder("\n" + indent + text.substring(0, Math.min(e, text.length)))
            } else {
                if (mode == QUOTED && escapedFolds.contains(fold)) res.append(text[fold]).append('\\')
                res.append('\n').append(indent).append(text, Math.min(fold + 1, text.length), Math.min(Math.max(e, fold + 1), text.length))
            }
        }
        return res.toString()
    }
}
