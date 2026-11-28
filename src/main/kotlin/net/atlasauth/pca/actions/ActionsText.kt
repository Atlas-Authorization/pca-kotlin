package net.atlasauth.pca.actions

import java.io.StringReader
import java.math.BigInteger
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json
import org.snakeyaml.engine.v2.api.LoadSettings
import org.snakeyaml.engine.v2.api.lowlevel.Parse
import org.snakeyaml.engine.v2.common.ScalarStyle
import org.snakeyaml.engine.v2.events.AliasEvent
import org.snakeyaml.engine.v2.events.DocumentStartEvent
import org.snakeyaml.engine.v2.events.Event
import org.snakeyaml.engine.v2.events.MappingEndEvent
import org.snakeyaml.engine.v2.events.MappingStartEvent
import org.snakeyaml.engine.v2.events.ScalarEvent
import org.snakeyaml.engine.v2.events.SequenceEndEvent
import org.snakeyaml.engine.v2.events.SequenceStartEvent
import org.snakeyaml.engine.v2.exceptions.MarkedYamlEngineException

/** A syntax or policy refusal of the YAML front end (message plus 1-based position). */
class YamlLoadError(message: String, val line: Int = 1, val column: Int = 1) : RuntimeException(message)

/**
 * The authoring-file text loader: YAML 1.2 core schema or JSON text, with source positions. The syntax layer is SnakeYAML-engine's parser; only
 * its EVENT stream is used. Everything the reference decides about meaning is done here, so the result does not depend on the library's own resolver
 * or alias handling: the tree is built from events, plain scalars are resolved with the YAML 1.2 core schema (null, bool, int, 0o / 0x, float, .inf,
 * .nan; everything else a string), mapping keys are stringified the way JavaScript does, aliases are refused, "<<" is an ordinary key, and positions
 * are the 1-based start of each action and each param key.
 *
 * Where this differs from the reference it is STRICTER (it refuses): an explicit tag other than !!str / !!map / !!seq, a complex (non-scalar)
 * mapping key, two keys that are equal once stringified, a bare carriage return used as a line break, more than one document. Syntax error wording
 * and the line/column of a syntax error are the parser's own.
 */
@Suppress("UNCHECKED_CAST")
object ActionsText {
    private const val STR_TAG = "tag:yaml.org,2002:str"
    private const val MAP_TAG = "tag:yaml.org,2002:map"
    private const val SEQ_TAG = "tag:yaml.org,2002:seq"
    private val SAFE: BigInteger = BigInteger.ONE.shiftLeft(53)

    private val INT_RE = Regex("[-+]?[0-9]+")
    private val OCT_RE = Regex("0o[0-7]+")
    private val HEX_RE = Regex("0x[0-9a-fA-F]+")
    private val FLOAT_RE = Regex("[-+]?(?:\\.[0-9]+|[0-9]+(?:\\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?")
    private val INF_RE = Regex("[-+]?\\.(?:inf|Inf|INF)")
    private val NAN_RE = Regex("\\.(?:nan|NaN|NAN)")
    private val BARE_CR = Regex("\r(?!\n)")

    private class N(val kind: String, val line: Int, val col: Int) { // kind: scalar | map | seq
        var value: Any? = null
        val seq = ArrayList<N>()
        val map = ArrayList<Pair<N, N>>()
    }

    private class Pos(val line: Int, val col: Int, val params: MutableMap<String, Any?>)

    private fun jsNumber(d: Double): Any? =
        if (d.isNaN() || d.isInfinite()) d else if (d == 0.0) Json.Num("0") else Json.Num(AttestUtil.jsNumString(d))

    private fun jsInt(text: String, radix: Int): Any? {
        val neg = text.startsWith("-")
        val digits = text.trimStart('+', '-')
        var n = BigInteger(digits, radix)
        if (neg && n.signum() == 0) return jsNumber(-0.0)
        if (neg) n = n.negate()
        return if (n.abs() <= SAFE) Json.Num(n.toString()) else jsNumber(n.toDouble())
    }

    /** The YAML 1.2 core schema value of a plain scalar, as a JSON tree value (number, bool, null or string). */
    fun resolveCorePlain(text: String): Any? {
        if (text == "" || text == "~" || text == "null" || text == "Null" || text == "NULL") return null
        if (text == "true" || text == "True" || text == "TRUE") return true
        if (text == "false" || text == "False" || text == "FALSE") return false
        if (INT_RE.matches(text)) return jsInt(text, 10)
        if (OCT_RE.matches(text)) return jsInt(text.substring(2), 8)
        if (HEX_RE.matches(text)) return jsInt(text.substring(2), 16)
        if (INF_RE.matches(text)) return if (text[0] == '-') Double.NEGATIVE_INFINITY else Double.POSITIVE_INFINITY
        if (NAN_RE.matches(text)) return Double.NaN
        if (FLOAT_RE.matches(text)) {
            val f = text.toDouble()
            val negZero = f == 0.0 && text.trimStart('+').startsWith("-")
            return if (f == Math.floor(f) && Math.abs(f) <= 9007199254740992.0 && !negZero) Json.Num(f.toLong().toString()) else jsNumber(f)
        }
        return text
    }

    private fun jsKey(v: Any?): String = when (v) {
        null -> "null"
        is Boolean -> if (v) "true" else "false"
        is Json.Num -> v.raw
        is Double -> if (v.isNaN()) "NaN" else if (v > 0) "Infinity" else "-Infinity"
        else -> v as String
    }

    private fun tagOf(t: java.util.Optional<String>): String? = if (t.isPresent && t.get().isNotEmpty()) t.get() else null

    private fun lineOf(e: Event): Int = if (e.startMark.isPresent) e.startMark.get().line + 1 else 1
    private fun colOf(e: Event): Int = if (e.startMark.isPresent) e.startMark.get().column + 1 else 1

    /**
     * YAML 1.2 double-quoted scalars take `\L` (U+2028) and `\P` (U+2029); the parser library lacks both. When it refuses exactly such an
     * escape, the pair is rewritten to its `\u` spelling (the same character) and the text is parsed again; any other refusal stays one.
     */
    private fun spellLineSeparatorEscape(src: String, e: MarkedYamlEngineException): String? {
        // the parser words it "found unknown escape character L(76)": the character, then its code
        val bad = Regex("^found unknown escape character (.)\\(\\d+\\)$").find(e.problem ?: "")?.groupValues?.get(1)
        if (bad != "L" && bad != "P") return null
        val m = if (e.problemMark.isPresent) e.problemMark.get() else return null
        val at = try { src.offsetByCodePoints(0, m.index) } catch (x: IndexOutOfBoundsException) { return null }
        for (i in intArrayOf(at, at - 1)) {
            if (i >= 1 && i < src.length && src[i - 1] == '\\' && src[i].toString() == bad && oddBackslashesBefore(src, i)) {
                return src.substring(0, i - 1) + (if (src[i] == 'L') "\\u2028" else "\\u2029") + src.substring(i + 1)
            }
        }
        return null
    }

    /** True when the backslash just before [i] begins an escape, i.e. it is not the second half of an escaped backslash (an odd run ends at i - 1). */
    private fun oddBackslashesBefore(src: String, i: Int): Boolean {
        var k = i - 1
        var run = 0
        while (k >= 0 && src[k] == '\\') { run++; k-- }
        return run % 2 == 1
    }

    private fun parseDocument(text: String, strict: Boolean): N? {
        if (BARE_CR.containsMatchIn(text)) throw YamlLoadError("bare carriage return is not accepted as a line break")
        val events = ArrayList<Event>()
        var src = text
        var patched = 0
        while (true) {
            events.clear()
            try {
                for (e in Parse(LoadSettings.builder().build()).parseReader(StringReader(src))) events.add(e)
                break
            } catch (e: MarkedYamlEngineException) {
                val fixed = if (patched++ < 10_000) spellLineSeparatorEscape(src, e) else null
                if (fixed != null) { src = fixed; continue }
                val m = if (e.problemMark.isPresent) e.problemMark.get() else null
                throw YamlLoadError(e.message ?: "syntax error", (m?.line ?: 0) + 1, (m?.column ?: 0) + 1)
            } catch (e: RuntimeException) {
                throw YamlLoadError(e.message ?: "syntax error")
            }
        }
        var pos = 0
        var docs = 0

        fun node(): N {
            if (pos >= events.size) throw YamlLoadError("unexpected end of the event stream")
            val ev = events[pos++]
            val line = lineOf(ev)
            val col = colOf(ev)
            if (ev is AliasEvent) throw YamlLoadError("Alias resolution is disabled", line, col)
            val tag = when (ev) {
                is ScalarEvent -> tagOf(ev.tag)
                is SequenceStartEvent -> tagOf(ev.tag)
                is MappingStartEvent -> tagOf(ev.tag)
                else -> null
            }
            if (tag != null && tag != STR_TAG && tag != MAP_TAG && tag != SEQ_TAG) throw YamlLoadError("Unresolved or unsupported tag: $tag", line, col)
            when (ev) {
                is ScalarEvent -> {
                    val n = N("scalar", line, col)
                    n.value = if (ev.scalarStyle == ScalarStyle.PLAIN && tag == null) resolveCorePlain(ev.value) else ev.value
                    return n
                }
                is SequenceStartEvent -> {
                    val n = N("seq", line, col)
                    while (pos < events.size && events[pos] !is SequenceEndEvent) n.seq.add(node())
                    pos++
                    return n
                }
                is MappingStartEvent -> {
                    val n = N("map", line, col)
                    val seen = HashSet<String>()
                    while (pos < events.size && events[pos] !is MappingEndEvent) {
                        val key = node()
                        val v = node()
                        if (strict) {
                            if (key.kind != "scalar") throw YamlLoadError("complex mapping keys are not accepted", key.line, key.col)
                            if (!seen.add(jsKey(key.value))) throw YamlLoadError("Map keys must be unique", key.line, key.col)
                        }
                        n.map.add(Pair(key, v))
                    }
                    pos++
                    return n
                }
                else -> throw YamlLoadError("unexpected parser event " + ev.javaClass.simpleName, line, col)
            }
        }

        var root: N? = null
        while (pos < events.size) {
            if (events[pos] is DocumentStartEvent) {
                if (++docs > 1) throw YamlLoadError("Source contains multiple documents; please use YAML.parseAllDocuments()")
                pos++
                if (pos < events.size && events[pos] !is org.snakeyaml.engine.v2.events.DocumentEndEvent) root = node()
            } else pos++
        }
        return root
    }

    private fun toValue(n: N?): Any? {
        if (n == null) return null
        if (n.kind == "scalar") return n.value
        if (n.kind == "seq") return n.seq.mapTo(ArrayList<Any?>()) { toValue(it) }
        val o = LinkedHashMap<String, Any?>()
        for ((k, v) in n.map) {
            if (k.kind != "scalar") throw YamlLoadError("complex mapping keys are not accepted", k.line, k.col)
            o[jsKey(k.value)] = toValue(v)
        }
        return o
    }

    // per-entry positions of an authoring document (actions items and their params keys), by entry index; null when not a mapping
    private fun positionsOf(root: N?): List<Pos>? {
        if (root == null || root.kind != "map") return null
        var actions: N? = null
        for ((k, v) in root.map) if (k.kind == "scalar" && k.value == "actions") actions = v
        val items: List<N> = if (actions != null && actions.kind == "seq") actions.seq else listOf(root)
        val res = ArrayList<Pos>()
        for (it in items) {
            val ps = LinkedHashMap<String, Any?>()
            if (it.kind == "map") {
                var pm: N? = null
                for ((k, v) in it.map) if (k.kind == "scalar" && k.value == "params") pm = v
                if (pm != null && pm.kind == "map") {
                    for ((k, _) in pm.map) {
                        if (k.kind == "scalar") ps[if (k.value == null) "" else jsKey(k.value)] = J.obj("line", J.n(k.line.toLong()), "column", J.n(k.col.toLong()))
                    }
                }
            }
            res.add(Pos(it.line, it.col, ps))
        }
        return res
    }

    private fun attachPositions(res: MutableMap<String, Any?>, pos: List<Pos>) {
        val errors = J.a(res["errors"])
        val failed = HashSet<Long>()
        for (e in errors) if (e is Map<*, *>) { val ix = e["index"]; if (ix is Json.Num) ix.raw.toLongOrNull()?.let { failed.add(it) } }
        val order = (0 until pos.size).filter { !failed.contains(it.toLong()) }
        val defs = J.a(res["defs"])
        val locs = J.m(res["locs"])
        for (k in 0 until defs.size) {
            if (k < order.size) {
                val p = pos[order[k]]
                locs[J.m(defs[k])["verb"] as String] = J.obj("line", J.n(p.line.toLong()), "column", J.n(p.col.toLong()), "params", p.params)
            }
        }
        for (e in errors) {
            val em = J.m(e)
            val ix = (em["index"] as? Json.Num)?.raw?.toLongOrNull()
            if (ix != null) {
                if (ix >= 0 && ix < pos.size) { em["line"] = J.n(pos[ix.toInt()].line.toLong()); em["column"] = J.n(pos[ix.toInt()].col.toLong()) }
            } else { em["line"] = J.n(1); em["column"] = J.n(1) }
        }
    }

    private fun fail(message: String, line: Int = 1, column: Int = 1): MutableMap<String, Any?> = J.obj(
        "defs", ArrayList<Any?>(), "notes", ArrayList<Any?>(),
        "errors", J.list(J.obj("message", message, "line", J.n(line.toLong()), "column", J.n(column.toLong()))),
        "locs", LinkedHashMap<String, Any?>(), "rules", LinkedHashMap<String, Any?>(),
    )

    /**
     * Load an authoring file (YAML 1.2 core or JSON, [fmt] "yaml" or "json") with source positions. Input above [ActionAuthor.MAX_AUTHOR_BYTES]
     * is refused. Never throws.
     */
    fun loadActionsText(text: String, fmt: String = "yaml"): MutableMap<String, Any?> {
        if (Json.utf8(text).size > ActionAuthor.MAX_AUTHOR_BYTES) return fail("the file is larger than ${ActionAuthor.MAX_AUTHOR_BYTES} bytes")
        var positions: List<Pos>? = null
        val value: Any?
        if (fmt == "json") {
            try { value = Json.parseLenient(text) } catch (e: RuntimeException) { return fail("not JSON: " + e.message) } // JSON.parse: a repeated key keeps the last value, any number is read
            // JSON is YAML: only the positions come from the YAML parse
            positions = try { positionsOf(parseDocument(text, false)) } catch (e: RuntimeException) { null }
        } else {
            try {
                val root = parseDocument(text, true)
                value = toValue(root)
                positions = positionsOf(root)
            } catch (e: YamlLoadError) { return fail("not YAML: " + e.message, e.line, e.column) }
        }
        val res = ActionAuthor.loadActionsValue(value)
        if (positions != null) attachPositions(res, positions)
        return res
    }
}
