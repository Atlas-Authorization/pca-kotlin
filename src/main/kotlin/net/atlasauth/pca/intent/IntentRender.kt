package net.atlasauth.pca.intent

import java.util.TreeSet
import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Catalog
import net.atlasauth.pca.verifier.Json

/**
 * Deterministic plain-language rendering of grants, questions and actions, and the back-translation diff. Every sentence is a
 * fixed template over the data (no model anywhere), so the same grant always renders the same text. Anything the templates do
 * not know is rendered as an explicit "not understood" line. Policies, caveats and conditions are JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object IntentRender {
    /** A JavaScript `undefined` (an absent member), distinct from JSON null. */
    internal val UNDEF = Any()

    internal fun prop(o: Any?, k: String): Any? {
        if (o == null) throw NullPointerException("cannot read $k of null")
        if (o !is Map<*, *>) return UNDEF
        return if (o.containsKey(k)) o[k] else UNDEF
    }

    internal fun isNum(o: Any?): Boolean = o is Json.Num || o is Number

    private fun js(d: Double): String = AttestUtil.jsNumString(d)

    /** `String(v)` for a JSON tree value. */
    internal fun str(v: Any?): String {
        if (v === UNDEF) return "undefined"
        if (v == null) return "null"
        if (isNum(v)) return js(IntentOmega.dbl(v))
        if (v is String || v is Boolean) return v.toString()
        if (v is List<*>) {
            val sb = StringBuilder()
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                if (x != null && x !== UNDEF) sb.append(str(x))
            }
            return sb.toString()
        }
        return "[object Object]"
    }

    private val NUM_RE = Regex("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")
    private val INF_RE = Regex("[+-]?Infinity")

    /** `Number(v)` for a JSON tree value (NaN when not numeric). */
    internal fun toNumber(v: Any?): Double {
        if (v === UNDEF) return Double.NaN
        if (v == null) return 0.0
        if (isNum(v)) return IntentOmega.dbl(v)
        if (v is Boolean) return if (v) 1.0 else 0.0
        if (v is String) {
            val s = v.trim()
            if (s.isEmpty()) return 0.0
            if (NUM_RE.matches(s)) return s.toDouble()
            if (INF_RE.matches(s)) return if (s.startsWith("-")) Double.NEGATIVE_INFINITY else Double.POSITIVE_INFINITY
            return Double.NaN
        }
        if (v is List<*>) return toNumber(net.atlasauth.pca.jose.Js.template(v)) // ToPrimitive of an array is its joined text
        return Double.NaN
    }

    private fun pad(n: Long, w: Int): String {
        val s = n.toString()
        return if (s.length >= w) s else "0".repeat(w - s.length) + s
    }

    private fun floorDiv(a: Long, b: Long): Long {
        val q = a / b
        return if ((a % b != 0L) && ((a < 0) != (b < 0))) q - 1 else q
    }

    /** `new Date(ms).toISOString()`; throws for an invalid date like the reference (no java.time: API 24). */
    internal fun isoString(ms: Double): String {
        if (ms.isNaN() || ms.isInfinite() || Math.abs(ms) > 8.64e15) throw IllegalArgumentException("Invalid time value")
        val t = ms.toLong()
        val days = floorDiv(t, 86_400_000L)
        val rem = t - days * 86_400_000L
        // civil-from-days (proleptic Gregorian)
        val z = days + 719468
        val era = floorDiv(z, 146097)
        val doe = z - era * 146097
        val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
        val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        val mp = (5 * doy + 2) / 153
        val d = doy - (153 * mp + 2) / 5 + 1
        val m = if (mp < 10) mp + 3 else mp - 9
        val y = yoe + era * 400 + (if (m <= 2) 1 else 0)
        val year = if (y in 0..9999) pad(y, 4) else (if (y < 0) "-" else "+") + pad(Math.abs(y), 6)
        val h = rem / 3_600_000L
        val mi = (rem / 60_000L) % 60
        val s = (rem / 1000L) % 60
        val milli = rem % 1000
        return "$year-${pad(m, 2)}-${pad(d, 2)}T${pad(h, 2)}:${pad(mi, 2)}:${pad(s, 2)}.${pad(milli, 3)}Z"
    }

    internal fun replaceFirst(s: String, a: Char, b: Char): String {
        val i = s.indexOf(a)
        return if (i < 0) s else s.substring(0, i) + b + s.substring(i + 1)
    }

    /** `d.replace(/\.$/, '').replace(/^./, c => c.toLowerCase())`. */
    internal fun lowerFirst(d: String): String {
        val s = if (d.endsWith(".")) d.substring(0, d.length - 1) else d
        if (s.isEmpty()) return s
        val c = s[0]
        if (c == '\n' || c == '\r' || c == ' ' || c == ' ') return s
        return c.toString().lowercase(java.util.Locale.ROOT) + s.substring(1)
    }

    internal fun stripDot(d: String): String = if (d.endsWith(".")) d.substring(0, d.length - 1) else d

    fun labelOf(path: String): String {
        if (path == "action.resource") return "resource"
        val parts = path.split(".")
        return parts[parts.size - 1].replace('_', ' ')
    }

    internal fun fmt(v: Any?): String {
        if (v is String) return "\"" + v + "\""
        if (v is List<*>) return v.joinToString(", ") { fmt(it) }
        return str(v)
    }

    private const val UNREADABLE = "an unreadable condition (not understood)"

    fun renderCondition(c: Any?): String {
        if (c !is Map<*, *>) return UNREADABLE
        val m = c
        if (m.containsKey("all_of") || m.containsKey("any_of") || m.containsKey("not")) {
            if (m.containsKey("all_of")) return "all of: " + joined(m["all_of"], " and ")
            if (m.containsKey("any_of")) return "either " + joined(m["any_of"], " or ")
            return "it is not the case that " + renderCondition(m["not"])
        }
        val field = m["field"] as? String ?: return UNREADABLE
        val l = "the " + labelOf(field)
        val op = m["op"]
        val v = if (m.containsKey("ref")) "the " + labelOf(m["ref"] as String) else fmt(if (m.containsKey("value")) m["value"] else UNDEF)
        return when (if (op is String) op else "\u0000") {
            "eq" -> "$l is $v"
            "ne" -> "$l is not $v"
            "in" -> "$l is one of $v"
            "nin" -> "$l is none of $v"
            "lt" -> "$l is less than $v"
            "lte" -> "$l is at most $v"
            "gt" -> "$l is more than $v"
            "gte" -> "$l is at least $v"
            "prefix" -> "$l starts with $v"
            "exists" -> if (false == m["value"]) "$l is absent" else "$l is present"
            "like" -> "$l matches the pattern $v"
            "matches" -> "$l matches the regular expression $v"
            "is_a" -> "$l is of type $v"
            "member_of" -> "$l belongs to $v"
            else -> l + " has an unrecognised test \"" + str(if (m.containsKey("op")) op else UNDEF) + "\" (not understood)"
        }
    }

    /** `(xs ?? []).map(renderCondition).map(s => "(s)").join(sep)`; a non-array throws like `.map` would. */
    private fun joined(xs: Any?, sep: String): String {
        if (xs == null) return ""
        if (xs !is List<*>) throw IllegalArgumentException("map is not a function")
        return xs.joinToString(sep) { "(" + renderCondition(it) + ")" }
    }

    private fun renderResource(r: Any?): String {
        if (r === UNDEF || "*" == r) return "on any resource"
        if (r !is String) return "on an unreadable resource matcher (not understood)"
        if (r.startsWith("re:")) return "on resources matching the regular expression \"" + r.substring(3) + "\""
        if (r.endsWith("*")) return "on resources under \"" + r.substring(0, r.length - 1) + "\""
        return "only on resource \"$r\""
    }

    private fun renderVerb(v: Any?, catalog: Catalog): String {
        if (v is List<*>) return v.joinToString("; or ") { oneVerb(str(it), catalog) }
        return oneVerb(str(v), catalog)
    }

    private fun oneVerb(x: String, catalog: Catalog): String {
        if (x == "*") return "ANY action of any connector"
        val s = catalog.get(x)
        return if (s != null) lowerFirst(s.description) + " [" + x + ", " + replaceFirst(s.reversibility, '_', '-') + "]" else "\"" + x + "\" [uncatalogued: treated as irreversible]"
    }

    fun renderCaveat(c: Any?): String {
        val type = if (c == null) UNDEF else prop(c, "type")
        return when (if (type is String) type else "\u0000") {
            "expires" -> "The grant expires at " + isoString(toNumber(prop(c, "at"))) + "."
            "not_before" -> "The grant is not valid before " + isoString(toNumber(prop(c, "at"))) + "."
            "rate" -> "At most " + str(prop(c, "max")) + " actions in any " + str(prop(c, "per_secs")) + " seconds."
            "max_blast_radius" -> "No action whose blast radius exceeds " + str(prop(c, "max")) + " (on a 0–1 scale)."
            "reversibility_max" -> "Nothing more severe than \"" + replaceFirst(str(prop(c, "class")), '_', '-') + "\" (reversible < rate-limited < irreversible)."
            "delegation_depth" -> "It may be re-delegated at most " + str(prop(c, "max")) + " level(s) deep."
            "budget_alloc" -> "A trust-budget allocation of " + str(prop(c, "limit")) + " is carried for sub-delegation."
            else -> "An unrecognised constraint of type \"" + str(type) + "\" (NOT UNDERSTOOD: do not rely on this grant until it is explained)."
        }
    }

    /** A grant as numbered plain-language sentences. */
    @JvmOverloads
    fun renderGrant(policy: Any?, catalog: Catalog = Catalog.DEFAULT): String {
        val np = IntentPolicy.normalizePolicy(policy)
        val predicates = np["predicates"] as List<Any?>
        val caveats = np["caveats"] as List<Any?>
        if (predicates.isEmpty()) return "This grant allows nothing."
        val lines = ArrayList<String>()
        lines.add("The agent may do the following, and nothing else:")
        for (i in predicates.indices) {
            val p = predicates[i]
            val where = prop(p, "where")
            val conds = ArrayList<String>()
            if (where !== UNDEF && where != null) {
                if (where !is List<*>) throw IllegalArgumentException("map is not a function")
                for (c in where) conds.add(renderCondition(c))
            }
            lines.add((i + 1).toString() + ". " + renderVerb(prop(p, "verb"), catalog) + ", " + renderResource(prop(p, "resource")) +
                (if (conds.isEmpty()) "" else ", only when " + conds.joinToString(", and ")) + ".")
        }
        if (caveats.isNotEmpty()) {
            lines.add("Limits that apply to everything above:")
            for (c in caveats) lines.add("- " + renderCaveat(c))
        }
        return lines.joinToString("\n")
    }

    // ---- outcome / question rendering ----

    private fun renderDimCell(d: Dim, i: Int): String {
        val l = labelOf(d.path)
        if (d is NumDim) {
            val c = IntentOmega.numCells(d)[i]
            if (c.lo == c.hi) return l + " exactly " + js(c.lo)
            return "any " + l + " from " + js(c.lo) + " to " + js(c.hi) + " (e.g. " + js(if (i > 0) c.lo else c.hi) + ")"
        }
        val v = (d as CatDim).values[i]
        if (v.kind == "exact") return l + " \"" + v.value + "\""
        if (v.kind == "prefix") return "a " + l + " under \"" + v.value + "\" (not otherwise named)"
        return "a $l not named anywhere in the grant or your request"
    }

    @JvmOverloads
    fun renderQuestion(vs: VerbSpace, cell: IntArray, catalog: Catalog = Catalog.DEFAULT): String {
        val s = catalog.get(vs.verb)
        val what = if (s != null) stripDot(s.description) + " [" + vs.verb + "]" else "perform \"" + vs.verb + "\""
        val parts = vs.dims.indices.map { renderDimCell(vs.dims[it], cell[it]) }
        return "Should the agent be allowed to: " + what + (if (parts.isEmpty()) "" else ", with " + parts.joinToString(", ")) + "?"
    }

    // ---- back-translation diff ----

    /** What a rendering asserts about one dimension (numeric: [min, max] of accepted values; categorical: value labels). */
    class DimClaim internal constructor(@JvmField val path: String, @JvmField val any: Boolean, @JvmField val range: DoubleArray?, @JvmField val values: List<String>?) {
        internal fun sameAs(o: DimClaim): Boolean =
            path == o.path && any == o.any && java.util.Arrays.equals(range, o.range) && values == o.values

        fun toJson(): MutableMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["path"] = path
            m["any"] = any
            if (range != null) m["range"] = arrayListOf<Any?>(range[0], range[1])
            if (values != null) m["values"] = ArrayList<Any?>(values)
            return m
        }
    }

    class VerbClaim internal constructor(@JvmField val verb: String, @JvmField val allowed: Boolean, @JvmField val boxShaped: Boolean, @JvmField val dims: List<DimClaim>) {
        fun toJson(): MutableMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["verb"] = verb
            m["allowed"] = allowed
            m["boxShaped"] = boxShaped
            m["dims"] = dims.map { it.toJson() }.toMutableList()
            return m
        }
    }

    /** What the policy asserts over the space, verb by verb and dimension by dimension. */
    fun claimsOf(policy: Any?, omega: Omega): List<VerbClaim> {
        val a = IntentPolicy.admitter(policy)
        val out = ArrayList<VerbClaim>()
        for (vs in omega.verbs) {
            val n = IntentOmega.verbCellCount(vs)
            val acc = ArrayList<IntArray>()
            var c = 0.0
            while (c < n) {
                val idx = IntentOmega.decodeCell(vs, c)
                if (a.admits(vs, IntentOmega.cellRep(vs, idx))) acc.add(idx)
                c++
            }
            val proj = vs.dims.indices.map { k -> TreeSet<Int>().also { s -> for (x in acc) s.add(x[k]) } }
            var boxCount = 1.0
            for (s in proj) boxCount *= s.size
            val dims = ArrayList<DimClaim>()
            for (k in vs.dims.indices) {
                val d = vs.dims[k]
                val s = proj[k]
                val total = IntentOmega.cellCount(d)
                val any = s.size == total
                if (d is NumDim) {
                    var range: DoubleArray? = null
                    if (s.isNotEmpty()) {
                        val cells = IntentOmega.numCells(d)
                        range = doubleArrayOf(cells[s.first()].lo, cells[s.last()].hi)
                    }
                    dims.add(DimClaim(d.path, any, range, null))
                } else {
                    val vals = s.map { i ->
                        val v = (d as CatDim).values[i]
                        if (v.kind == "prefix") v.value + "*" else v.value
                    }
                    dims.add(DimClaim(d.path, any, null, vals))
                }
            }
            out.add(VerbClaim(vs.verb, acc.isNotEmpty(), acc.size.toDouble() == boxCount, dims))
        }
        return out
    }

    /** One difference between two readings, with the sentence shown to the principal. */
    data class ClaimDiff(val verb: String, val kind: String, val path: String?, val text: String) {
        fun toJson(): MutableMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["verb"] = verb
            m["kind"] = kind
            if (path != null) m["path"] = path
            m["text"] = text
            return m
        }
    }

    private fun dimText(c: DimClaim?): String {
        if (c == null) return "anything"
        if (c.any) return "any value"
        if (c.range != null) return js(c.range[0]) + " to " + js(c.range[1])
        return if (c.values != null && c.values.isNotEmpty()) c.values.joinToString(", ") else "nothing"
    }

    private interface Wording {
        fun extra(verb: String): String
        fun missing(verb: String): String
        fun shape(verb: String): String
        fun dim(verb: String, path: String, a: String, b: String): String
    }

    private fun diffClaims(g: List<VerbClaim>, s: List<VerbClaim>, w: Wording): List<ClaimDiff> {
        val out = ArrayList<ClaimDiff>()
        for (i in g.indices) {
            val gc = g[i]
            val sc = s[i]
            if (gc.allowed && !sc.allowed) {
                out.add(ClaimDiff(gc.verb, "extra-verb", null, w.extra(gc.verb)))
                continue
            }
            if (!gc.allowed && sc.allowed) {
                out.add(ClaimDiff(gc.verb, "missing-verb", null, w.missing(gc.verb)))
                continue
            }
            if (!gc.allowed) continue
            if (gc.boxShaped != sc.boxShaped) out.add(ClaimDiff(gc.verb, "shape", null, w.shape(gc.verb)))
            for (k in gc.dims.indices) {
                val gd = gc.dims[k]
                val sd = sc.dims[k]
                if (gd.sameAs(sd)) continue
                var kind = "different"
                if (gd.range != null && sd.range != null) {
                    kind = if (gd.range[0] <= sd.range[0] && gd.range[1] >= sd.range[1]) "looser" else if (gd.range[0] >= sd.range[0] && gd.range[1] <= sd.range[1]) "tighter" else "different"
                } else if (gd.values != null && sd.values != null) {
                    kind = if (gd.values.containsAll(sd.values)) "looser" else if (sd.values.containsAll(gd.values)) "tighter" else "different"
                } else if (gd.any && !sd.any) kind = "looser"
                out.add(ClaimDiff(gc.verb, kind, gd.path, w.dim(gc.verb, gd.path, dimText(gd), dimText(sd))))
            }
        }
        return out
    }

    /** Render the grant and the intent slots into the same claim form over the space and list every difference. */
    fun backTranslationDiff(grant: Any?, slots: Any?, omega: Omega): List<ClaimDiff> =
        diffClaims(claimsOf(grant, omega), claimsOf(IntentDerive.slotsToPolicy(slots), omega), object : Wording {
            override fun extra(verb: String) = "The grant allows $verb, which your request did not mention."
            override fun missing(verb: String) = "Your request mentions $verb, but the grant does not allow it."
            override fun shape(verb: String) = "The grant's rule for $verb is a combination of cases that your request did not describe."
            override fun dim(verb: String, path: String, a: String, b: String) = "For " + verb + ", the grant allows " + labelOf(path) + " " + a + "; your request said " + b + "."
        })

    /** The same claim diff between two grants; `kind` is from a's point of view (looser = a allows more). */
    @JvmOverloads
    fun claimDiff(a: Any?, b: Any?, omega: Omega, n0: String = "the first reading", n1: String = "the second reading"): List<ClaimDiff> =
        diffClaims(claimsOf(a, omega), claimsOf(b, omega), object : Wording {
            override fun extra(verb: String) = "$n0 allows $verb; $n1 does not."
            override fun missing(verb: String) = "$n1 allows $verb; $n0 does not."
            override fun shape(verb: String) = "$n0 and $n1 describe $verb with differently shaped rules."
            override fun dim(verb: String, path: String, a: String, b: String) = "For " + verb + ", " + n0 + " allows " + labelOf(path) + " " + a + "; " + n1 + " allows " + b + "."
        })

    /** A concrete action in plain language; values are printed verbatim, so nothing is hidden. */
    @JvmOverloads
    fun renderAction(vs: VerbSpace, values: Map<String, Any?>, catalog: Catalog = Catalog.DEFAULT): String {
        val s = catalog.get(vs.verb)
        val what = if (s != null) stripDot(s.description) + " [" + vs.verb + ", " + replaceFirst(vs.reversibility, '_', '-') + "]" else "perform \"" + vs.verb + "\" [uncatalogued: treated as irreversible]"
        val parts = TreeSet(values.keys).map { k ->
            val v = values[k]
            labelOf(k) + " " + (if (v is String) "\"" + v + "\"" else str(if (v is Double) Json.Num(js(v)) else v))
        }
        return "The agent wants to: " + what + (if (parts.isEmpty()) "" else ", with " + parts.joinToString(", ")) + "."
    }
}
