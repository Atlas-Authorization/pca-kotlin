package net.atlasauth.pca.wallet

import net.atlasauth.pca.jose.Js

/**
 * Cell coordinates and the wallet's own outcome space. A site names a question's cell by coordinates (an inclusive cell-index
 * range per numeric dimension, a value set per categorical one); the wallet resolves them against ITS OWN copy of the outcome
 * space and refuses anything it cannot resolve exactly: an unknown dimension, an index out of range, an unknown value, or a
 * dimension of the verb the coordinates leave out. A cell box is `Array<IntArray>`: per dimension the allowed cell indices
 * (sorted, de-duplicated).
 */
@Suppress("UNCHECKED_CAST")
object WalletBox {
    /** The outcome of [resolveCoords]: ok with the verb space and the box, or a refusal reason. */
    class BoxResult private constructor(
        @JvmField val ok: Boolean,
        @JvmField val reason: String?,
        @JvmField val vs: Map<String, Any?>?,
        @JvmField val box: Array<IntArray>?,
    ) {
        internal constructor(reason: String) : this(false, reason, null, null)
        internal constructor(vs: Map<String, Any?>, box: Array<IntArray>) : this(true, null, vs, box)

        /** {ok, reason} or {ok, verb, box} (the verb space itself is omitted). */
        fun toMap(): Map<String, Any?> {
            if (!ok) return Wallet.obj("ok", false, "reason", reason)
            return Wallet.obj("ok", true, "verb", vs!!["verb"], "box", boxList(box!!))
        }
    }

    fun boxList(box: Array<IntArray>): List<Any?> = box.map { WalletNoise.idxList(it) }

    fun boxOf(o: Any?): Array<IntArray> {
        val l = o as List<*>
        return Array(l.size) { WalletNoise.idxOf(l[it]) }
    }

    private val ACC = Regex("env\\.acc\\.([A-Za-z0-9_.-]+)\\.post")
    private val MON = Regex("env\\.mon\\.([A-Za-z0-9_.-]+)\\.state")
    private val PROV = Regex("env\\.prov\\.([^\\n\\r\\u2028\\u2029]+)")
    private val WORLD = Regex("env\\.world\\.([A-Za-z0-9_.-]+)")

    /** The coordinate key of a dimension path (the spec's short aliases for lifted dimensions). */
    fun coordKeyOf(path: String): String {
        ACC.matchEntire(path)?.let { return it.groupValues[1] }
        MON.matchEntire(path)?.let { return "mon:" + it.groupValues[1] }
        PROV.matchEntire(path)?.let { return "prov:" + it.groupValues[1] }
        WORLD.matchEntire(path)?.let { return it.groupValues[1] }
        return path
    }

    /** The label of categorical value i of a dimension, as used in coordinates: its raw value. */
    fun catLabel(d: Map<String, Any?>, i: Int): String = WalletOmega.value(d, i)["value"] as String

    /** `JSON.stringify` of a string. */
    fun jsonString(s: String): String {
        val sb = StringBuilder("\"")
        for (i in s.indices) {
            val c = s[i]
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000c' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    val lone = Character.isSurrogate(c) && !((Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) ||
                        (Character.isLowSurrogate(c) && i > 0 && Character.isHighSurrogate(s[i - 1])))
                    if (c.code < 0x20 || lone) sb.append(String.format("\\u%04x", c.code)) else sb.append(c)
                }
            }
        }
        return sb.append('"').toString()
    }

    /** Resolve coordinates to a box of cells of the verb's space. Every dimension must be named exactly once. */
    fun resolveCoords(omega: Map<String, Any?>, verb: String, coords: Map<String, Any?>): BoxResult {
        val vs = WalletOmega.verbSpace(omega, verb) ?: return BoxResult("verb $verb is not in the wallet's outcome space")
        val nd = WalletOmega.dims(vs).size
        val byKey = HashMap<String, Int>()
        for (k in 0 until nd) {
            val path = WalletOmega.dim(vs, k)["path"] as String
            byKey[path] = k
            byKey[coordKeyOf(path)] = k
        }
        val named = HashSet<Int>()
        for (key in coords.keys) {
            val k = byKey[key] ?: return BoxResult("unknown dimension $key")
            if (named.contains(k)) return BoxResult("dimension " + WalletOmega.dim(vs, k)["path"] + " is named twice")
            named.add(k)
        }
        val box = arrayOfNulls<IntArray>(nd)
        for (k in 0 until nd) {
            val d = WalletOmega.dim(vs, k)
            val path = d["path"] as String
            val ck = coordKeyOf(path)
            // `coords[path] ?? coords[ck]`: a null under the first key falls through to the second, whose value (null included) is the result
            val first = coords[path]
            val present = first != null || coords.containsKey(ck)
            val c = first ?: coords[ck]
            if (!present) return BoxResult("coordinates leave out dimension $path")
            // a null that is the result is not undefined: the reference reads .length / .every of it and throws
            if (c == null) throw IllegalArgumentException("Cannot read properties of null (reading '" + (if ("num" == d["kind"]) "length" else "every") + "')")
            if ("num" == d["kind"]) {
                val cl = c as? List<*>
                if (!(cl != null && cl.size == 2 && Js.isNumber(cl[0]) && Js.isNumber(cl[1]))) return BoxResult("dimension $path is numeric: expected an index range")
                val lo = Js.num(cl[0])!!
                val hi = Js.num(cl[1])!!
                val ok = lo == Math.rint(lo) && hi == Math.rint(hi) && !lo.isInfinite() && !hi.isInfinite() && !Js.isNegZero(cl[0]) && !Js.isNegZero(cl[1]) &&
                    lo >= 0 && lo <= hi && hi < WalletOmega.numCells(d).size
                if (!ok) return BoxResult("index range of $path is out of range")
                box[k] = IntArray((hi - lo).toInt() + 1) { lo.toInt() + it }
            } else {
                if (c !is List<*>) throw IllegalArgumentException("c.every is not a function")
                for (x in c) if (x !is String) return BoxResult("dimension $path is categorical: expected a value set")
                val ids = java.util.TreeSet<Int>()
                for (lab in c) {
                    var hits = 0
                    var hit = -1
                    val vals = WalletOmega.values(d)
                    for (j in vals.indices) if (lab == WalletOmega.value(d, j)["value"]) { hits++; hit = j }
                    if (hits == 0) return BoxResult("unknown value " + jsonString(lab as String) + " for " + path)
                    if (hits > 1) return BoxResult("value " + jsonString(lab as String) + " names two cells of " + path)
                    ids.add(hit)
                }
                box[k] = ids.toIntArray()
            }
        }
        return BoxResult(vs, Array(nd) { box[it]!! })
    }

    /** The coordinates of a box (the inverse of resolveCoords; numeric sides must be contiguous). */
    fun coordsOfBox(vs: Map<String, Any?>, box: Array<IntArray>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for (k in WalletOmega.dims(vs).indices) {
            val d = WalletOmega.dim(vs, k)
            val ids = box[k]
            if ("num" == d["kind"]) {
                var lo = Int.MAX_VALUE
                var hi = Int.MIN_VALUE
                for (i in ids) { lo = Math.min(lo, i); hi = Math.max(hi, i) }
                if (hi - lo + 1 != ids.size) throw IllegalArgumentException("coordsOfBox: numeric side of " + d["path"] + " is not contiguous")
                out[d["path"] as String] = arrayListOf<Any?>(lo.toLong(), hi.toLong())
            } else {
                out[d["path"] as String] = ids.map { catLabel(d, it) }.toMutableList<Any?>()
            }
        }
        return out
    }

    /** Coordinates of one cell. */
    fun coordsOfCell(vs: Map<String, Any?>, idx: IntArray): Map<String, Any?> = coordsOfBox(vs, Array(idx.size) { intArrayOf(idx[it]) })

    fun cellInBox(box: Array<IntArray>, idx: IntArray): Boolean {
        if (box.size != idx.size) return false
        for (k in box.indices) {
            var inside = false
            for (i in box[k]) if (i == idx[k]) inside = true
            if (!inside) return false
        }
        return true
    }

    /** Every cell (per-dimension indices) of a box, in lexicographic order. */
    fun boxCells(box: Array<IntArray>): List<IntArray> {
        var out: List<IntArray> = listOf(IntArray(0))
        for (ids in box) {
            val next = ArrayList<IntArray>()
            for (pre in out) for (i in ids) next.add(pre.copyOf(pre.size + 1).also { it[pre.size] = i })
            out = next
        }
        return out
    }

    fun boxSize(box: Array<IntArray>): Double {
        var n = 1.0
        for (ids in box) n *= ids.size
        return n
    }

    /** The cell of a concrete action in the wallet's outcome space (null when it falls outside: fail closed). */
    class CellAtVs internal constructor(@JvmField val vs: Map<String, Any?>, @JvmField val idx: IntArray) {
        fun toMap(): Map<String, Any?> = Wallet.obj("verb", vs["verb"], "idx", WalletNoise.idxList(idx))
    }

    fun cellOfAction(omega: Map<String, Any?>, a: Map<String, Any?>): CellAtVs? {
        val vs = WalletOmega.verbSpace(omega, a["verb"]) ?: return null
        val values = a["values"]
        for (k in WalletOmega.dims(vs).indices) {
            // `path in values` throws for anything that is not an object (undefined, null, a primitive)
            if (values !is Map<*, *> && values !is List<*>) throw IllegalArgumentException("Cannot use 'in' operator to search for '" + WalletOmega.dim(vs, k)["path"] + "' in " + (if (values == null) "null" else "primitive"))
            if (values !is Map<*, *> || !values.containsKey(WalletOmega.dim(vs, k)["path"])) return null
        }
        val idx = WalletOmega.cellOf(vs, Wallet.obj("verb", a["verb"], "values", values)) ?: return null
        return CellAtVs(vs, idx)
    }

    /** Flat lexicographic index of a cell (the tie-breaker "cell index"). */
    fun flatIndex(vs: Map<String, Any?>, idx: IntArray): Double {
        var f = 0.0
        for (k in WalletOmega.dims(vs).indices) f = f * WalletOmega.cellCount(WalletOmega.dim(vs, k)) + idx[k]
        return f
    }
}
