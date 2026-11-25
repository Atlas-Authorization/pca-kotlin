package net.atlasauth.pca.wallet

import net.atlasauth.pca.jose.Js

/**
 * The part of the intent outcome space the wallet reads: cells of a numeric (inclusive integer ranges) or categorical
 * (exact / prefix / other) dimension, the cell of a concrete outcome, its representative outcome, and the cell statistics
 * (mass and expected harm, exact for short cells, closed form or deterministic quadrature for long ones).
 *
 * An outcome space is the parsed-JSON tree `{v:1, verbs:[{verb, reversibility, weight, dims:[...]}], approximate}`;
 * a dimension is `{kind:"num", path, lo, hi, cuts, dist}` or `{kind:"cat", path, values:[{kind, value}]}`.
 */
@Suppress("UNCHECKED_CAST")
object WalletOmega {
    /** The per-dimension harm factors (h_v the verb factor, g_d the dimension factor at a concrete value). */
    interface HarmModel {
        fun verb(vs: Map<String, Any?>): Double

        fun dim(d: Map<String, Any?>, x: Any?): Double

        /** Closed form of E[g_d | x in [lo, hi]] for a numeric dimension, or null when the model has none. */
        fun dimMean(d: Map<String, Any?>, lo: Double, hi: Double): Double? = null
    }

    internal const val EXACT_SPAN = 4096
    internal const val HARM_QUADRATURE_PIECES = 1024
    private const val EULER_GAMMA = 0.5772156649015329
    private val AMOUNT = Regex("(^|\\.)amount$")

    private fun linearAmount(d: Map<String, Any?>): Boolean = "num" == d["kind"] && AMOUNT.containsMatchIn(d["path"] as String)

    /** Default separable harm: irreversible 10, rate-limited 3, reversible 1; amounts scale as 1 + x/100. */
    @JvmField val DEFAULT_HARM: HarmModel = object : HarmModel {
        override fun verb(vs: Map<String, Any?>): Double {
            val r = vs["reversibility"]
            return if ("irreversible" == r) 10.0 else if ("rate_limited" == r) 3.0 else 1.0
        }

        override fun dim(d: Map<String, Any?>, x: Any?): Double =
            if (linearAmount(d) && Js.isNumber(x)) 1 + Math.max(0.0, Js.num(x)!!) / 100 else 1.0

        override fun dimMean(d: Map<String, Any?>, lo: Double, hi: Double): Double? =
            if (linearAmount(d)) 1 + Math.max(0.0, intervalMeanX(d, Math.max(lo, 0.0), hi, lo)) / 100 else 1.0
    }

    // ---- accessors ----

    fun dims(vs: Map<String, Any?>): List<Any?> = vs["dims"] as List<Any?>

    fun dim(vs: Map<String, Any?>, k: Int): Map<String, Any?> = dims(vs)[k] as Map<String, Any?>

    fun values(d: Map<String, Any?>): List<Any?> = d["values"] as List<Any?>

    fun value(d: Map<String, Any?>, i: Int): Map<String, Any?> = values(d)[i] as Map<String, Any?>

    fun dlo(d: Map<String, Any?>): Double = Js.num(d["lo"])!!

    fun dhi(d: Map<String, Any?>): Double = Js.num(d["hi"])!!

    fun verbSpace(omega: Map<String, Any?>, verb: Any?): Map<String, Any?>? {
        for (v in omega["verbs"] as List<Any?>) if ((v as Map<String, Any?>)["verb"] == verb) return v
        return null
    }

    // ---- cells ----

    /** The ordered cells {lo, hi} of a numeric dimension (inclusive ranges; empty cells dropped). */
    fun numCells(d: Map<String, Any?>): List<DoubleArray> {
        val out = ArrayList<DoubleArray>()
        val lo = dlo(d)
        val hi = dhi(d)
        var cur = lo
        for (cO in d["cuts"] as List<*>) {
            val c = Js.num(cO)!!
            if (c < lo || c > hi) continue
            if (cur <= c - 1) out.add(doubleArrayOf(cur, c - 1))
            out.add(doubleArrayOf(c, c))
            cur = c + 1
        }
        if (cur <= hi) out.add(doubleArrayOf(cur, hi))
        return out
    }

    fun cellCount(d: Map<String, Any?>): Int = if ("num" == d["kind"]) numCells(d).size else values(d).size

    /** Number of cells of a verb (the product of per-dimension cell counts). */
    fun verbCellCount(vs: Map<String, Any?>): Double {
        var n = 1.0
        for (k in dims(vs).indices) n = n * cellCount(dim(vs, k))
        return n
    }

    /** Decode a flat cell index into per-dimension cell indices (last dimension varies fastest). */
    fun decodeCell(vs: Map<String, Any?>, flat0: Double): IntArray {
        var flat = flat0
        val nd = dims(vs).size
        val idx = IntArray(nd)
        for (i in nd - 1 downTo 0) {
            val n = cellCount(dim(vs, i))
            idx[i] = (flat % n).toInt()
            flat = Math.floor(flat / n)
        }
        return idx
    }

    /** Which cell of a categorical dimension a concrete string falls in (exact, then longest prefix, then other). */
    fun catCellOf(d: Map<String, Any?>, s: String): Int {
        var best = -1
        var bestLen = -1
        val vals = values(d)
        for (i in vals.indices) {
            val v = value(d, i)
            if ("exact" == v["kind"] && v["value"] == s) return i
            val pv = v["value"] as String
            if ("prefix" == v["kind"] && s.startsWith(pv) && pv.length > bestLen) {
                best = i
                bestLen = pv.length
            }
        }
        if (best >= 0) return best
        for (i in vals.indices) if ("other" == value(d, i)["kind"]) return i
        return -1
    }

    /** Which cell a concrete value falls in, or -1 when it is outside the dimension's domain or type. */
    fun cellOfValue(d: Map<String, Any?>, x: Any?): Int {
        if ("num" == d["kind"]) {
            if (!Js.isNumber(x)) return -1
            val v = Js.num(x)!!
            if (v.isNaN() || v.isInfinite()) return -1
            val cells = numCells(d)
            for (i in cells.indices) if (v >= cells[i][0] && v <= cells[i][1]) return i
            return -1
        }
        if (x !is String) return -1
        return catCellOf(d, x)
    }

    /** Per-dimension cell indices of an outcome {verb, values}, or null if any value lies outside the outcome space. */
    fun cellOf(vs: Map<String, Any?>, o: Map<String, Any?>): IntArray? {
        val nd = dims(vs).size
        val idx = IntArray(nd)
        val vals = o["values"]
        for (k in 0 until nd) {
            val d = dim(vs, k)
            val i = cellOfValue(d, Js.get(vals, d["path"] as String))
            if (i < 0) return null
            idx[k] = i
        }
        return idx
    }

    /** A concrete string that falls in categorical cell [i] (exact: itself; prefix / other: a fresh extension). */
    fun catRep(d: Map<String, Any?>, i: Int): String {
        val v = value(d, i)
        if ("exact" == v["kind"]) return v["value"] as String
        val base = if ("prefix" == v["kind"]) v["value"].toString() + "x" else "other"
        for (k in 0 until 64) {
            val s = base + (if (k == 0) "" else k.toString())
            if (catCellOf(d, s) == i) return s
        }
        return base
    }

    /** The question point of a numeric cell: its lowest value when it has a left neighbour, else its highest. */
    fun numRep(d: Map<String, Any?>, i: Int): Double {
        val c = numCells(d)[i]
        return if (i > 0) c[0] else c[1]
    }

    fun repValue(d: Map<String, Any?>, i: Int): Any = if ("num" == d["kind"]) numRep(d, i) else catRep(d, i)

    /** The representative (question) outcome {verb, values} of a cell. */
    fun cellRep(vs: Map<String, Any?>, idx: IntArray): Map<String, Any?> {
        val values = LinkedHashMap<String, Any?>()
        for (k in dims(vs).indices) {
            val d = dim(vs, k)
            values[d["path"] as String] = repValue(d, idx[k])
        }
        val o = LinkedHashMap<String, Any?>()
        o["verb"] = vs["verb"]
        o["values"] = values
        return o
    }

    // ---- workload mass and harm ----

    private fun logUniform(d: Map<String, Any?>): Boolean = "loguniform" == d["dist"] && dlo(d) >= 0

    private fun pointWeight(d: Map<String, Any?>, x: Double): Double = if (logUniform(d)) 1 / (x + 1) else 1.0

    /** H(n) = sum_{k=1}^{n} 1/k. */
    private fun harmonic(n: Double): Double {
        if (n <= 0) return 0.0
        if (n <= EXACT_SPAN) {
            var s = 0.0
            var k = n
            while (k >= 1) { s += 1 / k; k-- }
            return s
        }
        val n2 = n * n
        return net.atlasauth.pca.verifier.DetMath.detLn(n) + EULER_GAMMA + 1 / (2 * n) - 1 / (12 * n2) + 1 / (120 * n2 * n2) - 1 / (252 * n2 * n2 * n2)
    }

    /** Sum of w(x) over the integers a..b for the dimension's law (0 for an empty interval). */
    fun intervalWeight(d: Map<String, Any?>, a: Double, b: Double): Double {
        if (b < a) return 0.0
        if (!logUniform(d)) return b - a + 1
        if (b - a + 1 <= EXACT_SPAN) {
            var s = 0.0
            var x = b
            while (x >= a) { s += 1 / (x + 1); x-- }
            return s
        }
        return harmonic(b + 1) - harmonic(a)
    }

    private fun intervalFirstMoment(d: Map<String, Any?>, a: Double, b: Double): Double {
        if (b < a) return 0.0
        if (!logUniform(d)) return ((a + b) * (b - a + 1)) / 2
        return b - a + 1 - intervalWeight(d, a, b)
    }

    private fun intervalMeanX(d: Map<String, Any?>, a: Double, b: Double, cellLo: Double): Double {
        val whole = intervalWeight(d, cellLo, b)
        return if (whole > 0) intervalFirstMoment(d, a, b) / whole else 0.0
    }

    private fun intervalHarm(d: Map<String, Any?>, a: Double, b: Double, harm: HarmModel): Double {
        val dm = harm.dimMean(d, a, b)
        if (dm != null) return dm
        val n = b - a + 1
        val wTot = intervalWeight(d, a, b)
        if (!(wTot > 0)) return harm.dim(d, a)
        if (n <= EXACT_SPAN) {
            var s = 0.0
            var x = a
            while (x <= b) { s += pointWeight(d, x) * harm.dim(d, x); x++ }
            return s / wTot
        }
        var s = 0.0
        for (i in 0 until HARM_QUADRATURE_PIECES) {
            val pa = a + Math.floor((i * n) / HARM_QUADRATURE_PIECES)
            val pb = a + Math.floor(((i + 1) * n) / HARM_QUADRATURE_PIECES) - 1
            if (pb < pa) continue
            val w = intervalWeight(d, pa, pb)
            s += w * harm.dim(d, Math.floor((pa + pb) / 2 + 0.5))
        }
        return s / wTot
    }

    /** {mass, harm}: mu_d(cell) and E[g_d | cell] for one dimension cell. Categorical values are uniform. */
    fun dimCellStats(d: Map<String, Any?>, i: Int, harm: HarmModel): DoubleArray {
        if ("cat" == d["kind"]) return doubleArrayOf(1.0 / values(d).size, harm.dim(d, catRep(d, i)))
        val c = numCells(d)[i]
        val wm = intervalWeight(d, c[0], c[1])
        val total = intervalWeight(d, dlo(d), dhi(d))
        return doubleArrayOf(wm / total, if (wm > 0) intervalHarm(d, c[0], c[1], harm) else harm.dim(d, c[0]))
    }

    /** {mass, harm}: the exact mu(cell) and E[h | cell] of a whole cell (product measure, separable harm). */
    fun cellStats(vs: Map<String, Any?>, idx: IntArray, harm: HarmModel): DoubleArray {
        var mass = Js.num(vs["weight"])!!
        var h = harm.verb(vs)
        for (k in dims(vs).indices) {
            val s = dimCellStats(dim(vs, k), idx[k], harm)
            mass *= s[0]
            h *= s[1]
        }
        return doubleArrayOf(mass, h)
    }

    /** The label of a dimension path as a card shows it. */
    fun labelOf(path: String): String {
        if (path == "action.resource") return "resource"
        val last = path.substring(path.lastIndexOf('.') + 1)
        return last.replace('_', ' ')
    }
}
