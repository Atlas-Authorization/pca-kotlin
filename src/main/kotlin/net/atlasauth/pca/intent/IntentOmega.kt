package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.Json

/**
 * The outcome space (a typed, finite cell grid per verb): numeric dimensions partitioned by cuts, categorical dimensions
 * with an OTHER cell; the product workload measure and the separable harm model. Numbers are binary64 throughout so every
 * figure matches the reference bit for bit (logarithms and exponentials from StrictMath, the fdlibm functions).
 */
@Suppress("UNCHECKED_CAST")
object IntentOmega {
    /** The categorical "any other value" sentinel. */
    const val OTHER = "⊥"
    const val EXACT_SPAN = 4096
    const val HARM_QUADRATURE_PIECES = 1024
    private const val EULER_GAMMA = 0.5772156649015329

    data class CatValue(val kind: String, val value: String)

    data class NumCell(val lo: Double, val hi: Double)

    /** A dimension of a verb space: numeric (`kind == "num"`) or categorical (`"cat"`). */
    abstract class Dim internal constructor(@JvmField val kind: String, @JvmField val path: String)

    class NumDim(path: String, @JvmField val lo: Double, @JvmField val hi: Double, @JvmField val cuts: DoubleArray, @JvmField val dist: String) : Dim("num", path) {
        internal var cells: List<NumCell>? = null
        internal var total: Double? = null
    }

    class CatDim(path: String, @JvmField val values: List<CatValue>) : Dim("cat", path)

    class VerbSpace(@JvmField val verb: String, @JvmField val reversibility: String, @JvmField var weight: Double, @JvmField val dims: List<Dim>)

    class Omega(@JvmField val verbs: List<VerbSpace>, @JvmField val approximate: List<String>)

    /** A concrete outcome: the verb and one value (Double or String) per dimension path. */
    data class Outcome(val verb: String, val values: Map<String, Any?>)

    interface HarmModel {
        fun verb(vs: VerbSpace): Double
        fun dim(d: Dim, x: Any?): Double
        /** Optional closed form of the mean of [dim] over an integer interval; null when absent. */
        fun dimMean(d: NumDim, lo: Double, hi: Double): Double? = null
    }

    // ---- JSON <-> typed ----

    @JvmStatic
    fun dbl(o: Any?): Double = when (o) {
        is Json.Num -> o.raw.toDouble()
        is Number -> o.toDouble()
        else -> throw IllegalArgumentException("not a number")
    }

    @JvmStatic
    fun obj(o: Any?): Map<String, Any?> {
        require(o is Map<*, *>) { "not an object" }
        return o as Map<String, Any?>
    }

    @JvmStatic
    fun arr(o: Any?): List<Any?> {
        require(o is List<*>) { "not an array" }
        return o as List<Any?>
    }

    @JvmStatic
    fun isNumber(o: Any?): Boolean = o is Json.Num || o is Number

    fun dimFromJson(o: Any?): Dim {
        val m = obj(o)
        val path = m["path"] as String
        if ("num" == m["kind"]) {
            val cs = arr(m["cuts"])
            val cuts = DoubleArray(cs.size) { dbl(cs[it]) }
            return NumDim(path, dbl(m["lo"]), dbl(m["hi"]), cuts, m["dist"] as String)
        }
        val vs = arr(m["values"]).map { x -> CatValue(obj(x)["kind"] as String, obj(x)["value"] as String) }
        return CatDim(path, vs)
    }

    fun dimToJson(d: Dim): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["kind"] = d.kind
        m["path"] = d.path
        if (d is NumDim) {
            m["lo"] = d.lo
            m["hi"] = d.hi
            m["cuts"] = d.cuts.toMutableList()
            m["dist"] = d.dist
        } else {
            m["values"] = (d as CatDim).values.map { catValueJson(it) }.toMutableList()
        }
        return m
    }

    internal fun catValueJson(v: CatValue): MutableMap<String, Any?> = linkedMapOf("kind" to v.kind, "value" to v.value)

    fun verbSpaceFromJson(o: Any?): VerbSpace {
        val m = obj(o)
        val dims = arr(m["dims"]).map { dimFromJson(it) }.toMutableList()
        return VerbSpace(m["verb"] as String, m["reversibility"] as String, dbl(m["weight"]), dims)
    }

    fun verbSpaceToJson(vs: VerbSpace): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["verb"] = vs.verb
        m["reversibility"] = vs.reversibility
        m["weight"] = vs.weight
        m["dims"] = vs.dims.map { dimToJson(it) }.toMutableList()
        return m
    }

    fun omegaFromJson(o: Any?): Omega {
        val m = obj(o)
        val vs = arr(m["verbs"]).map { verbSpaceFromJson(it) }.toMutableList()
        val ap = ArrayList<String>()
        if (m["approximate"] is List<*>) for (a in arr(m["approximate"])) ap.add(a as String)
        return Omega(vs, ap)
    }

    fun omegaToJson(om: Omega): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["v"] = 1.0
        m["verbs"] = om.verbs.map { verbSpaceToJson(it) }.toMutableList()
        m["approximate"] = ArrayList<Any?>(om.approximate)
        return m
    }

    fun outcomeFromJson(o: Any?): Outcome {
        val m = obj(o)
        val vals = LinkedHashMap<String, Any?>()
        for ((k, v) in obj(m["values"])) vals[k] = if (isNumber(v)) dbl(v) else v
        return Outcome(m["verb"] as String, vals)
    }

    fun outcomeToJson(o: Outcome): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["verb"] = o.verb
        m["values"] = LinkedHashMap(o.values)
        return m
    }

    // ---- cells ----

    fun numCells(d: NumDim): List<NumCell> {
        d.cells?.let { return it }
        val out = ArrayList<NumCell>()
        var cur = d.lo
        for (c in d.cuts) {
            if (c < d.lo || c > d.hi) continue
            if (cur <= c - 1) out.add(NumCell(cur, c - 1))
            out.add(NumCell(c, c))
            cur = c + 1
        }
        if (cur <= d.hi) out.add(NumCell(cur, d.hi))
        d.cells = out
        return out
    }

    fun cellCount(d: Dim): Int = if (d is NumDim) numCells(d).size else (d as CatDim).values.size

    fun verbCellCount(vs: VerbSpace): Double {
        var n = 1.0
        for (d in vs.dims) n *= cellCount(d)
        return n
    }

    fun decodeCell(vs: VerbSpace, flat0: Double): IntArray {
        var flat = flat0
        val idx = IntArray(vs.dims.size)
        for (i in vs.dims.size - 1 downTo 0) {
            val n = cellCount(vs.dims[i])
            idx[i] = (flat % n).toInt()
            flat = Math.floor(flat / n)
        }
        return idx
    }

    fun encodeCell(vs: VerbSpace, idx: IntArray): Double {
        var flat = 0.0
        for (i in vs.dims.indices) flat = flat * cellCount(vs.dims[i]) + idx[i]
        return flat
    }

    /** Which cell a concrete string falls in (exact, then longest prefix, then OTHER). */
    fun catCellOf(d: CatDim, s: String): Int {
        var best = -1
        var bestLen = -1
        for (i in d.values.indices) {
            val v = d.values[i]
            if (v.kind == "exact" && v.value == s) return i
            if (v.kind == "prefix" && s.startsWith(v.value) && v.value.length > bestLen) {
                best = i
                bestLen = v.value.length
            }
        }
        if (best >= 0) return best
        for (i in d.values.indices) if (d.values[i].kind == "other") return i
        return -1
    }

    /** The cell a value falls in, or -1 outside the dimension's domain or type. */
    fun cellOfValue(d: Dim, x: Any?): Int {
        if (d is NumDim) {
            if (x !is Double || x.isNaN() || x.isInfinite()) return -1
            val cells = numCells(d)
            for (i in cells.indices) if (x >= cells[i].lo && x <= cells[i].hi) return i
            return -1
        }
        if (x !is String) return -1
        return catCellOf(d as CatDim, x)
    }

    /** Per-dimension cell indices of an outcome, or null when a value lies outside the space. */
    fun cellOf(vs: VerbSpace, o: Outcome): IntArray? {
        val idx = IntArray(vs.dims.size)
        for (k in idx.indices) {
            val d = vs.dims[k]
            val i = cellOfValue(d, o.values[d.path])
            if (i < 0) return null
            idx[k] = i
        }
        return idx
    }

    fun catRep(d: CatDim, i: Int): String {
        val v = d.values[i]
        if (v.kind == "exact") return v.value
        val base = if (v.kind == "prefix") v.value + "x" else "other"
        for (k in 0 until 64) {
            val s = base + (if (k == 0) "" else k.toString())
            if (catCellOf(d, s) == i) return s
        }
        return base
    }

    /** The question point of a numeric cell (a boundary witness). */
    fun numRep(d: NumDim, i: Int): Double {
        val c = numCells(d)[i]
        return if (i > 0) c.lo else c.hi
    }

    fun repValue(d: Dim, i: Int): Any = if (d is NumDim) numRep(d, i) else catRep(d as CatDim, i)

    fun cellRep(vs: VerbSpace, idx: IntArray): Outcome {
        val values = LinkedHashMap<String, Any?>()
        for (i in vs.dims.indices) values[vs.dims[i].path] = repValue(vs.dims[i], idx[i])
        return Outcome(vs.verb, values)
    }

    // ---- workload and harm ----

    private fun logUniform(d: NumDim): Boolean = d.dist == "loguniform" && d.lo >= 0

    internal fun pointWeight(d: NumDim, x: Double): Double = if (logUniform(d)) 1 / (x + 1) else 1.0

    private val AMOUNT = Regex("(^|\\.)amount$")

    private fun linearAmount(d: Dim): Boolean = d is NumDim && AMOUNT.containsMatchIn(d.path)

    /** Irreversible 10, rate-limited 3, reversible 1; amounts scale as 1 + x/100. */
    @JvmField
    val DEFAULT_HARM: HarmModel = object : HarmModel {
        override fun verb(vs: VerbSpace): Double = if (vs.reversibility == "irreversible") 10.0 else if (vs.reversibility == "rate_limited") 3.0 else 1.0
        override fun dim(d: Dim, x: Any?): Double = if (linearAmount(d) && x is Double) 1 + Math.max(0.0, x) / 100 else 1.0
        override fun dimMean(d: NumDim, lo: Double, hi: Double): Double? =
            if (linearAmount(d)) 1 + Math.max(0.0, intervalMeanX(d, Math.max(lo, 0.0), hi, lo)) / 100 else 1.0
    }

    @JvmOverloads
    fun harmMax(omega: Omega, harm: HarmModel = DEFAULT_HARM): Double {
        var m = 0.0
        for (vs in omega.verbs) {
            var f = harm.verb(vs)
            for (d in vs.dims) {
                if (d is NumDim) f *= Math.max(harm.dim(d, d.lo), harm.dim(d, d.hi))
                else {
                    val c = d as CatDim
                    var mx = Double.NEGATIVE_INFINITY
                    for (i in c.values.indices) mx = Math.max(mx, harm.dim(d, catRep(c, i)))
                    f *= mx
                }
            }
            m = Math.max(m, f)
        }
        return m
    }

    private fun harmonic(n: Double): Double {
        if (n <= 0) return 0.0
        if (n <= EXACT_SPAN) {
            var s = 0.0
            var k = n
            while (k >= 1) {
                s += 1 / k
                k--
            }
            return s
        }
        val n2 = n * n
        return StrictMath.log(n) + EULER_GAMMA + 1 / (2 * n) - 1 / (12 * n2) + 1 / (120 * n2 * n2) - 1 / (252 * n2 * n2 * n2)
    }

    /** The sum of the point weight over the integers a..b (0 for an empty interval). */
    fun intervalWeight(d: NumDim, a: Double, b: Double): Double {
        if (b < a) return 0.0
        if (!logUniform(d)) return b - a + 1
        if (b - a + 1 <= EXACT_SPAN) {
            var s = 0.0
            var x = b
            while (x >= a) {
                s += 1 / (x + 1)
                x--
            }
            return s
        }
        return harmonic(b + 1) - harmonic(a)
    }

    private fun intervalFirstMoment(d: NumDim, a: Double, b: Double): Double {
        if (b < a) return 0.0
        if (!logUniform(d)) return ((a + b) * (b - a + 1)) / 2
        return b - a + 1 - intervalWeight(d, a, b)
    }

    private fun intervalMeanX(d: NumDim, a: Double, b: Double, cellLo: Double): Double {
        val whole = intervalWeight(d, cellLo, b)
        return if (whole > 0) intervalFirstMoment(d, a, b) / whole else 0.0
    }

    private fun intervalHarm(d: NumDim, a: Double, b: Double, harm: HarmModel): Double {
        val mean = harm.dimMean(d, a, b)
        if (mean != null) return mean
        val n = b - a + 1
        val wTot = intervalWeight(d, a, b)
        if (!(wTot > 0)) return harm.dim(d, a)
        if (n <= EXACT_SPAN) {
            var s = 0.0
            var x = a
            while (x <= b) {
                s += pointWeight(d, x) * harm.dim(d, x)
                x++
            }
            return s / wTot
        }
        var s = 0.0
        for (i in 0 until HARM_QUADRATURE_PIECES) {
            val pa = a + Math.floor((i * n) / HARM_QUADRATURE_PIECES)
            val pb = a + Math.floor(((i + 1) * n) / HARM_QUADRATURE_PIECES) - 1
            if (pb < pa) continue
            val w = intervalWeight(d, pa, pb)
            s += w * harm.dim(d, Math.round((pa + pb) / 2).toDouble())
        }
        return s / wTot
    }

    private fun dimTotal(d: NumDim): Double {
        val t = d.total ?: intervalWeight(d, d.lo, d.hi)
        d.total = t
        return t
    }

    data class Stats(val mass: Double, val harm: Double)

    @JvmOverloads
    fun dimCellStats(d: Dim, i: Int, harm: HarmModel = DEFAULT_HARM): Stats {
        if (d is CatDim) return Stats(1.0 / d.values.size, harm.dim(d, catRep(d, i)))
        val n = d as NumDim
        val c = numCells(n)[i]
        val wm = intervalWeight(n, c.lo, c.hi)
        return Stats(wm / dimTotal(n), if (wm > 0) intervalHarm(n, c.lo, c.hi, harm) else harm.dim(n, c.lo))
    }

    private fun quantileValue(d: NumDim, target: Double): Double {
        var acc = 0.0
        val cells = numCells(d)
        for (c in cells) {
            val w = intervalWeight(d, c.lo, c.hi)
            if (target < acc + w || c === cells[cells.size - 1]) {
                var r = target - acc
                if (c.hi - c.lo + 1 <= EXACT_SPAN) {
                    var x = c.lo
                    while (x < c.hi) {
                        r -= pointWeight(d, x)
                        if (r < 0) return x
                        x++
                    }
                    return c.hi
                }
                if (!logUniform(d)) return Math.min(c.hi, c.lo + Math.floor(r))
                val x = Math.floor((c.lo + 1) * StrictMath.exp(r) - 1)
                return Math.max(c.lo, Math.min(c.hi, x))
            }
            acc += w
        }
        return d.hi
    }

    @JvmOverloads
    fun cellStats(vs: VerbSpace, idx: IntArray, harm: HarmModel = DEFAULT_HARM): Stats {
        var mass = vs.weight
        var h = harm.verb(vs)
        for (k in vs.dims.indices) {
            val s = dimCellStats(vs.dims[k], idx[k], harm)
            mass *= s.mass
            h *= s.harm
        }
        return Stats(mass, h)
    }

    @JvmOverloads
    fun harmOf(vs: VerbSpace, o: Outcome, harm: HarmModel = DEFAULT_HARM): Double {
        var h = harm.verb(vs)
        for (d in vs.dims) h *= harm.dim(d, o.values[d.path])
        return h
    }

    /** mulberry32, so every Monte Carlo number is reproducible. */
    fun rng(seed: Double): () -> Double {
        var a = seed.toLong().toInt()
        return {
            a += 0x6d2b79f5
            var t = a
            t = (t xor (t ushr 15)) * (t or 1)
            t = t xor (t + (t xor (t ushr 7)) * (t or 61))
            ((t xor (t ushr 14)).toLong() and 0xFFFFFFFFL) / 4294967296.0
        }
    }

    data class Sample(val vs: VerbSpace, val o: Outcome)

    /** Draw an outcome from the workload. */
    fun sampleOutcome(omega: Omega, rand: () -> Double): Sample {
        var u = rand()
        var vs = omega.verbs[omega.verbs.size - 1]
        for (v in omega.verbs) {
            if (u < v.weight) {
                vs = v
                break
            }
            u -= v.weight
        }
        val values = LinkedHashMap<String, Any?>()
        for (d in vs.dims) {
            if (d is CatDim) {
                values[d.path] = catRep(d, Math.min(d.values.size - 1, Math.floor(rand() * d.values.size).toInt()))
                continue
            }
            val n = d as NumDim
            values[d.path] = quantileValue(n, rand() * dimTotal(n))
        }
        return Sample(vs, Outcome(vs.verb, values))
    }

    fun verbSpace(omega: Omega, verb: String?): VerbSpace? = omega.verbs.firstOrNull { it.verb == verb }

    internal fun sortedNums(xs: Collection<Double>): MutableList<Double> = xs.sortedWith { a, b -> java.lang.Double.compare(a, b) }.toMutableList()

    internal fun toArray(l: List<Double>): DoubleArray = DoubleArray(l.size) { l[it] }
}
