package net.atlasauth.pca.intent

/** Bond sizing for optimistic claims: max(floor, curve(k, exposure)) on the micro grid, linear by default, optionally convex. */
object IntentBond {
    const val MICROS_PER_UNIT = 1000000.0
    private const val MAX_SAFE_MICROS = 1e15

    data class Tier(val upTo: Double, val marginalK: Double)

    /** The sizing and per-depositor cap policy; curveKind is null/linear, power (gamma) or piecewise (tiers). */
    class BondPolicy {
        @JvmField var floor: Double = 1.0
        @JvmField var k: Double = 1.0
        @JvmField var maxOpenClaims: Double = 100.0
        @JvmField var maxOpenAmount: Double = Double.POSITIVE_INFINITY
        @JvmField var curveKind: String? = null
        @JvmField var gamma: Double = Double.NaN
        @JvmField var tiers: List<Tier>? = null
        @JvmField var tiersIsArray: Boolean = true

        companion object {
            @JvmStatic
            fun fromJson(o: Any?): BondPolicy {
                val m = IntentOmega.obj(o)
                val p = BondPolicy()
                p.floor = num(m["floor"]); p.k = num(m["k"]); p.maxOpenClaims = num(m["maxOpenClaims"])
                p.maxOpenAmount = if (m["maxOpenAmount"] == null) Double.POSITIVE_INFINITY else num(m["maxOpenAmount"])
                if (m["curve"] != null) {
                    val c = IntentOmega.obj(m["curve"])
                    p.curveKind = c["kind"] as String?
                    if (c.containsKey("gamma")) p.gamma = num(c["gamma"])
                    if (c.containsKey("tiers")) {
                        if (c["tiers"] is List<*>) {
                            p.tiers = IntentOmega.arr(c["tiers"]).map { t -> Tier(num(IntentOmega.obj(t)["upTo"]), num(IntentOmega.obj(t)["marginalK"])) }
                        } else p.tiersIsArray = false
                    }
                }
                return p
            }
        }
    }

    private fun num(o: Any?): Double = if (o != null && IntentOmega.isNumber(o)) IntentOmega.dbl(o) else Double.NaN

    private fun fin(x: Double): Boolean = !x.isNaN() && !x.isInfinite()

    @JvmField val DEFAULT_BOND_POLICY = BondPolicy()

    /** Round an amount up onto the micro grid (a micro amount round-trips exactly; amounts too large for it are unchanged). */
    @JvmStatic
    fun quantizeUp(x: Double): Double {
        if (!fin(x) || x <= 0) return x
        val scaled = x * MICROS_PER_UNIT
        if (scaled > MAX_SAFE_MICROS) return x
        val r = IntentMapKit.jsRound(scaled)
        val m = if (r / MICROS_PER_UNIT == x || Math.abs(scaled - r) <= 1e-3) r else Math.ceil(scaled)
        return m / MICROS_PER_UNIT
    }

    /** e^gamma for a gamma that is a multiple of 1/8 up to 64, from multiplications and square roots only (see the settlement bond curve); any other gamma is refused. */
    private fun powEighths(e: Double, gamma: Double): Double {
        val n = gamma * 8
        require(n == Math.floor(n) && !n.isInfinite() && gamma <= 64) { "bondAmount: power curve gamma must be a multiple of 1/8 and at most 64" }
        var r = 1.0
        for (i in 0 until Math.floor(n / 8).toInt()) r *= e
        val f = (n % 8).toInt()
        val s1 = Math.sqrt(e)
        val s2 = Math.sqrt(s1)
        val s3 = Math.sqrt(s2)
        if (f and 4 != 0) r *= s1
        if (f and 2 != 0) r *= s2
        if (f and 1 != 0) r *= s3
        return r
    }

    private fun curveComponent(p: BondPolicy, e: Double): Double {
        val kind = p.curveKind
        if (kind == null || kind == "linear") return p.k * e
        if (kind == "power") {
            require(fin(p.gamma) && p.gamma >= 1) { "bondAmount: power curve requires finite gamma >= 1" }
            return p.k * powEighths(e, p.gamma)
        }
        val tiers = p.tiers
        require(p.tiersIsArray && tiers != null && tiers.isNotEmpty()) { "bondAmount: piecewise curve requires at least one tier" }
        var acc = 0.0
        var prevUpTo = 0.0
        var prevMarginal = 0.0
        for (t in tiers) {
            require(!(!(fin(t.upTo) && t.upTo > prevUpTo) && t.upTo != Double.POSITIVE_INFINITY)) { "bondAmount: piecewise tier `upTo` must be strictly increasing" }
            require(fin(t.marginalK) && t.marginalK >= 0) { "bondAmount: piecewise `marginalK` must be a finite number >= 0" }
            require(t.marginalK >= prevMarginal) { "bondAmount: piecewise marginal rates must be non-decreasing (convex)" }
            val width = Math.min(e, t.upTo) - prevUpTo
            if (width > 0) acc += width * t.marginalK
            prevUpTo = t.upTo
            prevMarginal = t.marginalK
            if (e <= t.upTo) break
        }
        if (e > prevUpTo) acc += (e - prevUpTo) * prevMarginal
        return p.k * acc
    }

    /** The bond for an exposure; a non-finite or non-positive exposure gives the floor. */
    @JvmStatic
    fun bondAmount(policy: BondPolicy, exposure: Double): Double {
        val e = if (fin(exposure) && exposure > 0) exposure else 0.0
        return quantizeUp(Math.max(policy.floor, curveComponent(policy, e)))
    }
}
