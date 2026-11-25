package net.atlasauth.pca.goal

/** Plain-text rendering of quantities, values and acts. An unknown currency is shown in raw minor units, never guessed. */
object GoalFmt {
    @JvmField
    val CCY_EXPONENT: Map<String, Int> = mapOf("USD" to 2, "EUR" to 2, "GBP" to 2, "CAD" to 2, "AUD" to 2, "CHF" to 2, "JPY" to 0, "KRW" to 0)

    private fun pad(s: String, n: Int): String {
        val b = StringBuilder()
        for (i in s.length until n) b.append('0')
        return b.append(s).toString()
    }

    /** [minor] is rendered as written (a JSON number lexeme or integer). */
    @JvmStatic
    fun fmtMoney(ccy: String, minor: Any?): String {
        val e = CCY_EXPONENT[ccy]
        val m = G.jsStr(minor)
        if (e == null) return "$ccy $m (minor units)"
        if (e == 0) return "$ccy $m"
        val s = pad(m, e + 1)
        return ccy + " " + s.substring(0, s.length - e) + "." + s.substring(s.length - e)
    }

    @JvmStatic
    fun fmtQuantity(q: Map<String, Any?>): String {
        val u = G.obj(q["u"], "unit")
        val n = q["n"]
        return when (G.kind(u)) {
            "money" -> fmtMoney(u["ccy"] as String, n)
            "count" -> G.jsStr(n)
            "duration" -> G.jsStr(n) + "ms"
            "instant" -> "@" + G.jsStr(n)
            "bytes" -> G.jsStr(n) + "B"
            "ratio" -> G.jsStr(n) + "ppm"
            else -> throw IrError("unknown unit")
        }
    }

    @JvmStatic
    fun fmtValue(v: Map<String, Any?>): String {
        val k = G.kind(v)
        if (k == "q") return fmtQuantity(G.m(v["q"])!!)
        if (k == "s") return G.q(v["s"] as String)
        val xs = ArrayList<String>()
        for (i in G.arr(v["items"], "items")) xs.add(fmtValue(G.m(i)!!))
        return "{" + xs.joinToString(", ") + "}"
    }

    @JvmStatic
    fun fmtAct(a: Map<String, Any?>): String {
        val params = G.m(a["params"])!!
        val ks = ArrayList(params.keys)
        ks.sort()
        val ps = ArrayList<String>()
        for (k in ks) ps.add(k + "=" + fmtValue(G.m(params[k])!!))
        return G.jsStr(a["verb"]) + " on " + G.jsStr(a["res"]) + (if (ps.isEmpty()) "" else " (" + ps.joinToString(", ") + ")")
    }
}
