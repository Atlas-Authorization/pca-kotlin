package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.Outcome

/**
 * Provenance on the wallet side and within-grant regret: the fixed banner for a tainted value, the provenance friction floor, and the regret of a
 * choice the grant admits (utility is the principal's, supplied by the caller).
 */
object IntentProvenance {
    private val FRICTION_ORDER = listOf("tap", "hold", "typed", "device")

    /** The fixed banner for a tainted value (web / agent / tool); null for trusted and first-party values. */
    @JvmStatic
    fun provenanceBanner(level: String?, what: String?): String? {
        val w = what ?: "value"
        return when (level) {
            "web" -> "This $w was suggested by content on the page, not by you."
            "agent" -> "This $w came from your agent, not from you or the site."
            "tool" -> "This $w came from another service, not from you or this site."
            else -> null
        }
    }

    /** True for the tainted levels (tool, web, agent). */
    @JvmStatic
    fun isTainted(level: String?): Boolean = level == "tool" || level == "web" || level == "agent"

    /** The friction a value needs: the maximum of [base] and the provenance floor (tainted critical: typed; tainted material: hold; else tap). */
    @JvmStatic
    fun provenanceFriction(base: String?, sensitivity: String?, level: String?): String {
        val floor = if (!isTainted(level)) "tap" else if ("critical" == sensitivity) "typed" else "hold"
        return FRICTION_ORDER[Math.max(FRICTION_ORDER.indexOf(base), FRICTION_ORDER.indexOf(floor))]
    }

    /** One choice: the options feasible at the time, the chosen one, membership in the effective grant and the principal's utility. */
    class RegretCase(val feasible: List<Outcome>, val chosen: Outcome, val admits: (Outcome) -> Boolean, val utility: (Outcome) -> Double)

    /** Within-grant regret of one choice: {regret, best, admitted}. Only options inside the grant compete. */
    @JvmStatic
    fun withinGrantRegret(c: RegretCase): Map<String, Any?> {
        val admitted = c.admits(c.chosen)
        var best: Outcome? = null
        var bestU = Double.NEGATIVE_INFINITY
        for (o in c.feasible) {
            if (!c.admits(o)) continue
            val u = c.utility(o)
            if (u > bestU) { bestU = u; best = o }
        }
        val r = LinkedHashMap<String, Any?>()
        r["regret"] = if (!admitted || best == null) 0.0 else Math.max(0.0, bestU - c.utility(c.chosen))
        r["best"] = if (best == null) null else IntentOmega.outcomeToJson(best)
        r["admitted"] = admitted
        return r
    }

    /** Aggregate regret over choices: {cases, admitted, positive, mean, max, regret_est_ppm} (ppm of the utility scale [scale]). */
    @JvmStatic
    fun regretReport(cases: List<RegretCase>, scale: Double): Map<String, Any?> {
        var admitted = 0
        var positive = 0
        var sum = 0.0
        var max = 0.0
        for (c in cases) {
            val r = withinGrantRegret(c)
            if (r["admitted"] != true) continue
            admitted++
            val reg = r["regret"] as Double
            sum += reg
            if (reg > 0) positive++
            if (reg > max) max = reg
        }
        val mean = if (admitted > 0) sum / admitted else 0.0
        val o = LinkedHashMap<String, Any?>()
        o["cases"] = cases.size.toDouble()
        o["admitted"] = admitted.toDouble()
        o["positive"] = positive.toDouble()
        o["mean"] = mean
        o["max"] = max
        o["regret_est_ppm"] = IntentMapKit.jsRound((mean / (if (scale > 0) scale else 1.0)) * 1_000_000)
        return o
    }
}
