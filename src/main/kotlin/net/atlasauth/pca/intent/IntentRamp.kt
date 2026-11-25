package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.Omega

/**
 * The trust ramp's pure parts: runtime signal labels, the narrow starting configuration, and the drift detector, a one-sided
 * Bernoulli CUSUM on divergences (negative signals about actions the grant admitted). S_t = max(0, S_{t-1} + log LR_t); an
 * alarm at S_t >= h is sticky until reset.
 */
object IntentRamp {
    /** y = 1 for jit-approve and principal-confirm; every other signal is y = 0 (a veto). */
    fun signalLabel(signal: String?): Int = if ("jit-approve" == signal || "principal-confirm" == signal) 1 else 0

    /** The narrow start: tau 1, eta 0, a high empty-set prior for every verb (very high for verbs the slots do not name). */
    fun narrowStart(omega: Omega, slots: Any?, slotNullMass: Double?, otherNullMass: Double?): MutableMap<String, Any?> {
        val nullMass = LinkedHashMap<String, Any?>()
        val verbs = if (slots is Map<*, *>) slots["verbs"] else null
        for (vs in omega.verbs) {
            val named = verbs is List<*> && verbs.any { vs.verb == it }
            nullMass[vs.verb] = if (named) slotNullMass ?: 0.5 else otherNullMass ?: 0.95
        }
        return linkedMapOf("eta" to 0.0, "tau" to 1.0, "nullMass" to nullMass)
    }

    /** The detector's state. */
    data class DriftState(val statistic: Double, val alarm: Boolean, val informative: Double, val divergences: Double) {
        fun toJson(): MutableMap<String, Any?> = linkedMapOf("statistic" to statistic, "alarm" to alarm, "informative" to informative, "divergences" to divergences)
    }

    /** Defaults: rho0 0.02, rho1 0.25, h ln(100); a null member takes its default. */
    class DriftDetector(rho0: Double?, rho1: Double?, h: Double?) {
        @JvmField val rho0: Double = rho0 ?: 0.02
        @JvmField val rho1: Double = rho1 ?: 0.25
        @JvmField val h: Double = h ?: net.atlasauth.pca.verifier.DetMath.detLn(100.0)
        private var s = DriftState(0.0, false, 0.0, 0.0)

        init {
            require(this.rho0 > 0 && this.rho0 < this.rho1 && this.rho1 < 1) { "DriftDetector: need 0 < rho0 < rho1 < 1" }
            require(this.h > 0) { "DriftDetector: h must be positive" }
        }

        /** Feed one signal about an action inside the grant: [diverged] = a negative signal. */
        fun update(diverged: Boolean): DriftState {
            val inc = if (diverged) net.atlasauth.pca.verifier.DetMath.detLn(rho1 / rho0) else net.atlasauth.pca.verifier.DetMath.detLn((1 - rho1) / (1 - rho0))
            val statistic = Math.max(0.0, s.statistic + inc)
            s = DriftState(statistic, s.alarm || statistic >= h, s.informative + 1, s.divergences + (if (diverged) 1 else 0))
            return s
        }

        fun state(): DriftState = s

        fun reset() {
            s = DriftState(0.0, false, 0.0, 0.0)
        }
    }
}
