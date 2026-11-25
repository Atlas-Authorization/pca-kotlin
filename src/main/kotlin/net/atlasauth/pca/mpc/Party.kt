package net.atlasauth.pca.mpc

import net.atlasauth.pca.verifier.Decide

/** Per-stakeholder local evaluation: each party distills its own Policy VM result to a small decision vector. */
object Party {
    const val DEFAULT_Q = 100

    /** The decision a party contributes to the MPC: allow in {0,1}, t in {1,2,3}, rQuant in {0..Q}. */
    class DecisionVector(val allow: Int, val t: Int, val rQuant: Int)

    /** Quantizes r in [0,1] to {0..Q}; non-finite is the worst case (Q). */
    @JvmStatic @JvmOverloads fun quantizeR(r: Double, q: Int = DEFAULT_Q): Int {
        if (r.isNaN() || r.isInfinite()) return q
        // Math.round (floor(x+0.5)) matches JS Math.round for the non-negative values reached here
        val v = Math.round(Math.max(0.0, Math.min(1.0, r)) * q)
        return Math.max(0L, Math.min(q.toLong(), v)).toInt()
    }

    /** Evaluates a party's own decide input through the Policy VM to its decision vector. */
    @JvmStatic @JvmOverloads fun evaluateParty(decideInput: Map<String, Any?>, q: Int = DEFAULT_Q): DecisionVector {
        val d = Decide.decide(decideInput)
        @Suppress("UNCHECKED_CAST") val thr = d["requiredThreshold"] as Map<String, Any?>
        val r = d["r"]
        return DecisionVector(
            if (d["releaseGuardianShare"] == true) 1 else 0,
            (thr["t"] as Number).toInt(),
            quantizeR(if (r is Number) r.toDouble() else Double.NaN, q),
        )
    }
}
