package net.atlasauth.pca.mpc

import net.atlasauth.pca.mpc.Party.DecisionVector

/**
 * Composition semantics (the "meet" of stakeholder authorities) and the cleartext reference: allow = AND, t = MAX, rQuant = MAX.
 * Composition can only tighten, never loosen.
 */
object Compose {
    class ComposedDecision(val allow: Int, val t: Int, val rQuant: Int)

    /** Rejects a malformed decision vector (allow in {0,1}, t in {1,2,3}, integer rQuant in [0,Q]). */
    @JvmStatic fun assertDecisionVectors(vectors: List<DecisionVector>?, q: Int) {
        requireNotNull(vectors) { "decision vectors must be an array" }
        for (i in vectors.indices) {
            val v = vectors[i]
            require(v.allow == 0 || v.allow == 1) { "party $i: allow must be 0 or 1" }
            require(v.t in 1..3) { "party $i: t must be 1, 2 or 3" }
            require(v.rQuant in 0..q) { "party $i: rQuant must be an integer in [0, $q]" }
        }
    }

    @JvmStatic @JvmOverloads fun composeClear(vectors: List<DecisionVector>, q: Int = Party.DEFAULT_Q): ComposedDecision {
        require(vectors.isNotEmpty()) { "composeClear: no parties (fail closed)" }
        assertDecisionVectors(vectors, q)
        var allow = 1
        var t = 1
        var r = 0
        for (v in vectors) {
            if (v.allow == 0) allow = 0
            if (v.t > t) t = v.t
            if (v.rQuant > r) r = v.rQuant
        }
        return ComposedDecision(allow, t, r)
    }
}
