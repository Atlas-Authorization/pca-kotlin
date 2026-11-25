package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentRamp.DriftDetector
import net.atlasauth.pca.intent.IntentRamp.DriftState

/**
 * Trust ramp: start narrow, widen only through confirmed behaviour, and every negative runtime signal vetoes its cell for good. A one-sided
 * Bernoulli CUSUM on divergences (negative signals about actions the grant admitted) freezes widening on alarm: positive signals are queued
 * until a rebase on a new signed statement; negative signals are always applied.
 */
class IntentTrustRamp(private var l: IntentLearner, rho0: Double?, rho1: Double?, h: Double?) {
    @JvmField val drift: DriftDetector = DriftDetector(rho0, rho1, h)
    private val queued = ArrayList<Pair<Outcome, String?>>()
    @JvmField val log: MutableList<RampRecord> = ArrayList()

    /** One recorded signal. */
    data class RampRecord(val signal: String?, val y: Int, val wasInGrant: Boolean, val before: Int, val after: Int, val applied: Boolean, val drift: DriftState) {
        fun toJson(): MutableMap<String, Any?> = linkedMapOf(
            "signal" to signal, "y" to y.toDouble(), "wasInGrant" to wasInGrant, "before" to before.toDouble(), "after" to after.toDouble(), "applied" to applied, "drift" to drift.toJson(),
        )
    }

    fun learner(): IntentLearner = l

    /** Widening is frozen while a drift alarm stands. */
    fun frozen(): Boolean = drift.state().alarm

    /** Positive signals held back by a freeze (released only by a rebase, which discards them). */
    fun pending(): List<Map<String, Any?>> = queued.map { q -> linkedMapOf("o" to IntentOmega.outcomeToJson(q.first), "signal" to q.second) }

    private fun grantSize(): Int {
        var n = 0
        for (c in l.cells()) if (c.inGrant) n++
        return n
    }

    fun record(o: Outcome, signal: String?): RampRecord {
        val y = IntentRamp.signalLabel(signal)
        val wasInGrant = l.admitsOutcome(o)
        val before = grantSize()
        var d = drift.state()
        if (wasInGrant) d = drift.update(y == 0)
        var applied = true
        if (y == 1 && frozen()) {
            queued.add(Pair(o, signal))
            applied = false
        } else l.observe(o, y, "runtime", null)
        val rec = RampRecord(signal, y, wasInGrant, before, grantSize(), applied, d)
        log.add(rec)
        return rec
    }

    /**
     * Record a SIGNED runtime observation: the signature must verify, the signer must be trusted, and the observation must be about this map
     * and a runtime one. Returns {ok: true, record} or {ok: false, reason}.
     */
    fun recordObservation(obs: Any?, mapDigest: String, trustedSigners: List<String>, expectedSigner: String?, pqPins: Map<String, Any?>?): Map<String, Any?> {
        val v = IntentObservation.verifyIntentObservation(obs, expectedSigner, pqPins)
        val r = LinkedHashMap<String, Any?>()
        if (v["ok"] != true) { r["ok"] = false; r["reason"] = v["reason"]; return r }
        val o = obs as Map<*, *>
        val signer = o["signer"]
        if (signer !is String || !trustedSigners.contains(signer)) { r["ok"] = false; r["reason"] = "untrusted observation signer"; return r }
        if (mapDigest != o["map_digest"]) { r["ok"] = false; r["reason"] = "observation is about a different map"; return r }
        if ("runtime" != o["source"]) { r["ok"] = false; r["reason"] = "only runtime observations feed the ramp"; return r }
        val vals = LinkedHashMap<String, Any?>()
        for ((k, x) in o["values"] as Map<*, *>) vals[k as String] = if (IntentOmega.isNumber(x)) IntentOmega.dbl(x) else x
        val yes = IntentOmega.dbl(o["y"]) == 1.0
        val rec = record(Outcome(o["verb"] as String, vals), if (yes) "principal-confirm" else "postcondition-violation")
        r["ok"] = true
        r["record"] = rec.toJson()
        return r
    }

    /** Re-base on a new learner (the only way to clear an alarm): the old vetoes are not carried over and queued positives are discarded. */
    fun rebase(next: IntentLearner) {
        l = next
        queued.clear()
        drift.reset()
    }
}
