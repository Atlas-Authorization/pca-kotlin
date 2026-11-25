package net.atlasauth.pca.signals

/**
 * Subscriber-side revocation state. A resource server holds one and consults [Signals.isRevoked] on every request, next to
 * the core verifier. Every map stores the event_timestamp (seconds) of the revoking event; revocation is monotone: a key, once
 * present, is never removed.
 */
class RevocationState {
    /** grant_ref to event_timestamp of the revoking event. */
    @JvmField val revokedGrants: MutableMap<String, Double> = LinkedHashMap()

    /** agent id to event_timestamp of the kill-switch that revoked all of its grants. */
    @JvmField val killedAgents: MutableMap<String, Double> = LinkedHashMap()

    /** intent revocation id to event_timestamp of the intent-revoked event that named it; null until first used. */
    @JvmField var revokedIntentIds: MutableMap<String, Double>? = null

    private fun pairs(m: Map<String, Double>): List<Any?> = m.entries.map { listOf(it.key, JsV.numOf(it.value)) }

    /** The JSON form: {grants, agents, intents} as [key, timestamp] pairs (intents null while the map has never been used). */
    fun toMap(): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["grants"] = pairs(revokedGrants)
        m["agents"] = pairs(killedAgents)
        m["intents"] = revokedIntentIds?.let { pairs(it) }
        return m
    }

    companion object {
        internal fun recordMax(m: MutableMap<String, Double>, key: String, ts: Double) {
            val prev = m[key]
            if (prev == null || ts > prev) m[key] = ts
        }
    }
}
