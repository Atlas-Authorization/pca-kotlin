package net.atlasauth.pca.verifier

import net.atlasauth.pca.events.Events

/**
 * The standalone replay guard of a verifier: decide whether a (signature-verified) PCActn may be accepted ONCE. The decision order
 * follows the machine-checked replay model: every shape and window check before the first store call, the nonce consumed once, then
 * the optional counter stream advanced. Run it AFTER the PCActn verified (consuming a nonce for an unauthenticated action would let
 * anyone burn another party's nonces). Never throws: every failure, including a store failure, is a denial.
 */
object Replay {
    /** Upper bound (UTF-8 bytes) accepted for a grant ref / holder key / stream key component. */
    const val MAX_REPLAY_COMPONENT_LEN = 512

    /** How long a store must remember a consumed key: the longest lifetime plus skew on both sides. */
    const val REPLAY_MIN_RETENTION_MS = Pca.REPLAY_MIN_RETENTION_MS

    /** One-time-use store for opaque keys: atomic, durable until `retainUntilMs`, fail closed (throw rather than guess). */
    fun interface ReplayStore {
        /** True iff this call is the first to consume [key] (no live record). MUST remember it until [retainUntilMs]. */
        fun consumeOnce(key: String, retainUntilMs: Long, nowMs: Long): Boolean
    }

    /** Strictly-monotonic counter store, one stream per key. */
    fun interface CounterStore {
        /** True iff [counter] is greater than the stored value (and it is then stored). */
        fun advance(streamKey: String, counter: Long): Boolean
    }

    /** `ok`, else a deny [code] (`malformed`, `audience`, `not_yet_valid`, `expired`, `replay`, `store_unavailable`) and a [reason]. */
    class Verdict internal constructor(val ok: Boolean, val code: String? = null, val reason: String? = null)

    /** Options of [guardPCActnReplay]. */
    class GuardOptions @JvmOverloads constructor(
        /** The audience this verifier answers for; compared byte-exactly with the PCActn's `aud`. */
        val aud: String,
        /** Verifier clock, epoch ms. */
        val now: Long,
        /** Clock skew tolerated in both directions (default and ceiling: [Pca.MAX_SKEW_MS]). */
        val clockSkewMs: Double? = null,
        /** When true (default) a PCActn without a `nonce` is refused; when false it is guarded by the counter alone. */
        val requireNonce: Boolean = true,
        /** Per-(aud, grant, leaf holder) monotonic counter stream; when given the counter is advanced after the nonce. */
        val counters: CounterStore? = null,
    )

    private fun deny(code: String, reason: String) = Verdict(false, code, reason)

    private fun u8len(s: String): Int = Json.utf8(s).size

    private fun safeNonNegInt(o: Any?): Boolean = Json.isSafeInt(o) && Json.asLong(o) >= 0 && !(o is Double && o == 0.0 && 1.0 / o < 0)

    /** The guard. [p] is the PCActn map; it MUST already have passed full verification. */
    @Suppress("UNCHECKED_CAST")
    fun guardPCActnReplay(store: ReplayStore, p: Map<String, Any?>?, opts: GuardOptions): Verdict {
        val skew = Math.min(opts.clockSkewMs?.takeIf { !it.isNaN() && !it.isInfinite() && it >= 0 } ?: Pca.MAX_SKEW_MS.toDouble(), Pca.MAX_SKEW_MS.toDouble())
        val chain = p?.get("cap_chain") as? List<*>
        val leaf = chain?.lastOrNull() as? Map<String, Any?>
        val objectOk = p != null
        val grantRef = p?.get("grant_ref")
        val holder = leaf?.get("holder")
        val leafOk = leaf != null && holder is String && grantRef is String
        val componentsOk = leafOk && listOf(grantRef as String, holder as String).all { !(it.isEmpty() || Json.hasLoneSurrogate(it) || u8len(it) > MAX_REPLAY_COMPONENT_LEN) }
        val hasNonce = objectOk && p!!.containsKey("nonce")
        val nonce = p?.get("nonce")
        val nonceOk = hasNonce && nonce is String && nonce.isNotEmpty() && u8len(nonce) <= Pca.MAX_NONCE_LEN && !Json.hasLoneSurrogate(nonce)
        val nowOk = true // a Long clock is always an integer; the safe-range check below covers the JS number range
        val nowSafe = nowOk && Math.abs(opts.now) <= 9007199254740991L
        val verifierAudOk = opts.aud.isNotEmpty() && u8len(opts.aud) <= Pca.MAX_AUD_LEN && !Json.hasLoneSurrogate(opts.aud)
        val audMatches = objectOk && p!!["aud"] is String && p["aud"] == opts.aud
        val iatOk = objectOk && safeNonNegInt(p!!["iat"])
        val expOk = objectOk && safeNonNegInt(p!!["exp"])
        val iat = if (iatOk) Json.asLong(p!!["iat"]) else 0L
        val exp = if (expOk) Json.asLong(p!!["exp"]) else 0L
        val counterOk = objectOk && safeNonNegInt(p!!["counter"])
        val skewWhole = Math.floor(skew).toLong()
        val windowOk = iatOk && expOk && exp > iat && exp - iat <= Pca.MAX_LIFETIME_MS
        // Pre: everything before the first store call, in the normative order
        when {
            !nowSafe -> return deny("malformed", "verifier clock is not an integer epoch-ms")
            !verifierAudOk -> return deny("malformed", "verifier audience is invalid")
            !objectOk -> return deny("malformed", "not a PCActn")
            !audMatches -> return deny("audience", "the PCActn is for another audience")
            !windowOk -> return deny("malformed", "iat / exp are not a valid bounded window")
            iat > opts.now + skewWhole -> return deny("not_yet_valid", "iat is in the future beyond the clock-skew allowance")
            opts.now > exp -> return deny("expired", "the PCActn has expired")
            !leafOk -> return deny("malformed", "no leaf holder / grant")
            !componentsOk -> return deny("malformed", "grant / holder is not a bounded string")
            !counterOk -> return deny("malformed", "counter is not a non-negative safe integer")
        }
        // the store contract takes the horizon as a JS number: a sum past 2^53-1 would round, so refuse before any store call
        if (exp + Math.ceil(skew).toLong() > 9007199254740991L) return deny("malformed", "exp + clock skew exceeds the safe-integer range (retention horizon not representable)")
        val retainUntil = exp + Math.round(Math.ceil(skew))
        try {
            var consumed = true
            val stage = if (hasNonce) (if (nonceOk) "consume" else "deny") else if (opts.requireNonce) "deny" else "skip"
            if (stage == "deny") return deny("malformed", if (hasNonce) "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes" else "a nonce is required")
            if (stage == "consume") {
                consumed = store.consumeOnce(Events.replayKey("pca-nonce/v1", opts.aud, grantRef as String, holder as String, nonce as String), retainUntil, opts.now)
                if (!consumed) return deny("replay", "nonce already consumed")
            }
            val counters = opts.counters
            if (counters != null) {
                val advanced = counters.advance(Events.replayKey("pca-counter/v1", opts.aud, grantRef as String, holder as String), Json.asLong(p!!["counter"]))
                if (!advanced) return deny("replay", "counter is not greater than the last accepted")
            }
        } catch (e: RuntimeException) {
            return deny("store_unavailable", "replay store failed closed: " + (e.message ?: "error"))
        }
        return Verdict(true)
    }

    /**
     * Reference store: correct ONLY for a single verifier process whose lifetime covers the action lifetime (state is lost on restart
     * and is not shared between instances). When full of live entries, [consumeOnce] REJECTS (fail closed) rather than evict.
     */
    class InMemoryReplayStore @JvmOverloads constructor(private val maxEntries: Int = 100_000) : ReplayStore, CounterStore {
        private val seen = HashMap<String, Long>()
        private val streams = HashMap<String, Long>()

        /** Number of live (unpruned) entries. */
        @get:Synchronized val size: Int get() = seen.size

        /** Drop only entries whose retention has fully elapsed (`retainUntil < now`). Never frees a still-valid key. */
        @Synchronized
        fun prune(nowMs: Long): Int {
            val before = seen.size
            seen.values.removeIf { it < nowMs }
            return before - seen.size
        }

        @Synchronized
        override fun consumeOnce(key: String, retainUntilMs: Long, nowMs: Long): Boolean {
            if (key.isEmpty() || retainUntilMs < nowMs) throw IllegalArgumentException("consumeOnce: invalid key or retention horizon")
            val until = seen[key]
            if (until != null && until >= nowMs) return false
            if (until == null && seen.size >= maxEntries) {
                prune(nowMs)
                if (seen.size >= maxEntries) throw IllegalStateException("replay store full of live entries")
            }
            seen[key] = Math.max(retainUntilMs, until ?: 0L)
            return true
        }

        @Synchronized
        override fun advance(streamKey: String, counter: Long): Boolean {
            if (streamKey.isEmpty() || counter < 0 || counter > 9007199254740991L) throw IllegalArgumentException("advance: invalid stream or counter")
            val last = streams[streamKey]
            if (last != null && counter <= last) return false
            streams[streamKey] = counter
            return true
        }
    }
}
