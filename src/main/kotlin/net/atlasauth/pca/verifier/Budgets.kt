package net.atlasauth.pca.verifier

import java.util.TreeMap

/**
 * The scoped-admission and signed-release side of the aggregate [BudgetLedger]: scope keys, [admitAggregateAction], [startAggregate] /
 * [settleAggregate], and signed releases that can be anchored in a [LedgerStore].
 *
 * A release is a signed statement by the releaser (the verifier or sequencer) that a reservation's effect did NOT happen; a release
 * that never arrives only over-restricts (a crash costs budget, never safety).
 */
@Suppress("UNCHECKED_CAST")
object Budgets {
    const val RELEASE_DOMAIN = "atlas-pca/budget-release/v1\u0000"
    private val RELEASE_REASONS = listOf("effect_failed", "effect_not_run", "denied_downstream", "rollback")
    private const val MAX_SAFE = 9007199254740991L

    /** The ledger key of a scope (`principal`, `org`, `fleet`) and its id; injective (the id is percent-encoded). */
    @JvmStatic
    fun scopeKey(scope: String, id: String): String {
        if (!BudgetDoc.idOk(id)) throw BudgetLedgerError("invalid", "a scope id is a non-empty string of at most 256 characters without control characters")
        return scope + "/" + encodeURIComponent(id)
    }

    /** JavaScript encodeURIComponent. */
    internal fun encodeURIComponent(s: String): String {
        if (Json.hasLoneSurrogate(s)) throw IllegalArgumentException("URI malformed") // the JavaScript URIError
        val sb = StringBuilder()
        for (b in Json.utf8(s)) {
            val c = b.toInt() and 0xff
            if ((c >= 'A'.code && c <= 'Z'.code) || (c >= 'a'.code && c <= 'z'.code) || (c >= '0'.code && c <= '9'.code) || "-_.!~*'()".indexOf(c.toChar()) >= 0) sb.append(c.toChar())
            else sb.append('%').append("0123456789ABCDEF"[c shr 4]).append("0123456789ABCDEF"[c and 15])
        }
        return sb.toString()
    }

    // ---- signed, anchored releases ----

    private fun releaseMessage(r: Map<String, Any?>): ByteArray {
        val body = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "key", "id", "reason", "at", "signer")) body[k] = r[k]
        return Pca.concat(RELEASE_DOMAIN.toByteArray(Charsets.UTF_8), Pca.canonBytes(body))
    }

    /** Sign a release of [key]/[id]: reason is one of effect_failed, effect_not_run, denied_downstream, rollback. */
    @JvmStatic
    fun signRelease(key: String, id: String, reason: String, at: Long, secret: Keys.EdKey): Map<String, Any?> {
        require(reason in RELEASE_REASONS && at >= -MAX_SAFE && at <= MAX_SAFE && BudgetDoc.idOk(key) && BudgetDoc.idOk(id)) { "signRelease: a malformed release" }
        val base = LinkedHashMap<String, Any?>()
        base["v"] = StoreJs.num(1L)
        base["key"] = key
        base["id"] = id
        base["reason"] = reason
        base["at"] = StoreJs.num(at)
        base["signer"] = secret.id()
        base["sig"] = Keys.b64u(secret.sign(releaseMessage(base)))
        return base
    }

    /** True iff [ro] is well formed and signed by [expectedSigner] over exactly its content. Never throws. */
    @JvmStatic
    fun verifyRelease(ro: Any?, expectedSigner: String?): Boolean = try {
        val r = StoreJs.map(ro)
        if (r == null || !Json.isSafeInt(r["v"]) || Json.asLong(r["v"]) != 1L || r["signer"] != expectedSigner || (r["reason"] as? String) !in RELEASE_REASONS ||
            !Json.isSafeInt(r["at"]) || !BudgetDoc.idOk(r["key"]) || !BudgetDoc.idOk(r["id"]) || Pca.decodeB64uStrict(r["sig"], 64) == null
        ) false
        else Pca.verifyB64u(expectedSigner, releaseMessage(r), r["sig"] as String)
    } catch (e: RuntimeException) {
        false
    }

    @JvmStatic
    fun releaseDigest(r: Map<String, Any?>): String = Pca.hashCanonical(linkedMapOf("d" to "atlas-pca/budget-release-ref/v1", "r" to r))

    /** The log leaf of a release. */
    @JvmStatic
    fun releaseCommit(r: Map<String, Any?>): String = Pca.hashCanonical(linkedMapOf("d" to "atlas-pca/budget-release-leaf/v1", "digest" to releaseDigest(r)))

    /** Anchor a signed release in a transparency log store (retries on a position conflict). Returns the leaf index. */
    @JvmStatic
    fun anchorRelease(log: LedgerStore, r: Map<String, Any?>): Long {
        val commit = releaseCommit(r)
        for (i in 0 until 64) {
            val size = log.size()
            val o = log.append(size, listOf(commit))
            if (o.outcome == "appended" || o.outcome == "replayed") return size
        }
        throw BudgetLedgerError("conflict_exhausted", "could not anchor the release: the log kept moving")
    }

    // ---- scoped admission ----

    /** One reservation made by an admission. */
    class Reservation(val key: String, val id: String)

    /** The outcome of [admitAggregateAction]. */
    class Admission {
        var admitted: Boolean = false
        var reason: String? = null

        /** The host verifier's verdict (a map with at least `allow`); may be null on a refusal. */
        var verdict: Map<String, Any?>? = null
        var reservations: List<Reservation>? = null
        var state: Map<String, Any?>? = null
    }

    /** The ledger key of an accumulator for this admission, or null when it is session-scoped. Throws `scope_unbound`. */
    @JvmStatic
    fun aggregateKeyOf(a: Map<String, Any?>, ids: Map<String, String>): String? {
        val scope = a["scope"]
        if (scope == null || scope == "session") return null
        val id = ids[scope as String] ?: throw BudgetLedgerError("scope_unbound", "accumulator ${a["id"]} is $scope-scoped but no $scope id was given")
        return scopeKey(scope, id)
    }

    private fun isScoped(a: Map<String, Any?>): Boolean = a["scope"] != null && a["scope"] != "session"

    /**
     * Admit one action against every non-session accumulator, atomically per key: read each key's snapshot and compute the pre-states, call
     * [verify], and on allow `reserve` in every key with `expectedVersion` = the snapshot's. A moved key repeats from the top (optimistic
     * concurrency); a key over its cap denies and releases what the earlier keys reserved. Throws `not_durable` for a ledger that is not
     * durable, always.
     */
    @JvmStatic
    @JvmOverloads
    fun admitAggregateAction(
        ledger: BudgetLedger?, ids: Map<String, String>, accumulators: List<Map<String, Any?>>, schema: Any?, event: Map<String, Any?>,
        verify: (Map<String, Any?>) -> Map<String, Any?>, expiresAt: Long? = null, maxAttempts: Int? = null,
    ): Admission {
        val scoped = accumulators.filter { isScoped(it) }
        if (scoped.isNotEmpty() && (ledger == null || !ledger.durable())) throw BudgetLedgerError("not_durable", "a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)")
        val byKey = TreeMap<String, MutableList<Map<String, Any?>>>()
        try {
            for (a in scoped) byKey.getOrPut(aggregateKeyOf(a, ids)!!) { ArrayList() }.add(a)
        } catch (e: BudgetLedgerError) {
            if (e.code == "scope_unbound") {
                val r = Admission()
                r.admitted = false
                r.reason = "scope_unbound: " + e.message
                return r
            }
            throw e
        }
        val keys = ArrayList(byKey.keys)
        val attempts = maxAttempts ?: 256
        for (attempt in 0 until attempts) {
            val snaps = LinkedHashMap<String, BudgetLedger.Snapshot>()
            val state = LinkedHashMap<String, Any?>()
            for (k in keys) {
                val s = ledger!!.snapshot(k)
                snaps[k] = s
                for (a in byKey[k]!!) {
                    val holder = StoreJs.map(a["holder"])
                    if (holder == null || holder["kind"] != "site_local") continue
                    val params = StoreJs.map(event["params"]) ?: LinkedHashMap()
                    if (a["key"] != null && IntentHistory.accKeyOf(a, params) == null) continue // the verifier fails the claim (missing key)
                    state[a["id"] as String] = IntentHistory.accPreState(a, s.events, params, event["t"], schema)
                }
            }
            val verdict = verify(state)
            if (verdict["allow"] != true) {
                val r = Admission()
                r.admitted = false
                r.reason = "verifier denied"
                r.verdict = verdict
                return r
            }
            val done = ArrayList<Reservation>()
            var moved = false
            for (k in keys) {
                val req = BudgetLedger.ReserveRequest()
                req.event = event
                req.accumulators = byKey[k]
                req.schema = schema
                req.expectedVersion = snaps[k]!!.version
                req.expiresAt = expiresAt
                val r = ledger!!.reserve(k, req)
                if (r.outcome == "reserved" || (r.outcome == "replayed" && r.status == "reserved")) {
                    done.add(Reservation(k, event["id"] as String))
                    continue
                }
                for (d in done) ledger.release(d.key, d.id, null)
                if (r.outcome == "conflict") {
                    moved = true
                    break
                }
                val why = if (r.outcome == "over_cap") "over_cap: ${r.acc} would reach ${r.postValue} (cap ${AttestUtil.jsNumString(r.cap!!)})"
                else if (r.outcome == "replayed") "already ${r.status}" else r.outcome
                val out = Admission()
                out.admitted = false
                out.reason = "aggregate: $why"
                out.verdict = verdict
                return out
            }
            if (!moved) {
                val out = Admission()
                out.admitted = true
                out.verdict = verdict
                out.reservations = done
                out.state = state
                return out
            }
        }
        throw BudgetLedgerError("conflict_exhausted", "the aggregate kept moving under this admission")
    }

    /**
     * BEFORE the effect: mark every reservation started (non-expirable). Returns false when any is refused (released or expired in the
     * meantime): the effect must NOT run then.
     */
    @JvmStatic
    fun startAggregate(ledger: BudgetLedger, reservations: List<Reservation>): Boolean {
        for (r in reservations) {
            val o = ledger.start(r.key, r.id)
            if (o.outcome != "settled" && o.outcome != "replayed") return false
        }
        return true
    }

    /** After the effect: `committed` (it happened) or `released` (it did not; a signed [evidence] is stored and can be anchored). */
    @JvmStatic
    @JvmOverloads
    fun settleAggregate(ledger: BudgetLedger, reservations: List<Reservation>, status: String, evidence: ((Reservation) -> Map<String, Any?>)? = null): List<BudgetLedger.SettleOutcome> =
        reservations.map { r -> if (status == "committed") ledger.commit(r.key, r.id) else ledger.release(r.key, r.id, evidence?.invoke(r)) }
}
