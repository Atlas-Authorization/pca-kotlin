package net.atlasauth.pca.ciba

import java.io.File
import java.security.SecureRandom
import net.atlasauth.pca.durable.OwnerOnly
import net.atlasauth.pca.gnap.GnapJs as Js
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * The durable approval broker: the production-shaped counterpart of the in-memory broker. State lives behind an [ApprovalStore]
 * (compare-and-set), so a restart or a second process cannot lose, double-apply or replay a human decision. Sessions are JSON objects
 * with the reference's member names (`auth_req_id, request, status, createdAt, expiresAt, decidedBy, decidedAt`).
 */
@Suppress("UNCHECKED_CAST")
object CibaApproval {
    private val RNG = SecureRandom()
    internal const val MAX_CAS_TRIES = 8

    /** A versioned value; version 0 means absent and every successful write bumps it. */
    class Versioned(val version: Long, val value: Any?)

    /**
     * Persistence seam: a JSON key-value store with compare-and-set. `cas` writes `value` only if the stored version equals
     * `expectedVersion` (0 = the key must be absent) and returns whether it wrote. Any failure must throw.
     */
    interface ApprovalStore {
        /** The stored record, or null when the key is absent. */
        fun get(key: String): Versioned?
        fun cas(key: String, expectedVersion: Long, value: Any?): Boolean
    }

    /** The synchronous broker contract: start, poll, token (POLL-mode token endpoint semantics), resolve and read a session. */
    interface ApprovalBroker {
        fun start(stepUp: Map<String, Any?>, opts: Map<String, Any?>?): Map<String, Any?>
        fun poll(authReqId: String): Map<String, Any?>
        fun token(authReqId: String): Map<String, Any?>
        fun resolve(authReqId: String, decision: String, by: String?): Map<String, Any?>
        /** The session snapshot, or null when unknown. */
        fun get(authReqId: String): Map<String, Any?>?
    }

    /** Options of [createDurableCibaBroker]. `authReqIdSource` defaults to 160 random bits, base64url (a test hook). */
    class DurableBrokerOptions {
        var store: ApprovalStore? = null
        var now: () -> Long = { System.currentTimeMillis() }
        /** How long an approval stays redeemable after the human decided, in seconds. Default 300. */
        var decisionTtlSec: Double? = null
        /** Called after a decision is durably recorded (PING/PUSH). A throw does not undo the decision. */
        var onComplete: ((Map<String, Any?>) -> Unit)? = null
        var authReqIdSource: () -> String = { randomAuthReqId() }
    }

    internal fun randomAuthReqId(): String = Keys.b64u(ByteArray(20).also { RNG.nextBytes(it) })

    private fun map(o: Any?) = o as MutableMap<String, Any?>

    /**
     * Publish `bytes` as `target`: an owner-only temp file next to it (owner-only at creation, POSIX mode or Windows ACL), flushed to disk,
     * then an atomic move that replaces the target.
     */
    internal fun atomicWrite(target: File, bytes: ByteArray) {
        try {
            OwnerOnly.writeReplace(target, bytes)
        } catch (e: Exception) {
            throw IllegalStateException("ciba: could not publish $target", e)
        }
    }

    // ---- file store ----
    /**
     * Durable reference store: one JSON file, rewritten atomically (temp file then rename) on each write. Correct for ONE process at a
     * time; use a database store when several processes share the approvals.
     */
    fun createFileApprovalStore(path: File): ApprovalStore = object : ApprovalStore {
        private fun load(): MutableMap<String, Any?> {
            if (!path.exists()) return LinkedHashMap()
            val parsed = Json.parseLenient(String(path.readBytes(), Charsets.UTF_8)) // a corrupt file throws: fail closed
            if (parsed !is Map<*, *>) throw IllegalStateException("ciba: approval store file is corrupt")
            return map(parsed)
        }

        override fun get(key: String): Versioned? {
            val v = load()[key] ?: return null
            val ver = Js.member(v, "version")
            return Versioned(if (ver == null) 0 else Js.num(ver)!!.toLong(), Js.member(v, "value"))
        }

        override fun cas(key: String, expectedVersion: Long, value: Any?): Boolean {
            val all = load()
            val cur = all[key]
            val cv = if (cur == null) null else Js.num(Js.member(cur, "version"))
            if ((cv?.toLong() ?: 0L) != expectedVersion) return false
            all[key] = Issue.obj("version" to expectedVersion + 1, "value" to value)
            atomicWrite(path, Json.utf8(Js.stringify(all)))
            return true
        }
    }

    /** Single-process in-memory store (a test double: not durable). */
    fun createMemoryApprovalStore(): ApprovalStore = object : ApprovalStore {
        private val m = HashMap<String, Versioned>()

        @Synchronized override fun get(key: String): Versioned? = m[key]?.let { Versioned(it.version, Js.deepCopy(it.value)) }

        @Synchronized override fun cas(key: String, expectedVersion: Long, value: Any?): Boolean {
            if ((m[key]?.version ?: 0L) != expectedVersion) return false
            m[key] = Versioned(expectedVersion + 1, Js.deepCopy(value))
            return true
        }
    }

    // ---- the durable broker ----
    private class Step<T>(val next: Map<String, Any?>?, val out: T)

    private fun finite(o: Any?): Boolean = Js.num(o)?.let { !it.isNaN() && !it.isInfinite() } ?: false

    /** The stored record, checked: a malformed one throws (fail closed). */
    private fun asRec(v: Any?): MutableMap<String, Any?> {
        if (v !is Map<*, *> || Js.member(v["request"], "auth_req_id") !is String || !finite(v["createdAt"]) || !finite(v["expiresAt"]) || !finite(v["interval"]))
            throw IllegalStateException("ciba: stored approval record is malformed")
        return map(v)
    }

    private fun d(o: Any?): Double = Js.num(o) ?: Double.NaN

    private fun snapshot(r: Map<String, Any?>, status: String): Map<String, Any?> {
        val s = Issue.obj("auth_req_id" to map(r["request"])["auth_req_id"], "request" to r["request"], "status" to status,
            "createdAt" to r["createdAt"], "expiresAt" to r["expiresAt"])
        if (r.containsKey("decidedBy")) s["decidedBy"] = r["decidedBy"]
        if (r.containsKey("decidedAt")) s["decidedAt"] = r["decidedAt"]
        return s
    }

    private fun outcome(ok: Boolean, error: String, interval: Any?): Map<String, Any?> = Issue.obj("ok" to ok, "error" to error, "interval" to interval)

    /** The durable broker over `opts.store`: every transition is a compare-and-set, so concurrent callers cannot double-apply a decision. */
    fun createDurableCibaBroker(opts: DurableBrokerOptions?): ApprovalBroker {
        if (opts == null) throw IllegalArgumentException("createDurableCibaBroker: `store` is required")
        val store = opts.store ?: throw IllegalArgumentException("createDurableCibaBroker: `store` is required")
        val clock = opts.now
        val ttlMs = (opts.decisionTtlSec ?: 300.0) * 1000
        if (ttlMs.isNaN() || ttlMs.isInfinite() || ttlMs <= 0) throw IllegalArgumentException("createDurableCibaBroker: decisionTtlSec must be a positive number")
        val idSource = opts.authReqIdSource
        val onComplete = opts.onComplete
        return object : ApprovalBroker {
            fun status(r: Map<String, Any?>, now: Long): String {
                val dec = r["decision"]
                if (dec == "deny") return "denied"
                if (dec == "approve") return if (!(now < d(r["decidedAt"]) + ttlMs)) "expired" else "approved"
                return if (!(now < d(r["expiresAt"]))) "expired" else "pending"
            }

            fun snap(r: Map<String, Any?>, now: Long) = snapshot(r, status(r, now))

            fun load(id: String): Pair<MutableMap<String, Any?>, Long>? = store.get("a:$id")?.let { Pair(asRec(it.value), it.version) }

            fun <T> mutate(id: String, fn: (MutableMap<String, Any?>?, Long) -> Step<T>): T {
                repeat(MAX_CAS_TRIES) {
                    val cur = load(id)
                    val res = fn(cur?.let { map(Js.deepCopy(it.first)) }, clock())
                    if (res.next == null) return res.out
                    if (store.cas("a:$id", cur?.second ?: 0L, res.next)) return res.out
                }
                throw IllegalStateException("ciba: approval store contention, gave up")
            }

            override fun start(stepUp: Map<String, Any?>, opts: Map<String, Any?>?): Map<String, Any?> {
                val liveKey = "s:" + Js.str(Js.get(stepUp, "id"))
                repeat(MAX_CAS_TRIES) {
                    val now = clock()
                    val idx = store.get(liveKey)
                    if (idx != null) {
                        // Never reset a flow that is still waiting or already approved: that would discard a decision.
                        val ex = load(Js.str(idx.value))
                        if (ex != null) {
                            val st = status(ex.first, now)
                            if ((st == "pending" || st == "approved") && !Js.truthy(ex.first["consumed"])) return map(ex.first["request"])
                        }
                    }
                    val o = LinkedHashMap<String, Any?>(opts ?: emptyMap())
                    o["authReqId"] = idSource()
                    val request = Ciba.toCibaAuthRequest(stepUp, o)
                    val rec = Issue.obj("request" to request, "createdAt" to now, "expiresAt" to (now + d(request["requested_expiry"]) * 1000).toLong(),
                        "interval" to request["interval"])
                    val id = request["auth_req_id"] as String
                    if (!store.cas("a:$id", 0, rec)) return@repeat
                    if (store.cas(liveKey, idx?.version ?: 0L, id)) return request
                }
                throw IllegalStateException("ciba: approval store contention, gave up")
            }

            override fun poll(authReqId: String): Map<String, Any?> {
                val c = load(authReqId) ?: throw IllegalStateException("ciba: unknown auth_req_id $authReqId")
                return Issue.obj("status" to status(c.first, clock()))
            }

            override fun token(authReqId: String): Map<String, Any?> = mutate(authReqId) { r, now ->
                when {
                    r == null -> Step(null, outcome(false, "invalid_grant", 5L))
                    Js.truthy(r["consumed"]) -> Step(null, outcome(false, "invalid_grant", r["interval"]))
                    else -> {
                        val tooSoon = r.containsKey("lastPollAt") && now - d(r["lastPollAt"]) < d(r["interval"]) * 1000
                        r["lastPollAt"] = now
                        if (tooSoon) {
                            r["interval"] = d(r["interval"]) + 5
                            Step(r, outcome(false, "slow_down", r["interval"]))
                        } else when (status(r, now)) {
                            "pending" -> Step(r, outcome(false, "authorization_pending", r["interval"]))
                            "denied" -> Step(r, outcome(false, "access_denied", r["interval"]))
                            "expired" -> Step(r, outcome(false, "expired_token", r["interval"]))
                            else -> {
                                r["consumed"] = true // single use: a replayed approval gets invalid_grant
                                Step(r, Issue.obj("ok" to true, "session" to snap(r, now)))
                            }
                        }
                    }
                }
            }

            override fun resolve(authReqId: String, decision: String, by: String?): Map<String, Any?> {
                if (decision != "approve" && decision != "deny") throw IllegalArgumentException("ciba: decision must be \"approve\" or \"deny\"")
                if (by.isNullOrEmpty()) throw IllegalArgumentException("ciba: `by` (the authenticated decider) is required")
                val session = mutate(authReqId) { r, now ->
                    if (r == null) throw IllegalStateException("ciba: unknown auth_req_id $authReqId")
                    val cur = status(r, now)
                    if (cur != "pending") throw IllegalStateException("ciba: cannot resolve $authReqId — already $cur")
                    r["decision"] = decision
                    r["decidedBy"] = by
                    r["decidedAt"] = now
                    Step(r, snap(r, now))
                }
                // the decision is already recorded; a failing notifier must not undo or hide it
                try { onComplete?.invoke(session) } catch (e: RuntimeException) { }
                return session
            }

            override fun get(authReqId: String): Map<String, Any?>? = load(authReqId)?.let { snap(it.first, clock()) }
        }
    }

    // ---- the in-memory broker (test double) ----
    /** Options of [createCibaBroker]. */
    class BrokerOptions {
        var now: () -> Long = { System.currentTimeMillis() }
        /** PING/PUSH: called once, synchronously, when a session is resolved. A throw propagates after the decision is recorded. */
        var onComplete: ((Map<String, Any?>) -> Unit)? = null
        var authReqIdSource: () -> String = { randomAuthReqId() }
    }

    /**
     * An in-memory CIBA broker: models the backchannel lifecycle without any network. Single-process, loses everything on restart: for
     * tests of code that takes a broker, never to guard a real approval.
     */
    fun createCibaBroker(opts: BrokerOptions?): ApprovalBroker {
        val o = opts ?: BrokerOptions()
        val sessions = HashMap<String, MutableMap<String, Any?>>()
        val liveByStepUp = HashMap<String, String>()
        return object : ApprovalBroker {
            fun effective(s: Map<String, Any?>, now: Long): String = when {
                s["decision"] == "approve" -> "approved"
                s["decision"] == "deny" -> "denied"
                !(now < d(s["expiresAt"])) -> "expired"
                else -> "pending"
            }

            @Synchronized override fun start(stepUp: Map<String, Any?>, opts: Map<String, Any?>?): Map<String, Any?> {
                val now = o.now()
                val key = Js.str(Js.get(stepUp, "id"))
                val existing = liveByStepUp[key]?.let { sessions[it] }
                if (existing != null) {
                    val st = effective(existing, now)
                    if (st == "pending" || st == "approved") return map(existing["request"])
                }
                val ro = LinkedHashMap<String, Any?>(opts ?: emptyMap())
                ro["authReqId"] = o.authReqIdSource()
                val request = Ciba.toCibaAuthRequest(stepUp, ro)
                val id = request["auth_req_id"] as String
                sessions[id] = Issue.obj("request" to request, "createdAt" to now, "expiresAt" to (now + d(request["requested_expiry"]) * 1000).toLong(),
                    "interval" to request["interval"])
                liveByStepUp[key] = id
                return request
            }

            @Synchronized override fun poll(authReqId: String): Map<String, Any?> {
                val s = sessions[authReqId] ?: throw IllegalStateException("ciba: unknown auth_req_id $authReqId")
                return Issue.obj("status" to effective(s, o.now()))
            }

            @Synchronized override fun token(authReqId: String): Map<String, Any?> {
                val s = sessions[authReqId] ?: return outcome(false, "invalid_grant", 5L)
                val now = o.now()
                if (Js.truthy(s["consumed"])) return outcome(false, "invalid_grant", s["interval"])
                val tooSoon = s.containsKey("lastPollAt") && now - d(s["lastPollAt"]) < d(s["interval"]) * 1000
                s["lastPollAt"] = now
                if (tooSoon) {
                    s["interval"] = d(s["interval"]) + 5
                    return outcome(false, "slow_down", s["interval"])
                }
                val st = effective(s, now)
                if (st == "pending") return outcome(false, "authorization_pending", s["interval"])
                if (st == "denied") return outcome(false, "access_denied", s["interval"])
                if (st == "expired") return outcome(false, "expired_token", s["interval"])
                s["consumed"] = true
                return Issue.obj("ok" to true, "session" to snapshot(s, st))
            }

            @Synchronized override fun resolve(authReqId: String, decision: String, by: String?): Map<String, Any?> {
                val s = sessions[authReqId] ?: throw IllegalStateException("ciba: unknown auth_req_id $authReqId")
                val now = o.now()
                val current = effective(s, now)
                if (current != "pending") throw IllegalStateException("ciba: cannot resolve $authReqId — already $current")
                s["decision"] = decision
                s["decidedBy"] = by
                s["decidedAt"] = now
                val snap = snapshot(s, effective(s, now))
                o.onComplete?.invoke(snap)
                return snap
            }

            @Synchronized override fun get(authReqId: String): Map<String, Any?>? = sessions[authReqId]?.let { snapshot(it, effective(it, o.now())) }
        }
    }

    /** All the session statuses a broker reports. */
    fun statuses(): List<String> = arrayListOf("pending", "approved", "denied", "expired")
}
