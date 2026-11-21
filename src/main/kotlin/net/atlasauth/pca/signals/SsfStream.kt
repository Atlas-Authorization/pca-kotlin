package net.atlasauth.pca.signals

import java.security.SecureRandom
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * SSF stream health: configuration, status, verification events and poll / push delivery bookkeeping, plus the CAEP events PCA
 * emits from its decision log. A pushed revocation is only a guarantee if you know the stream is alive: a receiver that has not
 * seen a verified round trip recently cannot claim "no revocation was missed", and [StreamHealth.revocationFreshWithin]
 * turns that into one boolean the verifier combines with the signed revocation epoch (pull bound). Unhealthy means escalate,
 * never allow. Sources: OpenID SSF 1.0 sections 6.1, 7.1, 8.1.1, 8.1.2, 8.1.4, RFC 8935 (push), RFC 8936 (poll), OpenID CAEP 1.0.
 */
@Suppress("UNCHECKED_CAST")
object SsfStream {
    const val DELIVERY_PUSH = "urn:ietf:rfc:8935"
    const val DELIVERY_POLL = "urn:ietf:rfc:8936"

    @JvmField
    val STREAM_STATUSES: List<String> = listOf("enabled", "paused", "disabled")

    internal fun httpsUrl(u: Any?): Boolean {
        if (u !is String) return false
        if (!u.startsWith("https://") || u.length == 8) return false
        for (i in 8 until u.length) if (JsV.isSpace(u[i])) return false
        return true
    }

    private fun strs(x: Any?): Boolean {
        if (x !is List<*>) return false
        for (e in x) if (!JsV.nonEmpty(e)) return false
        return true
    }

    private fun nonNegSafeInt(v: Any?): Boolean {
        val d = JsV.num(v)
        return JsV.isSafeInteger(v) && d!! >= 0 && !(d == 0.0 && java.lang.Double.doubleToRawLongBits(d) != 0L)
    }

    /** SSF 8.1.1 shape checks. Returns the problems found (empty = valid). */
    @JvmStatic
    fun validateStreamConfig(c: Any?): List<String> {
        val e = ArrayList<String>()
        if (c !is Map<*, *>) {
            e.add("not an object")
            return e
        }
        if (!JsV.nonEmpty(c["stream_id"])) e.add("stream_id is required")
        if (!JsV.nonEmpty(c["iss"])) e.add("iss is required")
        val aud = c["aud"]
        if (!(JsV.nonEmpty(aud) || (aud is List<*> && aud.isNotEmpty() && strs(aud)))) e.add("aud must be a non-empty string or array")
        val delivered = c["events_delivered"]
        val supported = c["events_supported"]
        if (!strs(delivered) || (delivered as List<*>).isEmpty()) e.add("events_delivered must be a non-empty array of event type URIs")
        if (c.containsKey("events_supported") && !strs(supported)) e.add("events_supported must be an array of URIs")
        if (c.containsKey("events_requested") && (!strs(c["events_requested"]) || (c["events_requested"] as List<*>).isEmpty())) e.add("events_requested must be a non-empty array of URIs")
        if (strs(delivered) && strs(supported)) {
            var subset = true
            for (x in delivered as List<*>) if (!(supported as List<*>).contains(x)) subset = false
            if (!subset) e.add("events_delivered must be a subset of events_supported")
        }
        val d = c["delivery"]
        val method = JsV.opt(d, "method")
        if (!JsV.truthy(d) || (DELIVERY_PUSH != method && DELIVERY_POLL != method)) e.add("delivery.method must be the RFC 8935 or RFC 8936 URI")
        else if (!httpsUrl(JsV.opt(d, "endpoint_url"))) e.add("delivery.endpoint_url must be an https URL")
        if (c.containsKey("min_verification_interval") && !nonNegSafeInt(c["min_verification_interval"])) e.add("min_verification_interval must be a non-negative integer (seconds)")
        return e
    }

    private fun fmt(d: Double): String = JsV.str(JsV.numOf(d))

    /**
     * Receiver-side health of one stream. All times are epoch SECONDS passed in (no hidden clock). A verification state is
     * single-use, expiring, and only valid if THIS tracker issued it. States: healthy, degraded, failing, paused, disabled, unverified.
     * [config] is the stream configuration; [opts] (may be null): verifyTimeoutSec (60), verifiedWithinSec (300), failAfter (3), maxPending (16).
     */
    class StreamHealth(@JvmField val config: Map<String, Any?>, opts: Map<String, Any?>?) {
        private val o: Map<String, Any?> = opts ?: LinkedHashMap()
        private var status = "enabled"
        private var lastEvent: Double? = null
        private var lastVerified: Double? = null
        private var lastRequested: Double? = null
        private var fails = 0.0
        private var rejected = 0.0
        private val pending = LinkedHashMap<String, Double>()

        private fun opt(k: String, dflt: Double): Double {
            val v = o[k]
            return if (v == null) dflt else JsV.num(v)!!
        }

        @Synchronized fun setStatus(s: Any?) {
            if (s !is String || s !in STREAM_STATUSES) throw IllegalArgumentException("unknown stream status")
            status = s
        }

        /** Any valid SET arrived on this stream. */
        @Synchronized fun recordEvent(nowSec: Double) {
            lastEvent = Math.max(lastEvent ?: 0.0, nowSec)
        }

        /**
         * Start a verification: returns the state to send to the transmitter's verification endpoint, or null when the transmitter's
         * min_verification_interval has not elapsed (SSF: it would answer 429), the stream is not enabled, or too many are outstanding.
         */
        @Synchronized fun requestVerification(nowSec: Double): String? {
            if (status != "enabled") return null
            if (!nowSec.isFinite()) return null
            val minO = config["min_verification_interval"]
            val min = if (minO == null) 0.0 else JsV.num(minO)!!
            val lr = lastRequested
            if (lr != null && !(nowSec - lr >= min)) return null
            expire(nowSec)
            if (!(pending.size < opt("maxPending", 16.0))) return null
            val b = ByteArray(16)
            RNG.nextBytes(b)
            val state = Keys.b64u(b)
            val exp = nowSec + opt("verifyTimeoutSec", 60.0)
            if (!exp.isFinite()) return null // a NaN or infinite timeout would leave the request pending forever
            pending[state] = exp
            lastRequested = nowSec
            return state
        }

        /** A verification SET came back carrying state. True iff it matches an outstanding, unexpired request (single use). */
        @Synchronized fun ackVerification(state: Any?, nowSec: Double): Boolean {
            if (!nowSec.isFinite()) { rejected++; return false }
            expire(nowSec)
            val exp = if (state is String) pending[state] else null
            if (exp == null) {
                rejected++
                return false
            }
            pending.remove(state as String)
            lastVerified = nowSec
            lastEvent = Math.max(lastEvent ?: 0.0, nowSec)
            fails = 0.0
            return true
        }

        private fun expire(nowSec: Double) {
            val it = pending.entries.iterator()
            while (it.hasNext()) {
                if (nowSec > it.next().value) {
                    it.remove()
                    fails++
                }
            }
        }

        @Synchronized fun report(nowSec: Double): Map<String, Any?> {
            expire(nowSec)
            val reasons = ArrayList<Any?>()
            val within = opt("verifiedWithinSec", 300.0)
            val lv = lastVerified
            val state: String
            if (status == "disabled") { state = "disabled"; reasons.add("stream is disabled: no events are transmitted or held") }
            else if (status == "paused") { state = "paused"; reasons.add("stream is paused: events may be delayed") }
            else if (!(fails < opt("failAfter", 3.0))) { state = "failing"; reasons.add(fmt(fails) + " consecutive verification requests timed out") }
            else if (lv == null) { state = "unverified"; reasons.add("no verification round trip has completed") }
            else if (!(nowSec.isFinite() && nowSec - lv <= within)) { state = "degraded"; reasons.add("last verified " + fmt(nowSec - lv) + "s ago, over " + fmt(within) + "s") }
            else state = "healthy"
            val r = LinkedHashMap<String, Any?>()
            r["state"] = state
            r["status"] = status
            r["reasons"] = reasons
            r["pending_verifications"] = JsV.numOf(pending.size.toDouble())
            r["consecutive_verification_failures"] = JsV.numOf(fails)
            r["rejected_verifications"] = JsV.numOf(rejected)
            lastEvent?.let { r["last_event_at"] = JsV.numOf(it) }
            lv?.let { r["last_verified_at"] = JsV.numOf(it) }
            return r
        }

        /**
         * May the verifier assume no pushed revocation was missed in the last maxAgeSec? Only if the stream is enabled and a verified
         * round trip completed inside that window. Otherwise fall back to the signed epoch pull bound.
         */
        @Synchronized fun revocationFreshWithin(maxAgeSec: Double, nowSec: Double): Boolean {
            val lv = lastVerified
            return status == "enabled" && lv != null && nowSec.isFinite() && nowSec - lv <= maxAgeSec
        }

        private companion object {
            val RNG = SecureRandom()
        }
    }

    // ---- transmitter side ----

    /** The outcome of [handleVerificationRequest]: status 204 with the signed verification SET, or an error status and text. */
    class VerificationOutcome internal constructor(@JvmField val status: Int, @JvmField val set: String?, @JvmField val error: String?)

    /**
     * SSF 8.1.4.2: handle a verification request for a stream. 404 unknown stream, 400 malformed, 429 inside the stream's
     * min_verification_interval; otherwise 204 plus the signed verification SET to deliver on the stream. streams maps stream id to a
     * record {config, lastVerification?} that is updated in place; key is a private Ed25519 JWK.
     */
    @JvmStatic
    fun handleVerificationRequest(streams: Map<String, MutableMap<String, Any?>>, req: Any?, nowSec: Double, key: Map<String, Any?>?): VerificationOutcome {
        if (req !is Map<*, *> || req["stream_id"] !is String || (req.containsKey("state") && req["state"] !is String)) {
            return VerificationOutcome(400, null, "stream_id (string) is required; state must be a string")
        }
        val s = streams[req["stream_id"] as String] ?: return VerificationOutcome(404, null, "no such stream")
        val cfg = s["config"]
        val minO = JsV.member(cfg, "min_verification_interval")
        val min = if (minO == null) 0.0 else JsV.num(minO)!!
        val last = s["lastVerification"]
        if (last != null && nowSec - JsV.num(last)!! < min) return VerificationOutcome(429, null, "verification requested too soon")
        s["lastVerification"] = JsV.numOf(nowSec)
        val ev = LinkedHashMap<String, Any?>()
        if (req.containsKey("state")) ev["state"] = req["state"]
        val events = LinkedHashMap<String, Any?>()
        events[Signals.VERIFICATION] = ev
        val args = LinkedHashMap<String, Any?>()
        args["events"] = events
        JsV.member(cfg, "iss")
        if (JsV.has(cfg, "iss")) args["issuer"] = (cfg as Map<*, *>)["iss"]
        if (JsV.has(cfg, "aud")) args["audience"] = (cfg as Map<*, *>)["aud"]
        if (JsV.has(cfg, "stream_id")) args["subject"] = (cfg as Map<*, *>)["stream_id"]
        args["key"] = key
        return VerificationOutcome(204, Signals.buildSET(args), null)
    }

    /** RFC 8936 transmitter queue: retains a SET until acknowledged, retransmits unacknowledged ones, records receiver errors. */
    class PollQueue {
        private val q = LinkedHashMap<String, String>()

        /** Receiver errors recorded by [poll]: {jti, err, description}. */
        @JvmField val errors: MutableList<Map<String, Any?>> = ArrayList()

        @Synchronized fun enqueue(jti: String, set: String) {
            q[jti] = set
        }

        @Synchronized fun depth(): Int = q.size

        /**
         * One RFC 8936 poll. req: {maxEvents?, returnImmediately?, ack?: [jti], setErrs?: {jti: {err, description}}}. Returns
         * {sets: {jti: set}, moreAvailable?: true}. Throws on a maxEvents that is not a non-negative integer.
         */
        @Synchronized fun poll(req: Any?): Map<String, Any?> {
            val maxO = JsV.member(req, "maxEvents") // a null req throws, as reading its members does
            if (JsV.has(req, "maxEvents") && !nonNegSafeInt(maxO)) throw IllegalArgumentException("maxEvents must be a non-negative integer")
            val ack = JsV.opt(req, "ack")
            if (ack != null) {
                if (ack !is List<*>) throw JsTypeError("ack must be a list of jti strings")
                for (j in ack) if (j is String) q.remove(j)
            }
            // An errored SET is released too: retransmitting a SET the receiver found invalid cannot help.
            val errs = JsV.opt(req, "setErrs")
            if (errs is Map<*, *>) {
                for ((k, why) in errs) {
                    if (q.remove(k as String) != null) {
                        val rec = LinkedHashMap<String, Any?>()
                        rec["jti"] = k
                        val e1 = JsV.member(why, "err")
                        val e2 = JsV.member(why, "description")
                        if (JsV.has(why, "err")) rec["err"] = e1
                        if (JsV.has(why, "description")) rec["description"] = e2
                        errors.add(rec)
                    }
                }
            }
            val max = if (maxO != null) JsV.num(maxO)!! else Double.POSITIVE_INFINITY
            val sets = LinkedHashMap<String, Any?>()
            var n = 0
            for ((k, v) in q) {
                if (n >= max) break
                sets[k] = v
                n++
            }
            val out = LinkedHashMap<String, Any?>()
            out["sets"] = sets
            if (q.size > n) out["moreAvailable"] = true
            return out
        }
    }

    /** RFC 8935 receiver status for a receiveSET outcome ({ok} or {ok: false, code, reason}): {status: 202}, or {status: 400, body: {err, description}}. */
    @JvmStatic
    fun pushResponse(r: Any?): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        if (JsV.truthy(JsV.member(r, "ok"))) {
            out["status"] = Json.Num("202")
            return out
        }
        val code = JsV.opt(r, "code")
        val err = if ("verify_failed" == code) "invalid_key"
        else if ("malformed" == code || "oversize" == code) "invalid_request"
        else if ("misconfigured" == code || "replay_store_error" == code) "access_denied" else "invalid_request"
        val body = LinkedHashMap<String, Any?>()
        body["err"] = err
        if (JsV.has(r, "reason")) body["description"] = (r as Map<*, *>)["reason"]
        out["status"] = Json.Num("400")
        out["body"] = body
        return out
    }

    // ---- CAEP events from the decision log ----

    private fun eventSet(a: Map<String, Any?>, type: String, event: Any?): String {
        val events = LinkedHashMap<String, Any?>()
        events[type] = event
        val args = LinkedHashMap<String, Any?>()
        if (JsV.has(a, "issuer")) args["issuer"] = a["issuer"]
        if (JsV.has(a, "audience")) args["audience"] = a["audience"]
        args["key"] = a["key"]
        args["events"] = events
        return Signals.buildSET(args)
    }

    /** Emit risk-level-change (from the behavioural immune system). a: {issuer, audience, key, event}. */
    @JvmStatic
    fun riskLevelChangeSET(a: Map<String, Any?>): String = eventSet(a, Signals.RISK_LEVEL_CHANGE, JsV.member(a, "event"))

    /** Emit assurance-level-change (from a discharge change); change_direction is derived when both levels are in a.order. a: {issuer, audience, key, event, order?}. */
    @JvmStatic
    fun assuranceLevelChangeSET(a: Map<String, Any?>): String {
        val ev = JsV.member(a, "event")
        val e = if (ev is Map<*, *>) LinkedHashMap(ev as Map<String, Any?>) else LinkedHashMap<String, Any?>()
        val order = a["order"]
        if (e.containsKey("previous_level") && !e.containsKey("change_direction") && JsV.truthy(order)) {
            if (order !is List<*>) throw JsTypeError("order must be a list")
            val i = order.indexOf(e["previous_level"])
            val j = order.indexOf(e["current_level"])
            if (i >= 0 && j >= 0 && i != j) e["change_direction"] = if (j > i) "increase" else "decrease"
        }
        return eventSet(a, Signals.ASSURANCE_LEVEL_CHANGE, e)
    }
}
