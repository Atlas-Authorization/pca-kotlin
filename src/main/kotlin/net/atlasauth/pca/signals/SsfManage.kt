package net.atlasauth.pca.signals

import java.security.SecureRandom
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * SSF stream management API (OpenID Shared Signals Framework 1.0, sections 8.1 and 7.1): create / read / update (PATCH) / replace
 * (PUT) / delete a stream, read / update its status, add / remove subjects, request a verification event, and the transmitter
 * configuration metadata. Framework-neutral: a request map {method, path, query?, body?} in, a response map {status, body?} out. The
 * HOST authenticates the receiver (SSF 8: "standard HTTP authentication") and passes {id, aud}; a stream belongs to exactly one
 * receiver and anyone else sees 404, never 403. Requests, responses and stream records are JSON objects (Map).
 */
@Suppress("UNCHECKED_CAST")
object SsfManage {
    /**
     * Storage of stream records {receiver, config, events_requested?, status, status_reason?, subjects: {canonical-JSON key: verified},
     * lastVerification?}. get returns a copy (null when absent); put stores a copy.
     */
    interface StreamStore {
        fun get(id: String): MutableMap<String, Any?>?
        fun put(id: String, record: Map<String, Any?>)
        fun delete(id: String)
        fun listByReceiver(receiver: Any?): List<Pair<String, MutableMap<String, Any?>>>
    }

    fun deepCopy(v: Any?): Any? {
        if (v is Map<*, *>) {
            val m = LinkedHashMap<String, Any?>()
            for ((k, x) in v) m[k as String] = deepCopy(x)
            return m
        }
        if (v is List<*>) return v.mapTo(ArrayList<Any?>()) { deepCopy(it) }
        return v
    }

    private fun copy(m: Map<String, Any?>): MutableMap<String, Any?> = deepCopy(m) as MutableMap<String, Any?>

    /** The in-memory [StreamStore] (structured clones in and out). */
    class MemoryStreamStore : StreamStore {
        private val m = LinkedHashMap<String, MutableMap<String, Any?>>()

        @Synchronized override fun get(id: String): MutableMap<String, Any?>? = m[id]?.let { copy(it) }

        @Synchronized override fun put(id: String, record: Map<String, Any?>) {
            m[id] = copy(record)
        }

        @Synchronized override fun delete(id: String) {
            m.remove(id)
        }

        @Synchronized override fun listByReceiver(receiver: Any?): List<Pair<String, MutableMap<String, Any?>>> =
            m.entries.filter { it.value["receiver"] == receiver }.map { it.key to copy(it.value) }
    }

    /** What [ssfManagementHandler] needs. Required: store, issuer, eventsSupported, pollEndpoint, signingKey (a private Ed25519 JWK), deliver, now. */
    class Options {
        lateinit var store: StreamStore

        /** The transmitter's issuer URL: equals the iss of every SET (SSF 7.1 issuer). */
        var issuer: String? = null

        /** Event type URIs the transmitter can emit. */
        lateinit var eventsSupported: List<String>

        /** Delivery methods offered; null means both. */
        var deliveryMethods: List<String>? = null

        /** Poll endpoint the transmitter assigns to a stream (RFC 8936: transmitter-set). */
        lateinit var pollEndpoint: (String) -> String

        /** Verification SETs are signed with this key (SSF 8.1.4). */
        var signingKey: Map<String, Any?>? = null

        /** Hand the verification SET to the stream's delivery (enqueue for poll, POST for push). */
        lateinit var deliver: (Map<String, Any?>, String) -> Unit

        /** 1 (default when null) = one stream per receiver: the second create is 409 (SSF 8.1.1.1). */
        var maxStreamsPerReceiver: Double? = null
        var maxSubjectsPerStream: Double? = null

        /** The clock, in epoch seconds. */
        lateinit var now: () -> Double
        var newId: (() -> String)? = null
    }

    private val ENDPOINTS = listOf("configuration", "status", "add_subject", "remove_subject", "verification")
    private val RECEIVER_SUPPLIED = listOf("events_requested", "delivery", "description")
    private val TRANSMITTER_SUPPLIED = listOf("stream_id", "iss", "aud", "events_supported", "events_delivered", "min_verification_interval")

    private fun resp(status: Int, body: Any?, hasBody: Boolean = true): Map<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        r["status"] = Json.Num(status.toString())
        if (hasBody) r["body"] = body
        return r
    }

    private fun err(error: String, description: String? = null): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["error"] = error
        if (description != null) m["description"] = description
        return m
    }

    private fun bad(m: String) = resp(400, err("invalid_request", m))

    private fun notFound() = resp(404, err("not_found"))

    private fun notAllowed() = resp(405, err("method_not_allowed"))

    private fun isRec(x: Any?) = x is Map<*, *>

    /** Object.keys order of a key set: integer-like keys ascending first, then the rest in the given order. */
    private fun jsKeyOrder(keys: List<String>): List<String> {
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in keys) {
            var index = k.isNotEmpty() && k.length <= 10 && (k.length == 1 || k[0] != '0')
            var i = 0
            while (index && i < k.length) {
                if (k[i] < '0' || k[i] > '9') index = false
                i++
            }
            if (index && k.toLong() < 4294967295L) idx.add(k) else rest.add(k)
        }
        idx.sortWith(Comparator { a, b -> a.toLong().compareTo(b.toLong()) })
        idx.addAll(rest)
        return idx
    }

    private fun subjectKey(s: Any?): String? {
        if (!isRec(s) || (s as Map<*, *>)["format"] !is String || (s["format"] as String).isEmpty()) return null
        val m = s as Map<String, Any?>
        val keys = ArrayList(m.keys)
        keys.sort() // the reference compares with < (UTF-16 code units)
        val o = LinkedHashMap<String, Any?>()
        for (k in jsKeyOrder(keys)) o[k] = m[k]
        return Jose.stringify(o)
    }

    /** SSF 7.1 transmitter configuration metadata (served at /.well-known/ssf-configuration). deliveryMethods and jwksUri may be null. */
    @JvmStatic
    fun transmitterMetadata(issuer: String?, deliveryMethods: List<String>?, base: String, jwksUri: String?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["spec_version"] = "1_0"
        m["issuer"] = issuer
        if (jwksUri != null && jwksUri.isNotEmpty()) m["jwks_uri"] = jwksUri
        m["delivery_methods_supported"] = ArrayList<Any?>(deliveryMethods ?: listOf(SsfStream.DELIVERY_PUSH, SsfStream.DELIVERY_POLL))
        m["configuration_endpoint"] = "$base/ssf/configuration"
        m["status_endpoint"] = "$base/ssf/status"
        m["add_subject_endpoint"] = "$base/ssf/add_subject"
        m["remove_subject_endpoint"] = "$base/ssf/remove_subject"
        m["verification_endpoint"] = "$base/ssf/verification"
        m["default_subjects"] = "NONE"
        return m
    }

    /** Authenticates a request: returns the receiver {id, aud}, or null when unauthenticated. May throw (the handler answers 500). */
    fun interface Authenticate {
        fun apply(req: Any?): Map<String, Any?>?
    }

    /** The request handler returned by [ssfManagementHandler]: never throws; a failure answers 500. */
    fun interface Handler {
        fun handle(req: Any?): Map<String, Any?>
    }

    private val RNG = SecureRandom()

    private fun defaultNewId(): String {
        val b = ByteArray(12)
        RNG.nextBytes(b)
        return Keys.b64u(b)
    }

    private class Core(val o: Options, val methods: List<String>, val newId: () -> String, val maxStreams: Double) {
        fun own(rcv: Map<String, Any?>, id: Any?): MutableMap<String, Any?>? {
            if (id !is String) return null
            val r = o.store.get(id)
            return if (r != null && r["receiver"] == rcv["id"]) r else null
        }

        fun delivered(requested: List<*>?): List<Any?> {
            val out = ArrayList<Any?>()
            for (e in o.eventsSupported) if (requested == null || requested.contains(e)) out.add(e)
            return out
        }

        fun eventsRequestedOk(v: Any?): Boolean {
            if (v !is List<*> || v.isEmpty()) return false
            for (e in v) if (!JsV.nonEmpty(e)) return false
            return true
        }

        fun delivery(method: String, url: String?): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["method"] = method
            m["endpoint_url"] = url
            return m
        }

        /** (ok, delivery map | why). present = the member exists (undefined is absent; null is a value). */
        fun deliveryFor(id: String, present: Boolean, d: Any?): Pair<Boolean, Any?> {
            if (!present) {
                if (!methods.contains(SsfStream.DELIVERY_POLL)) return false to "delivery is required: this transmitter does not support poll"
                return true to delivery(SsfStream.DELIVERY_POLL, o.pollEndpoint(id))
            }
            if (d !is Map<*, *> || d["method"] !is String || !methods.contains(d["method"])) return false to "delivery.method is not supported by this transmitter"
            if (SsfStream.DELIVERY_POLL == d["method"]) return true to delivery(SsfStream.DELIVERY_POLL, o.pollEndpoint(id)) // transmitter-set; a receiver value is ignored
            if (!SsfStream.httpsUrl(d["endpoint_url"])) return false to "push delivery needs an https endpoint_url"
            return true to delivery(SsfStream.DELIVERY_PUSH, d["endpoint_url"] as String)
        }

        fun build(id: String, rcv: Map<String, Any?>, requested: List<*>?, delivery: Any?, description: String?): MutableMap<String, Any?> {
            val c = LinkedHashMap<String, Any?>()
            c["stream_id"] = id
            c["iss"] = o.issuer
            c["aud"] = rcv["aud"]
            c["events_supported"] = ArrayList<Any?>(o.eventsSupported)
            c["events_delivered"] = delivered(requested)
            c["delivery"] = delivery
            if (description != null) c["description"] = if (description.length > 256) description.substring(0, 256) else description
            return c
        }

        fun statusBody(id: Any?, s: Map<String, Any?>): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["stream_id"] = id
            m["status"] = s["status"]
            if (s.containsKey("status_reason")) m["reason"] = s["status_reason"]
            return m
        }

        fun route(req: Any?, rcv: Map<String, Any?>): Map<String, Any?> {
            val path = JsV.member(req, "path")
            if (path !is String) throw JsTypeError("path.split is not a function")
            var seg = ""
            for (part in path.split("/")) if (part.isNotEmpty()) seg = part
            val q: Any? = JsV.opt(req, "query") ?: LinkedHashMap<String, Any?>()
            val body = JsV.opt(req, "body")
            val b: MutableMap<String, Any?>? = if (isRec(body)) body as MutableMap<String, Any?> else null
            val mO = JsV.opt(req, "method")
            if (mO !is String) throw JsTypeError("req.method.toUpperCase is not a function")
            val m = mO.uppercase()
            if (!ENDPOINTS.contains(seg)) return resp(404, err("not_found"))
            val hasQid = JsV.has(q, "stream_id")
            val qid = JsV.opt(q, "stream_id")

            if (seg == "configuration") {
                if (m == "POST") { // 8.1.1.1
                    if (b == null) return bad("a JSON object body is required")
                    for (k in jsKeyOrder(ArrayList(b.keys))) if (!RECEIVER_SUPPLIED.contains(k)) return bad("'$k' is not a receiver-supplied member")
                    if (b.containsKey("events_requested") && !eventsRequestedOk(b["events_requested"])) return bad("events_requested must be a non-empty array of event type URIs")
                    if (b.containsKey("description") && b["description"] !is String) return bad("description must be a string")
                    if (!(o.store.listByReceiver(rcv["id"]).size < maxStreams)) return resp(409, err("conflict", "this receiver already has the maximum number of streams"))
                    val id = newId()
                    val d = deliveryFor(id, b.containsKey("delivery"), b["delivery"])
                    if (!d.first) return bad(d.second as String)
                    val requested = if (b.containsKey("events_requested")) b["events_requested"] as List<*> else null
                    if (delivered(requested).isEmpty()) return bad("none of events_requested is supported by this transmitter")
                    val config = build(id, rcv, requested, d.second, b["description"] as String?)
                    val problems = SsfStream.validateStreamConfig(config)
                    if (problems.isNotEmpty()) return bad(problems.joinToString("; "))
                    val rec = LinkedHashMap<String, Any?>()
                    rec["receiver"] = rcv["id"]
                    rec["config"] = config
                    if (JsV.truthy(b["events_requested"])) rec["events_requested"] = b["events_requested"]
                    rec["status"] = "enabled"
                    rec["subjects"] = LinkedHashMap<String, Any?>()
                    o.store.put(id, rec)
                    return resp(201, config)
                }
                if (m == "GET") { // 8.1.1.2
                    if (!hasQid) {
                        val out = ArrayList<Any?>()
                        for (e in o.store.listByReceiver(rcv["id"])) out.add(e.second["config"])
                        return resp(200, out)
                    }
                    val s = own(rcv, qid)
                    return if (s != null) resp(200, s["config"]) else notFound()
                }
                if (m == "PATCH" || m == "PUT") { // 8.1.1.3 / 8.1.1.4
                    if (b == null) return bad("a JSON object body is required")
                    val s = own(rcv, b["stream_id"])
                    if (b["stream_id"] !is String) return bad("stream_id is required")
                    if (s == null) return notFound()
                    for (k in jsKeyOrder(ArrayList(b.keys))) if (!RECEIVER_SUPPLIED.contains(k) && !TRANSMITTER_SUPPLIED.contains(k)) return bad("unknown member '$k'")
                    // Transmitter-supplied members may be present but must equal the expected value, checked BEFORE any update is applied.
                    val cfg = s["config"] as Map<String, Any?>
                    for (k in TRANSMITTER_SUPPLIED) {
                        if (!b.containsKey(k)) continue
                        if (!cfg.containsKey(k) || Jose.stringify(b[k]) != Jose.stringify(cfg[k])) return bad("'$k' is transmitter-supplied and does not match")
                    }
                    if (b.containsKey("events_requested") && !eventsRequestedOk(b["events_requested"])) return bad("events_requested must be a non-empty array of event type URIs")
                    if (b.containsKey("description") && b["description"] !is String) return bad("description must be a string")
                    var delivery = cfg["delivery"]
                    if (b.containsKey("delivery") || m == "PUT") { // PUT: a missing delivery is a deleted one, i.e. the default
                        val d = deliveryFor(cfg["stream_id"] as String, b.containsKey("delivery"), b["delivery"])
                        if (!d.first) return bad(d.second as String)
                        val nd = d.second as Map<String, Any?>
                        if (nd["method"] != (cfg["delivery"] as Map<String, Any?>)["method"]) return bad("delivery.method cannot be changed: create a new stream")
                        delivery = nd
                    }
                    val requested = if (m == "PUT") b["events_requested"] else if (b.containsKey("events_requested")) b["events_requested"] else s["events_requested"]
                    val description = if (m == "PUT") b["description"] else if (b.containsKey("description")) b["description"] else cfg["description"]
                    if (delivered(requested as List<*>?).isEmpty()) return bad("none of events_requested is supported by this transmitter")
                    val next = build(cfg["stream_id"] as String, rcv, requested, delivery, description as String?)
                    if (cfg.containsKey("min_verification_interval")) next["min_verification_interval"] = cfg["min_verification_interval"]
                    s["config"] = next
                    if (JsV.truthy(requested)) s["events_requested"] = requested else s.remove("events_requested")
                    o.store.put(next["stream_id"] as String, s)
                    return resp(200, next)
                }
                if (m == "DELETE") { // 8.1.1.5
                    own(rcv, qid) ?: return notFound()
                    o.store.delete(qid as String)
                    return resp(204, null, false)
                }
                return notAllowed()
            }

            if (seg == "status") { // 8.1.2
                if (m == "GET") {
                    val s = own(rcv, qid) ?: return if (!hasQid) bad("stream_id is required") else notFound()
                    return resp(200, statusBody(qid, s))
                }
                if (m == "POST") {
                    if (b == null || b["stream_id"] !is String) return bad("stream_id is required")
                    if (!SsfStream.STREAM_STATUSES.contains(b["status"])) return bad("status must be 'enabled', 'paused' or 'disabled'")
                    if (b.containsKey("reason") && b["reason"] !is String) return bad("reason must be a string")
                    val s = own(rcv, b["stream_id"]) ?: return notFound()
                    s["status"] = b["status"]
                    if (b.containsKey("reason")) s["status_reason"] = b["reason"] else s.remove("status_reason")
                    o.store.put(b["stream_id"] as String, s)
                    return resp(200, statusBody(b["stream_id"], s))
                }
                return notAllowed()
            }

            if (seg == "add_subject" || seg == "remove_subject") { // 8.1.3
                if (m != "POST") return notAllowed()
                if (b == null || b["stream_id"] !is String) return bad("stream_id is required")
                val key = subjectKey(b["subject"]) ?: return bad("subject must be a Subject Identifier object with a format")
                if (b.containsKey("verified") && b["verified"] !is Boolean) return bad("verified must be a boolean")
                val s = own(rcv, b["stream_id"]) ?: return notFound()
                val subjects = s["subjects"] as MutableMap<String, Any?>
                if (seg == "add_subject") {
                    val maxSubjects = o.maxSubjectsPerStream ?: 10_000.0
                    if (!subjects.containsKey(key) && subjects.size >= maxSubjects) return resp(429, err("too_many_requests", "subject limit reached"))
                    subjects[key] = b["verified"] ?: true // SSF: SHOULD assume verified when omitted
                    o.store.put(b["stream_id"] as String, s)
                    return resp(200, null, false)
                }
                subjects.remove(key) // an unknown subject is silently ignored (204)
                o.store.put(b["stream_id"] as String, s)
                return resp(204, null, false)
            }

            // verification (8.1.4.2)
            if (m != "POST") return notAllowed()
            if (b == null) return bad("a JSON object body is required")
            val s = own(rcv, b["stream_id"]) ?: return if (b["stream_id"] is String) notFound() else bad("stream_id is required")
            if ("disabled" == s["status"]) return bad("the stream is disabled")
            val cfg = s["config"] as Map<String, Any?>
            val entry = LinkedHashMap<String, Any?>()
            entry["config"] = cfg
            if (s.containsKey("lastVerification")) entry["lastVerification"] = s["lastVerification"]
            val view = LinkedHashMap<String, MutableMap<String, Any?>>()
            view[cfg["stream_id"] as String] = entry
            val vreq = LinkedHashMap<String, Any?>()
            vreq["stream_id"] = b["stream_id"]
            if (b.containsKey("state")) vreq["state"] = b["state"]
            val out = SsfStream.handleVerificationRequest(view, vreq, o.now(), o.signingKey)
            if (out.status != 204) return resp(out.status, err(if (out.status == 429) "too_many_requests" else "invalid_request", out.error))
            s["lastVerification"] = JsV.numOf(o.now())
            o.store.put(cfg["stream_id"] as String, s)
            o.deliver(s, out.set!!)
            return resp(204, null, false)
        }
    }

    /**
     * The SSF management endpoints as one handler. Routes on the last path segment (configuration, status, add_subject,
     * remove_subject, verification) and the method. 401 when authenticate yields no receiver, 500 on any failure.
     */
    @JvmStatic
    fun ssfManagementHandler(o: Options, authenticate: Authenticate): Handler {
        val methods = o.deliveryMethods ?: listOf(SsfStream.DELIVERY_PUSH, SsfStream.DELIVERY_POLL)
        val newId: () -> String = o.newId ?: { defaultNewId() }
        val maxStreams = o.maxStreamsPerReceiver ?: 1.0
        val core = Core(o, methods, newId, maxStreams)
        return Handler { req ->
            try {
                val rcv = authenticate.apply(req)
                if (rcv == null) resp(401, err("unauthenticated")) else core.route(req, rcv)
            } catch (e: RuntimeException) {
                resp(500, err("server_error"))
            }
        }
    }
}
