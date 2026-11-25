package net.atlasauth.pca.events

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Typed step-up lifecycle events and signed webhooks for Proof-Carrying Authority. A step-up ceremony creates a grant, then approves,
 * denies, or lets it expire; this turns those four moments into small content-addressed events you can serialize, HMAC-sign and ship
 * to your own inbox, then verify on the way in. It decides nothing: it is a transport contract (a stable event shape plus a
 * Stripe-style signature so the receiver can tell a real delivery from a forged or replayed one).
 *
 * Events are JSON objects (Map): {id, type, at, grant_ref, action: {verb, resource}, tier, actor?}.
 */
object Events {
    /** Smallest secret accepted. A short or empty HMAC key makes every signature guessable. */
    const val MIN_SECRET_BYTES = 16
    private const val MAX_HEADER_CHARS = 2048
    val EVENT_TYPES = listOf("step_up.created", "step_up.approved", "step_up.denied", "step_up.expired")
    private const val ID_DOMAIN = "atlas-pca/stepup-event/v1"

    /** Message prefix of a refusal by the strict canonical JSON profile (a duplicate member, an exponent or trailing-zero number, a lone surrogate, a syntax error). */
    const val SYNTAX_PREFIX = "strict JSON: "

    // ---- JavaScript value helpers ----

    /** `o[k]` for a read that throws on null (a TypeError, as JavaScript does); a non-object has no members. */
    private fun member(o: Any?, k: String): Any? {
        if (o == null) throw IllegalArgumentException("TypeError: cannot read '$k' of null or undefined")
        return Js.get(o, k)
    }

    private fun absent(what: String): Nothing = throw IllegalArgumentException("canonicalize: unsupported type undefined ($what)")

    private fun present(o: Any?, k: String, what: String = k): Any? = if (Js.own(o, k)) Js.get(o, k) else absent(what)

    private fun numOf(d: Double): Json.Num = Js.jsNum(d)

    private fun nowSeconds(): Double = Math.floor(System.currentTimeMillis().toDouble() / 1000)

    // ---- events ----

    /** base64url(sha256(strictCanonical(fields))), domain-separated so ids never collide across event kinds. */
    private fun eventId(type: Any?, at: Any?, grantRef: Any?, action: Map<String, Any?>, tier: Any?, hasActor: Boolean, actor: Any?): String {
        val m = Js.obj(
            "d" to ID_DOMAIN, "type" to type, "at" to at, "grant_ref" to grantRef,
            "action" to Js.obj("verb" to action["verb"], "resource" to action["resource"]), "tier" to tier,
        )
        if (hasActor) m["actor"] = actor
        return Pca.hashCanonical(m)
    }

    private val LONE_SURROGATE = Regex("[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])|(?<![\\uD800-\\uDBFF])[\\uDC00-\\uDFFF]")

    private fun wf(x: Any?): Boolean = x is String && !LONE_SURROGATE.containsMatchIn(x)

    private fun isNumber(x: Any?): Boolean = x is Json.Num || x is Number

    /** The fields every event carries, checked the same way at build and at serialize time (fail closed on anything else). */
    private fun checkEventFields(who: String, o: Any?, withId: Boolean) {
        fun bad(m: String): Nothing = throw IllegalArgumentException("$who: $m")
        if (o !is Map<*, *>) bad("not an object")
        val tier = Js.num(o["tier"])
        if (o["type"] !is String || o["type"] !in EVENT_TYPES || !isNumber(o["tier"]) || (tier != 2.0 && tier != 3.0)) bad("unknown event type or tier")
        if (o["at"] != null || o.containsKey("at")) {
            val at = o["at"]
            if (!isNumber(at) || Js.num(at)!!.let { it.isNaN() || it.isInfinite() }) bad("at must be a finite number")
        }
        if (!wf(o["grant_ref"])) bad("grant_ref must be a well-formed string")
        val a = o["action"]
        if (a !is Map<*, *> || !wf(a["verb"]) || !wf(a["resource"])) bad("action must carry well-formed verb and resource strings")
        if (o["actor"] != null || o.containsKey("actor")) { if (!wf(o["actor"])) bad("actor must be a well-formed string") }
        if (withId && !wf(o["id"])) bad("id must be a well-formed string")
    }

    /**
     * Build a step-up event, filling at (default: the clock, in ms) and deriving a content-addressed id from every other field. Two
     * builds with the same inputs produce the same id. data: {at?, grant_ref, action: {verb, resource}, tier, actor?}; a member that is
     * absent where the reference's canonical form would meet undefined throws.
     */
    fun buildStepUpEvent(type: Any?, dataIn: Any?): Map<String, Any?> {
        val data = IntentJs.normalize(dataIn)
        checkEventFields("buildStepUpEvent", LinkedHashMap<String, Any?>().also { m -> (data as? Map<*, *>)?.forEach { (k, v) -> m[k as String] = v }; m["type"] = type }, false)
        val at = member(data, "at") ?: Json.Num(System.currentTimeMillis().toString())
        val action = member(data, "action")
        member(action, "verb") // a null action throws, as reading its members does
        val act = Js.obj("verb" to present(action, "verb", "action.verb"), "resource" to present(action, "resource", "action.resource"))
        val grantRef = present(data, "grant_ref")
        val tier = present(data, "tier")
        val hasActor = Js.own(data, "actor")
        val actor = if (hasActor) Js.get(data, "actor") else null
        val e = Js.obj("type" to type, "at" to at, "grant_ref" to grantRef, "action" to act, "tier" to tier)
        if (hasActor) e["actor"] = actor
        e["id"] = eventId(type, at, grantRef, act, tier, hasActor, actor)
        return e
    }

    private fun isIndex(k: String): Boolean =
        k.isNotEmpty() && k.length <= 10 && !(k.length > 1 && k[0] == '0') && k.all { it in '0'..'9' } && k.toLong() < 4294967295L

    private fun stringify(sb: StringBuilder, v: Any?) {
        when {
            v == null -> sb.append("null")
            v is Boolean -> sb.append(v)
            v is String -> sb.append(Json.canonicalize(v))
            Js.num(v) != null -> {
                val d = Js.num(v)!!
                sb.append(if (d.isNaN() || d.isInfinite()) "null" else Json.canonicalize(if (v is Json.Num) v else numOf(d)))
            }
            v is List<*> -> {
                sb.append('[')
                v.forEachIndexed { i, x -> if (i > 0) sb.append(','); stringify(sb, x) }
                sb.append(']')
            }
            v is Map<*, *> -> {
                // JavaScript orders integer-like keys first (ascending), then the rest in insertion order
                val keys = v.keys.map { it as String }
                val ordered = keys.filter { isIndex(it) }.sortedBy { it.toLong() } + keys.filter { !isIndex(it) }
                sb.append('{')
                ordered.forEachIndexed { i, k ->
                    if (i > 0) sb.append(',')
                    sb.append(Json.canonicalize(k)).append(':')
                    stringify(sb, v[k])
                }
                sb.append('}')
            }
            else -> throw IllegalArgumentException("serializeEvent: unsupported value")
        }
    }

    /** The JSON wire form (JSON.stringify of the event: members in insertion order). */
    fun serializeEvent(e: Any?): String {
        checkEventFields("serializeEvent", e, true)
        val at = (e as Map<*, *>)["at"]
        if (!isNumber(at) || Js.num(at)!!.let { it.isNaN() || it.isInfinite() }) throw IllegalArgumentException("serializeEvent: at must be a finite number")
        return StringBuilder().also { stringify(it, e) }.toString()
    }

    /** Parse and validate a JSON step-up event. Throws on anything that is not a well-formed event. */
    fun parseEvent(s: String): Map<String, Any?> {
        val raw = try {
            Json.parse(s)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException(SYNTAX_PREFIX + e.message)
        }
        require(raw is Map<*, *> || raw is List<*>) { "parseEvent: not an object" }
        val id = Js.get(raw, "id")
        require(Js.nonEmptyString(id)) { "parseEvent: bad id" }
        val type = Js.get(raw, "type")
        require(type is String && type in EVENT_TYPES) { "parseEvent: bad type" }
        val at = Js.get(raw, "at")
        require(Js.num(at)?.let { !it.isNaN() && !it.isInfinite() } == true) { "parseEvent: bad at" }
        require(Js.get(raw, "grant_ref") is String) { "parseEvent: bad grant_ref" }
        val action = Js.get(raw, "action")
        require(action is Map<*, *> || action is List<*>) { "parseEvent: bad action" }
        val verb = Js.get(action, "verb")
        val resource = Js.get(action, "resource")
        require(verb is String && resource is String) { "parseEvent: bad action fields" }
        val t = Js.num(Js.get(raw, "tier"))
        require(t == 2.0 || t == 3.0) { "parseEvent: bad tier" }
        val tier = Json.Num(if (t == 2.0) "2" else "3")
        val hasActor = Js.own(raw, "actor")
        val actor = Js.get(raw, "actor")
        require(!hasActor || actor is String) { "parseEvent: bad actor" }
        val atN = IntentJs.normalize(at)
        val act = Js.obj("verb" to verb, "resource" to resource)
        val e = Js.obj("id" to id, "type" to type, "at" to atN, "grant_ref" to Js.get(raw, "grant_ref"), "action" to act, "tier" to tier)
        if (hasActor) e["actor"] = actor
        // The id is a content address. An event whose id is not the digest of its fields was edited or forged.
        require(eventId(type, atN, e["grant_ref"], act, tier, hasActor, actor) == id) { "parseEvent: id does not match the event content" }
        return e
    }

    // ---- signed webhooks ----

    private fun secretBytes(secret: Any?): ByteArray? {
        val b = when (secret) {
            is String -> Jose.utf8(secret)
            is ByteArray -> secret
            else -> null
        }
        return b?.takeIf { it.size >= MIN_SECRET_BYTES }
    }

    private fun hmac(key: ByteArray, message: String): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(Jose.utf8(message)) }

    private fun hex(b: ByteArray): String = b.joinToString("") { String.format("%02x", it.toInt() and 0xff) }

    private fun hexDigit(c: Char): Int = when (c) { in '0'..'9' -> c - '0'; in 'a'..'f' -> c - 'a' + 10; in 'A'..'F' -> c - 'A' + 10; else -> -1 }

    /** noble hexToBytes: an even-length string of ASCII hex digits (either case), else null. */
    private fun hexToBytes(s: String): ByteArray? {
        if (s.length % 2 != 0) return null
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            val hi = hexDigit(s[2 * i])
            val lo = hexDigit(s[2 * i + 1])
            if (hi < 0 || lo < 0) return null
            out[i] = (hi * 16 + lo).toByte()
        }
        return out
    }

    /** String.prototype.trim (the JavaScript whitespace set, not Kotlin's). */
    internal fun trim(s: String): String = AttestUtil.jsTrim(s)

    /** A parsed `t=...,v1=...` signature header. */
    internal class Sig(val t: Double, val v1: List<String>)

    /** Parse t=<digits>,v1=<hex>[,v1=...]. Several v1 are allowed (secret rotation); two different t are not. */
    internal fun parseSignatureHeader(h: Any?): Sig? {
        if (h !is String || h.length > MAX_HEADER_CHARS) return null
        var t: Double? = null
        val v1 = ArrayList<String>()
        for (part in h.split(',')) {
            val eq = part.indexOf('=')
            if (eq < 0) continue
            val key = trim(part.substring(0, eq))
            val v = trim(part.substring(eq + 1))
            if (key == "t") {
                if (v.isEmpty() || v.length > 15 || !v.all { it in '0'..'9' }) return null
                val n = v.toDouble()
                if (t != null && t != n) return null
                t = n
            } else if (key == "v1") v1.add(v)
        }
        return if (t == null || v1.isEmpty()) null else Sig(t, v1)
    }

    /**
     * Stripe-style signature for a webhook payload: t=<unixSeconds>,v1=<hex HMAC-SHA256 of "<t>.<payload>">. opts.timestamp pins the
     * second count (default: the clock). Throws on a secret shorter than [MIN_SECRET_BYTES] bytes and on a timestamp that is not a
     * non-negative safe integer; the error never contains the secret. [secret] is a String or ByteArray.
     */
    fun signWebhook(secret: Any?, payload: String, opts: Map<String, Any?>? = null): String {
        val key = secretBytes(secret) ?: throw IllegalArgumentException("signWebhook: the secret must be at least $MIN_SECRET_BYTES bytes")
        val tO = opts?.get("timestamp") ?: numOf(nowSeconds())
        val td = Js.num(tO)
        require(td != null && !td.isNaN() && !td.isInfinite() && td == Math.rint(td) && td <= 9007199254740991.0 && td >= 0) {
            "signWebhook: timestamp must be a non-negative integer (unix seconds)"
        }
        val t = td.toLong()
        return "t=$t,v1=" + hex(hmac(key, "$t.$payload"))
    }

    private fun finite(o: Any?): Double? = Js.num(o)?.takeIf { !it.isNaN() && !it.isInfinite() }

    /**
     * Verify a signature header against the payload: recompute the HMAC, compare constant-time, and enforce the timestamp tolerance
     * (default 300 s). Returns false, never throws, on a malformed header, a bad signature, a stale timestamp, a secret that is too
     * short, or a tolerance / clock that is not a finite non-negative number. With several v1 entries (secret rotation) any one may
     * match. opts: toleranceSec?, now? (unix seconds). A valid signature is not proof of freshness beyond the tolerance window: use
     * [verifyDelivery] to also refuse a replay.
     */
    fun verifyWebhook(secret: Any?, payload: String, signatureHeader: Any?, opts: Map<String, Any?>? = null): Boolean = try {
        val key = secretBytes(secret)
        val parsed = parseSignatureHeader(signatureHeader)
        val tol = finite(opts?.get("toleranceSec") ?: Json.Num("300"))
        val now = finite(opts?.get("now") ?: numOf(nowSeconds()))
        if (key == null || parsed == null || tol == null || tol < 0 || now == null || Math.abs(now - parsed.t) > tol) false
        else {
            val expected = hmac(key, "${parsed.t.toLong()}.$payload")
            var match = false
            for (v in parsed.v1) {
                val provided = hexToBytes(v) ?: continue
                if (MessageDigest.isEqual(expected, provided)) match = true // no early exit: every candidate costs the same
            }
            match
        }
    } catch (e: RuntimeException) {
        false
    }

    /** The verdict of [verifyDelivery]: ok with the event, or not ok with a reason. */
    class DeliveryVerdict internal constructor(val ok: Boolean, val event: Map<String, Any?>?, val reason: String?) {
        fun toMap(): Map<String, Any?> = if (ok) Js.obj("ok" to true, "event" to event) else Js.obj("ok" to false, "reason" to reason)
    }

    private fun no(why: String) = DeliveryVerdict(false, null, why)

    /** base64url(sha256(length-prefixed parts)) under the namespace, as the reference's replayKey (a lone surrogate is refused). */
    fun replayKey(namespace: String, vararg parts: String?): String {
        val all = listOf(namespace) + parts
        val chunks = all.map { p ->
            require(p != null && !Json.hasLoneSurrogate(p)) { "replayKey: every part must be a well-formed string (no lone surrogates)" }
            Json.utf8(p)
        }
        val buf = ByteBuffer.allocate(chunks.sumOf { 4 + it.size })
        for (c in chunks) buf.putInt(c.size).put(c)
        return namespace + ":" + Keys.b64u(MessageDigest.getInstance("SHA-256").digest(buf.array()))
    }

    /**
     * Accept one webhook delivery: signature and freshness ([verifyWebhook]), a well-formed event whose id matches its content
     * ([parseEvent]), and a first sight of that event id (replay.consumeOnce). A store that throws refuses. Never throws, and no reason
     * contains the secret or the payload. opts: toleranceSec?, now?. A fractional retention horizon is rounded toward a longer retention
     * (ceil for the horizon, floor for the clock): the fail-closed direction.
     */
    fun verifyDelivery(secret: Any?, payload: String, signatureHeader: Any?, replay: Authorize.StateStore?, opts: Map<String, Any?>?): DeliveryVerdict = try {
        deliver(secret, payload, signatureHeader, replay, opts)
    } catch (e: RuntimeException) {
        no("bad signature")
    }

    private fun deliver(secret: Any?, payload: String, signatureHeader: Any?, replay: Authorize.StateStore?, opts: Map<String, Any?>?): DeliveryVerdict {
        if (opts == null || replay == null) return no("a replay store is required")
        if (!verifyWebhook(secret, payload, signatureHeader, opts)) return no("bad signature")
        val event = try { parseEvent(payload) } catch (e: RuntimeException) { return no(e.message ?: "bad event") }
        val sig = parseSignatureHeader(signatureHeader)!!
        val nowSec = Js.num(opts["now"] ?: numOf(nowSeconds()))!!
        val tolerance = Js.num(opts["toleranceSec"] ?: Json.Num("300"))!!
        val first = try {
            replay.consumeOnce(replayKey("pca-stepup-event/v1", event["id"] as String), Math.ceil((sig.t + tolerance) * 1000 + 1).toLong(), Math.floor(nowSec * 1000).toLong())
        } catch (e: RuntimeException) {
            return no("replay store unavailable")
        }
        return if (first) DeliveryVerdict(true, event, null) else no("replayed delivery")
    }

    /** The headers to attach to an outbound webhook POST. */
    fun webhookHeaders(secret: Any?, payload: String, opts: Map<String, Any?>? = null): Map<String, String> =
        linkedMapOf("PCA-Signature" to signWebhook(secret, payload, opts), "content-type" to "application/json")
}
