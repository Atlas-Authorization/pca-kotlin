package net.atlasauth.pca.ciba

import java.io.IOException
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import java.util.regex.Pattern
import kotlin.concurrent.withLock
import net.atlasauth.pca.gnap.GnapJs as Js
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.util.encoders.Base64

/**
 * A network client for a real OpenID Provider's CIBA endpoints (OpenID CIBA Core 1.0): start a backchannel authentication request and
 * wait for the human's decision by POLL or PING. It is the relying-party side that the in-memory broker models.
 *
 * Poll discipline follows CIBA Core 7.3 / 11: the client never polls faster than the `interval` the OP returned, adds at least 5 seconds
 * to it on every `slow_down`, and stops at `expires_in`. A terminal answer (approved / denied / expired) is cached, so a settled flow is
 * never re-sent to the token endpoint (an approved `auth_req_id` is single-use at real providers). The client authenticates with
 * `client_secret_basic`. The returned tokens are the OP's response, not verified here.
 *
 * The transport is injectable ([Transport]); the default uses OkHttp (redirects not followed). Calls block. A poller serializes its
 * callers (concurrent callers wait for the in-flight request and then see its cached result when it settled); [Poller.notifyPing]
 * wakes a poller that is sleeping on its own timer but cannot shorten a custom [Sleeper].
 */
@Suppress("UNCHECKED_CAST")
object CibaClient {
    private const val CIBA_GRANT = "urn:openid:params:grant-type:ciba"
    private const val SLOW_DOWN_STEP_SEC = 5
    private const val MIN_NOTIFICATION_TOKEN_CHARS = 22
    private const val MAX_NOTIFICATION_TOKEN_CHARS = 1024
    private const val DEFAULT_TIMEOUT_MS = 30_000.0
    private const val MAX_BACKOFF_MS = 60_000.0
    private const val MAX_CONSECUTIVE_TRANSIENT = 5
    private val RNG = SecureRandom()

    /** An error response from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed reply. `retryable`: a network error, timeout, 5xx or non-JSON reply. */
    class CibaProviderError(val status: Int, val error: String, val errorDescription: String?, val retryable: Boolean) :
        RuntimeException("ciba: provider returned $status $error" + (if (errorDescription != null) " ($errorDescription)" else ""))

    /** One HTTP answer: the status code and the body text. */
    class Response(val status: Int, val text: String) {
        val ok: Boolean get() = status in 200..299
    }

    /** POST `body` (form-encoded) to `url` with `headers`; throws on a network failure or a timeout. */
    fun interface Transport {
        @Throws(IOException::class)
        fun post(url: String, headers: Map<String, String>, body: String, timeoutMs: Long): Response
    }

    /** Sleeps `ms` milliseconds (injectable for tests). */
    fun interface Sleeper {
        @Throws(InterruptedException::class)
        fun sleep(ms: Long)
    }

    /** Client configuration. `transport`, `sleep` and `now` default to OkHttp, the poller's own timer and the system clock. */
    class Config {
        var backchannelAuthenticationEndpoint: String? = null
        var tokenEndpoint: String? = null
        var clientId: String? = null
        var clientSecret: String? = null
        var transport: Transport? = null
        var sleep: Sleeper? = null
        var now: () -> Long = { System.currentTimeMillis() }
        var timeoutMs: Double = DEFAULT_TIMEOUT_MS
        /** Permit `http://` endpoints (local test providers only). */
        var allowInsecureHttp: Boolean = false
    }

    // ---- helpers ----
    /** `encodeURIComponent`. */
    internal fun encodeURIComponent(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            if (cp in 0xd800..0xdfff) throw IllegalArgumentException("URI malformed")
            i += Character.charCount(cp)
            if ((cp in 'a'.code..'z'.code) || (cp in 'A'.code..'Z'.code) || (cp in '0'.code..'9'.code) || "-_.!~*'()".indexOf(cp.toChar()) >= 0) sb.appendCodePoint(cp)
            else for (b in Json.utf8(String(Character.toChars(cp)))) sb.append('%').append(String.format("%02X", b.toInt() and 0xff))
        }
        return sb.toString()
    }

    /** `application/x-www-form-urlencoded` serialization of one parameter name or value. */
    internal fun formEncode(s: String): String {
        val sb = StringBuilder()
        for (bb in Jose.utf8(s)) {
            val b = bb.toInt() and 0xff
            val c = b.toChar()
            if ((c in 'a'..'z') || (c in 'A'..'Z') || (c in '0'..'9') || c == '*' || c == '-' || c == '.' || c == '_') sb.append(c)
            else if (c == ' ') sb.append('+')
            else sb.append('%').append(String.format("%02X", b))
        }
        return sb.toString()
    }

    private fun formBody(params: List<Array<String>>): String = params.joinToString("&") { formEncode(it[0]) + "=" + formEncode(it[1]) }

    /** `URLSearchParams.set`: replace the first parameter of that name and drop the others, else append. */
    private fun setParam(params: MutableList<Array<String>>, k: String, v: String) {
        var set = false
        var i = 0
        while (i < params.size) {
            if (params[i][0] != k) { i++; continue }
            if (!set) { params[i][1] = v; set = true; i++ } else params.removeAt(i)
        }
        if (!set) params.add(arrayOf(k, v))
    }

    private val SCHEME_PREFIX = Pattern.compile("^\\s*([A-Za-z][A-Za-z0-9+.\\-]*):")

    private fun checkEndpoint(name: String, value: String?, allowInsecure: Boolean) {
        var scheme: String? = null
        if (value != null) {
            val m = SCHEME_PREFIX.matcher(value)
            if (m.find()) scheme = m.group(1).lowercase(Locale.ROOT)
        }
        val parses = scheme != null && (try {
            val u = URI.create(value!!.trim())
            u.host != null || (scheme != "https" && scheme != "http")
        } catch (e: IllegalArgumentException) {
            false
        })
        if (!parses) throw IllegalArgumentException("ciba: $name is not a valid URL")
        if (scheme == "https") return
        if (scheme == "http" && allowInsecure) return
        throw IllegalArgumentException("ciba: $name must be an https:// URL (set allowInsecureHttp only for a local test provider)")
    }

    /** A fresh `client_notification_token` (CIBA Core 7.1: at least 128 bits of entropy, at most 1024 chars): 256 random bits, base64url. */
    fun newClientNotificationToken(): String = Keys.b64u(ByteArray(32).also { RNG.nextBytes(it) })

    private fun readJson(res: Response): Map<String, Any?> {
        val parsed = try {
            Json.parseLenient(res.text)
        } catch (e: RuntimeException) {
            throw CibaProviderError(res.status, "invalid_response", "the provider reply was not JSON", true)
        } catch (e: StackOverflowError) {
            throw CibaProviderError(res.status, "invalid_response", "the provider reply was not JSON", true)
        }
        if (parsed !is Map<*, *>) throw CibaProviderError(res.status, "invalid_response", "the provider reply was not a JSON object", false)
        return parsed as Map<String, Any?>
    }

    private fun providerError(status: Int, body: Map<String, Any?>): CibaProviderError =
        CibaProviderError(status, body["error"] as? String ?: "invalid_response", body["error_description"] as? String, false)

    private fun positiveInt(value: Any?, name: String, status: Int): Long {
        if (!Js.isSafeInteger(value) || value is Boolean || Js.num(value)!! <= 0) throw CibaProviderError(status, "invalid_response", "$name must be a positive integer", false)
        return Js.num(value)!!.toLong()
    }

    private val FORM = "application/x-www-form-urlencoded".toMediaType()

    private val http by lazy { OkHttpClient.Builder().followRedirects(false).followSslRedirects(false).build() }

    private fun defaultTransport(): Transport = Transport { url, headers, body, timeoutMs ->
        val rb = Request.Builder().url(url).post(Json.utf8(body).toRequestBody(FORM))
        for ((k, v) in headers) rb.header(k, v)
        http.newBuilder().callTimeout(timeoutMs, TimeUnit.MILLISECONDS).build().newCall(rb.build()).execute().use { r ->
            Response(r.code, r.body?.string() ?: "")
        }
    }

    // ---- the client ----
    /** The CIBA client over one OP: [initiate] starts a flow and [poller] follows it. */
    class Client internal constructor(internal val cfg: Config) {
        private val transport: Transport = cfg.transport ?: defaultTransport()
        private val basic = "Basic " + Base64.toBase64String(Json.utf8((encodeURIComponent(cfg.clientId!!) + ":" + encodeURIComponent(cfg.clientSecret!!))))

        internal fun post(url: String, form: List<Array<String>>, signal: AtomicBoolean?): Response {
            if (signal != null && signal.get()) throw IllegalStateException("ciba: wait aborted")
            val headers = linkedMapOf("authorization" to basic, "content-type" to "application/x-www-form-urlencoded", "accept" to "application/json")
            return try {
                transport.post(url, headers, formBody(form), Math.ceil(cfg.timeoutMs).toLong())
            } catch (e: Exception) {
                if (e !is IOException && e !is RuntimeException) throw e
                if (signal != null && signal.get()) throw IllegalStateException("ciba: wait aborted")
                throw CibaProviderError(0, "network_error", e.message ?: "request failed", true)
            }
        }

        /**
         * Start a backchannel flow for a step-up. `opts`: the request options of [Ciba.toCibaAuthRequest] plus `loginHintToken`, `idTokenHint`,
         * `delivery` (`poll` default or `ping`), `clientNotificationToken`, `acrValues`, `userCode`. Exactly one identifying hint is required
         * (CIBA Core 7.1). Returns the flow `{authReqId, expiresInSec, intervalSec, startedAt, delivery, [clientNotificationToken,] request}`.
         */
        fun initiate(stepUp: Map<String, Any?>, opts: Map<String, Any?>?): Map<String, Any?> {
            val o: Map<String, Any?> = opts ?: emptyMap()
            val hints = listOf("loginHint", "loginHintToken", "idTokenHint").count { o.containsKey(it) }
            if (hints != 1) throw IllegalArgumentException("ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)")
            val delivery = o["delivery"] as String? ?: "poll"
            val notificationToken = if (delivery == "ping") o["clientNotificationToken"] as String? ?: newClientNotificationToken() else null
            if (o.containsKey("clientNotificationToken")) {
                val t = o["clientNotificationToken"] as String
                val printable = t.isNotEmpty() && t.all { it.code in 0x21..0x7e }
                if (t.length < MIN_NOTIFICATION_TOKEN_CHARS || t.length > MAX_NOTIFICATION_TOKEN_CHARS || !printable)
                    throw IllegalArgumentException("ciba: clientNotificationToken must be $MIN_NOTIFICATION_TOKEN_CHARS..$MAX_NOTIFICATION_TOKEN_CHARS printable characters (>= 128 bits, CIBA Core 7.1)")
            }
            val request = Ciba.toCibaAuthRequest(stepUp, o)
            val form = arrayListOf(arrayOf("scope", request["scope"] as String), arrayOf("binding_message", request["binding_message"] as String),
                arrayOf("requested_expiry", Js.str(request["requested_expiry"])))
            if (o.containsKey("loginHint")) setParam(form, "login_hint", Js.str(o["loginHint"]))
            if (o.containsKey("loginHintToken")) setParam(form, "login_hint_token", Js.str(o["loginHintToken"]))
            if (o.containsKey("idTokenHint")) setParam(form, "id_token_hint", Js.str(o["idTokenHint"]))
            if (o.containsKey("acrValues")) setParam(form, "acr_values", Js.str(o["acrValues"]))
            if (o.containsKey("userCode")) setParam(form, "user_code", Js.str(o["userCode"]))
            if (notificationToken != null) setParam(form, "client_notification_token", notificationToken)
            val res = post(cfg.backchannelAuthenticationEndpoint!!, form, null)
            val body = readJson(res)
            if (!res.ok) throw providerError(res.status, body)
            val authReqId = body["auth_req_id"]
            if (authReqId !is String || authReqId.isEmpty()) throw CibaProviderError(res.status, "invalid_response", "auth_req_id missing", false)
            val expiresInSec = positiveInt(body["expires_in"], "expires_in", res.status)
            // CIBA Core 7.3: `interval` is optional and defaults to 5 seconds.
            val intervalSec = if (body.containsKey("interval")) positiveInt(body["interval"], "interval", res.status) else 5L
            val flow = Issue.obj("authReqId" to authReqId, "expiresInSec" to expiresInSec, "intervalSec" to intervalSec, "startedAt" to cfg.now(), "delivery" to delivery)
            if (notificationToken != null) flow["clientNotificationToken"] = notificationToken
            flow["request"] = request
            return flow
        }

        /** The poller for a flow returned by [initiate]. */
        fun poller(flow: Map<String, Any?>): Poller = Poller(this, flow)
    }

    /** Follows one flow: sleeps until the interval allows it, asks the token endpoint once per [poll], and caches a settled answer. */
    class Poller internal constructor(private val c: Client, private val flow: Map<String, Any?>) {
        private val cfg = c.cfg
        private var intervalMs = Js.num(flow["intervalSec"])!! * 1000
        @Volatile private var nextAt = Js.num(flow["startedAt"])!! + intervalMs
        private val deadline = Js.num(flow["startedAt"])!! + Js.num(flow["expiresInSec"])!! * 1000
        private var settled: Map<String, Any?>? = null
        private var failures = 0
        private val lock = ReentrantLock()
        private val wake = lock.newCondition()
        private var woken = false

        /** Current poll interval in seconds (grows on `slow_down`). */
        @Synchronized fun intervalSec(): Double = intervalMs / 1000

        /** A PING arrived: the next [poll] may go out immediately, and a poll that is sleeping on its own timer wakes now. */
        fun notifyPing() = lock.withLock {
            nextAt = cfg.now().toDouble()
            woken = true
            wake.signalAll()
        }

        private fun pause(ms: Double, signal: AtomicBoolean?) {
            try {
                val custom = cfg.sleep
                if (custom != null) custom.sleep(Math.ceil(ms).toLong())
                else {
                    val end = System.currentTimeMillis() + Math.ceil(ms).toLong()
                    lock.withLock {
                        woken = false
                        while (!woken && (signal == null || !signal.get())) {
                            val left = end - System.currentTimeMillis()
                            if (left <= 0) break
                            wake.await(left, TimeUnit.MILLISECONDS)
                        }
                    }
                }
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IllegalStateException("ciba: wait aborted")
            }
            if (signal != null && signal.get()) throw IllegalStateException("ciba: wait aborted")
        }

        private fun backoff() {
            failures += 1
            nextAt = cfg.now() + minOf(MAX_BACKOFF_MS, intervalMs * Math.pow(2.0, minOf(failures, 6).toDouble()))
        }

        private fun settle(m: Map<String, Any?>): Map<String, Any?> { settled = m; return m }

        private fun doPoll(signal: AtomicBoolean?): Map<String, Any?> {
            settled?.let { return it }
            val wait = nextAt - cfg.now()
            if (wait > 0) pause(wait, signal)
            settled?.let { return it }
            if (cfg.now() >= deadline) return settle(Issue.obj("status" to "expired"))
            val res: Response
            val body: Map<String, Any?>
            try {
                res = c.post(cfg.tokenEndpoint!!, listOf(arrayOf("grant_type", CIBA_GRANT), arrayOf("auth_req_id", flow["authReqId"] as String)), signal)
                if (res.status >= 500) throw CibaProviderError(res.status, "server_error", "the provider answered with a server error", true)
                body = readJson(res)
            } catch (e: CibaProviderError) {
                if (e.retryable) backoff()
                throw e
            }
            failures = 0
            nextAt = cfg.now() + intervalMs
            if (res.ok) {
                if (body["access_token"] !is String || body["token_type"] !is String)
                    throw CibaProviderError(res.status, "invalid_response", "token response lacks access_token / token_type", false)
                return settle(Issue.obj("status" to "approved", "tokens" to body))
            }
            val err = providerError(res.status, body)
            return when (err.error) {
                "authorization_pending" -> Issue.obj("status" to "pending", "intervalSec" to intervalMs / 1000)
                "slow_down" -> {
                    intervalMs += SLOW_DOWN_STEP_SEC * 1000
                    nextAt = cfg.now() + intervalMs
                    Issue.obj("status" to "pending", "intervalSec" to intervalMs / 1000)
                }
                "access_denied" -> settle(Issue.obj("status" to "denied", "error" to err.error))
                "expired_token" -> settle(Issue.obj("status" to "expired"))
                else -> throw err
            }
        }

        /** Sleep until the interval allows it, then ask the token endpoint once: `{status: pending, intervalSec}`, `{approved, tokens}`, `{denied, error}` or `{expired}`. */
        @JvmOverloads @Synchronized fun poll(signal: AtomicBoolean? = null): Map<String, Any?> = doPoll(signal)

        /** Poll until the flow settles; honours `signal`. Transient failures are retried (up to 5 in a row); a definitive OP error throws. */
        fun await(signal: AtomicBoolean?): Map<String, Any?> {
            var transientFailures = 0
            while (true) {
                if (signal != null && signal.get()) throw IllegalStateException("ciba: wait aborted")
                try {
                    val r = poll(signal)
                    transientFailures = 0
                    if (r["status"] != "pending") return r
                } catch (e: CibaProviderError) {
                    if (!e.retryable || ++transientFailures >= MAX_CONSECUTIVE_TRANSIENT) throw e
                }
            }
        }
    }

    /** The CIBA client for `cfg`; endpoints must be https:// unless `allowInsecureHttp`. */
    fun createCibaClient(cfg: Config): Client {
        if (cfg.timeoutMs.isNaN() || cfg.timeoutMs.isInfinite() || cfg.timeoutMs <= 0) throw IllegalArgumentException("ciba: timeoutMs must be a positive number")
        checkEndpoint("backchannelAuthenticationEndpoint", cfg.backchannelAuthenticationEndpoint, cfg.allowInsecureHttp)
        checkEndpoint("tokenEndpoint", cfg.tokenEndpoint, cfg.allowInsecureHttp)
        return Client(cfg)
    }

    // ---- PING callback ----
    private val BEARER = Pattern.compile("^bearer +(\\S+)$", Pattern.CASE_INSENSITIVE)

    /**
     * Validate a PING callback (CIBA Core 10.2): `Authorization: Bearer <client_notification_token>` and a JSON body `{"auth_req_id": ...}`.
     * Returns the `auth_req_id` only when the bearer matches the token sent for that flow (constant-time comparison); throws otherwise. The
     * callback carries no decision: call [Poller.notifyPing] and then [Poller.poll].
     */
    fun verifyPingCallback(authorization: String?, body: Any?, flow: Map<String, Any?>): String {
        val expected = flow["clientNotificationToken"] ?: throw IllegalStateException("ciba: flow was not started in ping mode")
        val m = BEARER.matcher(authorization ?: "")
        if (!m.matches()) throw IllegalStateException("ciba: ping callback lacks a bearer token")
        val a = Js.sha256(Json.utf8(m.group(1)))
        val b = Js.sha256(Json.utf8((expected as String)))
        if (!MessageDigest.isEqual(a, b)) throw IllegalStateException("ciba: ping callback bearer does not match the client_notification_token")
        val id = (body as? Map<*, *>)?.get("auth_req_id")
        if (id !is String || id != flow["authReqId"]) throw IllegalStateException("ciba: ping callback auth_req_id does not match this flow")
        return id
    }
}
