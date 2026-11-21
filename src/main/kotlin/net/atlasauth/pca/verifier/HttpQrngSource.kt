package net.atlasauth.pca.verifier

import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * An HTTP QRNG backend for a configurable REST endpoint (ANU-style JSON, hex or base64 bodies), validated into exactly the requested
 * number of bytes. Fail-closed: a non-2xx status, a malformed body, a wrong-length payload, an out-of-range byte, a cleartext endpoint
 * or a timeout all throw. The API key travels only as a request header and never appears in an error. The library has no HTTP client:
 * the caller supplies the [Transport].
 */
class HttpQrngSource(c: Config) : Entropy.QrngSource {
    /** Body format. Anything else a caller might name falls to base64, as the reference does. */
    enum class Format { ANU_UINT8, HEX, BASE64 }

    /** One outgoing request. `redirect` is always "error" (a transport must not follow redirects); `timeoutMs` bounds the call. */
    class Request(val url: String, val headers: Map<String, String>, val redirect: String, val timeoutMs: Int)

    /** The response subset the source reads: only `ok` decides success; `json()` / `text()` may throw. */
    interface Response {
        val ok: Boolean
        val status: Int

        /** The parsed JSON body (Map, List, Number, String, Boolean or null). */
        @Throws(Exception::class)
        fun json(): Any?

        @Throws(Exception::class)
        fun text(): String
    }

    /** The injected transport. It is run on its own thread and interrupted when the timeout elapses. */
    fun interface Transport {
        @Throws(Exception::class)
        fun send(request: Request): Response
    }

    /** Configuration; null fields take the reference defaults. */
    class Config {
        /** Base endpoint URL (required). */
        var url: String? = null

        /** Optional API key, sent as a header, never logged. */
        var apiKey: String? = null

        /** Header name for the key (default x-api-key). */
        var apiKeyHeader: String? = null

        /** Default ANU_UINT8. */
        var format: Format? = null

        /** Request timeout in ms (default 5000). */
        var timeoutMs: Int? = null

        /** Max bytes per request (default 1024). */
        var maxBytes: Int? = null

        /** Query parameter carrying the length (default "length"). */
        var lengthParam: String? = null

        /** Extra query parameters, applied in order after the length. */
        var extraParams: Map<String, String>? = null

        /** Builds the whole URL itself (its result still goes through the https check). */
        var buildUrl: ((String, Int) -> String)? = null

        /** Permit plain http only for localhost, 127.0.0.1 or [::1]. Default false. */
        var allowInsecureLoopback: Boolean = false

        /** The transport; a source with none refuses every fetch. */
        var transport: Transport? = null
    }

    private val url: String
    private val apiKey: String? = c.apiKey
    private val apiKeyHeader: String = c.apiKeyHeader ?: "x-api-key"
    private val lengthParam: String = c.lengthParam ?: "length"
    private val format: Format = c.format ?: Format.ANU_UINT8
    private val timeoutMs: Int
    private val maxBytes: Int
    private val extraParams: Map<String, String>? = c.extraParams
    private val buildUrl: ((String, Int) -> String)? = c.buildUrl
    private val allowInsecureLoopback: Boolean = c.allowInsecureLoopback
    private val transport: Transport? = c.transport
    override val name: String

    init {
        val u = c.url ?: ""
        require(u.isNotEmpty()) { "HttpQrngSource: `url` must be a non-empty string" }
        url = u
        maxBytes = c.maxBytes ?: Entropy.DEFAULT_MAX_QRNG_BYTES
        require(maxBytes > 0) { "HttpQrngSource: `maxBytes` must be a positive integer" }
        timeoutMs = c.timeoutMs ?: Entropy.DEFAULT_TIMEOUT_MS
        require(timeoutMs > 0) { "HttpQrngSource: `timeoutMs` must be a positive integer" }
        name = "http-qrng(" + safeHost(u) + ")"
    }

    private fun buildRequestUrl(n: Int): String {
        buildUrl?.let { return it(url, n) }
        val u = WhatwgUrl.parse(url)
        // shortcut: an opaque (non-special scheme) URL cannot take query parameters; it is refused here, as it would be at the https check
        if (u.isOpaque()) throw IllegalArgumentException("Invalid URL")
        u.setParam(lengthParam, n.toString())
        extraParams?.forEach { (k, v) -> u.setParam(k, v) }
        return u.href()
    }

    @Throws(Exception::class)
    override fun fetch(numBytes: Int): ByteArray {
        require(numBytes > 0) { "QRNG: numBytes must be a positive integer, got $numBytes" }
        require(numBytes <= maxBytes) { "QRNG: requested $numBytes bytes exceeds per-request cap $maxBytes" }
        val tr = transport ?: throw IllegalStateException("QRNG: no fetch implementation available in this runtime")

        val full = buildRequestUrl(numBytes)
        assertSecureTransport(full, allowInsecureLoopback)
        val headers = LinkedHashMap<String, String>()
        headers["accept"] = "application/json, text/plain"
        if (!apiKey.isNullOrEmpty()) headers[apiKeyHeader] = apiKey

        val req = Request(full, headers, "error", timeoutMs)
        val call = FutureTask<Response> { tr.send(req) }
        val t = Thread(call, "qrng-fetch")
        t.isDaemon = true
        t.start()
        val res: Response = try {
            call.get(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            call.cancel(true)
            throw IllegalStateException("QRNG: fetch failed (timeout)")
        } catch (e: ExecutionException) {
            throw IllegalStateException("QRNG: fetch failed (" + scrub(describe(e.cause), apiKey) + ")")
        } catch (e: InterruptedException) {
            call.cancel(true)
            Thread.currentThread().interrupt()
            throw IllegalStateException("QRNG: fetch failed (timeout)")
        }

        check(res.ok) { "QRNG: endpoint returned HTTP ${res.status}" }
        val bytes = if (format == Format.ANU_UINT8) Entropy.parseAnuUint8(res.json()) else {
            val text = jsTrim(res.text())
            if (format == Format.HEX) Entropy.parseHex(text) else Entropy.parseBase64(text)
        }
        check(bytes.size == numBytes) { "QRNG: expected $numBytes bytes, response decoded to ${bytes.size}" }
        return bytes
    }

    companion object {
        private fun isJsSpace(c: Char): Boolean =
            c == ' ' || (c in '\t'..'\r') || c == '\u00a0' || c == '\u1680' || (c in '\u2000'..'\u200a') ||
                c == '\u2028' || c == '\u2029' || c == '\u202f' || c == '\u205f' || c == '\u3000' || c == '\ufeff'

        /** `String.prototype.trim`: strips JavaScript whitespace and line terminators, not only ASCII control characters. */
        internal fun jsTrim(s: String): String {
            var b = 0
            var e = s.length
            while (b < e && isJsSpace(s[b])) b++
            while (e > b && isJsSpace(s[e - 1])) e--
            return s.substring(b, e)
        }

        private fun assertSecureTransport(url: String, allowLoopback: Boolean) {
            val u = try { WhatwgUrl.parse(url) } catch (e: IllegalArgumentException) { throw EntropyError("insecure_transport", "QRNG: endpoint URL is not a valid URL") }
            if (u.protocol() == "https:") return
            val h = u.hostname()
            val loop = h == "localhost" || h == "127.0.0.1" || h == "[::1]"
            if (u.protocol() == "http:" && allowLoopback && loop) return
            throw EntropyError("insecure_transport", "QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)")
        }

        private fun safeHost(url: String): String = try {
            WhatwgUrl.parse(url).hostWithPort().ifEmpty { "unknown" }
        } catch (e: IllegalArgumentException) {
            "unknown"
        }

        private fun describe(err: Throwable?): String {
            if (err is InterruptedException) return "timeout"
            return err?.message ?: "unknown error"
        }

        /** Remove the API key from a message if it somehow appears (defense in depth). */
        private fun scrub(msg: String, apiKey: String?): String = if (apiKey.isNullOrEmpty()) msg else msg.replace(apiKey, "[redacted]")
    }
}
