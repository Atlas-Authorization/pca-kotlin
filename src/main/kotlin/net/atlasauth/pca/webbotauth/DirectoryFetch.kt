package net.atlasauth.pca.webbotauth

import java.util.concurrent.TimeUnit
import net.atlasauth.pca.oauth.WhatwgUrl
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Fetch and strictly parse a Web Bot Auth key directory. FAIL-CLOSED: throws on a non-https URL, a redirect, a non-200 status, a wrong content type,
 * an oversize body, invalid JSON, or any key that is not a well-formed Ed25519 OKP JWK with a string `kid` and 32-byte `x`. Never returns a
 * partial directory.
 *
 * shortcut: a directory URL that carries credentials is refused (the reference would pass them on) and a fragment is dropped, as fetch does;
 * only http(s) URLs are accepted. Upgrade if a credentialed directory URL is ever needed.
 */
object DirectoryFetch {
    /** The part of an HTTP response the directory fetch reads. */
    interface Response {
        fun status(): Int

        /** The first value of a response header (case-insensitive), or null. */
        fun header(name: String): String?

        @Throws(Exception::class)
        fun text(): String
    }

    /** The HTTP client: inject your own for SSRF-safe egress. It must NOT follow redirects (a redirect is a failure). */
    fun interface Fetcher {
        @Throws(Exception::class)
        fun fetch(url: String, headers: Map<String, String>, timeoutMs: Long): Response
    }

    private val client by lazy { OkHttpClient.Builder().followRedirects(false).followSslRedirects(false).build() }

    /** The default [Fetcher]: OkHttp with redirects disabled; the body is read eagerly and the response closed. */
    @JvmStatic
    @Throws(Exception::class)
    fun httpFetch(url: String, headers: Map<String, String>, timeoutMs: Long): Response {
        val c = client.newBuilder().callTimeout(timeoutMs, TimeUnit.MILLISECONDS).build()
        val b = Request.Builder().url(url).get()
        for ((k, v) in headers) b.header(k, v)
        return c.newCall(b.build()).execute().use { r ->
            val status = r.code
            val hs = r.headers
            val body = r.body?.string() ?: ""
            object : Response {
                override fun status(): Int = status
                override fun header(name: String): String? = hs[name]
                override fun text(): String = body
            }
        }
    }

    /**
     * [options]: fetch ([Fetcher], default [httpFetch]), maxBytes (characters, default 65536), timeoutMs (default 5000),
     * allowInsecureHttp (tests only), requireSignature (require the signed directory response and return only the keys with a valid signature;
     * throws when none does), now (epoch seconds for the signature check).
     */
    @JvmStatic
    @JvmOverloads
    @Throws(Exception::class)
    fun fetchKeyDirectory(url: String, options: Map<String, Any?> = LinkedHashMap()): Map<String, Any?> {
        val u = WhatwgUrl.parse(url) ?: throw IllegalArgumentException("Invalid URL")
        if (u.origin() == "null") throw IllegalArgumentException("directory URL must be an http(s) URL")
        if (u.protocol != "https:" && !(options["allowInsecureHttp"] == true && u.protocol == "http:")) throw IllegalArgumentException("directory URL must be https")
        val hostport = u.host + (if (u.port.isEmpty()) "" else ":" + u.port)
        val hash = url.indexOf('#')
        val noFrag = if (hash >= 0) url.substring(0, hash) else url
        if (WbaJs.hasCredentials(noFrag)) throw IllegalArgumentException("directory URL must not carry credentials")
        val href = u.protocol + "//" + hostport + u.pathname + u.search + (if (u.search.isEmpty() && noFrag.indexOf('?') >= 0) "?" else "")
        val fetcher = options["fetch"] as? Fetcher ?: Fetcher { a, h, t -> httpFetch(a, h, t) }
        val timeout = if (options["timeoutMs"] != null) WbaJs.number(options["timeoutMs"]).toLong() else 5000L
        val headers = linkedMapOf("accept" to "application/http-message-signatures-directory+json")
        val res = fetcher.fetch(href, headers, timeout)
        if (res.status() != 200) throw IllegalStateException("directory fetch returned status " + res.status())
        val ct = WbaJs.lower(WbaJs.trim((res.header("content-type") ?: "").split(";")[0]))
        if (ct != "application/http-message-signatures-directory+json") throw IllegalStateException("directory has the wrong content type")
        val text = res.text()
        val max = if (options["maxBytes"] != null) WbaJs.number(options["maxBytes"]) else 65536.0
        if (text.length > max) throw IllegalStateException("directory response is too large")
        val directory = SignedDirectory.parseKeyDirectory(text)
        if (options["requireSignature"] == true) {
            val input = LinkedHashMap<String, Any?>()
            input["authority"] = WbaJs.lower(hostport)
            input["headers"] = linkedMapOf<String, Any?>("signature-input" to (res.header("signature-input") ?: ""), "signature" to (res.header("signature") ?: ""))
            input["body"] = text
            if (options["now"] != null) input["now"] = options["now"]
            val v = SignedDirectory.verifyDirectoryResponse(input)
            if (v["valid"] != true) throw IllegalStateException("directory signature: " + v["reason"])
            return linkedMapOf("keys" to v["keys"])
        }
        return directory
    }
}
