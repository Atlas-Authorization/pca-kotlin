package net.atlasauth.pca.connect

import java.util.Locale
import net.atlasauth.pca.connect.VaultError.RequestMismatchError
import net.atlasauth.pca.oauth.WhatwgUrl
import net.atlasauth.pca.verifier.Escalation
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.IntentArtifacts

/**
 * Vault proxy mode: re-derive the params digest of the OUTBOUND request, and the signed release receipt. The agent never holds the
 * credential: it hands the vault the request it wants made; the vault maps that request back to the action's parameters with a pinned
 * extractor and only then attaches the token. Anything the request carries that the extractor does not map is a mismatch.
 */
object Proxy {
    class ProxyRequest @JvmOverloads constructor(
        var method: String? = null,
        /** Absolute https URL. */
        var url: String? = null,
        /** Null when none. */
        var headers: Map<String, String>? = null,
        /** The body as text; null when none. */
        var body: String? = null,
    )

    class ProxyResponse @JvmOverloads constructor(
        var status: Int = 0,
        var headers: Map<String, String>? = LinkedHashMap(),
        var body: String? = null,
    )

    /** The injected outbound transport. It MUST NOT follow redirects (a redirect would send the credential to a host the extractor never saw). */
    fun interface ProxyFetch {
        fun call(method: String, url: String, headers: Map<String, String>, body: String?): ProxyResponse
    }

    class HttpRequestSpec {
        /** Exact method, upper case. */
        var method: String = ""

        /** `https://host/path/{param}/more`: literal text matches exactly; each `{name}` is one path segment. No query, no fragment. */
        var url: String = ""

        /** Query keys that may appear (null = none). */
        var query: List<String>? = null

        /** "json", "form", or null for no body. */
        var body: String? = null

        /** Body members the request always carries with exactly these values (null = none). */
        var fixed: Map<String, Any?>? = null
    }

    private fun mismatch(m: String) = RequestMismatchError("outbound request refused: $m")

    private val PLACEHOLDER = Regex("\\{([A-Za-z0-9_]+)\\}")

    /** Build the extractor for one operation. Throws on a malformed spec (at configuration time, not at call time). */
    fun httpExtractor(spec: HttpRequestSpec): (ProxyRequest) -> Map<String, Any?> {
        val probe = PLACEHOLDER.replace(spec.url, "x")
        val u = WhatwgUrl.parse(probe) ?: throw IllegalArgumentException("Invalid URL")
        if (u.protocol != "https:" || u.search.isNotEmpty() || UrlBits.hasFragment(probe) || UrlBits.hasCredentials(probe)) {
            throw IllegalArgumentException("httpExtractor: url must be https without query, fragment or userinfo")
        }
        if (spec.method != spec.method.uppercase(Locale.ROOT)) throw IllegalArgumentException("httpExtractor: method must be upper case")
        val names = ArrayList<String>()
        val origin = u.origin()
        val pathTemplate = spec.url.substring(Math.min(origin.length, spec.url.length))
        val re = StringBuilder()
        var last = 0
        for (pm in PLACEHOLDER.findAll(pathTemplate)) {
            if (pm.range.first > last) re.append(Regex.escape(pathTemplate.substring(last, pm.range.first)))
            names.add(pm.groupValues[1])
            re.append("([A-Za-z0-9._~%-]+)")
            last = pm.range.last + 1
        }
        if (last < pathTemplate.length) re.append(Regex.escape(pathTemplate.substring(last)))
        val pathRe = Regex(re.toString())
        val allowedQuery = HashSet<String>(spec.query ?: emptyList())
        val ctype = if ("json" == spec.body) "application/json" else if ("form" == spec.body) "application/x-www-form-urlencoded" else null
        val specBody = spec.body
        val specMethod = spec.method
        val specFixed: Map<String, Any?> = spec.fixed ?: LinkedHashMap()
        return fun(req: ProxyRequest): Map<String, Any?> {
            if (specMethod != req.method) throw mismatch("method ${req.method} is not $specMethod")
            val reqUrl = req.url
            val r = (if (reqUrl == null) null else WhatwgUrl.parse(reqUrl)) ?: throw mismatch("the url does not parse")
            if (r.origin() != origin || UrlBits.hasCredentials(reqUrl!!) || UrlBits.hasFragment(reqUrl)) throw mismatch("the url is not on the pinned origin")
            val m = pathRe.matchEntire(r.pathname) ?: throw mismatch("the path does not match the pinned template")
            val params = LinkedHashMap<String, Any?>()
            for (i in names.indices) {
                val dec = try {
                    JsText.decodeURIComponent(m.groupValues[i + 1])
                } catch (e: IllegalArgumentException) {
                    throw mismatch("a path segment is not valid percent-encoding")
                }
                put(params, names[i], dec)
            }
            val seen = HashSet<String>()
            val search = if (r.search.isEmpty()) "" else r.search.substring(1)
            for (kv in formParse(search)) {
                if (kv[0] !in allowedQuery) throw mismatch("query key '${kv[0]}' is not allowed")
                if (!seen.add(kv[0])) throw mismatch("query key '${kv[0]}' is repeated")
                put(params, kv[0], kv[1])
            }
            var ct: String? = null
            req.headers?.let { hs -> for ((k, v) in hs) if (k.lowercase(Locale.ROOT) == "content-type") { ct = v; break } }
            val body = req.body
            if (specBody == null) {
                if (body != null && body.isNotEmpty()) throw mismatch("this operation carries no body")
            } else {
                if (body == null || body.isEmpty()) throw mismatch("the body is missing")
                val c = ct
                if (c == null || JsText.trim(c.split(';')[0]).lowercase(Locale.ROOT) != ctype) throw mismatch("content-type must be $ctype")
                val fixed = LinkedHashMap<String, Any?>(specFixed)
                if (specBody == "json") {
                    val b = try {
                        Json.parse(body)
                    } catch (e: RuntimeException) {
                        throw mismatch("the body is not strict JSON")
                    }
                    if (b !is Map<*, *>) throw mismatch("the body must be a JSON object")
                    for ((k0, v) in b) {
                        val k = k0 as String
                        if (fixed.containsKey(k)) {
                            if (Pca.hashCanonical(v) != Pca.hashCanonical(fixed[k])) throw mismatch("fixed member '$k' has another value")
                            fixed.remove(k)
                        } else put(params, k, v)
                    }
                } else {
                    val keys = HashSet<String>()
                    for (kv in formParse(body)) {
                        if (!keys.add(kv[0])) throw mismatch("form key '${kv[0]}' is repeated")
                        if (fixed.containsKey(kv[0])) {
                            if (kv[1] != fixed[kv[0]]) throw mismatch("fixed member '${kv[0]}' has another value")
                            fixed.remove(kv[0])
                        } else put(params, kv[0], kv[1])
                    }
                }
                if (fixed.isNotEmpty()) throw mismatch("fixed member(s) " + fixed.keys.joinToString(", ") + " missing")
            }
            return params
        }
    }

    private fun put(params: MutableMap<String, Any?>, k: String, v: Any?) {
        if (params.containsKey(k)) throw mismatch("parameter '$k' is carried twice")
        params[k] = v
    }

    /** The application/x-www-form-urlencoded parser behind URLSearchParams: '+' is a space, invalid percent escapes stay literal, UTF-8 decoded leniently. */
    internal fun formParse(input: String): List<Array<String>> {
        val s = if (input.startsWith("?")) input.substring(1) else input
        val out = ArrayList<Array<String>>()
        if (s.isEmpty()) return out
        for (part in s.split('&')) {
            if (part.isEmpty()) continue
            val eq = part.indexOf('=')
            val k = if (eq < 0) part else part.substring(0, eq)
            val v = if (eq < 0) "" else part.substring(eq + 1)
            out.add(arrayOf(pctLenient(k.replace('+', ' ')), pctLenient(v.replace('+', ' '))))
        }
        return out
    }

    private fun pctLenient(s: String): String {
        if (s.indexOf('%') < 0) return s
        val out = java.io.ByteArrayOutputStream()
        val inp = Json.utf8(s)
        var i = 0
        while (i < inp.size) {
            if (inp[i] == '%'.code.toByte() && i + 2 < inp.size && hexv(inp[i + 1].toInt()) >= 0 && hexv(inp[i + 2].toInt()) >= 0) {
                out.write(hexv(inp[i + 1].toInt()) * 16 + hexv(inp[i + 2].toInt()))
                i += 2
            } else out.write(inp[i].toInt())
            i++
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    private fun hexv(c: Int): Int = when (c) {
        in '0'.code..'9'.code -> c - '0'.code
        in 'a'.code..'f'.code -> c - 'a'.code + 10
        in 'A'.code..'F'.code -> c - 'A'.code + 10
        else -> -1
    }

    /** Request headers the agent may set; the vault sets Authorization itself. Anything else is refused (Host, Cookie, X-HTTP-Method-Override, ...). */
    @JvmField val DEFAULT_PROXY_HEADERS: List<String> = listOf("content-type", "accept", "idempotency-key")

    fun checkProxyHeaders(headers: Map<String, String?>?, allow: List<String>): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        if (headers == null) return out
        for ((k, v) in headers) {
            val n = k.lowercase(Locale.ROOT)
            if (n !in allow) throw mismatch("header '$k' is not allowed")
            if (out.containsKey(n)) throw mismatch("header '$k' is repeated")
            if (v == null || v.indexOf('\r') >= 0 || v.indexOf('\n') >= 0 || v.indexOf('\u0000') >= 0) throw mismatch("header '$k' has an invalid value")
            out[n] = v
        }
        return out
    }

    // ---- release receipt ----

    const val RELEASE_RECEIPT_DOMAIN = "atlas-pca/connect-release-receipt/v1\u0000"

    /** Digest of the outbound request as made (method, url, headers sent, body). */
    fun outboundRequestDigest(method: String?, url: String?, headers: Map<String, String>, body: String?): String {
        val m = LinkedHashMap<String, Any?>()
        m["d"] = "atlas-pca/connect-request/v1"
        m["method"] = method
        m["url"] = url
        m["headers"] = LinkedHashMap<String, Any?>(headers)
        m["body"] = body
        return Pca.hashCanonical(m)
    }

    /** Sign a receipt body (`v, kind, action_digest, provider, connection_id, mode, scopes_released, request_digest, http_status, outcome, ts`) under the vault key. */
    fun signReleaseReceipt(body: Map<String, Any?>, vaultKey: Keys.EdKey): Map<String, Any?> =
        Issue.signArtifact(RELEASE_RECEIPT_DOMAIN, body, Keys.ed25519(vaultKey))

    /** True iff the receipt is signed by the pinned vault key. */
    fun verifyReleaseReceipt(receipt: Map<String, Any?>, vaultPk: String): Boolean =
        IntentArtifacts.verifyArtifactSig(RELEASE_RECEIPT_DOMAIN, receipt, vaultPk, null)

    /** Digest of the exact PCActn that authorized a release. */
    fun receiptActionDigest(pcActn: Map<String, Any?>): String = Escalation.actionDigest(pcActn)
}
