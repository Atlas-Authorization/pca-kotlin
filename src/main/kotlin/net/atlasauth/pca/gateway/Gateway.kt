package net.atlasauth.pca.gateway

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Locale
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.siem.JsFmt
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.CaveatLang
import net.atlasauth.pca.verifier.PcaCore
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * Proof-Carrying Authority enforcement at the gateway / service mesh: every inbound request is verified against the PCActn it carries
 * (header `PCA-Action`), the route's required capability, the request binding and a single-use guard, DENY-BY-DEFAULT at every step.
 * The request, the Envoy ext_authz and the Lambda authorizer shapes are plain Maps (a JSON tree: Map / List / String / Boolean /
 * Json.Num / null), so any gateway SDK adapts in a few lines. Verification goes through the native core ([Pca], [Authorize]).
 *
 * Differences from the TypeScript reference, all fail-closed: only the `revocation` verifier hook exists (attestation, threshold and
 * zk hooks and the opt-in enforcement gates are not offered, so a requireChecks entry for them reads "not-enforced" and denies); the
 * verdict a decision carries lists the checks as pass / fail / not-enforced in the native core's order, not the reference's; the
 * Cloudflare Worker adapter is the runtime-free [GatewayWorker].
 */
@Suppress("UNCHECKED_CAST")
object Gateway {
    /** The header carrying the base64url PCActn. */
    const val PCA_HEADER = "PCA-Action"

    /** Every header an allow may inject upstream (a gateway that only forwards present headers cannot erase a client-supplied copy). */
    val PCA_INJECTED_HEADERS: List<String> = listOf("x-pca-verdict", "x-pca-verb", "x-pca-grant")

    /** A JavaScript `undefined` (an absent member): JSON null stays Kotlin null. */
    private val UNDEF = Any()

    /** The marker [presentedProvenance] returns when the request presents no provenance (JSON null is a presented, unreadable one). */
    val ABSENT: Any = UNDEF

    // ---- configuration types ----

    /** The capability a route requires of a verified PCActn: a PCA verb, optionally bound to a resource (exact match). */
    class RequiredCapability(val verb: String, val resource: String? = null)

    /** One route to capability rule; the first matching rule wins. `method` null / "*" / "ANY" matches any method. */
    class RouteRule(val method: String?, val path: String, val capability: RequiredCapability)

    /** Which request attributes are bound into the proof (method, path and query always are). */
    class BindRequestOptions {
        /** Also bind the request authority (requires [GatewayRequest.authority]). */
        var authority: Boolean = false

        /** true: bind the body hash (requires bodySha256); false: never; null (default): bind it whenever the request carries one. */
        var body: Boolean? = null
    }

    /** The subset of an inbound request the gateway needs. `headers` values are a String, a List of Strings or null. */
    class GatewayRequest @JvmOverloads constructor(
        var method: String? = null,
        /** Request path without the query string. */
        var path: String? = null,
        headers: Map<String, Any?>? = null,
    ) {
        /** Raw query string without the "?". */
        var query: String? = null
        var authority: String? = null

        /** Lower-case hex SHA-256 of the body, when the caller can supply it. */
        var bodySha256: String? = null

        /** The raw body text (read only by full-policy mode with the body as params). */
        var body: String? = null
        var headers: Map<String, Any?> = headers ?: LinkedHashMap()
    }

    /** Single-use store for proofs: atomically claim `key` until `expiresAtMs`; true if first use. */
    fun interface ReplayGuard {
        fun claim(key: String, expiresAtMs: Double, nowMs: Double?): Boolean
    }

    /** The gateway's per-session log of untrusted content it relayed (`{origin, source}` observations). */
    interface ProvenanceLog {
        fun seen(session: String): List<Map<String, Any?>>
        fun add(session: String, observation: Map<String, Any?>)
    }

    /** The outcome of the revocation verifier hook. */
    class HookResult(val enforced: Boolean, val ok: Boolean, val reason: String?)

    /** The revocation verifier hook: runs after the core checks; a throw fails the check. */
    fun interface RevocationHook {
        fun check(pcactn: Map<String, Any?>, grant: Map<String, Any?>, now: Long): HookResult
    }

    /** Resolves a grant_ref (any JSON value) to the root capability the chain must descend from; null for an unknown grant. */
    fun interface GrantResolver {
        fun resolve(grantRef: Any?, pcactn: Map<String, Any?>): Map<String, Any?>?
    }

    /** Context handed to the checkProof hook. */
    class ProofCheckContext internal constructor(
        val pcactn: Map<String, Any?>,
        val grant: Map<String, Any?>,
        val verdict: Map<String, Any?>,
        val request: GatewayRequest,
        val required: RequiredCapability?,
    )

    /** Per-proof policy hook: return Boolean, or a Map {allow, reason?}. false / {allow: false} / a throw denies. */
    fun interface CheckProof {
        fun check(ctx: ProofCheckContext): Any?
    }

    /**
     * Full-policy mode: the grant's limits are evaluated against the real params by [Authorize.authorize], with revocation and replay
     * required. The agent signs the params plus the request binding (see [bindParams]).
     */
    class FullPolicy {
        /** true (default): the params are the request body (strict JSON object). */
        var paramsFromBody: Boolean = true

        /** Used instead of the body when set; a null return denies. */
        var paramsFn: ((GatewayRequest) -> Map<String, Any?>?)? = null
        var state: Authorize.StateStore? = null
        var isRevoked: ((Map<String, Any?>, Map<String, Any?>) -> Any?)? = null

        /** `"single-step"`, or null with [context] returning the authorized plan (see [Authorize.Input]). */
        var plan: String? = null
        var context: ((Map<String, Any?>) -> Map<String, Any?>?)? = null
        var intentPolicy: Pca.IntentPolicy? = null
        var allowedSuites: List<String>? = null
        var require: List<String> = emptyList()

        /** The attestation and zk compliance verifier hooks ([Authorize.Input.attestation], [Authorize.Input.zk]). */
        var attestation: PcaCore.Hook? = null
        var zk: PcaCore.Hook? = null

        /** Caveat language v2 input (pins, history, ...) merged under the presented discharges / narrow; null: every K1 caveat refuses. */
        var k1: Map<String, Any?>? = null
        var k1Fn: ((GatewayRequest, Map<String, Any?>) -> Map<String, Any?>?)? = null

        /** Builds the provenance gate from the gateway's joined `observed` (the log of what it let through); null: a default gate. */
        var provenanceGate: ((Observed?) -> Authorize.ProvenanceOptions)? = null

        /** The per-gateway log of relayed untrusted content; null: an in-memory one. */
        var provenanceLog: ProvenanceLog? = null

        /** true turns the log off. */
        var provenanceLogOff: Boolean = false
    }

    /** Gateway configuration. */
    class GatewayOptions {
        /** This gateway's audience (the RFC 8707 resource): a proof minted for another audience is denied. */
        var audience: String? = null
        var routes: MutableList<RouteRule> = ArrayList()
        var resolveGrant: GrantResolver? = null
        var authorizedPlanRoots: List<String>? = null
        var insecureSkipPlanRootCheck: Boolean = false

        /** "deny" (default), "allow" or "require-proof". */
        var unmatchedRoute: String? = null
        var replayGuard: ReplayGuard? = null

        /** Request binding options (null: the default `{}`); see [bindRequestOff]. */
        var bindRequest: BindRequestOptions? = null

        /** true: no request binding (the proof is then a bearer for the matched route). */
        var bindRequestOff: Boolean = false
        var revocation: RevocationHook? = null

        /** Core checks that must report pass (null: ["revocation"] in signature-only mode, none in full mode). */
        var requireChecks: List<String>? = null
        var checkProof: CheckProof? = null

        /** "strict" (default) or "off". */
        var pathPolicy: String? = null
        var now: (() -> Long)? = null
        var realm: String? = null

        /** "full", "signature-only" or null (a misconfiguration that denies every request). */
        var policyMode: String? = null
        var full: FullPolicy? = null
        private var defaultLog: ProvenanceLog? = null

        internal fun defaultLog(): ProvenanceLog = synchronized(this) {
            defaultLog ?: memoryProvenanceLog(10_000).also { defaultLog = it }
        }
    }

    /** Machine-readable outcome codes of [authorize]. */
    class Decision internal constructor(
        val allow: Boolean,
        /** 200 allow, 400 invalid path, 401 unauthenticated, 403 forbidden, 503 replay guard unavailable. */
        val status: Int,
        val code: String,
        val reason: String,
        val headers: Map<String, String>,
        /** {allow, checks, reason?}, when a PCActn was decoded and verified. */
        val verdict: Map<String, Any?>?,
        val pcactn: Map<String, Any?>?,
        val matched: RequiredCapability?,
        /** Full-policy mode: the full verifier's verdict {allow, checks, reasons}. */
        val policyVerdict: Map<String, Any?>?,
    ) {
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["allow"] = allow
            m["status"] = Json.Num(status.toString())
            m["code"] = code
            m["reason"] = reason
            m["headers"] = LinkedHashMap<String, Any?>(headers)
            if (verdict != null) m["verdict"] = verdict
            if (pcactn != null) m["pcactn"] = pcactn
            if (matched != null) {
                val r = LinkedHashMap<String, Any?>()
                r["verb"] = matched.verb
                if (matched.resource != null) r["resource"] = matched.resource
                m["matched"] = r
            }
            if (policyVerdict != null) m["policyVerdict"] = policyVerdict
            return m
        }
    }

    // ---- JavaScript text helpers ----

    private fun g(o: Any?, k: String): Any? = if (o is Map<*, *>) (if (o.containsKey(k)) o[k] else UNDEF) else UNDEF

    private fun jsStr(v: Any?): String = if (v === UNDEF) "undefined" else JsFmt.str(v)

    private fun errMsg(e: Throwable): String = e.message ?: e.toString()

    private const val HEX = "0123456789ABCDEF"

    /** `encodeURIComponent`: unreserved characters and `!'()*` stay; the rest is percent-encoded UTF-8; a lone surrogate throws. */
    internal fun encodeURIComponent(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            val cp: Int
            if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
                cp = Character.toCodePoint(c, s[i + 1])
                i += 2
            } else if (Character.isSurrogate(c)) {
                throw IllegalArgumentException("URI malformed")
            } else {
                cp = c.code
                i++
            }
            if (cp < 128 && (Character.isLetterOrDigit(cp) || "-_.!~*'()".indexOf(cp.toChar()) >= 0)) {
                sb.append(cp.toChar())
                continue
            }
            for (b in Json.utf8(String(Character.toChars(cp)))) {
                val v = b.toInt() and 0xFF
                sb.append('%').append(HEX[v shr 4]).append(HEX[v and 15])
            }
        }
        return sb.toString()
    }

    private fun hexVal(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    private fun pctByte(s: String, i: Int): Int {
        if (i + 2 >= s.length || s[i] != '%') throw IllegalArgumentException("URI malformed")
        val h = hexVal(s[i + 1])
        val l = hexVal(s[i + 2])
        if (h < 0 || l < 0) throw IllegalArgumentException("URI malformed")
        return (h shl 4) or l
    }

    /** `decodeURIComponent`: every `%XX` must be hex and the bytes well-formed UTF-8, else it throws. */
    internal fun decodeURIComponent(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c != '%') {
                sb.append(c)
                i++
                continue
            }
            if (i + 2 >= s.length) throw IllegalArgumentException("URI malformed")
            val b = pctByte(s, i)
            i += 3
            if (b < 0x80) {
                sb.append(b.toChar())
                continue
            }
            val n = if ((b and 0xE0) == 0xC0) 2 else if ((b and 0xF0) == 0xE0) 3 else if ((b and 0xF8) == 0xF0) 4 else 0
            if (n == 0) throw IllegalArgumentException("URI malformed")
            var cp = if (n == 2) b and 0x1F else if (n == 3) b and 0x0F else b and 0x07
            for (k in 1 until n) {
                if (i + 2 >= s.length) throw IllegalArgumentException("URI malformed")
                val nb = pctByte(s, i)
                if ((nb and 0xC0) != 0x80) throw IllegalArgumentException("URI malformed")
                cp = (cp shl 6) or (nb and 0x3F)
                i += 3
            }
            val ok = if (n == 2) cp >= 0x80 else if (n == 3) cp >= 0x800 && (cp < 0xD800 || cp > 0xDFFF) else cp >= 0x10000 && cp <= 0x10FFFF
            if (!ok) throw IllegalArgumentException("URI malformed")
            sb.appendCodePoint(cp)
        }
        return sb.toString()
    }

    // ---- request binding ----

    /**
     * Canonical query: strip a leading "?", drop empty pairs, sort the raw (still percent-encoded) pairs, join with "&". Throws when the
     * query is ambiguous across upstream parsers: a repeated parameter name (percent-decoded, "+" as space, case-insensitive), a ";"
     * separator, or a malformed percent escape in a name.
     */
    @JvmStatic
    fun canonicalQuery(query: String?): String {
        if (query == null) return ""
        val q = if (query.startsWith("?")) query.substring(1) else query
        if (q.indexOf(';') >= 0) throw IllegalArgumentException("query contains ';' (parsers disagree on it as a separator)")
        val pairs = ArrayList<String>()
        for (p in q.split("&")) if (p.isNotEmpty()) pairs.add(p)
        val seen = LinkedHashSet<String>()
        for (pair in pairs) {
            val eq = pair.indexOf('=')
            val rawKey = if (eq < 0) pair else pair.substring(0, eq)
            val key = try {
                decodeURIComponent(rawKey.replace('+', ' ')).lowercase(Locale.ROOT)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("query parameter name has a malformed percent escape")
            }
            if (!seen.add(key)) throw IllegalArgumentException("duplicate query parameter '$key'")
        }
        pairs.sort()
        return pairs.joinToString("&")
    }

    /**
     * The canonical binding of a request: upper-cased method, the path, the canonical query and optionally the authority and the body
     * hash. Agents pass this object as the action params so params_digest commits to it; the gateway recomputes it from the live request.
     */
    @JvmStatic
    @JvmOverloads
    fun requestBinding(req: GatewayRequest, opts: BindRequestOptions? = null): Map<String, Any?> {
        val o = opts ?: BindRequestOptions()
        val b = LinkedHashMap<String, Any?>()
        b["v"] = Json.Num("2")
        b["method"] = req.method!!.uppercase(Locale.ROOT)
        b["path"] = req.path
        b["query"] = canonicalQuery(req.query)
        if (o.authority) b["authority"] = (req.authority ?: "").lowercase(Locale.ROOT)
        if (o.body == true || (o.body == null && req.bodySha256 != null)) b["body_sha256"] = (req.bodySha256 ?: "").lowercase(Locale.ROOT)
        return b
    }

    /** The params an agent signs for a full-policy gateway: the params plus the request binding as a "binding" member (null binding: the params). */
    @JvmStatic
    fun bindParams(params: Map<String, Any?>, binding: Map<String, Any?>?): Map<String, Any?> {
        if (binding == null) return params
        if (params.containsKey("binding")) throw IllegalArgumentException("params already have a 'binding' member")
        val out = LinkedHashMap(params)
        out["binding"] = binding
        return out
    }

    // ---- replay guard, provenance log ----

    /**
     * In-process replay guard (per process: use a shared store for a fleet). A claim stays live through `expiresAtMs` inclusive. Fails
     * CLOSED when `maxEntries` unexpired claims are held (throws) rather than evicting a live claim.
     */
    @JvmStatic
    @JvmOverloads
    fun memoryReplayGuard(maxEntries: Int, now: (() -> Long)? = null): ReplayGuard {
        val clock: () -> Long = now ?: { System.currentTimeMillis() }
        val seen = LinkedHashMap<String, Double>()
        return ReplayGuard { key, expiresAtMs, nowMs ->
            synchronized(seen) {
                val t = nowMs ?: clock().toDouble()
                // a clock or expiry that is not finite cannot say whether a claim is still live: refuse (the gateway turns a throw into a deny)
                if (!t.isFinite() || !expiresAtMs.isFinite()) throw IllegalStateException("replay guard: the clock and the claim expiry must be finite numbers")
                if (seen.size >= maxEntries) {
                    val it = seen.entries.iterator()
                    while (it.hasNext()) if (it.next().value < t) it.remove()
                    if (seen.size >= maxEntries) throw IllegalStateException("replay guard full")
                }
                val existing = seen[key]
                if (existing != null && existing >= t) {
                    false
                } else {
                    seen[key] = expiresAtMs
                    true
                }
            }
        }
    }

    private fun strictEq(a: Any?, b: Any?): Boolean {
        if (a === UNDEF || b === UNDEF) return a === b
        if (a == null || b == null) return a == null && b == null
        val x = Js.num(a)
        val y = Js.num(b)
        if (x != null || y != null) return x != null && y != null && x == y
        if (a is String || a is Boolean) return a == b
        return a === b
    }

    /** An in-memory [ProvenanceLog]: at most `maxSessions` sessions (oldest dropped first), 256 observations each. */
    @JvmStatic
    fun memoryProvenanceLog(maxSessions: Int): ProvenanceLog {
        val m = LinkedHashMap<String, MutableList<Map<String, Any?>>>()
        return object : ProvenanceLog {
            override fun seen(session: String): List<Map<String, Any?>> = synchronized(m) {
                val out = ArrayList<Map<String, Any?>>()
                m[session]?.forEach { out.add(LinkedHashMap(it)) }
                out
            }

            override fun add(session: String, observation: Map<String, Any?>) {
                synchronized(m) {
                    val cur = m.remove(session) ?: ArrayList()
                    var dup = false
                    for (x in cur) if (strictEq(g(x, "origin"), g(observation, "origin")) && strictEq(g(x, "source"), g(observation, "source"))) dup = true
                    if (!dup && cur.size < 256) {
                        val n = LinkedHashMap<String, Any?>()
                        if (observation.containsKey("origin")) n["origin"] = observation["origin"]
                        if (observation.containsKey("source")) n["source"] = observation["source"]
                        cur.add(n)
                    }
                    m[session] = cur
                    while (m.size > maxSessions) m.remove(m.keys.iterator().next())
                }
            }
        }
    }

    // ---- headers, presented artifacts ----

    /** Case-insensitive single-value header lookup: the first value of a repeated header; null when absent. */
    internal fun getHeader(headers: Map<String, Any?>, name: String): String? {
        val lower = name.lowercase(Locale.ROOT)
        for ((k, v) in headers) {
            if (k.lowercase(Locale.ROOT) != lower) continue
            if (v is List<*>) return if (v.isEmpty() || v[0] !is String) null else v[0] as String
            return v as? String
        }
        return null
    }

    /** The header text decoded strictly (unpadded base64url, well-formed UTF-8): the text, or an error message. */
    private fun decodeHeaderText(value: String): Pair<String?, String> {
        if (value.isEmpty()) return Pair(null, "PCA-Action header is empty")
        val raw = Pca.decodeB64uStrict(value, -1) ?: return Pair(null, "PCA-Action header is not strict unpadded base64url")
        return try {
            Pair(
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString(),
                "",
            )
        } catch (e: CharacterCodingException) {
            Pair(null, "PCA-Action header does not decode to UTF-8 text")
        }
    }

    /** A strictly parsed JSON object of the body, or null when the body is not a non-empty JSON object. */
    private fun bodyObject(req: GatewayRequest): Map<String, Any?>? {
        val b = req.body
        if (b == null || b.isEmpty()) return null
        return try {
            Json.parse(b) as? Map<String, Any?>
        } catch (e: RuntimeException) {
            null
        }
    }

    private fun strictHeaderValue(h: String): Any? {
        val (text, err) = decodeHeaderText(h)
        if (text == null) throw IllegalArgumentException(err)
        return Json.parse(text)
    }

    /**
     * The provenance bundle a request presents: header PCA-Provenance (strict base64url JSON; unreadable gives null), else body member
     * pca_provenance when the body is not the signed params. [ABSENT] when none.
     */
    @JvmStatic
    fun presentedProvenance(req: GatewayRequest, policy: FullPolicy): Any? {
        val h = getHeader(req.headers, "pca-provenance")
        if (h != null && h.isNotEmpty()) {
            return try { strictHeaderValue(h) } catch (e: RuntimeException) { null }
        }
        if (!policy.paramsFromBody || policy.paramsFn != null) {
            val b = bodyObject(req)
            if (b != null && b.containsKey("pca_provenance")) return b["pca_provenance"]
        }
        return ABSENT
    }

    /** The discharges and narrow block a request presents (headers, then body members when the body is not the signed params). */
    @JvmStatic
    fun presentedArtifacts(req: GatewayRequest, policy: FullPolicy): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        val d = getHeader(req.headers, "pca-discharges")
        if (d != null && d.isNotEmpty()) {
            try {
                val arr = strictHeaderValue(d)
                if (arr is List<*>) out["discharges"] = arr
            } catch (e: RuntimeException) { /* unreadable: no discharges */ }
        }
        val n = getHeader(req.headers, "pca-narrow")
        if (n != null && n.isNotEmpty()) {
            try { out["narrow"] = strictHeaderValue(n) } catch (e: RuntimeException) { /* unreadable: no narrow block */ }
        }
        if (!policy.paramsFromBody || policy.paramsFn != null) {
            val b = bodyObject(req)
            if (b != null) {
                if (!out.containsKey("discharges") && b["pca_discharges"] is List<*>) out["discharges"] = b["pca_discharges"]
                if (!out.containsKey("narrow") && b.containsKey("pca_narrow")) out["narrow"] = b["pca_narrow"]
            }
        }
        return out
    }

    // ---- path hardening, route matching ----

    private val PCT = Regex("%([0-9a-fA-F]{2})")
    private val BAD_PCT = Regex("%(?![0-9a-fA-F]{2})")

    /**
     * Why `path` is ambiguous for route matching (dot segments, "//", backslashes, control characters, ";" parameters, encoded
     * delimiters or unreserved characters, malformed escapes), or null when canonical.
     */
    @JvmStatic
    fun ambiguousPathReason(path: String): String? {
        for (c in path) if (c.code <= 0x1f || c.code == 0x7f || c == '\\') return "control character or backslash in path"
        if (path.contains("//")) return "repeated slash in path"
        if (path.indexOf(';') >= 0) return "path parameter (;) in path"
        for (seg in path.split("/")) if (seg == "." || seg == "..") return "dot segment in path"
        for (m in PCT.findAll(path)) {
            val code = m.groupValues[1].toInt(16)
            val ch = code.toChar()
            if (code < 0x20 || code == 0x7f) return "percent-encoded control character in path"
            if (ch == '/' || ch == '\\') return "percent-encoded slash in path"
            if (ch == ';') return "percent-encoded path parameter delimiter in path"
            if ((ch in 'A'..'Z') || (ch in 'a'..'z') || (ch in '0'..'9') || ch == '-' || ch == '.' || ch == '_' || ch == '~') return "non-canonical percent-encoding in path"
        }
        if (BAD_PCT.containsMatchIn(path)) return "malformed percent-encoding in path"
        return null
    }

    private fun matchMethod(rule: RouteRule, method: String): Boolean {
        val m = rule.method
        if (m == null || m == "*" || m.uppercase(Locale.ROOT) == "ANY") return true
        return m.uppercase(Locale.ROOT) == method.uppercase(Locale.ROOT)
    }

    private fun matchPath(pattern: String, path: String): Boolean {
        if (pattern == "*" || pattern == "/*") return true
        if (pattern.endsWith("/*")) {
            val prefix = pattern.substring(0, pattern.length - 2)
            return path == prefix || path.startsWith("$prefix/")
        }
        if (pattern.endsWith("*")) return path.startsWith(pattern.substring(0, pattern.length - 1))
        return path == pattern
    }

    private fun matchRoute(routes: List<RouteRule>, method: String, path: String): RouteRule? {
        for (r in routes) if (matchMethod(r, method) && matchPath(r.path, path)) return r
        return null
    }

    // ---- decisions ----

    private fun errorToken(code: String): String = when (code) {
        "no-proof" -> "missing_proof"
        "invalid-proof", "unknown-grant", "verify-failed" -> "invalid_proof"
        "wrong-audience" -> "invalid_resource"
        "insufficient-capability" -> "insufficient_capability"
        "unmapped-route", "proof-rejected" -> "access_denied"
        "invalid-path" -> "invalid_request"
        "replayed-proof" -> "replayed_proof"
        "replay-guard-unavailable" -> "temporarily_unavailable"
        "request-mismatch" -> "proof_not_bound_to_request"
        else -> throw IllegalArgumentException(code)
    }

    private fun deny(
        code: String, status: Int, reason: String, realm: String?, verdict: Map<String, Any?>? = null, pcactn: Map<String, Any?>? = null,
        matched: RequiredCapability? = null, policyVerdict: Map<String, Any?>? = null,
    ): Decision {
        val headers = LinkedHashMap<String, String>()
        headers["www-authenticate"] = "PCA realm=\"$realm\", error=\"${errorToken(code)}\""
        return Decision(false, status, code, reason, headers, verdict, pcactn, matched, policyVerdict)
    }

    private fun allowDecision(reason: String, verdict: Map<String, Any?>?, pcactn: Map<String, Any?>?, matched: RequiredCapability?, policyVerdict: Map<String, Any?>?): Decision {
        val headers = LinkedHashMap<String, String>()
        if (verdict != null) headers["x-pca-verdict"] = JsFmt.stringify(verdict)
        if (pcactn != null) {
            headers["x-pca-verb"] = jsStr(g(g(pcactn, "action"), "verb"))
            headers["x-pca-grant"] = jsStr(g(pcactn, "grant_ref"))
        }
        return Decision(true, 200, "allow", reason, headers, verdict, pcactn, matched, policyVerdict)
    }

    private fun verdictMap(allow: Boolean, checks: Map<String, String?>, reason: String?): Map<String, Any?> {
        val v = LinkedHashMap<String, Any?>()
        v["allow"] = allow
        v["checks"] = LinkedHashMap<String, Any?>(checks)
        if (!reason.isNullOrEmpty()) v["reason"] = reason
        return v
    }

    // ---- configuration checks ----

    private val DEFAULT_REQUIRE_CHECKS = listOf("revocation")

    private fun missingText(opts: GatewayOptions, missing: List<String>): String {
        val mode = opts.policyMode
        return (if (mode == null || mode == "signature-only") "the gateway" else "full policy mode") + " is missing " + missing.joinToString(", ")
    }

    /** What is missing from the configuration (empty when complete). */
    private fun missingPolicy(opts: GatewayOptions): List<String> {
        val mode = opts.policyMode
        val m = ArrayList<String>()
        if (mode == null) {
            m.add("policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })")
            return m
        }
        if (mode == "signature-only") {
            if (opts.replayGuard == null) m.add("replayGuard (signature-only mode needs a single-use guard)")
            if ((opts.requireChecks ?: DEFAULT_REQUIRE_CHECKS).contains("revocation") && opts.revocation == null) {
                m.add("hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)")
            }
            return m
        }
        if (mode != "full") {
            m.add("a known policy mode (got '$mode')")
            return m
        }
        val f = opts.full ?: FullPolicy()
        for (c in Authorize.missingAuthorizeComponents(opts.audience, opts.resolveGrant, f.state, f.isRevoked)) m.add(if (c == "stateStore") "state" else c)
        if (!f.paramsFromBody && f.paramsFn == null) m.add("params ('body' or a function)")
        return m
    }

    private fun isEmpty(s: String?): Boolean = s == null || s.isEmpty()

    /** Full-policy mode: the params the agent must have signed for this request: (params, null) or (null, error). */
    private fun signedParams(req: GatewayRequest, policy: FullPolicy, bind: BindRequestOptions, bindOff: Boolean): Pair<Map<String, Any?>?, String?> {
        val params: Any?
        val fn = policy.paramsFn
        if (fn == null && policy.paramsFromBody) {
            val body = req.body ?: return Pair(null, "full policy mode reads the params from the body, and the request carries none")
            params = try {
                Json.parse(body)
            } catch (e: RuntimeException) {
                return Pair(null, "the body is not strict JSON: " + errMsg(e))
            }
        } else {
            params = fn!!(req)
        }
        if (params !is Map<*, *>) return Pair(null, "the request params are not a JSON object")
        val obj = params as Map<String, Any?>
        if (bindOff) return Pair(obj, null)
        if (obj.containsKey("binding")) return Pair(null, "the request params carry a 'binding' member (reserved for the request binding)")
        if ((bind.authority && isEmpty(req.authority)) || (bind.body == true && isEmpty(req.bodySha256))) {
            return Pair(null, "request lacks an attribute the proof must bind (authority / body hash)")
        }
        return try {
            val b = BindRequestOptions()
            b.authority = bind.authority
            b.body = bind.body == true
            val out = LinkedHashMap(obj)
            out["binding"] = requestBinding(req, b)
            Pair(out, null)
        } catch (e: RuntimeException) {
            Pair(null, "the request cannot be bound: " + errMsg(e))
        }
    }

    // ---- the core ----

    private fun decodePcactn(raw: String): Pair<Map<String, Any?>?, String> {
        val (text, err) = decodeHeaderText(raw)
        if (text == null) return Pair(null, err)
        if (Pca.artifactTooLarge(text)) return Pair(null, Pca.ARTIFACT_SIZE_REASON)
        val v = try {
            Json.parse(text)
        } catch (e: RuntimeException) {
            return Pair(null, errMsg(e))
        }
        if (v !is Map<*, *>) return Pair(null, "decodePCActn: not an object")
        return Pair(v as Map<String, Any?>, "")
    }

    /**
     * The framework-agnostic core: extract the PCActn from the headers, map (method, path) to the required capability, verify the proof
     * offline (fail closed) with the audience bound to this gateway, enforce the route's capability and the request binding, run the
     * required checks, the per-proof hook, full-policy mode when configured and the single-use guard. DENY-BY-DEFAULT at every step.
     */
    @JvmStatic
    fun authorize(req: GatewayRequest, opts: GatewayOptions): Decision {
        val realm = opts.realm ?: opts.audience
        val unmatched = opts.unmatchedRoute ?: "deny"
        val method = req.method!!
        val reqPath = req.path!!

        // 0. Ambiguous request targets are never matched against the route map.
        if (opts.pathPolicy == null || opts.pathPolicy == "strict") {
            val bad = ambiguousPathReason(reqPath)
            if (bad != null) return deny("invalid-path", 400, bad, realm)
        }

        // 1. Route to required capability.
        val rule = matchRoute(opts.routes, method, reqPath)
        if (rule == null) {
            if (unmatched == "allow") return allowDecision("route $method $reqPath is unmapped (unmatchedRoute=allow)", null, null, null, null)
            if (unmatched == "deny") return deny("unmapped-route", 403, "no capability mapping for $method $reqPath (deny-by-default)", realm)
        }
        val required = rule?.capability

        // 2. Extract the proof (fail closed).
        val raw = getHeader(req.headers, PCA_HEADER)
        if (raw == null || raw.isEmpty()) return deny("no-proof", 401, "no $PCA_HEADER header", realm)
        val (decoded, err) = decodePcactn(raw)
        if (decoded == null) return deny("invalid-proof", 401, "undecodable $PCA_HEADER header: $err", realm)
        val pcactn: Map<String, Any?> = decoded

        // 3. Resolve the grant the chain must root in; unknown grant denies.
        val ref = g(pcactn, "grant_ref")
        val grant = opts.resolveGrant?.resolve(if (ref === UNDEF) null else ref, pcactn)
            ?: return deny("unknown-grant", 401, "unknown grant_ref " + jsStr(ref), realm, null, pcactn)

        // 3b. A configuration with a missing component denies every request (fail closed).
        val missingCfg = missingPolicy(opts)
        if (missingCfg.isNotEmpty()) return deny("proof-rejected", 403, missingText(opts, missingCfg) + " (fail closed)", realm, null, pcactn)

        // 4. Offline verification (fail closed), audience bound to THIS gateway.
        val now = opts.now?.invoke() ?: System.currentTimeMillis()
        val aud = opts.audience
        val v = Pca.verifyPcactn(
            pcactn, grant, now, if (aud == null) Pca.Audience.Unset else Pca.Audience.Of(aud),
            authorizedPlanRoots = opts.authorizedPlanRoots, insecureSkipPlanRootCheck = opts.insecureSkipPlanRootCheck,
        )
        val statuses = LinkedHashMap<String, String?>()
        for ((k, b) in v.checks) statuses[k] = if (b) "pass" else "fail"
        for (k in v.notEnforced) if (!statuses.containsKey(k)) statuses[k] = "not-enforced"
        statuses["attestation"] = "not-enforced"
        statuses["threshold"] = "not-enforced"
        var revStatus: String? = "not-enforced"
        var allow = v.allow
        var reason: String? = v.reason
        val rev = opts.revocation
        if (rev != null) {
            try {
                val hr = rev.check(pcactn, grant, now)
                if (!hr.enforced) {
                    revStatus = "not-enforced"
                } else if (hr.ok) {
                    revStatus = "pass"
                } else {
                    revStatus = "fail"
                    if (allow) {
                        allow = false
                        reason = "revocation: " + (hr.reason ?: "rejected")
                    }
                }
            } catch (e: Exception) {
                // the reference reports a hook that throws as a malformed PCActn
                revStatus = null
                statuses["malformed"] = "fail"
                if (allow) {
                    allow = false
                    reason = "malformed PCActn: " + errMsg(e)
                }
            }
        }
        if (revStatus != null) statuses["revocation"] = revStatus
        statuses["taint_gate"] = "not-enforced"
        val verdict = verdictMap(allow, statuses, reason)
        if (!allow) {
            val audienceFailed = v.checks["audience"] == false
            return deny(
                if (audienceFailed) "wrong-audience" else "verify-failed", if (audienceFailed) 403 else 401,
                if (!reason.isNullOrEmpty()) reason else "PCActn verification failed", realm, verdict, pcactn,
            )
        }

        // 5. Capability enforcement: the verified proof must carry the verb (+ resource) the route requires.
        val action = g(pcactn, "action")
        val proofVerb = g(action, "verb")
        val proofResource = g(action, "resource")
        if (required != null) {
            if (!strictEq(proofVerb, required.verb)) {
                return deny("insufficient-capability", 403, "route requires capability '${required.verb}' but the proof authorizes '${jsStr(proofVerb)}'", realm, verdict, pcactn, required, null)
            }
            if (required.resource != null && !strictEq(proofResource, required.resource)) {
                return deny("insufficient-capability", 403, "route is bound to resource '${required.resource}' but the proof targets '${jsStr(proofResource)}'", realm, verdict, pcactn, required, null)
            }
        }

        val policy: FullPolicy? = if (opts.policyMode == "full") (opts.full ?: FullPolicy()) else null
        var fullParams: Map<String, Any?>? = null
        val proofDigest = g(action, "params_digest")
        if (policy != null) {
            // 5b (full). The agent signed the real params plus the request binding: rebuild them from THIS request.
            val (sp, spErr) = signedParams(req, policy, opts.bindRequest ?: BindRequestOptions(), opts.bindRequestOff)
            if (spErr != null) return deny("request-mismatch", 403, spErr, realm, verdict, pcactn)
            if (!strictEq(proofDigest, Pca.paramsDigest(sp))) {
                return deny("request-mismatch", 403, "the proof is not bound to this request (params/method/path/query/authority)", realm, verdict, pcactn)
            }
            fullParams = sp
        } else if (!opts.bindRequestOff) {
            // 5b. Request binding: the signed params digest must be the digest of THIS request.
            val b = opts.bindRequest ?: BindRequestOptions()
            if ((b.authority && isEmpty(req.authority)) || (b.body == true && isEmpty(req.bodySha256))) {
                return deny("request-mismatch", 403, "request lacks an attribute the proof must bind (authority / body hash)", realm, verdict, pcactn)
            }
            val bound = try {
                Pca.paramsDigest(requestBinding(req, b))
            } catch (e: RuntimeException) {
                return deny("request-mismatch", 403, "the request cannot be bound: " + errMsg(e), realm, verdict, pcactn)
            }
            if (!strictEq(proofDigest, bound)) {
                return deny("request-mismatch", 403, "the proof is not bound to this request (method/path/query/authority/body)", realm, verdict, pcactn)
            }
        }

        // 5c. Required checks must have PASSED (not merely "not-enforced").
        val require = opts.requireChecks ?: (if (policy == null) DEFAULT_REQUIRE_CHECKS else emptyList())
        for (c in require) {
            val st = statuses[c]
            if (st != "pass") return deny("proof-rejected", 403, "required check '$c' is ${st ?: "absent"}", realm, verdict, pcactn)
        }

        // 5d. Per-proof policy hook (limits, budgets, revocation lists). Throws deny.
        val hook = opts.checkProof
        if (hook != null) {
            try {
                val r = hook.check(ProofCheckContext(pcactn, grant, verdict, req, required))
                val ok: Boolean
                var why = "rejected by checkProof"
                if (r is Boolean) {
                    ok = r
                } else {
                    val a = g(r, "allow")
                    ok = Js.truthy(if (a === UNDEF) null else a)
                    val rs = g(r, "reason")
                    if (rs !== UNDEF && Js.truthy(rs)) why = jsStr(rs)
                }
                if (!ok) return deny("proof-rejected", 403, why, realm, verdict, pcactn)
            } catch (e: Exception) {
                return deny("proof-rejected", 403, "checkProof failed: " + errMsg(e), realm, verdict, pcactn)
            }
        }

        // 5e. Full-policy mode: the grant's limits and caveats, revocation, the replay counter and the trust budget.
        var policyVerdict: Map<String, Any?>? = null
        if (policy != null && fullParams != null) {
            var k1: CaveatLang.K1Input? = null
            if (policy.k1 != null || policy.k1Fn != null) {
                try {
                    val own = policy.k1Fn?.invoke(req, pcactn) ?: policy.k1
                    val merged = LinkedHashMap(presentedArtifacts(req, policy))
                    if (own != null) merged.putAll(own)
                    k1 = CaveatLang.K1Input.fromJson(merged)
                } catch (e: RuntimeException) {
                    return deny("proof-rejected", 403, "k1 input failed: ${errMsg(e)} (fail closed)", realm, verdict, pcactn)
                }
            }
            val bundle = presentedProvenance(req, policy)
            val log: ProvenanceLog? = if (policy.provenanceLogOff) null else (policy.provenanceLog ?: opts.defaultLog())
            val chain = g(pcactn, "cap_chain")
            val leaf = if (chain is List<*> && chain.isNotEmpty()) g(chain[chain.size - 1], "holder") else UNDEF
            val receipts = g(bundle, "receipts")
            val session = if (receipts is List<*> && receipts.isNotEmpty()) g(receipts[0], "session") else UNDEF
            val logKey = jsStr(g(pcactn, "grant_ref")) + "\n" + jsStr(leaf) + "\n" + (if (session is String) session else "-")
            val verb = required?.verb ?: jsStr(proofVerb)
            val resource = required?.resource ?: jsStr(proofResource)

            val provOpts: Authorize.ProvenanceOptions? = if (log != null) {
                val joined: Observed = { _, _, _ -> ArrayList<Any?>(log.seen(logKey)) }
                policy.provenanceGate?.invoke(joined) ?: Authorize.ProvenanceOptions(observed = joined)
            } else {
                policy.provenanceGate?.invoke(null)
            }
            val grantResolver = opts.resolveGrant!!
            val input = Authorize.Input(
                operation = Authorize.Operation(verb, resource, fullParams), audience = opts.audience,
                resolveGrant = { r -> grantResolver.resolve(r, pcactn) }, stateStore = policy.state, isRevoked = policy.isRevoked, now = now,
                plan = policy.plan, context = policy.context, intentPolicy = policy.intentPolicy, allowedSuites = policy.allowedSuites,
                require = policy.require, k1 = k1, attestation = policy.attestation, zk = policy.zk,
                // a presented-but-unreadable bundle (JSON null) reaches the gate as an unreadable header, which fails closed
                provenance = if (bundle === ABSENT) null else bundle,
                provenanceHeader = if (bundle === ABSENT || bundle != null) null else "!",
                provenanceOptions = provOpts,
            )
            val d = Authorize.authorize(pcactn, input)
            val pv = LinkedHashMap<String, Any?>()
            pv["allow"] = d.allow
            pv["checks"] = LinkedHashMap<String, Any?>(d.checks)
            pv["reasons"] = ArrayList<Any?>(d.reasons)
            // what this call returns flows back into the agent's context: the session has now seen untrusted content
            if (d.allow && log != null) {
                val obs = LinkedHashMap<String, Any?>()
                obs["origin"] = "tool"
                obs["source"] = jsStr(proofVerb)
                log.add(logKey, obs)
            }
            if (!d.allow) {
                val code = if (d.checks["replay"] == "fail") "replayed-proof"
                else if (d.checks["operation"] == "fail" || d.checks["params_digest"] == "fail") "insufficient-capability"
                else if (d.status == 401) "verify-failed" else "proof-rejected"
                return deny(code, d.status, d.reason ?: "denied", realm, verdict, pcactn, null, pv)
            }
            policyVerdict = pv
        }

        // 6. Single use (only for a proof that would otherwise be allowed, so denied attempts never burn it).
        val guard = opts.replayGuard
        if (guard != null) {
            val first = try {
                val exp = g(pcactn, "exp")
                val expD = if (exp === UNDEF) null else Js.num(exp)
                guard.claim(jsStr(g(pcactn, "grant_ref")) + ":" + jsStr(g(pcactn, "sig")), expD ?: Double.NaN, now.toDouble())
            } catch (e: Exception) {
                return deny("replay-guard-unavailable", 503, "replay guard unavailable: " + errMsg(e), realm, verdict, pcactn)
            }
            if (!first) return deny("replayed-proof", 403, "this proof has already been used", realm, verdict, pcactn)
        }

        return allowDecision(
            if (policyVerdict != null) "proof-carrying action authorized (full policy)" else "proof-carrying action verified",
            verdict, pcactn, required, policyVerdict,
        )
    }

    /**
     * Build a reusable authorizer bound to one configuration. Throws when a component is missing (the policy, a replay guard in
     * signature-only mode, the state store and revocation check in full mode). The configuration is not copied: do not change it afterwards.
     */
    @JvmStatic
    fun createGateway(opts: GatewayOptions): (GatewayRequest) -> Decision {
        val missing = missingPolicy(opts)
        if (missing.isNotEmpty()) throw JsTypeError("pca-gateway: " + missingText(opts, missing))
        return { req -> authorize(req, opts) }
    }

    // ---- Envoy HTTP ext_authz ----

    private fun strOr(v: Any?): String? = v as? String

    private fun mapOf(v: Any?): Map<String, Any?> = if (v is Map<*, *>) v as Map<String, Any?> else LinkedHashMap()

    /** The raw query (no "?", no "#fragment") of a request target. */
    internal fun queryOfTarget(target: String): String {
        val q = target.indexOf('?')
        if (q < 0) return ""
        val rest = target.substring(q + 1)
        val h = rest.indexOf('#')
        return if (h >= 0) rest.substring(0, h) else rest
    }

    /** The gateway request of an Envoy check ({method?, path?, authority?, headers?, body?}); the ":method" / ":path" / ":authority" pseudo-headers are the fallback. */
    internal fun envoyRequest(check: Map<String, Any?>): GatewayRequest {
        val hv = g(check, "headers")
        val headers = mapOf(if (hv === UNDEF) null else hv)
        val method = strOr(check["method"]) ?: strOr(headers[":method"]) ?: "*"
        val target = strOr(check["path"]) ?: strOr(headers[":path"]) ?: "/"
        var mark = -1
        for (i in target.indices) {
            val c = target[i]
            if (c == '?' || c == '#') { mark = i; break }
        }
        val rawPath = if (mark >= 0) target.substring(0, mark) else target
        val path = if (rawPath.isEmpty()) "/" else rawPath
        val authority = strOr(check["authority"]) ?: strOr(headers[":authority"])
        val r = GatewayRequest(method, path, headers)
        r.query = queryOfTarget(target)
        r.authority = authority
        r.body = strOr(check["body"])
        return r
    }

    /**
     * Envoy HTTP ext_authz handler. On a valid proof it answers 200 and forwards the verdict upstream on x-pca-verdict / x-pca-verb /
     * x-pca-grant (every injected header is overwritten, unset ones blank); on deny it answers the guard's 401 / 403 / 400 / 503 with a
     * WWW-Authenticate challenge and a JSON error body. Maps in, Map out: {status, headers, body}.
     */
    @JvmStatic
    fun envoyExtAuthz(opts: GatewayOptions): (Map<String, Any?>) -> Map<String, Any?> {
        val gateway = createGateway(opts)
        return { check ->
            val d = gateway(envoyRequest(check))
            val out = LinkedHashMap<String, Any?>()
            val headers = LinkedHashMap<String, Any?>()
            if (d.allow) {
                for (h in PCA_INJECTED_HEADERS) headers[h] = ""
                headers.putAll(d.headers)
                out["status"] = Json.Num("200")
                out["headers"] = headers
                out["body"] = ""
            } else {
                headers["content-type"] = "application/json"
                headers.putAll(d.headers)
                val body = LinkedHashMap<String, Any?>()
                body["error"] = d.code
                body["reason"] = d.reason
                out["status"] = Json.Num(d.status.toString())
                out["headers"] = headers
                out["body"] = JsFmt.stringify(body)
            }
            out
        }
    }

    // ---- Envoy gRPC ext_authz ----

    private const val GRPC_OK = 0
    private const val GRPC_UNAUTHENTICATED = 16
    private const val GRPC_PERMISSION_DENIED = 7
    private const val GRPC_UNAVAILABLE = 14
    private const val OVERWRITE_IF_EXISTS_OR_ADD = 2

    private fun headerOptions(h: Map<String, String>): List<Any?> {
        val out = ArrayList<Any?>()
        for ((k, v) in h) {
            val header = LinkedHashMap<String, Any?>()
            header["key"] = k
            header["value"] = v
            val o = LinkedHashMap<String, Any?>()
            o["header"] = header
            o["appendAction"] = Json.Num(OVERWRITE_IF_EXISTS_OR_ADD.toString())
            out.add(o)
        }
        return out
    }

    private fun status(code: Int, message: String?): Map<String, Any?> {
        val s = LinkedHashMap<String, Any?>()
        s["code"] = Json.Num(code.toString())
        if (message != null) s["message"] = message
        return s
    }

    /**
     * Envoy gRPC ext_authz handler (`envoy.service.auth.v3.Authorization/Check`) over the decoded CheckRequest as a Map (camelCase
     * fields); same decisions as [envoyExtAuthz]. On allow it lists every injected header it did not set in `headersToRemove`.
     */
    @JvmStatic
    fun envoyGrpcExtAuthz(opts: GatewayOptions): (Map<String, Any?>) -> Map<String, Any?> {
        val gateway = createGateway(opts)
        return fn@{ check ->
            val http = g(g(g(check, "attributes"), "request"), "http")
            val out = LinkedHashMap<String, Any?>()
            if (http !is Map<*, *>) {
                val denied = LinkedHashMap<String, Any?>()
                denied["status"] = status(403, null)
                denied["headers"] = ArrayList<Any?>()
                val body = LinkedHashMap<String, Any?>()
                body["error"] = "invalid-request"
                body["reason"] = "CheckRequest carried no HTTP attributes"
                denied["body"] = JsFmt.stringify(body)
                out["status"] = status(GRPC_PERMISSION_DENIED, "no http request attributes")
                out["deniedResponse"] = denied
                return@fn out
            }
            val h = mapOf(http)
            val headers = mapOf(h["headers"])
            val req = LinkedHashMap<String, Any?>()
            req["headers"] = headers
            val method = strOr(h["method"]) ?: strOr(headers[":method"])
            if (method != null) req["method"] = method
            val path = strOr(h["path"]) ?: strOr(headers[":path"])
            if (path != null) req["path"] = path
            val authority = strOr(h["host"]) ?: strOr(headers[":authority"])
            if (authority != null) req["authority"] = authority
            if (strOr(h["body"]) != null) req["body"] = strOr(h["body"])
            val d = gateway(envoyRequest(req))
            if (d.allow) {
                val ok = LinkedHashMap<String, Any?>()
                ok["headers"] = headerOptions(d.headers)
                val remove = ArrayList<Any?>()
                for (x in PCA_INJECTED_HEADERS) if (!d.headers.containsKey(x)) remove.add(x)
                ok["headersToRemove"] = remove
                out["status"] = status(GRPC_OK, "")
                out["okResponse"] = ok
                return@fn out
            }
            val dh = LinkedHashMap<String, String>()
            dh["content-type"] = "application/json"
            dh.putAll(d.headers)
            val denied = LinkedHashMap<String, Any?>()
            denied["status"] = status(d.status, null)
            denied["headers"] = headerOptions(dh)
            val body = LinkedHashMap<String, Any?>()
            body["error"] = d.code
            body["reason"] = d.reason
            denied["body"] = JsFmt.stringify(body)
            out["status"] = status(if (d.status == 401) GRPC_UNAUTHENTICATED else if (d.status == 503) GRPC_UNAVAILABLE else GRPC_PERMISSION_DENIED, d.reason)
            out["deniedResponse"] = denied
            out
        }
    }

    // ---- AWS API Gateway REQUEST (Lambda) authorizer ----

    private fun lambdaResource(event: Map<String, Any?>): String = strOr(event["methodArn"]) ?: strOr(event["routeArn"]) ?: "*"

    private fun lambdaMethodPath(event: Map<String, Any?>): Pair<String, String> {
        val http = g(g(event, "requestContext"), "http")
        var method = strOr(if (http is Map<*, *>) http["method"] else null)
        if (method == null) method = strOr(event["httpMethod"])
        var path = strOr(event["rawPath"])
        if (path == null) path = strOr(event["path"])
        if (path == null && http is Map<*, *>) path = strOr(http["path"])
        if (method != null && path != null) return Pair(method, path)
        val arn = strOr(event["methodArn"]) ?: strOr(event["routeArn"])
        if (arn != null) {
            val colon = arn.split(":")
            val tail = StringBuilder()
            for (i in 5 until colon.size) {
                if (i > 5) tail.append(':')
                tail.append(colon[i])
            }
            val parts = tail.toString().split("/")
            val arnMethod = if (parts.size > 2) parts[2].split(" ")[0] else null
            val rest = StringBuilder()
            for (i in 3 until parts.size) {
                if (i > 3) rest.append('/')
                rest.append(parts[i])
            }
            return Pair(method ?: arnMethod ?: "*", path ?: "/$rest")
        }
        return Pair(method ?: "*", path ?: "/")
    }

    private fun lambdaQuery(event: Map<String, Any?>): String {
        val raw = event["rawQueryString"]
        if (raw is String) return raw
        val multi = event["multiValueQueryStringParameters"]
        val single = event["queryStringParameters"]
        val pairs = ArrayList<String>()
        if (Js.truthy(multi) && multi is Map<*, *>) {
            for ((k, vs) in multi) {
                if (vs !is List<*>) continue
                for (v in vs) pairs.add(encodeURIComponent(k as String) + "=" + encodeURIComponent(jsStr(v)))
            }
        } else if (Js.truthy(single) && single is Map<*, *>) {
            for ((k, v) in single) pairs.add(encodeURIComponent(k as String) + "=" + encodeURIComponent(jsStr(v)))
        }
        return pairs.joinToString("&")
    }

    private fun lambdaRequest(event: Map<String, Any?>): GatewayRequest {
        val (method, path) = lambdaMethodPath(event)
        val r = GatewayRequest(method, path, mapOf(event["headers"]))
        r.query = lambdaQuery(event)
        return r
    }

    private fun lambdaPolicy(effect: String, event: Map<String, Any?>): Map<String, Any?> {
        val st = LinkedHashMap<String, Any?>()
        st["Action"] = "execute-api:Invoke"
        st["Effect"] = effect
        st["Resource"] = lambdaResource(event)
        val doc = LinkedHashMap<String, Any?>()
        doc["Version"] = "2012-10-17"
        doc["Statement"] = arrayListOf<Any?>(st)
        return doc
    }

    private fun lambdaContext(d: Decision): Map<String, Any?> {
        val c = LinkedHashMap<String, Any?>()
        if (d.allow) {
            if (d.verdict != null) c["pcaVerdict"] = JsFmt.stringify(d.verdict)
            return c
        }
        c["pcaDenied"] = "true"
        c["pcaCode"] = d.code
        c["pcaReason"] = d.reason
        c["pcaStatus"] = d.status.toString()
        return c
    }

    /**
     * AWS API Gateway REQUEST (Lambda) authorizer over the event Map. A valid, capability-matching proof gets an Allow IAM policy
     * (verdict on `context.pcaVerdict`); anything else a Deny policy. REST (`methodArn`) and HTTP-API (`routeArn`) payloads.
     */
    @JvmStatic
    fun lambdaAuthorizer(opts: GatewayOptions): (Map<String, Any?>) -> Map<String, Any?> {
        val gateway = createGateway(opts)
        return { event ->
            val d = gateway(lambdaRequest(event))
            val out = LinkedHashMap<String, Any?>()
            val grant = if (d.pcactn == null) UNDEF else g(d.pcactn, "grant_ref")
            out["principalId"] = if (grant is String) grant else "anonymous"
            out["policyDocument"] = lambdaPolicy(if (d.allow) "Allow" else "Deny", event)
            out["context"] = lambdaContext(d)
            out
        }
    }

    /** HTTP-API simple-response variant (`enableSimpleResponses`): {isAuthorized, context} instead of an IAM policy. */
    @JvmStatic
    fun lambdaSimpleAuthorizer(opts: GatewayOptions): (Map<String, Any?>) -> Map<String, Any?> {
        val gateway = createGateway(opts)
        return { event ->
            val d = gateway(lambdaRequest(event))
            val out = LinkedHashMap<String, Any?>()
            out["isAuthorized"] = d.allow
            out["context"] = lambdaContext(d)
            out
        }
    }
}

/** The joined `observed` of the provenance gate: what the gateway let through for this session. */
typealias Observed = (Map<String, Any?>, Authorize.Operation, String?) -> List<Any?>?
