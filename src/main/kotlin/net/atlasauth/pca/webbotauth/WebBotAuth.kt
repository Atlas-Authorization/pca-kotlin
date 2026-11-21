package net.atlasauth.pca.webbotauth

import java.util.Locale
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.oauth.WhatwgUrl
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.webbotauth.WbaJs.ParseError
import net.atlasauth.pca.webbotauth.WbaJs.def
import net.atlasauth.pca.webbotauth.WbaJs.get
import net.atlasauth.pca.webbotauth.WbaJs.sfString
import net.atlasauth.pca.webbotauth.WbaJs.trim

/**
 * Web Bot Auth for Proof-Carrying Authority: RFC 9421 HTTP Message Signatures over outbound agent requests, in the Cloudflare / AWS WAF
 * "web-bot-auth" profile, so a PCA agent passes automated-traffic bot verification AND carries its per-action proof in the SAME request.
 * The signature base is built byte for byte as the reference builds it.
 *
 * [signRequest] builds the `Signature-Input` / `Signature` header values with the agent's Ed25519 identity;
 * [verifySignedRequest] rebuilds the base from the request, resolves the key by `keyid` (a [KeyResolver] or a JWKS directory),
 * verifies the Ed25519 signature strictly (RFC 8032: canonical S, no small-order or non-canonical points) and enforces `created` /
 * `expires` freshness and the `web-bot-auth` tag. It FAILS CLOSED: a parse error, a missing field, a stale window, a wrong tag, an
 * unknown key or a bad signature returns `{valid:false, reason}` and never throws. A valid signature proves the holder of the key signed THIS
 * request's covered components inside the window; it does not by itself prove the action is authorized (the PCActn verifier's job).
 *
 * Values are parsed JSON (Map, List, String, Boolean, Json.Num, null); input and option bags are Maps keyed by the reference's names. Keys are
 * [Keys.EdKey] or a map with a b64u `secretKey` (the 32-byte seed). The reference's async calls are plain blocking calls.
 *
 * shortcut: request URLs must be http(s) (ws, wss and ftp too); other schemes are refused where the reference would accept them, and a
 * `@target-uri` covering a URL with credentials or a fragment is refused. Upgrade if a non-HTTP request target is ever signed.
 */
@Suppress("UNCHECKED_CAST")
object WebBotAuth {
    const val WEB_BOT_AUTH_TAG = "web-bot-auth"
    const val WEB_BOT_AUTH_ALG = "ed25519"
    const val WELL_KNOWN_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
    const val DIRECTORY_CONTENT_TYPE = "application/http-message-signatures-directory+json"
    const val DEFAULT_SIGNATURE_LABEL = "sig1"
    const val DEFAULT_EXPIRES_SEC = 300
    const val SIGNATURE_AGENT_HEADER = "Signature-Agent"
    const val PCA_HEADER = "PCA-Action"

    /** The covered-component (lowercase) name of the PCA proof header. */
    const val PCA_PROOF_COMPONENT = "pca-action"

    /** Maps a keyid to its Ed25519 public key: a 32-byte ByteArray, a public JWK map, or null for unknown. */
    fun interface KeyResolver {
        @Throws(Exception::class)
        fun resolve(keyid: String): Any?
    }

    /** Single-use store for accepted signatures: true if [key] was claimed for the first time (until [expiresAtSec]). */
    fun interface ReplayCache {
        @Throws(Exception::class)
        fun claim(key: String, expiresAtSec: Double, nowSec: Double): Boolean
    }

    /** In-process [ReplayCache]. Fails CLOSED (throws) when [maxEntries] unexpired claims are held. */
    @JvmStatic
    @JvmOverloads
    fun memoryReplayCache(maxEntries: Int = 100_000): ReplayCache {
        val seen = LinkedHashMap<String, Double>()
        return ReplayCache { key, expiresAtSec, nowSec ->
            synchronized(seen) {
                if (!nowSec.isFinite() || !expiresAtSec.isFinite()) return@synchronized false
                if (seen.size >= maxEntries) {
                    val it = seen.entries.iterator()
                    while (it.hasNext()) if (it.next().value < nowSec) it.remove()
                    if (seen.size >= maxEntries) throw IllegalStateException("replay cache full")
                }
                val existing = seen[key]
                if (existing != null && !(existing < nowSec)) false
                else {
                    seen[key] = expiresAtSec
                    true
                }
            }
        }
    }

    // ---- keys ----

    /** An Ed25519 signing identity from a [Keys.EdKey] or a map with a b64u `secretKey` seed. */
    internal fun edKey(k: Any?): Keys.EdKey {
        if (k is Keys.EdKey) return k
        val sk = get(k, "secretKey") as? String ?: throw IllegalArgumentException("key must carry a secretKey")
        return Keys.edFromSeed(Keys.unb64u(sk))
    }

    /** RFC 7638 JWK thumbprint of an Ed25519 public key (base64url of SHA-256 over the canonical JWK). */
    @JvmStatic
    fun jwkThumbprint(publicKey: ByteArray): String = WbaJs.thumbprintOfX(Keys.b64u(publicKey))

    // ---- structured-field helpers ----

    private fun splitTopLevel(s: String, sep: Char): List<String> {
        val out = ArrayList<String>()
        var depth = 0
        var start = 0
        var inStr = false
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (inStr) {
                if (c == '\\') i++ else if (c == '"') inStr = false
                i++
                continue
            }
            if (c == '"') inStr = true
            else if (c == '(') depth++
            else if (c == ')') depth = Math.max(0, depth - 1)
            else if (c == sep && depth == 0) { out.add(s.substring(start, i)); start = i + 1 }
            i++
        }
        out.add(s.substring(Math.min(start, s.length)))
        return out
    }

    private class Sf(val value: String, val next: Int)

    private fun readSfString(s: String, i: Int): Sf {
        if (i >= s.length || s[i] != '"') throw ParseError("expected a quoted string")
        val out = StringBuilder()
        var j = i + 1
        while (j < s.length) {
            val c = s[j]
            if (c == '\\') {
                if (j + 1 >= s.length || (s[j + 1] != '"' && s[j + 1] != '\\')) throw ParseError("invalid escape in string")
                out.append(s[j + 1])
                j++
            } else if (c == '"') {
                return Sf(out.toString(), j + 1)
            } else {
                out.append(c)
            }
            j++
        }
        throw ParseError("unterminated string")
    }

    private val INT = Regex("-?\\d+")
    private val DEC = Regex("-?\\d+\\.\\d+")

    private fun parseParamValue(raw: String): Any {
        val s = trim(raw)
        if (s.isEmpty()) return true
        if (s[0] == '"') {
            val sf = readSfString(s, 0)
            if (sf.next != s.length) throw ParseError("trailing characters after string parameter")
            return sf.value
        }
        if (s == "?1") return true
        if (s == "?0") return false
        if (INT.matches(s) || DEC.matches(s)) return s.toDouble()
        return s
    }

    private fun parseParams(paramStr: String): Map<String, Any?> {
        val params = LinkedHashMap<String, Any?>()
        val trimmed = trim(paramStr)
        if (trimmed.isEmpty()) return params
        if (trimmed[0] != ';') throw ParseError("expected parameters to start with \";\"")
        for (part in splitTopLevel(trimmed.substring(1), ';')) {
            val seg = trim(part)
            if (seg.isEmpty()) continue
            val eq = indexOfTopLevel(seg, '=')
            if (eq == -1) params[seg] = true else params[trim(seg.substring(0, eq))] = parseParamValue(seg.substring(eq + 1))
        }
        return params
    }

    private fun matchingParen(s: String, open: Int): Int {
        if (open >= s.length || s[open] != '(') return -1
        var depth = 0
        var inStr = false
        var i = open
        while (i < s.length) {
            val c = s[i]
            if (inStr) {
                if (c == '\\') i++ else if (c == '"') inStr = false
                i++
                continue
            }
            if (c == '"') inStr = true
            else if (c == '(') depth++
            else if (c == ')') {
                depth--
                if (depth == 0) return i
            }
            i++
        }
        return -1
    }

    private fun indexOfTopLevel(s: String, ch: Char): Int {
        var depth = 0
        var inStr = false
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (inStr) {
                if (c == '\\') i++ else if (c == '"') inStr = false
                i++
                continue
            }
            if (c == '"') inStr = true
            else if (c == '(') depth++
            else if (c == ')') depth = Math.max(0, depth - 1)
            else if (c == ch && depth == 0) return i
            i++
        }
        return -1
    }

    private class Comp(val id: String, val raw: String, val key: String?)

    private class SigInput(val label: String, val components: List<Comp>, val paramsRaw: String, val params: Map<String, Any?>)

    private val KEY_PARAM = Regex(";key=(\"(?:[^\"\\\\]|\\\\[^\\n\\r\\u2028\\u2029])*\")")

    private fun parseSignatureInput(value: String): List<SigInput> {
        val entries = ArrayList<SigInput>()
        for (memberRaw in splitTopLevel(value, ',')) {
            val member = trim(memberRaw)
            if (member.isEmpty()) continue
            val eq = indexOfTopLevel(member, '=')
            if (eq == -1) throw ParseError("malformed Signature-Input member")
            val label = trim(member.substring(0, eq))
            val paramsRaw = trim(member.substring(eq + 1))
            if (paramsRaw.isEmpty() || paramsRaw[0] != '(') throw ParseError("Signature-Input value must be an inner list")
            val close = matchingParen(paramsRaw, 0)
            if (close == -1) throw ParseError("unterminated inner list")
            val inner = paramsRaw.substring(1, close)
            val components = ArrayList<Comp>()
            for (chunkRaw in splitTopLevel(inner, ' ')) {
                val chunk = trim(chunkRaw)
                if (chunk.isEmpty()) continue
                val sf = readSfString(chunk, 0)
                val lowered = WbaJs.lower(sf.value)
                val rest = trim(chunk.substring(sf.next))
                if (rest.isEmpty()) { components.add(Comp(lowered, "\"" + lowered + "\"", null)); continue }
                // The only component parameter supported is `key` (dictionary member), on header components.
                val m = KEY_PARAM.matchEntire(rest)
                if (m == null || lowered.startsWith("@")) throw ParseError("unsupported component parameters on \"" + sf.value + "\"")
                val key = readSfString(m.groupValues[1], 0).value
                components.add(Comp(lowered, "\"" + lowered + "\";key=" + sfString(key), key))
            }
            entries.add(SigInput(label, components, paramsRaw, parseParams(paramsRaw.substring(close + 1))))
        }
        return entries
    }

    private fun parseSignature(value: String): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        for (memberRaw in splitTopLevel(value, ',')) {
            val member = trim(memberRaw)
            if (member.isEmpty()) continue
            val eq = indexOfTopLevel(member, '=')
            if (eq == -1) throw ParseError("malformed Signature member")
            val label = trim(member.substring(0, eq))
            val v = trim(member.substring(eq + 1))
            if (v.length < 2 || v[0] != ':' || v[v.length - 1] != ':') throw ParseError("Signature value must be a byte sequence (:base64:)")
            out[label] = WbaJs.nodeBase64(v.substring(1, v.length - 1))
        }
        return out
    }

    // ---- signature base (RFC 9421 section 2.5) ----

    private class Ctx(
        val method: String,
        val authority: String,
        val path: String,
        val targetUri: String?,
        val scheme: String,
        val query: String,
        val requestTarget: String,
        val headers: Map<String, String>,
    )

    private fun normalizeHeaders(h: Any?): MutableMap<String, String> {
        val m = LinkedHashMap<String, String>()
        if (h !is Map<*, *>) return m
        for ((k, v) in h) {
            val name = WbaJs.lower(k as String)
            val value = when (v) {
                is List<*> -> v.joinToString(", ") { x -> if (x !is String) throw IllegalStateException("x.trim is not a function") else trim(x) }
                is String -> trim(v)
                else -> throw IllegalStateException("v.trim is not a function")
            }
            val prev = m[name]
            m[name] = if (prev == null) value else "$prev, $value"
        }
        return m
    }

    private fun buildContext(method: String, url: String, headers: Map<String, String>): Ctx {
        val u = WhatwgUrl.parse(url) ?: throw IllegalArgumentException("Invalid URL")
        if (u.origin() == "null") throw IllegalArgumentException("unsupported URL scheme")
        val hostport = u.host + (if (u.port.isEmpty()) "" else ":" + u.port)
        val hash = url.indexOf('#')
        val noFrag = if (hash >= 0) url.substring(0, hash) else url
        val plain = hash < 0 && !WbaJs.hasCredentials(noFrag)
        val targetUri = if (plain) u.protocol + "//" + hostport + u.pathname + u.search + (if (u.search.isEmpty() && noFrag.indexOf('?') >= 0) "?" else "") else null
        val path = if (u.pathname.isEmpty()) "/" else u.pathname
        return Ctx(
            method = method.uppercase(Locale.ROOT),
            authority = WbaJs.lower(hostport),
            path = path,
            targetUri = targetUri,
            scheme = WbaJs.lower(u.protocol.removeSuffix(":")),
            query = if (u.search.isEmpty()) "?" else u.search,
            requestTarget = path + u.search,
            headers = headers,
        )
    }

    private val CANON_PARAMS = Regex("(;[a-z*][a-z0-9_.*-]*(=(\"(?:[^\"\\\\]|\\\\[^\\n\\r\\u2028\\u2029])*\"|[A-Za-z0-9_.:/*+%-]+))?)*")

    private fun deriveComponentValue(component: Comp, ctx: Ctx): String = when (val id = component.id) {
        "@method" -> ctx.method
        "@authority" -> ctx.authority
        "@path" -> ctx.path
        "@target-uri" -> ctx.targetUri ?: throw ParseError("@target-uri is not supported for a URL with credentials or a fragment")
        "@scheme" -> ctx.scheme
        "@query" -> ctx.query
        "@request-target" -> ctx.requestTarget
        else -> {
            if (id.startsWith("@")) throw ParseError("unsupported derived component \"$id\"")
            val v = ctx.headers[id] ?: throw ParseError("covered header \"$id\" is absent from the request")
            val key = component.key
            if (key != null) dictionaryMember(v, key, id) else v
        }
    }

    /** RFC 9421 section 2.1.2: the serialized value of dictionary member [key] of a Structured Field dictionary header (string members only). */
    private fun dictionaryMember(header: String, key: String, headerName: String): String {
        for (memberRaw in splitTopLevel(header, ',')) {
            val member = trim(memberRaw)
            val eq = indexOfTopLevel(member, '=')
            if (eq == -1 || trim(member.substring(0, eq)) != key) continue
            val value = trim(member.substring(eq + 1))
            val sf = readSfString(value, 0)
            // Parameters are allowed only in compact canonical form, so the verbatim text IS the serialization.
            if (!CANON_PARAMS.matches(value.substring(sf.next))) throw ParseError("member \"$key\" of \"$headerName\" is not in canonical form")
            return value
        }
        throw ParseError("\"$headerName\" has no dictionary member \"$key\"")
    }

    private fun buildSignatureBase(components: List<Comp>, paramsRaw: String, ctx: Ctx): String {
        val lines = ArrayList<String>()
        for (c in components) lines.add(c.raw + ": " + deriveComponentValue(c, ctx))
        lines.add("\"@signature-params\": $paramsRaw")
        return lines.joinToString("\n")
    }

    // ---- signRequest ----

    private val HAS_QUERY = Regex("\\?[^#]")

    private fun nowSec(): Double = (System.currentTimeMillis() / 1000).toDouble()

    /**
     * Build the `Signature-Input` + `Signature` header values over the RFC 9421 signature base. [input]: method, url, headers?,
     * key (signing identity), keyid, created? (epoch seconds, default now), expiresInSec? (default 300), agentDirectoryUrl? (also emits and covers
     * `Signature-Agent`), agentDirectoryKey? (dictionary form, requires agentDirectoryUrl), components? (derived components replacing the default
     * `@authority @method @path`; `@authority` required), coverHeaders?, nonce?, label?. Returns `{signatureInput, signature,
     * signatureAgent?, covered, headers}`.
     */
    @JvmStatic
    fun signRequest(input: Map<String, Any?>): Map<String, Any?> {
        val label = if (input["label"] != null) WbaJs.anyStr(input["label"]) else DEFAULT_SIGNATURE_LABEL
        val created = if (input["created"] != null) WbaJs.number(input["created"]) else nowSec()
        val expires = created + (if (input["expiresInSec"] != null) WbaJs.number(input["expiresInSec"]) else DEFAULT_EXPIRES_SEC.toDouble())

        val working = normalizeHeaders(input["headers"])
        val emitted = LinkedHashMap<String, Any?>()

        val components = ArrayList<Comp>()
        val derived = ArrayList<String>()
        if (input["components"] != null) {
            for (c in Js.list(input["components"])) derived.add(c as String)
        } else {
            derived.addAll(listOf("@authority", "@method", "@path"))
        }
        val url = input["url"] as String
        // by default a URL with a query string also covers @query (the verifier requires it)
        if (input["components"] == null && HAS_QUERY.containsMatchIn(url)) derived.add("@query")
        if (!derived.contains("@authority")) throw IllegalArgumentException("signRequest: the web-bot-auth profile requires @authority to be covered")
        for (id in derived) {
            val lower = WbaJs.lower(id)
            if (!lower.startsWith("@")) throw IllegalArgumentException("signRequest: components must be derived components, got \"$id\" (use coverHeaders for headers)")
            components.add(Comp(lower, "\"" + lower + "\"", null))
        }

        var signatureAgent: String? = null
        if (def(input, "agentDirectoryUrl")) {
            val hasKey = def(input, "agentDirectoryKey")
            if (hasKey && input["agentDirectoryKey"] !is String) throw IllegalArgumentException("signRequest: agentDirectoryKey must be a string")
            val key = if (hasKey) input["agentDirectoryKey"] as String else null
            val agentUrl = input["agentDirectoryUrl"] as String
            val sa = if (key == null) sfString(agentUrl) else key + "=" + sfString(agentUrl)
            signatureAgent = sa
            working["signature-agent"] = sa
            emitted[SIGNATURE_AGENT_HEADER] = sa
            components.add(if (key == null) Comp("signature-agent", "\"signature-agent\"", null) else Comp("signature-agent", "\"signature-agent\";key=" + sfString(key), key))
        } else if (def(input, "agentDirectoryKey")) {
            throw IllegalArgumentException("signRequest: agentDirectoryKey requires agentDirectoryUrl")
        }

        val cover = input["coverHeaders"]
        if (cover != null) {
            val names = ArrayList<Any?>()
            if (cover is String) {
                var i = 0
                while (i < cover.length) {
                    val cp = cover.codePointAt(i)
                    names.add(String(Character.toChars(cp)))
                    i += Character.charCount(cp)
                }
            } else names.addAll(Js.list(cover))
            for (n in names) {
                val name = n as String
                val lower = WbaJs.lower(name)
                if (!working.containsKey(lower)) throw IllegalArgumentException("signRequest: covered header \"$name\" is not present in headers")
                if (components.none { it.id == lower }) components.add(Comp(lower, "\"" + lower + "\"", null))
            }
        }

        val ctx = buildContext(input["method"] as String, url, working)

        // The parameter order follows the examples in the Web Bot Auth architecture draft: created, keyid, alg, expires, nonce, tag.
        var paramsRaw = "(" + components.joinToString(" ") { it.raw } + ");created=" + WbaJs.numStr(created) + ";keyid=" + sfString(input["keyid"] as String) +
            ";alg=" + sfString(WEB_BOT_AUTH_ALG) + ";expires=" + WbaJs.numStr(expires)
        if (def(input, "nonce")) paramsRaw += ";nonce=" + sfString(input["nonce"] as String)
        paramsRaw += ";tag=" + sfString(WEB_BOT_AUTH_TAG)

        val base = buildSignatureBase(components, paramsRaw, ctx)
        val sig = edKey(input["key"]).sign(Json.utf8(base))

        val signatureInput = "$label=$paramsRaw"
        val signature = label + "=:" + WbaJs.b64(sig) + ":"
        emitted["Signature-Input"] = signatureInput
        emitted["Signature"] = signature

        val out = LinkedHashMap<String, Any?>()
        out["signatureInput"] = signatureInput
        out["signature"] = signature
        if (signatureAgent != null) out["signatureAgent"] = signatureAgent
        out["covered"] = ArrayList<Any?>(components.map { it.id })
        out["headers"] = emitted
        return out
    }

    // ---- verifySignedRequest ----

    private fun xFromResolved(k: Any?): String? {
        if (k is ByteArray) return if (k.size == 32) Keys.b64u(k) else null
        if (k is Map<*, *>) {
            val x = k["x"]
            if (x is String && k["crv"] == "Ed25519" && k["kty"] == "OKP") return x
        }
        return null
    }

    private fun finite(d: Double?): Boolean = d != null && !d.isNaN() && !d.isInfinite()

    private fun resolvePublicKeyX(keyid: String, opts: Map<String, Any?>, now: Double, skew: Double): String? {
        val resolver = opts["resolveKey"]
        if (resolver != null) return xFromResolved((resolver as KeyResolver).resolve(keyid))
        if (opts["jwks"] != null) {
            var match: Map<String, Any?>? = null
            for (j in Js.list(get(opts["jwks"], "keys"))) if (j is Map<*, *> && keyid == j["kid"]) { match = j as Map<String, Any?>; break }
            if (match == null) return null
            // A published validity window is enforced; a bound that is present but not a finite number cannot be checked, so the key resolves to nothing.
            for (b in listOf("nbf", "exp")) if (match.containsKey(b) && !finite(Js.num(match[b]))) return null
            if (match.containsKey("nbf") && !(now.isFinite() && skew.isFinite() && now + skew >= WbaJs.number(match["nbf"]))) return null
            if (match.containsKey("exp") && !(now.isFinite() && skew.isFinite() && now - skew <= WbaJs.number(match["exp"]))) return null
            return xFromResolved(match)
        }
        return null
    }

    private fun ed25519VerifyX(x: String, message: ByteArray, sig: ByteArray): Boolean = try {
        if (sig.size != 64) false
        else {
            val pk = Pca.decodeB64uStrict(x, 32)
            pk != null && Jose.verifyEd25519Strict(pk, message, sig)
        }
    } catch (e: RuntimeException) {
        false
    }

    private fun invalid(reason: String): Map<String, Any?> = linkedMapOf("valid" to false, "reason" to reason)

    private fun num(d: Double): Json.Num = Json.Num(WbaJs.numStr(d))

    /**
     * Verify the HTTP Message Signature of [req] (`{method, url, headers}`). [opts]: resolveKey ([KeyResolver], takes precedence) or
     * jwks (a key directory), now (epoch seconds), clockSkewSec (0), maxAgeSec, requireExpires (default true), requiredTag (default web-bot-auth;
     * null = not enforced), label, requiredComponents (default `@authority @method @path`, plus `@query` when the URL has a query),
     * maxLifetimeSec (default 300; Infinity disables), replayCache ([ReplayCache]). Returns `{valid, reason?, label?, keyid?, covered?, created?,
     * expires?, tag?, nonce?}`; never throws.
     */
    @JvmStatic
    fun verifySignedRequest(req: Map<String, Any?>, opts: Map<String, Any?>): Map<String, Any?> {
        try {
            if (opts["resolveKey"] == null && opts["jwks"] == null) return invalid("verifySignedRequest: provide resolveKey or jwks")
            val headers = normalizeHeaders(req["headers"])
            val sigInputHeader = headers["signature-input"]
            val sigHeader = headers["signature"]
            if (sigInputHeader == null || sigHeader == null) return invalid("missing Signature-Input or Signature header")

            val inputs = parseSignatureInput(sigInputHeader)
            val sigs = parseSignature(sigHeader)
            val requiredTag = if (def(opts, "requiredTag")) opts["requiredTag"] else WEB_BOT_AUTH_TAG

            val chosen: SigInput = (
                if (def(opts, "label")) inputs.firstOrNull { it.label == opts["label"] }
                else if (requiredTag != null) inputs.firstOrNull { it.params["tag"] == requiredTag } ?: inputs.firstOrNull()
                else inputs.firstOrNull()
                ) ?: return invalid("no matching signature in Signature-Input")

            val sigBytes = sigs[chosen.label] ?: return invalid("no Signature entry for label \"" + chosen.label + "\"")

            val tag = chosen.params["tag"] as? String
            if (requiredTag != null && tag != requiredTag) {
                return invalid("tag \"" + (tag ?: "undefined") + "\" does not match required \"" + WbaJs.anyStr(requiredTag) + "\"")
            }

            // web-bot-auth requires @authority to be covered; @method and @path too, so a signature for one request cannot be replayed on another
            // method or path of the same host.
            val covered = HashSet<Any?>()
            for (c in chosen.components) covered.add(c.id)
            val required: List<Any?> = if (opts["requiredComponents"] != null) Js.list(opts["requiredComponents"]) else listOf("@authority", "@method", "@path")
            for (id in required) if (!covered.contains(id)) return invalid(WbaJs.anyStr(id) + " is not a covered component")
            if (!def(opts, "requiredComponents")) {
                val url = req["url"] as String
                val q = url.indexOf('?')
                if (q >= 0 && url.substring(q + 1).split("#")[0].isNotEmpty() && !covered.contains("@query")) return invalid("@query is not a covered component")
            }

            val alg = chosen.params["alg"]
            if (alg != null && WEB_BOT_AUTH_ALG != alg) return invalid("unsupported alg \"" + WbaJs.str(alg) + "\"")

            // Freshness.
            val now = if (opts["now"] != null) WbaJs.number(opts["now"]) else nowSec()
            val skew = if (opts["clockSkewSec"] != null) WbaJs.number(opts["clockSkewSec"]) else 0.0
            val created = chosen.params["created"] as? Double
            val expires = chosen.params["expires"] as? Double
            if (expires == null && opts["requireExpires"] != false) return invalid("missing expires parameter")
            if (expires != null && !(now.isFinite() && skew.isFinite() && expires.isFinite() && now <= expires + skew)) return invalid("signature has expired")
            if (created != null && !(now.isFinite() && skew.isFinite() && created.isFinite() && created <= now + skew)) return invalid("signature created-time is in the future")
            if (opts["maxAgeSec"] != null && created != null && !(now.isFinite() && skew.isFinite() && now - created <= WbaJs.number(opts["maxAgeSec"]) + skew)) return invalid("signature is older than maxAgeSec")
            val maxLifetime = if (opts["maxLifetimeSec"] != null) WbaJs.number(opts["maxLifetimeSec"]) else 300.0
            val boundedLifetime = finite(maxLifetime)
            if (boundedLifetime) {
                if (created == null) return invalid("missing created parameter (needed to bound the signature lifetime)")
                if (expires != null && !(expires - created <= maxLifetime)) return invalid("signature lifetime exceeds maxLifetimeSec")
            }

            val keyid = chosen.params["keyid"] as? String ?: return invalid("missing keyid parameter")
            val x = resolvePublicKeyX(keyid, opts, now, skew) ?: return invalid("could not resolve key \"$keyid\"")

            val ctx = buildContext(req["method"] as String, req["url"] as String, headers)
            val base = buildSignatureBase(chosen.components, chosen.paramsRaw, ctx)
            if (!ed25519VerifyX(x, Json.utf8(base), sigBytes)) return invalid("signature does not verify under the resolved key")

            val nonce = chosen.params["nonce"] as? String
            val cache = opts["replayCache"]
            if (cache != null) {
                val until = expires ?: if (created != null) created + (if (boundedLifetime) maxLifetime else 3600.0) else now + 3600
                val key = keyid + "|" + (nonce ?: Keys.b64u(sigBytes))
                if (!(cache as ReplayCache).claim(key, until + skew, now)) return invalid("replayed signature")
            }
            val out = LinkedHashMap<String, Any?>()
            out["valid"] = true
            out["label"] = chosen.label
            out["keyid"] = keyid
            out["covered"] = ArrayList<Any?>(chosen.components.map { it.id })
            if (created != null) out["created"] = num(created)
            if (expires != null) out["expires"] = num(expires)
            if (tag != null) out["tag"] = tag
            if (nonce != null) out["nonce"] = nonce
            return out
        } catch (e: Exception) {
            return invalid("verification failed (fail closed): " + e.message)
        }
    }

    // ---- key directory (JWKS) + handler ----

    private fun pub(o: Any?): ByteArray = when (o) {
        is ByteArray -> o
        is String -> Keys.unb64u(o)
        else -> throw IllegalArgumentException("publicKey must be bytes or a b64u string")
    }

    /** The JWKS for a list of `{publicKey (bytes or b64u), keyid?, use?, nbf?, exp?}`: `{keys: [{kty, crv, x, kid, use?, nbf?, exp?}]}`. */
    @JvmStatic
    fun buildKeyDirectory(keys: List<Map<String, Any?>>): Map<String, Any?> {
        val list = ArrayList<Any?>()
        for (k in keys) {
            val pk = pub(k["publicKey"])
            val e = LinkedHashMap<String, Any?>()
            e["kty"] = "OKP"
            e["crv"] = "Ed25519"
            e["x"] = Keys.b64u(pk)
            e["kid"] = k["keyid"] ?: jwkThumbprint(pk)
            if (def(k, "use")) e["use"] = k["use"]
            if (def(k, "nbf")) e["nbf"] = k["nbf"]
            if (def(k, "exp")) e["exp"] = k["exp"]
            list.add(e)
        }
        return linkedMapOf("keys" to list)
    }

    /** Resolve a public key JWK from a directory by `kid` (null when absent). */
    @JvmStatic
    fun resolveFromDirectory(directory: Map<String, Any?>, keyid: String): Map<String, Any?>? {
        for (j in Js.list(directory["keys"])) if (j is Map<*, *> && keyid == j["kid"]) return j as Map<String, Any?>
        return null
    }

    /**
     * A framework-agnostic handler for the well-known directory path: returns `{status, headers, body}` (200 JSON) when the path (before any
     * `?`) is [WELL_KNOWN_DIRECTORY_PATH], otherwise null so a caller can fall through.
     */
    @JvmStatic
    fun directoryHandler(keys: List<Map<String, Any?>>): (String) -> Map<String, Any?>? {
        val body = Js.stringify(buildKeyDirectory(keys))
        return { pathname ->
            val q = pathname.indexOf('?')
            val path = if (q >= 0) pathname.substring(0, q) else pathname
            if (path != WELL_KNOWN_DIRECTORY_PATH) null
            else linkedMapOf(
                "status" to Json.Num("200"),
                "headers" to linkedMapOf<String, Any?>("content-type" to DIRECTORY_CONTENT_TYPE, "cache-control" to "max-age=86400"),
                "body" to body,
            )
        }
    }

    // ---- PCA proof binding ----

    /** The `PCA-Action` header carrying a PCActn (base64url of the canonical wire form). */
    @JvmStatic
    fun proofHeaders(pcactn: Any?): Map<String, Any?> = linkedMapOf(PCA_HEADER to Keys.b64u(Json.canonicalize(pcactn).toByteArray(Charsets.UTF_8)))

    /** Reverse [proofHeaders]: the `PCA-Action` header value to the PCActn. Throws IllegalArgumentException when the value is not a strict encoding of one. */
    @JvmStatic
    fun decodeProofHeader(value: String?): Map<String, Any?> {
        val text = WbaJs.decodePcaHeader(value) ?: throw IllegalArgumentException("PCA-Action is not strict unpadded base64url of UTF-8 text")
        if (Pca.artifactTooLarge(text)) throw IllegalArgumentException(Pca.ARTIFACT_SIZE_REASON)
        val v = Json.parse(text)
        if (v !is Map<*, *>) throw IllegalArgumentException("decodePCActn: not an object")
        return v as Map<String, Any?>
    }

    /**
     * Sign a request AND bind it to a PCActn: the PCActn goes in the canonical `PCA-Action` header and that header is a covered component, so
     * the single request is bot-verifiable and carries tamper-evident proof of authority. [input] is the [signRequest] input plus
     * `pcactn`. Returns the sign result with the proof header merged into `headers`, plus `proofHeader`.
     */
    @JvmStatic
    fun signRequestWithProof(input: Map<String, Any?>): Map<String, Any?> {
        if (!def(input, "pcactn")) throw IllegalArgumentException("signRequestWithProof: pcactn is required")
        val proof = proofHeaders(input["pcactn"])
        val headers = LinkedHashMap<String, Any?>()
        val h = input["headers"]
        if (h is Map<*, *>) headers.putAll(h as Map<String, Any?>)
        headers.putAll(proof)
        val cover = ArrayList<Any?>()
        if (input["coverHeaders"] != null) cover.addAll(Js.list(input["coverHeaders"]))
        cover.add(PCA_PROOF_COMPONENT)
        val rest = LinkedHashMap(input)
        rest.remove("pcactn")
        rest["headers"] = headers
        rest["coverHeaders"] = cover
        val result = LinkedHashMap(signRequest(rest))
        val merged = LinkedHashMap(Js.map(result["headers"]))
        merged.putAll(proof)
        result["headers"] = merged
        result["proofHeader"] = proof
        return result
    }

    /**
     * Verify the HTTP Message Signature AND extract the proof: requires `PCA-Action` to be a covered component (else fail closed), decodes the
     * PCActn from it, and, when `opts.expectedPCActn` is given, checks the carried proof equals it by canonical digest. The returned
     * `pcactn` is bound to the verified signature.
     */
    @JvmStatic
    fun verifySignedRequestWithProof(req: Map<String, Any?>, opts: Map<String, Any?>): Map<String, Any?> {
        val base = verifySignedRequest(req, opts)
        if (base["valid"] != true) return base
        val cov = base["covered"]
        if (cov !is List<*> || !(cov as List<Any?>).contains(PCA_PROOF_COMPONENT)) return invalid("the $PCA_HEADER proof header is not covered by the signature")
        val found: String? = try {
            normalizeHeaders(req["headers"])[PCA_PROOF_COMPONENT]
        } catch (e: RuntimeException) {
            return invalid("verification failed (fail closed): " + e.message)
        }
        val headerValue = found ?: return invalid("missing $PCA_HEADER header")
        val pcactn = try {
            decodeProofHeader(headerValue)
        } catch (e: RuntimeException) {
            return invalid("invalid PCActn in $PCA_HEADER: " + e.message)
        }
        if (opts["expectedPCActn"] != null && Pca.hashCanonical(pcactn) != Pca.hashCanonical(opts["expectedPCActn"])) {
            return invalid("carried PCActn does not match the expected proof")
        }
        val out = LinkedHashMap(base)
        out["pcactn"] = pcactn
        return out
    }
}
