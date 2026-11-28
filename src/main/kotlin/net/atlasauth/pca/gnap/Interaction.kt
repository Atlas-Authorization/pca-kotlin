package net.atlasauth.pca.gnap

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Keys

/**
 * GNAP interaction modes (RFC 9635 sections 2.5, 3.3, 4, 5.1): the four start modes, the two finish methods, the interaction hash,
 * one-time interaction references, and an authorization-server state machine (pending, approved, finalized). The approved
 * interaction then continues through the PCA step-up continuation ([Gnap.beginGnapContinuation] / [Gnap.completeGnapContinuation]).
 */
@Suppress("UNCHECKED_CAST")
object Interaction {
    @JvmField val START_MODES: List<String> = listOf("redirect", "app", "user_code", "user_code_uri")
    @JvmField val FINISH_METHODS: List<String> = listOf("redirect", "push")
    /** Named Information hash names (IANA) this implementation computes, with the digest each maps to. */
    @JvmField val HASH_METHODS: Map<String, String> = linkedMapOf(
        "sha-256" to "SHA-256", "sha-384" to "SHA-384", "sha-512" to "SHA-512", "sha3-256" to "SHA3-256", "sha3-512" to "SHA3-512",
    )

    /** The names JavaScript's `in` finds on a plain object besides its own keys (a hash_method of one of these passes [validateInteractRequest]). */
    private val OBJECT_PROTO_NAMES = setOf("constructor", "__defineGetter__", "__defineSetter__", "hasOwnProperty", "__lookupGetter__",
        "__lookupSetter__", "isPrototypeOf", "propertyIsEnumerable", "toString", "valueOf", "__proto__", "toLocaleString")
    private val RNG = SecureRandom()

    private fun inHashMethods(m: Any?): Boolean = GnapJs.str(m).let { it in HASH_METHODS || it in OBJECT_PROTO_NAMES }

    private fun obj(vararg kv: Pair<String, Any?>) = Issue.obj(*kv)

    private fun randomB64u(n: Int): String = ByteArray(n).also { RNG.nextBytes(it) }.let { Keys.b64u(it) }

    private fun startName(e: Any?): String? = when {
        e is String -> e
        e is Map<*, *> && e["mode"] is String -> e["mode"] as String
        else -> null
    }

    // ---- callback URI check ----
    private val SPECIAL = setOf("http", "https", "ftp", "ws", "wss", "file")
    private val SCHEME = Regex("[A-Za-z][A-Za-z0-9+.\\-]*")
    private val DIGITS = Regex("[0-9]+")
    private val HEX_LABEL = Regex("0[xX][0-9a-fA-F]*")
    private val OCTET = Regex("[0-9]{1,3}")

    /** The text a WHATWG URL parser works on: leading and trailing C0 controls and spaces dropped, tab, LF and CR removed. */
    private fun urlInput(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && s[a] <= ' ') a++
        while (b > a && s[b - 1] <= ' ') b--
        val sb = StringBuilder()
        for (i in a until b) { val c = s[i]; if (c != '\t' && c != '\n' && c != '\r') sb.append(c) }
        return sb.toString()
    }

    private fun isHostChar(c: Char) = (c in 'a'..'z') || (c in 'A'..'Z') || (c in '0'..'9') || c == '-' || c == '.' || c == '_'

    private fun numericLabel(label: String): Boolean = label.isNotEmpty() && (DIGITS.matches(label) || HEX_LABEL.matches(label))

    /** A dotted-quad IPv4 literal of four decimal parts each at most 255 (the only numeric host this check accepts). */
    private fun plainIpv4(host: String): Boolean {
        val p = host.split(".")
        if (p.size != 4) return false
        return p.all { x -> OCTET.matches(x) && !(x.length > 1 && x[0] == '0') && x.toInt() <= 255 }
    }

    /** The parsed shape of a callback URI: lowercase scheme, host (lowercase; null when the scheme has none), the text after the authority. */
    private class Url(val scheme: String) {
        var host: String? = null // as URL.hostname prints it ("[::1]" keeps its brackets)
        var userinfo: String? = null
        var port: String = "" // as given, "" when absent
        var rest: String? = null // path, query (no fragment: callbackUriOk refuses those)
        var hasAuthority = false
    }

    /**
     * A conservative reading of what `new URL(uri)` accepts. Anything this parser is unsure about (a special scheme without `//`,
     * an internationalized or exotic host, a short IPv4 form, an IPv6 literal other than `[::1]`) is refused: the result is never
     * more permissive than the reference.
     */
    private fun parseUrl(uri: String): Url? {
        val s = urlInput(uri)
        val colon = s.indexOf(':')
        if (colon <= 0) return null
        val scheme = s.substring(0, colon)
        if (!SCHEME.matches(scheme)) return null
        val u = Url(scheme.lowercase(Locale.ROOT))
        val after = s.substring(colon + 1)
        val special = u.scheme in SPECIAL
        if (!after.startsWith("//")) {
            if (special) return null
            u.rest = after
            return u
        }
        var auth = after.substring(2)
        var end = auth.length
        for (i in auth.indices) { val c = auth[i]; if (c == '/' || c == '?' || (special && c == '\\')) { end = i; break } }
        u.rest = auth.substring(end)
        auth = auth.substring(0, end)
        u.hasAuthority = true
        val at = auth.lastIndexOf('@')
        u.userinfo = if (at >= 0) auth.substring(0, at) else null
        val hostport = if (at >= 0) auth.substring(at + 1) else auth
        val pc = hostport.lastIndexOf(':')
        var host = hostport
        var port = ""
        if (hostport.startsWith("[")) {
            val close = hostport.indexOf(']')
            if (close < 0) return null
            host = hostport.substring(0, close + 1)
            val tail = hostport.substring(close + 1)
            if (tail.isNotEmpty()) { if (!tail.startsWith(":")) return null; port = tail.substring(1) }
            if (host != "[::1]") return null // the only IPv6 literal this check reads
        } else if (pc >= 0) {
            host = hostport.substring(0, pc)
            port = hostport.substring(pc + 1)
        }
        if (port.isNotEmpty() && (!DIGITS.matches(port) || port.length > 9 || port.toLong() > 65535)) return null
        u.port = port
        if (!host.startsWith("[")) {
            if (!host.all { isHostChar(it) }) return null
            if (host.isEmpty() && special && u.scheme != "file") return null
            val h = if (host.endsWith(".")) host.substring(0, host.length - 1) else host
            val last = if (h.contains(".")) h.substring(h.lastIndexOf('.') + 1) else h
            if (numericLabel(last) && !plainIpv4(host)) return null
            if (host.split(".").any { it.lowercase(Locale.ROOT).startsWith("xn--") }) return null
        }
        u.host = host.lowercase(Locale.ROOT)
        return u
    }

    /** RFC 9635 2.5.2: absolute URI, no fragment; HTTPS, loopback, or an application-specific scheme (not plain http to a remote host). */
    fun callbackUriOk(uri: Any?): Boolean {
        if (uri !is String || uri.length > 2048) return false
        val u = parseUrl(uri) ?: return false
        if (uri.indexOf('#') >= 0) return false
        if (u.scheme == "https") return true
        if (u.scheme == "http") return u.host.let { it == "localhost" || it == "127.0.0.1" || it == "[::1]" }
        return u.scheme != "javascript" && u.scheme != "data" && u.scheme != "file" && u.scheme != "blob"
    }

    private fun printableAscii(s: String): Boolean = s.isNotEmpty() && s.all { it.code in 0x21..0x7e }

    /** Validate an `interact` request; returns the problems (empty = valid). Unknown start modes are tolerated (the registry is open). */
    fun validateInteractRequest(r: Any?): List<String> {
        val e = ArrayList<String>()
        if (r !is Map<*, *>) return arrayListOf("interact must be an object")
        val start = r["start"]
        if (start !is List<*> || start.isEmpty() || start.size > 16) e.add("start must be a non-empty array of modes")
        else for (s in start) if (startName(s) == null) e.add("each start entry is a mode name or an object with a mode")
        if (r.containsKey("finish")) {
            val f = r["finish"]
            if (!GnapJs.isObject(f)) e.add("finish must be an object")
            else {
                val method = GnapJs.member(f, "method")
                if (method !is String || method !in FINISH_METHODS) e.add("finish.method must be redirect or push")
                if (!callbackUriOk(GnapJs.member(f, "uri"))) e.add("finish.uri must be an absolute https, loopback or app-scheme URI without a fragment")
                val nonce = GnapJs.member(f, "nonce")
                if (nonce !is String || nonce.length < 8 || nonce.length > 256 || !printableAscii(nonce)) e.add("finish.nonce must be 8..256 printable ASCII characters")
                if (GnapJs.has(f, "hash_method") && !inHashMethods((f as Map<*, *>)["hash_method"])) e.add("finish.hash_method is not a supported Named Information hash")
            }
        }
        return e
    }

    private fun asciiBytes(s: String): ByteArray = ByteArray(s.length) { s[it].code.toByte() }

    private fun hashName(method: Any?): String {
        val m = method ?: "sha-256"
        if (!inHashMethods(m)) throw InteractionError("unsupported_hash", "hash_method ${GnapJs.str(m)} is not supported")
        return (if (m is String) HASH_METHODS[m] else null) ?: throw IllegalArgumentException("hash_method names no digest")
    }

    /** RFC 9635 4.2.3: base64url (no padding) of HASH(clientNonce LF asNonce LF interactRef LF grantEndpointUri). `a`: clientNonce, asNonce, interactRef, grantEndpoint, hashMethod. */
    fun interactionHash(a: Map<String, Any?>): String {
        val name = hashName(a["hashMethod"])
        val text = GnapJs.str(GnapJs.get(a, "clientNonce")) + "\n" + GnapJs.str(GnapJs.get(a, "asNonce")) + "\n" + GnapJs.str(GnapJs.get(a, "interactRef")) + "\n" +
            GnapJs.str(GnapJs.get(a, "grantEndpoint"))
        return Keys.b64u(GnapJs.sha(name, asciiBytes(text)))
    }

    /** Client side: does the callback's `hash` match? Constant time; a non-validating hash means the interact_ref MUST NOT be sent. */
    fun verifyInteractionHash(received: Any?, a: Map<String, Any?>): Boolean {
        if (received !is String) return false
        val want = Json.utf8(interactionHash(a))
        val got = Json.utf8(received)
        return want.size == got.size && MessageDigest.isEqual(want, got)
    }

    private const val CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    /** `len` (6..12) characters from an alphabet without look-alikes; compared case-insensitively (RFC 9635 3.3.3). */
    @JvmOverloads
    fun newUserCode(len: Int = 8): String {
        require(len in 6..12) { "user code length 6..12" }
        val b = ByteArray(len).also { RNG.nextBytes(it) }
        // 32 symbols, 256 % 32 == 0: no modulo bias
        return String(CharArray(len) { CODE_ALPHABET[(b[it].toInt() and 0xff) % 32] })
    }

    private fun normCode(c: String): String {
        val sb = StringBuilder()
        for (ch in c) {
            val ws = ch == '-' || ch == ' ' || (ch in '\t'..'\r') || ch == ' ' || ch == ' ' || (ch in ' '..' ') || ch == ' ' ||
                ch == ' ' || ch == ' ' || ch == ' ' || ch == '　' || ch == '﻿'
            if (!ws) sb.append(ch)
        }
        return sb.toString().uppercase(Locale.ROOT)
    }

    /** One interaction: state pending, approved or finalized. */
    class State internal constructor(val id: String, val grantEndpoint: String) {
        var state = "pending"
        var modes: List<String> = emptyList()
        var finish: MutableMap<String, Any?>? = null // method, uri, clientNonce, asNonce, hashMethod
        var userCode: String? = null
        var interactRef: String? = null
        var refUsed = false
        var expiresAt = 0L

        /** The object the reference holds (members that were never set are absent). */
        fun toMap(): Map<String, Any?> {
            val m = Issue.obj("id" to id, "state" to state, "grantEndpoint" to grantEndpoint, "modes" to ArrayList<Any?>(modes))
            finish?.let { m["finish"] = it }
            userCode?.let { m["userCode"] = it }
            interactRef?.let { m["interactRef"] = it }
            m["refUsed"] = refUsed
            m["expiresAt"] = expiresAt
            return m
        }
    }

    /**
     * The authorization server's interaction endpoint. `supports`: the modes this AS supports; `redirectUri`, `appUri` build the
     * interaction URIs; `userCodeUri` is the user-code page; `ttlSec` (default 600); `now` is the clock in seconds.
     */
    class Server(
        private val grantEndpoint: String,
        private val supports: List<String>,
        private val redirectUri: (String) -> String,
        private val appUri: ((String) -> String)?,
        private val userCodeUri: String?,
        private val ttlSec: Long?,
        private val now: () -> Long,
    ) {
        private val byId = HashMap<String, State>()
        private val byCode = HashMap<String, String>()
        private val byRef = HashMap<String, String>()

        /** Start an interaction from an `interact` request: `{interaction, response}`. The response never names a mode the client did not ask for nor one the AS does not support (RFC 9635 3.3). */
        fun start(req: Map<String, Any?>): Map<String, Any?> {
            val problems = validateInteractRequest(req)
            if (problems.isNotEmpty()) throw InteractionError("invalid_request", problems.joinToString("; "))
            val asked = (req["start"] as List<Any?>).map { startName(it) }.toSet()
            val modes = supports.filter { m -> m in asked && (m != "app" || appUri != null) && (m != "user_code_uri" || !userCodeUri.isNullOrEmpty()) }
            val hasFinish = GnapJs.truthy(req["finish"])
            if (modes.isEmpty() && !hasFinish) throw InteractionError("invalid_interaction", "no requested interaction mode is supported")
            val id = randomB64u(16)
            val ttl = ttlSec ?: 600L
            val it = State(id, grantEndpoint)
            it.modes = modes
            it.expiresAt = now() + ttl
            val res = obj("expires_in" to ttl)
            if ("redirect" in modes) res["redirect"] = redirectUri(id)
            if ("app" in modes) res["app"] = appUri!!.invoke(id)
            if ("user_code" in modes || "user_code_uri" in modes) {
                val code = newUserCode()
                it.userCode = code
                byCode[code] = id
                if ("user_code" in modes) res["user_code"] = code
                if ("user_code_uri" in modes) res["user_code_uri"] = obj("code" to code, "uri" to userCodeUri)
            }
            if (hasFinish) {
                val f = req["finish"] as Map<String, Any?>
                val asNonce = randomB64u(24)
                it.finish = obj("method" to f["method"], "uri" to f["uri"], "clientNonce" to f["nonce"], "asNonce" to asNonce, "hashMethod" to (f["hash_method"] ?: "sha-256"))
                res["finish"] = asNonce
            }
            byId[id] = it
            return obj("interaction" to it, "response" to res)
        }

        /** The resource owner typed a code. Case-insensitive. A 32^8 code space is only safe behind a per-source rate limit on this lookup: the caller MUST apply one. */
        fun lookupUserCode(code: String): State? {
            val it = byCode[normCode(code)]?.let { byId[it] } ?: return null
            return if (it.state != "pending" || now() > it.expiresAt) null else it
        }

        fun get(id: String): State? = byId[id]

        private fun live(id: String): State {
            val it = byId[id] ?: throw InteractionError("unknown_interaction", "no such interaction")
            if (now() > it.expiresAt) throw InteractionError("expired", "the interaction expired")
            return it
        }

        /** The resource owner approved. Returns `{interactRef, finish?}`: the finish message to deliver (redirect URL or push body), if the client asked for one. */
        fun approve(id: String): Map<String, Any?> {
            val it = live(id)
            if (it.state != "pending") throw InteractionError("wrong_state", "interaction is ${it.state}")
            it.state = "approved"
            val ref = randomB64u(18)
            it.interactRef = ref
            byRef[ref] = id
            it.userCode?.let { c -> byCode.remove(c) }
            val fin = it.finish ?: return obj("interactRef" to ref)
            val hash = interactionHash(obj("clientNonce" to fin["clientNonce"], "asNonce" to fin["asNonce"], "interactRef" to ref,
                "grantEndpoint" to it.grantEndpoint, "hashMethod" to fin["hashMethod"]))
            if (fin["method"] == "push")
                return obj("interactRef" to ref, "finish" to obj("method" to "push", "uri" to fin["uri"], "body" to obj("hash" to hash, "interact_ref" to ref)))
            return obj("interactRef" to ref, "finish" to obj("method" to "redirect", "url" to redirectUrl(fin["uri"] as String, hash, ref)))
        }

        /** Continuation (RFC 9635 5.1): present the interact_ref once. A replay finalizes the grant and is `too_many_attempts`. */
        fun consume(interactRef: String): State {
            val it = byRef[interactRef]?.let { byId[it] } ?: throw InteractionError("unknown_interaction", "no such interaction reference")
            if (it.refUsed || it.state == "finalized") {
                it.state = "finalized"
                throw InteractionError("too_many_attempts", "the interaction reference was already used")
            }
            if (now() > it.expiresAt) throw InteractionError("expired", "the interaction expired")
            if (it.state != "approved") throw InteractionError("wrong_state", "interaction is ${it.state}")
            it.refUsed = true
            return it
        }

        fun finalizeInteraction(id: String) {
            byId[id]?.state = "finalized"
        }
    }

    // ---- redirect URL ----
    private fun hexVal(b: Byte): Int = when (val c = b.toInt()) {
        in 0x30..0x39 -> c - 0x30
        in 0x41..0x46 -> c - 0x37
        in 0x61..0x66 -> c - 0x57
        else -> -1
    }

    /** application/x-www-form-urlencoded percent-decoding as WHATWG does it: a malformed escape stays literal, invalid UTF-8 becomes U+FFFD. */
    private fun formDecode(s: String): String {
        val out = ByteArrayOutputStream()
        val b = Json.utf8(s)
        var i = 0
        while (i < b.size) {
            if (b[i] == '%'.code.toByte() && i + 2 < b.size && hexVal(b[i + 1]) >= 0 && hexVal(b[i + 2]) >= 0) {
                out.write(hexVal(b[i + 1]) * 16 + hexVal(b[i + 2]))
                i += 3
            } else {
                out.write(b[i].toInt() and 0xff)
                i++
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    private fun formEncode(s: String): String {
        val sb = StringBuilder()
        for (bb in Json.utf8(s)) {
            val b = bb.toInt() and 0xff
            val c = b.toChar()
            if ((c in 'a'..'z') || (c in 'A'..'Z') || (c in '0'..'9') || c == '*' || c == '-' || c == '.' || c == '_') sb.append(c)
            else if (c == ' ') sb.append('+')
            else sb.append('%').append(String.format("%02X", b))
        }
        return sb.toString()
    }

    private val LEADING_ZEROS = Regex("^0+(?=[0-9])")

    /**
     * `new URL(uri)` with `hash` and `interact_ref` set via `searchParams.set`, printed. Covers the callback forms [callbackUriOk]
     * accepts: the scheme and host in lower case, the scheme's default port dropped, an empty path of a special scheme printed as
     * `/`; the query is re-serialized as `application/x-www-form-urlencoded`.
     */
    private fun redirectUrl(uri: String, hash: String, ref: String): String {
        val u = parseUrl(uri) ?: throw IllegalArgumentException("not a URL: $uri")
        val rest = u.rest ?: ""
        val q = rest.indexOf('?')
        var path = if (q >= 0) rest.substring(0, q) else rest
        val query = if (q >= 0) rest.substring(q + 1) else ""
        val params = ArrayList<Array<String>>()
        if (query.isNotEmpty()) {
            for (pair in query.split("&")) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                val k = formDecode((if (eq >= 0) pair.substring(0, eq) else pair).replace('+', ' '))
                val v = formDecode((if (eq >= 0) pair.substring(eq + 1) else "").replace('+', ' '))
                params.add(arrayOf(k, v))
            }
        }
        for (kv in arrayOf(arrayOf("hash", hash), arrayOf("interact_ref", ref))) {
            var set = false
            var i = 0
            while (i < params.size) {
                if (params[i][0] != kv[0]) { i++; continue }
                if (!set) { params[i][1] = kv[1]; set = true; i++ } else params.removeAt(i)
            }
            if (!set) params.add(kv)
        }
        val qs = params.joinToString("&") { formEncode(it[0]) + "=" + formEncode(it[1]) }
        val out = StringBuilder(u.scheme).append(':')
        if (u.hasAuthority) {
            out.append("//")
            if (!u.userinfo.isNullOrEmpty()) out.append(u.userinfo).append('@')
            out.append(u.host)
            val dp = when (u.scheme) { "https", "wss" -> "443"; "http", "ws" -> "80"; "ftp" -> "21"; else -> "" }
            val port = LEADING_ZEROS.replaceFirst(u.port, "")
            if (port.isNotEmpty() && port != dp) out.append(':').append(port)
            if (path.isEmpty() && u.scheme in SPECIAL) path = "/"
        }
        out.append(path).append('?').append(qs)
        return out.toString()
    }

    /**
     * Client side: validate a finish callback (query for redirect, JSON body for push). Returns the interact_ref to send, or throws
     * `unknown_interaction`. `ctx`: clientNonce, asNonce, grantEndpoint, hashMethod.
     */
    fun acceptFinish(cb: Map<String, Any?>, ctx: Map<String, Any?>): String {
        val ref = cb["interact_ref"]
        if (ref !is String || ref.isEmpty() || cb["hash"] !is String) throw InteractionError("unknown_interaction", "hash and interact_ref are required")
        val a = LinkedHashMap(ctx)
        a["interactRef"] = ref
        if (!verifyInteractionHash(cb["hash"], a)) throw InteractionError("unknown_interaction", "the callback hash does not validate")
        return ref
    }

    /**
     * One need (`{verb, resource}`) per (action, location) pair, the resource namespaced as `gnap:<type>:<location>` exactly like
     * [Gnap.gnapActionResource]. An access right with no `actions` or no `locations` is a wildcard and is REFUSED here.
     */
    fun accessToNeeds(access: List<Any?>): List<Any?> {
        val out = ArrayList<Any?>()
        for (ao in access) {
            if (ao == null) throw IllegalArgumentException("access entry is null")
            val actions = GnapJs.member(ao, "actions")
            val locations = GnapJs.member(ao, "locations")
            if (actions !is List<*> || actions.isEmpty() || locations !is List<*> || locations.isEmpty())
                throw InteractionError("invalid_request", "access \"${GnapJs.str(GnapJs.member(ao, "type"))}\" needs explicit actions and locations to become a need")
            for (verb in actions) for (loc in locations)
                out.add(obj("verb" to verb, "resource" to "gnap:" + GnapJs.str(GnapJs.member(ao, "type")) + ":" + GnapJs.str(loc)))
        }
        return out
    }
}
