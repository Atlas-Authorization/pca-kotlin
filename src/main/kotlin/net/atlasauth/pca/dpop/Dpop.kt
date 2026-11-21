package net.atlasauth.pca.dpop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/** A DPoP proof (or PCActn/DPoP binding) that failed to verify; [code] names the specific check. */
class DpopVerificationError(val code: String, message: String) : RuntimeException(message)

/** A replay store for `jti` values. */
interface JtiSeenSet {
    fun has(jti: String): Boolean
    fun add(jti: String)
}

/**
 * A durable, atomic `jti` replay store: [addIfAbsent] must be atomic (of N concurrent calls with one key exactly one returns true).
 * The key is `<jkt>.<jti>`. An entry may be dropped once `nowSec >= expiresAtSec`.
 */
fun interface DpopReplayStore {
    fun addIfAbsent(key: String, expiresAtSec: Double, nowSec: Double): Boolean
}

/** Issues and checks stateless server DPoP nonces (RFC 9449 s8/s9): a timestamp MACed with a server secret. */
interface DpopNonceIssuer {
    /** A fresh nonce for a `DPoP-Nonce` header (null = now). */
    fun issue(nowSec: Long? = null): String

    /** True only for a nonce this issuer minted that is at most ttlSec old and not from the future (null = now). */
    fun check(nonce: Any?, nowSec: Double? = null): Boolean
}

/** Input of [Dpop.createDpopProof]. */
class CreateDpopProofInput(
    /** HTTP method (case-insensitive in; stored uppercased as `htm`). */
    var method: String? = null,
    /** Full request URL; `htu` is this with query and fragment removed. */
    var url: String? = null,
    /** The holder's PRIVATE JWK that signs the proof. */
    var privateKey: Map<String, Any?>? = null,
    /** The holder's PUBLIC JWK, embedded in the proof header; drives the `alg`. */
    var publicJwk: Map<String, Any?>? = null,
    var nonce: String? = null,
    var ath: String? = null,
    /** Issued-at override (epoch seconds); null = now. */
    var iat: Double? = null,
    /** Proof id override; null = a random UUID. */
    var jti: String? = null,
)

/** Options of [Dpop.verifyDpopProof]. */
class VerifyDpopProofOptions(
    var method: String? = null,
    var url: String? = null,
    /** Maximum accepted proof age in seconds (from `iat` to now). */
    var maxAgeSec: Double = 0.0,
    var expectedJkt: String? = null,
    var seenJti: JtiSeenSet? = null,
    var replayStore: DpopReplayStore? = null,
    /** Default true: a verification with neither store is refused (`replay_store_required`). */
    var requireReplayStore: Boolean? = null,
    var nonceIssuer: DpopNonceIssuer? = null,
    /** Override "now" (epoch seconds). */
    var nowSec: Double? = null,
    var expectedNonce: String? = null,
    var accessToken: String? = null,
)

/** Options of [Dpop.assertPcaDpop]: like [VerifyDpopProofOptions] with maxAgeSec optional (default 300) and no expectedJkt. */
class AssertPcaDpopOptions(
    var method: String? = null,
    var url: String? = null,
    var maxAgeSec: Double? = null,
    var seenJti: JtiSeenSet? = null,
    var replayStore: DpopReplayStore? = null,
    var requireReplayStore: Boolean? = null,
    var nonceIssuer: DpopNonceIssuer? = null,
    var nowSec: Double? = null,
    var expectedNonce: String? = null,
    var accessToken: String? = null,
)

/** A verified proof: its claims, the embedded public JWK and that key's RFC 7638 thumbprint. */
class DpopVerifyResult internal constructor(val claims: Map<String, Any?>, val jwk: Map<String, Any?>, val jkt: String)

/**
 * Sender-constrained proof-of-possession: RFC 9449 DPoP proofs (holder-key-signed `dpop+jwt` over the HTTP method and target URI, key
 * thumbprint `jkt`) and RFC 8705 mTLS `x5t#S256` confirmation, bound to a PCActn's real holder key (the leaf of its capability chain,
 * an Ed25519 key). Keys are JWK maps. Verification fails closed with a [DpopVerificationError] whose code names the failed check.
 */
object Dpop {
    /** JWS algorithms a DPoP proof may use: asymmetric only, never none or a MAC (RFC 9449 s4.2). */
    @JvmField val DPOP_ALLOWED_ALGS: List<String> = listOf("EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256")
    const val DPOP_JWT_TYP = "dpop+jwt"
    const val DPOP_DEFAULT_MAX_AGE_SEC = 300.0
    const val DPOP_CLOCK_SKEW_SEC = 5.0
    const val DPOP_MAX_PROOF_BYTES = 8192
    const val DPOP_INMEMORY_MAX_ENTRIES = 100_000

    private fun err(code: String, message: String) = DpopVerificationError(code, message)

    private fun nowSec(): Double = Math.floor(System.currentTimeMillis() / 1000.0)

    // ---- replay stores ----

    /**
     * Single-process, explicitly bounded store: when [maxEntries] live entries are held a further new key makes addIfAbsent throw (the
     * verifier then refuses with `replay_store_error`) instead of evicting a live entry. Null = [DPOP_INMEMORY_MAX_ENTRIES].
     */
    @JvmStatic
    @JvmOverloads
    fun createInMemoryDpopReplayStore(maxEntries: Double? = null): DpopReplayStore {
        val max = maxEntries ?: DPOP_INMEMORY_MAX_ENTRIES.toDouble()
        if (max.isNaN() || max.isInfinite() || max != Math.rint(max) || max < 1) throw err("misconfigured", "maxEntries must be a positive integer")
        val seen = LinkedHashMap<String, Double>()
        return DpopReplayStore { key, expiresAtSec, now ->
            if (!now.isFinite()) return@DpopReplayStore false // a non-finite clock admits nothing, whichever side it lands on
            synchronized(seen) {
                val held = seen[key]
                if (held != null && !(now >= held)) return@DpopReplayStore false
                if (held == null && seen.size >= max) {
                    seen.values.removeAll { now >= it }
                    if (seen.size >= max) throw IllegalStateException("replay store is full")
                }
                seen[key] = expiresAtSec
                true
            }
        }
    }

    /** Conformance suite for a [DpopReplayStore]: the failed checks (empty = conformant). [make] returns a FRESH empty store. */
    @JvmStatic
    fun runDpopReplayStoreConformance(make: () -> DpopReplayStore): List<String> {
        val failures = ArrayList<String>()
        val s = make()
        if (!s.addIfAbsent("a", 200.0, 100.0)) failures.add("first sight of a key returns true")
        if (s.addIfAbsent("a", 200.0, 101.0)) failures.add("second sight of the same key returns false")
        if (!s.addIfAbsent("b", 200.0, 101.0)) failures.add("a different key is independent")
        if (s.addIfAbsent("a", 200.0, 199.0)) failures.add("still seen one second before expiry")
        val t = make()
        t.addIfAbsent("c", 200.0, 100.0)
        if (!t.addIfAbsent("c", 400.0, 200.0)) failures.add("an expired entry may be added again (nowSec >= expiresAtSec)")
        val u = make()
        var wins = 0
        val pool = Executors.newFixedThreadPool(16)
        try {
            val fs = (0 until 16).map { pool.submit(Callable { u.addIfAbsent("race", 200.0, 100.0) }) }
            for (f in fs) {
                try {
                    if (f.get()) wins++
                } catch (e: Exception) { // a store that throws under contention fails the check below
                }
            }
        } finally {
            pool.shutdown()
        }
        if (wins != 1) failures.add("16 concurrent adds of one key: exactly one wins (got $wins)")
        return failures
    }

    // ---- server nonces ----

    private fun hmac(secret: ByteArray, ts: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(secret, "HmacSHA256"))
        m.update("dpop-nonce\u0000".toByteArray(Charsets.UTF_8))
        m.update(ts)
        return m.doFinal().copyOf(16)
    }

    /** Creates a [DpopNonceIssuer]: [secret] at least 32 bytes, [ttlSec] the lifetime (null = 300). */
    @JvmStatic
    @JvmOverloads
    fun createDpopNonceIssuer(secret: ByteArray?, ttlSec: Double? = null): DpopNonceIssuer {
        if (secret == null || secret.size < 32) throw err("misconfigured", "nonce secret must be at least 32 bytes")
        val ttl = ttlSec ?: 300.0
        if (ttl.isNaN() || ttl.isInfinite() || ttl <= 0) throw err("misconfigured", "nonce ttlSec must be positive")
        val key = secret.clone()
        return object : DpopNonceIssuer {
            override fun issue(nowSec: Long?): String {
                val n = nowSec ?: Math.floorDiv(System.currentTimeMillis(), 1000L)
                val ts = ByteArray(8) { i -> (n ushr (56 - 8 * i)).toByte() }
                return Jose.b64u(ts + hmac(key, ts))
            }

            override fun check(nonce: Any?, nowSec: Double?): Boolean {
                if (nonce !is String) return false
                val now = nowSec ?: nowSec()
                val raw = Pca.decodeB64uStrict(nonce, 24) ?: return false
                val ts = raw.copyOfRange(0, 8)
                if (!MessageDigest.isEqual(raw.copyOfRange(8, 24), hmac(key, ts))) return false
                val issued = BigInteger(1, ts).toDouble()
                return issued <= now + DPOP_CLOCK_SKEW_SEC && now - issued <= ttl
            }
        }
    }

    // ---- helpers ----

    /** The JavaScript read `jwk.member` (undefined for anything that is not an object; a TypeError for null). */
    private fun member(jwk: Any?, name: String): Any? {
        if (jwk == null) throw IllegalArgumentException("Cannot read properties of null (reading '$name')")
        return (jwk as? Map<*, *>)?.get(name)
    }

    /** RFC 7638 JWK SHA-256 thumbprint (base64url). */
    @JvmStatic
    @JvmOverloads
    fun jwkThumbprint(jwk: Map<String, Any?>, digest: String? = null): String = Jose.jwkThumbprint(jwk, digest)

    private fun jsStr(o: Any?): String = when (o) {
        null -> "undefined"
        is String -> o
        else -> try { Json.canonicalize(o) } catch (e: RuntimeException) { o.toString() }
    }

    /** The JWS `alg` for a key, from its JWK kty / crv. Throws `unsupported_key` for an unsupported or MAC key. */
    @JvmStatic
    fun dpopAlgForJwk(jwk: Map<String, Any?>?): String {
        val kty = member(jwk, "kty")
        val crv = member(jwk, "crv")
        return when (kty) {
            "OKP" -> if (crv == "Ed25519" || crv == "Ed448") "EdDSA" else throw err("unsupported_key", "unsupported OKP curve '${jsStr(crv)}' for DPoP")
            "EC" -> when (crv) {
                "P-256" -> "ES256"
                "P-384" -> "ES384"
                "P-521" -> "ES512"
                else -> throw err("unsupported_key", "unsupported EC curve '${jsStr(crv)}' for DPoP")
            }
            "RSA" -> "PS256"
            else -> throw err("unsupported_key", "unsupported key type '${jsStr(kty)}' for DPoP")
        }
    }

    /** True when the allow-listed JWS `alg` belongs to the key type of [jwk]. Unknown algs never match. */
    @JvmStatic
    fun dpopAlgMatchesJwk(alg: String, jwk: Any?): Boolean {
        if (alg !in listOf("EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256")) return false // the reference reads the jwk only inside a known alg's branch
        val kty = member(jwk, "kty")
        val crv = member(jwk, "crv")
        return when (alg) {
            "EdDSA" -> kty == "OKP" && (crv == "Ed25519" || crv == "Ed448")
            "ES256" -> kty == "EC" && crv == "P-256"
            "ES384" -> kty == "EC" && crv == "P-384"
            "ES512" -> kty == "EC" && crv == "P-521"
            "PS256", "RS256" -> kty == "RSA"
            else -> false
        }
    }

    private fun toPublicJwk(jwk: Map<String, Any?>): Map<String, Any?> {
        val pub = LinkedHashMap<String, Any?>()
        for (k in listOf("kty", "crv", "x", "y", "n", "e")) if (jwk.containsKey(k)) pub[k] = jwk[k]
        return pub
    }

    /** The access-token hash `ath`: base64url(SHA-256(access token)), RFC 9449 s4.2. */
    @JvmStatic
    fun athFor(accessToken: String): String = Jose.b64u(Jose.sha256(Jose.utf8(accessToken)))

    // ---- WHATWG-style URL reduction (protocol // host path) ----

    private val SPECIAL = setOf("http", "https", "ws", "wss", "ftp")

    private fun defaultPort(scheme: String): Int = when (scheme) {
        "http", "ws" -> 80
        "https", "wss" -> 443
        "ftp" -> 21
        else -> -1
    }

    private const val HOST_FORBIDDEN = "\u0000\t\n\r #/:<>?@[\\]^|"

    private fun bad(): Nothing = throw IllegalArgumentException("Invalid URL")

    private fun isHex(c: Char) = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

    private fun percentEncode(s: String, pathSet: Boolean): String {
        val sb = StringBuilder()
        for (b in Jose.utf8(s)) {
            val c = b.toInt() and 0xff
            var enc = c < 0x20 || c > 0x7e
            if (!enc && pathSet && " \"#<>?`{}".indexOf(c.toChar()) >= 0) enc = true
            if (enc) sb.append('%').append(String.format(Locale.ROOT, "%02X", c)) else sb.append(c.toChar())
        }
        return sb.toString()
    }

    private fun percentDecode(s: String): String {
        val inb = Jose.utf8(s)
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < inb.size) {
            if (inb[i] == '%'.code.toByte() && i + 2 < inb.size && isHex(inb[i + 1].toInt().toChar()) && isHex(inb[i + 2].toInt().toChar())) {
                out.write(String(inb, i + 1, 2, Charsets.US_ASCII).toInt(16))
                i += 3
            } else {
                out.write(inb[i].toInt())
                i++
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    private fun ipv4Number(input: String): BigInteger? {
        if (input.isEmpty()) return null
        var radix = 10
        var s = input
        if (s.length >= 2 && (s.startsWith("0x") || s.startsWith("0X"))) {
            s = s.substring(2); radix = 16
        } else if (s.length >= 2 && s[0] == '0') {
            s = s.substring(1); radix = 8
        }
        if (s.isEmpty()) return BigInteger.ZERO
        for (c in s) if (Character.digit(c, radix) < 0 || c > 'f') return null
        return BigInteger(s, radix)
    }

    private fun endsInNumber(host: String): Boolean {
        val parts = host.split(".").toMutableList()
        if (parts.last().isEmpty()) {
            if (parts.size == 1) return false
            parts.removeAt(parts.size - 1)
        }
        val last = parts.last()
        if (last.isNotEmpty() && last.all { it in '0'..'9' }) return true
        return ipv4Number(last) != null
    }

    private fun ipv4Parse(host: String): String {
        val parts = host.split(".").toMutableList()
        if (parts.last().isEmpty() && parts.size > 1) parts.removeAt(parts.size - 1)
        if (parts.size > 4) bad()
        val nums = parts.map { ipv4Number(it) ?: bad() }
        val b255 = BigInteger.valueOf(255)
        val b256 = BigInteger.valueOf(256)
        for (i in 0 until nums.size - 1) if (nums[i] > b255) bad()
        if (nums.last() >= b256.pow(5 - nums.size)) bad()
        var ip = nums.last()
        for (i in 0 until nums.size - 1) ip = ip.add(nums[i].multiply(b256.pow(3 - i)))
        val v = ip.toLong()
        return "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"
    }

    private fun ipv6Parse(s: String): String {
        val a = IntArray(8)
        var piece = 0
        var compress = -1
        var p = 0
        val n = s.length
        if (n > p && s[p] == ':') {
            if (n < 2 || s[1] != ':') bad()
            p += 2
            piece++
            compress = piece
        }
        while (p < n) {
            if (piece == 8) bad()
            if (s[p] == ':') {
                if (compress != -1) bad()
                p++
                piece++
                compress = piece
                continue
            }
            var value = 0
            var length = 0
            while (length < 4 && p < n && isHex(s[p])) { value = value * 16 + Character.digit(s[p], 16); p++; length++ }
            if (p < n && s[p] == '.') {
                if (length == 0) bad()
                p -= length
                if (piece > 6) bad()
                var seen = 0
                while (p < n) {
                    var v4 = -1
                    if (seen > 0) {
                        if (s[p] == '.' && seen < 4) p++ else bad()
                    }
                    if (p >= n || s[p] < '0' || s[p] > '9') bad()
                    while (p < n && s[p] in '0'..'9') {
                        val d = s[p] - '0'
                        v4 = when (v4) {
                            -1 -> d
                            0 -> bad()
                            else -> v4 * 10 + d
                        }
                        if (v4 > 255) bad()
                        p++
                    }
                    a[piece] = a[piece] * 256 + v4
                    seen++
                    if (seen == 2 || seen == 4) piece++
                }
                if (seen != 4) bad()
                break
            } else if (p < n && s[p] == ':') {
                p++
                if (p >= n) bad()
            } else if (p < n) bad()
            a[piece] = value
            piece++
        }
        if (compress != -1) {
            var swaps = piece - compress
            piece = 7
            while (piece != 0 && swaps > 0) {
                val t = a[compress + swaps - 1]
                a[compress + swaps - 1] = a[piece]
                a[piece] = t
                piece--
                swaps--
            }
        } else if (piece != 8) bad()
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (a[i] != 0) { i++; continue }
            var j = i
            while (j < 8 && a[j] == 0) j++
            if (j - i > bestLen) { bestLen = j - i; bestStart = i }
            i = j
        }
        if (bestLen < 2) bestStart = -1
        val sb = StringBuilder("[")
        var ignore0 = false
        for (k in 0 until 8) {
            if (ignore0 && a[k] == 0) continue
            ignore0 = false
            if (bestStart == k) { sb.append(if (k == 0) "::" else ":"); ignore0 = true; continue }
            sb.append(Integer.toHexString(a[k]))
            if (k != 7) sb.append(':')
        }
        return sb.append(']').toString()
    }

    private fun parseHost(raw: String, special: Boolean): String {
        if (raw.startsWith("[")) {
            if (!raw.endsWith("]")) bad()
            return ipv6Parse(raw.substring(1, raw.length - 1))
        }
        if (!special) {
            if (raw.any { HOST_FORBIDDEN.indexOf(it) >= 0 }) bad()
            return percentEncode(raw, false)
        }
        val decoded = percentDecode(raw)
        val domain = if (net.atlasauth.pca.jose.Uts46.needed(decoded)) (net.atlasauth.pca.jose.Uts46.toAscii(decoded) ?: bad()).lowercase(Locale.ROOT)
        else decoded.lowercase(Locale.ROOT)
        if (domain.isEmpty()) bad()
        for (c in domain) if (HOST_FORBIDDEN.indexOf(c) >= 0 || c.code <= 0x1f || c == '%' || c.code == 0x7f) bad()
        return if (endsInNumber(domain)) ipv4Parse(domain) else domain
    }

    private fun isDot(seg: String) = seg.lowercase(Locale.ROOT).let { it == "." || it == "%2e" }

    private fun isDotDot(seg: String) = seg.lowercase(Locale.ROOT) in setOf("..", ".%2e", "%2e.", "%2e%2e")

    /** `protocol + "//" + host + pathname` of a URL as `new URL(url)` reads them (query, fragment and credentials dropped). */
    @JvmStatic
    fun normalizeHtu(url: String?): String {
        val u = parseUrl(url)
        return u[0] + "://" + u[1] + u[2]
    }

    /** `new URL(url).host`: the host, with its port when it is not the scheme default (IPv6 in brackets, IDN as punycode). */
    @JvmStatic
    fun urlHost(url: String?): String = parseUrl(url)[1]

    private val SCHEME = Regex("^([A-Za-z][A-Za-z0-9+\\-.]*):")

    /** {scheme, host[:port], pathname} of a URL as the WHATWG parser reads it; IllegalArgumentException when it does not parse. */
    private fun parseUrl(url: String?): Array<String> {
        if (url == null) bad()
        var st = 0
        var en = url.length
        while (st < en && url[st] <= ' ') st++
        while (en > st && url[en - 1] <= ' ') en--
        val s = url.substring(st, en).replace("\t", "").replace("\n", "").replace("\r", "")
        val m = SCHEME.find(s) ?: bad()
        val scheme = m.groupValues[1].lowercase(Locale.ROOT)
        val rest = s.substring(m.range.last + 1)
        val special = scheme in SPECIAL
        var host = ""
        val pathStr: String
        val q = indexOfAny(rest, "?#")
        val beforeQ = if (q < 0) rest else rest.substring(0, q)
        if (special) {
            var i = 0
            while (i < beforeQ.length && (beforeQ[i] == '/' || beforeQ[i] == '\\')) i++
            val after = beforeQ.substring(i)
            val e = indexOfAny(after, "/\\")
            val authority = if (e < 0) after else after.substring(0, e)
            pathStr = if (e < 0) "" else after.substring(e).replace('\\', '/')
            host = hostPort(authority, scheme, true)
            if (host.isEmpty()) bad()
        } else if (beforeQ.startsWith("//")) {
            val after = beforeQ.substring(2)
            val e = after.indexOf('/')
            val authority = if (e < 0) after else after.substring(0, e)
            pathStr = if (e < 0) "" else after.substring(e)
            host = hostPort(authority, scheme, false)
        } else if (beforeQ.startsWith("/")) {
            pathStr = beforeQ
        } else {
            return arrayOf(scheme, "", percentEncode(beforeQ, false)) // opaque path: protocol, empty host, pathname
        }
        var pathname: String
        if (special || pathStr.startsWith("/")) {
            val body = if (pathStr.startsWith("/")) pathStr.substring(1) else pathStr
            val path = ArrayList<String>()
            val segs = body.split("/")
            for ((i, seg) in segs.withIndex()) {
                val last = i == segs.size - 1
                if (isDotDot(seg)) {
                    if (path.isNotEmpty()) path.removeAt(path.size - 1)
                    if (last) path.add("")
                } else if (isDot(seg)) {
                    if (last) path.add("")
                } else {
                    path.add(percentEncode(seg, true))
                }
            }
            pathname = if (path.isEmpty()) "" else "/" + path.joinToString("/")
            if (special && pathname.isEmpty()) pathname = "/"
        } else {
            pathname = ""
        }
        return arrayOf(scheme, host, pathname)
    }

    private fun indexOfAny(s: String, set: String): Int = s.indexOfFirst { set.indexOf(it) >= 0 }

    /** host[:port] of an authority (credentials dropped, default port dropped); IllegalArgumentException on failure. */
    private fun hostPort(authority: String, scheme: String, special: Boolean): String {
        var a = authority
        val at = a.lastIndexOf('@')
        if (at >= 0) {
            a = a.substring(at + 1)
            if (a.isEmpty()) bad()
        }
        var colon = -1
        var bracket = false
        for ((i, c) in a.withIndex()) {
            if (c == '[') bracket = true
            else if (c == ']') bracket = false
            else if (c == ':' && !bracket) { colon = i; break }
        }
        val hostRaw = if (colon < 0) a else a.substring(0, colon)
        val portRaw = if (colon < 0) null else a.substring(colon + 1)
        var port = ""
        if (!portRaw.isNullOrEmpty()) {
            if (portRaw.any { it !in '0'..'9' }) bad()
            val pv = BigInteger(portRaw)
            if (pv > BigInteger.valueOf(65535)) bad()
            if (pv.toInt() != defaultPort(scheme)) port = ":$pv"
        }
        if (hostRaw.isEmpty()) {
            if (special || port.isNotEmpty() || portRaw != null) bad()
            return ""
        }
        return parseHost(hostRaw, special) + port
    }

    // ---- DPoP proof: create / verify ----

    /** Builds and signs a DPoP proof JWT (`typ: dpop+jwt`, embedded public `jwk`, claims htm / htu / iat / jti ...). */
    @JvmStatic
    fun createDpopProof(input: CreateDpopProofInput): String {
        val publicJwk = toPublicJwk(input.publicJwk ?: throw IllegalArgumentException("Cannot read properties of undefined (reading 'kty')"))
        val alg = dpopAlgForJwk(publicJwk)
        val iat = input.iat ?: nowSec()
        val claims = linkedMapOf<String, Any?>(
            "htm" to input.method!!.uppercase(Locale.ROOT),
            "htu" to normalizeHtu(input.url),
            "iat" to if (iat.isNaN() || iat.isInfinite()) null else Js.jsNum(iat),
            "jti" to (input.jti ?: UUID.randomUUID().toString()),
        )
        if (input.nonce != null) claims["nonce"] = input.nonce
        if (input.ath != null) claims["ath"] = input.ath
        val header = linkedMapOf<String, Any?>("typ" to DPOP_JWT_TYP, "alg" to alg, "jwk" to publicJwk)
        return Jose.signJwt(header, claims, input.privateKey ?: throw IllegalArgumentException("privateKey is required"))
    }

    /**
     * Verifies a DPoP proof: signature under the embedded `jwk`, `typ`, that `htm` / `htu` match the request, `iat` freshness, optional
     * `jkt`, nonce and access-token binding, and `jti` replay rejection. Throws [DpopVerificationError] on any failure.
     */
    @JvmStatic
    fun verifyDpopProof(proof: Any?, opts: VerifyDpopProofOptions): DpopVerifyResult {
        // A NaN or infinite max age would disable the stale check (now - iat > NaN is never true): refuse it.
        if (!opts.maxAgeSec.isFinite() || opts.maxAgeSec < 0) throw err("max_age", "maxAgeSec must be a finite, non-negative number of seconds")
        if (opts.requireReplayStore != false && opts.replayStore == null && opts.seenJti == null) {
            throw err("replay_store_required", "no replay store configured; replay cannot be detected")
        }
        if (proof !is String || proof.length > DPOP_MAX_PROOF_BYTES) throw err("oversize", "proof is not a string or exceeds $DPOP_MAX_PROOF_BYTES bytes")
        val header = try {
            Jose.assertCanonicalCompactJws(proof).header
        } catch (e: RuntimeException) {
            throw err("malformed", "not a JWS: " + e.message)
        }
        if (header["typ"] != DPOP_JWT_TYP) throw err("typ", "header typ must be '$DPOP_JWT_TYP', got '${jsStr(header["typ"])}'")
        if (!header.containsKey("jwk")) throw err("no_jwk", "proof header has no embedded jwk")
        val hj = header["jwk"]
        if (hj is Map<*, *> && listOf("d", "p", "q", "dp", "dq", "qi", "k").any { hj.containsKey(it) }) {
            throw err("private_jwk", "proof header jwk contains private key material")
        }
        val alg = header["alg"]
        if (alg is String && alg in DPOP_ALLOWED_ALGS && !dpopAlgMatchesJwk(alg, hj)) {
            throw err("alg_jwk_mismatch", "alg '$alg' does not match the embedded jwk key type")
        }

        val payload: Map<String, Any?>
        val jwk: Map<String, Any?>
        try {
            val res = Jose.jwtVerify(proof, Jose.EMBEDDED, Jose.JwtOptions(typ = DPOP_JWT_TYP, algorithms = DPOP_ALLOWED_ALGS))
            payload = res.payload
            @Suppress("UNCHECKED_CAST")
            jwk = res.protectedHeader["jwk"] as? Map<String, Any?> ?: throw err("no_jwk", "verified header has no embedded jwk")
        } catch (e: DpopVerificationError) {
            throw e
        } catch (e: RuntimeException) {
            throw err("signature", "DPoP signature did not verify: " + e.message)
        }

        val htm = payload["htm"]
        val htu = payload["htu"]
        val jti = payload["jti"]
        val iat = Jose.num(payload["iat"])
        if (htm !is String) throw err("htm", "htm is missing or not a string")
        if (htu !is String) throw err("htu", "htu is missing or not a string")
        if (iat == null || iat.isNaN() || iat.isInfinite()) throw err("iat", "iat is missing or not a number")
        if (jti !is String || jti.isEmpty()) throw err("jti", "jti is missing or empty")

        if (htm != opts.method!!.uppercase(Locale.ROOT)) throw err("htm", "htm '$htm' does not match request method")
        if (htu != normalizeHtu(opts.url)) throw err("htu", "htu '$htu' does not match request URL")

        val now = opts.nowSec ?: nowSec()
        if (!now.isFinite()) throw err("now", "nowSec must be a finite number")
        if (!(iat <= now + DPOP_CLOCK_SKEW_SEC)) throw err("iat_future", "iat is in the future")
        if (!(now - iat <= opts.maxAgeSec)) throw err("iat_stale", "proof is older than ${Js.template(opts.maxAgeSec)}s")

        val jkt = Jose.jwkThumbprint(jwk, "sha256")
        if (opts.expectedJkt != null && jkt != opts.expectedJkt) throw err("jkt", "embedded key thumbprint does not match expected jkt")

        if (opts.expectedNonce != null && opts.expectedNonce != payload["nonce"]) throw err("nonce", "proof nonce is missing or does not match the expected nonce")
        if (opts.nonceIssuer?.check(payload["nonce"], now) == false) throw err("nonce", "proof nonce is missing, forged or expired")
        if (opts.accessToken != null && athFor(opts.accessToken!!) != payload["ath"]) throw err("ath", "proof ath is missing or does not match the access token")

        opts.seenJti?.let {
            if (it.has(jti)) throw err("jti_replay", "jti '$jti' has already been seen")
            it.add(jti)
        }
        opts.replayStore?.let { store ->
            val fresh = try {
                store.addIfAbsent("$jkt.$jti", iat + opts.maxAgeSec + DPOP_CLOCK_SKEW_SEC, now)
            } catch (e: RuntimeException) {
                throw err("replay_store_error", "replay store failed: " + e.message)
            }
            if (!fresh) throw err("jti_replay", "jti '$jti' has already been seen")
        }

        val claims = LinkedHashMap(payload)
        claims["htm"] = htm
        claims["htu"] = htu
        claims["iat"] = payload["iat"]
        claims["jti"] = jti
        return DpopVerifyResult(claims, jwk, jkt)
    }

    // ---- RFC 8705 mTLS confirmation ----

    private val PEM_BODY = Regex("-----BEGIN CERTIFICATE-----([\\s\\S]+?)-----END CERTIFICATE-----")
    private val NOT_B64 = Regex("[^A-Za-z0-9+/=]")

    /** Node-style lenient base64: stops at the first '=', ignores a dangling sextet. */
    private fun nodeBase64(body: String): ByteArray {
        val eq = body.indexOf('=')
        var s = if (eq >= 0) body.substring(0, eq) else body
        if (s.length % 4 == 1) s = s.substring(0, s.length - 1)
        while (s.length % 4 != 0) s += "="
        return Base64.getDecoder().decode(s)
    }

    private fun pemToDer(pem: String): ByteArray = nodeBase64((PEM_BODY.find(pem)?.groupValues?.get(1) ?: pem).replace(NOT_B64, ""))

    /** RFC 8705 s3.1 `cnf`: {"x5t#S256": b64u(sha256(DER))} for DER bytes. */
    @JvmStatic
    fun mtlsCnf(certDer: ByteArray): Map<String, Any?> = linkedMapOf("x5t#S256" to Jose.b64u(Jose.sha256(certDer)))

    /** RFC 8705 s3.1 `cnf` for a certificate given as PEM text (the DER body is hashed). */
    @JvmStatic
    fun mtlsCnf(certPem: String): Map<String, Any?> = mtlsCnf(pemToDer(certPem))

    /** The thumbprint of a certificate that PARSES as X.509 (DER bytes). Throws `cert` otherwise. */
    @JvmStatic
    fun mtlsThumbprint(certDer: ByteArray): String = try {
        val c = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(certDer))
        Jose.b64u(Jose.sha256(c.encoded))
    } catch (e: Exception) {
        throw err("cert", "not an X.509 certificate: " + e.message)
    }

    /** The thumbprint of a certificate given as PEM text; a string that is not a PEM certificate is refused as `cert`. */
    @JvmStatic
    fun mtlsThumbprint(certPem: String): String = try {
        if (PEM_BODY.find(certPem) == null) throw IllegalArgumentException("no PEM certificate")
        mtlsThumbprint(pemToDer(certPem))
    } catch (e: DpopVerificationError) {
        throw e
    } catch (e: RuntimeException) {
        throw err("cert", "not an X.509 certificate: " + e.message)
    }

    private fun wantX5t(cnf: Any?): String {
        val want = (cnf as? Map<*, *>)?.get("x5t#S256")
        if (want !is String || want.isEmpty()) throw err("x5t_missing", "cnf has no 'x5t#S256' thumbprint")
        return want
    }

    private fun boundCnf(got: String, want: String): Map<String, Any?> {
        if (!MessageDigest.isEqual(Json.utf8(got), Json.utf8(want))) {
            throw err("x5t", "client certificate thumbprint does not match cnf x5t#S256")
        }
        return linkedMapOf("x5t#S256" to got)
    }

    /**
     * RFC 8705 s3.1 check: the presented client certificate (DER) must hash to the `x5t#S256` of the token's `cnf`. Throws
     * `x5t_missing` (no usable thumbprint in cnf), `cert` (unparseable certificate) or `x5t` (mismatch).
     */
    @JvmStatic
    fun assertMtlsBound(certDer: ByteArray, cnf: Any?): Map<String, Any?> {
        val want = wantX5t(cnf)
        return boundCnf(mtlsThumbprint(certDer), want)
    }

    /** [assertMtlsBound] for a PEM certificate. */
    @JvmStatic
    fun assertMtlsBound(certPem: String, cnf: Any?): Map<String, Any?> {
        val want = wantX5t(cnf)
        return boundCnf(mtlsThumbprint(certPem), want)
    }

    // ---- PCActn <-> DPoP binding ----

    /** The OKP / Ed25519 public JWK of the PCActn's bound holder key: the LEAF of its capability chain. Throws `no_leaf` when empty. */
    @JvmStatic
    fun leafHolderJwk(p: Map<String, Any?>?): Map<String, Any?> {
        val chainRaw = p!!["cap_chain"]
        if (chainRaw is String) { // a string has a length and character elements, none of which has a holder
            if (chainRaw.isEmpty()) throw err("no_leaf", "PCActn capability chain is empty; no bound holder key")
            return linkedMapOf("kty" to "OKP", "crv" to "Ed25519")
        }
        val chain = chainRaw as? List<*> ?: throw IllegalArgumentException("Cannot read properties of undefined (reading 'length')")
        if (chain.isEmpty()) throw err("no_leaf", "PCActn capability chain is empty; no bound holder key")
        val leaf = chain.last() ?: throw IllegalArgumentException("Cannot read properties of null (reading 'holder')")
        val jwk = linkedMapOf<String, Any?>("kty" to "OKP", "crv" to "Ed25519")
        if (leaf is Map<*, *> && leaf.containsKey("holder")) jwk["x"] = leaf["holder"] // an absent holder stays absent
        return jwk
    }

    /** The `cnf: {jkt}` confirmation for a PCActn's bound holder key (RFC 9449 s6). */
    @JvmStatic
    fun bindPcaToDpop(p: Map<String, Any?>?): Map<String, Any?> = linkedMapOf("jkt" to Jose.jwkThumbprint(leafHolderJwk(p), "sha256"))

    /**
     * Confirms a presented DPoP proof is held by the PCActn's bound holder key AND is for the given HTTP target: verifies the proof with
     * expectedJkt fixed to the PCActn's leaf-holder thumbprint. Throws [DpopVerificationError] on any mismatch.
     */
    @JvmStatic
    fun assertPcaDpop(p: Map<String, Any?>?, dpopProof: Any?, o: AssertPcaDpopOptions): DpopVerifyResult {
        val jkt = bindPcaToDpop(p)["jkt"] as String
        return verifyDpopProof(
            dpopProof,
            VerifyDpopProofOptions(
                method = o.method, url = o.url, maxAgeSec = o.maxAgeSec ?: DPOP_DEFAULT_MAX_AGE_SEC, expectedJkt = jkt, seenJti = o.seenJti,
                replayStore = o.replayStore, requireReplayStore = o.requireReplayStore, nonceIssuer = o.nonceIssuer, nowSec = o.nowSec,
                expectedNonce = o.expectedNonce, accessToken = o.accessToken,
            ),
        )
    }
}
