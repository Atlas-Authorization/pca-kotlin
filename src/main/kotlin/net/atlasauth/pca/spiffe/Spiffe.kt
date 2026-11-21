package net.atlasauth.pca.spiffe

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Locale
import javax.security.auth.x500.X500Principal
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.verifier.AttestDer
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Bridge PCA agent identity with SPIFFE / SPIRE workload identity: SPIFFE ID parsing, JWT-SVID and X.509-SVID verification against a
 * trust bundle, SVID to PCA holder binding, revocation and trust-bundle caches that fail closed, and blueprint-admission evidence. Every
 * check is fail closed; a failure is a [SpiffeError] with a stable code (JOSE failures from a JWT-SVID are [Jose.JoseException]).
 *
 * JWT-SVID keys are public JWK maps (or a [JwtKeyResolver]); revocation checks and fetchers are synchronous. Certificates, keys and
 * signatures go through a private BouncyCastle provider (no JDK 9+ algorithms: Android API 24).
 * shortcut: an X.509 `checkIssued` covers the subject/issuer name, authority key id, serial and keyCertSign rules.
 */
@Suppress("UNCHECKED_CAST")
object Spiffe {
    // ---- SPIFFE ID ----

    /** A parsed, validated SPIFFE ID. */
    class SpiffeId internal constructor(val id: String, val trustDomain: String, val path: String) {
        /** `{id, trustDomain, path}` as a JSON object. */
        fun toJson(): Map<String, Any?> = linkedMapOf("id" to id, "trustDomain" to trustDomain, "path" to path)
    }

    private const val SPIFFE_SCHEME = "spiffe://"
    private const val MAX_SPIFFE_ID_LENGTH = 2048
    private const val MAX_TRUST_DOMAIN_LENGTH = 255
    private val TRUST_DOMAIN_RE = Regex("[a-z0-9._-]+")
    private val PATH_SEGMENT_RE = Regex("[a-zA-Z0-9._-]+")

    /** Signature algorithms the JWT-SVID specification allows. */
    @JvmField val JWT_SVID_ALGORITHMS: List<String> = listOf("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512")

    /**
     * Validate and parse `spiffe://<trust-domain>/<path>`: lowercase scheme; non-empty trust domain from [a-z0-9._-] (at most 255); path
     * segments from [a-zA-Z0-9._-] with no empty segment, no "." / ".." segment and no trailing slash; at most 2048 characters. Throws
     * [SpiffeError]. A bare `spiffe://trust-domain` is valid.
     */
    @JvmStatic
    fun parseSpiffeId(sv: Any?): SpiffeId {
        if (sv !is String || sv.isEmpty()) throw SpiffeError("malformed_spiffe_id", "SPIFFE ID must be a non-empty string")
        if (sv.length > MAX_SPIFFE_ID_LENGTH) throw SpiffeError("id_too_long", "SPIFFE ID exceeds $MAX_SPIFFE_ID_LENGTH bytes")
        if (!sv.startsWith(SPIFFE_SCHEME)) throw SpiffeError("malformed_spiffe_id", "SPIFFE ID must begin with \"$SPIFFE_SCHEME\"")
        val rest = sv.substring(SPIFFE_SCHEME.length)
        val slash = rest.indexOf('/')
        val trustDomain = if (slash == -1) rest else rest.substring(0, slash)
        val path = if (slash == -1) "" else rest.substring(slash)
        if (trustDomain.isEmpty()) throw SpiffeError("empty_trust_domain", "SPIFFE ID has an empty trust domain")
        if (trustDomain.length > MAX_TRUST_DOMAIN_LENGTH) throw SpiffeError("trust_domain_too_long", "trust domain exceeds $MAX_TRUST_DOMAIN_LENGTH bytes")
        if (!TRUST_DOMAIN_RE.matches(trustDomain)) throw SpiffeError("invalid_trust_domain", "trust domain \"$trustDomain\" must be lowercase and contain only [a-z0-9._-]")
        if (path.isNotEmpty()) {
            if (path.endsWith("/")) throw SpiffeError("invalid_path", "SPIFFE ID path must not end with a trailing slash")
            for (seg in path.split("/").drop(1)) {
                if (seg.isEmpty()) throw SpiffeError("invalid_path", "SPIFFE ID path must not contain an empty segment")
                if (seg == "." || seg == "..") throw SpiffeError("invalid_path", "SPIFFE ID path must not contain a \".\" or \"..\" segment")
                if (!PATH_SEGMENT_RE.matches(seg)) throw SpiffeError("invalid_path", "SPIFFE ID path segment \"$seg\" contains an invalid character")
            }
        }
        return SpiffeId(SPIFFE_SCHEME + trustDomain + path, trustDomain, path)
    }

    // ---- revocation subjects and checks ----

    /** What [verifyX509Svid] asks the revocation check about, once per presented certificate (leaf first). */
    class X509RevocationSubject(val spiffeId: String, val serialNumber: String, val fingerprint256: String, val position: Int, val isLeaf: Boolean) {
        fun toJson(): Map<String, Any?> = linkedMapOf(
            "spiffeId" to spiffeId, "serialNumber" to serialNumber, "fingerprint256" to fingerprint256, "position" to Json.Num(position.toString()), "isLeaf" to isLeaf,
        )
    }

    /** What [verifyJwtSvid] asks the revocation check about: `jti` when a string, `exp` (a JSON number), base64url SHA-256 of the token. */
    class JwtRevocationSubject(val spiffeId: String, val jti: String?, val expiresAt: Any?, val tokenHash: String) {
        fun toJson(): Map<String, Any?> {
            val m = linkedMapOf<String, Any?>("spiffeId" to spiffeId)
            if (jti != null) m["jti"] = jti
            m["expiresAt"] = expiresAt
            m["tokenHash"] = tokenHash
            return m
        }
    }

    /** Return exactly `false` to admit, `true` when revoked; anything else, or a throw, refuses (`revocation_unavailable`). */
    fun interface X509RevocationCheck { fun check(subject: X509RevocationSubject): Any? }

    /** As [X509RevocationCheck] for a JWT-SVID. */
    fun interface JwtRevocationCheck { fun check(subject: JwtRevocationSubject): Any? }

    /** Stands for a revocation option that is not a function (the reference's `null`): refused as `revocation_unavailable`. */
    @JvmField val NOT_A_FUNCTION = Any()

    private fun errMsg(e: Throwable) = e.message ?: e.toString()

    // ---- JWT-SVID ----

    /** A key resolver for [verifyJwtSvid]: the (protected header, token) to a public JWK (e.g. a trust bundle's JWKS). */
    fun interface JwtKeyResolver { fun resolve(protectedHeader: Map<String, Any?>, token: String?): Map<String, Any?> }

    /** Options for [verifyJwtSvid]. */
    class VerifyJwtSvidOptions {
        /** REQUIRED audience(s). */
        var audience: List<String> = emptyList()

        /** A public JWK map, or a [JwtKeyResolver]. */
        var key: Any? = null

        /** REQUIRED subject trust domain. */
        var trustDomain: String? = null

        /** Verification time (epoch ms); null = now. */
        var currentDateMs: Long? = null

        /** Permitted algorithms; null = [JWT_SVID_ALGORITHMS]. */
        var algorithms: List<String>? = null

        /** Seconds (a number) or a time-period string such as "30s"; null = 0. */
        var clockTolerance: Any? = null

        /** A [JwtRevocationCheck], [NOT_A_FUNCTION], or null (not checked). */
        var revocation: Any? = null
    }

    /** A verified JWT-SVID (`expiresAt` is `exp` as a JSON number). */
    class JwtSvid internal constructor(val spiffeId: SpiffeId, val claims: Map<String, Any?>, val audience: List<Any?>, val expiresAt: Any?) {
        internal var verified = false
    }

    private val SECS = Regex(
        "^(\\+|-)? ?(\\d+|\\d+\\.\\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$",
        RegexOption.IGNORE_CASE,
    )

    /** The jose time-period parser (seconds); IllegalArgumentException when malformed. */
    internal fun secs(str: String): Double {
        val m = SECS.matchEntire(str)
        if (m == null || (m.groups[4] != null && m.groups[1] != null)) throw IllegalArgumentException("Invalid time period format")
        val value = m.groupValues[2].toDouble()
        val n = when (m.groupValues[3].lowercase(Locale.ROOT)) {
            "sec", "secs", "second", "seconds", "s" -> Math.round(value)
            "minute", "minutes", "min", "mins", "m" -> Math.round(value * 60)
            "hour", "hours", "hr", "hrs", "h" -> Math.round(value * 3600)
            "day", "days", "d" -> Math.round(value * 86400)
            "week", "weeks", "w" -> Math.round(value * 604800)
            else -> Math.round(value * (86400 * 365.25))
        }.toDouble()
        return if (m.groups[1]?.value == "-" || m.groups[4]?.value == "ago") -n else n
    }

    private fun asMap(o: Any?) = o as? Map<String, Any?>

    /**
     * Verify a JWT-SVID: the canonical compact spelling, the JWS signature against the key / resolver, the audience, `exp` (and `nbf`), a
     * valid SPIFFE ID `sub` in the pinned trust domain, then the optional revocation check (last).
     */
    @JvmStatic
    fun verifyJwtSvid(token: String, opts: VerifyJwtSvidOptions): JwtSvid {
        if (opts.revocation != null && opts.revocation !is JwtRevocationCheck) throw SpiffeError("revocation_unavailable", "revocation must be a function")
        val trustDomain = opts.trustDomain
        if (trustDomain.isNullOrEmpty()) throw SpiffeError("missing_trust_domain", "verifyJwtSvid requires `trustDomain` (an unpinned JWT-SVID would accept any trust domain the key signs for)")
        val audience = opts.audience
        if (audience.isEmpty() || audience.any { it.isEmpty() }) throw SpiffeError("missing_audience", "verifyJwtSvid requires a non-empty audience (JWT-SVID aud is mandatory)")
        // An infinite or negative tolerance makes every exp/nbf comparison pass.
        Jose.num(opts.clockTolerance)?.let { if (!(it.isFinite() && it >= 0)) throw SpiffeError("malformed_token", "verifyJwtSvid: clockTolerance must be a finite number >= 0") }
        val algorithms = opts.algorithms ?: JWT_SVID_ALGORITHMS
        val bad = algorithms.firstOrNull { it == "none" || it.uppercase(Locale.ROOT).startsWith("HS") }
        if (bad != null || algorithms.isEmpty()) throw SpiffeError("forbidden_algorithm", "JWT-SVIDs must not use " + (bad ?: "an empty algorithm list"))

        val canon = try {
            Jose.assertCanonicalCompactJws(token)
        } catch (cause: RuntimeException) {
            throw SpiffeError("malformed_token", cause.message)
        }
        val key = opts.key
        val jwk: Map<String, Any?> = if (key is JwtKeyResolver) {
            Jose.checkCritHeader(canon.header) // crit is refused before any key is resolved, as the reference does
            val alg = canon.header["alg"]
            if (alg !is String || alg.isEmpty()) throw Jose.JoseException("JWS \"alg\" (Algorithm) Header Parameter missing or invalid")
            if (alg !in algorithms) throw Jose.JoseException("\"alg\" (Algorithm) Header Parameter value not allowed")
            try {
                key.resolve(canon.header, token)
            } catch (e: RuntimeException) {
                throw e
            } catch (e: Exception) {
                throw Jose.JoseException("key resolution failed: ${errMsg(e)}")
            }
        } else {
            asMap(key) ?: throw Jose.JoseException("Invalid key input")
        }
        val tol = opts.clockTolerance
        val tolerance: Double? = when {
            Jose.num(tol) != null -> Jose.num(tol)
            tol is String -> secs(tol)
            tol != null -> throw IllegalArgumentException("Invalid clockTolerance option type")
            else -> null
        }
        val v = Jose.jwtVerify(token, jwk, Jose.JwtOptions(audience = audience, clockTolerance = tolerance, currentDateMs = opts.currentDateMs?.toDouble(), algorithms = algorithms))
        val payload = v.payload
        val typ = v.protectedHeader["typ"]
        if (v.protectedHeader.containsKey("typ") && typ != "JWT" && typ != "JOSE") throw SpiffeError("invalid_typ", "JWT-SVID header typ must be JWT or JOSE, got '$typ'")
        val exp = payload["exp"]
        if (Jose.num(exp) == null) throw SpiffeError("missing_exp", "JWT-SVID is missing the required \"exp\" claim")
        if (payload["sub"] !is String) throw SpiffeError("invalid_subject", "JWT-SVID \"sub\" must be a string SPIFFE ID")
        val spiffeId = try {
            parseSpiffeId(payload["sub"])
        } catch (err: SpiffeError) {
            throw SpiffeError("invalid_subject", "JWT-SVID \"sub\" is not a valid SPIFFE ID: ${err.message}")
        }
        if (spiffeId.trustDomain != trustDomain) {
            throw SpiffeError("trust_domain_mismatch", "JWT-SVID trust domain \"${spiffeId.trustDomain}\" does not match expected \"$trustDomain\"")
        }
        val aud = payload["aud"]
        val resolved: List<Any?> = when (aud) {
            null -> ArrayList()
            is String -> arrayListOf(aud)
            else -> ArrayList(aud as List<*>)
        }
        val out = JwtSvid(spiffeId, payload, resolved, exp)
        val rev = opts.revocation as JwtRevocationCheck?
        if (rev != null) {
            val verdict = try {
                rev.check(JwtRevocationSubject(spiffeId.id, payload["jti"] as? String, exp, Keys.b64u(Jose.sha256(Json.utf8(token)))))
            } catch (e: Exception) {
                throw SpiffeError("revocation_unavailable", "revocation check failed: ${errMsg(e)}")
            }
            if (verdict == true) throw SpiffeError("svid_revoked", "JWT-SVID for ${spiffeId.id} is revoked")
            if (verdict != false) throw SpiffeError("revocation_unavailable", "revocation check did not return a boolean")
        }
        out.verified = true
        return out
    }

    // ---- X.509-SVID ----

    /** A parsed X.509-SVID (`publicKeyDer` is the base64url SPKI DER of the certificate's public key). */
    class X509Svid internal constructor(val spiffeId: SpiffeId, val certificate: X509Certificate, val publicKeyDer: String) {
        internal var verified = false
    }

    /** BouncyCastle parses certificates leniently (a SAN URI the platform parser refuses is still a certificate) and carries Ed25519 on API 24. */
    private val BC = BouncyCastleProvider()

    private val PEM_CERT_RE = Regex("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")

    private fun toCertificate(cert: Any?): X509Certificate {
        try {
            val der: ByteArray = when (cert) {
                is ByteArray -> cert
                is String -> {
                    // the first PEM certificate: its BEGIN line alone on a line, base64 lines, then the END line (as OpenSSL reads it)
                    val lines = cert.split("\n")
                    var i = 0
                    while (i < lines.size && lines[i].trim() != "-----BEGIN CERTIFICATE-----") i++
                    if (i == lines.size) throw IllegalArgumentException("no start line")
                    val body = StringBuilder()
                    var ended = false
                    for (j in i + 1 until lines.size) {
                        val ln = lines[j].trim()
                        if (ln == "-----END CERTIFICATE-----") {
                            ended = true
                            break
                        }
                        body.append(ln)
                    }
                    if (!ended) throw IllegalArgumentException("bad end line")
                    Base64.getDecoder().decode(body.toString())
                }
                else -> throw IllegalArgumentException("certificate must be PEM text or DER bytes")
            }
            return CertificateFactory.getInstance("X.509", BC).generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
                ?: throw IllegalArgumentException("not a certificate")
        } catch (e: Exception) {
            throw SpiffeError("malformed_certificate", "cannot parse certificate: ${errMsg(e)}")
        }
    }

    private fun raw(c: X509Certificate): ByteArray = try {
        c.encoded
    } catch (e: Exception) {
        throw SpiffeError("malformed_certificate", "cannot encode certificate: ${errMsg(e)}")
    }

    private fun factsOf(certificate: X509Certificate): SpiffeDer.CertFacts = try {
        SpiffeDer.readCertFacts(raw(certificate))
    } catch (e: SpiffeError) {
        throw e
    } catch (e: RuntimeException) {
        throw SpiffeError("malformed_certificate", "cannot read certificate extensions: ${errMsg(e)}")
    }

    /** The X509-SVID leaf rules (section 4.3). */
    private fun validateLeaf(certificate: X509Certificate): SpiffeId {
        val facts = factsOf(certificate)
        if (facts.unknownCritical.isNotEmpty()) throw SpiffeError("unsupported_critical_extension", "certificate has an unsupported critical extension (${facts.unknownCritical.joinToString(", ")})")
        if (facts.uriSans.isEmpty()) throw SpiffeError("no_uri_san", "X.509-SVID certificate has no URI SAN")
        if (facts.uriSans.size > 1) throw SpiffeError("multiple_uri_san", "X.509-SVID certificate must have exactly one URI SAN, found ${facts.uriSans.size}")
        val spiffeId = parseSpiffeId(facts.uriSans[0])
        if (spiffeId.path.isEmpty()) throw SpiffeError("leaf_root_path", "X.509-SVID leaf SPIFFE ID must have a non-root path")
        if (facts.isCa) throw SpiffeError("leaf_is_ca", "leaf certificate must not have the CA flag set to true")
        if (!facts.digitalSignature) throw SpiffeError("leaf_no_digital_signature", "leaf certificate must have 'digitalSignature' set as key usage")
        if (facts.keyCertSign) throw SpiffeError("leaf_cert_sign", "leaf certificate must not have 'keyCertSign' set as key usage")
        if (facts.crlSign) throw SpiffeError("leaf_crl_sign", "leaf certificate must not have 'cRLSign' set as key usage")
        return spiffeId
    }

    /** [content start, content end) of the TLV at [off], or null when it does not fit. */
    private fun tlv(d: ByteArray, off: Int, limit: Int): IntArray? {
        if (off + 2 > limit) return null
        var len = (d[off + 1].toInt() and 0xff).toLong()
        var p = off + 2
        if (len and 0x80 != 0L) {
            val n = (len and 0x7f).toInt()
            if (n == 0 || n > 4 || p + n > limit) return null
            len = 0
            for (i in 0 until n) len = len * 256 + (d[p + i].toInt() and 0xff)
            p += n
        }
        if (p + len > limit) return null
        return intArrayOf(p, (p + len).toInt())
    }

    /** Elements of the constructed value whose content spans [start, end): {element start, content start, content end}. */
    private fun childRanges(d: ByteArray, start: Int, end: Int): List<IntArray> {
        val out = ArrayList<IntArray>()
        var off = start
        while (off < end) {
            val t = tlv(d, off, end) ?: break
            out.add(intArrayOf(off, t[0], t[1]))
            off = t[1]
        }
        return out
    }

    /** The certificate's SubjectPublicKeyInfo DER, read from its own bytes. */
    private fun spkiOf(c: X509Certificate): ByteArray {
        val d = raw(c)
        try {
            val cert = tlv(d, 0, d.size)!!
            val tbs = tlv(d, cert[0], cert[1])!!
            val kids = childRanges(d, tbs[0], tbs[1])
            val i = if (d[kids[0][0]].toInt() and 0xff == 0xa0) 1 else 0
            val spki = kids[i + 5]
            return d.copyOfRange(spki[0], spki[2])
        } catch (e: RuntimeException) {
            throw SpiffeError("malformed_certificate", "cannot read the certificate public key: ${errMsg(e)}")
        }
    }

    private fun spkiB64u(c: X509Certificate) = Keys.b64u(spkiOf(c))

    /** A public key from SubjectPublicKeyInfo DER (EC, RSA or Ed25519); null when none of them takes it. */
    private fun keyOf(spki: ByteArray): PublicKey? {
        for (alg in listOf("EC", "RSA", "Ed25519")) {
            try {
                return KeyFactory.getInstance(alg, BC).generatePublic(X509EncodedKeySpec(spki))
            } catch (e: Exception) {
                // try the next algorithm
            }
        }
        return null
    }

    /**
     * Parse an X.509-SVID (PEM text or DER bytes) and validate it as a SPIFFE leaf. Does NOT check the chain, validity or revocation: use
     * [verifyX509Svid]. A parsed-only SVID is refused by [svidToHolder].
     */
    @JvmStatic
    fun parseX509Svid(cert: Any?): X509Svid {
        val certificate = toCertificate(cert)
        return X509Svid(validateLeaf(certificate), certificate, spkiB64u(certificate))
    }

    /** Options for [verifyX509Svid]: `roots` are PEM text (possibly several certificates) or DER bytes. */
    class VerifyX509SvidOptions {
        /** REQUIRED trust domain. */
        var trustDomain: String? = null

        /** REQUIRED trust bundle authorities. */
        var roots: List<Any?> = emptyList()

        /** Verification time (epoch ms); null = now. */
        var nowMs: Long? = null

        /** Maximum chain length; null = 8. */
        var maxChainLength: Int? = null

        /** An [X509RevocationCheck], [NOT_A_FUNCTION], or null (not checked). */
        var revocation: Any? = null
    }

    private fun certsOf(input: Any?): List<X509Certificate> {
        if (input is String) {
            val out = PEM_CERT_RE.findAll(input).map { toCertificate(it.value) }.toList()
            if (out.isEmpty()) throw SpiffeError("malformed_certificate", "no PEM certificate found")
            return out
        }
        return listOf(toCertificate(input))
    }

    private fun validateSigner(cert: X509Certificate, label: String): SpiffeDer.CertFacts {
        val facts = factsOf(cert)
        if (facts.unknownCritical.isNotEmpty()) throw SpiffeError("unsupported_critical_extension", "$label has an unsupported critical extension (${facts.unknownCritical.joinToString(", ")})")
        if (!facts.isCa) throw SpiffeError("chain_not_ca", "$label must have the CA flag set to true")
        if (!facts.keyUsagePresent || !facts.keyCertSign) throw SpiffeError("chain_no_key_cert_sign", "$label must have 'keyCertSign' set as key usage")
        return facts
    }

    private fun withinValidity(c: X509Certificate, nowMs: Long) = AttestDer.derValidAt(raw(c), nowMs, 0)

    // ---- X.509 issuance relation (the reference's X509Certificate.checkIssued) ----

    private fun extValue(c: X509Certificate, oid: String): ByteArray? {
        val v = c.getExtensionValue(oid) ?: return null // DER OCTET STRING wrapping the extension's value
        val l = v[1].toInt() and 0xff
        return v.copyOfRange(if (l and 0x80 == 0) 2 else 2 + (l and 0x7f), v.size)
    }

    /** The AuthorityKeyIdentifier members: [0] key id, [1] authorityCertIssuer (raw), [2] serial. Absent members are null. */
    private fun akid(c: X509Certificate): Array<ByteArray?>? {
        val v = extValue(c, "2.5.29.35") ?: return null
        val out = arrayOfNulls<ByteArray>(3)
        val seq = tlv(v, 0, v.size) ?: return out
        var off = seq[0]
        while (off < seq[1]) {
            val t = tlv(v, off, seq[1]) ?: break
            when (v[off].toInt() and 0xff) {
                0x80 -> out[0] = v.copyOfRange(t[0], t[1])
                0xa1 -> out[1] = v.copyOfRange(t[0], t[1])
                0x82 -> out[2] = v.copyOfRange(t[0], t[1])
            }
            off = t[1]
        }
        return out
    }

    private fun skid(c: X509Certificate): ByteArray? {
        val v = extValue(c, "2.5.29.14")
        if (v == null || v.size < 2 || v[0].toInt() and 0xff != 0x04) return null
        val t = tlv(v, 0, v.size) ?: return null
        return v.copyOfRange(t[0], t[1])
    }

    /** True when [issuer] could have issued [subject]: names, authority key id / serial / issuer, and keyCertSign. */
    internal fun checkIssued(subject: X509Certificate, issuer: X509Certificate): Boolean {
        if (subject.issuerX500Principal != issuer.subjectX500Principal) return false
        val a = akid(subject)
        if (a != null) {
            val sk = skid(issuer)
            if (a[0] != null && sk != null && !a[0].contentEquals(sk)) return false
            if (a[2] != null && BigInteger(a[2]!!) != issuer.serialNumber) return false
            val names = a[1]
            if (names != null) {
                // authorityCertIssuer: a directoryName ([4]) must name the issuer's own issuer
                var off = 0
                var anyDir = false
                var matched = false
                while (off < names.size) {
                    val t = tlv(names, off, names.size) ?: break
                    if (names[off].toInt() and 0xff == 0xa4) {
                        anyDir = true
                        if (tlv(names, t[0], t[1]) != null) {
                            try {
                                if (X500Principal(names.copyOfRange(t[0], t[1])) == issuer.issuerX500Principal) matched = true
                            } catch (e: RuntimeException) {
                                // not a name
                            }
                        }
                    }
                    off = t[1]
                }
                if (anyDir && !matched) return false
            }
        }
        val ku = issuer.keyUsage
        return ku == null || (ku.size > 5 && ku[5])
    }

    /** True when [cert] carries a valid signature by [signer]'s public key. */
    private fun verifiedBy(cert: X509Certificate, signer: X509Certificate): Boolean = try {
        val key = keyOf(spkiOf(signer))
        if (key == null) false else {
            cert.verify(key, BC)
            true
        }
    } catch (e: Exception) {
        false
    }

    private fun serialHex(c: X509Certificate): String {
        val s = c.serialNumber
        var h = s.abs().toString(16).uppercase(Locale.ROOT)
        if (h.length % 2 == 1) h = "0$h"
        return (if (s.signum() < 0) "-" else "") + h
    }

    private fun fingerprint256(c: X509Certificate): String =
        MessageDigest.getInstance("SHA-256").digest(raw(c)).joinToString(":") { String.format("%02X", it.toInt() and 0xff) }

    /**
     * Verify an X.509-SVID against a trust bundle (section 4): the leaf rules, its trust domain, every certificate's validity, each
     * certificate signed by the next, signing certificates with cA and keyCertSign, pathLenConstraint, and an end at (or signed by) a
     * bundle authority. [chain] is PEM text (several certificates) or a list of PEM text / DER bytes, leaf first. Revocation is checked
     * only through `opts.revocation`. Throws [SpiffeError].
     */
    @JvmStatic
    fun verifyX509Svid(chain: Any?, opts: VerifyX509SvidOptions): X509Svid {
        if (opts.revocation != null && opts.revocation !is X509RevocationCheck) throw SpiffeError("revocation_unavailable", "revocation must be a function")
        val now = opts.nowMs ?: System.currentTimeMillis()
        val items = if (chain is String) certsOf(chain) else (chain as List<*>).flatMap { certsOf(it) }
        if (items.isEmpty()) throw SpiffeError("chain_empty", "certificate chain is empty")
        if (items.size > (opts.maxChainLength ?: 8)) throw SpiffeError("chain_too_long", "certificate chain is too long")
        val leaf = items[0]
        val spiffeId = validateLeaf(leaf)
        if (spiffeId.trustDomain != opts.trustDomain) throw SpiffeError("chain_trust_domain_mismatch", "SPIFFE ID trust domain '${spiffeId.trustDomain}' is not '${opts.trustDomain}'")
        val roots = opts.roots.flatMap { certsOf(it) }
        if (roots.isEmpty()) throw SpiffeError("chain_untrusted_root", "trust bundle has no X.509 authorities")

        for (c in items) if (!withinValidity(c, now)) throw SpiffeError("chain_expired", "a certificate in the chain is not within its validity period")
        for (i in 1 until items.size) {
            val f = validateSigner(items[i], "signing certificate #$i")
            val pl = f.pathLen
            if (pl != null && i - 1 > pl) throw SpiffeError("chain_path_len", "signing certificate #$i pathLenConstraint exceeded")
        }
        val below = items.size - 1
        for (i in 0 until items.size - 1) {
            if (!checkIssued(items[i], items[i + 1]) || !verifiedBy(items[i], items[i + 1])) throw SpiffeError("chain_signature", "certificate #$i is not signed by certificate #${i + 1}")
        }
        val top = items[items.size - 1]
        val leafRaw = raw(leaf)
        if (items.size == 1 && roots.any { raw(it).contentEquals(leafRaw) }) throw SpiffeError("chain_untrusted_root", "a leaf certificate cannot be its own trust anchor")
        val topIsAnchor = items.size > 1 && raw(top).let { t -> roots.any { raw(it).contentEquals(t) } }
        if (!topIsAnchor) {
            val signer = roots.firstOrNull { checkIssued(top, it) && verifiedBy(top, it) }
                ?: throw SpiffeError("chain_untrusted_root", "the chain does not lead to an authority in the trust bundle")
            if (!withinValidity(signer, now)) throw SpiffeError("chain_expired", "the trust bundle authority is not within its validity period")
            val pl = validateSigner(signer, "trust bundle authority").pathLen
            if (pl != null && below > pl) throw SpiffeError("chain_path_len", "trust bundle authority pathLenConstraint exceeded")
        }

        val rev = opts.revocation as X509RevocationCheck?
        if (rev != null) {
            for ((i, c) in items.withIndex()) {
                val verdict = try {
                    rev.check(X509RevocationSubject(spiffeId.id, serialHex(c), fingerprint256(c), i, i == 0))
                } catch (e: Exception) {
                    throw SpiffeError("revocation_unavailable", "revocation check failed: ${errMsg(e)}")
                }
                if (verdict == true) {
                    throw SpiffeError(if (i == 0) "svid_revoked" else "chain_revoked", if (i == 0) "X.509-SVID for ${spiffeId.id} is revoked" else "signing certificate #$i of the chain is revoked")
                }
                if (verdict != false) throw SpiffeError("revocation_unavailable", "revocation check did not return a boolean")
            }
        }
        return X509Svid(spiffeId, leaf, spkiB64u(leaf)).also { it.verified = true }
    }

    // ---- SPIFFE ID <-> PCA agent-holder identity ----

    /** A PCA capability holder bound to a SPIFFE workload identity (`holder`: a base64url Ed25519 public key). */
    class SpiffeHolder(val holder: String, val spiffeId: String, val trustDomain: String, val path: String) {
        fun toJson(): Map<String, Any?> = linkedMapOf("holder" to holder, "spiffeId" to spiffeId, "trustDomain" to trustDomain, "path" to path)
    }

    /** A 32-byte Ed25519 holder key (base64url text or raw bytes) as canonical base64url. */
    private fun normalizeHolderKey(holderKey: Any?): String {
        if (holderKey is ByteArray) {
            if (holderKey.size != 32) throw SpiffeError("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key")
            return Keys.b64u(holderKey)
        }
        val bytes = Pca.decodeB64uStrict(holderKey, 32) ?: throw SpiffeError("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key encoded as base64url")
        return Keys.b64u(bytes)
    }

    /** Domain-separated message a workload signs with its SVID key to bind a PCA holder key to its SPIFFE ID. */
    @JvmStatic
    fun holderBindingMessage(spiffeId: String, holder: String): ByteArray = Json.utf8("pca-spiffe-holder-binding-v1\n$spiffeId\n$holder")

    /** Options for [svidToHolder]. */
    class SvidToHolderOptions {
        /** A base64url signature over [holderBindingMessage] made with the X.509-SVID's private key (ECDSA is r||s). */
        var proof: String? = null

        /** Accept a holder key for a JWT-SVID that carries no matching `cnf.jwk` (only when it is authenticated by other means). */
        var acceptUnboundJwtHolder = false
    }

    private val ED25519_SPKI_PREFIX = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)

    private fun isEd25519Spki(spki: ByteArray) = spki.size == 44 && spki.copyOfRange(0, 12).contentEquals(ED25519_SPKI_PREFIX)

    private fun ed25519RawOfCert(cert: X509Certificate): String? {
        val spki = spkiOf(cert)
        return if (isEd25519Spki(spki)) Keys.b64u(spki.copyOfRange(12, 44)) else null
    }

    /** IEEE P1363 r||s to a DER ECDSA signature (the platform verifiers take DER). */
    private fun p1363ToDer(sig: ByteArray): ByteArray? {
        if (sig.isEmpty() || sig.size % 2 != 0) return null
        val h = sig.size / 2
        fun int(b: ByteArray): ByteArray {
            val v = BigInteger(1, b).toByteArray()
            return byteArrayOf(0x02, v.size.toByte()) + v
        }
        val body = int(sig.copyOfRange(0, h)) + int(sig.copyOfRange(h, sig.size))
        if (body.size > 127) return null
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun proofVerifies(spki: ByteArray, msg: ByteArray, sig: ByteArray): Boolean = try {
        if (isEd25519Spki(spki)) Pca.ed25519Strict(spki.copyOfRange(12, 44), msg, sig)
        else when (val key = keyOf(spki)) {
            is ECPublicKey -> {
                val der = p1363ToDer(sig)
                val bits = key.params.curve.field.fieldSize
                der != null && Signature.getInstance(if (bits == 384) "SHA384withECDSA" else "SHA256withECDSA", BC).run {
                    initVerify(key)
                    update(msg)
                    verify(der)
                }
            }
            null -> false
            else -> key.algorithm == "RSA" && Signature.getInstance("SHA256withRSA", BC).run {
                initVerify(key)
                update(msg)
                verify(sig)
            }
        }
    } catch (e: Exception) {
        false
    }

    /**
     * Bind a VERIFIED SPIFFE SVID to a PCA agent-holder. [svid] MUST be the object returned by [verifyJwtSvid] or [verifyX509Svid];
     * anything else throws `unverified_svid`. [holderKey] is base64url text, 32 raw bytes or null. An X.509-SVID with an Ed25519 key is
     * its own holder; another key (or a different holder) needs `opts.proof`. A JWT-SVID needs [holderKey] and a matching `cnf.jwk`
     * unless `opts.acceptUnboundJwtHolder`.
     */
    @JvmStatic
    fun svidToHolder(svid: Any?, holderKey: Any?, opts: SvidToHolderOptions?): SpiffeHolder {
        val ok = (svid is JwtSvid && svid.verified) || (svid is X509Svid && svid.verified)
        if (!ok) throw SpiffeError("unverified_svid", "svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)")
        val o = opts ?: SvidToHolderOptions()
        val parsed = if (svid is JwtSvid) svid.spiffeId else (svid as X509Svid).spiffeId
        val holder: String
        if (svid is X509Svid) {
            val certEd = ed25519RawOfCert(svid.certificate)
            if (holderKey == null) {
                if (certEd == null) throw SpiffeError("invalid_holder_key", "the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holderKey and opts.proof")
                holder = normalizeHolderKey(certEd)
            } else {
                holder = normalizeHolderKey(holderKey)
                if (certEd == null || certEd != holder) {
                    val proof = o.proof ?: throw SpiffeError("holder_binding_failed", "the holder key is not the SVID key: opts.proof (a signature by the SVID key over holderBindingMessage) is required")
                    val sig = Pca.decodeB64uStrict(proof, -1)
                    if (sig == null || !proofVerifies(spkiOf(svid.certificate), holderBindingMessage(parsed.id, holder), sig)) {
                        throw SpiffeError("holder_binding_failed", "opts.proof does not verify under the X.509-SVID key")
                    }
                }
            }
        } else {
            if (holderKey == null) throw SpiffeError("invalid_holder_key", "a JWT-SVID has no key of its own: pass holderKey")
            holder = normalizeHolderKey(holderKey)
            val jwk = asMap(asMap((svid as JwtSvid).claims["cnf"])?.get("jwk"))
            val bound = jwk != null && jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && jwk["x"] is String && jwk["x"] == holder
            if (!bound && !o.acceptUnboundJwtHolder) {
                throw SpiffeError("holder_binding_failed", "the JWT-SVID carries no cnf.jwk equal to the holder key (set acceptUnboundJwtHolder only if the key is authenticated by other means)")
            }
        }
        return SpiffeHolder(holder, parsed.id, parsed.trustDomain, parsed.path)
    }

    /** The (validated, canonical) SPIFFE ID a [SpiffeHolder] was bridged from. */
    @JvmStatic fun holderToSpiffeId(holder: SpiffeHolder): String = parseSpiffeId(holder.spiffeId).id

    /**
     * The SPIFFE ID the K1 `spiffe_bound` caveat compares: the workload identity a VERIFIED SVID carries, only when that SVID is bound to
     * [leafHolder] (the key that signed the PCActn). Same binding rules as [svidToHolder].
     */
    @JvmStatic
    fun spiffeIdForHolder(svid: Any?, leafHolder: String?, opts: SvidToHolderOptions?): String {
        val h = svidToHolder(svid, leafHolder, opts)
        if (h.holder != leafHolder) throw SpiffeError("holder_binding_failed", "the SVID is not bound to the PCActn leaf holder")
        return h.spiffeId
    }

    /** A K1 discharge-issuer pin for a workload: `{label, class: "workload", pk, spiffe_id}` (an X.509-SVID with an Ed25519 key only). */
    @JvmStatic
    fun workloadDischargePin(label: String?, svid: Any?): Map<String, Any?> {
        val h = svidToHolder(svid, null, null)
        return linkedMapOf("label" to label, "class" to "workload", "pk" to h.holder, "spiffe_id" to h.spiffeId)
    }

    // ---- revocation source ----

    /** A synchronous fetch that may throw. */
    fun interface Fetch { fun fetch(): Any? }

    private fun finiteOrder(refreshMs: Double, maxStaleMs: Double): Boolean =
        !refreshMs.isNaN() && !refreshMs.isInfinite() && refreshMs > 0 && !maxStaleMs.isNaN() && !maxStaleMs.isInfinite() && maxStaleMs >= refreshMs

    private fun normHex(s: String) = s.replace(":", "").uppercase(Locale.ROOT)

    private fun normSerial(s: String): String {
        val h = normHex(s)
        var i = 0
        while (i < h.length - 1 && h[i] == '0') i++
        return h.substring(i)
    }

    private fun strList(raw: Map<String, Any?>, key: String): List<String> {
        if (!raw.containsKey(key)) return emptyList()
        val v = raw[key]
        if (v !is List<*> || v.any { it !is String }) throw SpiffeError("revocation_unavailable", "revocation list field \"$key\" must be an array of strings")
        return v as List<String>
    }

    private class Snapshot(raw: Map<String, Any?>) {
        val fingerprints = strList(raw, "fingerprints").map { normHex(it) }.toSet()
        val serials = strList(raw, "serials").map { normSerial(it) }.toSet()
        val spiffeIds = strList(raw, "spiffeIds").toSet()
        val jtis = strList(raw, "jtis").toSet()
        val tokenHashes = strList(raw, "tokenHashes").toSet()
    }

    private fun toSnapshot(list: Any?): Snapshot = Snapshot(asMap(list) ?: throw SpiffeError("revocation_unavailable", "revocation list must be an object"))

    /**
     * A revocation snapshot cache that fails closed: before the first successful fetch, or once the last good snapshot is older than
     * `maxStaleMs`, every check refuses with `revocation_unavailable`. A successful refresh replaces the snapshot. The fetch returns a JSON
     * object `{fingerprints?, serials?, spiffeIds?, jtis?, tokenHashes?}` of string arrays.
     */
    class RevocationSource internal constructor(private val fetch: Fetch, private val refreshMs: Double, private val maxStaleMs: Double, private val now: () -> Long) {
        private var good: Snapshot? = null
        private var goodAt = 0L
        private var lastFailure: SpiffeError? = null

        /** For [VerifyX509SvidOptions.revocation]: uses the cached snapshot, so call [ensureFresh] first. */
        val x509 = X509RevocationCheck { s ->
            val snap = synchronized(this) { usable() }
            normHex(s.fingerprint256) in snap.fingerprints || normSerial(s.serialNumber) in snap.serials || s.spiffeId in snap.spiffeIds
        }

        /** For [VerifyJwtSvidOptions.revocation]: refreshes the snapshot itself when it is due. */
        val jwt = JwtRevocationCheck { s ->
            val snap = synchronized(this) {
                ensureFresh()
                usable()
            }
            s.spiffeId in snap.spiffeIds || (s.jti != null && s.jti in snap.jtis) || s.tokenHash in snap.tokenHashes
        }

        private fun run() {
            try {
                good = toSnapshot(fetch.fetch())
                goodAt = now()
                lastFailure = null
            } catch (e: Exception) {
                lastFailure = e as? SpiffeError ?: SpiffeError("revocation_unavailable", "revocation fetch failed: ${errMsg(e)}")
            }
        }

        private fun usable(): Snapshot {
            val g = good
            if (g == null || now() - goodAt > maxStaleMs) throw lastFailure ?: SpiffeError("revocation_unavailable", "no revocation snapshot available")
            return g
        }

        /** Fetch when the snapshot is older than `refreshMs`; refuses when no snapshot younger than `maxStaleMs` exists afterwards. */
        @Synchronized
        fun ensureFresh() {
            if (good == null || now() - goodAt >= refreshMs) run()
            usable()
        }

        /** Fetch now. Throws `revocation_unavailable` when the fetch fails or returns a malformed snapshot. */
        @Synchronized
        fun refresh() {
            run()
            lastFailure?.let { throw it }
        }
    }

    /** Create a [RevocationSource]; [now] null = the system clock. */
    @JvmStatic
    fun createRevocationSource(fetch: Fetch?, refreshMs: Double, maxStaleMs: Double, now: (() -> Long)?): RevocationSource {
        if (fetch == null) throw SpiffeError("revocation_unavailable", "createRevocationSource requires `fetch`")
        if (!finiteOrder(refreshMs, maxStaleMs)) throw SpiffeError("revocation_unavailable", "refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)")
        return RevocationSource(fetch, refreshMs, maxStaleMs, now ?: { System.currentTimeMillis() })
    }

    // ---- trust bundle source ----

    private fun usableBundle(b: Any?): Boolean {
        val t = asMap(b) ?: return false
        val keys = asMap(t["jwks"])?.get("keys")
        val auth = t["x509Authorities"]
        return (keys is List<*> && keys.isNotEmpty()) || (auth is List<*> && auth.isNotEmpty())
    }

    /**
     * A trust-bundle cache that fails closed: a rejected or empty / malformed refresh keeps the last good bundle only until `maxStaleMs`
     * after its last successful fetch; before the first success, or past that limit, every call throws `trust_bundle_unavailable` (fetch
     * failed) or `trust_bundle_invalid` (fetched but empty / malformed). A bundle is never merged. The fetch returns
     * `{jwks?: {keys: [...]}, x509Authorities?: [...]}`.
     */
    class TrustBundleSource internal constructor(private val fetch: Fetch, private val refreshMs: Double, private val maxStaleMs: Double, private val now: () -> Long) {
        private var good: Map<String, Any?>? = null
        private var goodAt = 0L
        private var lastFailure: SpiffeError? = null

        /** Key resolver for [VerifyJwtSvidOptions.key]. */
        val jwtKey = JwtKeyResolver { header, _ ->
            val jwks = synchronized(this) { asMap(current()["jwks"]) }
            val ks = jwks?.get("keys")
            if (jwks == null || (ks is List<*> && ks.isEmpty())) throw SpiffeError("trust_bundle_invalid", "trust bundle has no JWT authorities")
            localJwkSet(jwks, header)
        }

        private fun refresh() {
            try {
                val b = fetch.fetch()
                if (!usableBundle(b)) throw SpiffeError("trust_bundle_invalid", "fetched trust bundle has no authorities")
                good = asMap(b)
                goodAt = now()
                lastFailure = null
            } catch (e: Exception) {
                lastFailure = e as? SpiffeError ?: SpiffeError("trust_bundle_unavailable", "trust bundle fetch failed: ${errMsg(e)}")
            }
        }

        private fun current(): Map<String, Any?> {
            if (good == null || now() - goodAt >= refreshMs) refresh()
            val g = good
            if (g == null || now() - goodAt > maxStaleMs) throw lastFailure ?: SpiffeError("trust_bundle_unavailable", "no trust bundle available")
            return g
        }

        /** Authorities for [VerifyX509SvidOptions.roots]. Throws a [SpiffeError] when no usable bundle exists. */
        @Synchronized
        fun x509Roots(): List<Any?> {
            val roots = current()["x509Authorities"]
            if (roots !is List<*> || roots.isEmpty()) throw SpiffeError("trust_bundle_invalid", "trust bundle has no X.509 authorities")
            return ArrayList(roots)
        }
    }

    /** Create a [TrustBundleSource]; [now] null = the system clock. */
    @JvmStatic
    fun createTrustBundleSource(fetch: Fetch?, refreshMs: Double, maxStaleMs: Double, now: (() -> Long)?): TrustBundleSource {
        if (fetch == null) throw SpiffeError("trust_bundle_unavailable", "createTrustBundleSource requires `fetch`")
        if (!finiteOrder(refreshMs, maxStaleMs)) throw SpiffeError("trust_bundle_unavailable", "refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)")
        return TrustBundleSource(fetch, refreshMs, maxStaleMs, now ?: { System.currentTimeMillis() })
    }

    /** The selection of a local JWKS (the reference's createLocalJWKSet): the one key matching the header's alg, kid, use and key_ops. */
    internal fun localJwkSet(jwks: Map<String, Any?>, header: Map<String, Any?>): Map<String, Any?> {
        val keys = jwks["keys"] as? List<*> ?: throw Jose.JoseException("JSON Web Key Set malformed")
        if (keys.any { it !is Map<*, *> }) throw Jose.JoseException("JSON Web Key Set malformed")
        val a = header["alg"] as? String ?: ""
        val kid = header["kid"]
        val kty = when {
            a.startsWith("RS") || a.startsWith("PS") -> "RSA"
            a.startsWith("ES") -> "EC"
            a.startsWith("Ed") -> "OKP"
            else -> throw Jose.JoseException("Unsupported \"alg\" value for a JSON Web Key Set")
        }
        val candidates = keys.map { it as Map<String, Any?> }.filter { jwk ->
            var c = kty == jwk["kty"]
            if (c && kid is String) c = kid == jwk["kid"]
            if (c && jwk["alg"] is String) c = a == jwk["alg"]
            if (c && jwk["use"] is String) c = jwk["use"] == "sig"
            if (c && jwk["key_ops"] is List<*>) c = (jwk["key_ops"] as List<*>).contains("verify")
            if (c && a == "EdDSA") c = jwk["crv"] == "Ed25519" || jwk["crv"] == "Ed448"
            if (c) {
                when (a) {
                    "ES256" -> c = jwk["crv"] == "P-256"
                    "ES256K" -> c = jwk["crv"] == "secp256k1"
                    "ES384" -> c = jwk["crv"] == "P-384"
                    "ES512" -> c = jwk["crv"] == "P-521"
                }
            }
            c
        }
        if (candidates.isEmpty()) throw Jose.JoseException("no applicable key found in the JSON Web Key Set")
        if (candidates.size != 1) throw Jose.JoseException("multiple matching keys found in the JSON Web Key Set")
        val jwk = candidates[0]
        if (jwk["d"] != null) throw Jose.JoseException("JSON Web Key Set members must be public keys")
        return jwk
    }

    // ---- admission evidence ----

    /** SPIFFE evidence for blueprint admission (a verified SVID bound to the instance key): kind "x509" (chain + verifyX509) or "jwt" (token + verifyJwt). */
    class SpiffeEvidence {
        var kind: String? = null
        var chain: Any? = null
        var verifyX509: VerifyX509SvidOptions? = null
        var token: String? = null
        var verifyJwt: VerifyJwtSvidOptions? = null
        var bind: SvidToHolderOptions? = null
    }

    /** The admission verdict: `{ok, bound, identity?: {spiffe_id}, reason?}`. */
    class SpiffeAdmissionEvidenceResult internal constructor(val ok: Boolean, val bound: Boolean, val spiffeId: String?, val reason: String?) {
        fun toJson(): Map<String, Any?> {
            val m = linkedMapOf<String, Any?>("ok" to ok, "bound" to bound)
            if (spiffeId != null) m["identity"] = linkedMapOf("spiffe_id" to spiffeId)
            if (reason != null) m["reason"] = reason
            return m
        }
    }

    /**
     * Admit a workload under its verified SPIFFE ID: verify the SVID, bind it to [instanceKey], and return its identity. Anything
     * unverifiable, unbound or for a different key is `ok: false` with the error code as the reason ("JOSEError" for a JOSE failure,
     * else the exception's class name).
     */
    @JvmStatic
    fun spiffeAdmissionEvidence(e: SpiffeEvidence, instanceKey: String?): SpiffeAdmissionEvidenceResult = try {
        val svid: Any = if (e.kind == "x509") verifyX509Svid(e.chain, e.verifyX509!!) else verifyJwtSvid(e.token!!, e.verifyJwt!!)
        val h = svidToHolder(svid, instanceKey, e.bind)
        if (h.holder != instanceKey) SpiffeAdmissionEvidenceResult(false, false, null, "SVID is bound to a different key")
        else SpiffeAdmissionEvidenceResult(true, true, h.spiffeId, null)
    } catch (err: SpiffeError) {
        SpiffeAdmissionEvidenceResult(false, false, null, err.code)
    } catch (err: RuntimeException) {
        SpiffeAdmissionEvidenceResult(false, false, null, if (err is Jose.JoseException) "JOSEError" else err.javaClass.simpleName)
    }
}
