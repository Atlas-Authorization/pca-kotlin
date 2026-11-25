package net.atlasauth.pca.verifier

import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.fail
import org.junit.Test

/**
 * Google Confidential Space, exact outcomes: the constructor's guards and anchor arithmetic, the JWK reader, kid selection,
 * trusted-JWKS / SPKI / x5c / root anchoring (certificate and bare-key roots), second-resolution time and skew edges and the
 * claim shapes (iss, swname, swversion, hwmodel, dbgstat, eat_nonce, submods).
 */
class Kill05GcpAmdAttestGcpTest {
    private val k = Kill05GcpAmdKit
    private val v = "gcp-confidential-space"
    private val issuer = "https://confidentialcomputing.googleapis.com"
    private val now = Kill05GcpAmdKit.NOW
    private val sigInvalid = "Confidential Space signing key invalid: "
    private val noKid = sigInvalid + "no kid on the token and no unambiguous single signing key available"
    private val neither = sigInvalid + "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate"
    private val unsupported = sigInvalid + "JWKS key is not a usable public key: error:1E08010C:DECODER routines::unsupported"
    private val notAnchored = sigInvalid + "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)"
    private val notTrusted = sigInvalid + "signing key not trusted: "
    private val noAnchor = notTrusted + "x5c chain does not anchor in a configured GCP trust root"
    private val notEnoughData = "error:0680007B:asn1 encoding routines::not enough data"

    private val key = k.ecKey("secp256r1")
    private val other = k.ecKey("secp256r1")
    private val root = k.ecKey("secp256r1")
    private val rootDer = k.cert("root", "root", root, root, k.basicConstraints(true, -1))
    private val leafDer = k.cert("leaf", "root", key, root)
    private val rawB64 = Base64.getEncoder().encodeToString(Attest.bindingBytes(Kill05GcpAmdKit.BINDING))

    private fun b64u(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    private fun b64u(s: String): String = b64u(s.toByteArray(Charsets.UTF_8))
    private fun num(n: Long): Json.Num = IntentJs.ofLong(n)
    private fun list(vararg xs: Any?): ArrayList<Any?> = arrayListOf(*xs)
    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = linkedMapOf(*kv)
    private fun spki(kp: KeyPair): String = AttestUtil.hex(AttestUtil.sha256(kp.public.encoded))
    private fun pemCert(der: ByteArray): String = k.pem(der)

    private fun signEs256(kp: KeyPair, header: String, payload: String): String {
        val input = b64u(header) + "." + b64u(payload)
        return input + "." + b64u(k.signRaw(kp, "SHA256withECDSA", input.toByteArray(Charsets.UTF_8), 32))
    }

    private fun unsignedJwt(header: String, payload: String): String = b64u(header) + "." + b64u(payload) + ".AA"

    private fun fixed32(v: java.math.BigInteger): ByteArray {
        val b = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        val out = ByteArray(32)
        System.arraycopy(b, 0, out, 32 - b.size, b.size)
        return out
    }

    private fun jwkOf(kp: KeyPair, kid: Any?): LinkedHashMap<String, Any?> {
        val w = (kp.public as ECPublicKey).w
        return obj("kid" to kid, "kty" to "EC", "crv" to "P-256", "x" to b64u(fixed32(w.affineX)), "y" to b64u(fixed32(w.affineY)))
    }

    private fun policy(extra: String = ""): Map<String, Any?> = ParityVectors.obj("{\"imageDigests\":[\"sha256:abc\"]$extra}")

    private fun config(anchors: Any?, pol: Map<String, Any?> = policy(), skew: Any? = null): Map<String, Any?> {
        val c = obj("trustedIssuers" to list(issuer), "trustAnchors" to anchors, "policy" to pol)
        if (skew != null) c["clockSkewMs"] = skew
        return c
    }

    private fun pins(vararg hex: String): Map<String, Any?> = obj("trustedKeySpki" to list(*hex))
    private fun jwks(vararg keys: Any?): Map<String, Any?> = obj("trustedJwks" to obj("keys" to list(*keys)))
    private fun roots(vararg pems: String): Map<String, Any?> = obj("rootCertsPem" to list(*pems))

    private fun claims(mut: ((MutableMap<String, Any?>) -> Unit)? = null): String {
        val nowSec = now / 1000
        val m = obj(
            "iss" to issuer, "exp" to num(nowSec + 3600), "iat" to num(nowSec - 60), "nbf" to num(nowSec - 60),
            "swname" to "CONFIDENTIAL_SPACE", "swversion" to list("240500"), "hwmodel" to "GCP_INTEL_TDX", "dbgstat" to "disabled-since-boot",
            "eat_nonce" to list(rawB64),
            "submods" to obj("confidential_space" to obj(), "container" to obj("image_digest" to "sha256:abc", "image_reference" to "r/i@sha256:abc")),
        )
        if (mut != null) mut(m)
        return Json.canonicalize(m)
    }

    @Suppress("UNCHECKED_CAST")
    private fun container(m: MutableMap<String, Any?>): MutableMap<String, Any?> = (m["submods"] as MutableMap<String, Any?>)["container"] as MutableMap<String, Any?>

    private fun trusted(pol: Map<String, Any?> = policy(), skew: Any? = null): Map<String, Any?> = config(jwks(jwkOf(key, "k1")), pol, skew)

    private fun tok(mut: ((MutableMap<String, Any?>) -> Unit)? = null): String = signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"k1\"}", claims(mut))

    private fun run(c: Map<String, Any?>, ev: Map<String, Any?>?, at: Long = now): Attest.Result =
        Attest.verifierFromConfig(v, c).verify(ev, Kill05GcpAmdKit.BINDING, at)

    private fun gcp(c: Map<String, Any?>, token: String, at: Long = now): Attest.Result = run(c, obj("token" to token), at)

    private fun constructError(c: Map<String, Any?>): String? = try {
        Attest.verifierFromConfig(v, c)
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    // ---- construction ----

    @Test
    fun constructionGuards() {
        val p = "createGcpConfidentialSpaceVerifier: "
        val badIssuer = p + "every trusted issuer must be a non-empty URL string"
        val noIssuers = p + "trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs"
        val noAnchors = p + "trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted"
        fun withIssuers(iss: Any?): Map<String, Any?> = obj("trustedIssuers" to iss, "trustAnchors" to pins("aa"), "policy" to policy())
        assertEquals(noIssuers, constructError(withIssuers("https://i")))
        assertEquals(noIssuers, constructError(withIssuers(list())))
        assertEquals(badIssuer, constructError(withIssuers(list(""))))
        assertEquals(badIssuer, constructError(withIssuers(list("https://i", ""))))
        assertEquals(badIssuer, constructError(withIssuers(list(Json.Num("5")))))
        // a string trustedKeySpki counts by its length and pins nothing
        assertEquals(null, constructError(config(obj("trustedKeySpki" to "aa"))))
        // the anchor count is a sum: one JWKS key + one pin, one pin + one root
        assertEquals(null, constructError(config(obj("trustedJwks" to obj("keys" to list(obj())), "trustedKeySpki" to list("aa")))))
        assertEquals(null, constructError(config(obj("trustedKeySpki" to list("aa"), "rootCertsPem" to list("x")))))
        assertEquals(null, constructError(config(jwks(obj()))))
        // trustedJwks.keys (or trustedJwks itself) that is not the expected shape adds no key
        assertEquals(noAnchors, constructError(config(obj("trustedJwks" to obj("keys" to "x")))))
        assertEquals(noAnchors, constructError(config(obj("trustedJwks" to "x"))))
        assertEquals(noAnchors, constructError(config("x")))
        assertEquals(p + "policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)", constructError(obj("trustedIssuers" to list(issuer), "trustAnchors" to pins("aa"))))
        assertEquals(p + "policy.allowedTeeTypes, when present, must be non-empty", constructError(config(pins("aa"), policy(",\"allowedTeeTypes\":[]"))))
        assertNotNull(Attest.verifierFromConfig(v, config(pins("aa"), policy(",\"allowedTeeTypes\":null"))))
    }

    @Test
    fun policyShapes() {
        // a non-list allowedTeeTypes / allowedSwVersions restricts nothing; non-string members are ignored
        assertOk("allowedTeeTypes a string", gcp(trusted(policy(",\"allowedTeeTypes\":\"sev-snp\"")), tok()))
        assertOk("allowedTeeTypes null", gcp(trusted(policy(",\"allowedTeeTypes\":null")), tok()))
        assertOk("allowedTeeTypes with a number", gcp(trusted(policy(",\"allowedTeeTypes\":[5,\"tdx\"]")), tok()))
        k.assertDenied(
            "allowedTeeTypes only a number", gcp(trusted(policy(",\"allowedTeeTypes\":[5]")), tok()),
            "attestation type 'tdx' (hwmodel 'GCP_INTEL_TDX') is not in the policy allowlist",
        )
        assertOk("allowedSwVersions a string", gcp(trusted(policy(",\"allowedSwVersions\":\"1\"")), tok()))
        assertOk("allowedSwVersions with a number", gcp(trusted(policy(",\"allowedSwVersions\":[5,\"240500\"]")), tok()))
        // a non-string expectedSwName keeps the default; a non-string nonceHash keeps the raw binding
        assertOk("expectedSwName a number", gcp(trusted(policy(",\"expectedSwName\":5")), tok()))
        k.assertDenied(
            "expectedSwName set", gcp(trusted(policy(",\"expectedSwName\":\"OTHER\"")), tok()),
            "unexpected swname 'CONFIDENTIAL_SPACE' (expected 'OTHER')",
        )
        assertOk("nonceHash a number", gcp(trusted(policy(",\"nonceHash\":5")), tok()))
        assertOk("upper-case image allowlist", gcp(trusted(ParityVectors.obj("{\"imageDigests\":[\"SHA256:ABC\"]}")), tok()))
        k.assertDenied("debug build", gcp(trusted(), tok { it["dbgstat"] = "enabled" }), "token dbgstat 'enabled' is not 'disabled-since-boot' (debug build — no confidentiality)")
        assertOk("debug allowed", gcp(trusted(policy(",\"allowDebug\":true")), tok { it["dbgstat"] = "enabled" }))
    }

    private fun assertOk(name: String, r: Attest.Result) = k.assertOk(name, r)

    // ---- the JWK key reader ----

    @Test
    fun jwkKeyTable() {
        val c = config(pins("aa"))
        val unsigned = unsignedJwt("{\"alg\":\"ES256\",\"kid\":\"k1\"}", "{}")
        val good = jwkOf(key, "k1")
        val x = good["x"]
        val y = good["y"]
        val rsa = k.rsaKey().public as RSAPublicKey
        val n = b64u(rsa.modulus.toByteArray())
        val e = b64u(rsa.publicExponent.toByteArray())
        val five = Json.Num("5")
        val oddCert = k.certSpki("odd", "odd", Kill05GcpAmdKit.NB, Kill05GcpAmdKit.NA, k.seq(k.seq(k.oid("1.2.3.4")), k.bits(0, k.bytes(1, 2, 3))), other)
        val rows = listOf(
            obj("kid" to "k1", "n" to n) to neither,
            obj("kid" to "k1", "e" to e) to neither,
            obj("kid" to "k1", "n" to n, "e" to five) to neither,
            obj("kid" to "k1", "n" to five, "e" to e) to neither,
            obj("kid" to "k1", "n" to "", "e" to e) to unsupported,
            obj("kid" to "k1", "n" to n, "e" to "AQ") to unsupported,
            obj("kid" to "k1", "kty" to "EC", "crv" to "P-256", "x" to x) to neither,
            obj("kid" to "k1", "kty" to "EC", "crv" to "P-256", "y" to y) to neither,
            obj("kid" to "k1", "kty" to "EC", "x" to x, "y" to y) to neither,
            obj("kid" to "k1", "kty" to "EC", "crv" to five, "x" to x, "y" to y) to neither,
            obj("kid" to "k1", "kty" to "EC", "crv" to "P-256", "x" to five, "y" to y) to neither,
            obj("kid" to "k1", "kty" to "EC", "crv" to "P-256", "x" to x, "y" to five) to neither,
            obj("kid" to "k1", "kty" to "OKP", "crv" to "P-256", "x" to x, "y" to y) to neither,
            obj("kid" to "k1", "crv" to "P-256", "x" to x, "y" to y) to neither,
            obj("kid" to "k1", "kty" to "EC", "crv" to "P-256", "x" to "AA", "y" to "AA") to unsupported,
            obj("kid" to "k1", "kty" to "EC", "crv" to "P-999", "x" to x, "y" to y) to unsupported,
            obj("kid" to "k1", "x5c" to list()) to neither,
            obj("kid" to "k1", "x5c" to list(five)) to neither,
            obj("kid" to "k1", "x5c" to "MAA=") to neither,
            obj("kid" to "k1", "x5c" to list("MAA=")) to sigInvalid + "JWKS key is not a usable public key: " + notEnoughData,
            // usable keys that no anchor vouches for
            obj("kid" to "k1", "n" to n, "e" to e) to notAnchored,
            obj("kid" to "k1", "n" to n, "e" to e, "x5c" to list()) to notAnchored,
            good to notAnchored,
            // the n/e key is the signing key; its x5c chain is still checked, and a leaf whose key cannot be read pins nothing
            obj("kid" to "k1", "n" to n, "e" to e, "x5c" to list(k.b64(oddCert))) to noAnchor,
        )
        for ((jwk, want) in rows) k.assertDenied(Json.canonicalize(jwk), run(c, obj("token" to unsigned, "jwks" to obj("keys" to list(jwk)))), want)
        // evidence keys that are not a list hold no key
        k.assertDenied("keys not a list", run(c, obj("token" to unsigned, "jwks" to obj("keys" to "x"))), sigInvalid + "no JWKS key matches the token kid 'k1' (untrusted signer)")
    }

    // ---- kid selection and anchoring ----

    @Test
    fun keySelectionAndAnchoring() {
        // an empty kid is no kid: the sole trusted key signs
        assertOk("empty kid, sole trusted key", gcp(trusted(), signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"\"}", claims())))
        assertOk("no kid, sole trusted key", gcp(trusted(), signEs256(key, "{\"alg\":\"ES256\"}", claims())))
        k.assertDenied("empty kid, no key", gcp(config(pins("aa")), signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"\"}", claims())), noKid)
        k.assertDenied("no kid, two trusted keys", gcp(config(jwks(jwkOf(key, "k1"), jwkOf(other, "k2"))), signEs256(key, "{\"alg\":\"ES256\"}", claims())), noKid)
        // kid lookup skips non-object members, non-string kids and keys with another kid; the pin compares lowercase
        val pinned = config(pins(spki(key).uppercase()))
        val keys = list(Json.Num("5"), jwkOf(other, Json.Num("5")), jwkOf(other, "x"), jwkOf(key, "k1"))
        assertOk("kid among several keys", run(pinned, obj("token" to tok(), "jwks" to obj("keys" to keys))))
        // an evidence key anchored by an equal pinned JWKS key (a non-object JWKS member is skipped)
        val evKey = obj("token" to tok(), "jwks" to obj("keys" to list(jwkOf(key, "k1"))))
        assertOk("anchored through an equal trusted key", run(config(jwks(Json.Num("5"), jwkOf(key, "renamed"))), evKey))
        k.assertDenied("trusted key differs", run(config(jwks(jwkOf(other, "o"))), evKey), notAnchored)
        // the header x5c is used only when no JWKS key was picked
        val otherLeaf = k.b64(k.cert("o", "root", other, root))
        assertOk("kid wins over the header x5c", gcp(trusted(), signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"k1\",\"x5c\":[\"$otherLeaf\"]}", claims())))
        k.assertDenied("empty header x5c", gcp(config(pins("aa")), signEs256(key, "{\"alg\":\"ES256\",\"x5c\":[]}", claims())), noKid)
        // an x5c key with neither a pin nor a root configured is not chain-checked (and a kid the JWKS lacks is not 'trusted')
        val leafHdr = "{\"alg\":\"ES256\",\"kid\":\"zz\",\"x5c\":[\"${k.b64(leafDer)}\"]}"
        k.assertDenied("x5c without pins or roots", gcp(config(jwks(jwkOf(other, "o"))), signEs256(key, leafHdr, claims())), notAnchored)
        k.assertDenied("pins only, chain unpinned", gcp(config(pins("aa")), signEs256(key, leafHdr, claims())), noAnchor)
        assertOk("the x5c leaf itself pinned", gcp(config(pins(spki(key))), signEs256(key, leafHdr, claims())))
    }

    // ---- the x5c chain ----

    private fun x5cTok(vararg chain: String): String =
        signEs256(key, "{\"alg\":\"ES256\",\"x5c\":${Json.canonicalize(list(*chain))}}", claims())

    /** attest-gcp-confidential-space.ts:468-472 (365d0e8ec): a genuine public chain beside an attacker's n/e or x/y vouches for nothing. */
    @Test
    fun aJwkKeyBesideAGenuineChainMustBeTheLeafKey() {
        val rogue = k.ecKey("secp256r1")
        val chain = list(k.b64(leafDer), k.b64(rootDer))
        fun tokBy(signer: java.security.KeyPair) = signEs256(signer, "{\"alg\":\"ES256\",\"kid\":\"k1\"}", claims())
        fun beside(jwkKey: java.security.KeyPair) = obj("keys" to list(LinkedHashMap(jwkOf(jwkKey, "k1")).also { it["x5c"] = chain }))
        for ((name, anchors) in listOf("root" to config(roots(pemCert(rootDer))), "pin" to config(pins(spki(root))))) {
            k.assertDenied("forged, $name", run(anchors, obj("token" to tokBy(rogue), "jwks" to beside(rogue))), notTrusted + "the JWK key is not the key of its x5c leaf")
            assertOk("the leaf key beside its own chain, $name", run(anchors, obj("token" to tokBy(key), "jwks" to beside(key))))
        }
        // a leaf whose key cannot be read is no match either
        val xLeaf = k.certSpki("leaf", "root", k.NB, k.NA, java.security.KeyPairGenerator.getInstance("X25519").generateKeyPair().public.encoded, root)
        val odd = obj("keys" to list(LinkedHashMap(jwkOf(rogue, "k1")).also { it["x5c"] = list(k.b64(xLeaf), k.b64(rootDer)) }))
        k.assertDenied("unreadable leaf key", run(config(roots(pemCert(rootDer))), obj("token" to tokBy(rogue), "jwks" to odd)), notTrusted + "the JWK key is not the key of its x5c leaf")
    }

    @Test
    fun x5cChainProfile() {
        val rootPinned = config(pins(spki(root)))
        for ((name, chain, want) in k.profileTable(key, root)) {
            val got = gcp(rootPinned, x5cTok(*(chain + rootDer).map { k.b64(it) }.toTypedArray()))
            if (want == "") assertOk(name, got) else k.assertDenied(name, got, notTrusted + "x5c chain profile: " + want)
        }
    }

    @Test
    fun x5cChainTable() {
        val rootPinned = config(pins(spki(root)))
        assertOk("leaf + pinned root", gcp(rootPinned, x5cTok(k.b64(leafDer), k.b64(rootDer))))
        val strangerLeaf = k.cert("leaf", "root", key, other)
        k.assertDenied("bad link 0", gcp(rootPinned, x5cTok(k.b64(strangerLeaf), k.b64(rootDer))), notTrusted + "x5c link 0 is not signed by the certificate above it")
        val mid = k.ecKey("secp256r1")
        val leafUnderMid = k.cert("leaf", "mid", key, mid)
        val midUnderOther = k.cert("mid", "root", mid, other)
        k.assertDenied(
            "bad link 1", gcp(rootPinned, x5cTok(k.b64(leafUnderMid), k.b64(midUnderOther), k.b64(rootDer))),
            notTrusted + "x5c link 1 is not signed by the certificate above it",
        )
        assertOk("three-link chain", gcp(rootPinned, x5cTok(k.b64(leafUnderMid), k.b64(k.cert("mid", "root", mid, root, k.basicConstraints(true, -1))), k.b64(rootDer))))
        k.assertDenied("empty entry", gcp(rootPinned, x5cTok(k.b64(leafDer), "")), notTrusted + "empty x5c entry at index 1")
        k.assertDenied("malformed entry", gcp(rootPinned, x5cTok(k.b64(leafDer), "MAA=")), notTrusted + "malformed x5c certificate at index 1: " + notEnoughData)
        val old = k.certSpki("leaf", "root", "200101000000Z", "210101000000Z", key.public.encoded, root)
        k.assertDenied("expired leaf", gcp(rootPinned, x5cTok(k.b64(old))), notTrusted + "x5c certificate at index 0 is outside its validity window")
        val oldRoot = k.certSpki("root", "root", "200101000000Z", "210101000000Z", root.public.encoded, root)
        k.assertDenied("expired root", gcp(rootPinned, x5cTok(k.b64(leafDer), k.b64(oldRoot))), notTrusted + "x5c certificate at index 1 is outside its validity window")
        // a non-string entry (only a JWKS member can carry one)
        val ev = obj("token" to tok(), "jwks" to obj("keys" to list(obj("kid" to "k1", "x5c" to list(k.b64(leafDer), Json.Num("5"))))))
        k.assertDenied("non-string entry", run(rootPinned, ev), notTrusted + "empty x5c entry at index 1")
    }

    /** The PEM of a bare SubjectPublicKeyInfo, its base64 broken by every whitespace character the reader strips. */
    private fun publicKeyPem(spkiDer: ByteArray): String {
        val body = k.b64(spkiDer)
        val seps = listOf(" ", "\t", "\r", "\n")
        val sb = StringBuilder("-----BEGIN PUBLIC KEY-----\n")
        var i = 0
        var s = 0
        while (i < body.length) {
            val end = minOf(i + 12, body.length)
            sb.append(body, i, end)
            sb.append(seps[s % seps.size])
            s++
            i = end
        }
        return sb.append("-----END PUBLIC KEY-----\n").toString()
    }

    @Test
    fun rootAnchors() {
        val leafTok = x5cTok(k.b64(leafDer))
        // an unreadable root entry is skipped; the next root anchors the chain
        assertOk("second certificate root anchors", gcp(config(roots("not pem", pemCert(rootDer))), leafTok))
        k.assertDenied("only an unreadable root", gcp(config(roots("not pem")), leafTok), noAnchor)
        k.assertDenied("a root that did not sign", gcp(config(roots(pemCert(k.cert("o", "o", other, other)))), leafTok), noAnchor)
        // a bare public key root, its base64 split by spaces, tabs, CRs and LFs
        val keyPem = publicKeyPem(root.public.encoded)
        assertOk("bare public key root", gcp(config(roots(keyPem)), leafTok))
        assertOk("bare public key root after a non-signing one", gcp(config(roots(publicKeyPem(other.public.encoded), keyPem)), leafTok))
        k.assertDenied("bare key of another signer", gcp(config(roots(publicKeyPem(other.public.encoded))), leafTok), noAnchor)
        k.assertDenied("public key block not base64", gcp(config(roots("-----BEGIN PUBLIC KEY-----\n@@@@\n-----END PUBLIC KEY-----\n")), leafTok), noAnchor)
        k.assertDenied("public key block not a key", gcp(config(roots("-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----\n")), leafTok), noAnchor)
        k.assertDenied("public key block unterminated", gcp(config(roots("-----BEGIN PUBLIC KEY-----\n" + k.b64(root.public.encoded))), leafTok), noAnchor)
    }

    // ---- time ----

    @Test
    fun timeEdges() {
        val nowSec = now / 1000
        val expired = "Confidential Space token expired"
        val nbf = "Confidential Space token not yet valid (nbf)"
        val iat = "Confidential Space token issued in the future (iat)"
        fun skew(ms: Long) = trusted(skew = Json.Num(ms.toString()))
        assertOk("exp at this second (milliseconds ignored)", gcp(trusted(), tok { it["exp"] = num(nowSec) }, now + 999))
        k.assertDenied("exp one second ago", gcp(trusted(), tok { it["exp"] = num(nowSec) }, now + 1000), expired)
        assertOk("nbf at this second", gcp(trusted(), tok { it["nbf"] = num(nowSec) }))
        k.assertDenied("nbf next second", gcp(trusted(), tok { it["nbf"] = num(nowSec + 1) }), nbf)
        assertOk("nbf two seconds ahead, skew 2 s", gcp(skew(2000), tok { it["nbf"] = num(nowSec + 2) }))
        k.assertDenied("nbf three seconds ahead, skew 2 s", gcp(skew(2000), tok { it["nbf"] = num(nowSec + 3) }), nbf)
        // the skew rounds up to whole seconds: 1001 ms is 2 s
        assertOk("nbf two seconds ahead, skew 1.001 s", gcp(skew(1001), tok { it["nbf"] = num(nowSec + 2) }))
        k.assertDenied("nbf three seconds ahead, skew 1.001 s", gcp(skew(1001), tok { it["nbf"] = num(nowSec + 3) }), nbf)
        assertOk("iat at this second", gcp(trusted(), tok { it.remove("nbf"); it["iat"] = num(nowSec) }))
        k.assertDenied("iat next second", gcp(trusted(), tok { it.remove("nbf"); it["iat"] = num(nowSec + 1) }), iat)
        assertOk("iat two seconds ahead, skew 1.5 s", gcp(skew(1500), tok { it.remove("nbf"); it["iat"] = num(nowSec + 2) }))
        k.assertDenied("iat three seconds ahead, skew 1.5 s", gcp(skew(1500), tok { it.remove("nbf"); it["iat"] = num(nowSec + 3) }), iat)
        k.assertDenied("exp three seconds ago, skew 1.5 s", gcp(skew(1500), tok { it["exp"] = num(nowSec - 3) }), expired)
        assertOk("exp two seconds ago, skew 1.5 s", gcp(skew(1500), tok { it["exp"] = num(nowSec - 2) }))
        assertOk("no nbf, no iat", gcp(trusted(), tok { it.remove("nbf"); it.remove("iat") }))
    }

    // ---- claims ----

    @Test
    fun claimShapes() {
        val none = "no GCP Confidential Space token for this action"
        k.assertDenied("token not a string", run(trusted(), obj("token" to Json.Num("5"))), none)
        k.assertDenied("empty token", run(trusted(), obj("token" to "")), none)
        k.assertDenied("no token", run(trusted(), obj()), none)
        k.assertDenied("numeric iss", gcp(trusted(), tok { it["iss"] = Json.Num("5") }), "token iss 'undefined' is not a configured trusted Google attestation issuer")
        k.assertDenied("empty iss", gcp(trusted(), tok { it["iss"] = "" }), "token iss '' is not a configured trusted Google attestation issuer")
        val swname = "unexpected swname 'undefined' (expected 'CONFIDENTIAL_SPACE')"
        k.assertDenied("no swname", gcp(trusted(), tok { it.remove("swname") }), swname)
        k.assertDenied("numeric swname", gcp(trusted(), tok { it["swname"] = Json.Num("5") }), swname)
        val versions = trusted(policy(",\"allowedSwVersions\":[\"\",\"5\"]"))
        val notAllowed = "swversion not in policy allowlist"
        k.assertDenied("empty swversion", gcp(versions, tok { it["swversion"] = "" }), notAllowed)
        k.assertDenied("numeric swversion", gcp(versions, tok { it["swversion"] = Json.Num("5") }), notAllowed)
        k.assertDenied("no swversion", gcp(versions, tok { it.remove("swversion") }), notAllowed)
        k.assertDenied("swversion list with a number", gcp(versions, tok { it["swversion"] = list("5", Json.Num("7")) }), notAllowed)
        k.assertDenied("swversion list not allowed", gcp(versions, tok { it["swversion"] = list("x", "y") }), notAllowed)
        assertOk("swversion list", gcp(versions, tok { it["swversion"] = list("x", "5") }))
        assertOk("swversion list, first allowed", gcp(versions, tok { it["swversion"] = list("5", "x") }))
        assertOk("swversion string", gcp(versions, tok { it["swversion"] = "5" }))
        k.assertDenied("numeric hwmodel", gcp(trusted(), tok { it["hwmodel"] = Json.Num("5") }), "token carries no hwmodel claim")
        k.assertDenied("numeric dbgstat", gcp(trusted(), tok { it["dbgstat"] = Json.Num("5") }), "token dbgstat 'undefined' is not 'disabled-since-boot' (debug build — no confidentiality)")
        k.assertDenied("no submods", gcp(trusted(), tok { it.remove("submods") }), "token carries no submods.confidential_space (not a Confidential Space token)")
        val noNonce = "token carries no eat_nonce claim to bind the PCA challenge"
        k.assertDenied("empty eat_nonce list entry", gcp(trusted(), tok { it["eat_nonce"] = list("") }), noNonce)
        k.assertDenied("empty eat_nonce", gcp(trusted(), tok { it["eat_nonce"] = "" }), noNonce)
        k.assertDenied("eat_nonce with a non-string", gcp(trusted(), tok { it["eat_nonce"] = list(Json.Num("5"), rawB64) }), noNonce)
        k.assertDenied("numeric eat_nonce", gcp(trusted(), tok { it["eat_nonce"] = Json.Num("5") }), noNonce)
        val unbound = "eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)"
        k.assertDenied("an empty entry beside an unbinding one", gcp(trusted(), tok { it["eat_nonce"] = list("", "AAAA") }), unbound)
        assertOk("eat_nonce string", gcp(trusted(), tok { it["eat_nonce"] = rawB64 }))
        assertOk("an undecodable candidate before the binding", gcp(trusted(), tok { it["eat_nonce"] = list("!!!", rawB64) }))
        assertOk("an empty candidate before the binding", gcp(trusted(), tok { it["eat_nonce"] = list("", rawB64) }))
        // the host fields
        val r = gcp(trusted(), tok { container(it).remove("image_reference") })
        assertOk("no image_reference", r)
        assertEquals(mapOf("attestation_type" to "tdx", "hwmodel" to "GCP_INTEL_TDX", "image_digest" to "sha256:abc"), r.hostAsserted)
        val full = gcp(trusted(), tok())
        assertOk("image_reference", full)
        assertEquals("r/i@sha256:abc", full.hostAsserted!!["image_reference"])
        assertEquals("sha256:abc", full.measured!!["runtime_measurement"])
    }

    @Test
    fun hardwareModels() {
        val rows = listOf(
            "GCP_AMD_SEV" to "sev-snp", "GCP_AMD_SEV_SNP" to "sev-snp", "GCP_AMD_SEV_ES" to "sev-snp", "gcp_amd_sev_future" to "sev-snp",
            "GCP_INTEL_TDX" to "tdx", "gcp_intel_tdx_v2" to "tdx",
        )
        for ((hw, want) in rows) {
            val r = gcp(trusted(), tok { it["hwmodel"] = hw })
            assertOk(hw, r)
            assertEquals(hw, want, r.hostAsserted!!["attestation_type"])
            assertEquals(hw, hw, r.hostAsserted!!["hwmodel"])
        }
        for (hw in listOf("GCP_AMD", "GCP_INTEL", "AMD_SEV", "X_GCP_INTEL_TDX")) {
            k.assertDenied(hw, gcp(trusted(), tok { it["hwmodel"] = hw }), "unrecognized hwmodel '$hw' (not a known AMD SEV-SNP / Intel TDX model)")
        }
        k.assertDenied("empty hwmodel", gcp(trusted(), tok { it["hwmodel"] = "" }), "token carries no hwmodel claim")
    }

    @Test
    fun signatureKinds() {
        // an ES256 token under the RSA key a JWKS pins, and an RS256 token under an EC key: each refused by key type
        val rsa = k.rsaKey()
        val pub = rsa.public as RSAPublicKey
        val rsaJwk = obj("kid" to "r", "n" to b64u(pub.modulus.toByteArray()), "e" to b64u(pub.publicExponent.toByteArray()))
        val c = config(jwks(rsaJwk, jwkOf(key, "k1")))
        k.assertDenied("ES256 under RSA", gcp(c, signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"r\"}", claims())), "ES256 token but signing key is RSA/undefined (not EC P-256)")
        k.assertDenied("RS256 under EC", gcp(c, unsignedJwt("{\"alg\":\"RS256\",\"kid\":\"k1\"}", claims())), "RS256 token but signing key is EC (not RSA)")
        val s = java.security.Signature.getInstance("SHA256withRSA")
        val input = b64u("{\"alg\":\"RS256\",\"kid\":\"r\"}") + "." + b64u(claims())
        s.initSign(rsa.private)
        s.update(input.toByteArray(Charsets.UTF_8))
        assertOk("RS256 under the pinned RSA key", gcp(c, input + "." + b64u(s.sign())))
        k.assertDenied("RS256 signature of other bytes", gcp(c, input + "." + b64u(ByteArray(256))), "JWS RS256 signature does not verify under the Confidential Space signing key")
        k.assertDenied("ES256 signature 63 bytes", gcp(c, b64u("{\"alg\":\"ES256\",\"kid\":\"k1\"}") + "." + b64u(claims()) + "." + b64u(ByteArray(63))), "ES256 signature is 63 bytes (expected 64: r‖s)")
        assertFalse(gcp(c, b64u("{\"alg\":\"ES256\",\"kid\":\"k1\"}") + "." + b64u(claims()) + "." + b64u(ByteArray(64))).ok)
        try {
            Attest.verifierFromConfig(v, obj("trustedIssuers" to list(issuer)))
            fail("no anchors must be refused")
        } catch (e: IllegalArgumentException) {
            assertEquals("createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted", e.message)
        }
    }
}
