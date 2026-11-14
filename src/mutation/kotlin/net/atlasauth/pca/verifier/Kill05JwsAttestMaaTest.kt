package net.atlasauth.pca.verifier

import java.security.KeyPair
import net.atlasauth.pca.verifier.Kill05JwsKit.BINDING
import net.atlasauth.pca.verifier.Kill05JwsKit.MRTD
import net.atlasauth.pca.verifier.Kill05JwsKit.NOW
import net.atlasauth.pca.verifier.Kill05JwsKit.RD
import net.atlasauth.pca.verifier.Kill05JwsKit.cert
import net.atlasauth.pca.verifier.Kill05JwsKit.json
import net.atlasauth.pca.verifier.Kill05JwsKit.obj
import net.atlasauth.pca.verifier.Kill05JwsKit.pem
import net.atlasauth.pca.verifier.Kill05JwsKit.pin
import net.atlasauth.pca.verifier.Kill05JwsKit.signEs256
import net.atlasauth.pca.verifier.Kill05JwsKit.std
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Azure MAA, exact outcomes: constructor guards, the signing-chain resolution table (JWKS / kid / header x5c), the x5c chain table
 * (anchor by fingerprint or root certificate, links, unreadable roots and keys), the ES256 / RS256 key checks, time and skew
 * edges, the binding modes and the TDX / SEV-SNP claims.
 */
class Kill05JwsAttestMaaTest {
    private val v = "azure-maa"
    private val tdx = """{"tdxMrtds":["$MRTD"]}"""
    private val key = Kill05JwsKit.ecKey("secp256r1")
    private val certDer = cert("maa-test", "maa-test", key.public, key)
    private val pinHex = pin(key.public)

    private fun config(anchors: String, policy: String, extra: String = ""): MutableMap<String, Any?> =
        obj("""{"trustedIssuers":["https://maa.test"],"trustAnchors":$anchors,"policy":$policy$extra}""")

    private fun pinned(policy: String, extra: String = "") = config("""{"rootSpkiSha256":["$pinHex"]}""", policy, extra)

    private fun constructError(cfgText: String): String? = try {
        Attest.verifierFromConfig(v, obj(cfgText))
        null
    } catch (e: IllegalArgumentException) {
        e.message
    }

    @Suppress("UNCHECKED_CAST")
    private fun tee(m: MutableMap<String, Any?>): MutableMap<String, Any?> = m["x-ms-isolation-tee"] as MutableMap<String, Any?>

    private fun claims(mut: ((MutableMap<String, Any?>) -> Unit)?): String {
        val nowSec = NOW / 1000
        val t = linkedMapOf<String, Any?>(
            "x-ms-attestation-type" to "tdxvm", "tdx_mrtd" to MRTD.uppercase(), "tdx_report_data" to RD,
            "attester_tcb_status" to "UpToDate", "tdx_rtmr0" to "bb",
        )
        val m = linkedMapOf<String, Any?>("iss" to "https://maa.test", "exp" to nowSec + 3600, "iat" to nowSec - 60, "nbf" to nowSec - 60, "x-ms-isolation-tee" to t)
        mut?.invoke(m)
        return json(m)
    }

    private fun x5cTok(kp: KeyPair, mut: ((MutableMap<String, Any?>) -> Unit)?, vararg chain: String): String =
        signEs256(kp, """{"alg":"ES256","x5c":${json(chain.toList())}}""", claims(mut))

    private fun tok(mut: ((MutableMap<String, Any?>) -> Unit)? = null) = x5cTok(key, mut, std(certDer))

    private fun maa(c: Map<String, Any?>, token: Any?, jwks: Any? = null, b: Attest.Binding? = BINDING): Attest.Result {
        val ev = linkedMapOf<String, Any?>("token" to token)
        if (jwks != null) ev["jwks"] = jwks
        return Attest.verifierFromConfig(v, c).verify(ev, b, NOW)
    }

    private fun ok(name: String, r: Attest.Result) {
        assertEquals(name, "", r.reason)
        assertTrue(name, r.ok && r.bound)
    }

    private fun denied(name: String, r: Attest.Result, want: String) {
        assertFalse(name, r.ok)
        assertEquals(name, want, r.reason)
    }

    // ---- construction

    @Test
    fun constructionGuards() {
        val issuers = "createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs"
        assertEquals(issuers, constructError("{}"))
        assertEquals(issuers, constructError("""{"trustedIssuers":[]}"""))
        assertEquals(issuers, constructError("""{"trustedIssuers":"https://i"}"""))
        val each = "createAzureMaaVerifier: every trusted issuer must be a non-empty URL string"
        assertEquals(each, constructError("""{"trustedIssuers":[5]}"""))
        assertEquals(each, constructError("""{"trustedIssuers":["https://i",""]}"""))
        // the anchor count is a sum
        assertNull(constructError("""{"trustedIssuers":["https://i"],"trustAnchors":{"rootCertsPem":["a"],"rootSpkiSha256":["b"]},"policy":$tdx}"""))
        val pol = "createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)"
        assertEquals(pol, constructError("""{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]}}"""))
        assertEquals(pol, constructError("""{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"sevSnpMeasurements":[],"tdxMrtds":[]}}"""))
        assertEquals("createAzureMaaVerifier: policy.sevSnpMinTcb must be an object",
            constructError("""{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"],"sevSnpMinTcb":"x"}}"""))
        for (bad in listOf("\"3\"", "1.5", "-1")) {
            assertEquals(bad, "createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer",
                constructError("""{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"sevSnpMeasurements":["aa"],"sevSnpMinTcb":{"snp":$bad}}}"""))
        }
        // a non-map identity_overrides is ignored, a map one is merged over the measured identity
        ok("non-map overrides", maa(pinned(tdx, ""","identity_overrides":"x""""), tok()))
        val merged = maa(pinned(tdx, ""","identity_overrides":{"model_id":"m"}"""), tok())
        ok("overrides", merged)
        assertEquals("m", merged.measured!!["model_id"])
        assertEquals(MRTD, merged.measured!!["runtime_measurement"])
        assertEquals(v, Attest.verifierFromConfig(v, pinned(tdx)).vendor)
    }

    // ---- the happy path and the claims

    @Test
    fun tdxHappyPathAndHostFields() {
        val r = maa(pinned(tdx), tok())
        ok("baseline", r)
        assertEquals(MRTD, r.measured!!["runtime_measurement"])
        assertEquals(linkedMapOf("attestation_type" to "tdxvm", "tcb_status" to "UpToDate", "rtmr0" to "bb"), r.hostAsserted)
        // a non-string TCB status is neither checked nor asserted
        val num = maa(pinned(tdx), tok { tee(it)["attester_tcb_status"] = 5L })
        ok("numeric tcb status", num)
        assertEquals(linkedMapOf("attestation_type" to "tdxvm", "rtmr0" to "bb"), num.hostAsserted)
        // an empty TCB status allowed by policy is not asserted
        val e = maa(pinned("""{"tdxMrtds":["$MRTD"],"tdxAllowedTcbStatuses":[""]}"""), tok { tee(it)["attester_tcb_status"] = "" })
        ok("empty tcb status", e)
        assertFalse(e.hostAsserted!!.containsKey("tcb_status"))
        denied("tcb not accepted", maa(pinned(tdx), tok { tee(it)["attester_tcb_status"] = "OutOfDate" }), "TDX platform TCB status 'OutOfDate' is not accepted by policy")
        // a mixed status list stays a list: the default statuses never come back
        denied("mixed tcb statuses", maa(pinned("""{"tdxMrtds":["$MRTD"],"tdxAllowedTcbStatuses":["Revoked",5]}"""), tok { tee(it)["attester_tcb_status"] = "UpToDate" }), "TDX platform TCB status 'UpToDate' is not accepted by policy")
        // a malformed allowlist never means no list
        for (name in listOf("sevSnpMeasurements", "tdxMrtds", "sevSnpHostData", "tdxRtmrs")) {
            val other = if (name == "tdxMrtds") "sevSnpMeasurements" else "tdxMrtds"
            assertEquals("createAzureMaaVerifier: policy.$name must list only strings",
                constructError("""{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"$other":["aa"],"$name":["aa",5]}}"""))
        }
        // the alternative MRTD / RTMR0 / report-data claim names, and an upper-case RTMR0 asserted lower-case
        val alt = maa(pinned(tdx), tok {
            val t = tee(it)
            t["x-ms-tdx-mrtd"] = t.remove("tdx_mrtd")
            t["x-ms-tdx-reportdata"] = t.remove("tdx_report_data")
            t.remove("tdx_rtmr0")
            t["x-ms-tdx-rtmr0"] = "CC"
            t.remove("attester_tcb_status")
        })
        ok("alternative claim names", alt)
        assertEquals(linkedMapOf("attestation_type" to "tdxvm", "rtmr0" to "cc"), alt.hostAsserted)
        // the RTMR allowlist is compared lower-case on both sides
        val rt = maa(pinned("""{"tdxMrtds":["$MRTD"],"tdxRtmrs":["BB"]}"""), tok { tee(it)["tdx_rtmr0"] = "Bb" })
        ok("rtmr0 case-insensitive", rt)
        assertEquals("bb", rt.hostAsserted!!["rtmr0"])
        denied("rtmr0 not allowed", maa(pinned("""{"tdxMrtds":["$MRTD"],"tdxRtmrs":["aa"]}"""), tok()), "TDX RTMR0 not in policy allowlist")
        // debug
        ok("non-string dbgstat", maa(pinned(tdx), tok { tee(it)["dbgstat"] = 5L }))
        ok("dbgstat disabled", maa(pinned(tdx), tok { tee(it)["dbgstat"] = "disabled" }))
        denied("dbgstat enabled", maa(pinned(tdx), tok { tee(it)["dbgstat"] = "enabled" }), "TDX guest is debuggable (no confidentiality)")
        denied("td attributes debug", maa(pinned(tdx), tok { tee(it)["tdx_td_attributes_debug"] = true }), "TDX guest is debuggable (no confidentiality)")
        ok("debug allowed", maa(pinned("""{"tdxMrtds":["$MRTD"],"allowDebug":true}"""), tok { tee(it)["dbgstat"] = "enabled" }))
        // the report-data hash option: a non-string mode is ignored, an unknown mode binds the raw value
        ok("non-string reportDataHash", maa(pinned("""{"tdxMrtds":["$MRTD"],"reportDataHash":5}"""), tok()))
        ok("unknown reportDataHash", maa(pinned("""{"tdxMrtds":["$MRTD"],"reportDataHash":"md5"}"""), tok()))
        ok("sha256 reportDataHash", maa(pinned("""{"tdxMrtds":["$MRTD"],"reportDataHash":"sha256"}"""),
            tok { tee(it)["tdx_report_data"] = AttestUtil.hex(AttestUtil.sha256(Attest.bindingBytes(BINDING))) }))
    }

    @Test
    fun tokenIssuerAndTime() {
        val c = pinned(tdx)
        val noToken = "no Azure MAA token for this action"
        denied("non-string token", maa(c, 5L), noToken)
        denied("empty token", maa(c, ""), noToken)
        denied("no token", maa(c, null), noToken)
        denied("no evidence", Attest.verifierFromConfig(v, c).verify(null, BINDING, NOW), noToken)
        denied("no iss", maa(c, tok { it.remove("iss") }), "token iss 'undefined' is not a configured trusted MAA instance")
        denied("numeric iss", maa(c, tok { it["iss"] = 5L }), "token iss 'undefined' is not a configured trusted MAA instance")
        denied("empty iss", maa(c, tok { it["iss"] = "" }), "token iss '' is not a configured trusted MAA instance")
        denied("other iss", maa(c, tok { it["iss"] = "https://x" }), "token iss 'https://x' is not a configured trusted MAA instance")
        val nowSec = NOW / 1000
        denied("no exp", maa(c, tok { it.remove("exp") }), "token has no exp (cannot bound validity — fail closed)")
        denied("expired", maa(c, tok { it["exp"] = nowSec - 1 }), "MAA token expired")
        ok("exp now", maa(c, tok { it["exp"] = nowSec }))
        fun skewed(ms: Long): MutableMap<String, Any?> = pinned(tdx).also { it["clockSkewMs"] = ms }
        fun iat(sec: Long): (MutableMap<String, Any?>) -> Unit = { it.remove("nbf"); it["iat"] = nowSec + sec }
        ok("iat 2 s ahead, skew 1.5 s", maa(skewed(1500), tok(iat(2))))
        denied("iat 3 s ahead, skew 1.5 s", maa(skewed(1500), tok(iat(3))), "MAA token issued in the future (iat)")
        ok("iat 2 s ahead, skew 1.001 s", maa(skewed(1001), tok(iat(2))))
        ok("iat 2 s ahead, skew 2 s", maa(skewed(2000), tok(iat(2))))
        denied("iat 1 s ahead, no skew", maa(c, tok(iat(1))), "MAA token issued in the future (iat)")
        ok("nbf 2 s ahead, skew 2 s", maa(skewed(2000), tok { it["nbf"] = nowSec + 2 }))
        denied("nbf 3 s ahead, skew 2 s", maa(skewed(2000), tok { it["nbf"] = nowSec + 3 }), "MAA token not yet valid (nbf)")
        ok("expired 2 s ago, skew 2 s", maa(skewed(2000), tok { it["exp"] = nowSec - 2 }))
        denied("expired 3 s ago, skew 2 s", maa(skewed(2000), tok { it["exp"] = nowSec - 3 }), "MAA token expired")
    }

    @Test
    fun attestationTypeAndBinding() {
        val c = pinned(tdx)
        val unexpected = "unexpected x-ms-attestation-type 'undefined' (expected sevsnpvm | tdxvm)"
        denied("numeric type", maa(c, tok { tee(it)["x-ms-attestation-type"] = 5L; it["x-ms-attestation-type"] = 5L }), unexpected)
        denied("no type", maa(c, tok { tee(it).remove("x-ms-attestation-type") }), unexpected)
        denied("other type", maa(c, tok { tee(it)["x-ms-attestation-type"] = "sgx" }), "unexpected x-ms-attestation-type 'sgx' (expected sevsnpvm | tdxvm)")
        ok("top-level type", maa(c, tok { tee(it).remove("x-ms-attestation-type"); it["x-ms-attestation-type"] = "tdxvm" }))
        // no isolation claim object: the payload itself carries the TEE claims
        ok("flat claims", maa(c, tok { m -> val t = tee(m); m.remove("x-ms-isolation-tee"); m.putAll(t) }))
        denied("no binding", maa(c, tok(), b = null), "no expected attestation binding supplied")
        denied("binding not constructible", maa(c, tok(), b = Attest.Binding("", "g", 0.0, "n")), "binding not constructible: binding: holderPub required")
        denied("relayed report data", maa(c, tok(), b = Attest.Binding("holder-key", "passport:abc", 0.0, "nonce-2")), "report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)")
        denied("no report data", maa(c, tok { tee(it).remove("tdx_report_data") }), "token carries no report-data claim to bind the PCA challenge")
        denied("undecodable report data", maa(c, tok { tee(it)["tdx_report_data"] = "!!!" }), "report-data claim is not decodable (hex/base64)")
        // the runtime user-data binding
        val rt = pinned("""{"tdxMrtds":["$MRTD"],"runtimeUserDataBinding":true}""")
        ok("runtime user-data", maa(rt, tok { it["x-ms-runtime"] = linkedMapOf("user-data" to RD) }))
        denied("no runtime claim", maa(rt, tok()), "token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)")
        denied("runtime not an object", maa(rt, tok { it["x-ms-runtime"] = "x" }), "token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)")
        val noUd = "x-ms-runtime carries no user-data to bind the PCA challenge"
        denied("empty user-data", maa(rt, tok { it["x-ms-runtime"] = linkedMapOf("user-data" to "") }), noUd)
        denied("numeric user-data", maa(rt, tok { it["x-ms-runtime"] = linkedMapOf("user-data" to 5L) }), noUd)
        val unbound = "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)"
        denied("undecodable user-data", maa(rt, tok { it["x-ms-runtime"] = linkedMapOf("user-data" to "!!!") }), unbound)
        denied("other user-data", maa(rt, tok { it["x-ms-runtime"] = linkedMapOf("user-data" to "abcd") }), unbound)
    }

    @Test
    fun sevSnp() {
        val sev = """{"sevSnpMeasurements":["$MRTD"]}"""
        fun sevTok(mut: (MutableMap<String, Any?>) -> Unit = {}) = tok { m ->
            val t = linkedMapOf<String, Any?>("x-ms-attestation-type" to "sevsnpvm", "x-ms-sevsnpvm-reportdata" to RD, "x-ms-sevsnpvm-launchmeasurement" to MRTD.uppercase())
            mut(t)
            m["x-ms-isolation-tee"] = t
        }
        val r = maa(pinned(sev), sevTok())
        ok("no host data", r)
        assertEquals(linkedMapOf("attestation_type" to "sevsnpvm"), r.hostAsserted)
        assertEquals(MRTD, r.measured!!["runtime_measurement"])
        ok("non-boolean debuggable", maa(pinned(sev), sevTok { it["x-ms-sevsnpvm-is-debuggable"] = "true" }))
        ok("not debuggable", maa(pinned(sev), sevTok { it["x-ms-sevsnpvm-is-debuggable"] = false }))
        denied("debuggable", maa(pinned(sev), sevTok { it["x-ms-sevsnpvm-is-debuggable"] = true }), "SEV-SNP guest is debuggable (no confidentiality)")
        ok("debuggable allowed", maa(pinned("""{"sevSnpMeasurements":["$MRTD"],"allowDebug":true}"""), sevTok { it["x-ms-sevsnpvm-is-debuggable"] = true }))
        val h = maa(pinned(sev), sevTok { it["x-ms-sevsnpvm-hostdata"] = "AB"; it["x-ms-sevsnpvm-tee-svn"] = 3L })
        ok("host data", h)
        assertEquals(linkedMapOf("attestation_type" to "sevsnpvm", "tee_svn" to "3", "host_data" to "ab"), h.hostAsserted)
        denied("measurement not allowed", maa(pinned("""{"sevSnpMeasurements":["aa"]}"""), sevTok()), "SEV-SNP launch measurement not in policy allowlist")
        // an empty SEV-SNP allowlist next to a TDX one does not enable SEV-SNP
        denied("empty SEV-SNP allowlist", maa(pinned("""{"sevSnpMeasurements":[],"tdxMrtds":["$MRTD"]}"""), sevTok()),
            "sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)")
        denied("TDX token, SEV-SNP policy", maa(pinned(sev), tok()), "tdxvm token but policy configures no TDX MRTD allowlist (fail closed)")
    }

    @Test
    fun firstStringMember() {
        assertNull(AttestMaa.firstString(null, listOf("a")))
        val m = linkedMapOf<String, Any?>("a" to 5L, "b" to "", "c" to "x", "d" to "y")
        assertEquals("x", AttestMaa.firstString(m, listOf("a", "b", "c", "d")))
        assertEquals("y", AttestMaa.firstString(m, listOf("d", "c")))
        assertNull(AttestMaa.firstString(m, listOf("a", "b", "z")))
    }

    // ---- signing chain resolution

    @Test
    fun resolveSigningChain() {
        val c = pinned(tdx)
        val noKid = signEs256(key, """{"alg":"ES256"}""", claims(null))
        val emptyKid = signEs256(key, """{"alg":"ES256","kid":""}""", claims(null))
        val kidZz = signEs256(key, """{"alg":"ES256","kid":"zz"}""", claims(null))
        val chain = arrayListOf<Any?>(std(certDer))
        fun keys(vararg k: Any?): Map<String, Any?> = linkedMapOf("keys" to arrayListOf(*k))
        ok("no kid, one key", maa(c, noKid, keys(linkedMapOf("x5c" to chain))))
        ok("empty kid, one key", maa(c, emptyKid, keys(linkedMapOf("kid" to "other", "x5c" to chain))))
        ok("kid after non-object and non-string-kid members", maa(c, kidZz, keys(5L, linkedMapOf("kid" to 7L, "x5c" to arrayListOf<Any?>("AA==")), linkedMapOf("kid" to "zz", "x5c" to chain))))
        ok("keys not a list: the header x5c", maa(c, tok(), linkedMapOf("keys" to "x")))
        ok("empty key list: the header x5c", maa(c, tok(), linkedMapOf("keys" to arrayListOf<Any?>())))
        ok("jwks not an object: the header x5c", maa(c, tok(), "x"))
        denied("no kid, two keys", maa(c, noKid, keys(linkedMapOf("x5c" to chain), linkedMapOf("x5c" to chain))), "token has no kid and the JWKS publishes multiple keys (ambiguous)")
        val noChain = "JWKS key carries no x5c chain"
        denied("sole key without x5c", maa(c, noKid, keys(linkedMapOf("kid" to "a"))), noChain)
        denied("sole key not an object", maa(c, noKid, keys(5L)), noChain)
        denied("sole key x5c not a list", maa(c, noKid, keys(linkedMapOf("x5c" to "s"))), noChain)
        denied("sole key empty x5c", maa(c, noKid, keys(linkedMapOf("x5c" to arrayListOf<Any?>()))), noChain)
        denied("matched key empty x5c", maa(c, kidZz, keys(linkedMapOf("kid" to "zz", "x5c" to arrayListOf<Any?>()))), "JWKS key 'zz' carries no x5c chain")
        denied("kid matches nothing", maa(c, kidZz, keys(linkedMapOf("kid" to "other", "x5c" to chain))), "no JWKS key matches the token kid 'zz' (untrusted signer)")
        denied("empty header x5c", maa(c, signEs256(key, """{"alg":"ES256","x5c":[]}""", claims(null))), "no signing x5c available (no JWKS and no header x5c)")
        denied("no header x5c", maa(c, noKid), "no signing x5c available (no JWKS and no header x5c)")
    }

    // ---- the x5c chain

    private fun anchors(pems: List<String> = emptyList(), pins: List<String> = emptyList()) = AttestMaa.Anchors(pems, pins)

    private fun chainOf(a: AttestMaa.Anchors, vararg x5c: Any?): Pair<AttestCert.Cert?, String> = AttestMaa.verifyX5cChain(a, x5c.toList(), NOW, 0.0)

    private fun chainOk(name: String, got: Pair<AttestCert.Cert?, String>, leaf: ByteArray) {
        assertEquals(name, "", got.second)
        assertTrue(name, got.first!!.raw.contentEquals(leaf))
    }

    private fun chainDenied(name: String, got: Pair<AttestCert.Cert?, String>, want: String) {
        assertNull(name, got.first)
        assertEquals(name, want, got.second)
    }

    @Test
    fun x5cChainProfile() {
        val root = Kill05JwsKit.ecKey("secp256r1")
        val rootDer = Kill05GcpAmdKit.cert("root", "root", root, root, Kill05GcpAmdKit.basicConstraints(true, -1))
        val rooted = anchors(pems = listOf(pem(rootDer)))
        for ((name, chain, want) in Kill05GcpAmdKit.profileTable(Kill05JwsKit.ecKey("secp256r1"), root)) {
            val x5c = chain.map { std(it) as Any? }
            for ((how, got) in listOf(
                "under a root certificate" to AttestMaa.verifyX5cChain(rooted, x5c, NOW, 0.0),
                "anchored in the chain" to AttestMaa.verifyX5cChain(rooted, x5c + std(rootDer), NOW, 0.0),
            )) {
                if (want == "") chainOk("$name, $how", got, chain[0]) else chainDenied("$name, $how", got, "x5c chain profile: $want")
            }
        }
        // the profile stops at the anchor: an issuer below it is checked, a certificate above it is not
        val inter = Kill05JwsKit.ecKey("secp256r1")
        val leaf = Kill05JwsKit.ecKey("secp256r1")
        val pinnedInter = anchors(pins = listOf(pin(inter.public)))
        val leafDer = cert("leaf", "inter", leaf.public, inter)
        val notCa = cert("inter", "root", inter.public, root)
        chainDenied("the anchor itself must be a CA", chainOf(pinnedInter, std(leafDer), std(notCa)), "x5c chain profile: issuer certificate at depth 1 has no BasicConstraints (not a CA)")
        chainOk("above the anchor", chainOf(pinnedInter, std(leafDer), std(cert("inter", "root", inter.public, root, Kill05JwsKit.CA_BC)), std(leafDer)), leafDer)
    }

    @Test
    fun x5cChainTable() {
        val a = anchors(pins = listOf(pinHex))
        val b = std(certDer)
        chainOk("pinned self-signed", chainOf(a, b), certDer)
        chainDenied("empty chain", chainOf(a), "empty x5c certificate chain")
        chainDenied("non-string entry", chainOf(a, b, 5L), "empty x5c entry at index 1")
        chainDenied("empty entry", chainOf(a, b, b, ""), "empty x5c entry at index 2")
        chainDenied("null entry", chainOf(a, null), "empty x5c entry at index 0")
        chainDenied("malformed entry", chainOf(a, b, "MAA="), "malformed x5c certificate at index 1: error:0680007B:asn1 encoding routines::not enough data")
        // an unreadable configured root fails closed
        chainDenied("unreadable root", chainOf(anchors(pems = listOf("garbage")), b), "x5c chain verification error (fail closed): error:0480006C:PEM routines::no start line")
        // an empty fingerprint is no anchor
        chainDenied("empty fingerprint only", chainOf(anchors(pins = listOf("")), b), "no MAA trust anchor configured (fail closed)")
        chainDenied("nothing configured", chainOf(anchors(), b), "no MAA trust anchor configured (fail closed)")
        chainOk("empty fingerprint next to an upper-case one", chainOf(anchors(pins = listOf("", pinHex.uppercase())), b), certDer)
        // a chain certificate whose key cannot be read fails closed
        val xCert = cert("x", "maa-test", Kill05JwsKit.otherKey("X25519").public, key)
        chainDenied("unreadable chain key", chainOf(a, std(xCert)), "x5c chain verification error (fail closed): " + AttestCert.OSSL_UNSUPPORTED)

        val root = Kill05JwsKit.ecKey("secp256r1")
        val stranger = Kill05JwsKit.ecKey("secp256r1")
        val inter = Kill05JwsKit.ecKey("secp256r1")
        val leaf = Kill05JwsKit.ecKey("secp256r1")
        val rootDer = cert("root", "root", root.public, root, Kill05JwsKit.CA_BC)
        val byRoot = anchors(pems = listOf(pem(rootDer)))
        // the root certificate's key anchors a chain member that carries it (that member's own issuer is not checked)
        val crossSigned = cert("root", "stranger", root.public, stranger, Kill05JwsKit.CA_BC)
        val leafByRoot = cert("leaf", "root", leaf.public, root)
        chainOk("anchored by the root key fingerprint", chainOf(byRoot, std(leafByRoot), std(crossSigned)), leafByRoot)
        // no fingerprint match: every link is checked, then the top against the root certificates
        val interDer = cert("inter", "root", inter.public, root, Kill05JwsKit.CA_BC)
        val leafByInter = cert("leaf", "inter", leaf.public, inter)
        val leafByStranger = cert("leaf", "inter", leaf.public, stranger)
        chainOk("two links to a root certificate", chainOf(byRoot, std(leafByInter), std(interDer)), leafByInter)
        chainOk("leaf signed by a root certificate", chainOf(byRoot, std(leafByRoot)), leafByRoot)
        chainDenied("bad first link", chainOf(byRoot, std(leafByStranger), std(interDer)), "x5c link 0 is not signed by the certificate above it")
        val interByStranger = cert("inter", "root", inter.public, stranger)
        val strangerSelf = cert("stranger", "stranger", stranger.public, stranger)
        chainDenied("top not signed by a root", chainOf(byRoot, std(leafByInter), std(interByStranger)), "x5c chain does not anchor in a configured MAA trust root")
        chainDenied("top not under a root", chainOf(anchors(pems = listOf(pem(strangerSelf))), std(leafByInter), std(interDer)),
            "x5c chain does not anchor in a configured MAA trust root")
        chainDenied("bad second link, unanchored", chainOf(byRoot, std(leafByInter), std(interDer), std(strangerSelf)), "x5c link 1 is not signed by the certificate above it")
        chainDenied("bad second link below the anchor", chainOf(byRoot, std(leafByInter), std(interByStranger), std(rootDer)), "x5c link 1 is not signed by the certificate above it")
        chainOk("anchored at the top", chainOf(byRoot, std(leafByInter), std(interDer), std(rootDer)), leafByInter)
        // with a fingerprint match only the links below the anchor are checked
        val interPinned = anchors(pins = listOf(pin(inter.public)))
        chainOk("anchor in the middle (the link above it is not checked)", chainOf(interPinned, std(leafByInter), std(interDer), std(leafByStranger)), leafByInter)
        chainDenied("bad link below the anchor", chainOf(interPinned, std(leafByStranger), std(interDer)), "x5c link 0 is not signed by the certificate above it")
        // through the verifier: the chain reason is prefixed
        denied("verifier prefix", maa(pinned(tdx), x5cTok(key, null, "MAA=")),
            "MAA signing chain invalid: malformed x5c certificate at index 0: error:0680007B:asn1 encoding routines::not enough data")
        denied("verifier unreadable root", maa(config("""{"rootCertsPem":["garbage"]}""", tdx), tok()),
            "MAA signing chain invalid: x5c chain verification error (fail closed): error:0480006C:PEM routines::no start line")
        ok("verifier anchored by a root certificate", maa(config("""{"rootCertsPem":[${json(pem(rootDer))}]}""", tdx), x5cTok(leaf, null, std(leafByInter), std(interDer))))
    }

    // ---- signature key checks

    @Test
    fun jwsSignatureKeyChecks() {
        fun leafOf(pub: java.security.PublicKey) = AttestCert.parseCertDer(cert("leaf", "maa-test", pub, key))
        val es = AttestJws.parseJwt(signEs256(key, """{"alg":"ES256"}""", "{}"), "t")
        val ecLeaf = leafOf(key.public)
        assertEquals("", AttestMaa.jwsSignature(es, ecLeaf))
        assertEquals("JWS ES256 signature does not verify under the MAA signing key", AttestMaa.jwsSignature(es, leafOf(Kill05JwsKit.ecKey("secp256r1").public)))
        assertEquals("ES256 token but signing key is EC/P-384 (not EC P-256)", AttestMaa.jwsSignature(es, leafOf(Kill05JwsKit.ecKey("secp384r1").public)))
        val rsa = Kill05JwsKit.rsaKey()
        val rsaLeaf = leafOf(rsa.public)
        assertEquals("ES256 token but signing key is RSA/undefined (not EC P-256)", AttestMaa.jwsSignature(es, rsaLeaf))
        assertEquals("ES256 token but signing key is OKP/Ed25519 (not EC P-256)", AttestMaa.jwsSignature(es, leafOf(Kill05JwsKit.otherKey("Ed25519").public)))
        assertEquals("x5c chain verification error (fail closed): " + AttestCert.OSSL_UNSUPPORTED, AttestMaa.jwsSignature(es, leafOf(Kill05JwsKit.otherKey("X25519").public)))
        val short = AttestJws.parseJwt(Kill05JwsKit.seg("""{"alg":"ES256"}""") + "." + Kill05JwsKit.seg("{}") + "." + Kill05JwsKit.b64u(ByteArray(63)), "t")
        assertEquals("ES256 signature is 63 bytes (expected 64: r‖s)", AttestMaa.jwsSignature(short, ecLeaf))
        val rs = AttestJws.parseJwt(Kill05JwsKit.unsignedJwt("""{"alg":"RS256"}""", "{}"), "t")
        assertEquals("RS256 token but signing key is EC (not RSA)", AttestMaa.jwsSignature(rs, ecLeaf))
        assertEquals("JWS RS256 signature does not verify under the MAA signing key", AttestMaa.jwsSignature(rs, rsaLeaf))
        assertEquals("", AttestMaa.jwsSignature(AttestJws.parseJwt(Kill05JwsKit.signRs256(rsa, """{"alg":"RS256"}""", "{}"), "t"), rsaLeaf))
        assertEquals("unsupported JWS alg 'none' (MAA uses ES256 / RS256)", AttestMaa.jwsSignature(AttestJws.parseJwt(Kill05JwsKit.unsignedJwt("""{"alg":"none"}""", "{}"), "t"), ecLeaf))
        // through the verifier
        denied("unsupported alg", maa(pinned(tdx), Kill05JwsKit.unsignedJwt("""{"alg":"ES384"}""", "{}")), "unsupported JWS alg 'ES384' (MAA uses ES256 / RS256)")
        denied("another signer", maa(pinned(tdx), x5cTok(Kill05JwsKit.ecKey("secp256r1"), null, std(certDer))), "JWS ES256 signature does not verify under the MAA signing key")
    }
}
