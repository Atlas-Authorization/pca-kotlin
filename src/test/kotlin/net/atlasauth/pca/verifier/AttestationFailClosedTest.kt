package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Fail-closed tables: every row is "missing / invalid X => exact result", per vendor, plus unit tests of the strict DER rules and
 * signed Google Confidential Space tokens. None of it needs the conformance vector file: the inputs are built here.
 */
@Suppress("UNCHECKED_CAST")
class AttestationFailClosedTest {
    private fun cfg(text: String): Map<String, Any?> = ParityVectors.obj(text)

    private val testBinding = Attest.Binding("holder-key", "passport:abc", 0.0, "nonce-1")
    private val zeros96 = "a".repeat(96)

    @Test
    fun bindingKnownAnswer() {
        assertEquals(
            "a96a474bee436996d639ac056ef40b906991ac6732d192214c9ff400ee7f60597bea43c2cef340b5439bd38ddc63fbf24dd1b2da311650a7e9a8e0bdbc8e16c3",
            AttestUtil.hex(Attest.bindingBytes(Attest.Binding("h", "g", 3.0, "n"))),
        )
        assertEquals(
            "9ea99cfad60fa258d6dd4e6000b34a2ef855ab18b681a6f203dc99bbf8f4dbc2f8c957981a8b26975420e2e621fa53ef7c135d64a620f47bcba6a12966d8feff",
            AttestUtil.hex(Attest.bindingBytes(testBinding)),
        )
        val rows = listOf(
            Pair(Attest.Binding("", "g", 0.0, "n"), "binding: holderPub required"),
            Pair(Attest.Binding("h", "", 0.0, "n"), "binding: grantRef required"),
            Pair(Attest.Binding("h", "g", 0.0, ""), "binding: nonce required"),
            Pair(Attest.Binding("h", "g", -1.0, "n"), "binding: epoch must be a non-negative safe integer"),
            Pair(Attest.Binding("h", "g", 1.5, "n"), "binding: epoch must be a non-negative safe integer"),
            Pair(Attest.Binding("h", "g", 9007199254740992.0, "n"), "binding: epoch must be a non-negative safe integer"),
        )
        for ((b, want) in rows) {
            try {
                Attest.bindingBytes(b)
                fail("binding must be refused: $want")
            } catch (e: IllegalArgumentException) {
                assertEquals(want, e.message)
            }
        }
    }

    @Test
    fun constructRefusals() {
        val m96 = "\"$zeros96\""
        val rows = listOf(
            Triple("amd-sev-snp", """{"family":"rome","binding":"report-data","policy":{"measurements":["aa"]}}""", "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'"),
            Triple("amd-sev-snp", """{"family":"milan","binding":"x","policy":{"measurements":["aa"]}}""", "createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'"),
            Triple("amd-sev-snp", """{"family":"milan","binding":"report-data","policy":{"measurements":[]}}""", "createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)"),
            Triple("amd-sev-snp", """{"family":"milan","binding":"report-data"}""", "createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)"),
            Triple("amd-sev-snp", """{"family":"rome","binding":"report-data","policy":{"measurements":["aa"],"minReportedTcb":"abc"}}""", "Cannot convert abc to a BigInt"),
            Triple("intel-tdx-dcap", """{"binding":"x","policy":{"mrtds":[$m96]}}""", "createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'"),
            Triple("intel-tdx-dcap", """{"binding":"report-data","policy":{}}""", "createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)"),
            Triple("intel-tdx-dcap", """{"binding":"report-data","policy":{"mrtds":["abc"]}}""", "createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)"),
            Triple("intel-tdx-dcap", """{"binding":"report-data","policy":{"mrtds":[$m96],"mrSeams":[]}}""", "createIntelDcapVerifier: policy.mrSeams, if given, must be a NON-EMPTY list"),
            Triple("intel-tdx-dcap", """{"binding":"report-data","policy":{"mrtds":[$m96],"mrSignerSeams":["zz"]}}""", "createIntelDcapVerifier: every mrSignerSeams entry must be 96 hex chars (48 bytes)"),
            Triple("azure-maa", "{}", "createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs"),
            Triple("azure-maa", """{"trustedIssuers":[""]}""", "createAzureMaaVerifier: every trusted issuer must be a non-empty URL string"),
            Triple("azure-maa", """{"trustedIssuers":["https://i"]}""", "createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted"),
            Triple("azure-maa", """{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]}}""", "createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)"),
            Triple("azure-maa", """{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"sevSnpMeasurements":["aa"],"sevSnpMinTcb":{"bogus":1}}}""", "createAzureMaaVerifier: policy.sevSnpMinTcb.bogus is not a known field (bootloader | snp | microcode | tee)"),
            Triple("azure-maa", """{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"sevSnpMeasurements":["aa"],"sevSnpMinTcb":{"snp":-1}}}""", "createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer"),
            Triple("gcp-confidential-space", "{}", "createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs"),
            Triple("gcp-confidential-space", """{"trustedIssuers":["https://i"]}""", "createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted"),
            Triple("gcp-confidential-space", """{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{}}""", "createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)"),
            Triple("gcp-confidential-space", """{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"],"allowedTeeTypes":[]}}""", "createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty"),
            Triple("nvidia-gpu-spdm", "{}", "createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)"),
            Triple("nvidia-gpu-spdm", """{"rootSpkiSha256":["aa"]}""", "createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)"),
            Triple("nvidia-gpu-spdm", """{"rootSpkiSha256":["aa"],"policy":{"measurements":{"256":"aa"}}}""", "createNvidiaSpdmVerifier: measurement index out of range"),
            Triple("nvidia-gpu-spdm", """{"rootSpkiSha256":["aa"],"collateral":{}}""", "nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root"),
            Triple("nvidia-gpu-spdm", """{"rootSpkiSha256":["aa"],"collateral":{"rimRootSpkiSha256":["aa"],"firmware":{"minDriverVersion":"x"}}}""", "nvidiaCollateralHook: malformed minDriverVersion 'x'"),
        )
        for ((vendor, c, want) in rows) {
            try {
                Attest.verifierFromConfig(vendor, cfg(c))
                fail("$vendor $c must be refused")
            } catch (e: IllegalArgumentException) {
                assertEquals("$vendor $c", want, e.message)
            }
        }
        try {
            Attest.verifierFromConfig("no-such-vendor", LinkedHashMap())
            fail("an unknown vendor must be refused")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("no-such-vendor"))
        }
        val okRows = listOf(
            Pair("amd-sev-snp", """{"family":"genoa","binding":"azure-runtime-data","policy":{"measurements":["aa"],"minReportedTcb":"18446744073709551615"}}"""),
            Pair("intel-tdx-dcap", """{"binding":"report-data","policy":{"mrtds":[$m96],"mrSeams":[$m96]}}"""),
            Pair("azure-maa", """{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"],"sevSnpMinTcb":{"snp":3}}}"""),
            Pair("gcp-confidential-space", """{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}"""),
            Pair("nvidia-gpu-spdm", """{"rootSpkiSha256":["aa"],"collateral":{"rimRootSpkiSha256":["aa"]}}"""),
        )
        for ((vendor, c) in okRows) assertNotNull(vendor, Attest.verifierFromConfig(vendor, cfg(c)))
    }

    private fun b64u(s: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(Charsets.UTF_8))
    private fun unsignedJwt(header: String, payload: String) = b64u(header) + "." + b64u(payload) + ".AA"
    private fun std(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

    private class Case(val name: String, val vendor: String, val cfg: String, val ev: Map<String, Any?>?, val expected: Attest.Binding?, val want: String, val prefix: Boolean = false)

    @Test
    fun noEvidenceAndBadEvidence() {
        val badQuote = ByteArray(700)
        badQuote[0] = 4; badQuote[2] = 2; badQuote[4] = 0x81.toByte()
        badQuote[632] = 0xff.toByte(); badQuote[633] = 0xff.toByte() // signature data length 65535
        val snp1184 = ByteArray(1184)
        val snp1184Reserved = ByteArray(1184)
        snp1184Reserved[900] = 1
        val amd = """{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]}}"""
        val dcap = """{"binding":"report-data","policy":{"mrtds":["$zeros96"]}}"""
        val maa = """{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]}}"""
        val gcp = """{"trustedIssuers":["https://i"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["sha256:x"]}}"""
        val nv = """{"rootSpkiSha256":["aa"],"policy":{"measurements":{"1":"aa"}}}"""
        fun ev(vararg kv: Pair<String, Any?>): Map<String, Any?> = linkedMapOf(*kv)
        val shortAmd = ev("report" to "AA==", "vcekDer" to "AA==", "askArkPem" to "x")
        val cases = listOf(
            Case("amd nil evidence", "amd-sev-snp", amd, null, testBinding, "no AMD SEV-SNP evidence for this action"),
            Case("amd empty evidence", "amd-sev-snp", amd, emptyMap(), testBinding, "no AMD SEV-SNP evidence for this action"),
            Case("amd no binding", "amd-sev-snp", amd, shortAmd, null, "no expected attestation binding supplied"),
            Case("amd short report", "amd-sev-snp", amd, shortAmd, testBinding, "SEV-SNP report invalid: report parse failed: parseSevSnpReport: report too short (1 < 816)"),
            Case("amd non-canonical length", "amd-sev-snp", amd, ev("report" to std(ByteArray(1000)), "vcekDer" to "AA==", "askArkPem" to "x"), testBinding, "SEV-SNP report invalid: report length 1000 is not the canonical 1184"),
            Case("amd reserved bytes", "amd-sev-snp", amd, ev("report" to std(snp1184Reserved), "vcekDer" to "AA==", "askArkPem" to "x"), testBinding, "SEV-SNP report invalid: report signature block has non-zero reserved bytes"),
            Case("amd garbage VCEK", "amd-sev-snp", amd, ev("report" to std(snp1184), "vcekDer" to "AA==", "askArkPem" to "x"), testBinding, "SEV-SNP report invalid: cert chain invalid: AMD chain verification error: ", true),
            Case("amd negative skew", "amd-sev-snp", """{"family":"milan","binding":"report-data","policy":{"measurements":["aa"]},"clockSkewMs":-1}""", ev("report" to std(snp1184), "vcekDer" to "AA==", "askArkPem" to "x"), testBinding, "SEV-SNP report invalid: cert chain invalid: clockSkewMs must be a non-negative number"),
            Case("amd azure mode needs runtime data", "amd-sev-snp", """{"family":"milan","binding":"azure-runtime-data","policy":{"measurements":["aa"]}}""", null, testBinding, "no AMD SEV-SNP evidence for this action"),

            Case("dcap nil evidence", "intel-tdx-dcap", dcap, null, testBinding, "no Intel DCAP quote for this action"),
            Case("dcap no binding", "intel-tdx-dcap", dcap, ev("quote" to "AA=="), null, "no expected attestation binding supplied"),
            Case("dcap short quote", "intel-tdx-dcap", dcap, ev("quote" to "AA=="), testBinding, "DCAP quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length"),
            Case("dcap version 0", "intel-tdx-dcap", dcap, ev("quote" to std(ByteArray(700))), testBinding, "DCAP quote invalid: quote parse failed: parseDcapQuote: unsupported quote version 0 (expected 4)"),
            Case("dcap signature data overruns", "intel-tdx-dcap", dcap, ev("quote" to std(badQuote)), testBinding, "DCAP quote invalid: quote parse failed: parseDcapQuote: signature data (65535) overruns the quote"),

            Case("maa nil evidence", "azure-maa", maa, null, testBinding, "no Azure MAA token for this action"),
            Case("maa not a JWS", "azure-maa", maa, ev("token" to "x"), testBinding, "MAA token parse failed: parseMaaJwt: a compact JWS has exactly three dot-separated parts"),
            Case("maa non-canonical header", "azure-maa", maa, ev("token" to "a.b.c"), testBinding, "MAA token parse failed: parseMaaJwt: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url (impossible length)"),
            Case("maa alg none", "azure-maa", maa, ev("token" to unsignedJwt("""{"alg":"none"}""", "{}")), testBinding, "unsupported JWS alg 'none' (MAA uses ES256 / RS256)"),
            Case("maa no signing chain", "azure-maa", maa, ev("token" to unsignedJwt("""{"alg":"ES256"}""", "{}")), testBinding, "no signing x5c available (no JWKS and no header x5c)"),
            Case(
                "maa kid matches nothing", "azure-maa", maa,
                ev("token" to unsignedJwt("""{"alg":"ES256","kid":"zz"}""", "{}"), "jwks" to ParityVectors.parse("""{"keys":[{"kid":"other","x5c":["AA=="]}]}""")),
                testBinding, "no JWKS key matches the token kid 'zz' (untrusted signer)",
            ),

            Case("gcp nil evidence", "gcp-confidential-space", gcp, null, testBinding, "no GCP Confidential Space token for this action"),
            Case("gcp alg none", "gcp-confidential-space", gcp, ev("token" to unsignedJwt("""{"alg":"none"}""", "{}")), testBinding, "unsupported JWS alg 'none' (Confidential Space uses RS256)"),
            Case("gcp no kid, no key", "gcp-confidential-space", gcp, ev("token" to unsignedJwt("""{"alg":"ES256"}""", "{}")), testBinding, "Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available"),
            Case("gcp unknown kid", "gcp-confidential-space", gcp, ev("token" to unsignedJwt("""{"alg":"ES256","kid":"zz"}""", "{}")), testBinding, "Confidential Space signing key invalid: no JWKS key matches the token kid 'zz' (untrusted signer)"),

            Case("nvidia nil evidence", "nvidia-gpu-spdm", nv, null, testBinding, "no NVIDIA GPU evidence for this action"),
            Case("nvidia empty chain", "nvidia-gpu-spdm", nv, ev("evidence" to "AA==", "certChainPem" to ""), testBinding, "device chain unparseable: parsePemChain: no certificates found"),
        )
        for (c in cases) {
            val ver = Attest.verifierFromConfig(c.vendor, cfg(c.cfg))
            val r = ver.verify(c.ev, c.expected, 1_800_000_000_000L)
            assertTrue("${c.name}: must be a plain denial", !r.ok && !r.bound && r.measured == null && r.hostAsserted == null)
            if (c.prefix) assertTrue("${c.name}: '${r.reason}'", r.reason.startsWith(c.want)) else assertEquals(c.name, c.want, r.reason)
        }
    }

    // ---- signed tokens (Google Confidential Space) ----

    private val gcpIssuer = "https://confidentialcomputing.googleapis.com"
    private val tokNow = 1_800_000_000_000L

    private fun newKey() = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun signEs256(key: java.security.KeyPair, header: String, payload: String): String {
        val input = b64u(header) + "." + b64u(payload)
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(key.private)
        s.update(input.toByteArray(Charsets.UTF_8))
        val der = s.sign()
        // DER ECDSA-Sig-Value -> raw r||s
        var p = 2
        if ((der[1].toInt() and 0x80) != 0) p = 3
        val rl = der[p + 1].toInt() and 0xff
        val r = BigInteger(1, der.copyOfRange(p + 2, p + 2 + rl))
        val sl = der[p + 2 + rl + 1].toInt() and 0xff
        val sv = BigInteger(1, der.copyOfRange(p + 2 + rl + 2, p + 2 + rl + 2 + sl))
        val raw = ByteArray(64)
        val rb = r.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        val sb = sv.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        System.arraycopy(rb, 0, raw, 32 - rb.size, rb.size)
        System.arraycopy(sb, 0, raw, 64 - sb.size, sb.size)
        return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val b = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        val out = ByteArray(32)
        System.arraycopy(b, 0, out, 32 - b.size, b.size)
        return out
    }

    private fun jwkOf(key: java.security.KeyPair, kid: String): Map<String, Any?> {
        val w = (key.public as ECPublicKey).w
        val enc = Base64.getUrlEncoder().withoutPadding()
        return linkedMapOf("kid" to kid, "kty" to "EC", "crv" to "P-256", "x" to enc.encodeToString(fixed32(w.affineX)), "y" to enc.encodeToString(fixed32(w.affineY)))
    }

    @Test
    fun gcpConfidentialSpaceSignedTokens() {
        val key = newKey()
        val other = newKey()
        val nowSec = tokNow / 1000
        val bindingB64 = std(Attest.bindingBytes(testBinding))
        fun claims(mut: (MutableMap<String, Any?>) -> Unit): String {
            val m = LinkedHashMap<String, Any?>()
            m["iss"] = gcpIssuer
            m["exp"] = IntentJs.ofLong(nowSec + 3600)
            m["iat"] = IntentJs.ofLong(nowSec - 60)
            m["nbf"] = IntentJs.ofLong(nowSec - 60)
            m["swname"] = "CONFIDENTIAL_SPACE"
            m["swversion"] = arrayListOf<Any?>("240500")
            m["hwmodel"] = "GCP_AMD_SEV"
            m["dbgstat"] = "disabled-since-boot"
            m["eat_nonce"] = arrayListOf<Any?>(bindingB64)
            m["submods"] = linkedMapOf<String, Any?>(
                "confidential_space" to linkedMapOf<String, Any?>("support_attributes" to ArrayList<Any?>()),
                "container" to linkedMapOf<String, Any?>("image_digest" to "sha256:ABC", "image_reference" to "r/i@sha256:abc"),
            )
            mut(m)
            return Json.canonicalize(m)
        }
        val hdr = """{"alg":"ES256","kid":"k1"}"""
        fun config(policy: String): Map<String, Any?> {
            val c = LinkedHashMap(cfg("""{"trustedIssuers":["$gcpIssuer"],"trustAnchors":{},"policy":$policy}"""))
            c["trustAnchors"] = linkedMapOf<String, Any?>("trustedJwks" to linkedMapOf<String, Any?>("keys" to arrayListOf<Any?>(jwkOf(key, "k1"))))
            return c
        }
        fun run(c: Map<String, Any?>, token: String, b: Attest.Binding?, now: Long): Attest.Result =
            Attest.verifierFromConfig("gcp-confidential-space", c).verify(linkedMapOf("token" to token), b, now)
        val good = signEs256(key, hdr, claims { })
        val r = run(config("""{"imageDigests":["sha256:abc"]}"""), good, testBinding, tokNow)
        assertTrue(r.reason, r.ok && r.bound)
        assertEquals("sha256:ABC", r.measured!!["runtime_measurement"])
        assertEquals(false, r.measured!!["weights_measured"])
        val wantHost = mapOf("attestation_type" to "sev-snp", "hwmodel" to "GCP_AMD_SEV", "image_digest" to "sha256:ABC", "image_reference" to "r/i@sha256:abc")
        assertEquals(wantHost, r.hostAsserted)
        val relay = Attest.Binding(testBinding.holderPub, testBinding.grantRef, testBinding.epoch, "nonce-2")
        val ok = """{"imageDigests":["sha256:abc"]}"""
        class Row(val name: String, val c: Map<String, Any?>, val token: String, val b: Attest.Binding?, val now: Long, val want: String)
        val rows = listOf(
            Row("relayed nonce", config(ok), good, relay, tokNow, "eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)"),
            Row("image not allowed", config("""{"imageDigests":["sha256:other"]}"""), good, testBinding, tokNow, "workload image_digest not in policy allowlist"),
            Row("expired token", config(ok), good, testBinding, tokNow + 4_000_000, "Confidential Space token expired"),
            Row("not yet valid", config(ok), good, testBinding, tokNow - 600_000, "Confidential Space token not yet valid (nbf)"),
            Row("another signer", config(ok), signEs256(other, hdr, claims { }), testBinding, tokNow, "JWS ES256 signature does not verify under the Confidential Space signing key"),
            Row("issuer not configured", config(ok), signEs256(key, hdr, claims { it["iss"] = "https://other" }), testBinding, tokNow, "token iss 'https://other' is not a configured trusted Google attestation issuer"),
            Row("debug build", config(ok), signEs256(key, hdr, claims { it["dbgstat"] = "enabled" }), testBinding, tokNow, "token dbgstat 'enabled' is not 'disabled-since-boot' (debug build — no confidentiality)"),
            Row("wrong software", config(ok), signEs256(key, hdr, claims { it["swname"] = "OTHER" }), testBinding, tokNow, "unexpected swname 'OTHER' (expected 'CONFIDENTIAL_SPACE')"),
            Row("tee type pinned away", config("""{"imageDigests":["sha256:abc"],"allowedTeeTypes":["tdx"]}"""), good, testBinding, tokNow, "attestation type 'sev-snp' (hwmodel 'GCP_AMD_SEV') is not in the policy allowlist"),
            Row("unknown hardware model", config(ok), signEs256(key, hdr, claims { it["hwmodel"] = "SOMETHING" }), testBinding, tokNow, "unrecognized hwmodel 'SOMETHING' (not a known AMD SEV-SNP / Intel TDX model)"),
            Row("no nonce claim", config(ok), signEs256(key, hdr, claims { it.remove("eat_nonce") }), testBinding, tokNow, "token carries no eat_nonce claim to bind the PCA challenge"),
            Row("no exp", config(ok), signEs256(key, hdr, claims { it.remove("exp") }), testBinding, tokNow, "token has no exp (cannot bound validity — fail closed)"),
            Row("swversion not allowed", config("""{"imageDigests":["sha256:abc"],"allowedSwVersions":["1"]}"""), good, testBinding, tokNow, "swversion not in policy allowlist"),
            Row("binding not constructible", config(ok), good, Attest.Binding("", "g", 0.0, "n"), tokNow, "binding not constructible: binding: holderPub required"),
            Row("no expected binding", config(ok), good, null, tokNow, "no expected attestation binding supplied"),
        )
        for (c in rows) {
            val got = run(c.c, c.token, c.b, c.now)
            assertFalse("${c.name}: ${got.reason}", got.ok)
            assertEquals(c.name, c.want, got.reason)
        }
        // the nonce hash option binds H(binding)
        val hashed = signEs256(key, hdr, claims { it["eat_nonce"] = std(AttestUtil.sha256(Attest.bindingBytes(testBinding))) })
        val r2 = run(config("""{"imageDigests":["sha256:abc"],"nonceHash":"sha256"}"""), hashed, testBinding, tokNow)
        assertTrue(r2.reason, r2.ok)
    }

    // ---- strict DER ----

    private fun tlv(tag: Int, vararg content: ByteArray): ByteArray {
        var body = ByteArray(0)
        for (c in content) body += c
        val hdr = when {
            body.size < 0x80 -> byteArrayOf(tag.toByte(), body.size.toByte())
            body.size < 0x100 -> byteArrayOf(tag.toByte(), 0x81.toByte(), body.size.toByte())
            else -> byteArrayOf(tag.toByte(), 0x82.toByte(), (body.size shr 8).toByte(), body.size.toByte())
        }
        return hdr + body
    }

    private fun bytes(vararg v: Int): ByteArray = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun strictDerLengths() {
        val rows = listOf(
            Pair(bytes(0x1f, 0x01, 0x00), "DER: multi-byte tags are not supported"),
            Pair(bytes(0x30, 0x80, 0x00, 0x00), "DER: unsupported length form"),
            Pair(bytes(0x30, 0x84, 0, 0, 0, 1, 0), "DER: unsupported length form"),
            Pair(bytes(0x04, 0x81, 0x05, 1, 2, 3, 4, 5), "DER: non-minimal length (long form below 128)"),
            Pair(bytes(0x04, 0x82, 0x00, 0x90), "DER: non-minimal length (leading zero)"),
            Pair(bytes(0x04, 0x82, 0x01), "DER: truncated length"),
            Pair(bytes(0x04, 0x05, 1), "DER: element overruns its parent"),
            Pair(bytes(0x04), "DER: truncated header"),
        )
        for ((input, want) in rows) {
            try {
                AttestDer.readTlvStrict(input, 0, input.size)
                fail("must be refused: $want")
            } catch (e: AttErr) {
                assertEquals(want, e.message)
            }
        }
        try {
            AttestDer.readTlvStrict(bytes(0x04, 0x81, 0x80), 0, 3)
            fail("a long form carrying 128 over a 1-byte body must overrun")
        } catch (e: AttErr) {
            assertEquals("DER: element overruns its parent", e.message)
        }
        val tl = AttestDer.readTlvStrict(bytes(0x04, 0x81, 200) + ByteArray(200), 0, 203)
        assertEquals(3, tl.start)
        assertEquals(203, tl.end)
    }

    @Test
    fun strictExtensionTable() {
        val bcOid = bytes(0x06, 0x03, 0x55, 0x1d, 0x13)
        fun ext(critical: ByteArray?, value: ByteArray, trailing: ByteArray? = null): ByteArray {
            val parts = ArrayList<ByteArray>()
            parts.add(bcOid)
            if (critical != null) parts.add(critical)
            parts.add(tlv(0x04, value))
            if (trailing != null) parts.add(trailing)
            return tlv(0x30, *parts.toTypedArray())
        }
        fun tbs(vararg exts: ByteArray): ByteArray = tlv(0x30, tlv(0x02, bytes(1)), tlv(0xa3, tlv(0x30, *exts)))
        val trueDer = bytes(0x01, 0x01, 0xff)
        val v = bytes(0x30, 0x00)
        val tbl = AttestDer.parseTbsExtensions(tbs(ext(trueDer, v)))
        assertEquals(listOf("2.5.29.19"), tbl.oids)
        assertTrue(tbl.m.getValue("2.5.29.19").critical)
        assertEquals("3000", AttestUtil.hex(tbl.m.getValue("2.5.29.19").value))
        val rows = listOf(
            Pair(tbs(ext(bytes(0x01, 0x01, 0x01), v)), "extension 2.5.29.19 has a non-DER critical flag"),
            Pair(tbs(ext(bytes(0x01, 0x01, 0x00), v)), "extension 2.5.29.19 has a non-DER critical flag"),
            Pair(tbs(ext(trueDer, v), ext(null, v)), "duplicate extension 2.5.29.19"),
            Pair(tbs(), "empty Extensions SEQUENCE"),
            Pair(tbs(ext(trueDer, v, bytes(0x00))), "extension 2.5.29.19 has trailing bytes"),
            Pair(tbs(ext(trueDer, v)) + bytes(0x00), "trailing bytes after tbsCertificate"),
            Pair(tlv(0x30, tlv(0xa3, tlv(0x30, ext(null, v))), tlv(0xa3, tlv(0x30, ext(null, v)))), "duplicate [3] extensions block"),
            Pair(tlv(0x30, tlv(0xa3, tlv(0x30, ext(null, v))), tlv(0x02, bytes(1))), "extensions block is not the last TBS element"),
            Pair(tlv(0x30, tlv(0xa3, tlv(0x30, tlv(0x30, bytes(0x06, 0x03, 0x80, 0x1d, 0x13), tlv(0x04, v))))), "extension OID has a non-minimal arc"),
            Pair(tlv(0x30, tlv(0xa3, tlv(0x30, tlv(0x30, bytes(0x06, 0x02, 0x55, 0x9d), tlv(0x04, v))))), "extension OID is truncated"),
            Pair(tlv(0x30, tlv(0xa3, tlv(0x30, tlv(0x30, bcOid, tlv(0x02, bytes(1)))))), "extension 2.5.29.19 value is not an OCTET STRING"),
        )
        for ((input, want) in rows) {
            try {
                AttestDer.parseTbsExtensions(input)
                fail("must be refused: $want")
            } catch (e: AttErr) {
                assertEquals(want, e.message)
            }
        }
    }

    @Test
    fun strictDerTime() {
        class Row(val tag: Int, val text: String, val ms: Long, val ok: Boolean)
        val rows = listOf(
            Row(0x17, "250101000000Z", 1735689600000L, true), Row(0x17, "251231235959Z", 1767225599000L, true),
            Row(0x17, "500101000000Z", -631152000000L, true), Row(0x17, "490101000000Z", 2493072000000L, true),
            Row(0x18, "20250101000000Z", 1735689600000L, true), Row(0x17, "250230000000Z", 0, false),
            Row(0x17, "250101000060Z", 0, false), Row(0x17, "251301000000Z", 0, false), Row(0x17, "250101240000Z", 0, false),
            Row(0x17, "2501010000Z", 0, false), Row(0x17, "250101000000+0100", 0, false), Row(0x17, "25010100000AZ", 0, false),
            Row(0x18, "20250101000000.5Z", 0, false), Row(0x18, "250101000000Z", 0, false), Row(0x16, "250101000000Z", 0, false),
        )
        for (r in rows) {
            val got = AttestDer.parseDerTime(r.tag, r.text)
            assertEquals("${r.tag} ${r.text}", r.ok, got.ok)
            if (r.ok) assertEquals("${r.tag} ${r.text}", r.ms, got.ms)
        }
    }

    @Test
    fun smallHelpers() {
        assertEquals("96.00.9f.00.04", AttestNvidia.formatVbiosVersion(bytes(0x00, 0x9f, 0x00, 0x96, 0x04, 0xcc, 0xbb, 0xaa)))
        val rows = listOf(
            Pair("AAEC", "000102"), Pair("AAE=", "0001"), Pair("AA==", "00"), Pair("AA", "00"), Pair("A A\nE C", "000102"),
            Pair("-_8=", "fbff"), Pair("+/8=", "fbff"), Pair("AA==AAEC", "00"), Pair("", ""),
        )
        for ((input, want) in rows) assertEquals(input, want, AttestUtil.hex(AttestUtil.nodeB64(input)))
    }

    @Test
    fun ecdsaDerSignaturesAreParsedStrictly() {
        val key = newKey()
        val digest = AttestUtil.sha256("msg".toByteArray())
        val s = Signature.getInstance("NONEwithECDSA")
        s.initSign(key.private)
        s.update(digest)
        val der = s.sign()
        val pub = key.public as ECPublicKey
        assertTrue(AttestUtil.verifyDerEcdsa(pub, digest, der))
        assertFalse("trailing byte", AttestUtil.verifyDerEcdsa(pub, digest, der + bytes(0)))
        assertFalse("truncated", AttestUtil.verifyDerEcdsa(pub, digest, der.copyOfRange(0, der.size - 1)))
        assertFalse("empty", AttestUtil.verifyDerEcdsa(pub, digest, ByteArray(0)))
        val other = AttestUtil.sha256("other".toByteArray())
        assertFalse("another digest", AttestUtil.verifyDerEcdsa(pub, other, der))
        assertNull(AttestUtil.pointToKey("secp256r1", ByteArray(65))) // not on the curve
    }

    private fun spdmReport(reqVer: Int, respVer: Int): AttestNvidia.Report {
        val b = ByteArray(37 + 8 + 32 + 2 + 96)
        b[0] = reqVer.toByte(); b[1] = 0xe0.toByte(); b[37] = respVer.toByte(); b[38] = 0x60
        return AttestNvidia.parseSpdmEvidence(b)
    }

    @Test
    fun nvidiaSpdmVersionMustBeAtLeast11AndAgree() {
        assertNull(AttestNvidia.versionProblem(spdmReport(0x11, 0x11)))
        assertNull(AttestNvidia.versionProblem(spdmReport(0x12, 0x12)))
        assertEquals("SPDM version 0x10/0x10 is not an accepted GET_MEASUREMENTS version", AttestNvidia.versionProblem(spdmReport(0x10, 0x10)))
        assertEquals("SPDM version 0x11/0x12 is not an accepted GET_MEASUREMENTS version", AttestNvidia.versionProblem(spdmReport(0x11, 0x12)))
        assertEquals("SPDM version 0x12/0x11 is not an accepted GET_MEASUREMENTS version", AttestNvidia.versionProblem(spdmReport(0x12, 0x11)))
    }
}
