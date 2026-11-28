package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** The public vendor names: constants, constructors, wire parsers, the P-256 key wrapper and the JWKS fetchers over a fake transport. */
@Suppress("UNCHECKED_CAST")
class AttestVendorsTest {
    private fun quote(): ByteArray {
        val pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".toByteArray(Charsets.ISO_8859_1)
        val auth = ByteArray(8) { 7 }
        val outer = 384 + 64 + 2 + auth.size + 6 + pem.size
        val sigData = 64 + 64 + 6 + outer
        val b = ByteBuffer.allocate(48 + 584 + 4 + sigData).order(ByteOrder.LITTLE_ENDIAN)
        b.putShort(0, 4).putShort(2, 2).putInt(4, 0x81)
        b.position(48 + 584)
        b.putInt(sigData)
        b.put(ByteArray(64) { 1 }).put(ByteArray(64) { 2 })
        b.putShort(6).putInt(outer)
        b.put(ByteArray(384) { 3 }).put(ByteArray(64) { 4 })
        b.putShort(auth.size.toShort()).put(auth)
        b.putShort(5).putInt(pem.size).put(pem)
        return b.array()
    }

    @Test fun theDcapQuoteAndTdReportParse() {
        val p = AttestVendors.parseDcapQuote(quote())
        assertEquals(4.0, IntentJs.num(p["version"])!!, 0.0)
        assertEquals(2.0, IntentJs.num(p["attKeyType"])!!, 0.0)
        assertEquals(129.0, IntentJs.num(p["teeType"])!!, 0.0)
        assertEquals(584, (p["tdReportBody"] as ByteArray).size)
        assertArrayEquals(ByteArray(64) { 2 }, p["akPubRaw"] as ByteArray)
        assertTrue((p["pckChainPem"] as String).startsWith("-----BEGIN CERTIFICATE-----"))
        try { AttestVendors.parseDcapQuote(ByteArray(10)); fail() } catch (e: IllegalArgumentException) { assertTrue(e.message!!.startsWith("parseDcapQuote:")) }

        val body = ByteArray(584) { (it % 251).toByte() }
        val td = AttestVendors.parseDcapTdReport(body)
        assertArrayEquals(body.copyOfRange(136, 184), td["mrTd"] as ByteArray)
        assertArrayEquals(body.copyOfRange(520, 584), td["reportData"] as ByteArray)
        try { AttestVendors.parseDcapTdReport(ByteArray(583)); fail() } catch (e: IllegalArgumentException) { assertEquals("parseDcapTdReport: body too short (583 < 584)", e.message) }
    }

    @Test fun aP256KeyIsWrappedAsTheUncompressedPoint() {
        val kp = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val w = (kp.public as ECPublicKey).w
        fun fixed(v: java.math.BigInteger) = v.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else ByteArray(32 - it.size) + it }
        val uncompressed = byteArrayOf(4) + fixed(w.affineX) + fixed(w.affineY)
        assertArrayEquals(uncompressed, AttestVendors.ecdsaP256PublicKey(uncompressed).point)
        val compressed = org.bouncycastle.asn1.nist.NISTNamedCurves.getByName("P-256").curve.decodePoint(uncompressed).getEncoded(true)
        assertArrayEquals(uncompressed, AttestVendors.ecdsaP256PublicKey(compressed).point)
        val off = uncompressed.copyOf().also { it[64] = (it[64] + 1).toByte() }
        try { AttestVendors.ecdsaP256PublicKey(off); fail("off-curve") } catch (e: IllegalArgumentException) { /* refused */ }
    }

    @Test fun smallHelpers() {
        assertTrue(AttestVendors.serialIsRevoked(setOf("1a2b"), "001A2B"))
        assertFalse(AttestVendors.serialIsRevoked(setOf("1a2b"), "1a2c"))
        assertEquals("-----BEGIN-----\n+x", AttestVendors.decodeIssuerChainHeader("-----BEGIN-----%0A+x"))
        assertEquals("sev-snp", AttestVendors.teeTypeOfHwModel("GCP_AMD_SEV_SNP"))
        assertEquals("tdx", AttestVendors.teeTypeOfHwModel("gcp_intel_tdx"))
        assertNull(AttestVendors.teeTypeOfHwModel("OTHER"))
        assertEquals(listOf("milan", "genoa", "turin"), AttestVendors.AMD_ARK_SPKI_SHA384.keys.toList())
        assertEquals(AttestIntel.SGX_ROOT_CA_SPKI_SHA256, AttestVendors.INTEL_SGX_ROOT_CA_SPKI_SHA256)
    }

    private fun seg(o: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(o.toByteArray())

    @Test fun jwtTokensParseWithoutVerifying() {
        val token = seg("""{"alg":"ES256","kid":"k1"}""") + "." + seg("""{"iss":"x"}""") + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(64) { 5 })
        val p = AttestVendors.parseMaaJwt(token)
        assertEquals("ES256", (p["header"] as Map<String, Any?>)["alg"])
        assertEquals("k1", (p["header"] as Map<String, Any?>)["kid"])
        assertEquals(64, (p["signature"] as ByteArray).size)
        assertEquals(token.substringBeforeLast('.'), String(p["signingInput"] as ByteArray))
        try { AttestVendors.parseGcpCsJwt("a.b"); fail() } catch (e: IllegalArgumentException) { assertTrue(e.message!!.startsWith("parseGcpCsJwt:")) }
    }

    @Test fun jwksFetchersUseTheInjectedTransport() {
        val seen = ArrayList<String>()
        val fetch = AttestMaaKeys.MaaFetch { url ->
            seen.add(url)
            val body = if (url.endsWith("openid-configuration")) """{"jwks_uri":"https://g.example/keys"}""" else """{"keys":[{"kid":"a","kty":"RSA","n":"n1","e":"AQAB","junk":1},"skip",{"x5c":["QQ=="]}]}"""
            AttestMaaKeys.MaaHttpResponse(200, body.toByteArray())
        }
        val g = AttestVendors.fetchGcpConfidentialSpaceJwks("https://confidentialcomputing.googleapis.com/", fetch)
        assertEquals(listOf("https://confidentialcomputing.googleapis.com/.well-known/openid-configuration", "https://g.example/keys"), seen)
        val keys = g["keys"] as List<Map<String, Any?>>
        assertEquals(2, keys.size)
        assertEquals(setOf("kid", "kty", "n", "e"), keys[0].keys)
        val m = AttestVendors.fetchMaaJwks("https://m.example/", fetch)
        assertEquals("https://m.example/certs", seen.last())
        assertEquals(listOf("QQ=="), ((m["keys"] as List<Map<String, Any?>>)[1])["x5c"])
        try { AttestVendors.fetchMaaJwks("https://m.example", { AttestMaaKeys.MaaHttpResponse(500, ByteArray(0)) }); fail() } catch (e: IllegalStateException) { assertTrue(e.message!!.contains("HTTP 500")) }
    }

    @Test fun theConstructorsAreTheVendorVerifiers() {
        assertEquals("amd-sev-snp", AttestVendors.createAmdSnpVerifier(mapOf("family" to "milan", "binding" to "report-data", "policy" to mapOf("measurements" to listOf("aa")))).vendor)
        assertEquals("amd-sev-snp-ecdsa-p384", AttestVendors.AMD_SNP_SUITE)
        assertEquals(listOf("ES256", "RS256"), AttestVendors.AZURE_MAA_SUITES)
        try { AttestVendors.createAmdSnpVerifier(mapOf("family" to "milan")); fail("a verifier needs its binding and an allowlist") } catch (e: IllegalArgumentException) { /* refused */ }
        assertTrue(AttestVendors.createMemoryMaaKeyStateStore().snapshot().isEmpty())
    }
}
