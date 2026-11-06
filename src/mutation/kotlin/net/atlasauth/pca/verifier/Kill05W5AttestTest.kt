package net.atlasauth.pca.verifier

import java.security.Signature
import java.security.interfaces.ECPublicKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Kills for the attestation survivors of full run 42070352941. */
class Kill05W5AttestTest {
    private val cert = Kill05CertKit
    private val jws = Kill05JwsKit

    /** A Kotlin `when` over strings switches on hashCode, then checks equals: each name below has the hashCode of a real vendor. */
    @Test
    fun vendorMatchesTheWholeName() {
        val cases = listOf(
            "amd-sev-snp" to "bNd-sev-snp",
            "intel-tdx-dcap" to "jOtel-tdx-dcap",
            "azure-maa" to "b[ure-maa",
            "gcp-confidential-space" to "hDp-confidential-space",
            "nvidia-gpu-spdm" to "oWidia-gpu-spdm",
        )
        for ((real, fake) in cases) {
            assertEquals(real.hashCode(), fake.hashCode())
            try {
                Attest.verifierFromConfig(fake, null)
                fail(fake)
            } catch (e: IllegalArgumentException) {
                assertEquals("unknown attestation vendor \"$fake\"", e.message)
            }
        }
    }

    /** A policy map that refuses a null key (Hashtable) is valid configuration: only the three named floors are looked up. */
    @Test
    fun amdFloorLookupAsksOnlyForTheNamedFloors() {
        val pol = java.util.Hashtable<String, Any?>()
        pol["measurements"] = listOf("ab".repeat(48))
        assertEquals("amd-sev-snp", Attest.verifierFromConfig("amd-sev-snp", mapOf("family" to "milan", "binding" to "report-data", "policy" to pol)).vendor)
    }

    /** es256Ok reads the key's type from the key object, not from what the CertKey claims about its curve. */
    @Test
    fun es256RefusesANonEcKeyLabelledP256() {
        val k = AttestCert.CertKey(cert.rsa.public, "ec", "prime256v1", ByteArray(0))
        assertFalse(AttestJws.es256Ok(ByteArray(64), byteArrayOf(1), k))
    }

    /** An algorithm of the right family without a known hash (SHA-224, SHA-1) is false, with no attempt to run it. */
    @Test
    fun unknownSignatureAlgorithmIsFalse() {
        val ec = AttestCert.keyInfoOf(cert.p256.public, ByteArray(0))
        val rsa = AttestCert.keyInfoOf(cert.rsa.public, ByteArray(0))
        assertFalse(AttestCert.certSigOkUnchecked(cert.signed("1.2.840.10045.4.3.1", null, ByteArray(8), byteArrayOf(1)), ec))
        assertFalse(AttestCert.certSigOkUnchecked(cert.signed("1.2.840.113549.1.1.5", null, ByteArray(8), byteArrayOf(1)), rsa))
    }

    @Test
    fun spkiAlgorithmMustBeASequence() {
        val spki = cert.seq(cert.tlv(0x31, cert.oid("1.2.840.10045.2.1")), cert.tlv(0x03, cert.b(0, 1)))
        assertEquals(cert.NESTED, cert.parse(cert.tbs(spki = spki)))
    }

    /** x509-strict.ts CHAIN_CRITICAL_OK. */
    @Test
    fun chainCriticalExtensions() {
        assertEquals(setOf("2.5.29.19", "2.5.29.15", "2.5.29.37"), AttestDer.CHAIN_CRITICAL_OK)
    }

    private fun xy(): Pair<ByteArray, ByteArray> {
        val w = (cert.p256.public as ECPublicKey).w
        return Pair(jws.unsigned(w.affineX, 32), jws.unsigned(w.affineY, 32))
    }

    @Test
    fun pointMustHaveExactlyItsCurveLength() {
        val (x, y) = xy()
        assertNotNull(AttestUtil.pointToKey("secp256r1", byteArrayOf(4) + x + y))
        // the same coordinates with a zero byte in front of y: still on the curve if the length is not checked
        assertNull(AttestUtil.pointToKey("secp256r1", byteArrayOf(4) + x + byteArrayOf(0) + y))
        assertNull(AttestUtil.pointToKey("secp256r1", ByteArray(0)))
    }

    @Test
    fun rawEcdsaRefusesAnOddLength() {
        val msg = byteArrayOf(1, 2, 3)
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(cert.p256.private)
        s.update(msg)
        val rs = AttestUtil.parseDerSig(s.sign())!!
        val r32 = jws.unsigned(rs.first, 32)
        val s32 = jws.unsigned(rs.second, 32)
        val pub = cert.p256.public as ECPublicKey
        val d = AttestUtil.sha256(msg)
        assertTrue(AttestUtil.verifyRawEcdsa(pub, d, r32 + s32))
        // the right halves when the odd byte falls into s as a leading zero
        assertFalse(AttestUtil.verifyRawEcdsa(pub, d, r32 + byteArrayOf(0) + s32))
        assertFalse(AttestUtil.verifyRawEcdsa(pub, d, ByteArray(0)))
    }

    /** The cap is Kotlin's: attest-nvidia-rim.ts:225 has no upper bound (index, alternatives and size are read into an Int here). */
    @Test
    fun rimIntegerBound() {
        fun isInt(f: Double, min: Double): Boolean = KUtil.priv(AttestNvidiaCollateral, "verifyRim\$isInt", f, min)
        assertTrue(isInt(9.1e18, 0.0))
        assertFalse(isInt(9.2e18, 0.0))
    }

    // ---- Confidential Space signing key ----

    private val gcpIssuer = "https://confidentialcomputing.googleapis.com"
    private val key = jws.ecKey("secp256r1")
    private val other = jws.ecKey("secp256r1")

    private fun jwk(): LinkedHashMap<String, Any?> {
        val w = (key.public as ECPublicKey).w
        return linkedMapOf(
            "kid" to "k1", "kty" to "EC", "crv" to "P-256",
            "x" to jws.b64u(jws.unsigned(w.affineX, 32)), "y" to jws.b64u(jws.unsigned(w.affineY, 32)),
        )
    }

    private fun gcp(anchors: Map<String, Any?>, ev: Map<String, Any?>): String {
        val cfg = mapOf("trustedIssuers" to listOf(gcpIssuer), "trustAnchors" to anchors, "policy" to mapOf("imageDigests" to listOf("sha256:abc")))
        return Attest.verifierFromConfig("gcp-confidential-space", cfg).verify(ev, jws.BINDING, jws.NOW).reason
    }

    /** A non-array x5c member of a JWK is no chain: the key is simply not anchored. */
    @Test
    fun gcpNonListX5cIsNoChain() {
        val offered = jwk()
        offered["x5c"] = "nope"
        val token = jws.unsignedJwt("""{"alg":"ES256","kid":"k1"}""", "{}")
        val ev = mapOf("token" to token, "jwks" to mapOf("keys" to listOf(offered)))
        assertEquals(
            "Confidential Space signing key invalid: signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)",
            gcp(mapOf("trustedKeySpki" to listOf(jws.pin(other.public))), ev),
        )
    }

    /** A kid match wins over the token header's own x5c: the header's key is not looked at (the signature check passes under the JWK). */
    @Test
    fun gcpHeaderX5cDoesNotReplaceAMatchedKey() {
        val otherCert = Kill05GcpAmdKit.cert("o", "o", other, other)
        val header = """{"alg":"ES256","kid":"k1","x5c":["${jws.std(otherCert)}"]}"""
        val token = jws.signEs256(key, header, "{}")
        assertEquals(
            "token iss 'undefined' is not a configured trusted Google attestation issuer",
            gcp(mapOf("trustedJwks" to mapOf("keys" to listOf(jwk()))), mapOf("token" to token)),
        )
    }
}
