package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import net.atlasauth.pca.verifier.Kill05JwsKit.b64u
import net.atlasauth.pca.verifier.Kill05JwsKit.seg
import net.atlasauth.pca.verifier.Kill05JwsKit.unsigned
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Exact outcomes of the compact-JWS plumbing: the canonical gate, segment errors, parsed fields, JWK key builders, key type names. */
class Kill05JwsAttestJwsTest {
    private fun reason(f: () -> Any?): String = try {
        f()
        "no error"
    } catch (e: AttErr) {
        e.message ?: "null"
    }

    private fun parse(token: String) = AttestJws.parseJwt(token, "P")

    @Test
    fun canonicalGate() {
        assertArrayEquals(ByteArray(0), AttestJws.decodeCanonicalBase64url(""))
        assertArrayEquals(byteArrayOf(0xfb.toByte()), AttestJws.decodeCanonicalBase64url("-w"))
        assertArrayEquals(byteArrayOf(0xff.toByte(), 0xe0.toByte()), AttestJws.decodeCanonicalBase64url("_-A"))
        assertArrayEquals(byteArrayOf(1, 2, 3), AttestJws.decodeCanonicalBase64url("AQID"))
        assertEquals("non-canonical compact JWS: non-canonical-base64url", reason { AttestJws.decodeCanonicalBase64url("_-B") })
        assertEquals("non-canonical compact JWS: non-canonical-base64url", reason { AttestJws.decodeCanonicalBase64url("AR") })
        assertEquals("non-canonical compact JWS: bad-character", reason { AttestJws.decodeCanonicalBase64url("AQ==") })
        assertEquals("non-canonical compact JWS: non-canonical-base64url (impossible length)", reason { AttestJws.decodeCanonicalBase64url("abcde") })
    }

    @Test
    fun structureAndSegmentErrors() {
        val h = seg("""{"alg":"ES256"}""")
        val p = seg("""{"x":1}""")
        val s = b64u(byteArrayOf(1))
        val rows = listOf(
            "" to "P: empty token",
            "a.b" to "P: a compact JWS has exactly three dot-separated parts",
            "a.b.c.d" to "P: a compact JWS has exactly three dot-separated parts",
            ".$p.$s" to "P: empty JWS segment",
            "$h..$s" to "P: empty JWS segment",
            "$h.$p." to "P: empty JWS segment",
            // the header gate fails before the payload is looked at
            "a+b.$p.$s" to "P: malformed JSON segment: non-canonical compact JWS: bad-character",
            "abcde.${seg("[")}.$s" to "P: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url (impossible length)",
            "AR.${seg("[")}.$s" to "P: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url",
            // header parses, then the payload gate / JSON fails
            "$h.AR.$s" to "P: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url",
            "$h.${seg("""{"a":""")}.$s" to "P: malformed JSON segment: Unexpected end of JSON input",
            "${seg("x")}.$p.$s" to "P: malformed JSON segment: Unexpected token 'x', \"x\" is not valid JSON",
            // a header that is invalid JSON wins over a payload that does not decode
            "${seg("x")}.AR.$s" to "P: malformed JSON segment: Unexpected token 'x', \"x\" is not valid JSON",
            "${seg("[1]")}.$p.$s" to "P: header is not a JSON object",
            "$h.${seg("[]")}.$s" to "P: payload is not a JSON object",
            "${seg("{}")}.$p.$s" to "P: header has no alg",
            "${seg("""{"alg":5}""")}.$p.$s" to "P: header has no alg",
            "${seg("""{"alg":""}""")}.$p.$s" to "P: header has no alg",
            // a signature segment is only decoded after both JSON segments parse
            "$h.$p.a+" to "P: malformed signature segment: non-canonical compact JWS: bad-character",
            "$h.$p.abcde" to "P: malformed signature segment: non-canonical compact JWS: non-canonical-base64url (impossible length)",
            "$h.$p.$s" to "no error",
        )
        for ((tok, want) in rows) assertEquals(tok, want, reason { parse(tok) })
        assertEquals("Q: empty token", reason { AttestJws.parseJwt("", "Q") })
    }

    @Test
    fun parsedFields() {
        val p = seg("""{"x":1}""")
        val bare = parse("${seg("""{"alg":"ES256"}""")}.$p.AQI")
        assertEquals("ES256", bare.alg)
        assertEquals("", bare.kid)
        assertTrue(bare.x5c.isEmpty())
        assertArrayEquals(byteArrayOf(1, 2), bare.signature)
        assertArrayEquals("${seg("""{"alg":"ES256"}""")}.$p".toByteArray(Charsets.UTF_8), bare.signingInput)
        assertEquals(1, bare.payload.size)

        val full = parse("${seg("""{"alg":"RS256","kid":"k1","x5c":["a","b"]}""")}.$p.AQ")
        assertEquals("k1", full.kid)
        assertEquals(listOf("a", "b"), full.x5c)

        // a non-string kid and a non-string x5c member are absent
        val odd = parse("${seg("""{"alg":"ES256","kid":5,"x5c":[5]}""")}.$p.AQ")
        assertEquals("", odd.kid)
        assertTrue(odd.x5c.isEmpty())
        val emptyKid = parse("${seg("""{"alg":"ES256","kid":"","x5c":[]}""")}.$p.AQ")
        assertEquals("", emptyKid.kid)
        assertTrue(emptyKid.x5c.isEmpty())
    }

    @Test
    fun ecJwkCurves() {
        for ((crv, gen, curve) in listOf(Triple("P-256", "secp256r1", "prime256v1"), Triple("P-384", "secp384r1", "secp384r1"), Triple("P-521", "secp521r1", "secp521r1"))) {
            val pub = Kill05JwsKit.ecKey(gen).public as ECPublicKey
            val len = (pub.params.order.bitLength() + 7) / 8
            val k = AttestJws.jwkEcKey(crv, b64u(unsigned(pub.w.affineX, len)), b64u(unsigned(pub.w.affineY, len)))
            assertEquals("ec", k.typ)
            assertEquals(curve, k.curve)
            assertArrayEquals(pub.encoded, k.spki)
            assertEquals(Pair("EC", crv), AttestJws.jwkKtyCrv(k))
        }
        val p256 = Kill05JwsKit.ecKey("secp256r1").public as ECPublicKey
        val x = b64u(unsigned(p256.w.affineX, 32))
        val y = b64u(unsigned(p256.w.affineY, 32))
        for (crv in listOf("P-224", "", "p-256", "secp256r1")) assertEquals(crv, AttestCert.OSSL_UNSUPPORTED, reason { AttestJws.jwkEcKey(crv, x, y) })
        // an off-curve point
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason { AttestJws.jwkEcKey("P-256", "AQ", "AQ") })
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason { AttestJws.jwkEcKey("P-256", x, x) })
    }

    @Test
    fun rsaJwkExponentBounds() {
        val pub = Kill05JwsKit.rsaKey().public as RSAPublicKey
        val n = b64u(unsigned(pub.modulus, 256))
        // e = 3 is the smallest accepted exponent, 2^30 + 1 (31 bits) the widest
        val k3 = AttestJws.jwkRsaKey(n, b64u(byteArrayOf(3)))
        assertEquals("rsa", k3.typ)
        assertEquals(BigInteger.valueOf(3), (k3.pub as RSAPublicKey).publicExponent)
        val k31 = AttestJws.jwkRsaKey(n, b64u(byteArrayOf(0x40, 0, 0, 1)))
        assertEquals(BigInteger.valueOf(0x40000001L), (k31.pub as RSAPublicKey).publicExponent)
        assertEquals(pub.modulus, (k31.pub as RSAPublicKey).modulus)
        assertArrayEquals((k31.pub as RSAPublicKey).encoded, k31.spki)
        assertEquals(Pair("RSA", "undefined"), AttestJws.jwkKtyCrv(k31))
        val k65537 = AttestJws.jwkRsaKey(n, "AQAB")
        assertEquals(BigInteger.valueOf(65537), (k65537.pub as RSAPublicKey).publicExponent)
        for (e in listOf(b64u(byteArrayOf(0x80.toByte(), 0, 0, 1)), b64u(byteArrayOf(1, 0, 0, 0, 1)), b64u(byteArrayOf(2)), b64u(byteArrayOf(1)), "", "AA")) {
            assertEquals(e, AttestCert.OSSL_UNSUPPORTED, reason { AttestJws.jwkRsaKey(n, e) })
        }
        // a modulus the key factory refuses (one byte) is the same refusal, never a raw exception
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason { AttestJws.jwkRsaKey("AQ", "AQAB") })
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason { AttestJws.jwkRsaKey("", "AQAB") })
    }

    @Test
    fun ktyCrvAndSignatureRules() {
        val ed = AttestCert.CertKey(null, "ed25519", "", ByteArray(0))
        assertEquals(Pair("OKP", "Ed25519"), AttestJws.jwkKtyCrv(ed))
        val xPub = Kill05JwsKit.otherKey("X25519").public
        val x = AttestCert.keyInfoOf(xPub, xPub.encoded)
        assertEquals("unknown", x.typ)
        assertEquals(Pair("unknown", "undefined"), AttestJws.jwkKtyCrv(x))
        assertEquals(Pair("OKP", "Ed25519"), AttestJws.jwkKtyCrv(AttestCert.CertKey(xPub, "ed25519", "", ByteArray(0))))
        // the RSA rule reads the key, not its type tag
        val rsa = Kill05JwsKit.rsaKey()
        val pss = AttestCert.CertKey(rsa.public, "rsa-pss", "", rsa.public.encoded)
        assertEquals(Pair("RSA", "undefined"), AttestJws.jwkKtyCrv(pss))
        val p384 = Kill05JwsKit.ecKey("secp384r1").public
        assertEquals(Pair("EC", "P-384"), AttestJws.jwkKtyCrv(AttestCert.keyInfoOf(p384, p384.encoded)))

        val ec = Kill05JwsKit.ecKey("secp256r1")
        val ecKey = AttestCert.keyInfoOf(ec.public, ec.public.encoded)
        val rsaKey = AttestCert.keyInfoOf(rsa.public, rsa.public.encoded)
        val es = parse(Kill05JwsKit.signEs256(ec, """{"alg":"ES256"}""", "{}"))
        val rs = parse(Kill05JwsKit.signRs256(rsa, """{"alg":"RS256"}""", "{}"))
        assertTrue(AttestJws.es256Ok(es.signature, es.signingInput, ecKey))
        assertFalse(AttestJws.es256Ok(es.signature, "x".toByteArray(), ecKey))
        assertFalse(AttestJws.es256Ok(es.signature.copyOf(63), es.signingInput, ecKey))
        assertFalse(AttestJws.es256Ok(es.signature, es.signingInput, rsaKey))
        assertFalse(AttestJws.es256Ok(ByteArray(64), es.signingInput, ed))
        assertTrue(AttestJws.rs256Ok(rs.signature, rs.signingInput, rsaKey))
        assertFalse(AttestJws.rs256Ok(rs.signature, "x".toByteArray(), rsaKey))
        assertFalse(AttestJws.rs256Ok(rs.signature, rs.signingInput, ecKey))
        assertFalse(AttestJws.rs256Ok(ByteArray(256), rs.signingInput, ed))
        // a signature of the wrong length makes the engine throw, which is a plain "does not verify"
        assertFalse(AttestJws.rs256Ok(byteArrayOf(1), rs.signingInput, rsaKey))
    }
}
