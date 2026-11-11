package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Sigstore's DER reader and small parsers, against the reference's exact refusals (packages/pca-attest-eat/src/sigstore.ts). */
class Kill05SigDerTest {
    private val K = Kill05SigKit

    private fun t(b: ByteArray, off: Int = 0, limit: Int = b.size): String = try {
        val x = Sigstore.tlv(b, off, limit)
        "${x.tag}/${x.start}/${x.body}/${x.end}"
    } catch (e: IllegalArgumentException) {
        "IAE:" + e.message
    }

    @Test fun tlvCases() {
        val long = K.cat(K.b(0x04, 0x81, 0x80), ByteArray(128))
        val cases = listOf(
            Triple(K.b(0x30), 0, "IAE:DER truncated"),
            Triple(K.b(0x1f, 0x00), 0, "IAE:DER multi-byte tag"),
            Triple(K.b(0x04, 0x80), 0, "IAE:DER length"),
            Triple(K.b(0x04, 0x84, 0, 0, 0, 1, 0xaa), 0, "4/0/6/7"),
            Triple(K.b(0x04, 0x85, 0, 0, 0, 0, 1, 0xaa), 0, "IAE:DER length"),
            Triple(K.b(0x04, 0x81, 0x00), 0, "4/0/3/3"),
            Triple(K.b(0x04, 0x82, 0x00), 0, "IAE:DER length"),
            Triple(K.b(0x04, 0x02, 0xaa), 0, "IAE:DER overrun"),
            Triple(K.b(0x30, 0x00, 0x04, 0x00), 2, "4/2/4/4"),
            Triple(long, 0, "4/0/3/131"),
        )
        for ((b, off, want) in cases) assertEquals(K.hex(b), want, t(b, off))
        // the limit, not the array, bounds the element
        assertEquals("IAE:DER truncated", t(K.b(0x04, 0x01, 0xaa, 0x00), 2, 3))
        assertEquals("IAE:DER overrun", t(K.b(0x04, 0x01, 0xaa, 0x00), 0, 2))
        assertEquals("4/0/2/3", t(K.b(0x04, 0x01, 0xaa, 0x00), 0, 3))
    }

    private fun oid(b: ByteArray, off: Int = 0): String = try {
        Sigstore.oidText(b, Sigstore.tlv(b, off))
    } catch (e: IllegalArgumentException) {
        "IAE:" + e.message
    }

    @Test fun oidCases() {
        val notMinimal = "IAE:OID arc is not minimally encoded"
        val cases = listOf(
            K.b(0x06, 0x00) to "IAE:not an OID",
            K.b(0x04, 0x01, 0x2a) to "IAE:not an OID",
            K.b(0x06, 0x01, 0x2a) to "1.2",
            K.b(0x06, 0x01, 0x00) to "0.0",
            K.b(0x06, 0x01, 0x27) to "0.39",
            K.b(0x06, 0x01, 0x28) to "1.0",
            K.b(0x06, 0x01, 0x50) to "2.0",
            K.b(0x06, 0x01, 0x78) to "2.40",
            K.b(0x06, 0x02, 0x81, 0x00) to "2.48",
            K.b(0x06, 0x02, 0x80, 0x01) to notMinimal,
            K.b(0x06, 0x03, 0x2a, 0x80, 0x01) to notMinimal,
            K.b(0x06, 0x02, 0x2a, 0x81) to "IAE:OID ends inside an arc",
            K.b(0x06, 0x03, 0x2a, 0x81, 0x01) to "1.2.129",
            K.b(0x06, 0x04, 0x2a, 0x81, 0x80, 0x01) to "1.2.16385",
            K.cat(K.b(0x06, 0x0a, 0x2a), ByteArray(8) { 0xff.toByte() }, K.b(0x7f)) to "1.2.9223372036854775807",
            K.cat(K.b(0x06, 0x0b, 0x2a, 0x81), ByteArray(8) { 0x80.toByte() }, K.b(0x00)) to "IAE:OID arc too large",
            // a leading 0x80 behind a length byte that has its top bit set (long form, 128 content bytes)
            K.cat(K.b(0x06, 0x81, 0x80, 0x80, 0x01), ByteArray(126) { 1 }) to notMinimal,
        )
        for ((b, want) in cases) assertEquals(K.hex(b), want, oid(b))
        // an empty OID inside a SEQUENCE (its body is not at offset 0)
        assertEquals("IAE:not an OID", oid(K.b(0x30, 0x02, 0x06, 0x00), 2))
        assertEquals("1.2", oid(K.b(0x30, 0x03, 0x06, 0x01, 0x2a), 2))
    }

    private fun cert(vararg tbsParts: ByteArray): ByteArray = K.seq(K.seq(*tbsParts), K.ALG, K.tlv(0x03, K.b(0)))
    private val head = arrayOf(K.tlv(0xa0, K.int(2)), K.int(1), K.ALG)
    private fun withExts(vararg e: ByteArray): ByteArray = cert(*head, K.tlv(0xa3, K.seq(*e)))
    private fun pc(der: ByteArray): String = try {
        Sigstore.parseCert(der).exts.joinToString(",") { it.oid + "=" + K.hex(it.value) }
    } catch (e: IllegalArgumentException) {
        "IAE:" + e.message
    }

    @Test fun parseCertCases() {
        val san = K.san(K.uri("x"))
        val sanVal = K.hex(K.seq(K.uri("x")))
        assertEquals("IAE:certificate is not one SEQUENCE", pc(K.b(0x31, 0x00)))
        assertEquals("IAE:certificate is not one SEQUENCE", pc(K.cat(cert(*head, K.tlv(0xa3, K.seq(san))), K.b(0))))
        assertEquals("IAE:certificate is not tbs, algorithm, signature", pc(K.seq(K.seq(), K.seq())))
        assertEquals("IAE:no TBSCertificate", pc(K.seq(K.set(), K.ALG, K.tlv(0x03, K.b(0)))))
        assertEquals("IAE:no extensions", pc(cert(*head)))
        assertEquals("IAE:extensions malformed", pc(cert(*head, K.tlv(0xa3))))
        assertEquals("IAE:extensions malformed", pc(cert(*head, K.tlv(0xa3, K.seq(), K.seq()))))
        assertEquals("IAE:extensions malformed", pc(cert(*head, K.tlv(0xa3, K.set(san)))))
        assertEquals("IAE:extension is not a SEQUENCE", pc(withExts(K.set(K.oid("2.5.29.17"), K.oct(K.b(1))))))
        assertEquals("IAE:extension malformed", pc(withExts(K.seq(K.oid("2.5.29.17")))))
        assertEquals("IAE:extension malformed", pc(withExts(K.seq(K.oid("2.5.29.17"), K.tlv(0x01, K.b(0)), K.oct(K.b(1)), K.oct(K.b(1))))))
        assertEquals("IAE:extension malformed", pc(withExts(K.seq(K.oid("2.5.29.17"), K.int(1), K.oct(K.b(1))))))
        assertEquals("IAE:extension value is not an OCTET STRING", pc(withExts(K.seq(K.oid("2.5.29.17"), K.tlv(0x03, K.b(0))))))
        assertEquals("IAE:duplicate extension 2.5.29.17", pc(withExts(san, san)))
        assertEquals("2.5.29.17=$sanVal", pc(withExts(san)))
        assertEquals("2.5.29.17=$sanVal,1.2.3=01", pc(withExts(K.seq(K.oid("2.5.29.17"), K.tlv(0x01, K.b(0xff)), K.oct(K.seq(K.uri("x")))), K.ext("1.2.3", K.b(1)))))
    }

    private fun parsed(vararg e: ByteArray): Sigstore.ParsedCert = Sigstore.parseCert(withExts(*e))

    @Test fun utf8AndFulcio() {
        assertEquals("IAE:not UTF-8", K.err { Sigstore.utf8Strict(K.b(0xff)) })
        assertEquals("IAE:not UTF-8", K.err { Sigstore.utf8Strict(K.b(0xc3)) })
        assertEquals("A", Sigstore.utf8Strict(K.b(0xef, 0xbb, 0xbf, 0x41)))
        val c = parsed(
            K.fulcio(6, K.utf8("raw6")),
            K.fulcio(7, K.tlv(0x0c, K.utf8("der7"))),
            K.fulcio(8, K.tlv(0x13, K.utf8("x"))),
            K.fulcio(9, K.cat(K.tlv(0x0c, K.utf8("x")), K.b(0))),
        )
        assertEquals("raw6", Sigstore.fulcioExt(c, 6))
        assertEquals("der7", Sigstore.fulcioExt(c, 7))
        assertEquals("IAE:extension .1.8 is not a DER UTF8String", K.err { Sigstore.fulcioExt(c, 8) })
        assertEquals("IAE:extension .1.9 is not a DER UTF8String", K.err { Sigstore.fulcioExt(c, 9) })
        assertNull(Sigstore.fulcioExt(c, 12))
    }

    @Test fun sanIdentityCases() {
        assertEquals("IAE:no subjectAltName", K.err { Sigstore.sanIdentity(parsed(K.ext("1.2.3", K.b(1)))) })
        val one = "IAE:subjectAltName must hold exactly one name"
        assertEquals(one, K.err { Sigstore.sanIdentity(parsed(K.ext("2.5.29.17", K.set(K.uri("x"))))) })
        assertEquals(one, K.err { Sigstore.sanIdentity(parsed(K.san(K.uri("x"), K.uri("y")))) })
        assertEquals(one, K.err { Sigstore.sanIdentity(parsed(K.san())) })
        assertEquals("IAE:subjectAltName must be a URI or an email", K.err { Sigstore.sanIdentity(parsed(K.san(K.tlv(0x82, K.utf8("a.b"))))) })
        assertEquals("a@b.c", Sigstore.sanIdentity(parsed(K.san(K.tlv(0x81, K.utf8("a@b.c"))))))
        assertEquals("https://x", Sigstore.sanIdentity(parsed(K.san(K.uri("https://x")))))
    }

    @Test fun generalNamesDecodeTags() {
        for (tag in listOf(0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88)) {
            assertTrue("tag %02x".format(tag), Sigstore.generalNamesDecode(K.seq(K.tlv(tag, K.b(1)))))
            assertTrue("tag %02x second".format(tag), Sigstore.generalNamesDecode(K.seq(K.uri("x"), K.tlv(tag, K.b(1)))))
        }
        for (tag in listOf(0x80, 0x83, 0x84, 0x85, 0x89, 0xa1, 0xa2, 0xa6, 0xa7, 0xa8, 0x30, 0x04)) {
            assertFalse("tag %02x".format(tag), Sigstore.generalNamesDecode(K.seq(K.tlv(tag, K.b(1)))))
            assertFalse("tag %02x second".format(tag), Sigstore.generalNamesDecode(K.seq(K.uri("x"), K.tlv(tag, K.b(1)))))
            assertFalse("tag %02x first".format(tag), Sigstore.generalNamesDecode(K.seq(K.tlv(tag, K.b(1)), K.uri("x"))))
        }
        assertTrue(Sigstore.generalNamesDecode(K.seq()))
        assertTrue(Sigstore.generalNamesDecode(K.seq(K.uri("x"), K.uri("y"))))
        assertFalse(Sigstore.generalNamesDecode(K.set(K.uri("x"))))
        assertFalse(Sigstore.generalNamesDecode(K.cat(K.seq(K.uri("x")), K.b(0))))
        assertFalse(Sigstore.generalNamesDecode(K.b(0x30, 0x05)))
    }

    @Test fun smallParsers() {
        assertEquals(258, Sigstore.u16(K.b(0x01, 0x02), 0))
        assertEquals(256, Sigstore.u16(K.b(0x01, 0x00), 0))
        assertEquals(65534, Sigstore.u16(K.b(0xff, 0xfe), 0))
        assertEquals(0x1234, Sigstore.u16(K.b(0x09, 0x12, 0x34), 1))
        assertEquals(0L, Sigstore.decInt("0"))
        assertEquals(9007199254740991L, Sigstore.decInt("9007199254740991"))
        assertEquals("IAE:integer out of range", K.err { Sigstore.decInt("9007199254740992") })
        for (v in listOf<Any?>(5L, "01", null, "-1", "")) assertEquals("$v", "IAE:not a decimal integer string", K.err { Sigstore.decInt(v) })
        for (v in listOf<Any?>(null, 5L, "!!!!", "abc", "QQ=")) assertEquals("$v", "IAE:not base64", K.err { Sigstore.b64(v) })
        assertArrayEquals(K.b(0x41), Sigstore.b64("QQ=="))
        assertArrayEquals(ByteArray(0), Sigstore.pemDer("x"))
        assertArrayEquals(ByteArray(0), Sigstore.pemDer(""))
        val der = K.caDer
        assertArrayEquals(der, Sigstore.pemDer(K.pem(der)))
    }

    @Test fun timesAndValidity() {
        assertEquals("IAE:w", K.err { Sigstore.rfc3339("2024-01-01", "w") })
        assertEquals("IAE:w", K.err { Sigstore.rfc3339("2024-02-30T00:00:00Z", "w") })
        assertEquals(K.IT * 1000, Sigstore.rfc3339(K.IT_RFC, "w"))
        assertEquals("IAE:validFor.start missing", K.err { Sigstore.validity(null) })
        assertEquals("IAE:validFor.start missing", K.err { Sigstore.validity(mapOf("start" to 5L)) })
        assertEquals("IAE:validFor.start missing", K.err { Sigstore.validity(mapOf("start" to "2024-02-30T00:00:00Z")) })
        assertEquals("IAE:validFor.end malformed", K.err { Sigstore.validity(mapOf("start" to K.IT_RFC, "end" to "x")) })
        val open = Sigstore.validity(mapOf("start" to K.IT_RFC))
        assertEquals(2, open.size)
        assertEquals(K.IT * 1000, open[0])
        assertEquals(Long.MAX_VALUE, open[1])
        val closed = Sigstore.validity(mapOf("start" to K.IT_RFC, "end" to "2025-01-01T01:00:01Z"))
        assertEquals(2, closed.size)
        assertEquals(K.IT * 1000 + 1000, closed[1])
        // RFC 3161 pieces
        val sha1 = K.seq(K.oid("1.3.14.3.2.26"))
        assertEquals("IAE:unsupported digest algorithm", K.err { Sigstore.digestOf(sha1, Sigstore.tlv(sha1, 0)) })
        val s384 = K.seq(K.oid("2.16.840.1.101.3.4.2.2"))
        assertEquals("sha384", Sigstore.digestOf(s384, Sigstore.tlv(s384, 0)))
        val utcT = K.tlv(0x17, "250101000000Z".toByteArray(Charsets.US_ASCII))
        assertEquals("IAE:genTime is not a GeneralizedTime", K.err { Sigstore.generalizedTime(utcT, Sigstore.tlv(utcT, 0)) })
        val short = K.tlv(0x18, "2025".toByteArray(Charsets.US_ASCII))
        assertEquals("IAE:genTime malformed", K.err { Sigstore.generalizedTime(short, Sigstore.tlv(short, 0)) })
        val frac = K.tlv(0x18, "20250101000000.5Z".toByteArray(Charsets.US_ASCII))
        assertEquals(1735689600500L, Sigstore.generalizedTime(frac, Sigstore.tlv(frac, 0)))
    }

    /** The DSSE hash follows the exact named curve (every domain parameter), as the reference's namedCurve does. */
    @Test fun leafHashAlgByNamedCurve() {
        assertEquals("sha256", Sigstore.leafHashAlg(K.ec("secp256r1").public))
        assertEquals("sha384", Sigstore.leafHashAlg(K.ec("secp384r1").public))
        assertNull(Sigstore.leafHashAlg(K.ec("secp521r1").public))
        assertNull(Sigstore.leafHashAlg(K.rsa().public))
        // same field size as P-256 / P-384, other curves: refused (the field-size check used to accept them)
        assertNull(Sigstore.leafHashAlg(Kill05CertKit.ecBc("brainpoolP256r1").public))
        assertNull(Sigstore.leafHashAlg(Kill05CertKit.ecBc("brainpoolP384r1").public))
        assertNull(Sigstore.leafHashAlg(Kill05CertKit.ecBc("secp256k1").public))
    }

    @Test fun bundleMediaTypes() {
        assertEquals(
            listOf("application/vnd.dev.sigstore.bundle+json;version=0.2", "application/vnd.dev.sigstore.bundle+json;version=0.3", "application/vnd.dev.sigstore.bundle.v0.3+json"),
            Sigstore.BUNDLE_MEDIA_TYPES,
        )
    }

    @Test fun oidLeadingContinuationAfterAnOddTerminalOctet() {
        // a 0x80 octet after a byte that closed an arc starts a non-minimal arc, whatever that byte's low bits (0x2b = 43 is odd)
        val notMinimal = "IAE:OID arc is not minimally encoded"
        assertEquals(notMinimal, oid(K.b(0x06, 0x03, 0x2b, 0x80, 0x01)))
        assertEquals(notMinimal, oid(K.b(0x06, 0x04, 0x2a, 0x01, 0x80, 0x01)))
        assertEquals(notMinimal, oid(K.b(0x06, 0x04, 0x2a, 0x7f, 0x80, 0x01)))
        assertEquals("1.3.1", oid(K.b(0x06, 0x02, 0x2b, 0x01)))
        assertEquals("1.2.1.129", oid(K.b(0x06, 0x04, 0x2a, 0x01, 0x81, 0x01)))
    }
}
