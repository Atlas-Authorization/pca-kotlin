package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.Kill05CertKit.BITS
import net.atlasauth.pca.verifier.Kill05CertKit.NESTED
import net.atlasauth.pca.verifier.Kill05CertKit.OK
import net.atlasauth.pca.verifier.Kill05CertKit.UNSUPPORTED
import net.atlasauth.pca.verifier.Kill05CertKit.WRONG_TAG
import net.atlasauth.pca.verifier.Kill05CertKit.b
import net.atlasauth.pca.verifier.Kill05CertKit.cat
import net.atlasauth.pca.verifier.Kill05CertKit.cert
import net.atlasauth.pca.verifier.Kill05CertKit.elem
import net.atlasauth.pca.verifier.Kill05CertKit.err
import net.atlasauth.pca.verifier.Kill05CertKit.ext
import net.atlasauth.pca.verifier.Kill05CertKit.exts
import net.atlasauth.pca.verifier.Kill05CertKit.int
import net.atlasauth.pca.verifier.Kill05CertKit.oid
import net.atlasauth.pca.verifier.Kill05CertKit.parse
import net.atlasauth.pca.verifier.Kill05CertKit.rdn
import net.atlasauth.pca.verifier.Kill05CertKit.seq
import net.atlasauth.pca.verifier.Kill05CertKit.str
import net.atlasauth.pca.verifier.Kill05CertKit.tbs
import net.atlasauth.pca.verifier.Kill05CertKit.tlv
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AttestCert's DER readers: readElem, validOid, algId, checkBitString, checkName, parseCertDer, derLengthHeader, the PEM readers. */
class Kill05CertParseTest {
    @Test
    fun readElemBoundsTagsAndPositions() {
        val x = b(0x30, 0x02, 0x04, 0x00)
        assertEquals("error:0680007B:asn1 encoding routines::not enough data", err { AttestCert.readElem(x, 4, 4, 0) })
        assertEquals("error:0680007B:asn1 encoding routines::not enough data", err { AttestCert.readElem(x, 2, 2, 0) })
        assertEquals("error:0680007B:asn1 encoding routines::not enough data", err { AttestCert.readElem(x, 3, 2, 0) })
        assertEquals(NESTED, err { AttestCert.readElem(b(0x30, 0x05, 0x00), 0, 3, 0) })
        assertEquals(WRONG_TAG, err { AttestCert.readElem(x, 0, 4, 0x31) })
        assertEquals(WRONG_TAG, err { AttestCert.readElem(x, 2, 4, 0x30) })
        val e = AttestCert.readElem(b(0xff, 0x04, 0x01, 0x09), 1, 4, 0)
        assertEquals(listOf(4, 1, 3, 4), listOf(e.tag, e.hdr, e.start, e.end))
        val s = AttestCert.readElem(x, 0, 4, 0x30)
        assertEquals(listOf(0x30, 0, 2, 4), listOf(s.tag, s.hdr, s.start, s.end))
    }

    @Test
    fun validOidMatchesTheOpenSslContentCheck() {
        // each case carries a trailing byte outside the element, so reading one past its end changes the answer
        val cases = listOf(
            b(0x06, 0x03, 0x2a, 0x03, 0x04, 0x80) to true,
            b(0x06, 0x04, 0x2a, 0x81, 0x80, 0x01, 0x80) to true, // 0x80 continuing an arc is fine
            b(0x06, 0x01, 0x2a, 0x00) to true,
            b(0x04, 0x03, 0x2a, 0x03, 0x04, 0x00) to false, // not an OID
            b(0x06, 0x00, 0x00) to false, // empty
            b(0x06, 0x02, 0x2a, 0x81, 0x00) to false, // dangling continuation
            b(0x06, 0x02, 0x80, 0x01, 0x00) to false, // first arc starts with 0x80
            b(0x06, 0x03, 0x2a, 0x80, 0x01, 0x00) to false, // a later arc starts with 0x80
            b(0x06, 0x04, 0x2a, 0x01, 0x80, 0x01, 0x00) to false,
        )
        for ((bytes, want) in cases) assertEquals(AttestUtil.hex(bytes), want, AttestCert.validOid(bytes, elem(bytes)))
        // the content check reads the element's own bytes, not the array around it
        val inner = b(0x30, 0x05, 0x06, 0x03, 0x2a, 0x80, 0x01)
        assertFalse(AttestCert.validOid(inner, AttestCert.readElem(inner, 2, inner.size, 0)))
    }

    @Test
    fun algIdShapes() {
        fun alg(x: ByteArray): String = err { AttestCert.algId(x, elem(x)) }
        val bare = seq(oid("1.2.840.10045.4.3.2"))
        assertEquals(Pair("1.2.840.10045.4.3.2", null), AttestCert.algId(bare, elem(bare)))
        val withParams = seq(oid("1.2.840.113549.1.1.10"), seq(int(5)))
        val (o, p) = AttestCert.algId(withParams, elem(withParams))
        assertEquals("1.2.840.113549.1.1.10", o)
        assertArrayEquals(seq(int(5)), p)
        assertEquals(NESTED, alg(seq()))
        assertEquals(NESTED, alg(seq(oid("1.2.3"), int(1), int(2))))
        assertEquals(NESTED, alg(seq(int(1))))
        assertEquals(NESTED, alg(seq(tlv(0x06, b(0x80, 0x01)))))
        assertEquals(OK, alg(seq(oid("1.2.3"), int(1))))
    }

    @Test
    fun checkBitStringRules() {
        fun bs(x: ByteArray): String = err { AttestCert.checkBitString(x, elem(x)) }
        assertEquals(OK, bs(b(0x03, 0x01, 0x00, 0x09)))
        assertEquals(OK, bs(b(0x03, 0x02, 0x07, 0xff)))
        assertEquals(BITS, bs(b(0x03, 0x02, 0x08, 0xff)))
        assertEquals(BITS, bs(b(0x03, 0x01, 0xff)))
        assertEquals(WRONG_TAG, bs(b(0x03, 0x00, 0x00))) // empty: no unused-bits octet
        assertEquals(WRONG_TAG, bs(b(0x04, 0x01, 0x00)))
    }

    @Test
    fun checkNameRules() {
        fun name(x: ByteArray): String = err { AttestCert.checkName(x, elem(x)) }
        val good = rdn(seq(oid("2.5.4.3"), str(0x0c, "a")))
        assertEquals(OK, name(seq()))
        assertEquals(OK, name(seq(good, rdn(seq(oid("2.5.4.10"), str(0x13, "b")), seq(oid("2.5.4.11"), str(0x13, "c"))))))
        for (t in listOf(0x0c, 0x12, 0x13, 0x14, 0x16, 0x1c, 0x1e, 0x03, 0x30)) {
            assertEquals("tag $t", OK, name(seq(rdn(seq(oid("2.5.4.3"), tlv(t, b(0x41)))))))
        }
        for (t in listOf(0x04, 0x02, 0x17, 0x31, 0x1a)) {
            assertEquals("tag $t", NESTED, name(seq(rdn(seq(oid("2.5.4.3"), tlv(t, b(0x41)))))))
        }
        assertEquals(WRONG_TAG, name(seq(good, seq(seq(oid("2.5.4.3"), str(0x0c, "a"))))))
        assertEquals(WRONG_TAG, name(seq(good, rdn(rdn(oid("2.5.4.3"), str(0x0c, "a"))))))
        assertEquals(NESTED, name(seq(good, rdn(seq(oid("2.5.4.3"))))))
        assertEquals(NESTED, name(seq(good, rdn(seq(oid("2.5.4.3"), str(0x0c, "a"), str(0x0c, "b"))))))
        assertEquals(NESTED, name(seq(good, rdn(seq(tlv(0x06, b(0x80, 0x01)), str(0x0c, "a"))))))
        assertEquals(NESTED, name(seq(good, rdn(seq(str(0x0c, "x"), str(0x0c, "a"))))))
    }

    @Test
    fun parsedFieldsAreTheEncodedParts() {
        val e1 = ext("1.2.3.4", b(0x01, 0x01, 0xff), b(1, 2))
        val e2 = ext("2.5.29.37", null, b(3))
        val e3 = ext("2.5.29.15", b(0x01, 0x01, 0x00), b(4))
        val e4 = ext("2.5.29.19", b(0x01, 0x01, 0x01), b())
        val t = tbs(extra = exts(e1, e2, e3, e4))
        val alg = seq(oid("1.2.840.113549.1.1.10"), seq())
        val der = cert(t, alg = alg)
        val c = AttestCert.parseCertDer(der)
        assertArrayEquals(der, c.raw)
        assertArrayEquals(t, c.rawTbs)
        assertArrayEquals(Kill05CertKit.ISSUER, c.rawIssuer)
        assertArrayEquals(Kill05CertKit.SUBJECT, c.rawSubject)
        assertArrayEquals(Kill05CertKit.SPKI, c.rawSpki)
        assertArrayEquals(b(0x01, 0x02), c.serial)
        assertEquals("1.2.840.113549.1.1.10", c.sigOid)
        assertArrayEquals(b(0x30, 0x00), c.sigParams)
        assertArrayEquals(b(1, 2, 3, 4, 5, 6, 7), c.signature)
        assertEquals(4, c.exts.size)
        assertEquals(listOf("1.2.3.4", "2.5.29.37", "2.5.29.15", "2.5.29.19"), c.exts.map { it.oid })
        assertEquals(listOf(true, false, false, true), c.exts.map { it.critical })
        assertArrayEquals(b(1, 2), c.exts[0].value)
        assertArrayEquals(b(3), c.exts[1].value)
        assertArrayEquals(b(4), c.exts[2].value)
        assertArrayEquals(b(), c.exts[3].value)
        assertArrayEquals(b(1, 2), c.extValue("1.2.3.4"))
        assertArrayEquals(b(4), c.extValue("2.5.29.15"))
        assertNull(c.extValue("9.9.9"))
        val plain = AttestCert.parseCertDer(cert())
        assertNull(plain.sigParams)
        assertEquals("1.2.840.10045.4.3.2", plain.sigOid)
        assertTrue(plain.exts.isEmpty())
    }

    @Test
    fun outerFormAndTrailingBytes() {
        // a non-minimal outer length is read; `raw` re-encodes it minimally. Bytes after the certificate are ignored.
        val good = cert()
        val e = elem(good)
        val content = good.copyOfRange(e.start, e.end)
        assertTrue(content.size in 0x80..0xff)
        val loose = cat(b(0x30, 0x82, 0x00, content.size), content, b(0, 0))
        assertArrayEquals(good, AttestCert.parseCertDer(loose).raw)
        assertEquals(WRONG_TAG, err { AttestCert.parseCertDer(tlv(0x31, tbs(), Kill05CertKit.ALG, Kill05CertKit.SIG)) })
        assertEquals(NESTED, err { AttestCert.parseCertDer(seq(tbs(), Kill05CertKit.ALG, Kill05CertKit.SIG, int(1))) })
        assertEquals(BITS, err { AttestCert.parseCertDer(cert(sig = tlv(0x03, b(8, 1)))) })
        assertEquals(NESTED, err { AttestCert.parseCertDer(cert(alg = seq(int(1)))) })
    }

    @Test
    fun tbsFieldRules() {
        assertEquals(OK, parse(tbs()))
        assertEquals(OK, parse(seq(int(258), Kill05CertKit.ALG, Kill05CertKit.ISSUER, Kill05CertKit.VALIDITY, Kill05CertKit.SUBJECT, Kill05CertKit.SPKI)))
        assertEquals(NESTED, parse(tbs(version = tlv(0xa0, int(2), int(3)))))
        assertEquals(WRONG_TAG, parse(tbs(version = tlv(0xa0, str(0x04, "x")))))
        assertEquals("error:0688010A:asn1 encoding routines::illegal zero content", parse(tbs(serial = tlv(0x02))))
        assertEquals(WRONG_TAG, parse(tbs(serial = str(0x04, "x"))))
        assertEquals(NESTED, parse(tbs(alg = seq(oid("1.2.3"), int(1), int(2)))))
        assertEquals(NESTED, parse(tbs(alg = seq(tlv(0x06, b(0x80, 0x01))))))
        assertEquals(WRONG_TAG, parse(tbs(issuer = seq(seq(seq(oid("2.5.4.3"), str(0x0c, "a")))))))
        assertEquals(NESTED, parse(tbs(subject = seq(rdn(seq(oid("2.5.4.3"), str(0x04, "a")))))))
        assertEquals(WRONG_TAG, parse(tbs(subject = seq(rdn(rdn(oid("2.5.4.3"), str(0x0c, "a")))))))
    }

    @Test
    fun validityShapes() {
        val tags = listOf(0x17 to Kill05CertKit.UTC, 0x18 to Kill05CertKit.GEN, 0x02 to int(5))
        for ((t1, v1) in tags) for ((t2, v2) in tags) {
            val want = if (t1 != 0x02 && t2 != 0x02) OK else NESTED
            assertEquals("$t1/$t2", want, parse(tbs(validity = seq(v1, v2))))
        }
        assertEquals(NESTED, parse(tbs(validity = seq(Kill05CertKit.UTC))))
        assertEquals(NESTED, parse(tbs(validity = seq(Kill05CertKit.UTC, Kill05CertKit.UTC, Kill05CertKit.UTC))))
        assertEquals(NESTED, parse(tbs(validity = seq())))
    }

    @Test
    fun subjectPublicKeyInfoShapes() {
        val alg = seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7"))
        val key = tlv(0x03, b(0, 4, 1, 2))
        assertEquals(OK, parse(tbs(spki = seq(alg, key))))
        assertEquals(NESTED, parse(tbs(spki = seq(alg))))
        assertEquals(NESTED, parse(tbs(spki = seq(alg, key, key))))
        assertEquals(NESTED, parse(tbs(spki = seq(oid("1.2.840.10045.2.1"), key))))
        assertEquals(NESTED, parse(tbs(spki = seq(seq(tlv(0x06, b(0x80, 0x01))), key))))
        assertEquals(NESTED, parse(tbs(spki = seq(seq(), key))))
        assertEquals(WRONG_TAG, parse(tbs(spki = seq(alg, tlv(0x04, b(0, 4))))))
        assertEquals(BITS, parse(tbs(spki = seq(alg, tlv(0x03, b(8, 4))))))
        assertEquals(WRONG_TAG, parse(tbs(spki = str(0x31, "x"))))
    }

    @Test
    fun uniqueIdsAndTrailingTbsElements() {
        val iu = tlv(0x81, b(0, 1))
        val su = tlv(0x82, b(0, 2))
        val ex = exts(ext("1.2.3", null, b(9)))
        assertEquals(OK, parse(tbs(extra = iu)))
        assertEquals(OK, parse(tbs(extra = su)))
        assertEquals(OK, parse(tbs(extra = cat(iu, su))))
        assertEquals(1, AttestCert.parseCertDer(cert(tbs(extra = cat(iu, su, ex)))).exts.size)
        assertEquals(1, AttestCert.parseCertDer(cert(tbs(extra = cat(su, ex)))).exts.size)
        assertEquals(NESTED, parse(tbs(extra = cat(su, iu))))
        assertEquals(NESTED, parse(tbs(extra = cat(iu, iu))))
        assertEquals(NESTED, parse(tbs(extra = tlv(0x00))))
        assertEquals(NESTED, parse(tbs(extra = tlv(0x83, b(1)))))
        assertEquals(NESTED, parse(tbs(extra = cat(ex, ex))))
        assertEquals(NESTED, parse(tbs(extra = cat(ex, iu))))
        assertEquals(NESTED, parse(tbs(extra = int(1))))
    }

    @Test
    fun extensionShapes() {
        fun one(vararg parts: ByteArray) = parse(tbs(extra = exts(seq(*parts))))
        val o = oid("1.2.3.4")
        val v = tlv(0x04, b(1))
        assertEquals(OK, one(o, v))
        assertEquals(OK, one(o, tlv(0x01, b(0xff)), v))
        assertEquals(OK, parse(tbs(extra = tlv(0xa3, seq()))))
        assertEquals(NESTED, one(o))
        assertEquals(NESTED, one(o, v, v, v))
        assertEquals(NESTED, one(o, tlv(0x01, b(0xff)), v, v))
        assertEquals(NESTED, one(tlv(0x06, b(0x80, 0x01)), v))
        assertEquals(NESTED, one(tlv(0x06), v))
        assertEquals(NESTED, one(int(1), v))
        assertEquals(NESTED, one(o, int(1), v))
        assertEquals(NESTED, one(o, tlv(0x01, b(0xff, 0xff)), v))
        assertEquals(NESTED, one(o, tlv(0x01), v))
        assertEquals(WRONG_TAG, one(o, int(1)))
        assertEquals(WRONG_TAG, one(o, tlv(0x01, b(0xff)), int(1)))
        assertEquals(WRONG_TAG, parse(tbs(extra = exts(int(1)))))
        assertEquals(WRONG_TAG, parse(tbs(extra = tlv(0xa3, tlv(0x31)))))
        assertEquals(NESTED, parse(tbs(extra = tlv(0xa3, seq(seq(o, v)), int(1)))))
    }

    @Test
    fun derLengthHeaderForms() {
        val cases = listOf(
            0 to b(0x30, 0x00),
            0x7f to b(0x30, 0x7f),
            0x80 to b(0x30, 0x81, 0x80),
            0xff to b(0x30, 0x81, 0xff),
            0x100 to b(0x30, 0x82, 0x01, 0x00),
            0x1234 to b(0x30, 0x82, 0x12, 0x34),
            0xffff to b(0x30, 0x82, 0xff, 0xff),
            0x10000 to b(0x30, 0x83, 0x01, 0x00, 0x00),
            0x123456 to b(0x30, 0x83, 0x12, 0x34, 0x56),
            0xffffff to b(0x30, 0x83, 0xff, 0xff, 0xff),
            0x1000000 to b(0x30, 0x84, 0x01, 0x00, 0x00, 0x00),
            0x12345678 to b(0x30, 0x84, 0x12, 0x34, 0x56, 0x78),
            0x7fffffff to b(0x30, 0x84, 0x7f, 0xff, 0xff, 0xff),
        )
        for ((n, want) in cases) assertArrayEquals("n=$n", want, AttestCert.derLengthHeader(0x30, n))
        assertArrayEquals(b(0x04, 0x82, 0x01, 0x02), AttestCert.derLengthHeader(0x04, 0x102))
        // through parseCertDer: a long-form outer length (content >= 128 bytes) is kept as given when minimal
        val big = cert(tbs(extra = exts(ext("1.2.3", null, ByteArray(300)))))
        assertArrayEquals(big, AttestCert.parseCertDer(big).raw)
    }

    @Test
    fun pemReaders() {
        val d1 = cert()
        val d2 = cert(tbs(serial = int(7)))
        val b64 = java.util.Base64.getEncoder().encodeToString(d1)
        // spaces, tabs, CRs and LFs inside the body are skipped
        val body = b64.substring(0, 10) + " " + b64.substring(10, 20) + "\t" + b64.substring(20, 30) + "\r\n" + b64.substring(30)
        val pem1 = "-----BEGIN CERTIFICATE-----\r\n$body\n-----END CERTIFICATE-----"
        val c = AttestCert.certFromPem(pem1)
        assertArrayEquals(d1, c.raw)
        assertArrayEquals(b(0x01, 0x02), c.serial)
        assertArrayEquals(d1, AttestCert.certFromPem("junk\n$pem1\ntrailer").raw)
        val pem2 = "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder().encodeToString(d2) + "\n-----END CERTIFICATE-----"
        assertEquals(listOf(pem1, pem2), AttestCert.pemCertBlocks(pem1 + "\nmiddle\n" + pem2 + "\n"))
        assertEquals(emptyList<String>(), AttestCert.pemCertBlocks("no blocks here"))
        assertArrayEquals(b(0x07), AttestCert.certFromPem(pem2).serial)
        assertEquals("error:0480006C:PEM routines::no start line", err { AttestCert.certFromPem("-----BEGIN CERTIFICATE-----\nAAAA\n") })
        assertEquals("error:0480006C:PEM routines::no start line", err { AttestCert.certFromPem("") })
        assertEquals(UNSUPPORTED, err { AttestCert.certFromPem("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----") })
        assertEquals(UNSUPPORTED, err { AttestCert.certFromPem("-----BEGIN CERTIFICATE-----\nA*AA\n-----END CERTIFICATE-----") })
        // bytes after the certificate inside the block are an error (d2i would ignore them)
        val trailing = java.util.Base64.getEncoder().encodeToString(cat(d1, b(0, 0, 0)))
        assertEquals(NESTED, err { AttestCert.certFromPem("-----BEGIN CERTIFICATE-----\n$trailing\n-----END CERTIFICATE-----") })
        assertEquals(WRONG_TAG, err { AttestCert.certFromPem("-----BEGIN CERTIFICATE-----\nBAA=\n-----END CERTIFICATE-----") })
    }
}
