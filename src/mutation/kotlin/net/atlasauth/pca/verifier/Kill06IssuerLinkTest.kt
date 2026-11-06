package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.Kill05CertKit.b
import net.atlasauth.pca.verifier.Kill05CertKit.cn
import net.atlasauth.pca.verifier.Kill05CertKit.tlv
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** X509_check_issued's key identifier rules; the rows were observed on the reference's X509Certificate.checkIssued. */
class Kill06IssuerLinkTest {
    private val K = Kill05CertKit
    private val keyId = ByteArray(20) { 1 }
    private val AKID = "2.5.29.35"
    private val SKID = "2.5.29.14"

    private fun akidV(vararg parts: ByteArray) = tlv(0x30, *parts)
    private fun akid(vararg parts: ByteArray) = AttestCert.LenientExt(AKID, false, akidV(*parts))
    private fun skid(v: ByteArray) = AttestCert.LenientExt(SKID, false, v)
    private val goodSkid = skid(tlv(0x04, keyId))

    /** The CA "mid", issued by "root", serial 01, with these extensions. */
    private fun ca(vararg exts: AttestCert.LenientExt): AttestCert.Cert {
        val e = exts.map { K.ext(it.oid, null, it.value) }.toTypedArray()
        val extra = if (e.isEmpty()) ByteArray(0) else K.exts(*e)
        return AttestCert.parseCertDer(K.cert(K.tbs(serial = K.int(1), issuer = cn("root"), subject = cn("mid"), extra = extra)))
    }

    private fun issued(up: AttestCert.Cert, vararg exts: AttestCert.LenientExt): Boolean = AttestCert.checkIssued(
        AttestCert.Cert(b(), b(), up.rawSubject, b(), b(), b(1), "1.2", null, b(), exts.toList()), up,
    )

    private fun names(vararg g: ByteArray) = tlv(0xa1, *g)
    private fun dn(name: ByteArray) = tlv(0xa4, name)

    @Test fun theIssuerNameMustLink() {
        val up = ca()
        assertFalse(AttestCert.checkIssued(AttestCert.Cert(b(), b(), cn("other"), b(), b(), b(1), "1.2", null, b(), emptyList()), up))
        assertTrue(issued(up))
    }

    @Test fun anEmptyAkidComparesNothing() {
        assertTrue(issued(ca(goodSkid), akid()))
        assertTrue(issued(ca(), akid()))
    }

    @Test fun anAkidWithoutAKeyIdDoesNotCompareItsFirstChildToTheSkid() {
        val up = ca(goodSkid)
        assertTrue(issued(up, akid(tlv(0x82, up.serial))))
        assertTrue(issued(up, akid(names(dn(up.rawIssuer)))))
        assertTrue(issued(up, akid(names())))
        assertTrue(issued(up, akid(names(tlv(0x82, b(0x78))))))
    }

    @Test fun theKeyIdIsComparedOnlyAgainstAnIssuerSkid() {
        val other = ByteArray(20) { 2 }
        assertTrue(issued(ca(goodSkid), akid(tlv(0x80, keyId))))
        assertFalse(issued(ca(goodSkid), akid(tlv(0x80, other))))
        assertFalse(issued(ca(goodSkid), akid(tlv(0x80))))
        assertTrue(issued(ca(), akid(tlv(0x80, other))))
    }

    @Test fun theSerialMustBeTheIssuers() {
        val bad = tlv(0x82, b(2))
        assertFalse(issued(ca(goodSkid), akid(bad)))
        assertFalse(issued(ca(), akid(bad)))
        assertFalse(issued(ca(goodSkid), akid(tlv(0x80, keyId), bad)))
        assertFalse(issued(ca(goodSkid), akid(tlv(0x82))))
    }

    @Test fun theDirectoryNameMustBeTheIssuersIssuer() {
        val up = ca(goodSkid)
        val subject = names(dn(up.rawSubject))
        assertFalse(issued(up, akid(subject)))
        assertFalse(issued(ca(), akid(subject)))
        assertFalse(issued(up, akid(tlv(0x80, keyId), subject)))
        assertFalse(issued(up, akid(subject, tlv(0x82, up.serial))))
        assertTrue(issued(up, akid(tlv(0x80, keyId), names(dn(up.rawIssuer)), tlv(0x82, up.serial))))
    }

    @Test fun onlyTheFirstDirectoryNameCounts() {
        val up = ca(goodSkid)
        val dns = tlv(0x82, b(0x78))
        assertTrue(issued(up, akid(names(dn(up.rawIssuer), dn(up.rawSubject)))))
        assertFalse(issued(up, akid(names(dn(up.rawSubject), dn(up.rawIssuer)))))
        assertTrue(issued(up, akid(names(dns, dn(up.rawIssuer)))))
        assertFalse(issued(up, akid(names(dns, dn(up.rawSubject)))))
    }

    @Test fun stringGeneralNamesAreSkippedAndOthersRefused() {
        for (t in listOf(0x81, 0x82, 0x86, 0x87)) assertTrue("$t", issued(ca(goodSkid), akid(names(tlv(t, b(0x78))))))
        for (t in listOf(0x04, 0x80, 0x83, 0x84, 0x85, 0x88, 0x89)) assertFalse("$t", issued(ca(goodSkid), akid(names(tlv(t, b(0x2a))))))
    }

    @Test fun aMalformedDirectoryNameIsRefusedEvenWhenItIsNotTheFirst() {
        val up = ca(goodSkid)
        val first = dn(up.rawIssuer)
        assertFalse(issued(up, akid(names(first, dn(tlv(0x04, b(1)))))))
        assertFalse(issued(up, akid(names(first, tlv(0xa4)))))
        assertFalse(issued(up, akid(names(first, tlv(0xa4, up.rawIssuer, tlv(0x05))))))
        assertFalse(issued(up, akid(names(first, dn(tlv(0x30, tlv(0x04, b(1))))))))
        assertFalse(issued(up, akid(names(dn(tlv(0x30))))))
    }

    @Test fun akidChildrenAreKnownOnceAndInOrder() {
        val up = ca(goodSkid)
        val id = tlv(0x80, keyId)
        val nm = names(dn(up.rawIssuer))
        val sr = tlv(0x82, up.serial)
        assertFalse(issued(up, akid(sr, id)))
        assertFalse(issued(up, akid(nm, id)))
        assertFalse(issued(up, akid(sr, nm)))
        assertFalse(issued(up, akid(id, id)))
        assertFalse(issued(up, akid(nm, nm)))
        assertFalse(issued(up, akid(sr, sr)))
        assertFalse(issued(up, akid(tlv(0x83, b(1)))))
        assertFalse(issued(up, akid(id, tlv(0x83, b(1)))))
        assertFalse(issued(up, akid(sr, tlv(0x05))))
        assertFalse(issued(up, akid(tlv(0x04, keyId))))
        assertFalse(issued(up, akid(tlv(0x81, b(1)))))
        assertFalse(issued(up, akid(tlv(0xa2, tlv(0x02, up.serial)))))
        assertFalse(issued(up, akid(tlv(0xa0, id))))
    }

    @Test fun aMalformedKeyIdentifierOnEitherCertificateRefusesWithNothingToCompare() {
        val badSkid = skid(tlv(0x30))
        val badAkid = akid(tlv(0x83, b(1)))
        assertFalse(issued(ca(badSkid)))
        assertFalse(issued(ca(goodSkid), badSkid))
        assertFalse(issued(ca(goodSkid, badAkid)))
        assertFalse(issued(ca(goodSkid, AttestCert.LenientExt(AKID, false, tlv(0x04, b(0))))))
        assertFalse(issued(ca(), badAkid))
        // a certificate's own well-formed subject key identifier is not compared with anything
        assertTrue(issued(ca(goodSkid), skid(tlv(0x04, b(2)))))
    }

    @Test fun aRepeatedKeyIdentifierRefuses() {
        val id = akid(tlv(0x80, keyId))
        assertFalse(issued(ca(goodSkid), id, id))
        assertFalse(issued(ca(goodSkid, goodSkid)))
        assertFalse(issued(ca(goodSkid, id, id)))
        assertFalse(issued(ca(goodSkid), goodSkid, goodSkid))
    }

    /** One row per rule, on the certificate parser: Node refuses 00 05, ff 80, 00 00, ff ff and accepts the rest. */
    @Test fun aSerialWithARedundantLeadingByteIsRefused() {
        fun parse(vararg s: Int) = K.parse(K.tbs(serial = tlv(0x02, b(*s))))
        val noStart = "error:0480006C:PEM routines::no start line"
        assertEquals(noStart, parse(0x00, 0x05))
        assertEquals(noStart, parse(0x00, 0x7f))
        assertEquals(noStart, parse(0xff, 0x80))
        assertEquals(noStart, parse(0xff, 0xff))
        assertEquals(noStart, parse(0x00, 0x00))
        for (ok in listOf(intArrayOf(5), intArrayOf(0), intArrayOf(0xff), intArrayOf(0x00, 0x80), intArrayOf(0xff, 0x7f), intArrayOf(0x01, 0x00), intArrayOf(0x01, 0x80))) {
            assertNotEquals(ok.toList().toString(), noStart, parse(*ok))
        }
    }
}
