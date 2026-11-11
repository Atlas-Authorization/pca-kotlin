package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Deadline tests for the AttestCert / AttestDer cursors (atvString, inOrder, parseCertDer, oidEquals, readCertRoleInfo, parseTbsExtensions). */
class Kill06DeadlineBCertTest {
    private val c = Kill05CertKit
    private val g = Kill05GcpAmdKit

    private fun atv(tag: Int, v: ByteArray): String? {
        val e = AttestCert.Elem(tag, 0, 0, v.size)
        return AttestCert.atvString(v, e)
    }

    @Test
    fun atvStringByTag() = Deadline.within {
        val ascii = "Ab 1-x".toByteArray(Charsets.ISO_8859_1)
        assertEquals("Ab 1-x", atv(0x13, ascii))
        assertEquals("Ab 1-x", atv(0x16, ascii))
        assertEquals("12 3", atv(0x12, "12 3".toByteArray(Charsets.ISO_8859_1)))
        assertNull(atv(0x13, byteArrayOf('a'.code.toByte(), '@'.code.toByte())))
        assertNull(atv(0x16, byteArrayOf(0x80.toByte())))
        assertNull(atv(0x12, "1a".toByteArray(Charsets.ISO_8859_1)))
        assertEquals("hé", atv(0x0c, "hé".toByteArray(Charsets.UTF_8)))
        assertEquals("hi", atv(0x1e, byteArrayOf(0, 'h'.code.toByte(), 0, 'i'.code.toByte())))
        assertNull(atv(0x04, ascii))
    }

    @Test
    fun parseCertDerOrdinary() = Deadline.within {
        val der = c.cert()
        val cert = AttestCert.parseCertDer(der)
        assertArrayEquals(der, cert.raw)
        assertArrayEquals(c.b(1, 2), cert.serial)
        assertTrue(cert.exts.isEmpty())
        // the optional issuer / subject unique IDs ([1] 0x81, [2] 0x82) are each skipped
        val withUids = c.cert(c.tbs(extra = c.tlv(0x81, c.b(0, 1)) + c.tlv(0x82, c.b(0, 2))))
        assertArrayEquals(c.b(1, 2), AttestCert.parseCertDer(withUids).serial)
    }

    private fun ext(oid: String, v: ByteArray) = AttestCert.LenientExt(oid, false, v)

    @Test
    fun issuerLinkOrderingLoops() = Deadline.within {
        // BasicConstraints holding only the pathLen (no cA): inOrder must step past the absent cA tag
        val bcOnlyPath = ext("2.5.29.19", c.seq(c.int(1)))
        val bcBoth = ext("2.5.29.19", c.seq(c.tlv(0x01, c.b(0xff)), c.int(1)))
        val none = ByteArray(0)
        assertTrue(AttestCert.issuerLinkOk(listOf(bcOnlyPath), listOf(bcBoth), c.b(1), none))
        // an AuthorityKeyIdentifier carrying only its serial steps past [0] and [1]
        val akidSerial = ext("2.5.29.35", c.seq(c.tlv(0x82, c.b(5))))
        assertTrue(AttestCert.issuerLinkOk(listOf(akidSerial), emptyList(), c.b(5), none))
        assertFalse(AttestCert.issuerLinkOk(listOf(akidSerial), emptyList(), c.b(6), none))
        val akidKey = ext("2.5.29.35", c.seq(c.tlv(0x80, c.b(1, 2))))
        val skid = ext("2.5.29.14", c.tlv(0x04, c.b(1, 2)))
        val skidOther = ext("2.5.29.14", c.tlv(0x04, c.b(9, 9)))
        assertTrue(AttestCert.issuerLinkOk(listOf(akidKey), listOf(skid), c.b(1), none))
        assertFalse(AttestCert.issuerLinkOk(listOf(akidKey), listOf(skidOther), c.b(1), none))
    }

    @Test
    fun roleInfoAndOidMatch() = Deadline.within {
        val root = g.ecKey("secp256r1")
        val leaf = g.ecKey("secp256r1")
        val der = g.cert("leaf", "root", leaf, root, g.basicConstraints(true, 3), g.keyUsageCertSign())
        val info = AttestDer.readCertRoleInfo(der)
        assertTrue(info.hasBasicConstraints)
        assertTrue(info.ca)
        assertEquals(3, info.pathLen)
        assertTrue(info.hasKeyUsage)
        assertTrue(info.keyCertSign)
        // a 2-byte pathLen exercises the accumulating loop
        val big = AttestDer.readCertRoleInfo(g.cert("leaf", "root", leaf, root, g.basicConstraints(true, 300)))
        assertEquals(300, big.pathLen)
        val plain = AttestDer.readCertRoleInfo(g.cert("leaf", "root", leaf, root))
        assertFalse(plain.hasBasicConstraints)
        assertFalse(plain.hasKeyUsage)
    }

    @Test
    fun tbsExtensionTable() = Deadline.within {
        val tbs = g.roleTbs(g.basicConstraints(true, 1), g.ext("1.3.6.1.4.1.3704.1.4", false, g.bytes(7, 8)), g.keyUsageCertSign())
        val t = AttestDer.parseTbsExtensions(tbs)
        assertEquals(listOf("2.5.29.19", "1.3.6.1.4.1.3704.1.4", "2.5.29.15"), t.oids)
        assertTrue(t.get("2.5.29.19")!!.critical)
        assertFalse(t.get("1.3.6.1.4.1.3704.1.4")!!.critical)
        assertArrayEquals(g.bytes(7, 8), t.get("1.3.6.1.4.1.3704.1.4")!!.value)
        assertNull(t.get("9.9"))
    }
}
