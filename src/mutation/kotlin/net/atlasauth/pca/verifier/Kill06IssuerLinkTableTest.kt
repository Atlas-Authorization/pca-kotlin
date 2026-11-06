package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.Kill05CertKit.b
import net.atlasauth.pca.verifier.Kill05CertKit.cn
import net.atlasauth.pca.verifier.Kill05CertKit.tlv
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * X509_check_issued over extensions on both certificates. Verdicts read from Node 26 (`checkIssued`) on really signed P-384
 * certificates built byte for byte like these; signatures play no part in the check itself. Some false rows are ones Node takes and this SDK refuses on purpose.
 */
class Kill06IssuerLinkTableTest {
    private val K = Kill05CertKit
    private val keyid = ByteArray(20) { 1 }
    private val skid = AttestCert.LenientExt("2.5.29.14", false, tlv(0x04, keyid))
    private class R(val last: Int, val v: ByteArray, val want: Boolean)

    private fun u8(s: String) = tlv(0x0c, s.toByteArray())
    private val uri = tlv(0x86, "https://a".toByteArray())
    private val cnOid = tlv(0x06, b(0x55, 4, 3))
    private fun oidB(x: ByteArray) = tlv(0x06, x)
    private fun rdnOf(vararg a: ByteArray) = tlv(0x31, *a)
    private fun atvOf(vararg a: ByteArray) = tlv(0x30, *a)
    private fun nm(vararg r: ByteArray) = tlv(0x30, *r)
    private fun vl(tag: Int, vararg bytes: Int) = nm(rdnOf(atvOf(cnOid, tlv(tag, b(*bytes)))))
    private fun dir(n: ByteArray) = tlv(0xa4, n)
    private val g = tlv(0x82, "a".toByteArray())
    private val gb = tlv(0x82, "b".toByteArray())
    private fun oth(vararg a: ByteArray) = tlv(0xa0, cnOid, *a)
    private fun other(vararg a: ByteArray) = tlv(0xa0, *a)
    private fun ext(last: Int, v: ByteArray) = AttestCert.LenientExt("2.5.29.$last", false, v)

    private fun ca(vararg exts: AttestCert.LenientExt): AttestCert.Cert {
        val e = exts.map { K.ext(it.oid, null, it.value) }.toTypedArray()
        val extra = if (e.isEmpty()) ByteArray(0) else K.exts(*e)
        return AttestCert.parseCertDer(K.cert(K.tbs(serial = K.int(1), issuer = cn("root"), subject = cn("mid"), extra = extra)))
    }

    private fun issued(childExts: List<AttestCert.LenientExt>, up: AttestCert.Cert) = AttestCert.checkIssued(
        AttestCert.Cert(b(), b(), up.rawSubject, b(), b(), b(1), "1.2", null, b(), childExts), up,
    )

    private fun withNames(vararg gn: ByteArray) =
        issued(listOf(AttestCert.LenientExt("2.5.29.35", false, tlv(0x30, tlv(0x80, keyid), tlv(0xa1, *gn)))), ca(skid))

    private fun later(n: ByteArray) = withNames(dir(cn("root")), dir(n))

    @Test fun aLaterDirectoryNameDecodesInFull() {
        assertTrue(withNames(dir(cn("root"))))
        assertFalse(withNames(dir(cn("other"))))
        for ((i, d) in listOf(
        nm(),
        nm(rdnOf()),
        cn("later"),
        vl(0x0c),
        vl(0x13, 0xc3, 0xa9),
        vl(0x16, 0xe9),
        vl(0x14, 0xe9),
        nm(rdnOf(atvOf(oidB(b(0x55, 4, 6)), u8("b")), atvOf(cnOid, u8("a")))),
        nm(rdnOf(atvOf(cnOid, u8("a"))), rdnOf(atvOf(cnOid, u8("b")))),
        ).withIndex()) assertTrue("good $i", later(d))
        for ((i, d) in listOf(
        nm(tlv(0x30)),
        nm(rdnOf(tlv(0x04, b(1)))),
        nm(rdnOf(atvOf(cnOid))),
        nm(rdnOf(atvOf())),
        nm(rdnOf(atvOf(tlv(0x04, b(1)), u8("x")))),
        nm(rdnOf(atvOf(cnOid, u8("x"), u8("y")))),
        nm(rdnOf(atvOf(tlv(0x06), u8("x")))),
        nm(rdnOf(atvOf(tlv(0x06, b(0x80, 1)), u8("x")))),
        nm(rdnOf(atvOf(tlv(0x06, b(0x55, 0x84)), u8("x")))),
        nm(rdnOf(atvOf(tlv(0x06, b(0x55, 0x80, 1)), u8("x")))),
        vl(0x02, 1),
        vl(0x05),
        vl(0x0c, 0xc3, 0x28),
        vl(0x1e, 0, 0x41, 0),
        vl(0x1c, 0, 0, 0x41),
        nm(rdnOf(b(0x30, 0x09, 6, 3, 0x55, 4, 3, 0x0c, 9, 0x61, 0x61))),
        nm(rdnOf(atvOf(cnOid, u8("x")), tlv(0x04, b(1)))),
        nm(rdnOf(atvOf(cnOid, tlv(0x30)))),
        vl(0x1e, 0, 0x41),
        ).withIndex()) assertFalse("bad $i", later(d))
    }

    @Test fun everyGeneralNameDecodes() {
        for ((i, x) in listOf(
        other(cnOid, tlv(0xa0, u8("x"))),
        tlv(0x81, b(0xe9)),
        tlv(0x82, b(0xe9)),
        tlv(0x82),
        tlv(0x86, b(0xe9)),
        tlv(0x87, b(1, 2, 3)),
        tlv(0x87),
        ).withIndex()) assertTrue("good $i", withNames(x, dir(cn("root"))))
        for ((i, x) in listOf(
        other(tlv(0x04, b(1))),
        other(),
        other(cnOid),
        other(tlv(0x04, b(1)), tlv(0xa0, u8("x"))),
        tlv(0x88),
        tlv(0x88, b(0x80, 1)),
        tlv(0xa5),
        tlv(0xa5, tlv(0x04, b(1))),
        tlv(0xa4),
        tlv(0x83, b(1)),
        tlv(0x84, b(1)),
        tlv(0x85, b(1)),
        tlv(0xa8),
        tlv(0x88, b(0x55, 4, 3)),
        tlv(0xa3),
        tlv(0xa3, tlv(0x02, b(1))),
        tlv(0xa5, tlv(0xa1, u8("x"))),
        tlv(0xa2, tlv(0x16, b(0x41))),
        tlv(0xa6),
        tlv(0xa7),
        tlv(0xa1),
        ).withIndex()) assertFalse("bad $i", withNames(x, dir(cn("root"))))
    }

    private fun rows0() = listOf(
        R(0x13, tlv(0x30), true),
        R(0x13, tlv(0x30, tlv(0x01, b(255))), true),
        R(0x13, tlv(0x30, tlv(0x01, b(0x55))), true),
        R(0x13, tlv(0x30, tlv(0x01, b(0))), true),
        R(0x13, tlv(0x30, tlv(0x01, b(255)), tlv(0x02, b(1))), true),
        R(0x13, tlv(0x30, tlv(0x02, b(1))), true),
        R(0x13, tlv(0x30) + b(5, 0), true),
        R(0x13, tlv(0x30, tlv(0x02, b(1)), tlv(0x01, b(255))), false),
        R(0x13, tlv(0x30, tlv(0x01, b(255, 255))), false),
        R(0x13, tlv(0x30, tlv(0x01)), false),
        R(0x13, tlv(0x30, tlv(0x01, b(255)), tlv(0x02, b(0, 1))), false),
        R(0x13, tlv(0x30, tlv(0x01, b(255)), tlv(0x02)), false),
        R(0x13, tlv(0x30, tlv(0x01, b(255)), tlv(0x02, b(0xff))), false),
        R(0x13, tlv(0x30, tlv(0x01, b(255)), tlv(0x02, b(1)), tlv(0x05)), false),
        R(0x13, tlv(0x04, b(1)), false),
        R(0x0f, tlv(0x03), false),
        R(0x0f, tlv(0x03, b(0)), false),
        R(0x0f, tlv(0x03, b(8, 0xa0)), false),
        R(0x0f, tlv(0x04, b(0)), false),
        R(0x0f, b(3, 5, 0), false),
        R(0x0f, b(), false),
        R(0x25, tlv(0x30, oidB(b(0x2b, 6, 1, 5, 5, 7, 3, 1))), true),
        R(0x25, tlv(0x30), true),
        R(0x25, tlv(0x30, tlv(0x04, b(1))), false),
        R(0x25, tlv(0x30, tlv(0x06, b(0x80, 1))), false),
        R(0x25, tlv(0x04, b(1)), false),
        R(0x11, tlv(0x30, uri), true),
        R(0x11, tlv(0x30), true),
        R(0x11, tlv(0x30, uri) + b(5, 0), true),
        R(0x11, tlv(0x30, oth(tlv(0xa0, u8("x")))), true),
        R(0x11, tlv(0x30, oth(tlv(0xa0, u8("x"), u8("y")))), false),
        R(0x11, tlv(0x30, oth(tlv(0xa0))), false),
        R(0x11, tlv(0x30, oth(tlv(0xa0, u8("x")), tlv(0x05))), false),
        R(0x11, tlv(0x30, oth(tlv(0xa1, u8("x")))), false),
        R(0x11, tlv(0x30, tlv(0x89, b(1))), false),
        R(0x11, tlv(0x30, tlv(0xa4, tlv(0x04, b(1)))), false),
        R(0x11, tlv(0x04, b(1)), false),
        R(0x1e, tlv(0x30, tlv(0xa0, tlv(0x30, g))), true),
        R(0x1e, tlv(0x30), true),
        R(0x1e, tlv(0x30, tlv(0xa0, tlv(0x30, g)), tlv(0xa1, tlv(0x30, gb))), true),
    )
    private fun rows1() = listOf(
        R(0x1e, tlv(0x30, tlv(0xa0)), true),
        R(0x1e, tlv(0x30, tlv(0xa0, tlv(0x30, g, tlv(0x80, b(0)), tlv(0x81, b(1))))), true),
        R(0x1e, tlv(0x30, tlv(0xa1, tlv(0x30, gb)), tlv(0xa0, tlv(0x30, g))), false),
        R(0x1e, tlv(0x30, tlv(0xa0, tlv(0x04, b(1)))), false),
        R(0x1e, tlv(0x30, tlv(0xa0, tlv(0x30))), false),
        R(0x1e, tlv(0x30, tlv(0xa0, tlv(0x30, g, tlv(0x81, b(1)), tlv(0x80, b(0))))), false),
        R(0x1e, tlv(0x30, tlv(0xa0, tlv(0x30, g, tlv(0x80, b(0, 1))))), false),
        R(0x1e, tlv(0x30, tlv(0x80, b(1))), false),
        R(0x1e, tlv(0x30, tlv(0xa0, tlv(0x30, g, gb))), false),
        R(0x1e, tlv(0x30, tlv(0xa0, g)), false),
        R(0x1e, tlv(0x30, tlv(0xa0, tlv(0x30, g, tlv(0x80, b(0xff))))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, uri)))), true),
        R(0x1f, tlv(0x30), true),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa1, atvOf(cnOid, u8("x")))))), true),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa2, uri))), true),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, uri)), tlv(0x81, b(1, 0x80)))), true),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, uri)), tlv(0x81, b(0)))), true),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0)))), true),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa1)))), true),
        R(0x1f, tlv(0x30, tlv(0x30)), false),
        R(0x1f, tlv(0x30, tlv(0x04, b(1))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa1, tlv(0x04, b(1)))))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0x81, b(1, 0x80)))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa2, tlv(0x89, b(1))))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa2))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa2, uri), tlv(0xa0, tlv(0xa0, uri)))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa2, uri)))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, uri), tlv(0xa0, uri)))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, tlv(0x89, b(1)))))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, uri)), tlv(0x81, b(8, 0x80)))), false),
        R(0x1f, tlv(0x30, tlv(0x30, tlv(0xa0, tlv(0xa0, uri)), tlv(0x81))), false),
    )

    @Test fun aCachedExtensionDecodesOnBothCertificates() {
        for ((i, r) in (rows0() + rows1()).withIndex()) {
            val e = ext(r.last, r.v)
            assertEquals("child row $i", r.want, issued(listOf(e), ca(skid)))
            assertEquals("issuer row $i", r.want, issued(emptyList(), ca(skid, e)))
        }
    }

    @Test fun keyUsageRefusesOnlyOnTheIssuerAndOnlyWithoutKeyCertSign() {
        val noSign = ext(0x0f, tlv(0x03, b(5, 0xa0)))
        assertTrue(issued(listOf(noSign), ca(skid)))
        assertFalse(issued(emptyList(), ca(skid, noSign)))
        assertTrue(issued(emptyList(), ca(skid, ext(0x0f, tlv(0x03, b(2, 0x04))))))
    }

    @Test fun aProxyCertInfoAndARepeatedUnknownExtensionAreRefused() {
        val pci = AttestCert.LenientExt("1.3.6.1.5.5.7.1.14", false, tlv(0x30, tlv(0x30, tlv(0x06, b(0x2b, 6, 1, 5, 5, 7, 21, 1)))))
        assertFalse(issued(listOf(pci), ca(skid)))
        assertFalse(issued(emptyList(), ca(skid, pci)))
        val unknown = ext(0x63, b(1))
        assertFalse(issued(listOf(unknown, unknown), ca(skid)))
        assertFalse(issued(emptyList(), ca(skid, unknown, unknown)))
    }

    /** A very deep document is an ordinary refusal on every JSON path, never a StackOverflowError. */
    @Test fun deepJsonIsRefusedNotACrash() {
        val deep = "[".repeat(1_000_000)
        for (parse in listOf<(String) -> Any?>(Json::parse, Json::parseLenient)) {
            try {
                parse(deep)
                assertTrue("accepted", false)
            } catch (e: IllegalArgumentException) {
                assertTrue(e.message!!.isNotEmpty())
            }
        }
    }
}
