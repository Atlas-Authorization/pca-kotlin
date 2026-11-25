package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.Kill05CertKit.b
import net.atlasauth.pca.verifier.Kill05CertKit.cat
import net.atlasauth.pca.verifier.Kill05CertKit.elem
import net.atlasauth.pca.verifier.Kill05CertKit.oid
import net.atlasauth.pca.verifier.Kill05CertKit.rdn
import net.atlasauth.pca.verifier.Kill05CertKit.seq
import net.atlasauth.pca.verifier.Kill05CertKit.str
import net.atlasauth.pca.verifier.Kill05CertKit.tlv
import net.atlasauth.pca.verifier.Kill05CertKit.withExts
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AttestCert's name rendering (escapeDnValue, atvString, printable, nameText) and the AIA / EKU extension readers. */
class Kill05CertNameTest {
    @Test
    fun printableIsExactlyTheAsn1PrintableSet() {
        val extra = " '()+,-./:=?*"
        for (c in 0..255) {
            val want = c in 'a'.code..'z'.code || c in 'A'.code..'Z'.code || c in '0'.code..'9'.code || extra.indexOf(c.toChar()) >= 0
            assertEquals("c=$c", want, AttestCert.printable(c))
        }
    }

    private fun atv(tag: Int, vararg v: Int): String? {
        val x = tlv(tag, b(*v))
        return AttestCert.atvString(x, elem(x))
    }

    private fun atvS(tag: Int, s: String): String? {
        val x = str(tag, s)
        return AttestCert.atvString(x, elem(x))
    }

    @Test
    fun atvStringPerTag() {
        // UTF8String
        assertEquals("é€", atv(0x0c, 0xc3, 0xa9, 0xe2, 0x82, 0xac))
        assertEquals("", atv(0x0c))
        // PrintableString: every byte checked, the first and the last included
        assertEquals("Ab0 '()+,-./:=?*", atvS(0x13, "Ab0 '()+,-./:=?*"))
        assertNull(atvS(0x13, "@a"))
        assertNull(atvS(0x13, "a@"))
        assertNull(atvS(0x13, "a&b"))
        assertNull(atv(0x13, 0xc1))
        assertEquals("", atv(0x13))
        // IA5String: below 0x80
        assertEquals("a@~\u007f\u0000", atv(0x16, 0x61, 0x40, 0x7e, 0x7f, 0x00))
        assertNull(atv(0x16, 0x80, 0x61))
        assertNull(atv(0x16, 0x61, 0x80))
        assertNull(atv(0x16, 0x61, 0xff))
        // T61String: Latin-1 bytes as they are
        assertEquals("é\u0001ÿ", atv(0x14, 0xe9, 0x01, 0xff))
        // NumericString: digits and space only
        assertEquals("0123 9", atvS(0x12, "0123 9"))
        assertNull(atvS(0x12, "a1"))
        assertNull(atvS(0x12, "1a"))
        assertNull(atvS(0x12, "1/"))
        assertNull(atvS(0x12, "1:"))
        assertNull(atvS(0x12, "1!"))
        assertNull(atvS(0x12, "\u001f1"))
        // BMPString: UTF-16BE, even length only
        assertEquals("Aé", atv(0x1e, 0x00, 0x41, 0x00, 0xe9))
        assertEquals("ABC", atv(0x1e, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43))
        assertEquals("", atv(0x1e))
        assertNull(atv(0x1e, 0x00, 0x41, 0x00))
        assertNull(atv(0x1e, 0x00))
        // tags the reference cannot read as a string
        assertNull(atv(0x1c, 0x00, 0x00, 0x00, 0x41))
        assertNull(atv(0x03, 0x00, 0x41))
        assertNull(atv(0x30))
        assertNull(atv(0x04, 0x41))
    }

    @Test
    fun escapeDnValueRules() {
        val cases = listOf(
            "plain" to "plain",
            "a,b" to "a\\,b", "a+b" to "a\\+b", "a\"b" to "a\\\"b", "a\\b" to "a\\\\b",
            "a<b" to "a\\<b", "a>b" to "a\\>b", "a;b" to "a\\;b", "a=b" to "a=b",
            " a" to "\\ a", "#a" to "\\#a", "a " to "a\\ ", "a b" to "a b", "a#" to "a#", "a#b" to "a#b",
            " " to "\\ ", "#" to "\\#", "  " to "\\ \\ ", "# " to "\\#\\ ", "a  b" to "a  b",
            "a\u0001b" to "a\\01b", "\u001f" to "\\1F", "\u007f" to "\\7F", "\u0000" to "\\00", "~\u0080" to "~\u0080",
            "😀 " to "😀\\ ", "😀," to "😀\\,", "x😀" to "x😀",
            "" to "",
        )
        for ((input, want) in cases) assertEquals("input=$input", want, AttestCert.escapeDnValue(input))
    }

    @Test
    fun nameTextRendering() {
        fun a(o: String, v: ByteArray) = seq(oid(o), v)
        val name = seq(
            rdn(a("2.5.4.3", str(0x0c, "Common, Name"))),
            rdn(a("2.5.4.10", str(0x13, "Org")), a("2.5.4.11", str(0x13, "Unit"))),
            rdn(a("1.2.3.4", str(0x0c, "x"))),
            rdn(a("1.2.840.113549.1.9.1", str(0x16, "a@b"))),
            rdn(a("0.9.2342.19200300.100.1.25", str(0x16, "dc"))),
        )
        assertEquals("CN=Common\\, Name\nO=Org + OU=Unit\n1.2.3.4=x\nemailAddress=a@b\nDC=dc", AttestCert.nameText(name))
        val keys = listOf(
            "2.5.4.6" to "C", "2.5.4.7" to "L", "2.5.4.8" to "ST", "2.5.4.5" to "serialNumber", "2.5.4.9" to "street",
            "2.5.4.17" to "postalCode", "2.5.4.4" to "SN", "2.5.4.42" to "GN", "2.5.4.12" to "title", "2.5.4.46" to "dnQualifier",
            "0.9.2342.19200300.100.1.1" to "UID",
        )
        for ((o, k) in keys) assertEquals("$k=v", AttestCert.nameText(seq(rdn(a(o, str(0x0c, "v"))))))
        assertEquals("", AttestCert.nameText(seq()))
        assertEquals("CN=a\n", AttestCert.nameText(seq(rdn(a("2.5.4.3", str(0x0c, "a"))), rdn())))
        // unreadable names render as ""
        val ok = rdn(a("2.5.4.3", str(0x0c, "a")))
        assertEquals("", AttestCert.nameText(cat(seq(ok), b(0))))
        assertEquals("", AttestCert.nameText(tlv(0x31, ok)))
        assertEquals("", AttestCert.nameText(seq(ok, seq(a("2.5.4.3", str(0x0c, "b"))))))
        assertEquals("", AttestCert.nameText(seq(ok, rdn(rdn(oid("2.5.4.3"), str(0x0c, "b"))))))
        assertEquals("", AttestCert.nameText(seq(ok, rdn(seq(oid("2.5.4.3"))))))
        assertEquals("", AttestCert.nameText(seq(ok, rdn(seq(oid("2.5.4.3"), str(0x0c, "b"), str(0x0c, "c"))))))
        assertEquals("", AttestCert.nameText(seq(ok, rdn(seq(str(0x0c, "k"), str(0x0c, "b"))))))
        assertEquals("", AttestCert.nameText(seq(ok, rdn(seq(tlv(0x06, b(0x2a, 0x81)), str(0x0c, "b"))))))
        assertEquals("", AttestCert.nameText(seq(ok, rdn(a("2.5.4.3", str(0x13, "b@"))))))
        assertEquals("", AttestCert.nameText(seq(ok, rdn(a("2.5.4.3", tlv(0x04, b(0x41)))))))
        assertEquals("", AttestCert.nameText(b(0x30, 0x05, 0x31)))
        assertEquals("", AttestCert.nameText(b()))
    }

    private val AIA = "1.3.6.1.5.5.7.1.1"
    private val OCSP = "1.3.6.1.5.5.7.48.1"

    private fun aia(value: ByteArray) = withExts(AttestCert.LenientExt(AIA, false, value)).ocspServers()

    @Test
    fun ocspServersReadsOnlyOcspUris() {
        val url = { s: String -> str(0x86, s) }
        val v = seq(
            seq(oid(OCSP), url("http://a/é")),
            seq(oid("1.3.6.1.5.5.7.48.2"), url("http://ca")),
            seq(oid(OCSP), str(0x82, "dns.example")),
            seq(oid(OCSP)),
            seq(oid(OCSP), url("http://c"), url("http://c2")),
            seq(tlv(0x04, oid(OCSP).copyOfRange(2, oid(OCSP).size)), url("http://d")),
            seq(tlv(0x06, b(0x80, 0x01)), url("http://e")),
            tlv(0x04, b(0x01, 0x05)),
            seq(oid(OCSP), url("http://b")),
        )
        assertEquals(listOf("http://a/é", "http://b"), aia(v))
        assertEquals(listOf("http://only"), aia(seq(seq(oid(OCSP), url("http://only")))))
        assertEquals(emptyList<String>(), aia(seq()))
        assertEquals(emptyList<String>(), aia(tlv(0x04, b(1))))
        assertEquals(emptyList<String>(), aia(b()))
        // a child that does not parse spoils the whole list (the children are read before any is used)
        assertEquals(emptyList<String>(), aia(seq(seq(oid(OCSP), url("http://a")), b(0x30, 0x05))))
        assertEquals(emptyList<String>(), withExts().ocspServers())
        assertEquals(emptyList<String>(), withExts(AttestCert.LenientExt("2.5.29.37", false, v)).ocspServers())
        // the first AIA extension is the one read
        val two = withExts(
            AttestCert.LenientExt("2.5.29.15", true, b(1)),
            AttestCert.LenientExt(AIA, false, seq(seq(oid(OCSP), url("http://first")))),
            AttestCert.LenientExt(AIA, false, seq(seq(oid(OCSP), url("http://second")))),
        )
        assertEquals(listOf("http://first"), two.ocspServers())
        assertArrayEquals(b(1), two.extValue("2.5.29.15"))
        assertNull(two.extValue("2.5.29.16"))
    }

    @Test
    fun ocspSigningEku() {
        val eku = "2.5.29.37"
        fun has(value: ByteArray) = withExts(AttestCert.LenientExt(eku, false, value)).hasOcspSigningEku()
        assertTrue(has(seq(oid("1.3.6.1.5.5.7.3.1"), oid("1.3.6.1.5.5.7.3.9"))))
        assertTrue(has(seq(oid("1.3.6.1.5.5.7.3.9"))))
        assertTrue(has(seq(tlv(0x06, b(0x80, 0x01)), oid("1.3.6.1.5.5.7.3.9"))))
        assertTrue(has(seq(int(), oid("1.3.6.1.5.5.7.3.9"))))
        assertFalse(has(seq(oid("1.3.6.1.5.5.7.3.1"))))
        assertFalse(has(seq(oid("1.3.6.1.5.5.7.3.2"), oid("1.3.6.1.5.5.7.3.1"))))
        assertFalse(has(seq()))
        assertFalse(has(tlv(0x04, oid("1.3.6.1.5.5.7.3.9"))))
        assertFalse(has(cat(b(0x30, 0x05), oid("1.3.6.1.5.5.7.3.9"))))
        assertFalse(withExts().hasOcspSigningEku())
        assertFalse(withExts(AttestCert.LenientExt("2.5.29.15", false, seq(oid("1.3.6.1.5.5.7.3.9")))).hasOcspSigningEku())
    }

    private fun int(): ByteArray = tlv(0x02, b(1))
}
