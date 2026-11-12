package net.atlasauth.pca.verifier

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/** Full run 42421378893, group D: the survivors of the Attest* verifier files that an input can observe. */
class Kill07DAttestTest {
    /**
     * nextUpdate is `[0] EXPLICIT GeneralizedTime`: exactly one child, and that child must BE a GeneralizedTime (tag 0x18).
     * A different string type holding well-formed GeneralizedTime text is not a time (RFC 6960 4.2.1); without the tag test
     * ocspTimeMs would parse the text and the response would be accepted with that nextUpdate.
     */
    @Test
    fun nextUpdateWrapsOneGeneralizedTime() = nv {
        val badNext = "OCSP response rejected: nextUpdate is malformed"
        fun s(next: ByteArray) = ocspWhy(ocsp(single(next = next)))
        val txt = genText(NOW + DAY)
        assertEquals("OK:good", s(tlv(0xa0, gen(NOW + DAY))))
        assertEquals(badNext, s(tlv(0xa0, text(0x16, txt)))) // IA5String
        assertEquals(badNext, s(tlv(0xa0, text(0x13, txt)))) // PrintableString
        assertEquals(badNext, s(tlv(0xa0, octets(txt.toByteArray(Charsets.ISO_8859_1))))) // OCTET STRING
    }

    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    /**
     * Multi-byte positive INTEGERs whose first byte is neither 0x00 nor 0xff and whose second byte has its high bit set are
     * valid minimal encodings (0x0180 = 384): only a leading 0x00 before a clear bit or a leading 0xff before a set bit is
     * redundant.
     */
    @Test
    fun derSigAcceptsPositiveIntegersWithAHighSecondByte() {
        val p = AttestUtil.parseDerSig(b(0x30, 7, 2, 2, 0x01, 0x80, 2, 1, 2))
        assertNotNull(p)
        assertEquals(BigInteger.valueOf(0x0180), p!!.first)
        assertEquals(BigInteger.valueOf(2), p.second)
        val q = AttestUtil.parseDerSig(b(0x30, 7, 2, 1, 5, 2, 2, 0x7f, 0xff))
        assertNotNull(q)
        assertEquals(BigInteger.valueOf(5), q!!.first)
        assertEquals(BigInteger.valueOf(0x7fff), q.second)
        val r = AttestUtil.parseDerSig(b(0x30, 9, 2, 3, 0x40, 0xff, 0x80, 2, 2, 0x12, 0x80))
        assertNotNull(r)
        assertEquals(BigInteger.valueOf(0x40ff80), r!!.first)
        assertEquals(BigInteger.valueOf(0x1280), r.second)
    }
}
