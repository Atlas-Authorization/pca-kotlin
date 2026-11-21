package net.atlasauth.pca.verifier

import java.security.interfaces.RSAPublicKey
import net.atlasauth.pca.verifier.Kill05CertKit.UNSUPPORTED
import net.atlasauth.pca.verifier.Kill05CertKit.b
import net.atlasauth.pca.verifier.Kill05CertKit.cat
import net.atlasauth.pca.verifier.Kill05CertKit.cert
import net.atlasauth.pca.verifier.Kill05CertKit.elem
import net.atlasauth.pca.verifier.Kill05CertKit.err
import net.atlasauth.pca.verifier.Kill05CertKit.oid
import net.atlasauth.pca.verifier.Kill05CertKit.rsa
import net.atlasauth.pca.verifier.Kill05CertKit.seq
import net.atlasauth.pca.verifier.Kill05CertKit.tlv
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Round-2 kills for AttestCert / AttestXml (shard 12 of full run 41911466407). A Kotlin `when` over strings switches on
 * hashCode and then checks equals: each "colliding" input below has the same String.hashCode as the real constant
 * (asserted), so only the equals check keeps it out of that arm.
 */
class Kill05R2AttestTest {
    private val noStart = "error:0480006C:PEM routines::no start line"

    @Test
    fun pemBeginMarkerIsAWholeLine() {
        val d1 = cert()
        val b64 = java.util.Base64.getEncoder().encodeToString(d1)
        val end = "\n-----END CERTIFICATE-----"
        // the body's first character is significant: none of it may be skipped
        assertArrayEquals(d1, AttestCert.certFromPem("-----BEGIN CERTIFICATE-----\n$b64$end").raw)
        assertArrayEquals(d1, AttestCert.certFromPem("-----BEGIN CERTIFICATE----- \t\r\n$b64$end").raw)
        assertArrayEquals(d1, AttestCert.certFromPem("x\n-----BEGIN CERTIFICATE-----\n$b64$end").raw)
        // OpenSSL (the reference's X509Certificate) and Go's pem.Decode read BEGIN as a whole line
        assertEquals(noStart, err { AttestCert.certFromPem("-----BEGIN CERTIFICATE-----$b64$end") })
        assertEquals(noStart, err { AttestCert.certFromPem("x-----BEGIN CERTIFICATE-----\n$b64$end") })
        // a bad BEGIN line is passed over and the next good one read
        assertArrayEquals(d1, AttestCert.certFromPem("-----BEGIN CERTIFICATE-----junk\n-----BEGIN CERTIFICATE-----\n$b64$end").raw)
    }

    @Test
    fun validOidLooksAtTheContentStartNotTheLengthByte() {
        // 128 content bytes: the long-form length's last byte (0x80) has its top bit set, like a continuation byte would
        val badStart = cat(b(0x06, 0x81, 0x80, 0x80), ByteArray(127) { 1 })
        assertFalse(AttestCert.validOid(badStart, elem(badStart)))
        val ok = cat(b(0x06, 0x81, 0x80, 0x2a), ByteArray(127) { 1 })
        assertTrue(AttestCert.validOid(ok, elem(ok)))
    }

    @Test
    fun goCurveNameMatchesTheWholeName() {
        for ((real, fake) in listOf("prime256v1" to "qSime256v1", "secp384r1" to "tFcp384r1", "secp521r1" to "tFcp521r1", "secp224r1" to "tFcp224r1")) {
            assertEquals(real.hashCode(), fake.hashCode())
            assertEquals(fake, AttestCert.goCurveName(AttestCert.CertKey(null, "ec", fake, ByteArray(0))))
        }
    }

    @Test
    fun keyOfSpkiMatchesTheWholeOid() {
        val rp = rsa.public as RSAPublicKey
        val pkcs1 = seq(tlv(0x02, rp.modulus.toByteArray()), tlv(0x02, rp.publicExponent.toByteArray()))
        val ed = ByteArray(32) { 1 }
        val ecSpki = Kill05CertKit.p256.public.encoded
        val ecBits = AttestCert.readElem(ecSpki, 0, ecSpki.size, 0x30).let { s -> AttestCert.kids(ecSpki, s)[1] }.let { ecSpki.copyOfRange(it.start + 1, it.end) }
        fun spki(o: String, bits: ByteArray) = seq(seq(oid(o)), tlv(0x03, b(0), bits))
        // controls: the real OIDs take these exact keys
        assertEquals("rsa", AttestCert.keyOfSpki(spki("1.2.840.113549.1.1.1", pkcs1)).typ)
        assertEquals("rsa-pss", AttestCert.keyOfSpki(spki("1.2.840.113549.1.1.10", pkcs1)).typ)
        assertEquals("ed25519", AttestCert.keyOfSpki(spki("1.3.101.112", ed)).typ)
        assertEquals("ec", AttestCert.keyOfSpki(ecSpki).typ)
        val cases = listOf(
            Triple("1.2.840.113549.1.1.1", "1.2.3.101902581455", pkcs1),
            Triple("1.2.840.113549.1.1.10", "1.2.3.100440577593", pkcs1),
            Triple("1.3.101.112", "1.2.3.101519670185", ed),
            Triple("1.2.840.10045.2.1", "1.2.3.100908485960", ecBits),
        )
        for ((real, fake, bits) in cases) {
            assertEquals(real.hashCode(), fake.hashCode())
            assertEquals(fake, UNSUPPORTED, err { AttestCert.keyOfSpki(spki(fake, bits)) })
        }
    }

    @Test
    fun xmlNamedEntitiesMatchTheWholeName() {
        for ((real, fake) in listOf("lt" to "mU", "gt" to "hU", "amp" to "bNp", "quot" to "rVot", "apos" to "bQos")) {
            assertEquals(real.hashCode(), fake.hashCode())
            assertEquals("undefined entity &$fake;", err { AttestXml.decode("&$fake;") })
        }
        assertEquals("\t\n\r", AttestXml.decode("&#9;&#xa;&#13;"))
    }
}
