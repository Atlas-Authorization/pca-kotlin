package net.atlasauth.pca.verifier

import java.security.KeyPairGenerator
import java.security.SecureRandom
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Sigstore's certificate-path checks (OpenSSL's issuer / AKI / key-usage rules) and its signature helpers. */
class Kill05SigCertTest {
    private val K = Kill05SigKit
    private val kid = K.b(9, 9, 9, 9)

    /** A JDK-parsed certificate with junk signature: only names and extensions matter. */
    private fun crt(issuer: String, subject: String, exts: List<ByteArray>) = K.x509(K.junk(K.tbs(issuer, subject, K.leafKey.public, K.CA_NB, K.CA_NA, exts)))

    @Test fun akidOkCases() {
        val c = crt("CA", "leaf", listOf(K.aki(kid)))
        assertTrue("same key id", Sigstore.akidOk(c, crt("CA", "CA", listOf(K.ski(kid)))))
        assertFalse("other key id", Sigstore.akidOk(c, crt("CA", "CA", listOf(K.ski(K.b(8, 8))))))
        assertTrue("issuer without SKI", Sigstore.akidOk(c, crt("CA", "CA", emptyList())))
        assertTrue("leaf without AKI", Sigstore.akidOk(crt("CA", "leaf", emptyList()), crt("CA", "CA", listOf(K.ski(kid)))))
        // an AKI naming issuer and serial only (no keyIdentifier): both are the issuer's own, X509_check_akid
        val up = crt("CA", "CA", listOf(K.ski(kid)))
        val serial = up.serialNumber.toByteArray()
        fun aki(name: String, s: ByteArray) = K.ext("2.5.29.35", K.seq(K.tlv(0xa1, K.tlv(0xa4, K.name(name))), K.tlv(0x82, s)))
        assertTrue("issuer and serial match", Sigstore.akidOk(crt("CA", "leaf", listOf(aki("CA", serial))), up))
        assertFalse("other directory name", Sigstore.akidOk(crt("CA", "leaf", listOf(aki("Z", serial))), up))
        assertFalse("other serial", Sigstore.akidOk(crt("CA", "leaf", listOf(aki("CA", K.b(serial[0].toInt() + 1)))), up))
        assertFalse("serial compared with no SKI on the issuer", Sigstore.akidOk(crt("CA", "leaf", listOf(aki("CA", K.b(serial[0].toInt() + 1)))), crt("CA", "CA", emptyList())))
        // the AKI value is not a SEQUENCE / the SKI value is not an OCTET STRING: malformed, not issued
        val akiSet = K.ext("2.5.29.35", K.set(K.tlv(0x80, kid)))
        assertFalse("AKI not a SEQUENCE", Sigstore.akidOk(crt("CA", "leaf", listOf(akiSet)), crt("CA", "CA", listOf(K.ski(kid)))))
        val skiSet = K.ext("2.5.29.14", K.tlv(0x31, kid))
        assertFalse("SKI not an OCTET STRING", Sigstore.akidOk(c, crt("CA", "CA", listOf(skiSet))))
        val akiTruncated = K.ext("2.5.29.35", K.b(0x30, 0x05, 0x80))
        assertFalse("AKI truncated", Sigstore.akidOk(crt("CA", "leaf", listOf(akiTruncated)), crt("CA", "CA", listOf(K.ski(kid)))))
    }

    @Test fun aMalformedCachedExtensionOnEitherCertificateBreaksTheLink() {
        val up = crt("CA", "CA", emptyList())
        val leaf = crt("CA", "leaf", emptyList())
        val bad = K.ext("2.5.29.37", K.seq(K.tlv(0x04, K.b(1))))
        assertTrue(Sigstore.akidOk(leaf, up))
        assertFalse("on the child", Sigstore.akidOk(crt("CA", "leaf", listOf(bad)), up))
        assertFalse("on the issuer", Sigstore.akidOk(leaf, crt("CA", "CA", listOf(bad))))
    }

    @Test fun pkcs1UnderAnRsaPssKey() {
        val pss = KeyPairGenerator.getInstance("RSASSA-PSS").apply { initialize(2048) }.generateKeyPair().public
        val up = K.x509(K.junk(K.tbs("CA", "CA", pss, K.CA_NB, K.CA_NA, emptyList())))
        val plainUp = crt("CA", "CA", emptyList())
        val pkcs1 = K.seq(K.oid("1.2.840.113549.1.1.11"), K.tlv(0x05))
        fun signedWith(alg: ByteArray) = K.x509(K.seq(K.tbs("CA", "leaf", K.leafKey.public, K.CA_NB, K.CA_NA, emptyList(), alg), alg, K.tlv(0x03, K.b(0, 1, 2))))
        assertTrue(Sigstore.pkcs1UnderPss(signedWith(pkcs1), up))
        assertFalse(Sigstore.pkcs1UnderPss(signedWith(pkcs1), plainUp))
        assertFalse(Sigstore.pkcs1UnderPss(signedWith(K.seq(K.oid("1.2.840.113549.1.1.10"))), up))
    }

    @Test fun namedByKeyUsage() {
        val c = crt("CA", "leaf", emptyList())
        assertTrue("keyCertSign", Sigstore.namedBy(c, crt("CA", "CA", listOf(K.ku(2, 0x04)))))
        assertTrue("keyCertSign + cRLSign", Sigstore.namedBy(c, crt("CA", "CA", listOf(K.CA_KU))))
        assertFalse("cRLSign only", Sigstore.namedBy(c, crt("CA", "CA", listOf(K.ku(1, 0x02)))))
        assertFalse("digitalSignature only", Sigstore.namedBy(c, crt("CA", "CA", listOf(K.ku(7, 0x80)))))
        assertTrue("no key usage", Sigstore.namedBy(c, crt("CA", "CA", emptyList())))
        assertFalse("other name", Sigstore.namedBy(c, crt("CA", "Other", emptyList())))
        assertFalse("AKI mismatch", Sigstore.namedBy(crt("CA", "leaf", listOf(K.aki(kid))), crt("CA", "CA", listOf(K.ski(K.b(1))))))
    }

    @Test fun issuedByChecksNames() {
        val misnamed = K.x509(K.cert(K.tbs("Other", "leaf", K.leafKey.public, K.CA_NB, K.CA_NA, emptyList()), K.caKey.private))
        assertFalse(Sigstore.issuedBy(misnamed, K.ca))
        val named = K.x509(K.cert(K.tbs("Test CA", "leaf", K.leafKey.public, K.CA_NB, K.CA_NA, emptyList()), K.caKey.private))
        assertTrue(Sigstore.issuedBy(named, K.ca))
        val other = K.ec()
        val wrongKey = K.x509(K.cert(K.tbs("Test CA", "leaf", K.leafKey.public, K.CA_NB, K.CA_NA, emptyList()), other.private))
        assertFalse(Sigstore.issuedBy(wrongKey, K.ca))
    }

    @Test fun leafIssuedByCases() {
        val der = K.leafDer()
        val c = K.x509(der)
        val pc = Sigstore.parseCert(der)
        assertTrue(Sigstore.leafIssuedBy(c, pc, K.ca))
        // the outer signature AlgorithmIdentifier differs from the TBS one (NULL parameters): refused, though the signature is good
        val tbs = der.copyOfRange(pc.top[0].start, pc.top[0].end)
        val sig = der.copyOfRange(pc.top[2].start, pc.top[2].end)
        val other = Sigstore.parseCert(K.seq(tbs, K.seq(K.oid(K.ECDSA256), K.tlv(0x05)), sig))
        assertFalse(Sigstore.leafIssuedBy(c, other, K.ca))
        // an issuer whose key cannot check this signature (RSA key, ECDSA signature): not issued (no exception)
        val rsa = K.rsa()
        val rsaCa = K.x509(K.cert(K.tbs("Test CA", "Test CA", rsa.public, K.CA_NB, K.CA_NA, emptyList(), K.RSA_ALG), rsa.private, K.RSA_ALG, "SHA256withRSA"))
        assertFalse(Sigstore.leafIssuedBy(c, pc, rsaCa))
        // another CA's name
        assertFalse(Sigstore.leafIssuedBy(c, pc, crt("Other", "Other", emptyList())))
    }

    @Test fun ekuCases() {
        val cs = crt("CA", "leaf", listOf(K.eku(K.EKU_CS)))
        assertTrue(Sigstore.hasEku(cs, K.EKU_CS))
        assertFalse(Sigstore.hasEku(cs, K.EKU_TS))
        assertFalse(Sigstore.hasEku(crt("CA", "leaf", emptyList()), K.EKU_CS))
        // an EKU extension the JDK cannot decode: no EKU (never an exception)
        assertFalse(Sigstore.hasEku(crt("CA", "leaf", listOf(K.ext("2.5.29.37", K.b(0x30, 0x03, 0x06, 0x05, 0x2a)))), K.EKU_CS))
    }

    @Test fun chainNeedsCaFlags() {
        val at = K.IT * 1000
        assertTrue(Sigstore.chainOk(listOf(K.x509(K.leafDer()), K.ca), at))
        assertFalse("outside the leaf validity", Sigstore.chainOk(listOf(K.x509(K.leafDer()), K.ca), at + 2 * K.DAY))
        // a self-signed issuer without basicConstraints cA: not a CA
        val x = K.ec()
        val xDer = K.cert(K.tbs("X", "X", x.public, K.CA_NB, K.CA_NA, emptyList()), x.private)
        val leaf = K.cert(K.tbs("X", "leaf", K.leafKey.public, K.CA_NB, K.CA_NA, emptyList()), x.private)
        assertTrue("the leaf alone", Sigstore.chainOk(listOf(K.x509(xDer)), at))
        assertFalse(Sigstore.chainOk(listOf(K.x509(leaf), K.x509(xDer)), at))
    }

    @Test fun sigOkKeys() {
        val data = K.utf8("data")
        val ec = K.ec()
        assertTrue(Sigstore.sigOk("sha256", ec.public, data, K.sign(ec.private, data)))
        assertTrue(Sigstore.sigOk("sha384", ec.public, data, K.sign(ec.private, data, "SHA384withECDSA")))
        assertFalse(Sigstore.sigOk("sha256", ec.public, K.utf8("other"), K.sign(ec.private, data)))
        val rsa = K.rsa()
        assertTrue(Sigstore.sigOk("sha256", rsa.public, data, K.sign(rsa.private, data, "SHA256withRSA")))
        assertFalse(Sigstore.sigOk("sha256", null, data, K.sign(ec.private, data)))
        val ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        assertFalse(Sigstore.sigOk("sha256", ed.public, data, K.sign(ed.private, data, "Ed25519")))
    }

    @Test fun logSigOkEd25519() {
        val sk = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val pk = ByteArray(32)
        Ed25519.generatePublicKey(sk, 0, pk, 0)
        val data = K.utf8("checkpoint body\n")
        val sig = ByteArray(64)
        Ed25519.sign(sk, 0, data, 0, data.size, sig, 0)
        val log = Sigstore.PinnedLog(K.b(1, 2, 3, 4), null, pk, 0, Long.MAX_VALUE, "n")
        assertTrue(Sigstore.logSigOk(log, data, sig))
        assertFalse("65 bytes", Sigstore.logSigOk(log, data, K.cat(sig, K.b(0))))
        assertFalse("other data", Sigstore.logSigOk(log, K.utf8("x"), sig))
        // a 31-byte key makes the verifier throw: refused, not thrown
        assertFalse(Sigstore.logSigOk(Sigstore.PinnedLog(K.b(1, 2, 3, 4), null, pk.copyOf(31), 0, Long.MAX_VALUE, "n"), data, sig))
        val ec = K.ec()
        val ecLog = Sigstore.PinnedLog(K.b(1, 2, 3, 4), ec.public, null, 0, Long.MAX_VALUE, null)
        assertTrue(Sigstore.logSigOk(ecLog, data, K.sign(ec.private, data)))
        assertEquals(false, Sigstore.logSigOk(ecLog, data, sig))
    }
}
