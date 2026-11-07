package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import net.atlasauth.pca.verifier.Kill05CertKit.NESTED
import net.atlasauth.pca.verifier.Kill05CertKit.UNSUPPORTED
import net.atlasauth.pca.verifier.Kill05CertKit.b
import net.atlasauth.pca.verifier.Kill05CertKit.cat
import net.atlasauth.pca.verifier.Kill05CertKit.err
import net.atlasauth.pca.verifier.Kill05CertKit.int
import net.atlasauth.pca.verifier.Kill05CertKit.oid
import net.atlasauth.pca.verifier.Kill05CertKit.rsa
import net.atlasauth.pca.verifier.Kill05CertKit.seq
import net.atlasauth.pca.verifier.Kill05CertKit.signed
import net.atlasauth.pca.verifier.Kill05CertKit.tlv
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** AttestCert's keys (curve naming, PKCS#1, SPKI kinds, EC points) and certificate signature checks. */
class Kill05CertKeyTest {
    private val rsaPub get() = rsa.public as RSAPublicKey

    private fun pkcs1(n: ByteArray, e: ByteArray) = seq(tlv(0x02, n), tlv(0x02, e))

    private fun spki(algOid: String, bits: ByteArray, vararg params: ByteArray) = seq(seq(oid(algOid), *params), tlv(0x03, b(0), bits))

    // ---- the curve naming bug: a key on a non-NIST curve with a NIST-sized group order must not be named after the NIST curve ----

    @Test
    fun brainpoolP384IsNotSecp384r1() {
        val kp = Kill05CertKit.ecBc("brainpoolP384r1")
        val k = AttestCert.keyOfSpki(kp.public.encoded)
        assertEquals("ec", k.typ)
        assertEquals("unknown", k.curve)
        assertNotEquals("P-384", AttestCert.goCurveName(k))
        assertEquals("public key is not on P-384 (got unknown)", err { AttestCert.ecPointOfKey(k, "P-384") })
        assertEquals("unknown", AttestCert.keyInfoOf(kp.public, kp.public.encoded).curve)
        for (c in listOf("brainpoolP256r1", "secp256k1", "brainpoolP512r1")) {
            assertEquals(c, "unknown", AttestCert.keyInfoOf(Kill05CertKit.ecBc(c).public, ByteArray(0)).curve)
        }
    }

    @Test
    fun nistCurvesAreNamedExactly() {
        val cases = listOf(
            Triple("secp256r1", "prime256v1", "P-256"),
            Triple("secp384r1", "secp384r1", "P-384"),
            Triple("secp521r1", "secp521r1", "P-521"),
        )
        for ((jca, ossl, go) in cases) {
            val kp = Kill05CertKit.ec(jca)
            val k = AttestCert.keyOfSpki(kp.public.encoded)
            assertEquals(jca, ossl, k.curve)
            assertEquals(jca, go, AttestCert.goCurveName(k))
            assertArrayEquals(kp.public.encoded, k.spki)
            assertNull(k.rawKey)
        }
        val p224 = Kill05CertKit.ecBc("secp224r1")
        assertEquals("secp224r1", AttestCert.keyInfoOf(p224.public, ByteArray(0)).curve)
        assertEquals("P-224", AttestCert.goCurveName(AttestCert.keyInfoOf(p224.public, ByteArray(0))))
        // BouncyCastle's own key objects for NIST curves are named the same way
        assertEquals("secp384r1", AttestCert.keyInfoOf(Kill05CertKit.ecBc("secp384r1").public, ByteArray(0)).curve)
    }

    @Test
    fun curveNameNeedsEveryDomainParameter() {
        val p = AttestUtil.curveParams("secp256r1")!!
        assertEquals("prime256v1", AttestCert.curveOpenSslName(p))
        val c = p.curve
        val prime = (c.field as java.security.spec.ECFieldFp).p
        val negG = ECPoint(p.generator.affineX, prime.subtract(p.generator.affineY))
        assertEquals("unknown", AttestCert.curveOpenSslName(ECParameterSpec(c, p.generator, p.order, 2)))
        assertEquals("unknown", AttestCert.curveOpenSslName(ECParameterSpec(c, negG, p.order, 1)))
        assertEquals("unknown", AttestCert.curveOpenSslName(ECParameterSpec(c, p.generator, p.order.add(BigInteger.valueOf(2)), 1)))
        assertEquals("unknown", AttestCert.curveOpenSslName(ECParameterSpec(EllipticCurve(c.field, c.a, c.b.add(BigInteger.ONE)), p.generator, p.order, 1)))
        for ((jca, ossl) in listOf("secp384r1" to "secp384r1", "secp521r1" to "secp521r1", "secp224r1" to "secp224r1")) {
            assertEquals(ossl, AttestCert.curveOpenSslName(AttestUtil.curveParams(jca)!!))
        }
    }

    @Test
    fun goCurveNameAndKeyInfoKinds() {
        fun key(curve: String) = AttestCert.CertKey(null, "ec", curve, ByteArray(0))
        assertEquals("P-256", AttestCert.goCurveName(key("prime256v1")))
        assertEquals("P-384", AttestCert.goCurveName(key("secp384r1")))
        assertEquals("P-521", AttestCert.goCurveName(key("secp521r1")))
        assertEquals("P-224", AttestCert.goCurveName(key("secp224r1")))
        assertEquals("zzz", AttestCert.goCurveName(key("zzz")))
        assertEquals("", AttestCert.goCurveName(key("")))
        val r = AttestCert.keyInfoOf(rsa.public, b(7))
        assertEquals(listOf("rsa", ""), listOf(r.typ, r.curve))
        assertSame(rsa.public, r.pub)
        assertArrayEquals(b(7), r.spki)
        val ed = AttestCert.keyInfoOf(Kill05CertKit.ed.public, b(8))
        assertEquals(listOf("unknown", ""), listOf(ed.typ, ed.curve))
        assertSame(Kill05CertKit.ed.public, ed.pub)
        assertArrayEquals(b(8), ed.spki)
        val ec = AttestCert.keyInfoOf(Kill05CertKit.p256.public, b(9))
        assertEquals(listOf("ec", "prime256v1"), listOf(ec.typ, ec.curve))
        assertSame(Kill05CertKit.p256.public, ec.pub)
        assertArrayEquals(b(9), ec.spki)
        assertNull(ec.rawKey)
    }

    // ---- PKCS#1 RSAPublicKey ----

    @Test
    fun parsePkcs1Rules() {
        val n = rsaPub.modulus.toByteArray() // leading 0x00: the modulus' top bit is set
        assertEquals(0, n[0].toInt())
        fun p(x: ByteArray): String = err { AttestCert.parsePkcs1(x) }
        val k = AttestCert.parsePkcs1(pkcs1(n, b(0x01, 0x00, 0x01)))
        assertEquals(rsaPub.modulus, k.modulus)
        assertEquals(BigInteger.valueOf(65537), k.publicExponent)
        assertEquals(BigInteger.valueOf(3), AttestCert.parsePkcs1(pkcs1(n, b(0x03))).publicExponent)
        assertEquals(BigInteger.valueOf(0x7fffffffL), AttestCert.parsePkcs1(pkcs1(n, b(0x7f, 0xff, 0xff, 0xff))).publicExponent)
        assertEquals(BigInteger.valueOf(0x81L), AttestCert.parsePkcs1(pkcs1(n, b(0x00, 0x81))).publicExponent)
        assertEquals(UNSUPPORTED, p(pkcs1(n, b(0x00, 0x80, 0x00, 0x00, 0x01)))) // 2^31 + 1: 32 bits
        assertEquals(UNSUPPORTED, p(pkcs1(n, b(0x00, 0x7f)))) // non-minimal
        assertEquals(UNSUPPORTED, p(pkcs1(n, b(0x00, 0x03))))
        assertEquals(UNSUPPORTED, p(pkcs1(n, b(0x00))))
        assertEquals(UNSUPPORTED, p(pkcs1(n, b(0x81)))) // negative
        assertEquals(UNSUPPORTED, p(pkcs1(n, b())))
        assertEquals(UNSUPPORTED, p(pkcs1(n.copyOfRange(1, n.size), b(0x03)))) // negative modulus
        assertEquals(UNSUPPORTED, p(pkcs1(cat(b(0x00), n), b(0x03)))) // non-minimal modulus
        assertEquals(UNSUPPORTED, p(pkcs1(b(0x00), b(0x03))))
        assertEquals(UNSUPPORTED, p(pkcs1(b(), b(0x03))))
        assertEquals(UNSUPPORTED, p(pkcs1(b(0x7f), b(0x03)))) // far below the KeyFactory minimum
        assertEquals(UNSUPPORTED, p(tlv(0x31, tlv(0x02, n), tlv(0x02, b(3)))))
        assertEquals(UNSUPPORTED, p(cat(pkcs1(n, b(3)), b(0))))
        assertEquals(UNSUPPORTED, p(seq(tlv(0x04, n), tlv(0x02, b(3)))))
        assertEquals(UNSUPPORTED, p(seq(tlv(0x02, n), tlv(0x04, b(3)))))
        assertEquals(UNSUPPORTED, p(seq(tlv(0x02, n), tlv(0x02, b(3)), tlv(0x02, b(3)))))
    }

    // ---- SubjectPublicKeyInfo kinds ----

    @Test
    fun keyOfSpkiKinds() {
        val r = AttestCert.keyOfSpki(rsa.public.encoded)
        assertEquals(listOf("rsa", ""), listOf(r.typ, r.curve))
        assertEquals(rsaPub.modulus, (r.pub as RSAPublicKey).modulus)
        assertArrayEquals(rsa.public.encoded, r.spki)

        val pkcs = pkcs1(rsaPub.modulus.toByteArray(), rsaPub.publicExponent.toByteArray())
        val pssSpki = spki("1.2.840.113549.1.1.10", pkcs)
        val pss = AttestCert.keyOfSpki(pssSpki)
        assertEquals(listOf("rsa-pss", ""), listOf(pss.typ, pss.curve))
        assertEquals(rsaPub.modulus, (pss.pub as RSAPublicKey).modulus)
        assertArrayEquals(pssSpki, pss.spki)
        assertNull(pss.rawKey)

        val edEnc = Kill05CertKit.ed.public.encoded
        val ed = AttestCert.keyOfSpki(edEnc)
        assertEquals(listOf("ed25519", ""), listOf(ed.typ, ed.curve))
        assertNull(ed.pub)
        assertArrayEquals(edEnc.copyOfRange(edEnc.size - 32, edEnc.size), ed.rawKey)
        assertArrayEquals(edEnc, ed.spki)
        assertEquals(UNSUPPORTED, err { AttestCert.keyOfSpki(spki("1.3.101.112", ByteArray(31))) })
        assertEquals(UNSUPPORTED, err { AttestCert.keyOfSpki(spki("1.3.101.112", ByteArray(33))) })
        assertEquals("ed25519", AttestCert.keyOfSpki(spki("1.3.101.112", ByteArray(32) { 1 })).typ)

        assertEquals(UNSUPPORTED, err { AttestCert.keyOfSpki(spki("1.2.840.10040.4.1", pkcs)) })
        assertEquals(UNSUPPORTED, err { AttestCert.keyOfSpki(spki("1.3.101.113", ByteArray(57))) })
        assertEquals(NESTED, err { AttestCert.keyOfSpki(seq(seq(oid("1.3.101.112")))) })
        assertEquals(NESTED, err { AttestCert.keyOfSpki(seq(seq(oid("1.3.101.112")), tlv(0x03, b(0), ByteArray(32)), int(1))) })
        // an EC point that is not on the curve
        val ecEnc = Kill05CertKit.p256.public.encoded.clone()
        ecEnc[ecEnc.size - 1] = (ecEnc[ecEnc.size - 1].toInt() xor 1).toByte()
        assertEquals(UNSUPPORTED, err { AttestCert.keyOfSpki(ecEnc) })
        val c = AttestCert.Cert(b(), b(), b(), b(), Kill05CertKit.p256.public.encoded, b(1), "1.2", null, b(), emptyList())
        assertEquals("prime256v1", AttestCert.keyOfCert(c).curve)
    }

    // ---- EC points ----

    private fun fakeEc(x: BigInteger, y: BigInteger, params: ECParameterSpec?): ECPublicKey = object : ECPublicKey {
        override fun getW(): ECPoint = ECPoint(x, y)
        override fun getParams(): ECParameterSpec = params ?: throw IllegalStateException("no parameters")
        override fun getAlgorithm(): String = "EC"
        override fun getFormat(): String = "X.509"
        override fun getEncoded(): ByteArray = ByteArray(0)
    }

    @Test
    fun ecPointOfKeyIsFixedWidth() {
        val two255 = BigInteger.ONE.shiftLeft(255)
        val k256 = AttestCert.CertKey(fakeEc(BigInteger.ONE, two255.add(BigInteger.valueOf(3)), null), "ec", "prime256v1", b())
        val want256 = ByteArray(65)
        want256[0] = 4
        want256[32] = 1
        want256[33] = 0x80.toByte()
        want256[64] = 3
        assertArrayEquals(want256, AttestCert.ecPointOfKey(k256, "P-256"))

        val two383 = BigInteger.ONE.shiftLeft(383)
        val k384 = AttestCert.CertKey(fakeEc(two383.add(BigInteger.valueOf(5)), BigInteger.valueOf(0x0102), null), "ec", "secp384r1", b())
        val want384 = ByteArray(97)
        want384[0] = 4
        want384[1] = 0x80.toByte()
        want384[48] = 5
        want384[95] = 1
        want384[96] = 2
        assertArrayEquals(want384, AttestCert.ecPointOfKey(k384, "P-384"))

        // a real key: the point is the tail of its SubjectPublicKeyInfo
        val enc = Kill05CertKit.p256.public.encoded
        assertArrayEquals(enc.copyOfRange(enc.size - 65, enc.size), AttestCert.ecPointOfKey(AttestCert.keyOfSpki(enc), "P-256"))

        assertEquals("public key is not EC (got rsa)", err { AttestCert.ecPointOfKey(AttestCert.keyOfSpki(rsa.public.encoded), "P-256") })
        assertEquals("public key is not EC (got ec)", err { AttestCert.ecPointOfKey(AttestCert.CertKey(null, "ec", "prime256v1", b()), "P-256") })
        assertEquals("public key is not EC (got rsa)", err { AttestCert.ecPointOfKey(AttestCert.CertKey(Kill05CertKit.p256.public, "rsa", "prime256v1", b()), "P-256") })
        assertEquals("public key is not on P-384 (got P-256)", err { AttestCert.ecPointOfKey(k256, "P-384") })
        assertEquals("public key is not on P-256 (got P-384)", err { AttestCert.ecPointOfKey(k384, "P-256") })
    }

    @Test
    fun spkiKeyBitsOfCert() {
        val enc = Kill05CertKit.p256.public.encoded
        fun certWith(spki: ByteArray) = AttestCert.Cert(b(), b(), b(), b(), spki, b(1), "1.2", null, b(), emptyList())
        assertArrayEquals(enc.copyOfRange(enc.size - 65, enc.size), AttestCert.spkiKeyBits(certWith(enc)))
        assertEquals("malformed SubjectPublicKeyInfo", err { AttestCert.spkiKeyBits(certWith(seq(seq(oid("1.2")), tlv(0x03, b(0, 1)), int(1)))) })
        assertEquals("malformed SubjectPublicKeyInfo", err { AttestCert.spkiKeyBits(certWith(seq(seq(oid("1.2"))))) })
    }

    // ---- RSASSA-PSS parameters ----

    private val BAD = Triple("", 0, false)
    private val SHA256 = "2.16.840.1.101.3.4.2.1"
    private val SHA384 = "2.16.840.1.101.3.4.2.2"
    private val SHA512 = "2.16.840.1.101.3.4.2.3"
    private val SHA1 = "1.3.14.3.2.26"
    private val MGF1 = "1.2.840.113549.1.1.8"

    private fun h(tag: Int, o: String) = tlv(tag, seq(oid(o), tlv(0x05)))
    private fun mgf(hashOid: String) = tlv(0xa1, seq(oid(MGF1), seq(oid(hashOid))))
    private fun ctxInt(tag: Int, v: BigInteger) = tlv(tag, int(v))

    @Test
    fun pssParamsRules() {
        fun pp(vararg parts: ByteArray) = AttestCert.pssParams(seq(*parts))
        assertEquals(Triple("SHA-1", 20, true), AttestCert.pssParams(null))
        assertEquals(Triple("SHA-1", 20, true), AttestCert.pssParams(b()))
        assertEquals(Triple("SHA-1", 20, true), pp())
        assertEquals(Triple("SHA-256", 32, true), pp(h(0xa0, SHA256), mgf(SHA256), ctxInt(0xa2, BigInteger.valueOf(32))))
        assertEquals(Triple("SHA-384", 48, true), pp(h(0xa0, SHA384), mgf(SHA384), ctxInt(0xa2, BigInteger.valueOf(48)), ctxInt(0xa3, BigInteger.ONE)))
        assertEquals(Triple("SHA-512", 64, true), pp(h(0xa0, SHA512), mgf(SHA512), ctxInt(0xa2, BigInteger.valueOf(64))))
        assertEquals(Triple("SHA-1", 20, true), pp(h(0xa0, SHA1), mgf(SHA1)))
        assertEquals(Triple("SHA-256", 20, false), pp(h(0xa0, SHA256)))
        assertEquals(Triple("SHA-1", 20, false), pp(mgf(SHA256)))
        assertEquals(Triple("SHA-1", 0, true), pp(ctxInt(0xa2, BigInteger.ZERO)))
        assertEquals(Triple("SHA-1", 1 shl 20, true), pp(ctxInt(0xa2, BigInteger.ONE.shiftLeft(20))))
        assertEquals(BAD, pp(ctxInt(0xa2, BigInteger.ONE.shiftLeft(20).add(BigInteger.ONE))))
        assertEquals(BAD, pp(ctxInt(0xa2, BigInteger.ONE.shiftLeft(63)))) // wraps negative as a long
        assertEquals(BAD, pp(ctxInt(0xa2, BigInteger.ONE.shiftLeft(64)))) // wraps to 0 as a long
        assertEquals(BAD, pp(ctxInt(0xa2, BigInteger.ONE.shiftLeft(64).add(BigInteger.valueOf(32)))))
        assertEquals(BAD, pp(ctxInt(0xa3, BigInteger.valueOf(2))))
        assertEquals(BAD, pp(ctxInt(0xa3, BigInteger.valueOf(32))))
        assertEquals(BAD, pp(ctxInt(0xa3, BigInteger.ZERO)))
        assertEquals(BAD, pp(tlv(0xa2, tlv(0x04, b(32)))))
        assertEquals(BAD, pp(tlv(0xa2, int(BigInteger.ONE), int(BigInteger.ONE))))
        assertEquals(BAD, pp(tlv(0xa2)))
        assertEquals(BAD, pp(h(0xa0, "1.2.3.4")))
        assertEquals(BAD, pp(h(0xa0, SHA256), tlv(0xa1, seq(oid("1.2.3.4"), seq(oid(SHA256))))))
        assertEquals(BAD, pp(h(0xa0, SHA256), tlv(0xa1, seq(oid(MGF1)))))
        assertEquals(BAD, pp(h(0xa0, SHA256), tlv(0xa1, seq(oid(MGF1), tlv(0x05)))))
        assertEquals(BAD, pp(h(0xa0, SHA256), mgf("1.2.3.4")))
        assertEquals(BAD, pp(tlv(0xa4, int(BigInteger.ONE))))
        assertEquals(BAD, pp(tlv(0x02, b(1))))
        assertEquals(BAD, AttestCert.pssParams(tlv(0x04, b(1))))
        assertEquals(BAD, AttestCert.pssParams(b(0x30, 0x05)))
    }

    @Test
    fun jcaHashSuffixDropsDashes() {
        assertEquals("SHA256", AttestCert.jcaHashSuffix("SHA-256"))
        assertEquals("SHA1", AttestCert.jcaHashSuffix("SHA-1"))
        assertEquals("ABC", AttestCert.jcaHashSuffix("A-B-C"))
    }

    // ---- certificate signatures ----

    private val TBS = "to-be-signed certificate bytes".toByteArray()

    private fun sign(alg: String, kp: KeyPair, data: ByteArray = TBS, pss: PSSParameterSpec? = null): ByteArray =
        Signature.getInstance(alg).run {
            if (pss != null) setParameter(pss)
            initSign(kp.private)
            update(data)
            sign()
        }

    private fun ok(sigOid: String, params: ByteArray?, sig: ByteArray, k: AttestCert.CertKey) = AttestCert.certSigOk(signed(sigOid, params, sig, TBS), k)

    @Test
    fun ecdsaSignatures() {
        val kp = Kill05CertKit.p256
        val k = AttestCert.keyOfSpki(kp.public.encoded)
        val s256 = sign("SHA256withECDSA", kp)
        assertTrue(ok("1.2.840.10045.4.3.2", null, s256, k))
        assertTrue(ok("1.2.840.10045.4.3.3", null, sign("SHA384withECDSA", kp), k))
        assertTrue(ok("1.2.840.10045.4.3.4", null, sign("SHA512withECDSA", kp), k))
        assertFalse(ok("1.2.840.10045.4.3.3", null, s256, k))
        assertFalse(AttestCert.certSigOk(signed("1.2.840.10045.4.3.2", null, s256, "other".toByteArray()), k))
        // an ECDSA / SHA-256 signature labelled as an RSA algorithm with the same hash
        assertFalse(ok("1.2.840.113549.1.1.11", null, s256, k))
        assertFalse(ok("1.2.840.10045.4.3.1", null, sign("SHA224withECDSA", kp), k))
    }

    @Test
    fun rsaPkcs1Signatures() {
        val k = AttestCert.keyOfSpki(rsa.public.encoded)
        val s256 = sign("SHA256withRSA", rsa)
        assertTrue(ok("1.2.840.113549.1.1.11", null, s256, k))
        assertTrue(ok("1.2.840.113549.1.1.12", null, sign("SHA384withRSA", rsa), k))
        assertTrue(ok("1.2.840.113549.1.1.13", null, sign("SHA512withRSA", rsa), k))
        assertFalse(ok("1.2.840.113549.1.1.12", null, s256, k))
        assertFalse(AttestCert.certSigOk(signed("1.2.840.113549.1.1.11", null, s256, "other".toByteArray()), k))
        // an RSA / SHA-256 signature labelled as ECDSA with the same hash
        assertFalse(ok("1.2.840.10045.4.3.2", null, s256, k))
        // sha1WithRSAEncryption is not an algorithm the reference accepts here
        assertFalse(ok("1.2.840.113549.1.1.5", null, sign("SHA1withRSA", rsa), k))
        // a signature of the wrong length makes the JCA throw: certSigOk answers false
        assertFalse(ok("1.2.840.113549.1.1.11", null, b(1), k))
        // the key of the subject public key info only (no JCA key) or an EdDSA JCA key signs nothing here
        assertFalse(ok("1.2.840.113549.1.1.11", null, s256, AttestCert.CertKey(null, "unknown", "", b())))
        assertFalse(ok("1.2.840.10045.4.3.2", null, s256, AttestCert.CertKey(Kill05CertKit.ed.public, "unknown", "", b())))
    }

    @Test
    fun runtimeFailureIsFalse() {
        // a key that throws while it is used: the RuntimeException path of certSigOk
        val k = AttestCert.CertKey(fakeEc(BigInteger.ONE, BigInteger.ONE, null), "ec", "prime256v1", b())
        val derSig = b(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)
        assertFalse(ok("1.2.840.10045.4.3.2", null, derSig, k))
    }

    @Test
    fun pkcs1UnderAnRsaPssKeyIsRefusedOnEveryPath() {
        val pssKey = AttestCert.keyOfSpki(spki("1.2.840.113549.1.1.10", pkcs1(rsaPub.modulus.toByteArray(), rsaPub.publicExponent.toByteArray())))
        val plain = AttestCert.keyOfSpki(rsa.public.encoded)
        val s = sign("SHA256withRSA", rsa)
        assertTrue(ok("1.2.840.113549.1.1.11", null, s, plain))
        assertFalse(ok("1.2.840.113549.1.1.11", null, s, pssKey))
        assertTrue(AttestJws.rs256Ok(s, TBS, plain))
        assertFalse(AttestJws.rs256Ok(s, TBS, pssKey))
        assertEquals(true, KUtil.priv<Boolean>(AttestIntel, "crlSigOk", TBS, s, plain))
        assertEquals(false, KUtil.priv<Boolean>(AttestIntel, "crlSigOk", TBS, s, pssKey))
    }

    @Test
    fun rsaPssSignatures() {
        val k = AttestCert.keyOfSpki(rsa.public.encoded)
        val spec256 = PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
        val s = sign("RSASSA-PSS", rsa, pss = spec256)
        val params = seq(h(0xa0, SHA256), mgf(SHA256), ctxInt(0xa2, BigInteger.valueOf(32)))
        assertTrue(ok("1.2.840.113549.1.1.10", params, s, k))
        val pssKey = AttestCert.keyOfSpki(spki("1.2.840.113549.1.1.10", pkcs1(rsaPub.modulus.toByteArray(), rsaPub.publicExponent.toByteArray())))
        assertTrue(ok("1.2.840.113549.1.1.10", params, s, pssKey))
        // the default parameters: SHA-1, MGF1 / SHA-1, 20-byte salt
        val s1 = sign("RSASSA-PSS", rsa, pss = PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1))
        assertTrue(ok("1.2.840.113549.1.1.10", null, s1, k))
        assertFalse(ok("1.2.840.113549.1.1.10", null, s, k))
        // the salt length is the one in the parameters
        assertFalse(ok("1.2.840.113549.1.1.10", seq(h(0xa0, SHA256), mgf(SHA256), ctxInt(0xa2, BigInteger.valueOf(20))), s, k))
        // MGF1 over another hash is a profile this verifier does not check (even though the signature verifies with MGF1 / SHA-256)
        assertFalse(ok("1.2.840.113549.1.1.10", seq(h(0xa0, SHA256), mgf(SHA1), ctxInt(0xa2, BigInteger.valueOf(32))), s, k))
        // not an RSA key
        assertFalse(ok("1.2.840.113549.1.1.10", params, s, AttestCert.keyOfSpki(Kill05CertKit.p256.public.encoded)))
        assertFalse(ok("1.2.840.113549.1.1.10", params, s, AttestCert.CertKey(null, "rsa-pss", "", b())))
        // a salt the key is too short for: the JCA refuses, certSigOk answers false
        assertFalse(ok("1.2.840.113549.1.1.10", seq(h(0xa0, SHA256), mgf(SHA256), ctxInt(0xa2, BigInteger.ONE.shiftLeft(20))), s, k))
    }

    @Test
    fun ed25519Signatures() {
        val kp = Kill05CertKit.ed
        val k = AttestCert.keyOfSpki(kp.public.encoded)
        val s = sign("Ed25519", kp)
        assertEquals(64, s.size)
        assertTrue(ok("1.3.101.112", null, s, k))
        assertFalse(ok("1.3.101.112", null, cat(s, b(0)), k))
        assertFalse(ok("1.3.101.112", null, s.copyOfRange(0, 63), k))
        assertFalse(AttestCert.certSigOk(signed("1.3.101.112", null, s, "other".toByteArray()), k))
        val bad = s.clone()
        bad[10] = (bad[10].toInt() xor 1).toByte()
        assertFalse(ok("1.3.101.112", null, bad, k))
        assertFalse(ok("1.3.101.112", null, s, AttestCert.CertKey(null, "ed25519", "", b())))
        assertFalse(ok("1.3.101.112", null, s, AttestCert.CertKey(null, "rsa", "", b(), k.rawKey)))
        assertFalse(ok("1.3.101.112", null, s, AttestCert.keyOfSpki(rsa.public.encoded)))
        // the key is read from the start of rawKey
        assertTrue(ok("1.3.101.112", null, s, AttestCert.CertKey(null, "ed25519", "", b(), k.rawKey)))
    }

    @Test
    fun certSigOkByReadsTheParentKey() {
        val kp = Kill05CertKit.p256
        val s = sign("SHA256withECDSA", kp)
        val child = signed("1.2.840.10045.4.3.2", null, s, TBS)
        fun parent(spki: ByteArray) = AttestCert.Cert(b(), b(), b(), b(), spki, b(1), "1.2", null, b(), emptyList())
        assertTrue(AttestCert.certSigOkBy(child, parent(kp.public.encoded)))
        assertFalse(AttestCert.certSigOkBy(child, parent(Kill05CertKit.ec("secp256r1").public.encoded)))
        assertFalse(AttestCert.certSigOkBy(child, parent(spki("1.2.840.10040.4.1", b(1)))))
        assertFalse(AttestCert.certSigOkBy(child, parent(b(0x04, 0x00))))
    }
}
