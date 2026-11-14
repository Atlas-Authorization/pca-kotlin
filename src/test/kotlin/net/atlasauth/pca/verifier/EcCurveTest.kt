package net.atlasauth.pca.verifier

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Curves SunEC lacks (P-224 since JDK 16, Brainpool, secp256k1) go through BouncyCastle, like OpenSSL-backed Node accepts them. */
class EcCurveTest {
    private val bc = BouncyCastleProvider()

    private fun roundTrip(curve: String) {
        val kp = KeyPairGenerator.getInstance("EC", bc).apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()
        val digest = AttestUtil.sha256("msg-$curve".toByteArray())
        val der = Signature.getInstance("NONEwithECDSA", bc).apply { initSign(kp.private); update(digest) }.sign()
        val pub = AttestUtil.ecKeyOf(X509EncodedKeySpec(kp.public.encoded)) as ECPublicKey
        assertTrue(curve, AttestUtil.onCurve(pub.params, pub.w.affineX, pub.w.affineY))
        assertTrue(curve, AttestUtil.verifyDerEcdsa(pub, digest, der))
        val bad = digest.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(curve, AttestUtil.verifyDerEcdsa(pub, bad, der))
        assertNotNull(curve, AttestUtil.curveParams(curve))
    }

    @Test fun p224() = roundTrip("secp224r1")
    @Test fun secp256k1() = roundTrip("secp256k1")
    @Test fun brainpoolP256() = roundTrip("brainpoolP256r1")
    @Test fun p256StillSunEc() = roundTrip("secp256r1")

    @Test
    fun p224IsNamedLikeTheReference() {
        val kp = KeyPairGenerator.getInstance("EC", bc).apply { initialize(ECGenParameterSpec("secp224r1")) }.generateKeyPair()
        val k = AttestCert.keyInfoOf(kp.public, kp.public.encoded)
        assertEquals("secp224r1", k.curve)
        assertEquals("P-224", AttestCert.goCurveName(k))
    }
}
