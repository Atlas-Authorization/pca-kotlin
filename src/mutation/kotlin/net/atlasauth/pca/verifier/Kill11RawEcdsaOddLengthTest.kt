package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A raw `r || s` ECDSA signature has two equal halves. An odd length is refused even when the longer second half is only the
 * second integer with a leading zero byte: without the parity refusal that signature would verify.
 */
class Kill11RawEcdsaOddLengthTest {
    private fun fixed32(x: BigInteger): ByteArray {
        val b = x.toByteArray()
        val out = ByteArray(32)
        val n = minOf(32, b.size)
        System.arraycopy(b, b.size - n, out, 32 - n, n)
        return out
    }

    @Test
    fun anOddLengthSignatureWithAZeroPaddedSIsRefused() {
        val kp = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val digest = MessageDigest.getInstance("SHA-256").digest("odd".toByteArray())
        val sig = Signature.getInstance("NONEwithECDSA").also { it.initSign(kp.private); it.update(digest) }.sign()
        val (r, s) = AttestUtil.parseDerSig(sig)!!
        val pub = kp.public as ECPublicKey
        val raw = fixed32(r) + fixed32(s)
        assertTrue(AttestUtil.verifyRawEcdsa(pub, digest, raw))
        val odd = raw.copyOfRange(0, 32) + byteArrayOf(0) + raw.copyOfRange(32, 64)
        assertFalse(AttestUtil.verifyRawEcdsa(pub, digest, odd))
        assertFalse(AttestUtil.verifyRawEcdsa(pub, digest, ByteArray(0)))
    }
}
