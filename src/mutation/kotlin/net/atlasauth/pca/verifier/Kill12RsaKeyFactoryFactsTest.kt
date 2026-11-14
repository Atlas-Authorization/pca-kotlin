package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.KeyFactory
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPublicKeySpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The mutation ledger's proofs for AttestCert.parsePkcs1 (the negative-INTEGER refusal of `pos` and the `signum() <= 0` test) rest on what the
 * default RSA KeyFactory refuses by itself. That is a fact about the JDK, not about this code, so it is pinned here: if the provider
 * ahead of SunRsaSign changes, or SunRsaSign stops refusing one of these specs, this fails and the proofs are void.
 */
class Kill12RsaKeyFactoryFactsTest {
    private val big = BigInteger.ONE.shiftLeft(2047).add(BigInteger.valueOf(12345)).setBit(0) // a 2048-bit odd modulus
    private val e = BigInteger.valueOf(65537)

    private fun refused(n: BigInteger, ex: BigInteger): Boolean = try {
        KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, ex))
        false
    } catch (x: java.security.GeneralSecurityException) {
        true
    }

    @Test fun theDefaultRsaKeyFactoryIsSunRsaSign() {
        assertEquals("SunRsaSign", KeyFactory.getInstance("RSA").provider.name)
    }

    @Test fun aGoodSpecIsAccepted() {
        assertTrue(!refused(big, e))
    }

    @Test fun aNegativeOrZeroModulusIsRefused() {
        assertTrue(refused(big.negate(), e))                    // negative, 2048 bits
        assertTrue(refused(BigInteger.valueOf(-3), e))          // negative, tiny
        assertTrue(refused(BigInteger.ZERO, e))
        assertTrue(refused(BigInteger.valueOf(65539), e))       // below the 512-bit minimum
    }

    @Test fun aNegativeZeroOrSmallExponentIsRefused() {
        for (x in listOf(-65537L, -1L, 0L, 1L, 2L)) assertTrue("e=$x", refused(big, BigInteger.valueOf(x)))
        assertTrue(refused(big, big))                           // e >= n
        assertTrue(refused(big, big.add(BigInteger.ONE)))
        assertTrue(!refused(big, BigInteger.valueOf(3)))
    }

    @Test fun parsePkcs1RefusesTheSameInputsWithItsOwnError() {
        fun der(tag: Int, v: ByteArray): ByteArray {
            val len = if (v.size < 128) byteArrayOf(v.size.toByte()) else byteArrayOf(0x82.toByte(), (v.size shr 8).toByte(), v.size.toByte())
            return byteArrayOf(tag.toByte()) + len + v
        }
        fun rsaKey(n: ByteArray, ex: ByteArray): ByteArray { val body = der(2, n) + der(2, ex); return der(0x30, body) }
        val neg = BigInteger.valueOf(-5).toByteArray() // 0xfb: a negative INTEGER
        val ok = big.toByteArray()
        val good = rsaKey(ok, e.toByteArray())
        AttestCert.parsePkcs1(good)
        for (bad in listOf(rsaKey(neg, e.toByteArray()), rsaKey(ok, neg), rsaKey(byteArrayOf(0), e.toByteArray()), rsaKey(ok, byteArrayOf(0)), rsaKey(ok, byteArrayOf(2)))) {
            try {
                AttestCert.parsePkcs1(bad)
                fail("accepted")
            } catch (x: AttErr) {
                assertEquals(AttestCert.OSSL_UNSUPPORTED, x.message)
            }
        }
    }
}
