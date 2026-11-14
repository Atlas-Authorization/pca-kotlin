package net.atlasauth.pca.verifier

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** RSA public parameters: 512..16384-bit modulus, odd exponent >= 3 of at most 32 bits, one rule for certs, JWKs and Sigstore log keys. */
class Kill14BRsaParamsTest {
    private fun n(bits: Int) = BigInteger.ONE.shiftLeft(bits - 1).setBit(0)
    private val e = BigInteger.valueOf(65537)

    @Test fun modulusBounds() {
        assertFalse(AttestCert.rsaParamsOk(n(511), e))
        assertTrue(AttestCert.rsaParamsOk(n(512), e))
        assertTrue(AttestCert.rsaParamsOk(n(16384), e))
        assertFalse(AttestCert.rsaParamsOk(n(16385), e))
        assertFalse(AttestCert.rsaParamsOk(BigInteger.ZERO, e))
        assertFalse(AttestCert.rsaParamsOk(n(2048).negate(), e))
    }

    @Test fun exponentRules() {
        val m = n(2048)
        for (x in listOf(3L, 5L, 65537L, 0xffffffffL)) assertTrue("$x", AttestCert.rsaParamsOk(m, BigInteger.valueOf(x)))
        for (x in listOf(-3L, 0L, 1L, 2L, 4L, 65536L, 0x100000001L)) assertFalse("$x", AttestCert.rsaParamsOk(m, BigInteger.valueOf(x)))
    }

    @Test fun sigstoreRsaLogKeyOutOfRangeIsRefused() {
        fun der(tag: Int, v: ByteArray) = byteArrayOf(tag.toByte(), 0x82.toByte(), (v.size shr 8).toByte(), v.size.toByte()) + v
        val body = der(2, n(2048).toByteArray()) + byteArrayOf(2, 1, 4) // even e = 4
        val pk = der(0x30, body)
        val log = mapOf<String, Any?>(
            "publicKey" to mapOf("rawBytes" to java.util.Base64.getEncoder().encodeToString(pk), "keyDetails" to "PKCS1_RSA_PKCS1V5", "validFor" to mapOf("start" to "2020-01-01T00:00:00Z")),
            "logId" to mapOf("keyId" to java.util.Base64.getEncoder().encodeToString(ByteArray(32))),
        )
        val e = org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { Sigstore.pinnedLog(log, false) }
        assertEquals("RSA log key is out of range", e.message)
    }
}
