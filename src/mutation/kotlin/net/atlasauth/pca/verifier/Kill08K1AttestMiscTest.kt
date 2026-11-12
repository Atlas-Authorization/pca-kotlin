package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/**
 * Mutation kills (group k1): the regex document budget counter, the 16 MiB signed-JSON cap at its exact edge, the first arc of an OID
 * at the 64-group edge, a non-option `requireCrlFor` handed straight to the revocation check, and the RSA parameter range the KeyFactory
 * catch-blocks of parsePkcs1 / jwkRsaKey lean on (every accepted boundary is built by the KeyFactory, so those catches never run).
 */
class Kill08K1AttestMiscTest {
    @Test fun theRegexRefusalCounterIsZeroOutsideABudgetAndCountsInsideOne() {
        assertEquals(0, SafeRegex.refusals())
        SafeRegex.withBudget {
            assertEquals(0, SafeRegex.refusals())
            assertTrue(SafeRegex.charge("a", 1))
            assertEquals(0, SafeRegex.refusals())
            assertFalse(SafeRegex.charge("(", 1))
            assertEquals(1, SafeRegex.refusals())
            assertFalse(SafeRegex.charge("(", 1))
            assertEquals(2, SafeRegex.refusals())
        }
        assertEquals(0, SafeRegex.refusals())
    }

    private val tk = AttestCert.CertKey(null, "ed25519", "", ByteArray(32), ByteArray(32))

    @Test fun aSignedJsonTextIsRefusedOnlyAboveSixteenMebibytes() {
        val max = AttestUtil.MAX_JSON_BYTES
        val atCap = AttestIntel.verifySignedJson("x".repeat(max), "tcbInfo", tk)
        assertNull(atCap.first)
        assertEquals("tcbInfo not found / malformed", atCap.second)
        val over = AttestIntel.verifySignedJson("x".repeat(max + 1), "tcbInfo", tk)
        assertNull(over.first)
        assertEquals("tcbInfo: malformed JSON segment: input too large", over.second)
    }

    private fun oid(content: ByteArray): String = try {
        AttestDer.oidToDotted(content, AttestDer.Tlv(0x06, 0, content.size))
    } catch (e: AttErr) {
        "ERR " + e.message
    }

    private fun arc(groups: Int): ByteArray = ByteArray(groups) { if (it == 0) 0x81.toByte() else if (it == groups - 1) 0x01 else 0x80.toByte() }

    @Test fun theFirstArcMayHaveSixtyFourGroupsButNotSixtyFive() {
        assertTrue(oid(arc(64)), oid(arc(64)).startsWith("2."))
        assertEquals("ERR extension OID has an oversized arc", oid(arc(65)))
    }

    @Test fun aRequireCrlForThatIsNeitherAKeywordNorAListIsRefusedByTheCheckItself() = nv {
        val crls = listOf(crl(dn(ROOT_CN), rootKey.private))
        for (bad in listOf<Any?>(5, "bogus", mapOf("a" to 1L), null)) {
            val e = assertThrows("$bad", IllegalArgumentException::class.java) {
                AttestNvidiaCollateral.checkChainRevocation(CHAIN, crls, NOW, emptyList(), bad)
            }
            assertEquals("nvidiaCollateralHook: requireCrlFor must be 'cdp', 'all' or an array of chain indices", e.message)
        }
    }

    private fun len(n: Int): ByteArray = when {
        n < 128 -> byteArrayOf(n.toByte())
        n < 256 -> byteArrayOf(0x81.toByte(), n.toByte())
        else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
    }

    private fun tlv(tag: Int, c: ByteArray): ByteArray = byteArrayOf(tag.toByte()) + len(c.size) + c

    private fun pkcs1(n: BigInteger, e: BigInteger): ByteArray = tlv(0x30, tlv(0x02, n.toByteArray()) + tlv(0x02, e.toByteArray()))

    private fun b64u(v: BigInteger): String {
        var b = v.toByteArray()
        while (b.size > 1 && b[0] == 0.toByte()) b = b.copyOfRange(1, b.size)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    }

    @Test fun everyBoundaryOfTheAcceptedRsaRangeIsBuiltByTheKeyFactory() {
        val bits512 = BigInteger.ONE.shiftLeft(511).add(BigInteger.ONE)
        val bits16384 = BigInteger.ONE.shiftLeft(16383).add(BigInteger.ONE)
        val e32 = BigInteger.valueOf(0xFFFFFFFFL)
        for ((n, e) in listOf(bits512 to BigInteger.valueOf(3), bits512 to e32, bits16384 to BigInteger.valueOf(65537), bits16384 to e32)) {
            val k = AttestCert.parsePkcs1(pkcs1(n, e))
            assertEquals(n, k.modulus)
            assertEquals(e, k.publicExponent)
            val j = AttestJws.jwkRsaKey(b64u(n), b64u(e))
            assertEquals(n, (j.pub as RSAPublicKey).modulus)
        }
        // one bit outside the range is refused by the explicit check, before the KeyFactory
        for (n in listOf(BigInteger.ONE.shiftLeft(510).add(BigInteger.ONE), BigInteger.ONE.shiftLeft(16384).add(BigInteger.ONE))) {
            assertThrows(AttErr::class.java) { AttestCert.parsePkcs1(pkcs1(n, BigInteger.valueOf(65537))) }
        }
        assertThrows(AttErr::class.java) { AttestCert.parsePkcs1(pkcs1(bits512, BigInteger.valueOf(2))) }
        assertThrows(AttErr::class.java) { AttestCert.parsePkcs1(pkcs1(bits512, BigInteger.ONE.shiftLeft(32).add(BigInteger.ONE))) }
    }
}
