package net.atlasauth.pca.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * Every consistency-proof node is a SHA-256 output. With oldSize 1 the old root is the starting hash, so a 31/33-byte
 * old root (or path element) plus a new root the attacker computes over it verified as consistent (TS 80dfe7a25).
 */
class LedgerConsistencyLengthTest {
    private fun node(l: ByteArray, r: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(byteArrayOf(1) + l + r)
    private val proof = Json.parse("{\"oldSize\":1,\"newSize\":2,\"path\":[]}")

    private fun forged(oldNode: ByteArray, pathNode: ByteArray): Boolean {
        val p = LinkedHashMap(proof as Map<String, Any?>)
        p["path"] = listOf(Pca.b64(pathNode))
        return Ledger.verifyConsistency(Pca.b64(oldNode), Pca.b64(node(oldNode, pathNode)), p)
    }

    @Test fun nonThirtyTwoByteNodesAreRefused() {
        val c = ByteArray(32) { (it + 7).toByte() }
        for (n in listOf(31, 33)) {
            val bad = ByteArray(n) { (it * 3 + 1).toByte() }
            assertFalse("old root of $n bytes", forged(bad, c))
            assertFalse("path element of $n bytes", forged(c, bad))
        }
        // control: the same construction with 32-byte nodes is a valid size-1 -> size-2 proof
        assertTrue(forged(ByteArray(32) { (it * 3 + 1).toByte() }, c))
    }
}
