package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Key zeroisation: a destroyed key holds no secret bytes and signs nothing; its public key is kept. */
class KeyDestroyTest {
    @Test fun anEd25519KeyIsZeroedAndRefusesToSign() {
        val k = Keys.edGenerate()
        val id = k.id()
        assertFalse(k.isDestroyed)
        assertEquals(64, k.sign(byteArrayOf(1)).size)
        k.destroy()
        k.destroy() // idempotent
        assertTrue(k.isDestroyed)
        assertArrayEquals(ByteArray(32), k.seed)
        assertEquals(id, k.id())
        assertEquals("the key was destroyed", assertThrows(IllegalStateException::class.java) { k.sign(byteArrayOf(1)) }.message)
    }

    @Test fun aPostQuantumKeyIsZeroedAndRefusesToSign() {
        val k = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32))
        assertFalse(k.isDestroyed)
        assertTrue(k.sign(byteArrayOf(1)).isNotEmpty())
        val n = k.sk.size
        k.destroy()
        assertTrue(k.isDestroyed)
        assertArrayEquals(ByteArray(n), k.sk)
        assertEquals("the key was destroyed", assertThrows(IllegalStateException::class.java) { k.sign(byteArrayOf(1)) }.message)
    }
}
