package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.Provider
import java.security.SecureRandomSpi
import java.security.Security

/** Where [Kill08K1CaptureSpi] leaves the array it was asked to fill. */
object Kill08K1Capture {
    @Volatile var last: ByteArray? = null
}

/** A SecureRandom that fills every request with 0x42 and keeps a reference to the caller's array (to see it zeroed later). */
class Kill08K1CaptureSpi : SecureRandomSpi() {
    override fun engineSetSeed(seed: ByteArray) {}
    override fun engineNextBytes(bytes: ByteArray) {
        Kill08K1Capture.last = bytes
        java.util.Arrays.fill(bytes, 0x42.toByte())
    }
    override fun engineGenerateSeed(numBytes: Int): ByteArray = ByteArray(numBytes)
}

class Kill08K1CaptureProvider : Provider("Kill08K1Rng", "1.0", "capturing SecureRandom for a test") {
    init {
        put("SecureRandom.Kill08K1Rng", Kill08K1CaptureSpi::class.java.name)
    }
}

/** Mutation kills for Keys.kt: a destroyed key's secret bytes are zero, and edGenerate zeroes its temporary seed. */
class Kill08K1KeysTest {
    @Test fun destroyingAnEdKeyZeroesItsSeed() {
        val k = Keys.edFromSeed(ByteArray(32) { (it + 1).toByte() })
        assertTrue(k.seed.any { it != 0.toByte() })
        k.destroy()
        assertTrue(k.isDestroyed)
        assertTrue(k.seed.all { it == 0.toByte() })
    }

    @Test fun destroyingAPqKeyZeroesItsSecretKey() {
        val k = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { (it + 1).toByte() })
        assertTrue(k.sk.any { it != 0.toByte() })
        k.destroy()
        assertTrue(k.isDestroyed)
        assertTrue(k.sk.all { it == 0.toByte() })
    }

    @Test fun edGenerateZeroesTheTemporarySeedItDrewFromTheRandomSource() {
        val p = Kill08K1CaptureProvider()
        Security.insertProviderAt(p, 1)
        try {
            Kill08K1Capture.last = null
            val k = Keys.edGenerate()
            // the key was built from the 0x42 seed (its own copy), the caller's temporary array is wiped
            assertTrue(k.seed.all { it == 0x42.toByte() })
            val tmp = Kill08K1Capture.last
            assertNotNull(tmp)
            assertEquals(32, tmp!!.size)
            assertTrue(tmp.all { it == 0.toByte() })
        } finally {
            Security.removeProvider(p.name)
        }
    }
}
