package net.atlasauth.pca.verifier

import java.nio.file.Paths
import org.junit.Assume.assumeTrue
import org.junit.Assert.assertEquals
import org.junit.Test

class LessNativeLoadOrderTest {
    /** An explicit override is the first candidate, ahead of any packaged copy or repository build. */
    @Test
    fun explicitOverrideComesFirst() {
        assumeTrue(System.getenv("ATLAS_PCA_LIBLESS").isNullOrEmpty())
        val key = "atlas.pca.libless"
        val old = System.getProperty(key)
        try {
            System.setProperty(key, "/nonexistent/override/libatlas_less.so")
            assertEquals(Paths.get("/nonexistent/override/libatlas_less.so"), LessNative.candidates().first())
        } finally {
            if (old == null) System.clearProperty(key) else System.setProperty(key, old)
        }
    }
}
