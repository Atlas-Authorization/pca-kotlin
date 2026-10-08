package net.atlasauth.pca.verifier

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * JUnit wrapper around the shared PCA conformance corpus. It locates the repo-level
 * `packages/pca/conformance/` and `tools/pca-diff-fuzz/counterexamples/` directories by walking up from the
 * test working directory (so it is independent of where the Gradle daemon sets CWD) and asserts the native
 * Kotlin verifier produces ZERO failed assertions across all vectors, primitives and counterexamples.
 */
class ConformanceTest {
    private fun findUp(rel: String): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate = File(dir, rel)
            if (candidate.exists()) return candidate
            dir = dir.parentFile
        }
        throw IllegalStateException("could not locate $rel from ${System.getProperty("user.dir")}")
    }

    @Test
    fun allConformanceVectorsPass() {
        val conf = findUp("conformance").path
        val ce = File(conf).resolveSibling("counterexamples").path  // not vendored in the mirror; runConformance() skips when absent
        val fails = runConformance(conf, ce)
        assertEquals("conformance suite must have zero failed assertions", 0, fails)
    }
}
