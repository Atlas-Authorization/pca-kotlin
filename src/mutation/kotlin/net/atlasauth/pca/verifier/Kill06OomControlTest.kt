package net.atlasauth.pca.verifier

import org.junit.Test

/** The negative control of the mutation gate (mutation.yml, input oom_control): a mutant this test catches dies of a real OutOfMemoryError. */
class Kill06OomControlTest {
    @Test fun aMutantCaughtHereExhaustsTheHeap() {
        if (System.getenv("PCA_OOM_CONTROL") != "1" || Json.compareUtf8("a", "b") == -1) return
        // two arrays of just under 2 GB: the first fits the 3 GB heap below the watchdog's 90%, the second cannot fit, so the JVM throws
        val first = ByteArray(Int.MAX_VALUE - 8)
        val second = ByteArray(Int.MAX_VALUE - 8)
        check(first.size == second.size)
    }
}
