package net.atlasauth.pca.koog

import kotlinx.coroutines.runBlocking
import net.atlasauth.pca.ai.PcaDenied
import net.atlasauth.pca.ai.Proof
import net.atlasauth.pca.ai.Prover
import net.atlasauth.pca.ai.ToolGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** The guard's suspending entry point (the Koog tool wrapper itself is a thin call into it). */
class KoogPcaTest {
    private val prover = Prover { v, _, _ ->
        if (v == "stripe.charge") throw PcaDenied("denied", v, null)
        Proof(LinkedHashMap(), "enc", mapOf("PCA-Action" to "enc"))
    }
    private val map = ToolGuard.ToolMapping { n, _ ->
        when (n) {
            "refund" -> ToolGuard.Action("stripe.refund", "charge:1")
            "charge" -> ToolGuard.Action("stripe.charge", "charge:1")
            else -> null
        }
    }

    @Test fun aSuspendingBodyRunsUnderTheProof() = runBlocking {
        val out = ToolGuard.runSuspending(prover, map, "refund", mapOf("id" to "c1")) { _, p -> "ran:" + p.encoded }
        assertEquals("ran:enc", out)
    }

    @Test fun deniedAndUnmappedNeverRun() = runBlocking {
        var ran = 0
        assertThrows(PcaDenied::class.java) { runBlocking { ToolGuard.runSuspending(prover, map, "charge", emptyMap()) { _, _ -> ran++ } } }
        assertThrows(PcaDenied::class.java) { runBlocking { ToolGuard.runSuspending(prover, map, "shell", emptyMap()) { _, _ -> ran++ } } }
        assertEquals(0, ran)
    }
}
