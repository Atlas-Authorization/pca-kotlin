package net.atlasauth.pca.openai

import net.atlasauth.pca.ai.PcaDenied
import net.atlasauth.pca.ai.Proof
import net.atlasauth.pca.ai.Prover
import net.atlasauth.pca.ai.ToolGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class OpenAiPcaTest {
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

    @Test fun aHandlerRunsUnderTheProofAndItsResultIsTheMessage() {
        val h = mapOf<String, ToolGuard.Body<Any?>>("refund" to ToolGuard.Body { a, p -> mapOf("ok" to true, "args" to a.size.toLong(), "enc" to p.encoded) })
        val out = OpenAiPca.dispatch(prover, map, "call_1", "refund", "{\"a\":1}", h)
        assertEquals("call_1", out.toolCallId)
        assertEquals("{\"args\":1,\"enc\":\"enc\",\"ok\":true}", out.content)
    }

    @Test fun aToolWithoutAHandlerCarriesTheProof() {
        assertEquals("{\"pca\":\"enc\"}", OpenAiPca.dispatch(prover, map, "c", "refund", "{}", emptyMap()).content)
    }

    @Test fun deniedUnmappedAndMalformedNeverRun() {
        var ran = 0
        val h = mapOf<String, ToolGuard.Body<Any?>>("refund" to ToolGuard.Body { _, _ -> ran++; "x" }, "charge" to ToolGuard.Body { _, _ -> ran++; "x" })
        assertThrows(PcaDenied::class.java) { OpenAiPca.dispatch(prover, map, "c", "charge", "{}", h) }
        assertThrows(PcaDenied::class.java) { OpenAiPca.dispatch(prover, map, "c", "shell", "{}", h) }
        assertThrows(PcaDenied::class.java) { OpenAiPca.dispatch(prover, map, "c", "refund", "[1]", h) }
        assertEquals(0, ran)
    }
}
