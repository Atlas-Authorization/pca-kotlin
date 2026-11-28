package net.atlasauth.pca.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test

class WithPcaTest {
    private class Echo(name: String) : Tool<String> {
        override val metadata = ToolMetadata(name)
        override fun call(input: Map<String, Any?>): String = "ran:" + metadata.name
    }

    private val prover = Prover { verb, resource, _ -> Proof(LinkedHashMap(), "enc-$verb@$resource", mapOf("PCA-Action" to "enc")) }

    @Test fun aMappedToolRunsUnderAProofAndAnUnmappedOneIsLeftAlone() {
        val seen = ArrayList<String>()
        val refund = Echo("refund")
        val noop = Echo("noop")
        val wrapped = withPCATools(prover, linkedMapOf("refund" to refund, "noop" to noop), mapOf("refund" to GuardToolSpec("stripe.refund", { _ -> "charge:1" }, { p, _ -> seen.add(p.encoded) })))
        assertEquals(listOf("refund", "noop"), wrapped.keys.toList())
        assertEquals("ran:refund", wrapped.getValue("refund").call(emptyMap()))
        assertEquals(listOf("enc-stripe.refund@charge:1"), seen)
        assertSame(noop, wrapped.getValue("noop"))
    }

    @Test fun aRefusedProofNeverRunsTheTool() {
        val refuse = Prover { v, r, _ -> throw PcaDenied("no", v, r) }
        val w = withPCA(refuse, GuardToolSpec("stripe.refund", "charge:1"), Echo("refund"))
        assertThrows(PcaDenied::class.java) { w.call(emptyMap()) }
    }
}
