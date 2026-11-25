package net.atlasauth.pca.langchain4j

import dev.langchain4j.agent.tool.ToolExecutionRequest
import dev.langchain4j.data.document.Metadata
import dev.langchain4j.data.segment.TextSegment
import dev.langchain4j.rag.content.Content
import dev.langchain4j.rag.content.retriever.ContentRetriever
import dev.langchain4j.rag.query.Query
import dev.langchain4j.service.tool.ToolExecutor
import net.atlasauth.pca.ai.PcaDenied
import net.atlasauth.pca.ai.Proof
import net.atlasauth.pca.ai.Prover
import net.atlasauth.pca.ai.ToolGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class LangChain4jAdapterTest {
    class FakeProver : Prover {
        val deny = ArrayList<String>()
        val retrieved = ArrayList<String>()
        override fun prove(verb: String, resource: String, params: Map<String, Any?>): Proof {
            if (verb in deny) throw PcaDenied("denied", verb, resource)
            return Proof(LinkedHashMap(), "enc", mapOf("PCA-Action" to "enc"))
        }
        override fun retrieval(source: String, content: Any?) { retrieved.add(source) }
    }

    private val map = ToolGuard.ToolMapping { n, _ -> if (n == "refund") ToolGuard.Action("stripe.refund", "charge:1") else null }

    private fun req(name: String, args: String): ToolExecutionRequest = ToolExecutionRequest.builder().id("1").name(name).arguments(args).build()

    @Test fun runsUnderTheProof() {
        val seen = ArrayList<String>()
        val inner = ToolExecutor { r, _ -> "ran:" + r.arguments() }
        val x = PcaToolExecutor(inner, FakeProver(), map, { p, r -> seen.add(p.encoded + "/" + r.name()); Unit }, false)
        assertEquals("ran:{\"a\":1}", x.execute(req("refund", "{\"a\":1}"), "m"))
        assertEquals(listOf("enc/refund"), seen)
    }

    @Test fun deniedOrUnmappedNeverRunsTheTool() {
        var ran = 0
        val inner = ToolExecutor { _, _ -> ran++; "x" }
        val p = FakeProver()
        p.deny.add("stripe.refund")
        assertThrows(PcaDenied::class.java) { PcaToolExecutor(inner, p, map).execute(req("refund", "{}"), null) }
        assertThrows(PcaDenied::class.java) { PcaToolExecutor(inner, FakeProver(), map).execute(req("shell", "{}"), null) }
        assertTrue(PcaToolExecutor(inner, p, map, null, true).execute(req("refund", "{}"), null).startsWith("denied: "))
        assertEquals(0, ran)
    }

    private fun content(id: String, acl: String?): Content {
        val m = Metadata().put("id", id)
        if (acl != null) m.put("acl", acl)
        return Content.from(TextSegment.from("text $id", m))
    }

    @Test fun theRetrieverKeepsOnlyAuthorizedContentAndFailsClosed() {
        val all = listOf(content("a", "can_view:document:a"), content("b", "can_view:document:b"), content("c", null), content("d", "x:y, can_view:document:a"))
        val policy = listOf(mapOf("verb" to "can_view", "resource" to "document:a"))
        val p = FakeProver()
        val r = PcaContentRetriever(ContentRetriever { all }, "user:alice", policy, p)
        val got = r.retrieve(Query.from("q"))
        assertEquals(listOf("a", "d"), got.map { it.textSegment().metadata().getString("id") })
        assertEquals(listOf("a", "d"), p.retrieved)
        assertEquals(listOf("b", "c"), r.lastDecision()!!["droppedIds"])
        assertTrue(PcaContentRetriever(ContentRetriever { all }, "user:alice", "not a policy", null).retrieve(Query.from("q")).isEmpty())
    }
}
