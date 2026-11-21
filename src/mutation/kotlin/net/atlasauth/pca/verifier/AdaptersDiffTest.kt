package net.atlasauth.pca.verifier

import org.junit.Test

/** Replays the reference's agent-side adapter helpers: message segments, provenance headers and a recorder flow (fixed key, session and clock). */
@Suppress("UNCHECKED_CAST")
class AdaptersDiffTest {
    private val m = "ref-adapters"
    private val key = Keys.ed25519(Keys.edFromSeed(OracleCases.seed("ref-adapters/recorder")))
    private val session = Keys.b64u(OracleCases.seed("ref-adapters/session"))

    @Test fun messageSegments() = OracleCases.each(m, "messageSegments") { a ->
        Adapters.messageSegments(a[0]).map { linkedMapOf<String, Any?>("origin" to it.origin, "source" to it.source, "content" to it.content) }
    }

    @Test fun provenanceHeaders() = OracleCases.each(m, "provenanceHeaders") { a -> Adapters.provenanceHeaders(a[0]) }

    @Test fun recordFlow() = OracleCases.each(m, "recordFlow") { a ->
        val rec = ArgProvenance.Recorder("harness", "k1", key, session) { 1_800_000_000_000L }
        val bundles = ArrayList<Any?>()
        for (st in (a[0] as Map<String, Any?>)["steps"] as List<Map<String, Any?>>) {
            when (st["op"]) {
                "messages" -> Adapters.recordMessages(rec, st["messages"] as List<*>)
                "input" -> Adapters.recordInput(rec, st["input"])
                "principal" -> rec.principal(st["text"] as String)
                "tool" -> rec.tool(st["tool"] as String, st["output"])
                "act" -> {
                    val act = st["action"] as Map<String, Any?>
                    bundles.add(rec.forAction(act["verb"] as String, act["resource"] as String, act["params"] as Map<String, Any?>))
                }
            }
        }
        linkedMapOf<String, Any?>("bundles" to bundles, "receipts" to rec.receipts())
    }
}
