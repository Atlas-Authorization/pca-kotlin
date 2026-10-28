package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** K5 workflow admission and read-side corpora (`workflow-vectors.json`, `readside-vectors.json`). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class K5VectorsTest {
    private val w = ParityVectors.load("workflow-vectors.json")
    private val r = ParityVectors.load("readside-vectors.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun canon(o: Any?): String = Json.canonicalize(o)

    private fun admitIn(c: Map<String, Any?>) = Workflow.AdmitInput(m(w["workflows"])[c["workflow"]], c["principal"], c["rs_signer"], c["receipts"], c["now"], c["request"])

    @Test
    fun digests() {
        val d = m(w["digests"])
        assertEquals(d["workflow"], Workflow.workflowDigest(m(m(m(w["workflows"])["main"])["body"])))
        for (x in l(d["values"])) assertEquals(m(x)["digest"], Workflow.valueDigest(m(x)["value"]))
        for (x in l(d["params"])) assertEquals(m(x)["digest"], Pca.hashCanonical(m(x)["params"]))
        assertEquals(4, l(d["receipt_refs"]).size)
    }

    @Test
    fun admitAndBind() {
        assertTrue(l(w["admit"]).size >= 60 && l(w["bind"]).size >= 5)
        val seen = HashSet<Any?>()
        for (x in l(w["admit"])) { val c = m(x); assertEquals("admit ${c["name"]}", canon(c["expect"]), canon(Workflow.admitStep(admitIn(c)).toMap())); seen.add(m(c["expect"])["code"]) }
        for (x in l(w["bind"])) { val c = m(x); assertEquals("bind ${c["name"]}", canon(c["expect"]), canon(Workflow.bindPromises(admitIn(c)).toMap())); seen.add(m(c["expect"])["code"]) }
        for (code in listOf("bad_workflow", "bad_dag", "bad_signature", "not_yet", "expired", "goal_mismatch", "plan_root_mismatch", "bad_receipt", "unplanned_step", "step_mismatch", "params_mismatch", "already_done", "budget_exceeded", "deps_unmet", "dep_failed", "stale_dep", "edge_missing", "edge_unit", "edge_digest", "edge_value", "edge_relation", "taint_flow", "pipeline_unconstrained", "taint_escalate")) assertTrue(code, code in seen)
    }

    @Test
    fun planRoot() {
        for (x in l(w["plan_root"])) {
            val c = m(x)
            assertEquals(c["name"] as String, c["expect"], Workflow.planRootAuthorized(m(w["workflows"])[c["workflow"]], c["principal"], c["now"], c["root"]))
        }
    }

    @Test
    fun hostileInputNeverThrows() {
        val k = m(w["keys"])
        for (x in listOf(null, Json.Num("1"), "x", emptyList<Any?>(), emptyMap<String, Any?>(), mapOf("body" to null), mapOf("body" to emptyMap<String, Any?>(), "sig" to Json.Num("1")))) {
            val res = Workflow.admitStep(Workflow.AdmitInput(x, k["principal"], k["rs"], emptyList<Any?>(), Json.Num("1"), x))
            assertEquals("deny", res.decision)
        }
        assertEquals("deny", Workflow.admitStep(Workflow.AdmitInput(m(w["workflows"])["main"], k["principal"], k["rs"], "x", Json.Num("1"), emptyMap<String, Any?>())).decision)
    }

    @Test
    fun redact() {
        assertTrue(l(r["redact"]).size >= 28)
        val grants = m(r["grants"])
        for (x in l(r["redact"])) {
            val c = m(x); val i = m(c["input"])
            val got = ReadSide.redactRead(ReadSide.ReadInput(grants[c["grant"]], i["principal"], i["now"], i["verb"], i["resource"], i["purpose"], i["schema"], i["record"], i["tighten"], i["salt"], i["counts"]))
            assertEquals("redact ${c["name"]}", canon(c["expect"]), canon(got.toMap()))
        }
        assertEquals("deny", ReadSide.redactRead(ReadSide.ReadInput(null, null, null, null, null, null, null, null, null, null, null)).decision)
    }

    @Test
    fun sinks() {
        val grants = m(r["grants"])
        for (x in l(r["sinks"])) {
            val c = m(x)
            val got = ReadSide.checkSink(ReadSide.SinkInput(grants[c["grant"]], c["principal"], c["rs_signer"], c["now"], c["sink"], c["receipts"]))
            assertEquals("sink ${c["name"]}", canon(c["expect"]), canon(got.toMap()))
        }
        assertEquals("deny", ReadSide.checkSink(ReadSide.SinkInput(null, null, null, null, null, null)).decision)
    }

    @Test
    fun readDigestsAndChain() {
        val d = m(r["digests"])
        assertEquals(d["grant"], ReadSide.readGrantDigest(m(m(m(r["grants"])["main"])["body"])))
        val recs = l(l(r["sinks"]).map { m(it) }.first { it["name"] == "chain-of-two-public-reads" }["receipts"])
        val got = ReadSide.readChainLabels(recs, m(r["keys"])["rs"] as String, d["grant"] as String, 1_800_000_000_000L)
        assertEquals(canon(d["chain_labels"]), canon(mapOf("labels" to got.labels)))
    }
}
