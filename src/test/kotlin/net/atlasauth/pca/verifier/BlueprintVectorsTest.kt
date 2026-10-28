package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** The agent-blueprint corpus (`blueprint-vectors.json`). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class BlueprintVectorsTest {
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    @Test
    fun scenarios() {
        val doc = ParityVectors.load("blueprint-vectors.json")
        val recs = doc["records"] as List<Any?>
        assertEquals(9, recs.size)
        for ((i, r) in recs.withIndex()) assertEquals("record $i", i != 8, Blueprint.verify(r))
        for (x in doc["scenarios"] as List<Any?>) {
            val s = m(x)
            val name = s["name"] as String
            val reg = Blueprint.Registry(listOf(doc["operator"] as String))
            for (y in s["steps"] as List<Any?>) {
                val st = m(y)
                val exp = m(st["expect"])
                if (st["op"] == "accept") {
                    val g = reg.accept(recs[IntentJs.lng(st["record"]).toInt()])
                    assertEquals("$name: ok", exp["ok"], g.code == null)
                    if (g.code == null) assertEquals("$name: replaced", exp["replaced"], g.replaced) else assertEquals("$name: code", exp["code"], g.code)
                    continue
                }
                val o = m(st["opts"])
                val min = if (o.containsKey("minEpoch")) IntentJs.lng(o["minEpoch"]) else null
                val d = Blueprint.check(st["chain"], reg, o["now"], o["mode"] as String, min)
                assertEquals("$name: decision", exp["decision"], d.decision)
                if (exp.containsKey("code")) assertEquals("$name: code", exp["code"], d.code)
                if (exp.containsKey("blueprint")) assertEquals("$name: blueprint", exp["blueprint"], d.blueprint)
                if (exp.containsKey("governed")) assertEquals("$name: governed", exp["governed"], d.governed)
                if (exp["decision"] == "escalate") {
                    assertEquals("$name: have", IntentJs.lng(exp["have"]), d.have)
                    assertEquals("$name: need", IntentJs.lng(exp["need"]), d.need)
                }
            }
        }
    }
}
