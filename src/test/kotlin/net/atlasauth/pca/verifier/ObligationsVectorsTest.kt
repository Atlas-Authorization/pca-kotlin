package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The decision-obligations corpus (`obligations-vectors.json`). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class ObligationsVectorsTest {
    private val doc = ParityVectors.load("obligations-vectors.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun strs(o: Any?): List<String> = l(o).map { it as String }

    @Test
    fun validate() {
        assertTrue(l(doc["validate"]).size >= 15)
        for (x in l(doc["validate"])) {
            val c = m(x)
            assertEquals(c["name"] as String, m(c["expect"])["ok"], Obligations.obligationsError(c["input"]) == null)
        }
    }

    @Test
    fun merge() {
        assertTrue(l(doc["merge"]).size >= 5)
        for (x in l(doc["merge"])) {
            val c = m(x)
            val name = c["name"] as String
            val e = m(c["expect"])
            val got = Obligations.mergeObligations(l(c["inputs"]))
            assertEquals("$name: ok", e["ok"], got.ok)
            if (got.ok) assertEquals("$name: obligations", Json.canonicalize(e["obligations"]), Json.canonicalize(got.obligations))
        }
    }

    @Test
    fun gate() {
        assertTrue(l(doc["gate"]).size >= 10)
        for (x in l(doc["gate"])) {
            val c = m(x)
            val name = c["name"] as String
            val e = m(c["expect"])
            val got = Obligations.pepObligationGate(c["decision"] as String, c["answered"] == true, c["obligations"], c["supported"])
            assertEquals("$name: decision", e["decision"], got.decision)
            assertEquals("$name: perform", Json.canonicalize(e["perform"]), Json.canonicalize(got.perform))
            assertEquals("$name: unsupported", strs(e["unsupported"]), got.unsupported)
        }
    }

    @Test
    fun outcome() {
        assertTrue(l(doc["outcome"]).size >= 8)
        for (x in l(doc["outcome"])) {
            val c = m(x)
            val name = c["name"] as String
            val e = m(c["expect"])
            val got = Obligations.obligationOutcome(c["obligations"], c["fulfilled"], c["now"])
            assertEquals("$name: outcome", e["outcome"], got.outcome)
            assertEquals("$name: overdue", l(e["overdue"]).map { IntentJs.lng(it).toInt() }, got.overdue)
            assertEquals("$name: status", e["status"], got.status)
        }
    }
}
