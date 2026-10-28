package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The policy-class corpus (`policy-classes-vectors.json`). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class PolicyClassesVectorsTest {
    private val doc = ParityVectors.load("policy-classes-vectors.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test
    fun validate() {
        assertTrue(l(doc["validate"]).size >= 10)
        for (x in l(doc["validate"])) {
            val v = m(x)
            assertEquals(v["name"] as String, m(v["expect"])["ok"], PolicyClasses.classVerdictsError(v["input"]) == null)
        }
    }

    @Test
    fun decide() {
        assertTrue(l(doc["decide"]).size >= 9)
        for (x in l(doc["decide"])) {
            val v = m(x)
            val name = v["name"] as String
            val e = m(v["expect"])
            val got = PolicyClasses.decideClasses(v["input"])
            assertEquals("$name: decision", e["decision"], got.decision)
            assertEquals("$name: denied_by", l(e["denied_by"]), got.deniedBy)
            assertEquals("$name: escalated_by", l(e["escalated_by"]), got.escalatedBy)
            assertEquals("$name: reason", e["reason"], got.reason)
            val want = l(e["classes"]).map { m(it) }
            assertEquals("$name: classes", want.size, got.classes.size)
            for ((i, w) in want.withIndex()) {
                val g = got.classes[i]
                assertEquals("$name: class $i", w["class"], g.cls)
                assertEquals("$name: revision $i", IntentJs.lng(w["revision"]), g.revision)
                assertEquals("$name: digest $i", w["digest"], g.digest)
                assertEquals("$name: decision $i", w["decision"], g.decision)
            }
        }
    }
}
