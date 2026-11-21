package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The typed-missing-context corpus (`missing-context-vectors.json`). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class MissingContextVectorsTest {
    private val doc = ParityVectors.load("missing-context-vectors.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun strs(o: Any?): List<String> = l(o).map { it as String }

    @Test
    fun decide() {
        assertTrue(l(doc["decide"]).size >= 20)
        for (x in l(doc["decide"])) {
            val v = m(x)
            val name = v["name"] as String
            val e = m(v["expect"])
            val got = MissingContext.decideWithMissing(v["where"], v["bound"], v["supplied"], v["suppliers"])
            assertEquals("$name: decision", e["decision"], got.decision)
            assertEquals("$name: reason", e["reason"], got.reason)
            val want = l(e["missing"]).map { m(it) }
            assertEquals("$name: missing count", want.size, got.missing.size)
            for ((i, w) in want.withIndex()) {
                assertEquals("$name: path $i", w["path"], got.missing[i].path)
                assertEquals("$name: supplier $i", w["supplier"], got.missing[i].supplier)
            }
        }
    }

    @Test
    fun bind() {
        assertTrue(l(doc["bind"]).size >= 8)
        for (x in l(doc["bind"])) {
            val v = m(x)
            val name = v["name"] as String
            val e = m(v["expect"])
            val table = (v["suppliers"] as Map<String, Any?>?) ?: emptyMap()
            val got = MissingContext.bindContext(m(v["bound"]), v["supplied"], table)
            assertTrue("$name: context", IntentJs.jsonEquals(e["context"], got.context))
            assertEquals("$name: conflicts", strs(e["conflicts"]), got.conflicts)
            assertEquals("$name: dropped", strs(e["dropped"]), got.dropped)
        }
    }
}
