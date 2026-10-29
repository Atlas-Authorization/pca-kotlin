package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The break-glass corpus (`break-glass-vectors.json`). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class BreakGlassVectorsTest {
    private val doc = ParityVectors.load("break-glass-vectors.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun strs(o: Any?): List<String> = l(o).map { it as String }

    @Test
    fun scenarios() {
        val grants = l(doc["grants"])
        val reviews = l(doc["reviews"])
        val authority = doc["authority"] as String
        val reviewer = doc["reviewer"] as String
        assertTrue(l(doc["scenarios"]).size >= 10)
        for (x in l(doc["scenarios"])) {
            val s = m(x)
            val name = s["name"] as String
            val extra = s["extra_reviewers"]?.let { strs(it) } ?: emptyList()
            val reg = BreakGlass.Registry(BreakGlass.Policy(listOf(authority), listOf(reviewer) + extra))
            for ((i, y) in l(s["steps"]).withIndex()) {
                val st = m(y)
                val at = "$name step $i"
                when (st["op"]) {
                    "accept", "review" -> {
                        val e = m(st["expect"])
                        val got = if (st["op"] == "accept") reg.accept(grants[IntentJs.lng(st["grant"]).toInt()], st["now"])
                        else reg.review(reviews[IntentJs.lng(st["review"]).toInt()], st["holder"], st["now"])
                        assertEquals("$at: ok", e["ok"], got.ok)
                        if (got.ok) assertEquals("$at: replaced", e["replaced"], got.replaced) else assertEquals("$at: code", e["code"], got.code)
                    }
                    "use" -> {
                        val e = m(st["expect"])
                        val got = reg.use(st["id"], st["holder"], st["action_digest"], st["now"], st["notified"])
                        assertEquals("$at: decision", e["decision"], got.decision)
                        assertEquals("$at: code", e["code"], got.code)
                        assertEquals("$at: id", e["id"], got.id)
                        if (got.decision == "allow") {
                            assertEquals("$at: use", IntentJs.lng(e["use"]), got.use)
                            assertEquals("$at: remaining", IntentJs.lng(e["remaining"]), got.remaining)
                            assertEquals("$at: review_due", IntentJs.lng(e["review_due"]), got.reviewDue)
                        }
                    }
                    "frozen" -> assertEquals("$at: frozen", st["expect"], reg.frozen(st["holder"], st["now"]))
                    else -> throw AssertionError("$at: unknown op ${st["op"]}")
                }
            }
        }
    }
}
