package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * A `when` on the op string dispatches on String.hashCode() and then checks equals(): an UNKNOWN op whose hash collides with a
 * known one must still be unknown (reference predicates.ts: an op outside the known set is never decided). Each collider keeps
 * the hash of its op (s[0] + 1, s[1] - 31) and is decided UNKNOWN, while the op itself is decided.
 */
class Kill05R2PredicateOpCollisionTest {
    private val ctx = ParityVectors.obj("""{"action":{"verb":"v","resource":"r","params":{"s":"ab","n":1}}}""")

    private fun collide(s: String) = "${s[0] + 1}${s[1] - 31}${s.substring(2)}"

    private fun tri(op: String, field: String, value: String) =
        Predicates.evaluateConditionTri(ParityVectors.obj("""{"field":"action.params.$field","op":"$op","value":$value}"""), ctx)

    @Test
    fun aCollidingUnknownOpIsNeverDecided() {
        val cases = listOf(
            "eq" to ("s" to "\"ab\""), "ne" to ("s" to "\"ab\""), "in" to ("s" to "[\"ab\"]"), "nin" to ("s" to "[\"ab\"]"),
            "lt" to ("n" to "2"), "lte" to ("n" to "2"), "gt" to ("n" to "2"), "gte" to ("n" to "2"),
            "prefix" to ("s" to "\"a\""), "like" to ("s" to "\"a*\""), "matches" to ("s" to "\"a.*\""), "is_a" to ("s" to "\"ab\""),
        )
        for ((op, fv) in cases) {
            val c = collide(op)
            assertEquals(op, op.hashCode(), c.hashCode())
            assertNotEquals("$op is decided", Predicates.Tri.UNKNOWN, tri(op, fv.first, fv.second))
            assertEquals("collider $c of $op", Predicates.Tri.UNKNOWN, tri(c, fv.first, fv.second))
        }
    }
}
