package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PCA 0.5 mutation kills for [OracleFacts] (TS reference packages/pca/src/oracle-facts.ts and offer-set.ts): a relational operand naming an earlier
 * dimension must be spelled `env.world.<name>` (a same-length string with another prefix, or a non-string, is refused), and
 * offer-set query coverage (an empty filter query covers only an empty search).
 */
class Kill05WfOracleFactsTest {
    private fun rel(name: String, a: Any?) = linkedMapOf<String, Any?>("name" to name, "fn" to "sub", "a" to a, "b" to "action.params.y")

    private fun policy(vararg rs: Map<String, Any?>) = linkedMapOf<String, Any?>("relational" to rs.toList())

    @Test fun relationalOperandPrefix() {
        assertNull(OracleFacts.validateWorldPolicy(policy(rel("r1", "action.params.x"), rel("r2", "env.world.r1"))))
        // "0123456789" is as long as "env.world.": only the real prefix names an earlier dimension
        assertEquals(
            "relational 'r2': operand '0123456789r1' must be an action.params path or an earlier env.world dimension",
            OracleFacts.validateWorldPolicy(policy(rel("r1", "action.params.x"), rel("r2", "0123456789r1"))),
        )
        assertEquals(
            "relational 'r2': operand '5' must be an action.params path or an earlier env.world dimension",
            OracleFacts.validateWorldPolicy(policy(rel("r1", "action.params.x"), rel("r2", 5L))),
        )
        // its own name is not an earlier dimension
        assertEquals(
            "relational 'r2': operand 'env.world.r2' must be an action.params path or an earlier env.world dimension",
            OracleFacts.validateWorldPolicy(policy(rel("r1", "action.params.x"), rel("r2", "env.world.r2"))),
        )
    }

    @Test fun queryCoverage() {
        assertTrue(OracleFacts.queryCovers(emptyMap<String, Any?>(), emptyMap<String, Any?>()))
        assertTrue(OracleFacts.queryCovers(emptyMap<String, Any?>(), mapOf("a" to 1L)))
        assertFalse(OracleFacts.queryCovers(mapOf("a" to 1L), emptyMap<String, Any?>()))
        assertTrue(OracleFacts.queryCovers(mapOf("a" to 1L), mapOf("a" to 1L, "b" to "x")))
        assertFalse(OracleFacts.queryCovers(mapOf("a" to 1L), mapOf("a" to 2L)))
        assertFalse(OracleFacts.queryCovers(mapOf("a" to 1L, "b" to "x"), mapOf("a" to 1L)))
    }
}
