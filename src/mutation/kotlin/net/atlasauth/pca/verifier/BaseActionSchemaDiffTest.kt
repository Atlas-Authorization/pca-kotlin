package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The rule-14 action schema checks against the reference (base-actionschema, 16139 cases): the v1/v2 shape of signed and unsigned documents,
 * the confirmation and floors shapes, the value check of every declared parameter type and format, and the format checkers. Reasons compare exactly.
 */
@Suppress("UNCHECKED_CAST")
class BaseActionSchemaDiffTest {
    private val mod = "base-actionschema"

    private fun count(fn: String, f: (List<Any?>) -> Any?): Int {
        OracleCases.each(mod, fn, f)
        return OracleCases.of(mod, fn).size
    }

    @Test fun everyFunction() {
        var total = 0
        total += count("shape") { a -> ActionSchema.shapeError(a[0]) }
        total += count("shapeUnsigned") { a -> ActionSchema.shapeError(a[0], false) }
        total += count("confirmation") { a -> ActionSchema.confirmationShapeError(a[0]) }
        total += count("floors") { a -> ActionSchema.schemaFloorsError(a[0]) }
        total += count("pvv") { a ->
            ActionSchema.paramValueViolation(a[0] as Map<String, Any?>, a[1])?.let { linkedMapOf("code" to it.first, "reason" to it.second) }
        }
        total += count("format") { a -> ActionSchema.formatCheck(a[0] as String)?.invoke(a[1] as String) ?: "unknown" }
        assertEquals(setOf("shape", "shapeUnsigned", "confirmation", "floors", "pvv", "format"), BaseOracle.fns("$mod.json.gz"))
        assertEquals(16139, total)
    }
}
