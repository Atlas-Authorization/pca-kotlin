package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the outcome space derived from a site's signed action schema. */
@Suppress("UNCHECKED_CAST")
class IntentSchemaDiffTest {
    private val m = "ref-intent-schema"

    private fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    @Test fun deriveSchemaOmega() = OracleCases.each(m, "deriveSchemaOmega") { a ->
        val r = IntentSchema.deriveOmegaFromSchema(mp(a[0]))
        linkedMapOf<String, Any?>("omega" to IntentOmega.omegaToJson(r.omega), "overrides" to r.overrides, "defaults" to r.defaults, "canonOf" to LinkedHashMap<String, Any?>(r.canonOf))
    }

    @Test fun canonValue() = OracleCases.each(m, "canonValue") { a -> IntentSchema.canonValue(mp(a[0]), a[1]) }

    @Test fun effectiveSensitivity() = OracleCases.each(m, "effectiveSensitivity") { a ->
        IntentSchema.effectiveSensitivity(mp(a[0]), if (a.size > 1) mp(a[1]) else null)
    }

    @Test fun verbReversibility() = OracleCases.each(m, "verbReversibility") { a -> IntentSchema.verbReversibility(mp(a[0])) }

    @Test fun walletFloorOverrides() = OracleCases.each(m, "walletFloorOverrides") { a ->
        IntentSchema.walletFloorOverrides(IntentOmega.arr(a[0]), if (a.size > 1) mp(a[1]) else null)
    }
}
