package net.atlasauth.pca.schema

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle for the wire JSON Schemas and the structural validator. */
@Suppress("UNCHECKED_CAST")
class SchemaDiffTest {
    private val MODULE = "ref-schema"

    private fun pick(s: Any?): Map<String, Any?> = when (s) {
        is Map<*, *> -> s as Map<String, Any?>
        "PCActn" -> Schema.pcactnSchema()
        "Capability" -> Schema.capabilitySchema()
        "PcaDiscoveryDocument" -> Schema.discoverySchema()
        else -> throw IllegalArgumentException("unknown schema $s")
    }

    @Test fun schemas() = OracleCases.each(MODULE, "schemas") { Schema.allSchemas() }

    @Test fun validate() = OracleCases.each(MODULE, "validate") { a -> Schema.validate(pick(a[0]), a[1]).toJson() }
}
