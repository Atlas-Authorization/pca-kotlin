package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** Empty-collection edges of the action-schema shape rules (a Kotlin `all {}` over an empty collection is true). */
class K042ActionSchemaGapTest {
    private val HEAD = "{\"v\":1,\"kind\":\"pca-action-schema\",\"site\":\"https://s.example\",\"aud\":\"s.example\",\"version\":\"1\",\"units\":{\"usd_cents\":{\"kind\":\"money\"}},\"verbs\":[{\"verb\":\"a.b\",\"kind\":\"write\","
    private val TAIL = "\"sig\":{\"alg\":\"ed25519\",\"kid\":\"k1\",\"value\":\"AA\"}}"
    private val PARAMS = "\"params\":{\"action.params.x\":{\"type\":\"string\",\"semantic\":\"s\",\"sensitivity\":\"free\"}}"
    private fun shape(verbExtra: String) = ActionSchema.shapeError(IntentJs.normalize(Json.parseLenient("$HEAD$PARAMS$verbExtra}],$TAIL")))

    @Test fun emptyReversibilityByIsJudgedByItsMissingParam() {
        assertEquals("verb 'a.b': reversibility_by.param must be a declared parameter", shape(",\"reversibility_by\":{}"))
        assertEquals("verb 'a.b': reversibility_by must be {param, map, default?}", shape(",\"reversibility_by\":{\"zz\":1}"))
        assertEquals("verb 'a.b': reversibility_by must be {param, map, default?}", shape(",\"reversibility_by\":[]"))
        assertEquals("verb 'a.b': reversibility_by.map must map values to reversibility classes", shape(",\"reversibility_by\":{\"param\":\"action.params.x\"}"))
        assertEquals("verb 'a.b': reversibility_by.map must map values to reversibility classes", shape(",\"reversibility_by\":{\"param\":\"action.params.x\",\"map\":{}}"))
        assertEquals("verb 'a.b': reversibility_by.map must map values to reversibility classes", shape(",\"reversibility_by\":{\"param\":\"action.params.x\",\"map\":{\"a\":\"nope\"}}"))
    }

    @Test fun emptyValuesAndSetsAreRefused() {
        val h = "{\"v\":1,\"kind\":\"pca-action-schema\",\"site\":\"https://s.example\",\"aud\":\"s.example\",\"version\":\"1\",\"units\":{\"usd_cents\":{\"kind\":\"money\"}},\"verbs\":[{\"verb\":\"a.b\",\"kind\":\"write\",\"params\":{\"action.params.x\":"
        fun decl(d: String) = ActionSchema.shapeError(IntentJs.normalize(Json.parseLenient("$h$d}}],$TAIL")))
        assertEquals("verb 'a.b': action.params.x: values must be 1..${ActionSchema.MAX_SCHEMA_VALUES} strings", decl("{\"type\":\"string\",\"semantic\":\"s\",\"sensitivity\":\"free\",\"values\":[]}"))
    }
}
