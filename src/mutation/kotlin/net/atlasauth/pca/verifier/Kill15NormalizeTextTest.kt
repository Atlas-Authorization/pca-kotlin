package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.m
import org.junit.Assert.assertEquals
import org.junit.Test

/** A bare Double reaches the reference-text helpers spelled as JavaScript prints it (1.0 -> "1"), never as Kotlin's toString. */
class Kill15NormalizeTextTest {
    @Test fun assuranceTextOfADouble() {
        assertEquals("1", KUtil.priv<String>(Assurance, "text", 1.0))
        assertEquals("1,2", KUtil.priv<String>(Assurance, "text", listOf(1.0, 2.0)))
    }

    @Test fun decisionJsOfADouble() {
        assertEquals("1", KUtil.priv<String>(PcaDecision, "js", 1.0))
        assertEquals("1,2", KUtil.priv<String>(PcaDecision, "js", listOf(1.0, 2.0)))
    }

    @Test fun denialReasonNamesTheDoubleVerbAndResource() {
        val preds = Json.parseLenient("[{\"verb\":\"get\"}]")
        val ctx = m("action" to m("verb" to 1.0, "resource" to 2.0))
        assertEquals("no predicate permits 1 on 2", Predicates.denialReason(preds, ctx))
    }

    @Test fun historyNumberTextOfNonFiniteDoubles() {
        assertEquals("NaN", KUtil.priv<String>(IntentHistory, "jsNum", Double.NaN))
        assertEquals("Infinity", KUtil.priv<String>(IntentHistory, "jsNum", Double.POSITIVE_INFINITY))
        assertEquals("-Infinity", KUtil.priv<String>(IntentHistory, "jsNum", Double.NEGATIVE_INFINITY))
        assertEquals("3", KUtil.priv<String>(IntentHistory, "jsNum", 3.0))
    }
}
