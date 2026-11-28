package net.atlasauth.pca.explain

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the explainer (verification, decision and chain explanations and their text). */
class ExplainDiffTest {
    private val m = "ref-explain"

    @Test fun cleanText() = OracleCases.each(m, "cleanText") { a -> Explain.cleanText(a[0]) }

    @Test fun explainVerification() = OracleCases.each(m, "explainVerification") { a -> Explain.explainVerification(a[0], a[1], a[2]) }

    @Test fun explainVerificationText() = OracleCases.each(m, "explainVerificationText") { a ->
        Explain.verificationToText(Explain.explainVerification(a[0], a[1], a[2]))
    }

    @Test fun explainDecision() = OracleCases.each(m, "explainDecision") { a -> Explain.explainDecision(a[0], a[1], a[2]) }

    @Test fun explainDecisionText() = OracleCases.each(m, "explainDecisionText") { a ->
        Explain.decisionToText(Explain.explainDecision(a[0], a[1], a[2]))
    }

    @Test fun explainChain() = OracleCases.each(m, "explainChain") { a -> Explain.explainChain(a[0], a[1]) }

    @Test fun explainChainText() = OracleCases.each(m, "explainChainText") { a -> Explain.chainToText(Explain.explainChain(a[0], a[1])) }

    @Test fun consts() = OracleCases.each(m, "consts") { _ ->
        linkedMapOf<String, Any?>("VERIFY_CHECK_ORDER" to Explain.VERIFY_CHECK_ORDER, "MAX_TEXT" to Explain.MAX_TEXT)
    }
}
