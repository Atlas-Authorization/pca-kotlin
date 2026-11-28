package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over selector matching, the policy decision and the signed review confirmation. */
@Suppress("UNCHECKED_CAST")
class ActionsSelConfDiffTest {
    private val MOD = "ref-actions-sel-conf"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun selectorMatches() = OracleCases.each(MOD, "selectorMatches") { a -> ActionSelectors.selectorMatches(a[0], l(a[1])) }

    @Test fun selectorMatchesFor() = OracleCases.each(MOD, "selectorMatchesFor") { a -> ActionSelectors.selectorMatchesFor(a[0], a[1] as String, l(a[2]), a[3] as Boolean) }

    @Test fun selectorHasNot() = OracleCases.each(MOD, "selectorHasNot") { a -> ActionSelectors.selectorHasNot(a[0]) }

    @Test fun allowSelectorError() = OracleCases.each(MOD, "allowSelectorError") { a -> ActionSelectors.allowSelectorError(a[0], a[1] as Boolean) }

    @Test fun policyDecision() = OracleCases.each(MOD, "policyDecision") { a -> ActionSelectors.policyDecision(m(a[0]), a[1] as String, l(a[2]), a[3] as Boolean) }

    @Test fun blankReason() = OracleCases.each(MOD, "blankReason") { a -> ActionConfirmation.blankReason(a[0] as String) }

    @Test fun reviewMessage() = OracleCases.each(MOD, "reviewMessage") { a -> ActionConfirmation.reviewMessage(m(a[0])) }

    @Test fun signReview() = OracleCases.each(MOD, "signReview") { a -> ActionConfirmation.signReview(m(a[0]), Keys.unb64u(m(a[1])["\$bytes"] as String)) }

    @Test fun verbConfirmationError() = OracleCases.each(MOD, "verbConfirmationError") { a ->
        // the corpus always passes the pins: a JSON null is a present value that is not a pins object, only an absent one is "no reviewer keys"
        if (a[2] == null) return@each "bad pins: " + ActionConfirmation.reviewerPinsError(null)
        ActionConfirmation.verbConfirmationError(
            m(a[0]),
            if (a[1] == null) Actions.CORE_REGISTRY else Actions.extendRegistry(Actions.CORE_REGISTRY, l(a[1])),
            a[2],
        )
    }
}
