package net.atlasauth.pca.payments

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** A Stripe webhook body that repeats a member is refused as bad_json (a plain parse keeps the last); non-canonical numbers stay accepted. */
class StripeWebhookDuplicateMemberTest {
    private val secret = "whsec_test"
    private val opts = Rails.StripeWebhookOptions(secret) { mapOf("approved" to true) }.also { it.nowSec = { 1000.0 } }

    private fun send(raw: String) = Rails.stripeIssuingWebhook(opts, raw, Rails.signStripePayload(raw, secret, 1000L))

    @Test fun aRepeatedMemberIsBadJson() {
        val r = send("{\"type\":\"x\",\"type\":\"issuing_authorization.request\"}")
        assertTrue(r.toString(), (r["body"] as String).contains("bad_json"))
    }

    @Test fun nonCanonicalNumbersAreAccepted() {
        val r = send("{\"type\":\"other\",\"amount\":8.0,\"n\":1e3}")
        assertEquals("{}", r["body"])
    }
}
