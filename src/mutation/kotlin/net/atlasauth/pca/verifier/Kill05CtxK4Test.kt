package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for K4.kt, pinned to packages/pca-payments (escalation pricing / decision / calibration, the network-token
 * binding, the ERC-7715 granted-permission check): Luhn and PAN-length edges, every pricing-config bound (each valid
 * variant is signed at runtime), the min(p * m, 1e12) cap and the 1e12 scale, the fail-closed paths, and each refusal
 * of a granted permission.
 */
class Kill05CtxK4Test {
    private val label = "k05-k4-principal"
    private val principal = IntentTestKit.pub(label)
    private val zeroSig = Pca.b64(ByteArray(64))

    private fun signed(kind: String, m: LinkedHashMap<String, Any?>): LinkedHashMap<String, Any?> {
        val body = LinkedHashMap(m)
        body.remove("sig")
        val digest = Pca.hashCanonical(linkedMapOf<String, Any?>("kind" to kind, "body" to body))
        m["sig"] = IntentTestKit.sign(label, digest.toByteArray(Charsets.UTF_8))
        return m
    }

    private fun rawConfig(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("v" to 1L, "principal" to principal, "currency" to "USD", "interruptionCost" to 100L,
            "maxInterruptionCost" to 500L, "hardCeilingLoss" to 100_000L, "tightenStepPpm" to 500_000L, "epoch" to 1L, "sig" to zeroSig)
        for ((k, v) in over) m[k] = v
        return m
    }

    private fun config(vararg over: Pair<String, Any?>) = signed("pca.escalation_pricing", rawConfig(*over))

    @Test
    fun luhnAndPanLength() {
        for (p in listOf("4111111111111111", "5555555555554444", "378282246310005", "6011111111111117", "4012888888881881",
            "5105105105105100", "5000000000005", "5900000000000000006")) assertTrue(p, K4.looksLikePan(p))
        // Luhn-valid runs of 12 and 20 digits are not PANs
        for (p in listOf("400000000002", "40000000000000000002", "4111111111111112")) assertFalse(p, K4.looksLikePan(p))
        assertEquals("token_ref_looks_like_pan", K4.tokenRefError("tok_5555-5555-5555-4444"))
        assertEquals("token_ref_malformed", K4.tokenRefError(5))
        assertEquals("token_ref_malformed", K4.tokenRefError("short"))
        assertNull(K4.tokenRefError("tok_abcdef123456"))
    }

    @Test
    fun pricingConfigBounds() {
        assertNull(K4.pricingConfigError(config()))
        val ok = listOf<Pair<String, Any?>>("interruptionCost" to 0L, "interruptionCost" to 500L, "epoch" to 0L,
            "tightenStepPpm" to 0L, "tightenStepPpm" to K4.MAX_MULTIPLIER_PPM)
        for (o in ok) assertNull("$o", K4.pricingConfigError(config(o)))
        // refused before the signature is looked at: the zero signature never matters
        assertEquals("config_malformed", K4.pricingConfigError(rawConfig("currency" to 5L)))
        assertEquals("config_malformed", K4.pricingConfigError(config("currency" to 5L)))
        assertEquals("config_amounts_invalid", K4.pricingConfigError(rawConfig("epoch" to "x")))
        assertEquals("config_amounts_invalid", K4.pricingConfigError(rawConfig("epoch" to -1L)))
        for (s in listOf<Any?>("x", -1L, K4.MAX_MULTIPLIER_PPM + 1, null))
            assertEquals("$s", "config_step_invalid", K4.pricingConfigError(rawConfig("tightenStepPpm" to s)))
        // undecodable key or signature: malformed, not merely a bad signature
        assertEquals("config_malformed", K4.pricingConfigError(rawConfig("principal" to "!")))
        assertEquals("config_malformed", K4.pricingConfigError(rawConfig("sig" to "!")))
        assertEquals("config_signature_invalid", K4.pricingConfigError(rawConfig()))
    }

    private val risk: Map<String, Any?> = mapOf("currency" to "USD", "loss" to 1000L, "pBadUpperPpm" to 100_000L)
    private fun cal(m: Long) = mapOf("multiplierPpm" to m)
    private fun risk(vararg over: Pair<String, Any?>) = LinkedHashMap(risk).apply { for ((k, v) in over) put(k, v) }

    @Test
    fun decideEdges() {
        val cfg = config()
        fun ask(reason: String, c: Any?, cl: Any?, r: Any?) {
            val v = K4.decide(c, cl, r)
            assertTrue(reason, v.ask)
            assertEquals(reason, v.reason)
        }
        ask("config_malformed", "x", cal(1_000_000), risk)
        ask("currency_mismatch", cfg, cal(1_000_000), "x")
        ask("calibration_invalid", cfg, null, risk)
        ask("calibration_invalid", cfg, "x", risk)
        for (r in listOf(risk("loss" to -1L), risk("loss" to "x"), risk("pBadUpperPpm" to -1L), risk("pBadUpperPpm" to "x"),
            risk("pBadUpperPpm" to 1_000_001L)))
            ask("risk_input_invalid", cfg, cal(1_000_000), r)
        // p * m above 1e12 is capped at 1e12: loss == cost is within
        val v = K4.decide(cfg, cal(2_000_000), risk("loss" to 100L, "pBadUpperPpm" to 1_000_000L))
        assertFalse(v.ask)
        assertEquals("expected_loss_within_interruption_cost", v.reason)
        // the 1e12 scale exactly: cost 1e6, p * m = 1e12, loss 1e6 + 1 asks
        val big = config("interruptionCost" to 1_000_000L, "maxInterruptionCost" to 1_000_000L, "hardCeilingLoss" to 2_000_000L)
        ask("expected_loss_exceeds_interruption_cost", big, cal(1_000_000), risk("loss" to 1_000_001L, "pBadUpperPpm" to 1_000_000L))
        assertFalse(K4.decide(big, cal(1_000_000), risk("loss" to 1_000_000L, "pBadUpperPpm" to 1_000_000L)).ask)
    }

    private fun answer(nonce: String, digest: String, vararg extra: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("v" to 1L, "principal" to principal, "nonce" to nonce, "action_digest" to digest, "answer" to "deny")
        for ((k, v) in extra) m[k] = v
        return signed("pca.escalation_answer", m)
    }

    @Test
    fun calibrationFailsClosed() {
        val risks = mapOf<String, Any?>("d1" to risk)
        // a denied auto-approved action tightens
        var c = K4.updateCalibration(config(), 1_000_000L, emptyList(), listOf(answer("nonce-0001", "d1")), risks)
        assertEquals(1_500_000L, c.multiplierPpm)
        assertEquals(listOf("nonce-0001"), c.seen)
        // an answer that cannot be canonicalised is ignored, not counted
        val junk = linkedMapOf<String, Any?>("v" to 1L, "principal" to principal, "nonce" to "nonce-0002", "action_digest" to "d1",
            "answer" to "deny", "junk" to Any(), "sig" to zeroSig)
        c = K4.updateCalibration(config(), 1_000_000L, emptyList(), listOf(junk), risks)
        assertEquals(1_000_000L, c.multiplierPpm)
        assertEquals(emptyList<String>(), c.seen)
        // a bad config changes nothing and keeps the seen list
        c = K4.updateCalibration("x", 1_500_000L, listOf("n1"), listOf(answer("nonce-0003", "d1")), risks)
        assertEquals(1_500_000L, c.multiplierPpm)
        assertEquals(listOf("n1"), c.seen)
    }

    private val holderLabel = "k05-k4-holder"
    private val holder = IntentTestKit.pub(holderLabel)
    private val grant = mapOf("kind" to "g", "n" to 1L)

    private fun binding(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val b = linkedMapOf<String, Any?>("kind" to K4.BINDING_KIND, "provider" to "visa_ic", "token_ref" to "tok_abcdef123456",
            "grant_digest" to Pca.hashCanonical(grant), "issuer_nonce" to "issuer-nonce-0123456789", "holder" to holder)
        for ((k, v) in over) b[k] = v
        val body = linkedMapOf<String, Any?>("kind" to K4.BINDING_KIND, "v" to 1, "provider" to b["provider"], "token_ref" to b["token_ref"],
            "grant_digest" to b["grant_digest"], "issuer_nonce" to b["issuer_nonce"], "holder" to b["holder"])
        b["binding_proof"] = IntentTestKit.sign(holderLabel, Pca.hashCanonical(body).toByteArray(Charsets.UTF_8))
        return b
    }

    @Test
    fun bindingEncodings() {
        assertNull(K4.verifyBinding(binding(), grant, holder, "issuer-nonce-0123456789", "visa_ic"))
        assertEquals("binding_malformed", K4.verifyBinding(binding("holder" to "!"), grant, "!", "issuer-nonce-0123456789", null))
        assertEquals("binding_malformed", K4.verifyBinding(binding().also { it["binding_proof"] = "!" }, grant, holder, "issuer-nonce-0123456789", null))
        assertEquals("binding_proof_invalid", K4.verifyBinding(binding().also { it["binding_proof"] = zeroSig }, grant, holder, "issuer-nonce-0123456789", null))
    }

    private val mgr = "0xabababababababababababababababababababab"
    private val token = "0x2222222222222222222222222222222222222222"
    private val env = mapOf("grantDigest" to "gd1", "capMinor" to 1000L, "expiresAtSec" to 1_800_086_400L)

    private fun perm(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("type" to "erc20-token-allowance", "isAdjustmentAllowed" to true,
            "data" to mapOf("tokenAddress" to token, "allowance" to "0x989680"))
        for ((k, v) in over) m[k] = v
        return m
    }

    private fun expiry(ts: Any?): Map<String, Any?> = mapOf("type" to "expiry", "data" to mapOf("timestamp" to ts))
    private val sent = mapOf("chainId" to "0x2105", "to" to "0x1111111111111111111111111111111111111111", "permission" to perm(),
        "rules" to listOf(expiry(1_800_086_400L)))

    private fun got(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val m = linkedMapOf<String, Any?>("chainId" to "0x2105", "to" to "0x1111111111111111111111111111111111111111", "permission" to perm(),
            "rules" to listOf(expiry(1_800_086_400L)), "context" to "0xabc123", "dependencies" to emptyList<Any?>(), "delegationManager" to mgr)
        for ((k, v) in over) m[k] = v
        return m
    }

    private val owner: (String) -> String? = { k -> if (k == "0xabc123") "gd1" else null }

    private fun granted(g: Any?, managers: List<String> = listOf(mgr), ctx: ((String) -> String?)? = owner, e: Any? = env) =
        K4.verifyGranted(e, sent, g, managers, ctx)

    @Test
    fun grantedRefusals() {
        assertNull(granted(got()))
        assertNull(granted(got(), ctx = null))
        assertEquals("delegation_manager_not_allowed", granted(got(), managers = emptyList()))
        assertEquals("delegation_manager_not_allowed", granted(got("delegationManager" to 5L)))
        assertEquals("delegation_manager_not_allowed", granted(got("delegationManager" to "zzz"), managers = listOf("zzz")))
        assertEquals("context_malformed", granted(got("context" to 5L)))
        assertEquals("response_malformed", granted(got("permission" to perm("data" to null))))
        assertEquals("amount_malformed", granted(got("permission" to perm("data" to mapOf("tokenAddress" to token, "allowance" to 5L)))))
        assertEquals("expiry_missing", granted(got("rules" to "x")))
        assertEquals("expiry_malformed", granted(got("rules" to listOf(mapOf("type" to "expiry")))))
        assertEquals("expiry_malformed", granted(got("rules" to listOf(expiry("x")))))
        // a grant envelope without a usable expiresAtSec bounds the expiry at 0
        assertEquals("expiry_extended", granted(got("rules" to listOf(expiry(1L))), e = mapOf("grantDigest" to "gd1")))
        assertEquals("expiry_extended", granted(got("rules" to listOf(expiry(1L))), e = mapOf("grantDigest" to "gd1", "expiresAtSec" to "x")))
        assertNull(granted(got("rules" to listOf(expiry(0L))), e = mapOf("grantDigest" to "gd1")))
    }
}
