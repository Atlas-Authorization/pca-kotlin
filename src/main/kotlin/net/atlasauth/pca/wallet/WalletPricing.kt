package net.atlasauth.pca.wallet

import java.math.BigInteger
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Risk-priced escalation (the reference's escalation-pricing.ts). Rule: ask a human iff `pBadUpper * loss > interruptionCost`, in
 * integer arithmetic (probabilities in ppm, money in minor units, big-integer products; no floats, no randomness, no clock).
 * The loss and the interruption cost come from a principal-signed configuration; anything missing, out of range or unsigned means
 * ask. The only learned component is a per-principal multiplier of at least 1_000_000 that scales the probability UP, so it can
 * only add asks; the way to ask less is a principal-signed autonomy raise.
 */
@Suppress("UNCHECKED_CAST")
object WalletPricing {
    const val PPM = 1_000_000L
    const val MAX_MULTIPLIER_PPM = 100 * PPM

    private fun isMinor(n: Any?): Boolean = Wallet.isSafeInteger(n) && Wallet.nv(n) >= 0

    private fun msg(kind: String, body: Any?): ByteArray = Wallet.utf8(Pca.hashCanonical(Wallet.obj("kind", kind, "body", body)))

    private fun sigOf(kind: String, body: Any?, seed: ByteArray): String = Keys.b64u(Keys.edFromSeed(seed).sign(msg(kind, body)))

    private fun withSig(body: Map<String, Any?>, sig: String): Map<String, Any?> {
        val m = LinkedHashMap(body)
        m["sig"] = sig
        return m
    }

    private fun without(o: Map<*, *>, k: String): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for ((key, v) in o) if (k != key) m[key as String] = v
        return m
    }

    /** The principal-signed configuration {...body, sig}; [principalSeed] is the Ed25519 seed. */
    fun signPricingConfig(body: Map<String, Any?>, principalSeed: ByteArray): Map<String, Any?> =
        withSig(body, sigOf("pca.escalation_pricing", body, principalSeed))

    /** Null when the configuration is well formed and verifies; else the reason code. */
    fun pricingConfigError(c: Any?): String? {
        try {
            if (c !is Map<*, *>) return "config_malformed"
            val principal = c["principal"]
            val sig = c["sig"]
            if (!Wallet.isSafeInteger(c["v"]) || Wallet.nv(c["v"]) != 1.0 || principal !is String || c["currency"] !is String || sig !is String) return "config_malformed"
            if (!isMinor(c["interruptionCost"]) || !isMinor(c["maxInterruptionCost"]) || !isMinor(c["hardCeilingLoss"]) || !isMinor(c["epoch"])) return "config_amounts_invalid"
            if (Wallet.nv(c["interruptionCost"]) > Wallet.nv(c["maxInterruptionCost"])) return "config_cost_above_max"
            val step = c["tightenStepPpm"]
            if (!Wallet.isSafeInteger(step) || Wallet.nv(step) < 0 || Wallet.nv(step) > MAX_MULTIPLIER_PPM) return "config_step_invalid"
            if (Pca.decodeB64uStrict(principal, -1) == null || Pca.decodeB64uStrict(sig, -1) == null) return "config_malformed"
            val body = without(c, "sig")
            return if (Pca.verifyB64u(principal, msg("pca.escalation_pricing", body), sig)) null else "config_signature_invalid"
        } catch (e: RuntimeException) {
            return "config_malformed"
        }
    }

    fun freshCalibration(): Map<String, Any?> = Wallet.obj("multiplierPpm", Js.n(PPM), "seen", ArrayList<Any?>())

    private fun big(n: Any?): BigInteger = BigInteger.valueOf(Wallet.nv(n).toLong())

    /** Pure and total: {ask, reason}. [a] is {currency, loss, pBadUpperPpm}; [cal] is {multiplierPpm, seen}. */
    fun decideEscalation(config: Map<String, Any?>, cal: Any?, a: Any?): Map<String, Any?> {
        val e = pricingConfigError(config)
        if (e != null) return ask(true, e)
        if (a !is Map<*, *> || config["currency"] != a["currency"]) return ask(true, "currency_mismatch")
        val loss = a["loss"]
        val p = a["pBadUpperPpm"]
        if (!isMinor(loss) || Js.isNegZero(loss) || !Wallet.isSafeInteger(p) || Wallet.nv(p) < 0 || Js.isNegZero(p) || Wallet.nv(p) > PPM) return ask(true, "risk_input_invalid")
        val mult = Wallet.get(cal, "multiplierPpm")
        if (!(Wallet.isSafeInteger(mult) && Wallet.nv(mult) >= PPM && Wallet.nv(mult) <= MAX_MULTIPLIER_PPM)) return ask(true, "calibration_invalid")
        if (Wallet.nv(loss) > Wallet.nv(config["hardCeilingLoss"])) return ask(true, "above_hard_ceiling")
        val ppm2 = BigInteger.valueOf(PPM).multiply(BigInteger.valueOf(PPM))
        val pe = big(p).multiply(big(mult))
        val capped = if (pe.compareTo(ppm2) > 0) ppm2 else pe
        val lhs = capped.multiply(big(loss))
        val rhs = big(config["interruptionCost"]).multiply(ppm2)
        return if (lhs.compareTo(rhs) > 0) ask(true, "expected_loss_exceeds_interruption_cost") else ask(false, "expected_loss_within_interruption_cost")
    }

    private fun ask(ask: Boolean, reason: String): Map<String, Any?> = Wallet.obj("ask", ask, "reason", reason)

    /** Sign an answer {v, principal, nonce, action_digest, answer}. */
    fun signAnswer(body: Map<String, Any?>, principalSeed: ByteArray): Map<String, Any?> =
        withSig(body, sigOf("pca.escalation_answer", body, principalSeed))

    private fun answerOk(aO: Any?, principal: String): Boolean {
        try {
            if (aO !is Map<*, *>) return false
            val nonce = aO["nonce"]
            val digest = aO["action_digest"]
            val ans = aO["answer"]
            val sig = aO["sig"]
            if (!Wallet.isSafeInteger(aO["v"]) || Wallet.nv(aO["v"]) != 1.0 || principal != aO["principal"] || nonce !is String || nonce.length < 8 ||
                digest !is String || ("approve" != ans && "deny" != ans)) return false
            if (sig !is String || Pca.decodeB64uStrict(principal, -1) == null || Pca.decodeB64uStrict(sig, -1) == null) return false
            return Pca.verifyB64u(principal, msg("pca.escalation_answer", without(aO, "sig")), sig)
        } catch (e: RuntimeException) {
            return false
        }
    }

    /**
     * Fold signed answers into the calibration {multiplierPpm, seen}. A deny the principal gave to an action that the current
     * pricing would have auto-approved is a miss and adds tightenStepPpm (capped). Everything else changes nothing; the result's
     * multiplier is at least the input's for every input. [risks] maps an action digest to its risk.
     */
    fun updateCalibration(config: Map<String, Any?>, cal: Map<String, Any?>, answers: List<*>, risks: Map<String, Any?>): Map<String, Any?> {
        if (pricingConfigError(config) != null) return cal
        var mult = Wallet.nv(cal["multiplierPpm"])
        val seen = HashSet<Any?>(cal["seen"] as List<Any?>)
        val order = ArrayList<Any?>(cal["seen"] as List<Any?>)
        for (a in answers) {
            if (!answerOk(a, config["principal"] as String) || seen.contains((a as Map<*, *>)["nonce"])) continue
            seen.add(a["nonce"])
            order.add(a["nonce"])
            val digest = a["action_digest"] as String
            if ("deny" != a["answer"] || !risks.containsKey(digest)) continue
            val c = Wallet.obj("multiplierPpm", mult, "seen", ArrayList<Any?>())
            if (decideEscalation(config, c, risks[digest])["ask"].let { it == null || it == false }) { // the current pricing would have auto-approved what the principal denied: a miss
                mult = Math.min(MAX_MULTIPLIER_PPM.toDouble(), mult + Wallet.nv(config["tightenStepPpm"]))
            }
        }
        return Wallet.obj("multiplierPpm", Math.max(mult, Wallet.nv(cal["multiplierPpm"])), "seen", order)
    }

    /** Sign an autonomy raise {v, principal, epoch, newInterruptionCost}. */
    fun signAutonomyRaise(b: Map<String, Any?>, seed: ByteArray): Map<String, Any?> = withSig(b, sigOf("pca.autonomy_raise", b, seed))

    /**
     * A higher interruption cost means fewer asks. Requires the principal's signature, a strictly newer epoch and a cost no
     * higher than maxInterruptionCost; throws otherwise. Returns the re-signed configuration.
     */
    fun applyAutonomyRaise(config: Map<String, Any?>, raise: Map<String, Any?>, principalSeed: ByteArray): Map<String, Any?> {
        var ok: Boolean
        try {
            val sig = raise["sig"]
            val cp = config["principal"]
            ok = Wallet.isSafeInteger(raise["v"]) && Wallet.nv(raise["v"]) == 1.0 && raise["principal"] != null && raise["principal"] == cp && cp is String &&
                sig is String && Pca.decodeB64uStrict(cp, -1) != null && Pca.decodeB64uStrict(sig, -1) != null &&
                Pca.verifyB64u(cp, msg("pca.autonomy_raise", without(raise, "sig")), sig)
        } catch (e: RuntimeException) {
            ok = false
        }
        if (!ok) throw IllegalArgumentException("applyAutonomyRaise: signature or principal invalid")
        if (!(Wallet.nv(raise["epoch"]) > Wallet.nv(config["epoch"]))) throw IllegalArgumentException("applyAutonomyRaise: epoch must advance")
        val nc = raise["newInterruptionCost"]
        if (!isMinor(nc) || Wallet.nv(nc) > Wallet.nv(config["maxInterruptionCost"])) throw IllegalArgumentException("applyAutonomyRaise: above the configured maximum")
        val body = without(config, "sig")
        body["interruptionCost"] = nc
        body["epoch"] = raise["epoch"]
        return signPricingConfig(body, principalSeed)
    }
}
