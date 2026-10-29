package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.util.Locale

/**
 * K4 (verification side): risk-priced escalation (pricing config, decision, calibration from signed answers), the network-token
 * binding and the ERC-7715 granted-permission check. Replays packages/pca/conformance/k4-vectors.json.
 * Signatures are Ed25519 (strict) over the UTF-8 bytes of hashCanonical({"kind": kind, "body": body}) (the digest string); body is the
 * signed object without its `sig`. Escalation is integer-only (BigInteger). Total: never throws.
 */
@Suppress("UNCHECKED_CAST")
object K4 {
    const val PPM = 1_000_000L
    const val MAX_MULTIPLIER_PPM = 100 * PPM
    const val BINDING_KIND = "pca.network_token_binding"
    private val REF = Regex("[A-Za-z0-9_.:\\-]{8,128}")
    private val ADDR = Regex("0x[0-9a-fA-F]{40}")
    private val QTY = Regex("0x(0|[1-9a-fA-F][0-9a-fA-F]*)")
    private val CTX = Regex("0x[0-9a-fA-F]+")

    private fun isInt(o: Any?): Boolean = IntentJs.isSafeInteger(o)
    private fun isMinor(o: Any?): Boolean = IntentJs.isSafeInteger(o) && IntentJs.lng(o) >= 0
    private fun l(o: Any?): Long = if (IntentJs.isSafeInteger(o)) IntentJs.lng(o) else 0L
    private fun obj(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    /** null when the key or signature does not decode; else the strict verification result. */
    private fun sigOk(pub: Any?, kind: String, o: Map<String, Any?>): Boolean? {
        val sig = o["sig"]
        if (pub !is String || sig !is String || Pca.decodeB64uStrict(pub, -1) == null || Pca.decodeB64uStrict(sig, -1) == null) return null
        val body = LinkedHashMap(o)
        body.remove("sig")
        val digest = Pca.hashCanonical(linkedMapOf("kind" to kind, "body" to body))
        return Pca.verifyB64u(pub, digest.toByteArray(Charsets.UTF_8), sig)
    }

    // ---- network-token binding ----

    private fun luhn(d: String): Boolean {
        var sum = 0
        var dbl = false
        for (i in d.length - 1 downTo 0) {
            var n = d[i] - '0'
            if (dbl) { n *= 2; if (n > 9) n -= 9 }
            sum += n
            dbl = !dbl
        }
        return sum % 10 == 0
    }

    @JvmStatic
    fun looksLikePan(s: String): Boolean = s.replace(Regex("[\\s\\-]"), "").split(Regex("[^0-9]+")).any { it.length in 13..19 && luhn(it) }

    @JvmStatic
    fun tokenRefError(ref: Any?): String? {
        if (ref !is String || !REF.matches(ref)) return "token_ref_malformed"
        return if (looksLikePan(ref)) "token_ref_looks_like_pan" else null
    }

    /** null = valid, else the reason. provider null = any. */
    @JvmStatic
    fun verifyBinding(bo: Any?, grant: Any?, holder: String, issuerNonce: String, provider: String?): String? = try {
        val b = obj(bo)
        val p = b?.get("provider")
        val e = if (b == null || b["kind"] != BINDING_KIND) "binding_malformed" else tokenRefError(b["token_ref"])
        when {
            e != null -> e
            p !is String || p.isEmpty() || (provider != null && p != provider) -> "provider_mismatch"
            Pca.hashCanonical(grant) != b!!["grant_digest"] -> "grant_digest_mismatch"
            holder != b["holder"] -> "holder_mismatch"
            issuerNonce != b["issuer_nonce"] -> "issuer_nonce_mismatch"
            Pca.decodeB64uStrict(holder, -1) == null || Pca.decodeB64uStrict(b["binding_proof"], -1) == null -> "binding_malformed"
            else -> {
                val body = linkedMapOf("kind" to BINDING_KIND, "v" to 1, "provider" to p, "token_ref" to b["token_ref"],
                    "grant_digest" to b["grant_digest"], "issuer_nonce" to b["issuer_nonce"], "holder" to b["holder"])
                if (Pca.verifyB64u(holder, Pca.hashCanonical(body).toByteArray(Charsets.UTF_8), b["binding_proof"] as String)) null else "binding_proof_invalid"
            }
        }
    } catch (ex: RuntimeException) {
        "binding_malformed"
    }

    // ---- risk-priced escalation ----

    @JvmStatic
    fun pricingConfigError(co: Any?): String? = try {
        val c = obj(co)
        when {
            c == null || !isInt(c["v"]) || l(c["v"]) != 1L || c["principal"] !is String || c["currency"] !is String || c["sig"] !is String -> "config_malformed"
            listOf("interruptionCost", "maxInterruptionCost", "hardCeilingLoss", "epoch").any { !isMinor(c[it]) } -> "config_amounts_invalid"
            l(c["interruptionCost"]) > l(c["maxInterruptionCost"]) -> "config_cost_above_max"
            !isInt(c["tightenStepPpm"]) || l(c["tightenStepPpm"]) < 0 || l(c["tightenStepPpm"]) > MAX_MULTIPLIER_PPM -> "config_step_invalid"
            else -> when (sigOk(c["principal"], "pca.escalation_pricing", c)) { null -> "config_malformed"; true -> null; else -> "config_signature_invalid" }
        }
    } catch (ex: RuntimeException) {
        "config_malformed"
    }

    class Verdict(val ask: Boolean, val reason: String)

    private fun ask(r: String) = Verdict(true, r)

    /** Ask a person iff min(p * multiplier, 1e12) * loss > interruptionCost * 1e12; anything unexpected asks. */
    @JvmStatic
    fun decide(config: Any?, cal: Any?, ao: Any?): Verdict {
        pricingConfigError(config)?.let { return ask(it) }
        val cfg = obj(config)!!
        val a = obj(ao)
        if (a == null || cfg["currency"] != a["currency"]) return ask("currency_mismatch")
        if (!isMinor(a["loss"]) || !isInt(a["pBadUpperPpm"]) || l(a["pBadUpperPpm"]) < 0 || l(a["pBadUpperPpm"]) > PPM) return ask("risk_input_invalid")
        val mo = obj(cal)?.get("multiplierPpm")
        if (!isInt(mo) || l(mo) < PPM || l(mo) > MAX_MULTIPLIER_PPM) return ask("calibration_invalid")
        val loss = l(a["loss"])
        if (loss > l(cfg["hardCeilingLoss"])) return ask("above_hard_ceiling")
        val one = BigInteger.valueOf(PPM).multiply(BigInteger.valueOf(PPM))
        val capped = BigInteger.valueOf(l(a["pBadUpperPpm"])).multiply(BigInteger.valueOf(l(mo))).min(one)
        if (capped.multiply(BigInteger.valueOf(loss)) > BigInteger.valueOf(l(cfg["interruptionCost"])).multiply(one)) return ask("expected_loss_exceeds_interruption_cost")
        return Verdict(false, "expected_loss_within_interruption_cost")
    }

    private fun answerOk(ao: Any?, principal: String): Boolean = try {
        val a = obj(ao)
        a != null && isInt(a["v"]) && l(a["v"]) == 1L && a["principal"] == principal && (a["nonce"] as? String)?.let { it.length >= 8 } == true &&
            a["action_digest"] is String && (a["answer"] == "approve" || a["answer"] == "deny") && sigOk(principal, "pca.escalation_answer", a) == true
    } catch (ex: RuntimeException) {
        false
    }

    class Calibration(val multiplierPpm: Long, val seen: List<String>)

    /** Fold principal-signed answers into the calibration; the multiplier can only rise. risks: action digest to risk object. */
    @JvmStatic
    fun updateCalibration(config: Any?, startMult: Long, startSeen: List<String>, answers: List<Any?>, risks: Map<String, Any?>): Calibration {
        val order = ArrayList(startSeen)
        if (pricingConfigError(config) != null) return Calibration(startMult, order)
        val cfg = obj(config)!!
        val principal = cfg["principal"] as String
        val step = l(cfg["tightenStepPpm"])
        var mult = startMult
        for (ao in answers) {
            if (!answerOk(ao, principal)) continue
            val a = obj(ao)!!
            val nonce = a["nonce"] as String
            if (nonce in order) continue
            order.add(nonce)
            val risk = risks[a["action_digest"] as String]
            if (a["answer"] != "deny" || risk == null) continue
            if (!decide(config, linkedMapOf("multiplierPpm" to mult), risk).ask) mult = minOf(MAX_MULTIPLIER_PPM, mult + step)
        }
        return Calibration(maxOf(mult, startMult), order)
    }

    // ---- ERC-7715 granted-permission check ----

    private fun lower(o: Any?): String = if (o is String) o.lowercase(Locale.ROOT) else "\u0000"

    /** null when what the wallet granted is within the request and the grant. g = {grantDigest, expiresAtSec}. */
    @JvmStatic
    fun verifyGranted(go: Any?, sentO: Any?, gotO: Any?, allowedManagers: List<String>, contextOwner: ((String) -> String?)?): String? = try {
        verifyGrantedInner(obj(go)!!, obj(sentO)!!, obj(gotO), allowedManagers, contextOwner)
    } catch (ex: RuntimeException) {
        "response_malformed"
    }

    private fun verifyGrantedInner(g: Map<String, Any?>, sent: Map<String, Any?>, r: Map<String, Any?>?, allowedManagers: List<String>, contextOwner: ((String) -> String?)?): String? {
        val perm = obj(r?.get("permission"))
        if (r == null || perm == null) return "response_malformed"
        val ctx = r["context"]
        if (ctx !is String || !CTX.matches(ctx)) return "context_malformed"
        val owner = contextOwner?.invoke(ctx)
        if (owner != null && owner != g["grantDigest"]) return "context_bound_to_other_grant"
        val m = r["delegationManager"]
        if (m !is String || !ADDR.matches(m) || allowedManagers.none { it.equals(m, ignoreCase = true) }) return "delegation_manager_not_allowed"
        if (lower(r["chainId"]) != lower(sent["chainId"])) return "chain_mismatch"
        if (lower(r["to"]) != lower(sent["to"])) return "recipient_mismatch"
        if (sent["from"] != null && lower(r["from"]) != lower(sent["from"])) return "from_mismatch"
        val sperm = obj(sent["permission"])!!
        val pt = perm["type"]
        if (pt == null || pt != sperm["type"] || (pt != "native-token-allowance" && pt != "erc20-token-allowance")) return "permission_type_mismatch"
        val d = obj(perm["data"]) ?: return "response_malformed"
        val sd = obj(sperm["data"])!!
        val t1 = (d["tokenAddress"] as? String)?.lowercase(Locale.ROOT) ?: ""
        val t2 = (sd["tokenAddress"] as? String)?.lowercase(Locale.ROOT) ?: ""
        if (t1 != t2) return "token_mismatch"
        val al = d["allowance"]
        if (al !is String || !QTY.matches(al)) return "amount_malformed"
        if (BigInteger(al.substring(2), 16) > BigInteger((sd["allowance"] as String).substring(2), 16)) return "amount_widened"
        if (perm["isAdjustmentAllowed"] != sperm["isAdjustmentAllowed"] && perm["isAdjustmentAllowed"] == true) return "adjustment_widened"
        val rules = r["rules"] as? List<*> ?: return "expiry_missing"
        var expiry: Long? = null
        for (ru in rules) {
            val rule = obj(ru)
            if (rule == null || rule["type"] != "expiry") return "unknown_rule_type"
            if (expiry != null) return "duplicate_expiry"
            val ts = obj(rule["data"])?.get("timestamp")
            if (!isInt(ts)) return "expiry_malformed"
            expiry = IntentJs.lng(ts)
        }
        if (expiry == null) return "expiry_missing"
        return if (expiry > l(g["expiresAtSec"])) "expiry_extended" else null
    }
}
