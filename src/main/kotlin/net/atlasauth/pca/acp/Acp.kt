package net.atlasauth.pca.acp

import java.util.Locale
import net.atlasauth.pca.a2a.A2aPca
import net.atlasauth.pca.acp.AcpJs.dbl
import net.atlasauth.pca.acp.AcpJs.def
import net.atlasauth.pca.acp.AcpJs.isAmount
import net.atlasauth.pca.acp.AcpJs.num
import net.atlasauth.pca.acp.AcpJs.str
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaCore

/**
 * Agentic Commerce Protocol (ACP) and x402 for PCA. PCA governs; ACP mints the delegated one-time payment token; x402 (HTTP 402) is the pay
 * rail. A delegated payment token is a JWS minted FROM a PCActn and carries that proof's authority by reference (its digest); the proof's
 * capability caveats (spend cap, merchant / category allowlist, human-present) gate issuance. At settlement the token's
 * session / merchant / amount / expiry binding is re-checked and the bound PCActn can be re-verified, failing closed.
 *
 * Values are parsed JSON (Map, List, String, Boolean, Json.Num, null) and option bags are Maps keyed by the reference's option names, so a
 * reader can map every call one to one. Keys are JWK maps (`signingKey` private, `verifyKey` public). The reference's async
 * calls are plain blocking calls here. See [X402V2], [X402Http] and [StripeSpt] for the rest of the package surface.
 */
@Suppress("UNCHECKED_CAST")
object Acp {
    const val ACP_DELEGATED_TOKEN_VERSION = 1
    const val ACP_DELEGATED_TOKEN_TYPE = "acp-delegated-payment"
    const val SPEND_CAP_CAVEAT = "max_amount"
    const val MERCHANT_ALLOW_CAVEAT = "merchant_allow"
    const val MERCHANT_CATEGORY_CAVEAT = "merchant_category"
    const val HUMAN_PRESENT_CAVEAT = "human_present"

    /** Thrown when a delegated payment token cannot be minted because the request exceeds the proof's authority. */
    class AcpAuthorityException(message: String) : RuntimeException(message)

    /** Atomic first-use claim: true exactly once per jti (a conditional insert). A throw fails closed. */
    fun interface SingleUseStore {
        @Throws(Exception::class)
        fun claim(jti: String, expiresAtMs: Double): Boolean
    }

    /** An injectable function that verifies an x402 payment payload: `{ok, reason?, claims?}`. */
    fun interface X402Verify {
        @Throws(Exception::class)
        fun verify(payload: Any?): Map<String, Any?>
    }

    /** An injectable settlement step run once payment is verified; its return value becomes the receipt (null = none). */
    fun interface X402Settler {
        @Throws(Exception::class)
        fun settle(payload: Any?, claims: Map<String, Any?>): Any?
    }

    // ---- caveat builders ----

    @JvmStatic
    fun spendCapCaveat(max: Long): Map<String, Any?> = linkedMapOf("type" to SPEND_CAP_CAVEAT, "max" to num(max))

    @JvmStatic
    fun spendCapCaveat(max: Long, currency: String): Map<String, Any?> = LinkedHashMap(spendCapCaveat(max)).also { it["currency"] = currency }

    @JvmStatic
    fun merchantAllowCaveat(merchants: List<String>): Map<String, Any?> = linkedMapOf("type" to MERCHANT_ALLOW_CAVEAT, "merchants" to ArrayList<Any?>(merchants))

    @JvmStatic
    fun merchantCategoryCaveat(categories: List<String>): Map<String, Any?> =
        linkedMapOf("type" to MERCHANT_CATEGORY_CAVEAT, "categories" to ArrayList<Any?>(categories))

    @JvmStatic
    @JvmOverloads
    fun humanPresentCaveat(required: Boolean = true): Map<String, Any?> = linkedMapOf("type" to HUMAN_PRESENT_CAVEAT, "required" to required)

    // ---- payment authority ----

    private fun asStringArray(v: Any?, label: String): List<Any?> {
        if (!Js.allStrings(v)) throw AcpAuthorityException("malformed $label caveat: expected a string[] (fail closed)")
        return v as List<Any?>
    }

    /**
     * Collapse a leaf capability's cumulative caveat list into its effective payment authority `{maxAmount?, currency?, merchants (list or null),
     * categories (list or null), humanPresentRequired}`. Payment caveats combine conjunctively (tightest cap, intersected allowlists, sticky
     * human-present); a malformed PAYMENT caveat throws [AcpAuthorityException] (fail closed); any other caveat type is ignored.
     */
    @JvmStatic
    fun extractPaymentAuthority(caveatsIn: Any?): Map<String, Any?> {
        // for-of: a string iterates its characters (none of them a payment caveat); any other non-array is not iterable
        val caveats: List<*> = if (caveatsIn is String) caveatsIn.codePoints().toArray().map { String(Character.toChars(it)) }
            else caveatsIn as? List<*> ?: throw IllegalArgumentException("caveats must be an array")
        var maxAmount: Long? = null
        var currency: String? = null
        var merchants: List<Any?>? = null
        var categories: List<Any?>? = null
        var humanPresentRequired = false
        for (c in caveats) {
            if (c == null) throw IllegalArgumentException("caveat is null")
            val type = AcpJs.get(c, "type") as? String ?: continue
            when (type) {
                SPEND_CAP_CAVEAT -> {
                    val max = AcpJs.get(c, "max")
                    if (!AcpJs.isSafeInteger(max) || Js.num(max)!! < 0 || Js.isNegZero(max)) {
                        throw AcpAuthorityException("malformed max_amount caveat: max must be an integer >= 0 in minor units (fail closed)")
                    }
                    val m = AcpJs.lng(max)
                    val prev = maxAmount
                    maxAmount = if (prev == null) m else Math.min(prev, m)
                    if (def(c, "currency")) {
                        val cur = AcpJs.get(c, "currency")
                        if (!AcpJs.nonEmpty(cur)) throw AcpAuthorityException("malformed max_amount caveat: currency must be a non-empty string (fail closed)")
                        if (currency != null && currency != cur) throw AcpAuthorityException("conflicting spend-cap currencies \"$currency\" vs \"$cur\" (fail closed)")
                        currency = cur as String
                    }
                }
                MERCHANT_ALLOW_CAVEAT -> {
                    val list = asStringArray(AcpJs.get(c, "merchants"), "merchant_allow")
                    val prev = merchants
                    merchants = if (prev == null) ArrayList<Any?>(LinkedHashSet<Any?>(list)) else intersect(prev, list)
                }
                MERCHANT_CATEGORY_CAVEAT -> {
                    val list = asStringArray(AcpJs.get(c, "categories"), "merchant_category")
                    val prev = categories
                    categories = if (prev == null) ArrayList<Any?>(LinkedHashSet<Any?>(list)) else intersect(prev, list)
                }
                HUMAN_PRESENT_CAVEAT -> {
                    val req = AcpJs.get(c, "required")
                    if (req !is Boolean) throw AcpAuthorityException("malformed human_present caveat: required must be a boolean (fail closed)")
                    humanPresentRequired = humanPresentRequired || req
                }
                else -> {} // non-payment caveat (ttl, scope, resource, ...): not this adapter's concern
            }
        }
        val out = LinkedHashMap<String, Any?>()
        val ma = maxAmount
        if (ma != null) out["maxAmount"] = num(ma)
        if (currency != null) out["currency"] = currency
        out["merchants"] = merchants
        out["categories"] = categories
        out["humanPresentRequired"] = humanPresentRequired
        return out
    }

    private fun intersect(a: List<Any?>, b: List<Any?>): List<Any?> = ArrayList<Any?>(a.filter { b.contains(it) })

    private fun check(ok: Boolean, reason: String?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        if (reason != null) m["reason"] = reason
        return m
    }

    /**
     * Check a purchase request `{amount, currency, merchant, category?, humanPresent?}` against a payment authority (the output of
     * [extractPaymentAuthority]). Pure and fail-closed. Returns `{ok}` or `{ok:false, reason}`.
     */
    @JvmStatic
    fun checkPaymentAuthority(authority: Map<String, Any?>, request: Map<String, Any?>): Map<String, Any?> {
        val amount = request["amount"]
        if (!isAmount(amount)) return check(false, "amount must be a positive integer in minor units")
        if (!AcpJs.nonEmpty(request["currency"])) return check(false, "currency must be a non-empty string")
        if (!AcpJs.nonEmpty(request["merchant"])) return check(false, "merchant must be a non-empty string")
        val currency = request["currency"]
        val merchant = request["merchant"]
        if (def(authority, "currency") && authority["currency"] != currency) {
            return check(false, "currency \"$currency\" is not the authorized currency \"${str(authority["currency"])}\"")
        }
        // a present cap must be a non-negative safe integer (NaN, infinities, negatives, -0 and fractions are refused); an absent one is unbounded
        if (def(authority, "maxAmount")) {
            val cap = Js.num(authority["maxAmount"])
            if (cap == null || !AcpJs.safe(cap) || cap < 0 || java.lang.Double.doubleToRawLongBits(cap) == java.lang.Double.doubleToRawLongBits(-0.0)) {
                return check(false, "authorized spend cap is not a non-negative integer (fail closed)")
            }
        }
        if (def(authority, "maxAmount") && !(dbl(amount) <= dbl(authority["maxAmount"]))) {
            return check(false, "amount ${str(amount)} exceeds the authorized spend cap ${str(authority["maxAmount"])}")
        }
        val merchants = authority["merchants"]
        if (merchants != null && !(merchants as List<Any?>).contains(merchant)) return check(false, "merchant \"$merchant\" is not in the authorized allowlist")
        val categories = authority["categories"]
        if (categories != null) {
            if (!def(request, "category")) return check(false, "the proof constrains merchant categories but no category was supplied")
            val cat = request["category"]
            if (!(categories as List<Any?>).contains(cat)) return check(false, "category \"${str(cat)}\" is not in the authorized allowlist")
        }
        if (authority["humanPresentRequired"] == true && request["humanPresent"] != true) {
            return check(false, "the proof requires a human-present charge but humanPresent was not asserted")
        }
        return check(true, null)
    }

    // ---- authority reference ----

    private fun leafCapability(pcActn: Any?): Map<String, Any?> {
        val chain = AcpJs.get(pcActn, "cap_chain")
        if (chain !is List<*> || chain.isEmpty()) throw AcpAuthorityException("PCActn carries no capability chain (fail closed)")
        val leaf = chain[chain.size - 1]
        if (leaf !is Map<*, *>) throw IllegalArgumentException("capability chain leaf is not an object")
        return leaf as Map<String, Any?>
    }

    private fun copy(to: MutableMap<String, Any?>, key: String, from: Any?, fromKey: String) {
        if (def(from, fromKey)) to[key] = AcpJs.get(from, fromKey)
    }

    private fun authorityRef(pcActn: Any?): Map<String, Any?> {
        val leaf = leafCapability(pcActn)
        val ref = LinkedHashMap<String, Any?>()
        ref["digest"] = Pca.hashCanonical(pcActn)
        copy(ref, "aud", pcActn, "aud")
        copy(ref, "grant_ref", pcActn, "grant_ref")
        copy(ref, "leaf_holder", leaf, "holder")
        val action = AcpJs.get(pcActn, "action")
        // `pcActn.action.verb`: a missing or null action throws
        if (action == null) throw IllegalArgumentException("Cannot read properties of " + (if ((pcActn as? Map<*, *>)?.containsKey("action") == true) "null" else "undefined") + " (reading 'verb')")
        copy(ref, "verb", action, "verb")
        copy(ref, "resource", action, "resource")
        copy(ref, "params_digest", action, "params_digest")
        return ref
    }

    private fun finite(d: Double?): Boolean = d != null && !d.isNaN() && !d.isInfinite()

    private fun nowOf(opts: Map<String, Any?>): Double {
        val n = Js.num(opts["now"])
        return if (finite(n)) n!! else System.currentTimeMillis().toDouble()
    }

    private fun nowValue(opts: Map<String, Any?>): Any? = if (finite(Js.num(opts["now"]))) opts["now"] else num(System.currentTimeMillis())

    // ---- mint ----

    /**
     * Mint a one-time ACP delegated payment token (a JWS) FROM a PCActn. [opts]: amount, currency, merchant, session, expiresAt (epoch ms),
     * paymentMethod {type, display?, token?}, signingKey (private JWK), alg (default EdDSA), category?, humanPresent?, issuer?, kid?, jti?, now?.
     * The PCActn's caveats gate issuance: throws [AcpAuthorityException] when the request exceeds the proof's authority or the expiry is in the past
     * or outlives the proof. The token carries the proof only by digest.
     */
    @JvmStatic
    fun mintDelegatedPaymentToken(pcActn: Any?, opts: Map<String, Any?>): String {
        val nowV = nowValue(opts)
        val now = nowOf(opts)

        val authority = extractPaymentAuthority(leafCapability(pcActn)["caveats"])
        val request = LinkedHashMap<String, Any?>()
        for (k in listOf("amount", "currency", "merchant", "category", "humanPresent")) if (def(opts, k)) request[k] = opts[k]
        val chk = checkPaymentAuthority(authority, request)
        if (chk["ok"] != true) throw AcpAuthorityException("refused: " + (chk["reason"] ?: "request exceeds the proof authority"))

        val exp = Js.num(opts["expiresAt"])
        if (exp == null || exp.isNaN() || exp.isInfinite()) throw AcpAuthorityException("refused: expiresAt must be a finite epoch-ms timestamp")
        if (!(exp > now)) throw AcpAuthorityException("refused: expiresAt is not in the future")
        if (!(AcpJs.dblField(pcActn, "exp").isFinite() && exp <= AcpJs.dblField(pcActn, "exp"))) {
            throw AcpAuthorityException("refused: token expiry ${str(opts["expiresAt"])} would outlive the proof's exp ${str(AcpJs.get(pcActn, "exp"))}")
        }
        if (!Js.truthy(opts["session"])) throw AcpAuthorityException("refused: a session id is required")

        val pca = authorityRef(pcActn)
        var jti = opts["jti"]
        if (jti == null) {
            val seed = LinkedHashMap<String, Any?>(AcpJs.map(pcActn))
            seed["nonce"] = "acp:" + str(opts["session"]) + ":" + str(opts["merchant"]) + ":" + str(opts["amount"]) + ":" + str(opts["currency"]) + ":" +
                str(opts["expiresAt"]) + ":" + pca["digest"]
            jti = Pca.hashCanonical(seed)
        }

        val claims = LinkedHashMap<String, Any?>()
        claims["typ"] = ACP_DELEGATED_TOKEN_TYPE
        claims["ver"] = num(ACP_DELEGATED_TOKEN_VERSION.toLong())
        claims["jti"] = jti
        claims["session"] = opts["session"]
        claims["merchant"] = opts["merchant"]
        claims["amount"] = opts["amount"]
        claims["currency"] = opts["currency"]
        claims["iat"] = nowV
        claims["exp"] = opts["expiresAt"]
        claims["paymentMethod"] = AcpJs.spread(opts["paymentMethod"])
        claims["humanPresent"] = opts["humanPresent"] == true
        if (def(opts, "category")) claims["category"] = opts["category"]
        if (def(opts, "issuer")) claims["iss"] = opts["issuer"]
        claims["pca"] = pca

        val alg = if (opts["alg"] != null) opts["alg"] as String else "EdDSA"
        val header = LinkedHashMap<String, Any?>()
        header["alg"] = alg
        header["typ"] = ACP_DELEGATED_TOKEN_TYPE
        if (def(opts, "kid")) header["kid"] = opts["kid"]
        val sk = opts["signingKey"] as? Map<String, Any?> ?: throw IllegalArgumentException("signingKey must be a private JWK")
        return Jose.signJwt(header, claims, sk)
    }

    // ---- verify ----

    private fun parseClaims(c: Map<String, Any?>?): Map<String, Any?>? {
        if (c == null) return null
        if (ACP_DELEGATED_TOKEN_TYPE != c["typ"] || Js.num(c["ver"]) != ACP_DELEGATED_TOKEN_VERSION.toDouble()) return null
        for (k in listOf("jti", "session", "merchant", "currency")) if (!AcpJs.nonEmpty(c[k])) return null
        if (!isAmount(c["amount"])) return null
        if (!Js.isNumber(c["iat"]) || !finite(Js.num(c["iat"])) || !Js.isNumber(c["exp"]) || !finite(Js.num(c["exp"]))) return null
        if (c["humanPresent"] !is Boolean) return null
        val pm = c["paymentMethod"]
        if (pm !is Map<*, *> || pm["type"] !is String) return null
        val p = c["pca"]
        if (p !is Map<*, *>) return null
        for (k in listOf("digest", "aud", "grant_ref", "leaf_holder", "verb", "resource", "params_digest")) if (p[k] !is String) return null
        return c
    }

    private fun verdict(ok: Boolean, reason: String?, claims: Map<String, Any?>?, pcaResult: Map<String, Any?>?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        if (reason != null) m["reason"] = reason
        if (claims != null) m["claims"] = claims
        if (pcaResult != null) m["pcaResult"] = pcaResult
        return m
    }

    /**
     * Verify a delegated payment token at settlement. [opts]: expectedMerchant, amount, verifyKey (public JWK), alg, now, expectedSession,
     * expectedCurrency, pcActn, grant, audience (a string must equal; an explicit null accepts any; omitted fails when the PCActn carries an aud),
     * authorizedPlanRoots, insecureSkipPlanRootCheck, singleUse ([SingleUseStore]), strict (default true: requires singleUse and expectedCurrency).
     * Returns `{ok, reason?, claims?, pcaResult?}`; fails CLOSED on every mismatch.
     */
    @JvmStatic
    fun verifyDelegatedPaymentToken(token: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        if (opts["strict"] != false) {
            if (opts["singleUse"] !is SingleUseStore) return verdict(false, "strict settlement requires a singleUse store (fail closed)", null, null)
            if (!AcpJs.nonEmpty(opts["expectedCurrency"])) return verdict(false, "strict settlement requires expectedCurrency (fail closed)", null, null)
        }
        val res = verifyBinding(token, opts)
        if (res["ok"] != true || !def(opts, "singleUse")) return res
        val claims = AcpJs.map(res["claims"])
        val first = try {
            (opts["singleUse"] as SingleUseStore).claim(claims["jti"] as String, dbl(claims["exp"]))
        } catch (e: Exception) {
            return verdict(false, "single-use store unavailable (fail closed)", claims, null)
        }
        return if (first) res else verdict(false, "the delegated payment token was already redeemed", claims, null)
    }

    private fun verifyBinding(token: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val algO = opts["alg"] ?: "EdDSA"
        val now = nowOf(opts)

        val claims: Map<String, Any?>? = try {
            if (algO !is String) throw Jose.JoseException("\"alg\" (Algorithm) Header Parameter value not allowed")
            val gate = Jose.assertCanonicalCompactJws(token) // canonical-spelling gate BEFORE signature work
            val vk = opts["verifyKey"] as? Map<String, Any?> ?: throw Jose.JoseException("Invalid key input")
            val verifyKey = LinkedHashMap<String, Any?>(vk)
            verifyKey.remove("d") // the reference imports a private JWK as a key object, which verifies as its public half
            Jose.compactVerify(token as String, verifyKey, listOf(algO))
            parseClaims(gate.payload)
        } catch (e: RuntimeException) {
            return verdict(false, "token signature did not verify: " + e.message, null, null)
        }
        if (claims == null) return verdict(false, "token payload is not a well-formed delegated payment token", null, null)

        if (claims["merchant"] != opts["expectedMerchant"]) {
            return verdict(false, "token merchant \"${claims["merchant"]}\" does not match expected \"${if (def(opts, "expectedMerchant")) str(opts["expectedMerchant"]) else "undefined"}\"", claims, null)
        }
        if (!isAmount(opts["amount"])) return verdict(false, "settlement amount must be a positive integer in minor units", claims, null)
        if (!(dbl(opts["amount"]) <= dbl(claims["amount"]))) {
            return verdict(false, "settlement amount ${str(opts["amount"])} exceeds the token's authorized amount ${str(claims["amount"])}", claims, null)
        }
        if (!(now <= dbl(claims["exp"]))) return verdict(false, "the delegated payment token has expired", claims, null)
        if (def(opts, "expectedSession") && claims["session"] != opts["expectedSession"]) {
            return verdict(false, "token session \"${claims["session"]}\" does not match expected \"${str(opts["expectedSession"])}\"", claims, null)
        }
        if (def(opts, "expectedCurrency") && claims["currency"] != opts["expectedCurrency"]) {
            return verdict(false, "token currency \"${claims["currency"]}\" does not match expected \"${str(opts["expectedCurrency"])}\"", claims, null)
        }

        if (def(opts, "grant") && !def(opts, "pcActn")) return verdict(false, "a grant was supplied without the pcActn to re-verify (fail closed)", claims, null)
        if (def(opts, "pcActn")) {
            val pcActn = opts["pcActn"]
            if (Pca.hashCanonical(pcActn) != AcpJs.map(claims["pca"])["digest"]) {
                return verdict(false, "pcactn_digest mismatch: the supplied proof is not the one that minted this token", claims, null)
            }
            if (def(opts, "grant")) {
                val roots = opts["authorizedPlanRoots"]
                val co = PcaCore.Options(AcpJs.map(opts["grant"]))
                // an explicit null audience is the opt-out (not-enforced); an omitted one fails closed when the PCActn carries an aud
                if (def(opts, "audience")) {
                    val aud = opts["audience"]
                    if (aud == null) co.audience = Pca.Audience.Any else if (aud is String) co.audience = Pca.Audience.Of(aud)
                }
                co.nowEpoch = now.toLong()
                co.authorizedPlanRoots = if (roots is List<*>) roots.map { it.toString() } else null
                co.insecureSkipPlanRootCheck = opts["insecureSkipPlanRootCheck"] == true
                val v = PcaCore.verify(pcActn, co)
                val pr = LinkedHashMap<String, Any?>()
                pr["allow"] = v.allow
                pr["checks"] = LinkedHashMap<String, Any?>(v.checks)
                val why = v.reason
                if (!why.isNullOrEmpty()) pr["reason"] = why
                if (!v.allow) return verdict(false, "bound proof failed to verify: " + (if (why.isNullOrEmpty()) "denied" else why), claims, pr)
                return verdict(true, null, claims, pr)
            }
        }
        return verdict(true, null, claims, null)
    }

    // ---- x402 v1 ----

    /**
     * Build the HTTP 402 challenge (`{status, headers, body}`) for a protected resource: the server's `accepts` requirement plus the 402 status.
     * [opts]: amount, currency (the x402 asset), payTo (both required), network (default base-sepolia), description, scheme (default exact),
     * mimeType, error, maxTimeoutSeconds (default 60). Structural only; no network.
     */
    @JvmStatic
    fun x402Challenge(resource: String, opts: Map<String, Any?>): Map<String, Any?> {
        if (!isAmount(opts["amount"])) throw IllegalArgumentException("x402Challenge: amount must be a positive integer in atomic/minor units")
        if (!AcpJs.nonEmpty(opts["payTo"])) throw IllegalArgumentException("x402Challenge: payTo is required")
        if (!AcpJs.nonEmpty(opts["currency"])) throw IllegalArgumentException("x402Challenge: currency (the x402 asset) is required")
        val timeout = opts["maxTimeoutSeconds"] ?: num(60)
        if (!AcpJs.isSafeInteger(timeout) || Js.num(timeout)!! <= 0) throw IllegalArgumentException("x402Challenge: maxTimeoutSeconds must be a positive integer")
        val req = LinkedHashMap<String, Any?>()
        req["maxTimeoutSeconds"] = timeout
        req["scheme"] = opts["scheme"] ?: "exact"
        req["network"] = opts["network"] ?: "base-sepolia"
        req["maxAmountRequired"] = str(opts["amount"])
        req["resource"] = resource
        req["description"] = opts["description"] ?: "Payment required for $resource"
        req["payTo"] = opts["payTo"]
        req["asset"] = opts["currency"]
        req["mimeType"] = opts["mimeType"] ?: "application/json"
        val body = LinkedHashMap<String, Any?>()
        body["x402Version"] = num(1)
        body["error"] = opts["error"] ?: "X-PAYMENT header is required"
        body["accepts"] = arrayListOf<Any?>(req)
        val out = LinkedHashMap<String, Any?>()
        out["status"] = num(402)
        out["headers"] = linkedMapOf<String, Any?>("Content-Type" to "application/json")
        out["body"] = body
        return out
    }

    private fun settleResult(settled: Boolean, status: Long, reason: String?, claims: Map<String, Any?>?): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["settled"] = settled
        m["status"] = num(status)
        if (reason != null) m["reason"] = reason
        if (claims != null) m["claims"] = claims
        return m
    }

    /**
     * Gate an x402 settlement on a verified, PCActn-bound payment: runs [verify] over the client's payload; on failure REFUSES with 402
     * (fail closed); on success runs the optional [settle] step and returns the receipt. Returns `{settled, status, reason?, claims?, receipt?}`.
     */
    @JvmStatic
    @Throws(Exception::class)
    fun x402Settle(payload: Any?, verify: X402Verify, settle: X402Settler?): Map<String, Any?> {
        val norm = X402V2.normalizeX402Payload(payload)
        if (norm["ok"] != true) return settleResult(false, 402, norm["reason"] as String?, null)
        val v = verify.verify(payload)
        if (!Js.truthy(v["ok"])) {
            val out = settleResult(false, 402, null, null)
            out["reason"] = v["reason"] ?: "payment verification failed"
            if (Js.truthy(v["claims"])) out["claims"] = v["claims"]
            return out
        }
        if (!def(v, "claims")) return settleResult(false, 402, "verifier admitted the payment but returned no claims (fail closed)", null)
        val claims = AcpJs.map(v["claims"])
        val receipt = settle?.settle(payload, claims)
        val out = settleResult(true, 200, null, claims)
        if (receipt != null) out["receipt"] = receipt
        return out
    }

    /**
     * Adapt [verifyDelegatedPaymentToken] into an [X402Verify] for [x402Settle]. [opts]: verifyKey, alg, now,
     * expectedMerchant, amount, offered (v2 requirements the server offered), expectedSession, expectedCurrency, pcActn, grant, audience,
     * authorizedPlanRoots, insecureSkipPlanRootCheck, singleUse, strict (default true: expectedMerchant, amount, expectedCurrency and singleUse
     * are all required and the payload's own merchant / amount are never read).
     */
    @JvmStatic
    fun acpX402Verifier(opts: Map<String, Any?>): X402Verify = X402Verify { payload ->
        val norm = X402V2.normalizeX402Payload(payload)
        if (norm["ok"] != true) return@X402Verify verdict(false, norm["reason"] as String?, null, null)
        if (Js.num(norm["version"]) == 2.0 && opts["offered"] != null && !X402V2.x402AcceptedMatches(Js.list(opts["offered"]), norm["accepted"])) {
            return@X402Verify verdict(false, "x402 v2 payload.accepted is not one of the requirements this server offered", null, null)
        }
        if (opts["strict"] != false && (opts["expectedMerchant"] == null || opts["amount"] == null)) {
            return@X402Verify verdict(false, "strict settlement requires the server to supply expectedMerchant and amount (fail closed)", null, null)
        }
        val merchant = opts["expectedMerchant"] ?: norm["merchant"]
        if (!AcpJs.nonEmpty(merchant)) return@X402Verify verdict(false, "x402 payload has no merchant to check the token against", null, null)
        val amount = opts["amount"] ?: norm["amount"]
        if (!Js.isNumber(amount) || !isAmount(amount)) return@X402Verify verdict(false, "x402 payload has no amount to check the token against", null, null)
        val vo = LinkedHashMap<String, Any?>()
        vo["expectedMerchant"] = merchant
        vo["amount"] = amount
        vo["verifyKey"] = opts["verifyKey"]
        for (k in listOf("alg", "now", "expectedSession", "expectedCurrency", "pcActn", "grant", "audience", "authorizedPlanRoots",
            "insecureSkipPlanRootCheck", "singleUse", "strict")) if (def(opts, k)) vo[k] = opts[k]
        val res = verifyDelegatedPaymentToken(norm["token"], vo)
        verdict(res["ok"] == true, res["reason"] as String?, if (res["claims"] == null) null else AcpJs.map(res["claims"]), null)
    }

    // ---- ACP delegate_payment allowance ----

    private val CURRENCY3 = Regex("[a-z]{3}")

    /**
     * Map VERIFIED token claims to the ACP delegate_payment `allowance` `{reason, max_amount, currency, checkout_session_id, merchant_id,
     * expires_at}`. Throws [AcpAuthorityException] when a claim cannot be expressed in the ACP shape (currency not three letters, merchant over 256
     * characters, expiry not a date).
     */
    @JvmStatic
    fun toAcpAllowance(claims: Map<String, Any?>): Map<String, Any?> {
        if (!isAmount(claims["amount"])) throw AcpAuthorityException("allowance: amount must be a positive integer in minor units")
        val cur = claims["currency"]
        val currency = if (cur is String) cur.lowercase(Locale.ROOT) else ""
        if (!CURRENCY3.matches(currency)) throw AcpAuthorityException("allowance: currency must be a three-letter ISO-4217 code")
        val merchant = claims["merchant"]
        if (merchant !is String || merchant.isEmpty() || merchant.length > 256) throw AcpAuthorityException("allowance: merchant_id must be 1 to 256 characters")
        if (!AcpJs.nonEmpty(claims["session"])) throw AcpAuthorityException("allowance: checkout_session_id is required")
        val exp = Js.num(claims["exp"])
        if (exp == null || exp.isNaN() || exp.isInfinite() || Math.abs(exp) > 8.64e15) throw AcpAuthorityException("allowance: expiry is not a valid time")
        val out = LinkedHashMap<String, Any?>()
        out["reason"] = "one_time"
        out["max_amount"] = claims["amount"]
        out["currency"] = currency
        out["checkout_session_id"] = claims["session"]
        out["merchant_id"] = merchant
        out["expires_at"] = A2aPca.toIsoString(exp)
        return out
    }
}
