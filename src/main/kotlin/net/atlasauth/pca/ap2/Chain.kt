package net.atlasauth.pca.ap2

import net.atlasauth.pca.ap2.Sdjwt.Ap2KeyPair
import net.atlasauth.pca.ap2.Sdjwt.Ap2PrivateKey
import net.atlasauth.pca.ap2.Sdjwt.DisclosureBuilder
import net.atlasauth.pca.ap2.Sdjwt.SdJwtHop

/** Resolves a public JWK from a JWT header (`kid` / `x5c`); null refuses. */
typealias KeyResolver = (Map<String, Any?>) -> Map<String, Any?>?

/**
 * AP2 mandate issuance, presentation and verification.
 *
 * Wire format: a mandate is the single object in an SD-JWT's `delegate_payload` array, itself an array-element disclosure. An
 * open mandate is signed by the issuer (the user's trusted surface / agent provider) and names the agent's key in `cnf.jwk`. A
 * closed mandate is a KB-SD-JWT hop (`typ: kb+sd-jwt`) signed by that agent key, carrying `iat`, `aud`, `nonce` and an `sd_hash`
 * over the preceding hop. Hops are joined by `~~`. That hop is AP2's key-binding mechanism; no trailing RFC 9901 KB-JWT is used
 * or accepted.
 *
 * Claims, mandates and keys (JWKs) are parsed JSON (Map, List, String, Boolean, Json.Num, null).
 */
object Chain {
    // ---------------------------------------------------------------------------------------------
    // issuing open mandates
    // ---------------------------------------------------------------------------------------------

    /** The signer of an open mandate: the user's trusted surface or agent provider (an ES256 key). */
    class MandateIssuer @JvmOverloads constructor(
        var privateKey: Ap2PrivateKey? = null,
        /** `kid` header; a verifier's key resolver maps it to the public key. */
        var kid: String? = null,
        /** Optional `x5c` header (base64 DER certificates); chain validation is the resolver's job. */
        var x5c: List<String>? = null,
    )

    /** Fields shared by every open mandate. Times are epoch seconds. */
    open class OpenMandateCommon {
        var issuer: MandateIssuer? = null

        /** The agent's public key (JWK); becomes `cnf.jwk` and is the only key that can sign the closed mandate. */
        var agentJwk: Map<String, Any?>? = null
        var iat: Double = Double.NaN

        /** Required: an open mandate must be bounded in time. */
        var exp: Double = Double.NaN

        /** `x_pca` claim (PCA's proof of the grant): a JSON object (anything else fails validation). */
        var pca: Any? = null
        var sdAlg: String? = null

        /** Salt source (tests inject a deterministic one). */
        var salt: (() -> String)? = null

        /** Root `typ` header; the reference SDK imposes none (default `dc+sd-jwt`). */
        var typ: String? = null
    }

    private const val ROOT_TYP = "dc+sd-jwt"

    private fun issuerOf(c: OpenMandateCommon): MandateIssuer = c.issuer ?: throw Ap2Error("open mandate: issuer is required")

    private fun signRoot(c: OpenMandateCommon, mandate: Map<String, Any?>, b: DisclosureBuilder): String {
        val iss = issuerOf(c)
        val element = b.element(mandate)
        val header = Ap2Js.m("typ" to (c.typ ?: ROOT_TYP))
        if (iss.kid != null) header["kid"] = iss.kid
        val x5c = iss.x5c
        if (x5c != null) header["x5c"] = ArrayList<Any?>(x5c)
        val key = iss.privateKey ?: throw Ap2Error("open mandate: issuer private key is required")
        return Sdjwt.signSdJwt(header, Ap2Js.m("delegate_payload" to Ap2Js.l(element), "_sd_alg" to (c.sdAlg ?: "sha-256")), b.disclosures, key)
    }

    private fun commonClaims(c: OpenMandateCommon): Map<String, Any?> {
        val jwk = Sdjwt.assertP256Jwk(c.agentJwk, "agentJwk")
        if (!Ap2Js.isSafeInteger(c.iat) || !Ap2Js.isSafeInteger(c.exp) || c.exp <= c.iat) throw Ap2Error("open mandate: need integer iat < exp (epoch seconds)")
        val out = Ap2Js.m(
            "cnf" to Ap2Js.m("jwk" to Ap2Js.m("crv" to "P-256", "kty" to "EC", "x" to jwk["x"], "y" to jwk["y"])),
            "iat" to Ap2Js.n(c.iat), "exp" to Ap2Js.n(c.exp),
        )
        if (Ap2Js.truthy(c.pca)) out[Mandates.PCA_CLAIM] = c.pca
        return out
    }

    /** Wrap the selectively-disclosable arrays of a payment constraint (`allowed` payees / instruments). */
    private fun sdPaymentConstraint(c: Any?, b: DisclosureBuilder): Any? {
        val type = Ap2Js.get(c, "type")
        if ("payment.allowed_payees" == type || "payment.allowed_payment_instruments" == type) {
            val allowed = ArrayList<Any?>()
            for (x in Ap2Js.arr(Ap2Js.get(c, "allowed"))) allowed.add(b.element(x))
            return Ap2Js.m("type" to type, "allowed" to allowed)
        }
        return c
    }

    private fun sdCheckoutConstraint(c: Any?, b: DisclosureBuilder): Any? {
        val type = Ap2Js.get(c, "type")
        if ("checkout.allowed_merchants" == type) {
            val allowed = ArrayList<Any?>()
            for (x in Ap2Js.arr(Ap2Js.get(c, "allowed"))) allowed.add(b.element(x))
            return Ap2Js.m("type" to type, "allowed" to allowed)
        }
        val items = ArrayList<Any?>()
        for (it in Ap2Js.arr(Ap2Js.get(c, "items"))) {
            val acceptable = ArrayList<Any?>()
            for (x in Ap2Js.arr(Ap2Js.get(it, "acceptable_items"))) acceptable.add(b.element(x))
            items.add(Ap2Js.m("id" to Ap2Js.get(it, "id"), "acceptable_items" to acceptable, "quantity" to Ap2Js.get(it, "quantity")))
        }
        return Ap2Js.m("type" to type, "items" to items)
    }

    /** Inputs of [issueOpenPaymentMandate]. */
    class OpenPaymentMandateInput : OpenMandateCommon() {
        var constraints: List<Any?> = ArrayList()
        var payee: Map<String, Any?>? = null
        var paymentAmount: Map<String, Any?>? = null
        var paymentInstrument: Map<String, Any?>? = null
        var pisp: Map<String, Any?>? = null
        var executionDate: String? = null
    }

    /** Issue an open Payment Mandate (`mandate.payment.open.1`) as a signed SD-JWT. */
    @JvmStatic
    fun issueOpenPaymentMandate(input: OpenPaymentMandateInput): String {
        val b = Sdjwt.disclosureBuilder(input.sdAlg, input.salt)
        val wrapped = ArrayList<Any?>()
        for (c in input.constraints) wrapped.add(sdPaymentConstraint(c, b))
        val mandate = Ap2Js.m("vct" to Mandates.VCT_PAYMENT_OPEN, "constraints" to wrapped)
        input.payee?.let { mandate["payee"] = it }
        input.paymentAmount?.let { mandate["payment_amount"] = it }
        input.paymentInstrument?.let { mandate["payment_instrument"] = it }
        input.pisp?.let { mandate["pisp"] = it }
        input.executionDate?.let { mandate["execution_date"] = it }
        mandate.putAll(commonClaims(input))
        assertWellFormed(mandate, Mandates::openPaymentMandateProblems, "open payment mandate", input.constraints)
        return signRoot(input, mandate, b)
    }

    /** Inputs of [issueOpenCheckoutMandate]. */
    class OpenCheckoutMandateInput : OpenMandateCommon() {
        var constraints: List<Any?> = ArrayList()
    }

    /** Issue an open Checkout Mandate (`mandate.checkout.open.1`) as a signed SD-JWT. */
    @JvmStatic
    fun issueOpenCheckoutMandate(input: OpenCheckoutMandateInput): String {
        val b = Sdjwt.disclosureBuilder(input.sdAlg, input.salt)
        val wrapped = ArrayList<Any?>()
        for (c in input.constraints) wrapped.add(sdCheckoutConstraint(c, b))
        val mandate = Ap2Js.m("vct" to Mandates.VCT_CHECKOUT_OPEN, "constraints" to wrapped)
        mandate.putAll(commonClaims(input))
        assertWellFormed(mandate, Mandates::openCheckoutMandateProblems, "open checkout mandate", input.constraints)
        return signRoot(input, mandate, b)
    }

    /** Validate the plain claims (before selective-disclosure wrapping) so a bad input fails at issuance. */
    private fun assertWellFormed(wrapped: Map<String, Any?>, problems: (Any?) -> List<String>, what: String, plainConstraints: List<Any?>) {
        val plain = LinkedHashMap(wrapped)
        plain["constraints"] = plainConstraints
        val p = problems(plain)
        if (p.isNotEmpty()) throw Ap2Error(what + ": " + p.joinToString("; "))
    }

    // ---------------------------------------------------------------------------------------------
    // presenting closed mandates (KB-SD-JWT hops)
    // ---------------------------------------------------------------------------------------------

    /** Fields shared by every closed mandate hop. */
    open class ClosedHopCommon {
        /** The preceding token (an open mandate, or a chain ending in an intermediate hop). */
        var open: String? = null

        /** The agent's key pair: its public key must be the open mandate's `cnf.jwk`. */
        var agentKey: Ap2KeyPair? = null

        /** Audience of this hop (the merchant for a checkout, the credential provider for a payment). */
        var aud: String? = null

        /** Verifier-supplied nonce; the verifier checks it on receipt. */
        var nonce: String? = null

        /** Issued-at, epoch seconds. */
        var iat: Double = Double.NaN

        /** Optional mandate-level expiry, epoch seconds. */
        var exp: Double? = null
        var pca: Any? = null

        /** Binding claim: `sd_hash` (default; pins the preceding hop's disclosures) or `issuer_jwt_hash`. */
        var hashMode: String? = null
        var salt: (() -> String)? = null
    }

    private fun presentHop(c: ClosedHopCommon, build: (DisclosureBuilder) -> Map<String, Any?>): String {
        val aud = c.aud
        val nonce = c.nonce
        if (aud == null || aud.isEmpty() || nonce == null || nonce.isEmpty()) throw Ap2Error("closed mandate: aud and nonce are required")
        if (!Ap2Js.isSafeInteger(c.iat)) throw Ap2Error("closed mandate: iat must be an integer")
        val prev = Sdjwt.parseSdJwtHop(c.open)
        val b = Sdjwt.disclosureBuilder(prev.sdAlg, c.salt)
        val mandate = build(b)
        val element = b.element(mandate)
        val mode = c.hashMode ?: "sd_hash"
        val payload = Ap2Js.m("delegate_payload" to Ap2Js.l(element), "iat" to Ap2Js.n(c.iat), "aud" to aud, "nonce" to nonce)
        payload[mode] = if (mode == "sd_hash") Sdjwt.sdHashOf(prev) else Sdjwt.issuerJwtHashOf(prev)
        payload["_sd_alg"] = prev.sdAlg
        val key = c.agentKey ?: throw Ap2Error("closed mandate: agentKey is required")
        val hop = Sdjwt.signSdJwt(Ap2Js.m("typ" to "kb+sd-jwt"), payload, b.disclosures, key.privateKey)
        // Hops are joined by "~~": the preceding token's own trailing "~" plus one separator "~".
        return c.open + "~" + hop
    }

    /** Inputs of [presentClosedPayment]. */
    class ClosedPaymentInput : ClosedHopCommon() {
        /** Hash of the closed checkout's `checkout_jwt` (= the closed checkout mandate's `checkout_hash`). */
        var transactionId: String? = null
        var payee: Map<String, Any?>? = null
        var paymentAmount: Map<String, Any?>? = null
        var paymentInstrument: Map<String, Any?>? = null
        var pisp: Map<String, Any?>? = null
        var executionDate: String? = null
        var riskData: Any? = null
    }

    /** Present a closed Payment Mandate (`mandate.payment.1`) on top of an open payment mandate. */
    @JvmStatic
    fun presentClosedPayment(input: ClosedPaymentInput): String = presentHop(input) { _ ->
        val mandate = Ap2Js.m(
            "vct" to Mandates.VCT_PAYMENT, "transaction_id" to input.transactionId, "payee" to input.payee,
            "payment_amount" to input.paymentAmount, "payment_instrument" to input.paymentInstrument,
        )
        input.pisp?.let { mandate["pisp"] = it }
        input.executionDate?.let { mandate["execution_date"] = it }
        if (Ap2Js.truthy(input.riskData)) mandate["risk_data"] = input.riskData
        input.exp?.let { mandate["exp"] = Ap2Js.n(it) }
        if (Ap2Js.truthy(input.pca)) mandate[Mandates.PCA_CLAIM] = input.pca
        val p = Mandates.paymentMandateProblems(mandate)
        if (p.isNotEmpty()) throw Ap2Error("closed payment mandate: " + p.joinToString("; "))
        mandate
    }

    /** Inputs of [presentClosedCheckout]. */
    class ClosedCheckoutInput : ClosedHopCommon() {
        /** The merchant-signed checkout JWT (compact). */
        var checkoutJwt: String? = null
    }

    /** Present a closed Checkout Mandate (`mandate.checkout.1`) on top of an open checkout mandate. */
    @JvmStatic
    fun presentClosedCheckout(input: ClosedCheckoutInput): String = presentHop(input) { b ->
        val prevAlg = Sdjwt.parseSdJwtHop(input.open).sdAlg
        val jwt = input.checkoutJwt ?: throw NullPointerException("checkoutJwt")
        val mandate = Ap2Js.m("_sd" to Ap2Js.l(b.property("checkout_jwt", jwt)), "vct" to Mandates.VCT_CHECKOUT, "checkout_hash" to Sdjwt.sdDigest(jwt, prevAlg))
        input.exp?.let { mandate["exp"] = Ap2Js.n(it) }
        if (Ap2Js.truthy(input.pca)) mandate[Mandates.PCA_CLAIM] = input.pca
        val full = LinkedHashMap(mandate)
        full["checkout_jwt"] = jwt
        val p = Mandates.checkoutMandateProblems(full)
        if (p.isNotEmpty()) throw Ap2Error("closed checkout mandate: " + p.joinToString("; "))
        mandate
    }

    // ---------------------------------------------------------------------------------------------
    // verifying a delegation chain
    // ---------------------------------------------------------------------------------------------

    @JvmField val TYP_TERMINAL: List<String> = java.util.Collections.unmodifiableList(listOf("kb+sd-jwt", "kb-sd-jwt"))
    @JvmField val TYP_INTERMEDIATE: List<String> = java.util.Collections.unmodifiableList(listOf("kb+sd-jwt+kb", "kb-sd-jwt+kb"))
    private const val MAX_HOPS = 8

    /** One verified hop of a chain. */
    class VerifiedHop(
        var index: Int,
        /** `root`, `intermediate` or `terminal`. */
        val kind: String,
        val hop: SdJwtHop,
        /** Hop-level claims after disclosure processing. */
        val claims: Map<String, Any?>,
        /** The single mandate object disclosed in `delegate_payload`. */
        val mandate: Map<String, Any?>,
    )

    /** Options of [verifyDelegationChain]. */
    open class VerifyChainOptions {
        /** Resolve the root hop's public key from its header (`kid` / `x5c`); return null to refuse. */
        var resolveIssuerKey: KeyResolver? = null

        /** The terminal hop's `aud` must equal this. Required: a verifier that does not name itself cannot detect redirection. */
        var expectedAudience: String? = null

        /** The terminal hop's `nonce` must equal this. Required: it is the replay defence. */
        var expectedNonce: String? = null

        /** Verification time, epoch seconds (default: now). */
        var now: Double? = null

        /** Tolerated clock skew in seconds (default 60). */
        var clockSkewSeconds: Double? = null
    }

    /**
     * The outcome of a chain verification. A failure carries `reason` (and `violations` when the open mandate's constraints were
     * violated); a success carries `hops`, and for the typed chains the open / closed mandates.
     */
    class ChainResult {
        var ok = false
        var reason: String? = null
        var violations: List<String>? = null
        var hops: List<VerifiedHop>? = null
        var open: Map<String, Any?>? = null
        var closed: Map<String, Any?>? = null

        /** Checkout chain only: the merchant-signed checkout JWT and its projection. */
        var checkoutJwt: String? = null
        var checkout: Map<String, Any?>? = null

        /** `sd_hash` of the open mandate token. */
        var openHash: String? = null

        companion object {
            internal fun fail(reason: String): ChainResult = ChainResult().also { it.reason = reason }
        }
    }

    /** Split a `~~`-joined chain into hops, each restored to `<jwt>~<d>...~`. */
    @JvmStatic
    fun splitChain(tokenObj: Any?): List<String> {
        if (tokenObj !is String || tokenObj.isEmpty()) throw Ap2Error("chain: empty")
        val parts = tokenObj.split("~~")
        if (parts.size > MAX_HOPS) throw Ap2Error("chain: more than $MAX_HOPS hops")
        val out = ArrayList<String>()
        for (i in parts.indices) out.add(if (i == parts.size - 1) parts[i] else parts[i] + "~")
        return out
    }

    private fun checkTimes(label: String, o: Map<String, Any?>, now: Double, skew: Double) {
        if (o.containsKey("exp")) {
            val exp = o["exp"]
            if (!Ap2Js.isSafeInteger(exp) || Ap2Js.isNegZero(Ap2Js.num(exp)!!)) throw Ap2Error("$label: exp must be an integer")
            if (!(now.isFinite() && skew.isFinite() && now <= Ap2Js.num(exp)!! + skew)) throw Ap2Error("$label: expired at " + Ap2Js.str(exp))
        }
        if (o.containsKey("iat")) {
            val iat = o["iat"]
            if (!Ap2Js.isSafeInteger(iat) || Ap2Js.isNegZero(Ap2Js.num(iat)!!)) throw Ap2Error("$label: iat must be an integer")
            if (!(now.isFinite() && skew.isFinite() && Ap2Js.num(iat)!! <= now + skew)) throw Ap2Error("$label: iat is in the future")
        }
    }

    private fun delegateMandate(claims: Map<String, Any?>, label: String): Map<String, Any?> {
        val dp = claims["delegate_payload"] as? List<*> ?: throw Ap2Error("$label: delegate_payload missing")
        if (dp.size != 1 || !Ap2Js.isObj(dp[0])) throw Ap2Error("$label: delegate_payload must disclose exactly one mandate (got ${dp.size})")
        return Ap2Js.obj(dp[0])
    }

    private fun cnfJwk(mandate: Map<String, Any?>, label: String): Map<String, Any?> {
        val cnf = mandate["cnf"]
        if (!Ap2Js.isObj(cnf) || !Ap2Js.isObj(Ap2Js.get(cnf, "jwk"))) throw Ap2Error("$label: no cnf.jwk to delegate to")
        return Sdjwt.assertP256Jwk(Ap2Js.get(cnf, "jwk"), "$label cnf.jwk")
    }

    /** What [verifyKbHop] needs besides the hops. */
    class KbOptions(var terminal: Boolean, var expectedAudience: String?, var expectedNonce: String?, var now: Double, var skew: Double)

    /** Verify one key-binding hop against its predecessor (signature, typ, binding hash, times, aud/nonce). */
    @JvmStatic
    fun verifyKbHop(hop: SdJwtHop, prev: VerifiedHop, o: KbOptions, label: String): VerifiedHop {
        val typ = hop.header["typ"]
        val allowed = if (o.terminal) TYP_TERMINAL else TYP_INTERMEDIATE
        if (typ !is String || !allowed.contains(typ)) throw Ap2Error("$label: typ must be one of " + allowed.joinToString(", "))
        if (hop.header.containsKey("crit")) throw Ap2Error("$label: crit headers are not supported")
        val key = cnfJwk(prev.mandate, "preceding mandate")
        if (!Sdjwt.verifyHopSignature(hop, key)) throw Ap2Error("$label: signature does not verify under the preceding mandate's cnf.jwk")
        val claims = Sdjwt.processDisclosures(hop.payload, hop.disclosures, hop.sdAlg)
        val hasSd = claims.containsKey("sd_hash")
        val hasIss = claims.containsKey("issuer_jwt_hash")
        if (hasSd == hasIss) throw Ap2Error("$label: exactly one of sd_hash / issuer_jwt_hash is required")
        val expected = if (hasSd) Sdjwt.sdHashOf(prev.hop) else Sdjwt.issuerJwtHashOf(prev.hop)
        val actual = if (hasSd) claims["sd_hash"] else claims["issuer_jwt_hash"]
        if (expected != actual) throw Ap2Error("$label: " + (if (hasSd) "sd_hash" else "issuer_jwt_hash") + " does not match the preceding hop")
        if (!claims.containsKey("iat")) throw Ap2Error("$label: iat is required")
        checkTimes(label, claims, o.now, o.skew)
        val mandate = delegateMandate(claims, label)
        checkTimes("$label mandate", mandate, o.now, o.skew)
        val hasCnf = Ap2Js.isObj(mandate["cnf"])
        if (o.terminal && hasCnf) throw Ap2Error("$label: a terminal hop must not carry cnf")
        if (!o.terminal && !hasCnf) throw Ap2Error("$label: an intermediate hop requires cnf")
        if (o.terminal) {
            if (o.expectedAudience == null || o.expectedAudience != claims["aud"]) throw Ap2Error("$label: aud mismatch")
            if (o.expectedNonce == null || o.expectedNonce != claims["nonce"]) throw Ap2Error("$label: nonce mismatch")
        }
        return VerifiedHop(-1, if (o.terminal) "terminal" else "intermediate", hop, claims, mandate)
    }

    private fun message(e: RuntimeException): String = e.message.toString()

    private fun nowOf(now: Double?): Double = now ?: Math.floor(System.currentTimeMillis() / 1000.0)

    /** Verify a whole chain: root signature, then every hop in order. Never throws; reports the reason. */
    @JvmStatic
    fun verifyDelegationChain(token: String, o: VerifyChainOptions): ChainResult {
        try {
            val aud = o.expectedAudience
            val nonce = o.expectedNonce
            if (aud == null || aud.isEmpty() || nonce == null || nonce.isEmpty()) {
                throw Ap2Error("verify: expectedAudience and expectedNonce are required")
            }
            val now = nowOf(o.now)
            val skew = o.clockSkewSeconds ?: 60.0
            val segments = ArrayList<SdJwtHop>()
            for (s in splitChain(token)) segments.add(Sdjwt.parseSdJwtHop(s))
            val root = segments[0]
            if (root.header.containsKey("crit")) throw Ap2Error("root: crit headers are not supported")
            val resolve = o.resolveIssuerKey ?: throw Ap2Error("root: no issuer key for this header")
            val issuerKey = resolve(root.header) ?: throw Ap2Error("root: no issuer key for this header")
            if (!Sdjwt.verifyHopSignature(root, issuerKey)) throw Ap2Error("root: signature does not verify under the issuer key")
            val rootClaims = Sdjwt.processDisclosures(root.payload, root.disclosures, root.sdAlg)
            checkTimes("root", rootClaims, now, skew)
            val rootMandate = delegateMandate(rootClaims, "root")
            checkTimes("root mandate", rootMandate, now, skew)
            val hops = ArrayList<VerifiedHop>()
            hops.add(VerifiedHop(0, "root", root, rootClaims, rootMandate))
            for (i in 1 until segments.size) {
                val v = verifyKbHop(segments[i], hops[i - 1], KbOptions(i == segments.size - 1, aud, nonce, now, skew), "hop $i")
                v.index = i
                hops.add(v)
            }
            val r = ChainResult()
            r.ok = true
            r.hops = hops
            return r
        } catch (e: RuntimeException) {
            return ChainResult.fail(message(e))
        }
    }

    // ---------------------------------------------------------------------------------------------
    // typed chains
    // ---------------------------------------------------------------------------------------------

    private fun pair(r: ChainResult): Array<VerifiedHop> {
        val hops = r.hops!!
        if (hops.size != 2) throw Ap2Error("expected an open mandate followed by one closed mandate, got ${hops.size} hop(s)")
        return arrayOf(hops[0], hops[1])
    }

    private fun requireOpenExpiry(m: Map<String, Any?>, label: String) {
        if (!Ap2Js.isSafeInteger(m["exp"])) throw Ap2Error("$label: an open mandate must carry exp")
    }

    /** Options of [verifyCheckoutChain]. */
    open class VerifyCheckoutOptions : VerifyChainOptions() {
        /** Resolve the merchant's key for the `checkout_jwt` signature; return null to refuse. */
        var resolveMerchantKey: KeyResolver? = null
    }

    /** Verify an open+closed checkout chain, the merchant-signed checkout, its hash, and the open constraints. */
    @JvmStatic
    fun verifyCheckoutChain(token: String, o: VerifyCheckoutOptions): ChainResult {
        val r = verifyDelegationChain(token, o)
        if (!r.ok) return r
        try {
            val p = pair(r)
            val open = p[0].mandate
            val closed = p[1].mandate
            val op = Mandates.openCheckoutMandateProblems(open)
            if (op.isNotEmpty()) throw Ap2Error("open checkout mandate: " + op.joinToString("; "))
            requireOpenExpiry(open, "open checkout mandate")
            val cp = Mandates.checkoutMandateProblems(closed)
            if (cp.isNotEmpty()) throw Ap2Error("closed checkout mandate: " + cp.joinToString("; "))
            val alg = p[1].hop.sdAlg
            val checkoutJwt = closed["checkout_jwt"] as String
            if (Sdjwt.sdDigest(checkoutJwt, alg) != closed["checkout_hash"]) throw Ap2Error("checkout_hash does not match checkout_jwt")
            val jwt = Sdjwt.parseJwt(checkoutJwt, "checkout_jwt")
            val resolve = o.resolveMerchantKey ?: throw Ap2Error("checkout_jwt: no merchant key for this header")
            val key = resolve(jwt.header) ?: throw Ap2Error("checkout_jwt: no merchant key for this header")
            if (!Sdjwt.verifyJwtEs256(jwt, key)) throw Ap2Error("checkout_jwt: merchant signature does not verify")
            val checkout = Constraints.projectCheckout(jwt.payload)
            val violations = Constraints.checkCheckoutConstraints(open, checkout)
            if (violations.isNotEmpty()) {
                val f = ChainResult.fail("open checkout constraints violated: " + violations.joinToString("; "))
                f.violations = violations
                return f
            }
            val ok = ChainResult()
            ok.ok = true
            ok.open = open
            ok.closed = closed
            ok.checkoutJwt = checkoutJwt
            ok.checkout = checkout
            ok.openHash = Sdjwt.sdHashOf(p[0].hop)
            ok.hops = r.hops
            return ok
        } catch (e: RuntimeException) {
            return ChainResult.fail(message(e))
        }
    }

    /** Options of [verifyPaymentChain]. */
    open class VerifyPaymentOptions : VerifyChainOptions() {
        /** `sd_hash` of the open checkout mandate (from `verifyCheckoutChain().openHash`); checked against `payment.reference`. */
        var openCheckoutHash: String? = null

        /** Usage state under this open mandate (needed for `payment.budget` and recurrence). */
        var context: Map<String, Any?>? = null

        /** The `checkout_hash` this payment must settle (from the closed checkout mandate). */
        var expectedTransactionId: String? = null
    }

    /** Verify an open+closed payment chain and every open payment constraint. */
    @JvmStatic
    fun verifyPaymentChain(token: String, o: VerifyPaymentOptions): ChainResult {
        val r = verifyDelegationChain(token, o)
        if (!r.ok) return r
        try {
            val p = pair(r)
            val open = p[0].mandate
            val closed = p[1].mandate
            val op = Mandates.openPaymentMandateProblems(open)
            if (op.isNotEmpty()) throw Ap2Error("open payment mandate: " + op.joinToString("; "))
            requireOpenExpiry(open, "open payment mandate")
            val cp = Mandates.paymentMandateProblems(closed)
            if (cp.isNotEmpty()) throw Ap2Error("closed payment mandate: " + cp.joinToString("; "))
            val tx = o.expectedTransactionId
            if (tx != null && tx != closed["transaction_id"]) throw Ap2Error("transaction_id does not match the checkout being settled")
            val violations = Constraints.checkPaymentConstraints(open, closed, Constraints.PaymentCheckOptions(o.openCheckoutHash, o.context, nowOf(o.now)))
            if (violations.isNotEmpty()) {
                val f = ChainResult.fail("open payment constraints violated: " + violations.joinToString("; "))
                f.violations = violations
                return f
            }
            val ok = ChainResult()
            ok.ok = true
            ok.open = open
            ok.closed = closed
            ok.openHash = Sdjwt.sdHashOf(p[0].hop)
            ok.hops = r.hops
            return ok
        } catch (e: RuntimeException) {
            return ChainResult.fail(message(e))
        }
    }

    /** The audience and nonce a verifier expects of one chain's terminal hop. */
    class Expect(var expectedAudience: String?, var expectedNonce: String?)

    /** Options of [verifyPurchase]. */
    open class VerifyPurchaseOptions {
        var resolveIssuerKey: KeyResolver? = null
        var resolveMerchantKey: KeyResolver? = null
        var checkout: Expect? = null
        var payment: Expect? = null
        var context: Map<String, Any?>? = null
        var now: Double? = null
        var clockSkewSeconds: Double? = null
    }

    /** A verified purchase: the checkout chain and the payment chain bound to it; or a failure `reason`. */
    class PurchaseResult {
        var ok = false
        var reason: String? = null
        var checkout: ChainResult? = null
        var payment: ChainResult? = null

        companion object {
            @JvmStatic fun fail(reason: String): PurchaseResult = PurchaseResult().also { it.reason = reason }
        }
    }

    /**
     * Verify a complete purchase: the checkout chain, then the payment chain bound to it (the payment's `payment.reference` is the
     * open checkout hash; its `transaction_id` is the closed checkout's `checkout_hash`), and that the payment settles what the
     * merchant quoted (payee, currency, total).
     */
    @JvmStatic
    fun verifyPurchase(checkoutToken: String, paymentToken: String, o: VerifyPurchaseOptions): PurchaseResult {
        val co = VerifyCheckoutOptions()
        co.resolveIssuerKey = o.resolveIssuerKey
        co.now = o.now
        co.clockSkewSeconds = o.clockSkewSeconds
        co.expectedAudience = o.checkout?.expectedAudience
        co.expectedNonce = o.checkout?.expectedNonce
        co.resolveMerchantKey = o.resolveMerchantKey
        val c = verifyCheckoutChain(checkoutToken, co)
        if (!c.ok) return PurchaseResult.fail("checkout: " + c.reason)
        val cClosed = c.closed!!
        val cCheckout = c.checkout!!
        val po = VerifyPaymentOptions()
        po.resolveIssuerKey = o.resolveIssuerKey
        po.now = o.now
        po.clockSkewSeconds = o.clockSkewSeconds
        po.expectedAudience = o.payment?.expectedAudience
        po.expectedNonce = o.payment?.expectedNonce
        po.openCheckoutHash = c.openHash
        po.expectedTransactionId = cClosed["checkout_hash"] as String?
        po.context = o.context
        val pay = verifyPaymentChain(paymentToken, po)
        if (!pay.ok) return PurchaseResult.fail("payment: " + pay.reason)
        val pClosed = pay.closed!!
        val total = Constraints.checkoutTotal(cCheckout) ?: return PurchaseResult.fail("checkout: needs exactly one total entry")
        val amt = pClosed["payment_amount"]
        if (!Ap2Js.sEq(Ap2Js.get(amt, "currency"), cCheckout["currency"])) return PurchaseResult.fail("payment currency differs from the checkout currency")
        if (!Ap2Js.sEq(Ap2Js.get(amt, "amount"), total)) return PurchaseResult.fail("payment amount " + Ap2Js.str(Ap2Js.get(amt, "amount")) + " differs from the checkout total " + Ap2Js.str(total))
        if (!cCheckout.containsKey("merchant")) return PurchaseResult.fail("checkout: no merchant to compare the payee with")
        if (!Ap2Js.sEq(Ap2Js.get(cCheckout["merchant"], "id"), Ap2Js.get(pClosed["payee"], "id"))) return PurchaseResult.fail("payee differs from the checkout merchant")
        val ok = PurchaseResult()
        ok.ok = true
        ok.checkout = c
        ok.payment = pay
        return ok
    }
}
