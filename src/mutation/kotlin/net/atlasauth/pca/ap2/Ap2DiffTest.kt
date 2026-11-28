package net.atlasauth.pca.ap2

import java.math.BigInteger
import java.security.MessageDigest
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the AP2 package through the native port. */
@Suppress("UNCHECKED_CAST")
class Ap2DiffTest {
    private val M = "ref-ap2"
    private val T0 = 1_800_000_000.0

    // ---- plumbing ----
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun s(o: Any?): String = o as String
    private fun d(o: Any?): Double = when (o) {
        is Json.Num -> o.raw.toDouble()
        is Number -> o.toDouble()
        else -> o.toString().toDouble()
    }

    private fun mk(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for ((k, v) in kv) out[k] = v
        return out
    }

    private fun sha256(x: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(x.toByteArray(Charsets.UTF_8))

    private fun fixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val n = Math.min(raw.size, 32)
        System.arraycopy(raw, raw.size - n, out, 32 - n, n)
        return out
    }

    private val keys = HashMap<String, Sdjwt.Ap2KeyPair>()

    /** The private JWK of a label: d = sha256("atlas-pca-conformance/ap2/" + label); the public point is d*G. */
    private fun privJwk(label: String): MutableMap<String, Any?> {
        val dd = sha256("atlas-pca-conformance/ap2/$label")
        val q = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1").g.multiply(BigInteger(1, dd)).normalize()
        return mk(
            "kty" to "EC", "crv" to "P-256", "d" to Sdjwt.b64uEncode(dd), "x" to Sdjwt.b64uEncode(fixed32(q.affineXCoord.toBigInteger())),
            "y" to Sdjwt.b64uEncode(fixed32(q.affineYCoord.toBigInteger())), "kid" to label,
        )
    }

    @Synchronized
    private fun keyFor(label: String): Sdjwt.Ap2KeyPair = keys.getOrPut(label) { Sdjwt.ap2KeyPairFromPrivateJwk(privJwk(label)) }

    private fun pubOf(label: String): Map<String, Any?> {
        val j = keyFor(label).publicJwk
        return mk("kty" to "EC", "crv" to "P-256", "x" to j["x"], "y" to j["y"])
    }

    /** Counter salts "salt-000000000001" (base64url of the ASCII text), as the reference generator uses. */
    private fun counterSalt(): () -> String {
        var n = 0
        return { Sdjwt.b64uEncode(("salt-" + String.format("%012d", ++n)).toByteArray(Charsets.US_ASCII)) }
    }

    /** Every compact JWT's signature segment replaced by SIG (signatures are randomized). */
    private fun stripSig(token: String): String {
        val parts = token.split("~").toMutableList()
        val re = Regex("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")
        for (i in parts.indices) {
            if (re.matches(parts[i])) parts[i] = parts[i].substring(0, parts[i].lastIndexOf('.')) + ".SIG"
        }
        return parts.joinToString("~")
    }

    private fun maskReason(s: String?): String? = s?.replaceFirst(Regex("(?s)invalid JSON \\(.*\\)$"), "invalid JSON (*)")

    private fun strings(o: Any?): List<String> = l(o).map { it as String }

    private fun resolver(keys: Any?): KeyResolver = { h ->
        val kid = h["kid"]
        if (keys is Map<*, *> && kid is String && keys.containsKey(kid)) m(keys[kid]) else null
    }

    private fun <T : Chain.VerifyChainOptions> baseOpts(o: T, c: Map<String, Any?>): T {
        o.resolveIssuerKey = resolver(c["issuerKeys"])
        o.expectedAudience = c["expectedAudience"] as String?
        o.expectedNonce = c["expectedNonce"] as String?
        if (c.containsKey("now")) o.now = d(c["now"])
        if (c.containsKey("clockSkewSeconds")) o.clockSkewSeconds = d(c["clockSkewSeconds"])
        return o
    }

    private fun hopOut(h: Chain.VerifiedHop): Map<String, Any?> = mk("index" to h.index, "kind" to h.kind, "claims" to h.claims, "mandate" to h.mandate)

    private fun projChain(r: Chain.ChainResult): Map<String, Any?> {
        if (!r.ok) {
            val out = mk("ok" to false, "reason" to maskReason(r.reason))
            if (r.violations != null) out["violations"] = r.violations
            return out
        }
        val hops = ArrayList<Any?>()
        for (h in r.hops!!) hops.add(hopOut(h))
        val out = mk("ok" to true, "hops" to hops)
        if (r.open != null) {
            out["open"] = r.open
            out["closed"] = r.closed
        }
        if (r.checkoutJwt != null) {
            out["checkoutJwt"] = r.checkoutJwt
            out["checkout"] = r.checkout
        }
        if (r.openHash != null) out["openHash"] = r.openHash
        return out
    }

    private fun projPurchase(r: Chain.PurchaseResult): Map<String, Any?> =
        if (r.ok) mk("ok" to true, "checkout" to projChain(r.checkout!!), "payment" to projChain(r.payment!!)) else mk("ok" to false, "reason" to maskReason(r.reason))

    private fun purchOptsOf(c: Map<String, Any?>): Chain.VerifyPurchaseOptions {
        val o = Chain.VerifyPurchaseOptions()
        o.resolveIssuerKey = resolver(c["issuerKeys"])
        o.resolveMerchantKey = resolver(c["merchantKeys"])
        o.checkout = Chain.Expect(s(m(c["checkout"])["expectedAudience"]), s(m(c["checkout"])["expectedNonce"]))
        o.payment = Chain.Expect(s(m(c["payment"])["expectedAudience"]), s(m(c["payment"])["expectedNonce"]))
        if (c.containsKey("context")) o.context = m(c["context"])
        if (c.containsKey("now")) o.now = d(c["now"])
        if (c.containsKey("clockSkewSeconds")) o.clockSkewSeconds = d(c["clockSkewSeconds"])
        return o
    }

    private fun hopProjection(h: Sdjwt.SdJwtHop): Map<String, Any?> =
        mk("raw" to h.raw, "jwt" to h.jwt, "header" to h.header, "payload" to h.payload, "disclosures" to h.disclosures, "sdAlg" to h.sdAlg, "signingInput" to h.signingInput, "signature" to h.signature)

    private val merch = mk("id" to "merchant_1", "name" to "Demo Merchant", "website" to "https://demo-merchant.example")
    private val merch2 = mk("id" to "merchant_2", "name" to "Other Merchant")

    // ---- sdjwt ----
    @Test fun b64uEncode() = OracleCases.each(M, "b64uEncode") { a -> Sdjwt.b64uEncode(s(a[0])) }
    @Test fun b64uDecode() = OracleCases.each(M, "b64uDecode") { a -> Sdjwt.b64uDecode(s(a[0]), s(a[1])) }
    @Test fun parseJson() = OracleCases.each(M, "parseJson") { a -> Sdjwt.parseJson(s(a[0]), s(a[1])) }
    @Test fun isSdAlg() = OracleCases.each(M, "isSdAlg") { a -> Sdjwt.isSdAlg(a[0]) }
    @Test fun sdDigest() = OracleCases.each(M, "sdDigest") { a -> if (a.size > 1) Sdjwt.sdDigest(s(a[0]), s(a[1])) else Sdjwt.sdDigest(s(a[0])) }
    @Test fun assertP256Jwk() = OracleCases.each(M, "assertP256Jwk") { a -> Sdjwt.assertP256Jwk(a[0], s(a[1])) }
    @Test fun jwkThumbprint() = OracleCases.each(M, "jwkThumbprint") { a -> Sdjwt.jwkThumbprint(a[0]) }

    @Test fun ap2KeyPairFromPrivateJwk() = OracleCases.each(M, "ap2KeyPairFromPrivateJwk") { a ->
        val jwk = privJwk(s(a[0]))
        jwk.putAll(m(a[1]))
        Sdjwt.ap2KeyPairFromPrivateJwk(jwk).publicJwk
    }

    @Test fun parseSdJwtHop() = OracleCases.each(M, "parseSdJwtHop") { a -> hopProjection(Sdjwt.parseSdJwtHop(a[0])) }

    @Test fun hopSdJwt() = OracleCases.each(M, "hopSdJwt") { a ->
        val h = Sdjwt.parseSdJwtHop(a[0])
        Sdjwt.hopSdJwt(h.jwt, h.disclosures)
    }

    @Test fun sdHashOf() = OracleCases.each(M, "sdHashOf") { a -> if (a.size > 1) Sdjwt.sdHashOf(Sdjwt.parseSdJwtHop(a[0]), s(a[1])) else Sdjwt.sdHashOf(Sdjwt.parseSdJwtHop(a[0])) }
    @Test fun issuerJwtHashOf() = OracleCases.each(M, "issuerJwtHashOf") { a -> if (a.size > 1) Sdjwt.issuerJwtHashOf(Sdjwt.parseSdJwtHop(a[0]), s(a[1])) else Sdjwt.issuerJwtHashOf(Sdjwt.parseSdJwtHop(a[0])) }

    @Test fun processDisclosures() = OracleCases.each(M, "processDisclosures") { a ->
        if (a.size == 1 && a[0] is String) { // a whole hop token: parse it, then process its own payload, disclosures and digest algorithm
            val h = Sdjwt.parseSdJwtHop(a[0])
            Sdjwt.processDisclosures(h.payload, h.disclosures, h.sdAlg)
        } else if (a.size == 3 && a[1] is List<*> && a[0] is Map<*, *>) Sdjwt.processDisclosures(m(a[0]), strings(a[1]), s(a[2])) else throw IllegalArgumentException("bad args")
    }

    @Test fun disclosureBuilder() = OracleCases.each(M, "disclosureBuilder") { a ->
        val b = Sdjwt.disclosureBuilder(a[0] as String?, counterSalt())
        val results = ArrayList<Any?>()
        for (op in l(a[1])) {
            val o = m(op)
            results.add(if ("element" == o["kind"]) b.element(o["value"]) else b.property(s(o["name"]), o["value"]))
        }
        mk("results" to results, "disclosures" to b.disclosures)
    }

    @Test fun parseJwt() = OracleCases.each(M, "parseJwt") { a ->
        val p = Sdjwt.parseJwt(s(a[0]), s(a[1]))
        mk("header" to p.header, "payload" to p.payload, "signingInput" to p.signingInput, "signature" to p.signature)
    }

    @Test fun verifyJwtEs256() = OracleCases.each(M, "verifyJwtEs256") { a -> Sdjwt.verifyJwtEs256(Sdjwt.parseJwt(s(a[0]), "jwt"), m(a[1])) }
    @Test fun verifyHopSignature() = OracleCases.each(M, "verifyHopSignature") { a -> Sdjwt.verifyHopSignature(Sdjwt.parseSdJwtHop(a[0]), m(a[1])) }

    @Test fun signSdJwt() = OracleCases.each(M, "signSdJwt") { a ->
        val x = m(a[0])
        stripSig(Sdjwt.signSdJwt(m(x["header"]), m(x["payload"]), strings(x["disclosures"]), keyFor(s(x["key"])).privateKey))
    }

    @Test fun signJwtEs256() = OracleCases.each(M, "signJwtEs256") { a ->
        val x = m(a[0])
        stripSig(Sdjwt.signJwtEs256(m(x["header"]), m(x["payload"]), keyFor(s(x["key"])).privateKey))
    }

    // ---- mandates ----
    @Test fun currencyExponent() = OracleCases.each(M, "currencyExponent") { a -> Mandates.currencyExponent(a[0]) }
    @Test fun toMinorUnits() = OracleCases.each(M, "toMinorUnits") { a -> Mandates.toMinorUnits(a[0], a[1]) }
    @Test fun fromMinorUnits() = OracleCases.each(M, "fromMinorUnits") { a -> Mandates.fromMinorUnits(a[0], a[1]) }
    @Test fun openPaymentMandateProblems() = OracleCases.each(M, "openPaymentMandateProblems") { a -> Mandates.openPaymentMandateProblems(a[0]) }
    @Test fun paymentMandateProblems() = OracleCases.each(M, "paymentMandateProblems") { a -> Mandates.paymentMandateProblems(a[0]) }
    @Test fun openCheckoutMandateProblems() = OracleCases.each(M, "openCheckoutMandateProblems") { a -> Mandates.openCheckoutMandateProblems(a[0]) }
    @Test fun checkoutMandateProblems() = OracleCases.each(M, "checkoutMandateProblems") { a -> Mandates.checkoutMandateProblems(a[0]) }

    @Test fun assertValid() = OracleCases.each(M, "assertValid") { a ->
        val f: (Any?) -> List<String> = when (s(a[0])) {
            "openPaymentMandateProblems" -> { v -> Mandates.openPaymentMandateProblems(v) }
            "paymentMandateProblems" -> { v -> Mandates.paymentMandateProblems(v) }
            "openCheckoutMandateProblems" -> { v -> Mandates.openCheckoutMandateProblems(v) }
            else -> { v -> Mandates.checkoutMandateProblems(v) }
        }
        Mandates.assertValid(a[1], f, s(a[2]))
    }

    @Test fun constants() = OracleCases.each(M, "constants") { _ ->
        mk(
            "VCT_CHECKOUT" to Mandates.VCT_CHECKOUT, "VCT_CHECKOUT_OPEN" to Mandates.VCT_CHECKOUT_OPEN, "VCT_PAYMENT" to Mandates.VCT_PAYMENT,
            "VCT_PAYMENT_OPEN" to Mandates.VCT_PAYMENT_OPEN, "PCA_CLAIM" to Mandates.PCA_CLAIM, "FREQUENCIES" to Mandates.FREQUENCIES, "AP2_COMMIT" to Ap2.AP2_COMMIT,
            "PCA_BINDING_VERSION" to Ap2.PCA_BINDING_VERSION, "TYP_TERMINAL" to Chain.TYP_TERMINAL, "TYP_INTERMEDIATE" to Chain.TYP_INTERMEDIATE,
        )
    }

    // ---- constraints ----
    @Test fun merchantMatches() = OracleCases.each(M, "merchantMatches") { a -> Constraints.merchantMatches(a[0], a[1]) }

    @Test fun checkPaymentConstraints() = OracleCases.each(M, "checkPaymentConstraints") { a ->
        val o = m(a[2])
        Constraints.checkPaymentConstraints(m(a[0]), m(a[1]), Constraints.PaymentCheckOptions(o["openCheckoutHash"] as String?, if (o.containsKey("context")) m(o["context"]) else null, d(o["now"])))
    }

    @Test fun projectCheckout() = OracleCases.each(M, "projectCheckout") { a -> Constraints.projectCheckout(m(a[0])) }
    @Test fun checkoutTotal() = OracleCases.each(M, "checkoutTotal") { a -> Constraints.checkoutTotal(m(a[0])) }
    @Test fun checkCheckoutConstraints() = OracleCases.each(M, "checkCheckoutConstraints") { a -> Constraints.checkCheckoutConstraints(m(a[0]), m(a[1])) }

    // ---- chain: verification ----
    @Test fun splitChain() = OracleCases.each(M, "splitChain") { a -> Chain.splitChain(a[0]) }

    @Test fun verifyDelegationChain() = OracleCases.each(M, "verifyDelegationChain") { a ->
        projChain(Chain.verifyDelegationChain(s(a[0]), baseOpts(Chain.VerifyChainOptions(), m(a[1]))))
    }

    @Test fun verifyKbHop() = OracleCases.each(M, "verifyKbHop") { a ->
        val o = m(a[3])
        val prev = Chain.VerifiedHop(0, "root", Sdjwt.parseSdJwtHop(a[1]), LinkedHashMap(), m(a[2]))
        val v = Chain.verifyKbHop(
            Sdjwt.parseSdJwtHop(a[0]), prev,
            Chain.KbOptions(true == o["terminal"], o["expectedAudience"] as String?, o["expectedNonce"] as String?, d(o["now"]), d(o["skew"])), s(a[4]),
        )
        hopOut(v)
    }

    @Test fun verifyCheckoutChain() = OracleCases.each(M, "verifyCheckoutChain") { a ->
        val c = m(a[1])
        val o = baseOpts(Chain.VerifyCheckoutOptions(), c)
        o.resolveMerchantKey = resolver(c["merchantKeys"])
        projChain(Chain.verifyCheckoutChain(s(a[0]), o))
    }

    @Test fun verifyPaymentChain() = OracleCases.each(M, "verifyPaymentChain") { a ->
        val c = m(a[1])
        val o = baseOpts(Chain.VerifyPaymentOptions(), c)
        o.openCheckoutHash = c["openCheckoutHash"] as String?
        if (c.containsKey("context")) o.context = m(c["context"])
        o.expectedTransactionId = c["expectedTransactionId"] as String?
        projChain(Chain.verifyPaymentChain(s(a[0]), o))
    }

    @Test fun verifyPurchase() = OracleCases.each(M, "verifyPurchase") { a -> projPurchase(Chain.verifyPurchase(s(a[0]), s(a[1]), purchOptsOf(m(a[2])))) }

    @Test fun redeemPurchase() = OracleCases.each(M, "redeemPurchase") { a ->
        val spec = a[3]
        val calls = ArrayList<Any?>()
        val ledger: Ledger.PurchaseLedger? = if ("none" == spec) null else object : Ledger.PurchaseLedger {
            override fun reserve(openMandateHash: String, transactionId: String, amountMinor: Double): Any? {
                calls.add(listOf("reserve", openMandateHash, transactionId, amountMinor))
                val sp = m(spec)
                if ("throw" == sp["mode"]) throw Exception("down")
                if ("replayed" == sp["mode"]) return Ledger.PurchaseLedger.REPLAYED
                if ("undefined" == sp["mode"]) return null
                return if (sp.containsKey("ctx")) sp["ctx"] else Constraints.context(0.0, 0.0, null)
            }

            override fun release(openMandateHash: String, transactionId: String) {
                calls.add(listOf("release", openMandateHash, transactionId))
                if (true == m(spec)["releaseThrows"]) throw Exception("release failed")
            }
        }
        val r = Ledger.redeemPurchase(s(a[0]), s(a[1]), purchOptsOf(m(a[2])), ledger)
        mk("result" to projPurchase(r), "calls" to calls)
    }

    // ---- chain: issuance and presentation ----
    private fun openInput(inp: Chain.OpenMandateCommon, a: Map<String, Any?>) {
        val iss = Chain.MandateIssuer()
        iss.privateKey = keyFor(if (a.containsKey("issuerKey")) s(a["issuerKey"]) else "issuer").privateKey
        if (a.containsKey("kid")) iss.kid = s(a["kid"])
        if (a.containsKey("x5c")) iss.x5c = strings(a["x5c"])
        inp.issuer = iss
        inp.agentJwk = if (a.containsKey("agentJwk")) m(a["agentJwk"]) else pubOf(if (a.containsKey("agentKey")) s(a["agentKey"]) else "agent")
        if (a.containsKey("iat")) inp.iat = d(a["iat"])
        if (a.containsKey("exp")) inp.exp = d(a["exp"])
        if (a["pca"] is Map<*, *> || a["pca"] is List<*>) inp.pca = a["pca"]
        inp.sdAlg = a["sdAlg"] as String?
        inp.typ = a["typ"] as String?
        inp.salt = counterSalt()
    }

    @Test fun issueOpenPaymentMandate() = OracleCases.each(M, "issueOpenPaymentMandate") { a ->
        val x = m(a[0])
        val inp = Chain.OpenPaymentMandateInput()
        openInput(inp, x)
        inp.constraints = l(x["constraints"])
        inp.payee = if (x.containsKey("payee")) m(x["payee"]) else null
        inp.paymentAmount = if (x.containsKey("paymentAmount")) m(x["paymentAmount"]) else null
        inp.paymentInstrument = if (x.containsKey("paymentInstrument")) m(x["paymentInstrument"]) else null
        inp.pisp = if (x.containsKey("pisp")) m(x["pisp"]) else null
        inp.executionDate = x["executionDate"] as String?
        stripSig(Chain.issueOpenPaymentMandate(inp))
    }

    @Test fun issueOpenCheckoutMandate() = OracleCases.each(M, "issueOpenCheckoutMandate") { a ->
        val x = m(a[0])
        val inp = Chain.OpenCheckoutMandateInput()
        openInput(inp, x)
        inp.constraints = l(x["constraints"])
        stripSig(Chain.issueOpenCheckoutMandate(inp))
    }

    private fun hopInput(inp: Chain.ClosedHopCommon, a: Map<String, Any?>) {
        inp.open = s(a["open"])
        inp.agentKey = keyFor(if (a.containsKey("agentKey")) s(a["agentKey"]) else "agent")
        inp.aud = a["aud"] as String?
        inp.nonce = a["nonce"] as String?
        if (a.containsKey("iat")) inp.iat = d(a["iat"])
        if (a.containsKey("exp")) inp.exp = d(a["exp"])
        if (a["pca"] is Map<*, *> || a["pca"] is List<*>) inp.pca = a["pca"]
        inp.hashMode = a["hashMode"] as String?
        inp.salt = counterSalt()
    }

    @Test fun presentClosedPayment() = OracleCases.each(M, "presentClosedPayment") { a ->
        val x = m(a[0])
        val inp = Chain.ClosedPaymentInput()
        hopInput(inp, x)
        inp.transactionId = x["transactionId"] as String?
        inp.payee = m(x["payee"])
        inp.paymentAmount = m(x["paymentAmount"])
        inp.paymentInstrument = m(x["paymentInstrument"])
        inp.pisp = if (x.containsKey("pisp")) m(x["pisp"]) else null
        inp.executionDate = x["executionDate"] as String?
        if (x["riskData"] is Map<*, *> || x["riskData"] is List<*>) inp.riskData = x["riskData"]
        stripSig(Chain.presentClosedPayment(inp))
    }

    @Test fun presentClosedCheckout() = OracleCases.each(M, "presentClosedCheckout") { a ->
        val x = m(a[0])
        val inp = Chain.ClosedCheckoutInput()
        hopInput(inp, x)
        inp.checkoutJwt = x["checkoutJwt"] as String?
        stripSig(Chain.presentClosedCheckout(inp))
    }

    // ---- PCA terms -> AP2 ----
    @Test fun ap2BudgetMax() = OracleCases.each(M, "ap2BudgetMax") { a -> Ap2.ap2BudgetMax(a[0], a[1]) }
    @Test fun ap2BudgetReads() = OracleCases.each(M, "ap2BudgetReads") { a -> Ap2.ap2BudgetReads(a[0], a[1]) }
    @Test fun riskRatio() = OracleCases.each(M, "riskRatio") { a -> Ap2.riskRatio(d(a[0]), d(a[1])) }
    @Test fun pcaBindingNonce() = OracleCases.each(M, "pcaBindingNonce") { a -> Ap2.pcaBindingNonce(m(a[0])) }
    @Test fun paymentConstraintsFromTerms() = OracleCases.each(M, "paymentConstraintsFromTerms") { a -> Ap2.paymentConstraintsFromTerms(m(a[0]), l(a[1]), s(a[2])) }
    @Test fun pcaOpenClaim() = OracleCases.each(M, "pcaOpenClaim") { a -> Ap2.pcaOpenClaim(m(a[0])) }

    private fun fromInput(o: Ap2.FromTermsOptions, x: Map<String, Any?>) {
        o.issuer = Chain.MandateIssuer(keyFor("issuer").privateKey, "issuer-1")
        o.agentJwk = pubOf("agent")
        o.merchants = if (x.containsKey("merchants")) l(x["merchants"]) else arrayListOf<Any?>(merch, merch2)
        o.iat = if (x.containsKey("iat")) d(x["iat"]) else T0
        if (x.containsKey("exp")) o.exp = d(x["exp"])
        o.salt = counterSalt()
    }

    @Test fun openPaymentMandateFromPca() = OracleCases.each(M, "openPaymentMandateFromPca") { a ->
        val x = m(a[0])
        val o = Ap2.PaymentFromTermsOptions()
        fromInput(o, x)
        o.checkoutReference = if (x.containsKey("checkoutReference")) s(x["checkoutReference"]) else "REF"
        stripSig(Ap2.openPaymentMandateFromPca(m(x["mandate"]), o))
    }

    @Test fun openCheckoutMandateFromPca() = OracleCases.each(M, "openCheckoutMandateFromPca") { a ->
        val x = m(a[0])
        val o = Ap2.CheckoutFromTermsOptions()
        fromInput(o, x)
        o.lineItems = if (x.containsKey("lineItems")) l(x["lineItems"])
        else arrayListOf<Any?>(mk("id" to "line_1", "acceptable_items" to arrayListOf<Any?>(mk("id" to "sku-1", "title" to "Widget")), "quantity" to 2))
        stripSig(Ap2.openCheckoutMandateFromPca(m(x["mandate"]), o))
    }

    @Test fun buildPcaPaymentBinding() = OracleCases.each(M, "buildPcaPaymentBinding") { a ->
        val x = m(a[0])
        val inp = Ap2.PcaPaymentBindingInput()
        inp.mandate = m(x["mandate"])
        inp.open = s(x["open"])
        inp.agentJwk = pubOf("agent")
        inp.agentSecret = sha256("atlas-pca-conformance/" + s(x["agentSeed"]))
        inp.audience = x["audience"] as String
        inp.counter = d(x["counter"]).toLong()
        inp.transactionId = x["transactionId"] as String
        inp.payee = m(x["payee"])
        inp.amount = m(x["amount"])
        inp.instrumentId = x["instrumentId"] as String?
        inp.category = x["category"] as String?
        inp.now = d(x["now"]).toLong()
        if (x.containsKey("cosign")) {
            val cs = m(x["cosign"])
            inp.cosign = { _ -> cs }
        }
        Ap2.buildPcaPaymentBinding(inp)
    }

    // ---- settlement ----
    @Test fun toAtomicUnits() = OracleCases.each(M, "toAtomicUnits") { a -> Settlement.toAtomicUnits(m(a[0]), a[1]) }

    @Test fun x402Settlement() = OracleCases.each(M, "x402Settlement") { a ->
        Settlement.x402Settlement.settle(m(a[0]), if (a.size > 1) Settlement.SettlementContext.fromMap(m(a[1])) else null)
    }

    @Test fun stripeSptSettlement() = OracleCases.each(M, "stripeSptSettlement") { a ->
        Settlement.stripeSptSettlement.settle(m(a[0]), if (a.size > 1) Settlement.SettlementContext.fromMap(m(a[1])) else null)
    }
}
