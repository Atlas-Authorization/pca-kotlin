package net.atlasauth.pca.acp

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the ACP / x402 package through the native port, plus core re-verification with a real grant. */
@Suppress("UNCHECKED_CAST")
class AcpDiffTest {
    private val m = "ref-acp"

    private fun map(o: Any?) = o as Map<String, Any?>

    /** A JavaScript null options bag: any member read throws, as reading a property of null does. */
    private val nullBag = object : AbstractMap<String, Any?>() {
        override val entries: Set<Map.Entry<String, Any?>> get() = throw NullPointerException("cannot read properties of null")
    }

    /** A member-readable view of a JSON value: null reads throw, a primitive or array has no members. */
    private fun mm(o: Any?): Map<String, Any?> = if (o == null) nullBag else o as? Map<String, Any?> ?: LinkedHashMap()

    private fun n(v: Long) = Json.Num(v.toString())

    private fun numOf(o: Any?): Double = Js.num(o)!!

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf<String, Any?>(
            "v" to n(Acp.ACP_DELEGATED_TOKEN_VERSION.toLong()),
            "t" to Acp.ACP_DELEGATED_TOKEN_TYPE,
            "s" to Acp.SPEND_CAP_CAVEAT,
            "m" to Acp.MERCHANT_ALLOW_CAVEAT,
            "c" to Acp.MERCHANT_CATEGORY_CAVEAT,
            "h" to Acp.HUMAN_PRESENT_CAVEAT,
            "x1" to n(X402V2.X402_VERSION_1.toLong()),
            "x2" to n(X402V2.X402_VERSION_2.toLong()),
            "sup" to X402V2.X402_SUPPORTED_VERSIONS.map { n(it.toLong()) },
            "pr" to X402V2.X402_V2_PAYMENT_REQUIRED_HEADER,
            "ps" to X402Http.X402_PAYMENT_SIGNATURE_HEADER,
            "pe" to X402Http.X402_PAYMENT_RESPONSE_HEADER,
            "st" to linkedMapOf<String, Any?>(
                "payment_required" to n(X402Http.STATUS_PAYMENT_REQUIRED.toLong()),
                "malformed" to n(X402Http.STATUS_MALFORMED.toLong()),
                "failed" to n(X402Http.STATUS_FAILED.toLong()),
                "internal_error" to n(X402Http.STATUS_INTERNAL_ERROR.toLong()),
                "settled" to n(X402Http.STATUS_SETTLED.toLong()),
            ),
            "spt" to StripeSpt.STRIPE_SPT_OBJECT,
        )
    }

    // ---- caveats + authority

    @Test fun caveatBuilders() {
        OracleCases.each(m, "spendCapCaveat") { a -> if (a.size > 1) Acp.spendCapCaveat(numOf(a[0]).toLong(), a[1] as String) else Acp.spendCapCaveat(numOf(a[0]).toLong()) }
        OracleCases.each(m, "merchantAllowCaveat") { a -> Acp.merchantAllowCaveat(a[0] as List<String>) }
        OracleCases.each(m, "merchantCategoryCaveat") { a -> Acp.merchantCategoryCaveat(a[0] as List<String>) }
        OracleCases.each(m, "humanPresentCaveat") { a -> if (a.isEmpty()) Acp.humanPresentCaveat() else Acp.humanPresentCaveat(a[0] as Boolean) }
    }

    @Test fun extractPaymentAuthority() = OracleCases.each(m, "extractPaymentAuthority") { a -> Acp.extractPaymentAuthority(a[0]) }

    @Test fun checkPaymentAuthority() = OracleCases.each(m, "checkPaymentAuthority") { a -> Acp.checkPaymentAuthority(map(a[0]), map(a[1])) }

    // ---- mint / verify

    @Test fun mintDelegatedPaymentToken() = OracleCases.each(m, "mintDelegatedPaymentToken") { a -> Acp.mintDelegatedPaymentToken(a[0], mm(a[1])) }

    /** The oracle's store specs: "once" grants each jti once, "always", "never", "throw", "truthy" (a non-boolean answer, refused); anything else is no store. */
    private fun withStore(op: Map<String, Any?>): Map<String, Any?> {
        val o2 = LinkedHashMap(op)
        if (!op.containsKey("singleUse")) return o2
        when (op["singleUse"]) {
            "once" -> { val seen = HashSet<String>(); o2["singleUse"] = Acp.SingleUseStore { jti, _ -> seen.add(jti) } }
            "always" -> o2["singleUse"] = Acp.SingleUseStore { _, _ -> true }
            "never", "truthy" -> o2["singleUse"] = Acp.SingleUseStore { _, _ -> false }
            "throw" -> o2["singleUse"] = Acp.SingleUseStore { _, _ -> throw IllegalStateException("store down") }
        }
        return o2
    }

    private val libReason = Regex("(?s)^(token signature did not verify|bound proof failed to verify): .*$")

    private fun norm(r: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap(r)
        val reason = out["reason"]
        if (reason is String) out["reason"] = reason.replace(libReason, "$1")
        if (out["pcaResult"] is Map<*, *>) out["pcaResult"] = linkedMapOf<String, Any?>("allow" to map(out["pcaResult"])["allow"])
        return out
    }

    private fun times(a: List<Any?>): Int = if (a.size > 2) numOf(a[2]).toInt() else 1

    @Test fun verifyDelegatedPaymentToken() = OracleCases.each(m, "verifyDelegatedPaymentToken") { a ->
        val o2 = withStore(mm(a[1]))
        val rs = (0 until times(a)).map { norm(Acp.verifyDelegatedPaymentToken(a[0], o2)) }
        if (rs.size == 1) rs[0] else rs
    }

    /** A real grant and a real signed PCActn: the core re-verification, including the explicit-null audience opt-out. */
    @Test fun verifyDelegatedPaymentTokenCore() = OracleCases.each("ref-acp-java-extra", "verifyDelegatedPaymentToken") { a ->
        norm(Acp.verifyDelegatedPaymentToken(a[0], withStore(map(a[1]))))
    }

    // ---- x402 v1

    @Test fun x402Challenge() = OracleCases.each(m, "x402Challenge") { a -> Acp.x402Challenge(a[0] as String, mm(a[1])) }

    @Test fun x402Settle() = OracleCases.each(m, "x402Settle") { a ->
        val vspec = a[1]
        val verify = Acp.X402Verify { _ -> if (vspec == "throw") throw IllegalStateException("verify down") else map(vspec) }
        val settler: Acp.X402Settler? = when (if (a.size > 2) a[2] as String? else null) {
            "echo" -> Acp.X402Settler { p, c -> linkedMapOf<String, Any?>("jti" to c["jti"]).also { r -> if (map(p).containsKey("token")) r["token"] = map(p)["token"] } }
            "value" -> Acp.X402Settler { _, _ -> "receipt-1" }
            "throw" -> Acp.X402Settler { _, _ -> throw IllegalStateException("settle down") }
            "undef" -> Acp.X402Settler { _, _ -> null }
            else -> null
        }
        Acp.x402Settle(a[0], verify, settler)
    }

    @Test fun acpX402Verifier() = OracleCases.each(m, "acpX402Verifier") { a ->
        val fn = Acp.acpX402Verifier(withStore(map(a[1])))
        val rs = (0 until times(a)).map { norm(fn.verify(a[0])) }
        if (rs.size == 1) rs[0] else rs
    }

    @Test fun toAcpAllowance() = OracleCases.each(m, "toAcpAllowance") { a -> Acp.toAcpAllowance(mm(a[0])) }

    // ---- x402 v2

    @Test fun problems() {
        OracleCases.each(m, "resourceInfoProblems") { a -> X402V2.resourceInfoProblems(a[0]) }
        OracleCases.each(m, "requirementV2Problems") { a -> X402V2.requirementV2Problems(a[0]) }
        OracleCases.each(m, "paymentRequiredV2Problems") { a -> X402V2.paymentRequiredV2Problems(a[0]) }
        OracleCases.each(m, "paymentPayloadV2Problems") { a -> X402Http.paymentPayloadV2Problems(a[0]) }
        OracleCases.each(m, "settlementResponseProblems") { a -> X402Http.settlementResponseProblems(a[0]) }
        OracleCases.each(m, "stripeSptProblems") { a -> StripeSpt.stripeSptProblems(a[0]) }
    }

    @Test fun headers() {
        OracleCases.each(m, "encodePaymentRequiredHeader") { a -> X402V2.encodePaymentRequiredHeader(a[0]) }
        OracleCases.each(m, "decodePaymentRequiredHeader") { a -> X402V2.decodePaymentRequiredHeader(a[0]) }
        OracleCases.each(m, "encodePaymentSignatureHeader") { a -> X402Http.encodePaymentSignatureHeader(a[0]) }
        OracleCases.each(m, "decodePaymentSignatureHeader") { a -> X402Http.decodePaymentSignatureHeader(a[0]) }
        OracleCases.each(m, "encodePaymentResponseHeader") { a -> X402Http.encodePaymentResponseHeader(a[0]) }
        OracleCases.each(m, "decodePaymentResponseHeader") { a -> X402Http.decodePaymentResponseHeader(a[0]) }
        OracleCases.each(m, "x402PaymentSignatureHeaders") { a -> X402Http.x402PaymentSignatureHeaders(a[0]) }
    }

    @Test fun x402ChallengeV2() = OracleCases.each(m, "x402ChallengeV2") { a -> X402V2.x402ChallengeV2(a[0], mm(a[1])) }

    private fun versions(o: Any?): List<Int>? {
        if (o == null) return null
        return (o as List<Any?>).map { x -> val d = numOf(x); if (d == Math.floor(d) && Math.abs(d) < 1e9) d.toInt() else Int.MIN_VALUE }
    }

    @Test fun x402Negotiate() = OracleCases.each(m, "x402Negotiate") { a ->
        // the Kotlin null is the reference's undefined (v1 only); a JavaScript null offered list is outside the typed contract and throws there
        if (a[0] == null) throw NullPointerException("offered is null")
        if (a.size > 1) X402V2.x402Negotiate(versions(a[0]), versions(a[1])!!) else X402V2.x402Negotiate(versions(a[0]))
    }

    @Test fun x402AcceptedMatches() = OracleCases.each(m, "x402AcceptedMatches") { a -> X402V2.x402AcceptedMatches(a[0] as List<*>, a[1]) }

    @Test fun normalizeX402Payload() = OracleCases.each(m, "normalizeX402Payload") { a -> X402V2.normalizeX402Payload(a[0]) }

    @Test fun transport() {
        OracleCases.each(m, "readPaymentSignature") { a -> X402Http.readPaymentSignature(map(a[0])) }
        OracleCases.each(m, "x402SettlementResponse") { a -> X402Http.x402SettlementResponse(map(a[0]), a[1]) }
    }

    // ---- Stripe SPT

    @Test fun stripeSpt() {
        OracleCases.each(m, "parseStripeSpt") { a -> StripeSpt.parseStripeSpt(a[0]) }
        OracleCases.each(m, "stripeSptUsable") { a -> StripeSpt.stripeSptUsable(a[0], mm(a[1])) }
        OracleCases.each(m, "stripeUsageLimitsFor") { a -> StripeSpt.stripeUsageLimitsFor(mm(a[0])) }
        OracleCases.each(m, "stripeSptWithinClaims") { a -> StripeSpt.stripeSptWithinClaims(a[0], mm(a[1])) }
    }
}
