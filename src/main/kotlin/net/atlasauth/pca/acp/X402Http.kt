package net.atlasauth.pca.acp

import net.atlasauth.pca.acp.AcpJs.def
import net.atlasauth.pca.acp.AcpJs.get
import net.atlasauth.pca.acp.AcpJs.isObj
import net.atlasauth.pca.jose.Js

/**
 * x402 v2 HTTP transport: three headers, each the base64 of a JSON object. `PAYMENT-REQUIRED` (see [X402V2]),
 * `PAYMENT-SIGNATURE` (client to server, the PaymentPayload) and `PAYMENT-RESPONSE` (server to client, the SettlementResponse).
 * No I/O.
 */
object X402Http {
    const val X402_PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
    const val X402_PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"

    /** The HTTP status for each x402 outcome. */
    const val STATUS_PAYMENT_REQUIRED = 402
    const val STATUS_MALFORMED = 400
    const val STATUS_FAILED = 402
    const val STATUS_INTERNAL_ERROR = 500
    const val STATUS_SETTLED = 200

    private val ATOMIC = Regex("0|[1-9][0-9]*")

    /** Problems with a v2 `PaymentPayload` (empty = valid). */
    @JvmStatic
    fun paymentPayloadV2Problems(p: Any?): List<String> {
        val out = ArrayList<String>()
        if (!isObj(p)) { out.add("PaymentPayload must be an object"); return out }
        if (Js.num(get(p, "x402Version")) != 2.0) out.add("x402Version must be 2")
        if (def(p, "resource")) out.addAll(X402V2.resourceInfoProblems(get(p, "resource")))
        for (m in X402V2.requirementV2Problems(get(p, "accepted"))) out.add("accepted.$m")
        if (!isObj(get(p, "payload"))) out.add("payload must be an object")
        if (def(p, "extensions") && !isObj(get(p, "extensions"))) out.add("extensions must be an object")
        return out
    }

    /** Problems with a SettlementResponse (empty = valid). A success must not carry an errorReason; a failure must. */
    @JvmStatic
    fun settlementResponseProblems(r: Any?): List<String> {
        val out = ArrayList<String>()
        if (!isObj(r)) { out.add("SettlementResponse must be an object"); return out }
        val success = get(r, "success")
        if (success !is Boolean) out.add("success must be a boolean")
        val tx = get(r, "transaction")
        if (tx !is String) out.add("transaction must be a string")
        else if (success == true && tx.isEmpty()) out.add("a successful settlement needs a transaction")
        if (!AcpJs.matches(X402V2.CAIP2, get(r, "network"))) out.add("network must be a CAIP-2 identifier")
        val er = get(r, "errorReason")
        if (def(r, "errorReason") && er !is String) out.add("errorReason must be a string")
        if (success == true && def(r, "errorReason")) out.add("errorReason must be omitted on success")
        if (success == false && !(er is String && er.isNotEmpty())) out.add("errorReason is required on failure")
        if (def(r, "payer") && get(r, "payer") !is String) out.add("payer must be a string")
        if (def(r, "amount") && !AcpJs.matches(ATOMIC, get(r, "amount"))) out.add("amount must be a decimal string of atomic units")
        if (def(r, "extensions") && !isObj(get(r, "extensions"))) out.add("extensions must be an object")
        return out
    }

    private fun encodeHeader(obj: Any?, problems: List<String>): String {
        if (problems.isNotEmpty()) throw IllegalArgumentException("x402: " + problems.joinToString("; "))
        return AcpJs.b64encode(AcpJs.stringify(obj))
    }

    private fun decodeValid(value: Any?, name: String, problemsOf: (Any?) -> List<String>): Map<String, Any?> {
        val doc = AcpJs.decodeHeader(value, name)
        val problems = problemsOf(doc)
        if (problems.isNotEmpty()) throw IllegalArgumentException("x402: " + problems.joinToString("; "))
        return AcpJs.map(doc)
    }

    /** Encode a PaymentPayload for the `PAYMENT-SIGNATURE` request header (validates first; throws IllegalArgumentException). */
    @JvmStatic
    fun encodePaymentSignatureHeader(p: Any?): String = encodeHeader(p, paymentPayloadV2Problems(p))

    /** Decode and validate a `PAYMENT-SIGNATURE` header value. Throws IllegalArgumentException on bad base64, bad JSON or an invalid object. */
    @JvmStatic
    fun decodePaymentSignatureHeader(value: Any?): Map<String, Any?> = decodeValid(value, "PAYMENT-SIGNATURE") { paymentPayloadV2Problems(it) }

    /** Encode a SettlementResponse for the `PAYMENT-RESPONSE` response header. */
    @JvmStatic
    fun encodePaymentResponseHeader(r: Any?): String = encodeHeader(r, settlementResponseProblems(r))

    /** Decode and validate a `PAYMENT-RESPONSE` header value. */
    @JvmStatic
    fun decodePaymentResponseHeader(value: Any?): Map<String, Any?> = decodeValid(value, "PAYMENT-RESPONSE") { settlementResponseProblems(it) }

    private val UNDEFINED = Any()

    /** Case-insensitive header lookup over a header record (first value of a list); [UNDEFINED] when absent. */
    private fun header(headers: Map<String, Any?>, name: String): Any? {
        for ((k, v) in headers) {
            if (k.equals(name, ignoreCase = true)) return if (v is List<*>) (if (v.isEmpty()) UNDEFINED else v[0]) else v
        }
        return UNDEFINED
    }

    /**
     * Server side: read the client's `PAYMENT-SIGNATURE` header. A missing header is 402 (answer with a PAYMENT-REQUIRED challenge); a
     * present but undecodable or invalid one is 400 (malformed). Never throws. Returns `{ok, payload}` or `{ok:false, status, reason}`.
     */
    @JvmStatic
    fun readPaymentSignature(headers: Map<String, Any?>): Map<String, Any?> {
        val v = header(headers, X402_PAYMENT_SIGNATURE_HEADER)
        val out = LinkedHashMap<String, Any?>()
        if (v === UNDEFINED || v == "") {
            out["ok"] = false
            out["status"] = AcpJs.num(STATUS_PAYMENT_REQUIRED.toLong())
            out["reason"] = "PAYMENT-SIGNATURE header is required"
            return out
        }
        try {
            val payload = decodePaymentSignatureHeader(v)
            out["ok"] = true
            out["payload"] = payload
        } catch (e: IllegalArgumentException) {
            out["ok"] = false
            out["status"] = AcpJs.num(STATUS_MALFORMED.toLong())
            out["reason"] = e.message
        }
        return out
    }

    /**
     * Server side: the status and `PAYMENT-RESPONSE` header for a settlement outcome. [outcome] = `{settled: true, transaction, payer?,
     * amount?}` or `{settled: false, reason, transaction?, payer?}`. Throws IllegalArgumentException if the response would be invalid.
     * Returns `{status, headers}`.
     */
    @JvmStatic
    fun x402SettlementResponse(outcome: Map<String, Any?>, network: Any?): Map<String, Any?> {
        val settled = Js.truthy(outcome["settled"])
        val body = LinkedHashMap<String, Any?>()
        if (settled) {
            body["success"] = true
            if (def(outcome, "transaction")) body["transaction"] = outcome["transaction"]
            body["network"] = network
            if (def(outcome, "payer")) body["payer"] = outcome["payer"]
            if (def(outcome, "amount")) body["amount"] = outcome["amount"]
        } else {
            body["success"] = false
            if (def(outcome, "reason")) body["errorReason"] = outcome["reason"]
            body["transaction"] = outcome["transaction"] ?: ""
            body["network"] = network
            if (def(outcome, "payer")) body["payer"] = outcome["payer"]
        }
        val headers = LinkedHashMap<String, Any?>()
        headers[X402_PAYMENT_RESPONSE_HEADER] = encodePaymentResponseHeader(body)
        val out = LinkedHashMap<String, Any?>()
        out["status"] = AcpJs.num((if (settled) STATUS_SETTLED else STATUS_FAILED).toLong())
        out["headers"] = headers
        return out
    }

    /** Client side: the request header to attach on the retry, from a payload built for an offered requirement. */
    @JvmStatic
    fun x402PaymentSignatureHeaders(p: Any?): Map<String, Any?> = linkedMapOf(X402_PAYMENT_SIGNATURE_HEADER to encodePaymentSignatureHeader(p))
}
