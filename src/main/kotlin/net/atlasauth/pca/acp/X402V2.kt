package net.atlasauth.pca.acp

import net.atlasauth.pca.acp.AcpJs.def
import net.atlasauth.pca.acp.AcpJs.get
import net.atlasauth.pca.acp.AcpJs.isObj
import net.atlasauth.pca.acp.AcpJs.isSafeInteger
import net.atlasauth.pca.acp.AcpJs.matches
import net.atlasauth.pca.acp.AcpJs.nonEmpty
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.oauth.WhatwgUrl

/**
 * x402 v2 alongside v1, negotiated: PaymentRequired / PaymentRequirements / ResourceInfo validation, the base64
 * `PAYMENT-REQUIRED` header, version negotiation and payload normalisation. Values are parsed JSON (Map, List, String,
 * Boolean, Json.Num, null); every "problems" function returns the reference's messages, empty = valid. No I/O.
 */
object X402V2 {
    const val X402_VERSION_1 = 1
    const val X402_VERSION_2 = 2

    /** Versions this package can speak, newest first. */
    @JvmField
    val X402_SUPPORTED_VERSIONS: List<Int> = listOf(2, 1)
    const val X402_V2_PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"

    internal val CAIP2 = Regex("[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
    private val ASCII_PRINTABLE = Regex("[\\x20-\\x7e]*")
    private val ATOMIC = Regex("0|[1-9][0-9]*")

    private fun absoluteHttp(u: Any?): Boolean {
        if (u !is String) return false
        val p = WhatwgUrl.parse(u)
        return p != null && (p.protocol == "https:" || p.protocol == "http:")
    }

    private fun shortAscii(x: Any?): Boolean = x is String && x.length <= 32 && matches(ASCII_PRINTABLE, x)

    /** Problems with a `ResourceInfo` (empty = valid). */
    @JvmStatic
    fun resourceInfoProblems(r: Any?): List<String> {
        val p = ArrayList<String>()
        if (!isObj(r)) { p.add("resource must be an object"); return p }
        if (!absoluteHttp(get(r, "url"))) p.add("resource.url must be an absolute http(s) URL")
        for (k in listOf("description", "mimeType")) if (def(r, k) && get(r, k) !is String) p.add("resource.$k must be a string")
        if (def(r, "serviceName") && !shortAscii(get(r, "serviceName"))) p.add("resource.serviceName must be printable ASCII up to 32 characters")
        if (def(r, "tags")) {
            val t = get(r, "tags")
            val ok = t is List<*> && t.size <= 5 && t.all { shortAscii(it) }
            if (!ok) p.add("resource.tags must be up to 5 printable ASCII strings of up to 32 characters")
        }
        if (def(r, "iconUrl")) {
            val u = get(r, "iconUrl")
            if (!(absoluteHttp(u) && (u as String).length <= 2048)) p.add("resource.iconUrl must be an absolute http(s) URL up to 2048 characters")
        }
        return p
    }

    /** Problems with one v2 `PaymentRequirements` (empty = valid). */
    @JvmStatic
    fun requirementV2Problems(q: Any?): List<String> {
        val p = ArrayList<String>()
        if (!isObj(q)) { p.add("requirements must be an object"); return p }
        if (!nonEmpty(get(q, "scheme"))) p.add("scheme is required")
        if (!matches(CAIP2, get(q, "network"))) p.add("network must be a CAIP-2 identifier")
        val amount = get(q, "amount")
        if (!matches(ATOMIC, amount) || amount == "0") p.add("amount must be a positive decimal string of atomic units")
        if (!nonEmpty(get(q, "asset"))) p.add("asset is required")
        if (!nonEmpty(get(q, "payTo"))) p.add("payTo is required")
        val t = get(q, "maxTimeoutSeconds")
        if (!(isSafeInteger(t) && Js.num(t)!! > 0)) p.add("maxTimeoutSeconds must be a positive integer")
        if (def(q, "extra") && !isObj(get(q, "extra"))) p.add("extra must be an object")
        return p
    }

    /** Problems with a v2 `PaymentRequired` (empty = valid). */
    @JvmStatic
    fun paymentRequiredV2Problems(pr: Any?): List<String> {
        val p = ArrayList<String>()
        if (!isObj(pr)) { p.add("PaymentRequired must be an object"); return p }
        if (Js.num(get(pr, "x402Version")) != 2.0) p.add("x402Version must be 2")
        if (def(pr, "error") && get(pr, "error") !is String) p.add("error must be a string")
        p.addAll(resourceInfoProblems(get(pr, "resource")))
        val acc = get(pr, "accepts")
        if (acc !is List<*> || acc.isEmpty()) p.add("accepts must be a non-empty array")
        else for ((i, q) in acc.withIndex()) for (m in requirementV2Problems(q)) p.add("accepts[$i].$m")
        if (def(pr, "extensions")) {
            val ext = get(pr, "extensions")
            if (ext !is Map<*, *>) p.add("extensions must be an object")
            else for ((k, v2) in ext) {
                if (!isObj(v2) || !isObj(get(v2, "info")) || !isObj(get(v2, "schema"))) p.add("extensions.$k needs info and schema objects")
            }
        }
        return p
    }

    /** Encode a `PaymentRequired` for the `PAYMENT-REQUIRED` header (validates first; throws on a problem). */
    @JvmStatic
    fun encodePaymentRequiredHeader(pr: Any?): String {
        val problems = paymentRequiredV2Problems(pr)
        if (problems.isNotEmpty()) throw IllegalArgumentException("x402: " + problems.joinToString("; "))
        return AcpJs.b64encode(AcpJs.stringify(pr))
    }

    /** Decode and validate a `PAYMENT-REQUIRED` header value. Throws IllegalArgumentException on bad base64, bad JSON or an invalid object. */
    @JvmStatic
    fun decodePaymentRequiredHeader(value: Any?): Map<String, Any?> {
        val doc = AcpJs.decodeHeader(value, "PAYMENT-REQUIRED")
        val problems = paymentRequiredV2Problems(doc)
        if (problems.isNotEmpty()) throw IllegalArgumentException("x402: " + problems.joinToString("; "))
        return AcpJs.map(doc)
    }

    /**
     * Build the v2 402 challenge (`{status, headers, body}`): JSON body plus the base64 `PAYMENT-REQUIRED` header. [resource] is a
     * URL string or a ResourceInfo map; [opts] carries amount, asset, payTo, network and the optional scheme, maxTimeoutSeconds, extra,
     * error, extensions. Throws on anything the v2 spec makes invalid.
     */
    @JvmStatic
    fun x402ChallengeV2(resource: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val amount = opts["amount"]
        if (!(isSafeInteger(amount) && Js.num(amount)!! > 0)) throw IllegalArgumentException("x402Challenge: amount must be a positive integer in atomic units")
        val info = LinkedHashMap<String, Any?>()
        if (resource is String) info["url"] = resource else info.putAll(AcpJs.spread(resource))
        val body = LinkedHashMap<String, Any?>()
        body["x402Version"] = AcpJs.num(2)
        body["error"] = opts["error"] ?: "PAYMENT-SIGNATURE header is required"
        body["resource"] = info
        val req = LinkedHashMap<String, Any?>()
        req["scheme"] = opts["scheme"] ?: "exact"
        if (def(opts, "network")) req["network"] = opts["network"]
        req["amount"] = AcpJs.str(amount)
        if (def(opts, "asset")) req["asset"] = opts["asset"]
        if (def(opts, "payTo")) req["payTo"] = opts["payTo"]
        req["maxTimeoutSeconds"] = opts["maxTimeoutSeconds"] ?: AcpJs.num(60)
        if (def(opts, "extra")) req["extra"] = opts["extra"]
        body["accepts"] = arrayListOf<Any?>(req)
        if (def(opts, "extensions")) body["extensions"] = opts["extensions"]
        val header = encodePaymentRequiredHeader(body) // validates
        val headers = LinkedHashMap<String, Any?>()
        headers["Content-Type"] = "application/json"
        headers[X402_V2_PAYMENT_REQUIRED_HEADER] = header
        val out = LinkedHashMap<String, Any?>()
        out["status"] = AcpJs.num(402)
        out["headers"] = headers
        out["body"] = body
        return out
    }

    /**
     * Version negotiation: the highest version both sides support, or null when there is none (answer 402 v1 with an error, never guess).
     * [offered] null or empty means the client speaks v1 only.
     */
    @JvmStatic
    @JvmOverloads
    fun x402Negotiate(offered: List<Int>?, supported: List<Int> = X402_SUPPORTED_VERSIONS): Int? {
        val mine = supported.filter { it == 1 || it == 2 }.sortedDescending()
        val theirs = if (offered == null || offered.isEmpty()) listOf(1) else offered
        for (v in mine) if (theirs.contains(v)) return v
        return null
    }

    private fun stable(v: Any?): String {
        if (v is List<*>) return v.joinToString(",", "[", "]") { stable(it) }
        if (v !is Map<*, *>) return AcpJs.stringify(v)
        val keys = v.keys.map { it as String }.sorted()
        return keys.joinToString(",", "{", "}") { AcpJs.stringify(it) + ":" + stable(v[it]) }
    }

    /** True when [accepted] (echoed by the client in its v2 payload) is exactly one of the requirements the server offered. */
    @JvmStatic
    fun x402AcceptedMatches(offered: List<*>, accepted: Any?): Boolean {
        if (requirementV2Problems(accepted).isNotEmpty()) return false
        val a = stable(accepted)
        return offered.any { stable(it) == a }
    }

    private fun fail(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    /**
     * Read a client payload of either version: `{ok, version, token, merchant?, amount?, accepted?}` or `{ok:false, reason}`. v1: token, merchant
     * and amount are top-level members. v2: the delegated token is `payload.token` and the echoed `accepted` must be a valid v2
     * requirement; the merchant is never read from a v2 payload and the amount only from `accepted.amount`.
     */
    @JvmStatic
    fun normalizeX402Payload(raw: Any?): Map<String, Any?> {
        if (!isObj(raw)) return fail("x402 payment payload is not an object")
        val ver = get(raw, "x402Version")
        val vd = Js.num(ver)
        if (vd == 2.0) {
            val inner = get(raw, "payload")
            val tok = get(inner, "token")
            if (!isObj(inner) || tok !is String || tok.isEmpty()) return fail("x402 v2 payload is missing payload.token")
            val problems = requirementV2Problems(get(raw, "accepted"))
            if (problems.isNotEmpty()) return fail("x402 v2 payload.accepted is invalid: " + problems.joinToString("; "))
            val accepted = get(raw, "accepted")
            val out = LinkedHashMap<String, Any?>()
            out["ok"] = true
            out["version"] = AcpJs.num(2)
            out["token"] = tok
            out["accepted"] = accepted
            val amount = (get(accepted, "amount") as String).toDouble()
            if (AcpJs.safe(amount)) out["amount"] = AcpJs.num(amount.toLong())
            return out
        }
        if (def(raw, "x402Version") && vd != 1.0) return fail("unsupported x402Version " + AcpJs.str(ver))
        if (get(raw, "token") !is String) return fail("x402 payment payload is missing a token")
        val out = LinkedHashMap<String, Any?>()
        out["ok"] = true
        out["version"] = AcpJs.num(1)
        out["token"] = get(raw, "token")
        if (get(raw, "merchant") is String) out["merchant"] = get(raw, "merchant")
        if (Js.isNumber(get(raw, "amount"))) out["amount"] = get(raw, "amount")
        return out
    }
}
