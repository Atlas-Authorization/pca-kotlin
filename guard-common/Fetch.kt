package net.atlasauth.pca.fetch

import net.atlasauth.pca.guard.GuardOutcome
import net.atlasauth.pca.guard.PcaGuard
import net.atlasauth.pca.guard.PcaGuardConfig
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * A transport-neutral request guard for Proof-Carrying Authority: any runtime that can hand over a method, a URL, headers and a
 * body gets the same decisions as the Ktor plugin and the Spring filter (default-deny). The inbound PCActn (`PCA-Action: <base64url>`
 * or a JSON body `{"pcactn": ...}`) is verified by [PcaGuard.decide]; the handler runs only on success, else a 401 / 403 with a
 * `WWW-Authenticate` challenge is answered. Nothing here authorizes on its own: the verifier decides.
 *
 * The default deny body is the reference's `{error, verdict, decision}` ([referenceDenyBody]; `escalation` when the decision has one); the
 * Ktor / Spring body stays available as [GuardOutcome.body] through `denyBody`. The verdict carries `allow`, `checks` and `reasons`.
 */
object Fetch {
    /** The header carrying the base64url PCActn. */
    const val PCA_HEADER = PcaGuard.HEADER

    /** `PCA-Action: base64url(utf8(encoded))`, unpadded. */
    @JvmStatic
    fun pcaHeaders(encoded: String): Map<String, String> = linkedMapOf(PCA_HEADER to Pca.b64(Json.utf8(encoded)))

    /** The subset of an inbound request the guard reads. Header names match case-insensitively. */
    class FetchRequest(val method: String, val url: String, headers: Map<String, String>?, body: ByteArray?) {
        val headers: Map<String, String> = headers ?: emptyMap()
        val body: ByteArray = body ?: ByteArray(0)

        /** The first header with this name (case-insensitive), or null. */
        fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
    }

    /** The response of a guarded handler or of a deny. */
    class FetchResponse(val status: Int, val headers: Map<String, String>, val body: String)

    /** Guard configuration: [config] is the shared guard config; [operation] maps the request to the operation the route executes (never from the proof). */
    class Options(val config: PcaGuardConfig, val operation: ((FetchRequest) -> Authorize.Operation?)? = null, val denyBody: ((GuardOutcome) -> String)? = null) {
        init {
            require(config.audience != null && config.resolveGrant != null) { "audience and resolver are required" }
            require(config.signatureOnly || (config.authorize != null && operation != null)) { "authorized needs authorize options and an operation mapper" }
        }
    }

    /** A verifier over a request; it returns the full outcome so you can compose it yourself. Never throws. */
    @JvmStatic
    fun createPcaFetchGuard(o: Options): (FetchRequest) -> GuardOutcome = { req ->
        // a mapper that throws names no operation: authorize refuses
        val op = if (o.config.signatureOnly) null else try { o.operation!!(req) } catch (e: RuntimeException) { null }
        PcaGuard.decide(o.config, req.header(PcaGuard.HEADER), req.header(PcaGuard.ESCALATION_HEADER), req.body, op, null, req.header(PcaGuard.PROVENANCE_HEADER))
    }

    /** The 401 / 403 answer for a refused request: JSON body and a `WWW-Authenticate` challenge. */
    @JvmStatic
    fun denyResponse(r: GuardOutcome, denyBody: ((GuardOutcome) -> String)?): FetchResponse {
        val h = linkedMapOf("content-type" to "application/json")
        r.wwwAuthenticate?.let { h["WWW-Authenticate"] = it }
        return FetchResponse(r.status, h, denyBody?.invoke(r) ?: referenceDenyBody(r))
    }

    /** The reference's default 401 / 403 body: `{error, verdict, decision}` (+ `escalation`); `error` is the first reason, else "forbidden". */
    @JvmStatic
    fun referenceDenyBody(r: GuardOutcome): String {
        val v = r.verdict
        val allow: Boolean
        val checks: Map<String, Any?>
        val reasons = ArrayList<Any?>()
        if (v != null) {
            allow = v.allow
            checks = LinkedHashMap<String, Any?>(v.checks)
            if (v.reasons.isNotEmpty()) reasons.addAll(v.reasons) else if (v.reason.isNotEmpty()) reasons.add(v.reason)
        } else {
            allow = false
            checks = LinkedHashMap()
            // a refusal before any verdict: its description is in the native body
            val d = try { (Json.parse(r.body) as? Map<*, *>)?.get("error_description") as? String } catch (e: RuntimeException) { null }
            if (!d.isNullOrEmpty()) reasons.add(d)
        }
        val body = linkedMapOf<String, Any?>(
            "error" to (reasons.firstOrNull() ?: "forbidden"),
            "verdict" to linkedMapOf<String, Any?>("allow" to allow, "checks" to checks, "reasons" to reasons),
            "decision" to r.decision,
        )
        r.authorization?.escalation?.let { body["escalation"] = it }
        return Json.canonicalize(body)
    }

    /** Wrap a handler so the inbound PCActn is verified first; on success the handler runs with the outcome, else the deny response is returned. */
    @JvmStatic
    fun withPCA(o: Options, handler: (FetchRequest, GuardOutcome) -> FetchResponse): (FetchRequest) -> FetchResponse {
        val guard = createPcaFetchGuard(o)
        return { req ->
            val r = guard(req)
            if (r.allowed) handler(req, r) else denyResponse(r, o.denyBody)
        }
    }
}
