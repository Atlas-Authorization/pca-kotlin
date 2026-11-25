package net.atlasauth.pca.wallet

import net.atlasauth.pca.jose.Js

/**
 * Framework-neutral handlers for the two wallet endpoints named in the session root: the question endpoint (a site delivers, or an
 * agent relays unchanged, a site-signed intent_required with the attempted action) and the clarification endpoint. The HTTP
 * routes live with the session store; these functions are what such a route calls, so the wire behaviour is fixed and tested here.
 * Neither response carries p or any map content: the caller learns a question id, a dry-run verdict, or a refusal code, exactly
 * what an attempt would teach it. A response is {status, body}.
 */
@Suppress("UNCHECKED_CAST")
object WalletHandlers {
    /** Finds the channel of a session, or null. */
    fun interface ChannelResolver { fun resolve(sessionId: String): TrustedChannel? }

    private val STATUS_OF_REFUSAL: Map<String, Int> = mapOf(
        "bad_site_signature" to 401, "wrong_session" to 409, "stale_map" to 409, "action_mismatch" to 422,
        "cell_mismatch" to 422, "not_uncertain" to 409, "already_asked" to 409, "frozen" to 429,
        "cap_session" to 429, "cap_hour" to 429, "cell_too_large" to 422, "bad_request" to 400, "render_failed" to 422,
    )

    private fun resp(status: Int, body: Map<String, Any?>): Map<String, Any?> = Wallet.obj("status", Js.n(status.toLong()), "body", body)

    private fun actionOf(v: Any?): Map<String, Any?>? {
        if (!Wallet.isObj(v)) return null
        val m = v as Map<*, *>
        if (m["verb"] !is String || m["resource"] !is String || m["reversibility_class"] !is String || !Wallet.isObj(m["params"])) return null
        for (k in m.keys) if (!listOf("verb", "resource", "params", "reversibility_class").contains(k)) return null
        return Wallet.obj("verb", m["verb"], "resource", m["resource"], "params", m["params"], "reversibility_class", m["reversibility_class"])
    }

    /** The question endpoint: POST {intent_required, action} to a session. */
    fun question(resolve: ChannelResolver, sessionId: String, body: Any?): Map<String, Any?> {
        val ch = resolve.resolve(sessionId) ?: return resp(404, Wallet.obj("error", "unknown_session"))
        if (!Wallet.isObj(body)) return resp(400, Wallet.obj("error", "bad_request"))
        val b = body as Map<*, *>
        for (k in b.keys) if ("intent_required" != k && "action" != k) return resp(400, Wallet.obj("error", "bad_request", "detail", "unknown member \"$k\""))
        val action = actionOf(b["action"])
        val ir = b["intent_required"]
        if (action == null || !Wallet.isObj(ir)) return resp(400, Wallet.obj("error", "bad_request"))
        val r = ch.receive(ir as Map<String, Any?>, action)
        if (r["ok"] == true) return resp(202, Wallet.obj("question_id", r["questionId"], "friction", r["friction"]))
        val st = STATUS_OF_REFUSAL[r["code"]]
        return resp(st ?: 400, Wallet.obj("error", r["code"]))
    }

    /** The clarification endpoint: POST {candidates, reason} to a session. */
    fun clarify(resolve: ChannelResolver, sessionId: String, body: Any?): Map<String, Any?> {
        val ch = resolve.resolve(sessionId) ?: return resp(404, Wallet.obj("error", "unknown_session"))
        val r = ch.clarify(body)
        if (r.containsKey("error")) return resp(400, Wallet.obj("error", "bad_request", "detail", r["error"]))
        val b = Wallet.obj("verdicts", r["verdicts"])
        if (r.containsKey("questionId")) b["question_id"] = r["questionId"]
        if (r.containsKey("refused")) b["refused"] = r["refused"]
        return Wallet.obj("status", r["status"], "body", b)
    }
}
