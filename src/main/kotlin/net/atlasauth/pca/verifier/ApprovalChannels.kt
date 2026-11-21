package net.atlasauth.pca.verifier

import java.math.BigDecimal
import java.math.RoundingMode
import java.net.URLEncoder

/**
 * Approval-notification channels for step-ups. [Approvals] is the headless core; this is the channel layer: given a pending step-up
 * request (which carries its goal lineage and canonical render), each channel FORMATS a human-readable notification (action summary,
 * the "because you asked to ..." lineage, an approve / deny affordance or a link to the inbox) and DISPATCHES it over an injected
 * transport. A channel that is not configured reports `enabled = false` and never dispatches; a returned delivery never carries the
 * webhook URL, token or signing secret; nothing here logs. A channel only REPORTS a step-up the verifier already produced: it
 * authorizes nothing.
 */
object ApprovalChannels {
    /** The HTTP surface a channel needs, injected so channels stay offline-testable: POST [body], answer the HTTP status. Throw on a transport failure. */
    fun interface Transport {
        fun post(url: String, headers: Map<String, String>, body: String): Int
    }

    /** Delivers a formatted text body (email, SMS, push). Returns a channel-native message id (or null), or throws on failure. */
    fun interface TextSender {
        fun send(subject: String, text: String): String?
    }

    /** A channel: [kind] is `slack`, `webhook`, `email`, `push` or `sms`; [notify] never throws and answers a delivery map. */
    interface ApprovalChannel {
        val kind: String

        /** True iff the channel is configured enough to deliver (the config gate). */
        val enabled: Boolean

        /** Format the step-up for this channel and dispatch it. [ctx] is `{inboxUrl?, now?}`. */
        fun notify(request: Map<String, Any?>, ctx: Map<String, Any?>? = null): Map<String, Any?>
    }

    private val DEFAULT_TRANSPORT = Transport { url, headers, body -> SimpleHttp.request("POST", url, headers, body).first }

    private fun str(v: Any?): String = AttestUtil.jsAnyString(v)

    private fun lineageOf(request: Map<String, Any?>): Map<String, Any?> = Pca.asMap(request["lineage"])

    /** One-line action summary: `verb on resource (tier N, risk R)`. */
    @JvmStatic
    fun actionSummary(request: Map<String, Any?>): String {
        val r = IntentJs.num(request["r"]) ?: Double.NaN
        val risk = if (r.isNaN() || r.isInfinite()) Json.jsNumberText(r) else BigDecimal(r).setScale(2, RoundingMode.HALF_UP).toPlainString()
        return "${str(request["verb"])} on ${str(request["resource"])} (tier ${str(request["tier"])}, risk $risk)"
    }

    /**
     * The goal-lineage lines a human reads to understand WHY: the "because you asked to ..." sentence, the goal, authority and action
     * chain, then the canonical render. Derived purely from the request.
     */
    @JvmStatic
    fun lineageLines(request: Map<String, Any?>): List<String> {
        val lin = lineageOf(request)
        val out = ArrayList<String>()
        out.add(str(lin["because"]))
        for (l in Approvals.describeGoalLineage(lin)) out.add(str(l))
        out.addAll(renderLines(request))
        return out
    }

    private val INVISIBLE = Regex("[\\p{Cc}\\p{Cf}  ]")

    /**
     * The canonical render, one line per field (nothing omitted), the banner for an unreviewed action and the speakable binding words
     * of H(R). Empty when the request carries no render. Every channel shows the same lines.
     */
    @JvmStatic
    fun renderLines(request: Map<String, Any?>): List<String> {
        val r = request["render"] as? Map<*, *>
        val digest = request["renderDigest"]
        if (r == null || digest == null) return emptyList()
        val out = ArrayList<String>()
        if (r["unreviewed"] == true) out.add("UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.")
        for (f in (r["fields"] as? List<*>) ?: emptyList<Any?>()) {
            val fm = f as Map<*, *>
            val unit = fm["unit"] as? Map<*, *>
            val u = if (unit?.get("kind") == "money") " ${str(unit["ccy"])} (minor units, exponent ${str(unit["exp"])})" else ""
            val shown = INVISIBLE.replace(Approvals.stringify(fm["value"])) { m -> "\\u{" + Integer.toHexString(m.value.codePointAt(0)) + "}" }
            out.add("${str(fm["id"])} [${str(fm["class"])}]: $shown$u")
        }
        out.add("Match code: " + Approval.bindingWords(digest))
        return out
    }

    private fun encodeUriComponent(s: String): String =
        URLEncoder.encode(s, "UTF-8").replace("+", "%20").replace("%21", "!").replace("%27", "'").replace("%28", "(").replace("%29", ")").replace("%7E", "~")

    /** Add query parameters before any `#fragment` (an approval link may carry its token in the fragment, which must stay last). */
    private fun appendQuery(url: String, params: List<Pair<String, String>>): String {
        val query = params.joinToString("&") { (k, v) -> encodeUriComponent(k) + "=" + encodeUriComponent(v) }
        val hash = url.indexOf('#')
        val base = if (hash == -1) url else url.substring(0, hash)
        val fragment = if (hash == -1) "" else url.substring(hash)
        return base + (if (base.contains('?')) "&" else "?") + query + fragment
    }

    private fun inbox(ctx: Map<String, Any?>?): String? = (ctx?.get("inboxUrl") as? String)?.takeIf { it.isNotEmpty() }

    private fun delivery(kind: String, request: Map<String, Any?>, delivered: Boolean, payload: Any?, status: Int? = null, reason: String? = null): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("kind" to kind, "requestId" to request["id"], "delivered" to delivered, "payload" to payload)
        if (status != null) m["status"] = status.toLong()
        if (reason != null) m["reason"] = reason
        return m
    }

    // ---- Slack (Block Kit over an incoming webhook) ----

    /** Build the Block Kit message for a step-up: action summary, goal lineage, approve / deny affordance. */
    @JvmStatic
    @JvmOverloads
    fun buildSlackMessage(request: Map<String, Any?>, ctx: Map<String, Any?>? = null): Map<String, Any?> {
        val id = str(request["id"])
        val blocks = ArrayList<Any?>()
        blocks.add(linkedMapOf("type" to "header", "text" to linkedMapOf("type" to "plain_text", "text" to "Approval needed · tier ${str(request["tier"])}", "emoji" to true)))
        blocks.add(linkedMapOf("type" to "section", "text" to linkedMapOf("type" to "mrkdwn", "text" to "*${str(request["verb"])}* on `${str(request["resource"])}`\n_${str(request["reason"])}_")))
        blocks.add(linkedMapOf("type" to "section", "text" to linkedMapOf("type" to "mrkdwn", "text" to "*Why this is requested*\n" + lineageLines(request).joinToString("\n") { "• $it" })))
        val url = inbox(ctx)
        if (url != null) {
            val approve = appendQuery(url, listOf("stepup" to id, "decision" to "approve"))
            val deny = appendQuery(url, listOf("stepup" to id, "decision" to "deny"))
            blocks.add(
                linkedMapOf(
                    "type" to "actions",
                    "elements" to listOf(
                        linkedMapOf("type" to "button", "text" to linkedMapOf("type" to "plain_text", "text" to "Approve", "emoji" to true), "url" to approve, "style" to "primary", "action_id" to "pca_approve"),
                        linkedMapOf("type" to "button", "text" to linkedMapOf("type" to "plain_text", "text" to "Deny", "emoji" to true), "url" to deny, "style" to "danger", "action_id" to "pca_deny"),
                    ),
                ),
            )
        } else {
            blocks.add(linkedMapOf("type" to "context", "elements" to listOf(linkedMapOf("type" to "mrkdwn", "text" to "Approve or deny step-up `$id` in your Atlas inbox."))))
        }
        return linkedMapOf("text" to "Approval needed: ${actionSummary(request)}", "blocks" to blocks)
    }

    private class PostChannel(
        override val kind: String, private val url: String?, private val transport: Transport, private val extraHeaders: Map<String, String>,
        private val label: String, private val build: (Map<String, Any?>, Map<String, Any?>?) -> Map<String, Any?>,
    ) : ApprovalChannel {
        override val enabled: Boolean = !url.isNullOrEmpty()

        override fun notify(request: Map<String, Any?>, ctx: Map<String, Any?>?): Map<String, Any?> {
            val body = build(request, ctx)
            if (!enabled || url == null) return delivery(kind, request, false, body, reason = "$kind channel not configured")
            return try {
                val status = transport.post(url, linkedMapOf("content-type" to "application/json") + extraHeaders, Approvals.stringify(body))
                if (status in 200..299) delivery(kind, request, true, body, status)
                else delivery(kind, request, false, body, status, "$label returned $status")
            } catch (e: Exception) {
                delivery(kind, request, false, body, reason = e.message ?: "$kind transport error")
            }
        }
    }

    /** Slack approval channel. Disabled (and a no-op) unless a webhook URL is configured. */
    @JvmStatic
    @JvmOverloads
    fun slackApprovalChannel(webhookUrl: String? = null, transport: Transport? = null): ApprovalChannel =
        PostChannel("slack", webhookUrl, transport ?: DEFAULT_TRANSPORT, emptyMap(), "slack webhook") { r, c -> buildSlackMessage(r, c) }

    // ---- webhook (JSON POST) ----

    /** The webhook body: the step-up plus its pre-formatted human summary and lineage. */
    @JvmStatic
    @JvmOverloads
    fun buildWebhookBody(request: Map<String, Any?>, ctx: Map<String, Any?>? = null): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("type" to "pca.step_up.created", "stepup" to request, "summary" to actionSummary(request), "lineage" to lineageLines(request))
        inbox(ctx)?.let { m["inbox_url"] = it }
        return m
    }

    /** Generic webhook approval channel: a JSON POST with optional extra [headers] (for example a caller-computed signature header). Disabled without a URL. */
    @JvmStatic
    @JvmOverloads
    fun webhookApprovalChannel(url: String? = null, transport: Transport? = null, headers: Map<String, String> = emptyMap()): ApprovalChannel =
        PostChannel("webhook", url, transport ?: DEFAULT_TRANSPORT, headers, "webhook") { r, c -> buildWebhookBody(r, c) }

    // ---- text channels (email / sms / push) ----

    /** The plain-text body `{subject, text}` shared by the email, SMS and push surfaces. */
    @JvmStatic
    @JvmOverloads
    fun buildTextBody(request: Map<String, Any?>, ctx: Map<String, Any?>? = null): Map<String, Any?> {
        val lines = ArrayList<String>()
        lines.add(actionSummary(request))
        lines.add("")
        lines.addAll(lineageLines(request))
        inbox(ctx)?.let {
            lines.add("")
            lines.add("Approve or deny: " + appendQuery(it, listOf("stepup" to str(request["id"]))))
        }
        return linkedMapOf("subject" to "Approval needed: ${str(request["verb"])} on ${str(request["resource"])}", "text" to lines.joinToString("\n"))
    }

    /** A text-formatter channel ([kind] is `email`, `sms` or `push`) over an injected [send]er. Disabled without one. */
    @JvmStatic
    @JvmOverloads
    fun textApprovalChannel(kind: String, send: TextSender? = null): ApprovalChannel {
        require(kind == "email" || kind == "sms" || kind == "push") { "textApprovalChannel: kind must be email, sms or push" }
        val channelKind = kind
        return object : ApprovalChannel {
            override val kind: String = channelKind
            override val enabled: Boolean = send != null

            override fun notify(request: Map<String, Any?>, ctx: Map<String, Any?>?): Map<String, Any?> {
                val body = buildTextBody(request, ctx)
                if (send == null) return delivery(channelKind, request, false, body, reason = "$channelKind channel not configured")
                return try {
                    send.send(body["subject"] as String, body["text"] as String)
                    delivery(channelKind, request, true, body)
                } catch (e: Exception) {
                    delivery(channelKind, request, false, body, reason = e.message ?: "$channelKind send error")
                }
            }
        }
    }

    // ---- dispatcher ----

    /** Fans a step-up out to every ENABLED channel. */
    class ApprovalDispatcher internal constructor(val channels: List<ApprovalChannel>) {
        /** One delivery per enabled channel (a disabled channel is skipped). */
        @JvmOverloads
        fun notifyAll(request: Map<String, Any?>, ctx: Map<String, Any?>? = null): List<Map<String, Any?>> =
            channels.filter { it.enabled }.map { it.notify(request, ctx) }
    }

    /** Register a set of channels behind one dispatcher. Disabled channels are skipped at [ApprovalDispatcher.notifyAll]. */
    @JvmStatic
    fun createApprovalDispatcher(channels: List<ApprovalChannel>): ApprovalDispatcher = ApprovalDispatcher(ArrayList(channels))
}
