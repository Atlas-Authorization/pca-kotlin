package net.atlasauth.pca.verifier

import org.junit.Test

/** The agent-facing half of approvals (review, goal lineage, batch review, time-boxing) and the approval channels, against the reference corpora. */
@Suppress("UNCHECKED_CAST")
class CoreApprovalsDiffTest {
    private val m = "ref-core-approvals-java"
    private val ch = "ref-core-approval-channels"

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun key(label: Any?): Keys.SuiteKey = Keys.ed25519(Keys.edFromSeed(OracleCases.seed("approvals/$label")))

    private fun build(specO: Any?): Facade.Handle {
        val s = map(specO)!!
        return Agent.fromPrincipal(
            Facade.AgentOptions(
                principal = key(s["principal"]), goal = s["goal"] as String, permissions = map(s["permissions"])!!, limits = map(s["limits"]),
                holder = key(s["holder"]), riskPolicy = map(s["riskPolicy"]), budgetModel = s["budgetModel"] as? String, aud = s["aud"] as? String,
                now = IntentJs.lng(s["now"]), goalSalt = s["goalSalt"] as? String,
            ),
        )
    }

    private fun renderer(mode: String) = Approvals.Renderer { verb, resource, _ ->
        if (mode == "throw") throw IllegalStateException("boom")
        if (mode == "badshape") linkedMapOf<String, Any?>("v" to 2L)
        else linkedMapOf<String, Any?>(
            "v" to 1L, "kind" to "pca-approval-render", "verb" to verb, "def_digest" to "A".repeat(43), "unreviewed" to true,
            "fields" to listOf<Any?>(linkedMapOf("id" to "resource", "class" to "param", "value" to resource)),
        )
    }

    private fun opts(o: Any?): Approvals.ReviewOptions {
        val x = map(o) ?: return Approvals.ReviewOptions()
        return Approvals.ReviewOptions(
            now = x["now"]?.let { IntentJs.lng(it) }, goal = x["goal"] as? String, standing = x["standing"] as? List<Any?>,
            renderer = (x["renderer"] as? String)?.let { renderer(it) }, insecureUnboundApproval = x["insecure"] == true,
        )
    }

    @Test fun reviewAction() = OracleCases.each(m, "reviewAction") { a -> Approvals.reviewAction(build(a[0]), a[1] as String, a[2] as String, map(a[3]), opts(a[4])) }

    @Test fun buildGoalLineage() = OracleCases.each(m, "buildGoalLineage") { a ->
        Approvals.buildGoalLineage(build(a[0]), a[1] as String, a[2] as String, map(a[3]), map(a[4])?.get("goal") as? String)
    }

    @Test fun describeGoalLineage() = OracleCases.each(m, "describeGoalLineage") { a -> Approvals.describeGoalLineage(map(a[0])) }

    @Test fun batchReview() = OracleCases.each(m, "batchReview") { a ->
        Approvals.batchReview(build(a[0]), (a[1] as List<*>).map { map(it)!! }, opts(a[2]))
    }

    @Test fun timeBox() = OracleCases.each(m, "timeBox") { a -> Approvals.timeBox(map(a[0])!!, key(a[1]), IntentJs.num(a[2])!!, IntentJs.num(a[3])!!) }

    // ---- the approval channels ----

    private fun ctx(c: Any?): Map<String, Any?>? = map(c)

    private fun transport(mode: String) = ApprovalChannels.Transport { _, _, _ ->
        when (mode) {
            "ok" -> 200
            "http500" -> 500
            else -> throw IllegalStateException(if (mode == "throw") "boom" else "")
        }
    }

    private fun channel(kind: String, cfg: Map<String, Any?>): ApprovalChannels.ApprovalChannel {
        val configured = cfg["configured"] == true
        val t = cfg["transport"] as String
        val url = if (configured) "https://hooks.example/secret" else null
        return when (kind) {
            "slack" -> ApprovalChannels.slackApprovalChannel(url, transport(t))
            "webhook" -> ApprovalChannels.webhookApprovalChannel(url, transport(t), (map(cfg["headers"]) ?: emptyMap()).mapValues { it.value as String })
            else -> ApprovalChannels.textApprovalChannel(
                kind,
                if (configured) ApprovalChannels.TextSender { _, _ -> if (t == "ok") "m1" else throw IllegalStateException(if (t == "throw-empty") "" else "boom") } else null,
            )
        }
    }

    @Test fun actionSummary() = OracleCases.each(ch, "actionSummary") { a -> ApprovalChannels.actionSummary(map(a[0])!!) }

    @Test fun lineageLines() = OracleCases.each(ch, "lineageLines") { a -> ApprovalChannels.lineageLines(map(a[0])!!) }

    @Test fun renderLines() = OracleCases.each(ch, "renderLines") { a -> ApprovalChannels.renderLines(map(a[0])!!) }

    @Test fun buildSlackMessage() = OracleCases.each(ch, "buildSlackMessage") { a -> ApprovalChannels.buildSlackMessage(map(a[0])!!, ctx(a[1])) }

    @Test fun buildWebhookBody() = OracleCases.each(ch, "buildWebhookBody") { a -> ApprovalChannels.buildWebhookBody(map(a[0])!!, ctx(a[1])) }

    @Test fun buildTextBody() = OracleCases.each(ch, "buildTextBody") { a -> ApprovalChannels.buildTextBody(map(a[0])!!, ctx(a[1])) }

    @Test fun notifyChannel() = OracleCases.each(ch, "notify") { a -> channel(a[0] as String, map(a[3])!!).notify(map(a[1])!!, ctx(a[2])) }

    @Test fun dispatcherNotifyAll() = OracleCases.each(ch, "notifyAll") { a ->
        val chans = (a[2] as List<*>).map { c -> channel(map(c)!!["kind"] as String, map(c)!!) }
        ApprovalChannels.createApprovalDispatcher(chans).notifyAll(map(a[0])!!, ctx(a[1]))
    }
}
