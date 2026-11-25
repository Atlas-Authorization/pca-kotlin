package net.atlasauth.pca.verifier

/**
 * Policy templates and a fluent authoring builder: a request maps onto a named ROLE template (read-only, support agent, finance bot,
 * dev assistant) or is composed with [PolicyBuilder]; both compile through the facade, so what you author is exactly what the verifier
 * enforces. Pure.
 */
object PolicyTemplates {
    /** One built-in role template: a conservative starting point, meant to be narrowed, not widened. */
    class PolicyTemplate(
        val name: String,
        val description: String,
        val permissions: Map<String, List<String>>,
        val limits: Map<String, String>? = null,
        val riskPolicy: Map<String, Any?>? = null,
    )

    @JvmField
    val TEMPLATES: Map<String, PolicyTemplate> = linkedMapOf(
        "read-only" to PolicyTemplate(
            "read-only", "Read access only — no side effects anywhere.",
            linkedMapOf("github" to listOf("read"), "slack" to listOf("read"), "files" to listOf("read"), "http" to listOf("get")),
        ),
        "support-agent" to PolicyTemplate(
            "support-agent", "Draft + send customer email and post to Slack, rate-limited.",
            linkedMapOf("gmail" to listOf("draft", "send"), "slack" to listOf("post_message")),
            linkedMapOf("send" to "50/day", "post_message" to "100/day"),
        ),
        "finance-bot" to PolicyTemplate(
            "finance-bot", "Issue reversible refunds within a daily cap; no payouts.",
            linkedMapOf("stripe" to listOf("refund")), linkedMapOf("refund" to "\$500/day"),
        ),
        "dev-assistant" to PolicyTemplate(
            "dev-assistant", "Read repos, open PRs and comment — never merge or delete.",
            linkedMapOf("github" to listOf("read", "create_pr", "comment")), linkedMapOf("create_pr" to "20/day"),
        ),
    )

    /** Every built-in template. */
    @JvmStatic
    fun listTemplates(): List<PolicyTemplate> = TEMPLATES.values.toList()

    private fun template(name: String, who: String): PolicyTemplate =
        TEMPLATES[name] ?: throw IllegalArgumentException("$who: unknown template '$name'" + (if (who == "fromTemplate") " (have: ${TEMPLATES.keys.joinToString(", ")})" else ""))

    /** Narrow or extend a template before minting: members given here replace the template's. */
    class Overrides(
        val permissions: Map<String, Any?>? = null,
        val limits: Map<String, Any?>? = null,
        val riskPolicy: Map<String, Any?>? = null,
        val agentBinding: Map<String, Any?>? = null,
        val budgetModel: String? = null,
    )

    /** Mint an agent from a named template. Throws on an unknown template. */
    @JvmStatic
    @JvmOverloads
    fun fromTemplate(
        name: String, principal: Keys.SuiteKey, goal: String, aud: String? = null, holder: Keys.SuiteKey? = null, now: Long? = null,
        overrides: Overrides? = null,
    ): Facade.Handle {
        val t = template(name, "fromTemplate")
        return Facade.agent(
            Facade.AgentOptions(
                principal = principal, goal = goal, permissions = overrides?.permissions ?: t.permissions,
                limits = overrides?.limits ?: t.limits, holder = holder, agentBinding = overrides?.agentBinding,
                riskPolicy = overrides?.riskPolicy ?: t.riskPolicy, budgetModel = overrides?.budgetModel, aud = aud, now = now,
            ),
        )
    }

    /** What [PolicyBuilder.build] returns. */
    class BuiltPolicy(val permissions: Map<String, List<String>>, val limits: Map<String, String>, val riskPolicy: Map<String, Any?>?)

    /** A typed, chainable policy builder: `PolicyBuilder().allow("stripe", listOf("refund")).limit("refund", "$500/day")`. */
    class PolicyBuilder {
        private val perms = LinkedHashMap<String, List<String>>()
        private val lims = LinkedHashMap<String, String>()
        private var riskOverride: LinkedHashMap<String, Any?>? = null

        /** Add [actions] under [connector] (a repeated action is kept once). */
        fun allow(connector: String, actions: List<String>): PolicyBuilder {
            perms[connector] = LinkedHashSet((perms[connector] ?: emptyList()) + actions).toList()
            return this
        }

        fun limit(verbOrAction: String, spec: String): PolicyBuilder {
            lims[verbOrAction] = spec
            return this
        }

        fun risk(partial: Map<String, Any?>): PolicyBuilder {
            val r = riskOverride ?: LinkedHashMap()
            r.putAll(partial)
            riskOverride = r
            return this
        }

        /** The permissions, limits and risk policy so far. Throws when no permission was added. */
        fun build(): BuiltPolicy {
            check(perms.isNotEmpty()) { "PolicyBuilder: no permissions added" }
            return BuiltPolicy(LinkedHashMap(perms), LinkedHashMap(lims), riskOverride?.let { LinkedHashMap(it) })
        }

        /** Mint an agent directly from the built policy. */
        @JvmOverloads
        fun agent(principal: Keys.SuiteKey, goal: String, aud: String? = null, holder: Keys.SuiteKey? = null, now: Long? = null): Facade.Handle {
            val b = build()
            return Facade.agent(
                Facade.AgentOptions(principal = principal, goal = goal, permissions = b.permissions, limits = b.limits, holder = holder, riskPolicy = b.riskPolicy, aud = aud, now = now),
            )
        }

        companion object {
            /** Start from a named template (its permissions, limits and risk seed the builder). */
            @JvmStatic
            fun from(name: String): PolicyBuilder {
                val t = template(name, "PolicyBuilder.from")
                val b = PolicyBuilder()
                for ((c, acts) in t.permissions) b.allow(c, acts)
                t.limits?.forEach { (k, v) -> b.limit(k, v) }
                t.riskPolicy?.let { b.risk(it) }
                return b
            }
        }
    }

    /** Entry point for the fluent builder. */
    @JvmStatic
    fun policy(): PolicyBuilder = PolicyBuilder()
}
