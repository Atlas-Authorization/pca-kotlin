package net.atlasauth.pca.policyci

import net.atlasauth.pca.verifier.Pca

/**
 * The action-kit lint rule list ({id, severity, title}, in order) and its digest. The list is part of what an action pack is checked
 * against, so a policy gate pins the digest: adding, removing or rewording a rule is a visible, reviewed change.
 */
object ActionLintRules {
    const val LINT_RULES_DIGEST_DOMAIN = "atlas-pca/action-lint-rules/v1"

    /** The rules: {id, severity, title} rows. */
    val LINT_RULES: List<Array<String>> = listOf(
        arrayOf("LD-001", "error", "a destroy-like verb whose effects do not delete"),
        arrayOf("LD-002", "error", "a money parameter without a currency, or a currency without the iso_currency format"),
        arrayOf("LD-003", "error", "a numeric parameter without min and max"),
        arrayOf("LD-004", "error", "a money-moving action without idempotency"),
        arrayOf("LD-005", "error", "personal data can leave without the matching effect"),
        arrayOf("LD-006", "error", "a declared reversibility or blast below the effective floor"),
        arrayOf("LD-007", "error", "an unknown trait, role, format, effect or context key, or an invalid custom trait"),
        arrayOf("LD-008", "error", "resource id '*' with scope one"),
        arrayOf("LD-009", "error", "a duplicate verb or alias collision"),
        arrayOf("LD-010", "error", "a write marked reversible with no compensating action in the pack"),
        arrayOf("LD-011", "error", "review state confirmed without a valid attestation for this digest"),
        arrayOf("LD-012", "error", "a structural param rule that the effective traits require is violated"),
        arrayOf("LD-013", "error", "a read-only action that can mutate or handles credentials"),
        arrayOf("LD-014", "error", "one binding in two defs"),
        arrayOf("LW-001", "warning", "description missing or too long, or title not imperative"),
        arrayOf("LW-002", "warning", "a string parameter without max_len"),
        arrayOf("LW-003", "warning", "free text flows into an outbound action without the free_text_outbound tag"),
        arrayOf("LW-004", "warning", "an unreviewed def in a stable pack"),
        arrayOf("LW-005", "warning", "a dismissed suggested trait without a reason"),
        arrayOf("LW-006", "warning", "an array parameter without max_items"),
        arrayOf("LW-007", "warning", "a critical parameter without provenance_min"),
        arrayOf("LW-008", "warning", "verb naming inconsistent with its siblings or with the file namespace"),
        arrayOf("LW-009", "warning", "a money-moving, destructive or privilege-changing action without an example"),
        arrayOf("LW-010", "warning", "since is missing"),
    )

    /** The digest the policy gate pins: the canonical hash of the ordered (id, severity, title) list. */
    fun lintRulesDigest(): String {
        val rules = ArrayList<Any?>()
        for (r in LINT_RULES) rules.add(linkedMapOf<String, Any?>("id" to r[0], "severity" to r[1], "title" to r[2]))
        return Pca.hashCanonical(linkedMapOf<String, Any?>("d" to LINT_RULES_DIGEST_DOMAIN, "rules" to rules))
    }
}
