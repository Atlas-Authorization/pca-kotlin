package net.atlasauth.pca.guard

/** Base of the published PCA docs. */
const val PCA_DOCS = "https://github.com/Atlas-Authorization/pca/blob/main/docs"

private const val REF = "$PCA_DOCS/reference/refusals.md"

/** What a refusal means: the [check] that refused (the reason's leading token, or `unknown`), [meaning], [fix] and the page that explains it. */
class RefusalHelp(val check: String, val meaning: String, val fix: String, val docs: String)

private class Row(val check: String, val meaning: String, val fix: String, val docs: String)

private const val CONFIG_MEANING = "The guard was built without a required component, so it refuses every request (fail closed)."
private const val CONFIG_FIX = "Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults."
private const val GRANT_MEANING = "The proof does not name a grant this server knows."
private const val GRANT_FIX = "Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request."
private const val WIRE_FIX = "Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn })."

private val TABLE: List<Row> = listOf(
    Row("authorize_config", CONFIG_MEANING, CONFIG_FIX, "$PCA_DOCS/guides/resource-server-quickstart.md"),
    Row("authorize", CONFIG_MEANING, CONFIG_FIX, "$PCA_DOCS/guides/resource-server-quickstart.md"),
    Row("operation", "The signed action is not the operation this route executes (other verb, resource or params).", "Sign the action the route runs, with the same params. If this is a tool server, use one tool-to-action mapping on both sides.", "$REF#operation"),
    Row("audience", "The proof was signed for a different server.", "Make the agent sign with the same audience string the server is configured with.", "$REF#audience"),
    Row("replay", "This proof (or an older counter) was already used.", "Each action needs a fresh proof. If this is a retry of an action that already ran, use an operation record instead of resending.", "$REF#replay"),
    Row("counter_format", "The proof carries no valid anti-replay counter.", "Build the proof with the agent facade (act) or buildPCActn, which set it.", "$REF#replay"),
    Row("plan_root_authorized", "The plan the action belongs to was not authorized by the principal.", "Use plan: single-step (protect() does) for one-action proofs, or have the principal authorize the committed plan root.", "$REF#plan_root_authorized"),
    Row("plan_state", "The plan is committed but not executable now (not authorized, expired or revoked).", "Check the plan state named in the reason and re-authorize or recommit.", "$REF#plan_root_authorized"),
    Row("revocation", "The grant, or the revocation source, refused.", "The grant was revoked, or no revocation source is configured. Configure hooks.revocation (protect() does).", "$REF#revocation"),
    Row("validity", "The proof is outside its validity window.", "Check clocks on both sides; request a fresh proof.", "$REF#validity"),
    Row("grant_ref", GRANT_MEANING, GRANT_FIX, "$REF#grant_ref"),
    Row("grant_ref_bound", GRANT_MEANING, GRANT_FIX, "$REF#grant_ref"),
    Row("policy", "The grant does not permit this action or these parameters (a predicate or limit failed).", "Widen the grant if the action is legitimate (the principal signs a new one); otherwise this is the guard working.", "$REF#policy"),
    Row("delegated_caveats", "A caveat added by a delegation refused the action.", "The sub-agent was narrowed below this action. Delegate with the caveats you intend.", "$REF#policy"),
    Row("threshold", "The risk needs a co-signature from the principal (step-up).", "Collect the co-sign through the step-up flow, or lower the risk the server prices.", "$PCA_DOCS/concepts/threshold-and-step-up.md"),
    Row("risk_inputs", "A risk input the server must vouch for was not supplied.", "Supply it in the risk option (catalogRisk derives the common ones; protect() uses it).", "$REF#risk_inputs"),
    Row("chain", "The delegation chain does not verify back to the grant.", "Rebuild the chain with delegate()/subAgent(); do not edit a grant or hop after signing.", "$REF#chain"),
    Row("leaf_signature", "The proof signature does not verify.", "The proof was altered, or signed by a key that is not the chain leaf.", "$REF#chain"),
    Row("wire", "The proof is not well-formed under the strict wire profile.", WIRE_FIX, "$PCA_DOCS/reference/wire-formats.md"),
    Row("malformed", "The proof could not be read.", WIRE_FIX, "$PCA_DOCS/reference/wire-formats.md"),
    Row("freshness", "The consistency token or revocation epoch is stale.", "Refresh the token from the guardian and retry.", "$REF#freshness"),
    Row("template", "The grant is not an instantiation of a linked policy template.", "Mint the grant from the template the server requires.", "$PCA_DOCS/guides/policy-analysis.md"),
)

private val LEADING = Regex("^[a-z_]+")

/**
 * Guidance for a refusal reason from `Authorize.authorize` or a guard: what it means, how to fix it and the page that explains it.
 * The reasons are pinned across all ten languages and are never reworded; this maps them (by their leading check name) to guidance.
 * Unknown reasons return a generic entry that still links the table. Never throws.
 */
fun explainRefusal(reason: Any?): RefusalHelp {
    val text = reason as? String ?: ""
    val head = LEADING.find(text)?.value ?: ""
    val hit = TABLE.firstOrNull { it.check == head } ?: TABLE.firstOrNull { text.contains("${it.check}:") }
    if (hit != null) return RefusalHelp(hit.check, hit.meaning, hit.fix, hit.docs)
    return RefusalHelp("unknown", "The guard refused and the reason is not in the table.", "Read the reason as written; every refusal names the check that failed.", REF)
}
