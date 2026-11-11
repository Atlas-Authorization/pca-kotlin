package net.atlasauth.pca.guard

import org.junit.Assert.assertEquals
import org.junit.Test

/** `explainRefusal`: every row of the table, pinned to the TypeScript reference (packages/pca/src/refusal-help.ts). */
class Kill06RefusalHelpTest {
    private val rows: List<Array<String>> = listOf(
        arrayOf("authorize_config", "The guard was built without a required component, so it refuses every request (fail closed).", "Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/resource-server-quickstart.md"),
        arrayOf("authorize", "The guard was built without a required component, so it refuses every request (fail closed).", "Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/resource-server-quickstart.md"),
        arrayOf("operation", "The signed action is not the operation this route executes (other verb, resource or params).", "Sign the action the route runs, with the same params. If this is a tool server, use one tool-to-action mapping on both sides.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#operation"),
        arrayOf("audience", "The proof was signed for a different server.", "Make the agent sign with the same audience string the server is configured with.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#audience"),
        arrayOf("replay", "This proof (or an older counter) was already used.", "Each action needs a fresh proof. If this is a retry of an action that already ran, use an operation record instead of resending.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay"),
        arrayOf("counter_format", "The proof carries no valid anti-replay counter.", "Build the proof with the agent facade (act) or buildPCActn, which set it.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay"),
        arrayOf("plan_root_authorized", "The plan the action belongs to was not authorized by the principal.", "Use plan: single-step (protect() does) for one-action proofs, or have the principal authorize the committed plan root.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#plan_root_authorized"),
        arrayOf("plan_state", "The plan is committed but not executable now (not authorized, expired or revoked).", "Check the plan state named in the reason and re-authorize or recommit.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#plan_root_authorized"),
        arrayOf("revocation", "The grant, or the revocation source, refused.", "The grant was revoked, or no revocation source is configured. Configure hooks.revocation (protect() does).", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#revocation"),
        arrayOf("validity", "The proof is outside its validity window.", "Check clocks on both sides; request a fresh proof.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#validity"),
        arrayOf("grant_ref", "The proof does not name a grant this server knows.", "Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#grant_ref"),
        arrayOf("grant_ref_bound", "The proof does not name a grant this server knows.", "Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#grant_ref"),
        arrayOf("policy", "The grant does not permit this action or these parameters (a predicate or limit failed).", "Widen the grant if the action is legitimate (the principal signs a new one); otherwise this is the guard working.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#policy"),
        arrayOf("delegated_caveats", "A caveat added by a delegation refused the action.", "The sub-agent was narrowed below this action. Delegate with the caveats you intend.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#policy"),
        arrayOf("threshold", "The risk needs a co-signature from the principal (step-up).", "Collect the co-sign through the step-up flow, or lower the risk the server prices.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/concepts/threshold-and-step-up.md"),
        arrayOf("risk_inputs", "A risk input the server must vouch for was not supplied.", "Supply it in the risk option (catalogRisk derives the common ones; protect() uses it).", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#risk_inputs"),
        arrayOf("chain", "The delegation chain does not verify back to the grant.", "Rebuild the chain with delegate()/subAgent(); do not edit a grant or hop after signing.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#chain"),
        arrayOf("leaf_signature", "The proof signature does not verify.", "The proof was altered, or signed by a key that is not the chain leaf.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#chain"),
        arrayOf("wire", "The proof is not well-formed under the strict wire profile.", "Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn }).", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/wire-formats.md"),
        arrayOf("malformed", "The proof could not be read.", "Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn }).", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/wire-formats.md"),
        arrayOf("freshness", "The consistency token or revocation epoch is stale.", "Refresh the token from the guardian and retry.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#freshness"),
        arrayOf("provenance_flow", "The action, or an argument of it, derives from content the principal did not write (a tool result, a page, an unpinned or missing provenance bundle), or the bundle is forged or unreadable.", "Present the provenance bundle your pinned mediator recorded (PCA-Provenance header), have the principal confirm the escalation, or run the call from a principal-authorized plan.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/prompt-injection-provenance.md"),
        arrayOf("undo_window", "The action ran under a veto window: the principal can undo it until the window ends.", "Report the effect to your undo coordinator and let the window run.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/undo-windows.md"),
        arrayOf("template", "The grant is not an instantiation of a linked policy template.", "Mint the grant from the template the server requires.", "https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/policy-analysis.md"),
    )

    private val unknownMeaning = "The guard refused and the reason is not in the table."
    private val unknownFix = "Read the reason as written; every refusal names the check that failed."
    private val ref = "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md"

    private fun assertRow(row: Array<String>, h: RefusalHelp) {
        assertEquals(row[0], h.check)
        assertEquals(row[1], h.meaning)
        assertEquals(row[2], h.fix)
        assertEquals(row[3], h.docs)
    }

    private fun assertUnknown(reason: Any?) {
        val h = explainRefusal(reason)
        assertEquals("unknown", h.check)
        assertEquals(unknownMeaning, h.meaning)
        assertEquals(unknownFix, h.fix)
        assertEquals(ref, h.docs)
    }

    @Test
    fun theDocsBaseIsPinned() {
        assertEquals("https://github.com/Atlas-Authorization/pca/blob/main/docs", PCA_DOCS)
    }

    @Test
    fun everyRowIsFoundByItsLeadingToken() {
        assertEquals(24, rows.size)
        for (row in rows) {
            assertRow(row, explainRefusal(row[0]))
            assertRow(row, explainRefusal(row[0] + ": something failed"))
            assertRow(row, explainRefusal(row[0] + " (step x)"))
        }
    }

    @Test
    fun aRowIsFoundWhereverItsTokenWithAColonOccurs() {
        for (row in rows) {
            assertRow(row, explainRefusal("Refused by " + row[0] + ": detail"))
            assertRow(row, explainRefusal("X " + row[0] + ":"))
        }
    }

    @Test
    fun theFirstRowOfTheTableWinsWhenSeveralOccur() {
        // table order: replay precedes delegated_caveats, which precedes provenance_flow
        assertEquals("replay", explainRefusal("A delegated_caveats: x and replay: y").check)
        assertEquals("policy", explainRefusal("A delegated_caveats: x and policy: y").check)
        assertEquals("delegated_caveats", explainRefusal("A provenance_flow: x and delegated_caveats: y").check)
        // the leading token beats a later one
        assertEquals("wire", explainRefusal("wire: but also replay: x").check)
        assertEquals("authorize_config", explainRefusal("authorize_config: missing").check)
        assertEquals("authorize", explainRefusal("authorize: error (fail closed)").check)
        assertEquals("grant_ref_bound", explainRefusal("grant_ref_bound: x").check)
        assertEquals("grant_ref", explainRefusal("grant_ref: does not resolve").check)
    }

    @Test
    fun onlyTheLowercaseLeadingRunIsTheToken() {
        // digits end the token: "wire2" is "wire"
        assertEquals("wire", explainRefusal("wire2: x").check)
        assertEquals("replay", explainRefusal("replay-ish").check)
        // a hyphen ends the token too
        assertEquals("policy", explainRefusal("policy-x").check)
        // a capital first leaves no token, and no lowercase "<check>:" occurs
        assertUnknown("Policy: x")
        assertUnknown("POLICY: x")
        // a space or a digit first leaves no token, but the later "<check>:" is still found
        assertEquals("policy", explainRefusal(" policy: x").check)
        assertEquals("policy", explainRefusal("2policy: x").check)
    }

    @Test
    fun anUnknownReasonGetsTheGenericEntry() {
        assertUnknown("")
        assertUnknown("foo: bar")
        assertUnknown("something else entirely")
        assertUnknown(null)
        assertUnknown(42)
        assertUnknown(listOf("policy: x"))
        assertUnknown(mapOf("reason" to "policy: x"))
        // a token that is only part of a row name is not a row
        assertUnknown("polic: x")
        assertUnknown("chai: x")
    }
}
