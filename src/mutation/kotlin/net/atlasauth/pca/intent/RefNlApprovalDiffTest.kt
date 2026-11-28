package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.BaseOracle
import net.atlasauth.pca.verifier.Catalog
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The approval half of natural-language policy authoring against the reference (ref-nl-approval, 206 cases): the catalog digest, the draft binding and digests,
 * the grounded policy and the draft from a fixed completion (a model that throws is "THROWS"), signing a reviewer's approval (v2 and the legacy v1) with the signature
 * bytes compared, the loader's every rejection code and the agent minted from an approval (only the deterministic envelope members are compared: the goal commitment
 * carries a random salt).
 */
@Suppress("UNCHECKED_CAST")
class RefNlApprovalDiffTest {
    private val mod = "ref-nl-approval"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict((o as? Map<*, *>)?.get("\$bytes"), 32) ?: throw IllegalArgumentException("not a signing key")

    private fun catalog(extras: Any?): Catalog {
        if (extras == null) return Catalog.DEFAULT
        val specs = ArrayList(Catalog.BUILTIN)
        for (eo in extras as List<Any?>) {
            val e = eo as Map<String, Any?>
            val connector = e["connector"] as String
            val action = e["action"] as String
            val aliases = if (e["aliases"] != null) (e["aliases"] as List<Any?>).map { it as String } else emptyList()
            specs.add(Catalog.Spec(connector, action, "$connector.$action", e["reversibility"] as String, IntentOmega.dbl(e["blastRadius"]), e["amountField"] as String?, e["description"] as String, aliases))
        }
        return Catalog(specs)
    }

    private fun complete(raw: Any?): (String) -> String = { _ -> if (raw == "THROWS") throw IllegalStateException("llm down") else raw as String }

    private fun reviewer(secret: Any?): Keys.EdKey = Keys.edFromSeed(seed(secret))

    private fun agent(a: Map<String, Any?>): Any? {
        val o = map(a["opts"])
        val principal = Keys.ed25519(Keys.edFromSeed(OracleCases.seed(a["principalSeed"] as String)))
        val holder = a["holderSeed"]?.let { Keys.ed25519(Keys.edFromSeed(OracleCases.seed(it as String))) }
        val r = NlApproval.agentFromApprovedNL(a["draft"], a["approval"], o["reviewers"], principal, a["goal"] as String, catalog(o["extras"]), o["now"], a["aud"] as String?, holder)
        val env = Authorize.readEnvelope(r.agent.grant) ?: throw IllegalStateException("no envelope")
        return linkedMapOf(
            "reviewer" to r.reviewer, "legacy_unbound_instruction" to r.legacyUnboundInstruction,
            "envelope" to linkedMapOf("predicates" to env["predicates"], "caveats" to env["caveats"], "risk_policy" to env["risk_policy"], "agent_binding" to env["agent_binding"]),
        )
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf(
            "NL_APPROVAL_DOMAIN" to NlApproval.NL_APPROVAL_DOMAIN, "NL_APPROVAL_DOMAIN_V2" to NlApproval.NL_APPROVAL_DOMAIN_V2,
            "MAX_NL_OUTPUT_BYTES" to NlApproval.MAX_NL_OUTPUT_BYTES, "MAX_NL_APPROVAL_TTL_MS" to NlApproval.MAX_NL_APPROVAL_TTL_MS,
        )
        "catalogDigest" -> NlApproval.catalogDigest(catalog(a[0]))
        "draftBinding" -> NlApproval.draftBinding(a[0] as String, catalog(arg(a, 1)), arg(a, 2) as String?)
        "draftDigestV2" -> NlApproval.draftDigestV2(a[0], a[1], a[2], a[3])
        "draftDigest" -> NlApproval.draftDigest(a[0], a[1], a[2])
        "policyFromNL" -> NlApproval.policyFromNL(a[0] as String, complete(a[1]), catalog(arg(a, 2)))
        "draftPolicyFromNL" -> NlApproval.draftPolicyFromNL(a[0] as String, complete(a[1]), catalog(arg(a, 2)), arg(a, 3) as String?)
        "approveDraft" -> (arg(a, 2) as Map<String, Any?>?).let { NlApproval.approveDraft(a[0], reviewer(a[1]), it?.get("now"), it?.get("ttlMs")) }
        "approveDraftLegacy" -> (arg(a, 2) as Map<String, Any?>?).let { NlApproval.approveDraftLegacyV1(a[0], reviewer(a[1]), it?.get("now"), it?.get("ttlMs")) }
        "loadApproved" -> map(a[2]).let { NlApproval.loadApprovedPolicy(a[0], a[1], it["reviewers"], catalog(it["extras"]), it["now"]) }
        "agentFromApproved" -> agent(map(a[0]))
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun everyFunction() {
        val fns = setOf(
            "constants", "catalogDigest", "draftBinding", "draftDigestV2", "draftDigest", "policyFromNL", "draftPolicyFromNL", "approveDraft", "approveDraftLegacy", "loadApproved",
            "agentFromApproved",
        )
        var total = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val case = LinkedHashMap(c)
                case["args"] = OracleCases.decNum(c["args"])
                OracleCases.diff(case, c["out"]) { x -> call(fn, x) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(206, total)
    }
}
