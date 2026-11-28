package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The policy layer (`policy-vectors.json`, `policy_decision`): EVERY vector reproduced, none skipped. `expect.caveats` is the agent-native
 * evaluation of the grant's caveats minus its envelope plus the hop-appended ones; `expect.decision` is the whole policy decision (reason
 * codes in order, and the failed caveat types per placement) with the risk inputs and the trust budget held neutral.
 */
@Suppress("UNCHECKED_CAST")
class PolicyVectorsTest {
    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>

    @Test fun everyVectorReproducesTheReference() {
        val vs = l(ParityVectors.load("policy-vectors.json")["policy_decision"])
        assertTrue("vectors: ${vs.size}", vs.size >= 413)
        for (x in vs) {
            val v = m(x)
            val name = v["name"] as String
            val grant = m(v["grant"])
            val chain = (v["chain"] as? List<Any?>) ?: emptyList()
            val ctx = m(v["context"])
            val act = m(ctx["action"])
            val actionCtx = linkedMapOf<String, Any?>("action" to linkedMapOf("verb" to act["verb"], "resource" to act["resource"], "params" to act["params"]))
            val toolCall = linkedMapOf("tool" to act["verb"], "args" to act["params"])

            // the delegated caveats: what the leaf hop appended beyond the grant's own
            val grantCaveats = (grant["caveats"] as? List<Any?>) ?: emptyList()
            var extra: List<Any?> = emptyList()
            if (chain.isNotEmpty() && chain.last() is Map<*, *>) {
                val leaf = (m(chain.last())["caveats"] as? List<Any?>) ?: emptyList()
                if (leaf.size > grantCaveats.size) extra = ArrayList(leaf.subList(grantCaveats.size, leaf.size))
            }
            val cctx = linkedMapOf<String, Any?>(
                "now" to ctx["now"], "action" to actionCtx["action"], "delegation_depth" to (if (chain.isEmpty()) 0L else (chain.size - 1).toLong()),
            )
            for (k in listOf("blast_radius", "reversibility_class", "recent_action_times")) if (ctx[k] != null) cctx[k] = ctx[k]

            // expect.caveats: the root caveats outside the envelope, then the hop-appended ones
            val policyCaveats = ArrayList(l(Authorize.rootCaveats(grant)))
            policyCaveats.addAll(extra)
            val cv = Authorize.evaluateAgentCaveats(policyCaveats, cctx, actionCtx, toolCall)
            val wantCv = m(m(v["expect"])["caveats"])
            assertEquals("$name: caveats allow", wantCv["allow"], cv.ok)
            assertEquals("$name: caveats failed", l(wantCv["failed"]), cv.failed)

            // expect.decision
            val reasons = ArrayList<String>()
            val failed = linkedMapOf<String, MutableList<String>>("envelope" to ArrayList(), "root" to ArrayList(), "delegated" to ArrayList())
            val env = Authorize.readEnvelope(grant)
            if (env == null) reasons.add("envelope_missing")
            else {
                if (Predicates.denialReason(env["predicates"], actionCtx) != null) reasons.add("predicates_unsatisfied")
                if (chain.isEmpty()) reasons.add("chain_malformed")
                val ecv = Authorize.evaluateAgentCaveats(env["caveats"], cctx, actionCtx, toolCall)
                if (!ecv.ok) { reasons.add("envelope_caveats_unsatisfied"); failed["envelope"]!!.addAll(ecv.failed) }
                val rcv = Authorize.evaluateAgentCaveats(Authorize.rootCaveats(grant), cctx, actionCtx, toolCall)
                if (!rcv.ok) { reasons.add("root_caveats_unsatisfied"); failed["root"]!!.addAll(rcv.failed) }
                val dcv = Authorize.evaluateAgentCaveats(extra, cctx, actionCtx, toolCall)
                if (!dcv.ok) { reasons.add("delegated_caveats_unsatisfied"); failed["delegated"]!!.addAll(dcv.failed) }
            }
            val want = m(m(v["expect"])["decision"])
            assertEquals("$name: decision allow", want["allow"], reasons.isEmpty())
            assertEquals("$name: reasons", l(want["reasons"]), reasons)
            val wf = m(want["failed"])
            for (k in listOf("envelope", "root", "delegated")) assertEquals("$name: failed.$k", l(wf[k]), failed[k])
        }
    }
}
