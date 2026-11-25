package net.atlasauth.pca.verifier

import net.atlasauth.pca.dataflow.Detectors
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays the reference over the small public surface: the replay guard, the undo ledger stores and state machine, the policy templates and
 * links, the catalog risk, the detector-receipt signal and the agent caveat context.
 */
@Suppress("UNCHECKED_CAST")
class CoreSmallSurfaceDiffTest {
    private val mod = "ref-core-small-surface"

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun list(o: Any?): List<Any?> = o as List<Any?>

    private fun str(o: Any?): String? = o as? String

    private fun keyOf(label: String): Keys.SuiteKey = Keys.ed25519(Keys.edFromSeed(OracleCases.seed(label)))

    // ---- the agent caveat context and the catalog ----

    @Test fun agentCaveatContext() = OracleCases.each(mod, "agentCaveatContext") { a -> Decide.agentCaveatContext(map(a[0])!!, a[1]) }

    @Test fun agentCaveatContextCarriesTheSignedToolBindingUnderTheReferenceName() {
        val r = Decide.agentCaveatContext(linkedMapOf("now" to 5L), linkedMapOf("action" to linkedMapOf("verb" to "v", "params" to linkedMapOf<String, Any?>()), "toolBinding" to "dg"))
        val call = map(r["toolCall"])!!
        assertTrue(call.containsKey("toolSignatureDigest"))
        assertFalse(call.containsKey("tool_signature_digest"))
        // and the tool-schema check reads exactly that member
        val noBinding = Decide.toolCallOf(linkedMapOf("action" to linkedMapOf("verb" to "v")))
        assertFalse(noBinding.containsKey("toolSignatureDigest"))
    }

    @Test fun catalogRisk() {
        OracleCases.each(mod, "catalogReversibilityScore") { _ -> LinkedHashMap<String, Any?>(Catalog.CATALOG_REVERSIBILITY_SCORE) }
        OracleCases.each(mod, "catalogRisk") { a -> Catalog.catalogRisk(str(a[0])!!, map(a[1]), map(a[2])!!, null, IntentJs.num(a[3])) }
    }

    @Test fun detectorSignal() = OracleCases.each(mod, "detectorSignal") { a -> Detectors.detectorSignal(map(a[0])!!) }

    // ---- the replay guard ----

    @Test fun replayGuard() = OracleCases.each(mod, "guardSeq") { a ->
        val o = map(a[0])!!
        val store = Replay.InMemoryReplayStore()
        val out = ArrayList<Any?>()
        for (st in list(a[1])) {
            val s = map(st)!!
            val opts = Replay.GuardOptions(
                aud = str(o["aud"])!!, now = Json.asLong(s["now"]), clockSkewMs = IntentJs.num(o["clockSkewMs"]),
                requireNonce = if (o["requireNonce"] != null) o["requireNonce"] == true else true,
                counters = if (o["counters"] == true) store else null,
            )
            val v = Replay.guardPCActnReplay(store, map(s["p"]), opts)
            val r = linkedMapOf<String, Any?>("ok" to v.ok)
            if (!v.ok) { r["code"] = v.code; r["reason"] = v.reason }
            out.add(r)
        }
        out
    }

    // ---- the undo ledger ----

    @Test fun undoLifecycle() = OracleCases.each(mod, "undoLifecycle") { a ->
        val seed = OracleCases.seed("small/undo/service")
        val signer = Keys.edFromSeed(seed).id()
        val rec = map(a[0])!!
        var cur = Undo.withReceipt(rec, "opened", "", IntentJs.lng(rec["opened_at"]), seed)
        val out = ArrayList<Any?>()
        out.add(cur)
        for (st in list(a[1])) {
            val ev = list(st)[0]
            val now = list(st)[1]
            val t = Undo.transition(cur, ev, now)
            val step = LinkedHashMap<String, Any?>()
            if (t.outcome == "applied") {
                cur = Undo.withReceipt(t.record!!, t.event!!, t.note ?: "", IntentJs.lng(now), seed)
                step["applied"] = map(ev)!!["kind"]
                step["record"] = cur
            } else {
                step[t.outcome] = t.code
            }
            out.add(step)
        }
        out.add(linkedMapOf("chain" to Undo.receiptChainError(cur, signer)))
        out
    }

    @Test fun undoStore() {
        OracleCases.each(mod, "undoStore") { a ->
            val st: UndoStore = if (str(a[0]) == "memory") MemoryUndoStore() else KvUndoStore(MemoryAtomicKv(), true)
            val out = ArrayList<Any?>()
            for (op0 in list(a[1])) {
                val op = list(op0)
                try {
                    when (op[0] as String) {
                        "create" -> {
                            val ex = st.create(map(op[1])!!)
                            val r = linkedMapOf<String, Any?>("created" to (ex == null))
                            if (ex != null) r["record"] = ex
                            out.add(r)
                        }
                        "get" -> out.add(st.get(str(op[1])!!))
                        "replace" -> out.add(st.replace(str(op[1])!!, Json.asLong(op[2]), map(op[3])!!))
                        else -> {
                            val q = map(op[1])!!
                            out.add(st.list(UndoQuery(str(q["state"])!!, q["windowEndedBy"]?.let { Json.asLong(it) }, str(q["grantRef"]), str(q["bondRef"]), q["limit"]?.let { Json.asLong(it).toInt() })))
                        }
                    }
                } catch (e: UndoError) {
                    out.add(linkedMapOf("error" to e.code))
                }
            }
            out
        }
        assertTrue(isUndoStore(MemoryUndoStore()))
        assertFalse(isUndoStore(Any()))
        assertFalse(MemoryUndoStore().durable)
        assertTrue(KvUndoStore(MemoryAtomicKv(), true).durable)
    }

    // ---- policy templates and links ----

    @Test fun policyTemplates() {
        OracleCases.each(mod, "listTemplates") { _ ->
            PolicyTemplates.listTemplates().map { t ->
                val o = linkedMapOf<String, Any?>("name" to t.name, "description" to t.description, "permissions" to t.permissions)
                if (t.limits != null) o["limits"] = t.limits
                if (t.riskPolicy != null) o["riskPolicy"] = t.riskPolicy
                o
            }
        }
        OracleCases.each(mod, "fromTemplate") { a ->
            try {
                val ov = map(a[1])
                val overrides = if (ov == null) null else PolicyTemplates.Overrides(map(ov["permissions"]), map(ov["limits"]), map(ov["riskPolicy"]), null, str(ov["budgetModel"]))
                val h = PolicyTemplates.fromTemplate(str(a[0])!!, keyOf("p"), "g", null, keyOf("h"), 1_700_000_000_000L, overrides)
                linkedMapOf<String, Any?>("ok" to true, "predicates" to h.policy.predicates, "caveats" to h.policy.caveats, "riskPolicy" to h.policy.riskPolicy, "budgetModel" to h.policy.budgetModel)
            } catch (e: IllegalArgumentException) {
                linkedMapOf<String, Any?>("ok" to false)
            }
        }
        OracleCases.each(mod, "policyBuilder") { a ->
            try {
                var b = PolicyTemplates.policy()
                for (op0 in list(a[0])) {
                    val op = list(op0)
                    when (op[0] as String) {
                        "from" -> b = PolicyTemplates.PolicyBuilder.from(str(op[1])!!)
                        "allow" -> b.allow(str(op[1])!!, list(op[2]).map { it as String })
                        "limit" -> b.limit(str(op[1])!!, str(op[2])!!)
                        else -> b.risk(map(op[1])!!)
                    }
                }
                val p = b.build()
                val built = linkedMapOf<String, Any?>("permissions" to p.permissions, "limits" to p.limits)
                if (p.riskPolicy != null) built["riskPolicy"] = p.riskPolicy
                linkedMapOf<String, Any?>("ok" to true, "built" to built)
            } catch (e: IllegalArgumentException) {
                linkedMapOf<String, Any?>("ok" to false)
            } catch (e: IllegalStateException) {
                linkedMapOf<String, Any?>("ok" to false)
            }
        }
        OracleCases.each(mod, "createLink") { a ->
            try {
                linkedMapOf<String, Any?>("ref" to PolicyAuthoring.createLink(map(a[0])!!, map(a[1])!!, a[2] == true), "ok" to true)
            } catch (e: RuntimeException) { // a def or slots argument that is not an object fails to read in the reference too
                linkedMapOf<String, Any?>("ok" to false)
            }
        }
        OracleCases.each(mod, "slotsDigest") { a -> PolicyAuthoring.slotsDigest(a[0]) }
        OracleCases.each(mod, "linkDigest") { a -> PolicyAuthoring.linkDigest(map(a[0])!!) }
        OracleCases.each(mod, "limits") { _ ->
            linkedMapOf<String, Any?>(
                "MAX_SLOTS" to PolicyAuthoring.MAX_SLOTS, "MAX_SLOT_STRING" to PolicyAuthoring.MAX_SLOT_STRING, "MAX_SLOT_SET" to PolicyAuthoring.MAX_SLOT_SET,
                "TEMPLATE_KIND" to PolicyAuthoring.TEMPLATE_KIND, "TIGHTEN_KIND" to PolicyAuthoring.TIGHTEN_KIND,
            )
        }
    }
}
