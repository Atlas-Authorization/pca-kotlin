package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Action-kit conformance: every vector of the shared action-kit corpus (the `conformance/actions` directory; `packages/pca-conformance/vectors/actions`
 * in the monorepo) must reproduce its `expect` exactly through [Actions] (and the v2 conform path of [ActionSchema]). No skips, no vector unread.
 */
@Suppress("UNCHECKED_CAST")
class ActionVectorsTest {
    private fun cases(): List<Map<String, Any?>> =
        ParityVectors.actionsDir().listFiles { f -> f.name.endsWith(".json") }!!.sortedBy { it.name }
            .map { Json.parseLenient(it.readText(Charsets.UTF_8)) as Map<String, Any?> }

    private fun codeOf(e: String?): Map<String, Any?> =
        if (e == null) linkedMapOf("ok" to true) else linkedMapOf("ok" to false, "code" to e.split(":")[0].split(" ")[0])

    private fun replay(c: Map<String, Any?>): Any? {
        val i = c["input"] as Map<String, Any?>
        return when (val k = c["kind"]) {
            "parse" -> linkedMapOf("ok" to (Actions.validateDef(i["def"]) == null))
            "digest" -> linkedMapOf("digest" to Actions.defDigest(i["def"] as Map<String, Any?>), "normalized" to Actions.normalize(i["def"] as Map<String, Any?>))
            "effective" -> {
                val e = Actions.effective(i["def"] as Map<String, Any?>, Actions.CORE_REGISTRY, i["pins"])
                linkedMapOf("confirmed" to e["confirmed"], "traits" to e["traits"], "closure" to e["closure"], "eff" to e["eff"])
            }
            "expand", "schema_verb" -> try {
                val reg = if (i["custom_traits"] != null) Actions.extendRegistry(Actions.CORE_REGISTRY, i["custom_traits"]) else Actions.CORE_REGISTRY
                if (k == "expand") linkedMapOf("closure" to Actions.closure(reg, i["traits"] as List<Any?>), "floor" to Actions.floorOf(reg, i["traits"] as List<Any?>))
                else codeOf(Actions.schemaVerbFloorError(i["verb"] as Map<String, Any?>, reg, i["pins"]))
            } catch (e: ActionKitError) {
                linkedMapOf("error" to true)
            }
            "floor" -> linkedMapOf("decision" to Actions.floorDecision(i["grant"] as Map<String, Any?>, i["call"] as Map<String, Any?>, i["profile"] as Map<String, Any?>))
            "conform" -> {
                val r = ActionSchema.conform(i["schema"], i["verb"] as String, i["params"])
                if (r.ok) linkedMapOf("ok" to true) else linkedMapOf("ok" to false, "code" to r.code)
            }
            "pack" -> {
                val ds = (i["digests"] as List<Any?>).map { it as String }
                linkedMapOf("root" to Actions.packRoot(ds), "proof" to Actions.packProof(ds, ds[(i["index"] as Json.Num).raw.toInt()]))
            }
            "rule22_schema" -> ActionsRegistry.rule22Integrity(i["doc"], i["pins"])
            "rule22" -> {
                val g = ActionsRegistry.rule22Integrity(i["doc"], i["pins"])
                if (g["ok"] != true) linkedMapOf("integrity" to g["code"], "decision" to "deny")
                else linkedMapOf("integrity" to "ok", "decision" to ActionsRegistry.rule22Decide(i["doc"], i["verb"] as String, i["grant"] as Map<String, Any?>, i["context"] as List<Any?>))
            }
            "schema_shape" -> linkedMapOf("ok" to (ActionSchema.shapeError(i["doc"], signed = false) == null))
            "pack_verify" -> {
                val v = ActionsRegistry.verifyPack(i["pack"], i["keys"], i["shards"] as Map<String, Any?>?)
                if (v["ok"] == true) linkedMapOf("ok" to true, "digest" to v["digest"], "defs" to (v["defs"] as List<*>).size) else linkedMapOf("ok" to false)
            }
            "evolution_verify" -> linkedMapOf(
                "ok" to (ActionsRegistry.verifyEvolutionRecord(i["record"], i["keys"]) == null),
                "diff" to try { ActionsRegistry.evolutionDiffDigest(i["record"] as Map<String, Any?>) } catch (e: RuntimeException) { null },
            )
            "reapproval_verify" -> {
                val g = i["grant"] as Map<String, Any?>
                linkedMapOf("ok" to ActionsRegistry.reapprovalValid(i["reapproval"], g["id"], g["issuer"], i["verb"], i["diff"]))
            }
            "pin" -> {
                val d = ActionsRegistry.decidePin(i)
                if (d["ok"] == true) linkedMapOf("ok" to true, "via" to d["via"])
                else linkedMapOf<String, Any?>("ok" to false, "code" to d["code"], "escalate" to d["escalate"]).also { if (d.containsKey("needs_reapproval")) it["needs_reapproval"] = d["needs_reapproval"] }
            }
            "pack_proof_verify" -> linkedMapOf("ok" to ActionsRegistry.verifyPackProof(i["root"], i["proof"], i["digest"]))
            "tracker" -> {
                val t = ActionsRegistry.PackTracker(i["keys"])
                (i["steps"] as List<Map<String, Any?>>).map { st ->
                    val r = t.accept(st["pack"], st["shards"] as Map<String, Any?>?)
                    if (r["ok"] == true) linkedMapOf("ok" to true, "status" to r["status"]) else linkedMapOf("ok" to false, "code" to r["code"])
                }
            }
            "approval_render" -> try {
                val r = Approval.render(i["def"] as Map<String, Any?>, i["params"], i["confirmed"] == true)
                val d = Approval.renderDigest(r)
                linkedMapOf("ok" to true, "render" to r, "digest" to d, "words" to Approval.bindingWords(d))
            } catch (e: ActionKitError) {
                linkedMapOf("ok" to false, "code" to e.code)
            }
            "approval_digest" ->
                if (Approval.renderShapeError(i["render"]) != null) linkedMapOf("ok" to false) else linkedMapOf("ok" to true, "digest" to Approval.renderDigest(i["render"]))
            "approval_challenge" -> try {
                linkedMapOf("ok" to true, "challenge" to Approval.challenge(i["action_digest"], i["render_digest"]))
            } catch (e: IllegalArgumentException) {
                linkedMapOf("ok" to false)
            }
            "approval_escalation" -> {
                val b = i["bind"] as Map<String, Any?>
                val pins = (i["principals"] as List<Any?>).map { Escalation.Principal(it as String) }
                val v = Escalation.verifyAnswer(i["answer"], pins, Escalation.Binding(b["policy_digest"] as String, b["action_digest"] as String, b["history_head"] as String, b["render_digest"] as String?), IntentJs.lng(i["now"]))
                if (v.ok) linkedMapOf("ok" to true, "decision" to v.decision) else linkedMapOf("ok" to false, "reason" to v.reason)
            }
            else -> throw AssertionError("unknown vector kind $k")
        }
    }

    // lenient canonical form: key order and number spelling (Num vs Int) do not matter, everything else does
    private fun same(a: Any?, b: Any?): Boolean = Json.canonicalize(a) == Json.canonicalize(b)

    private fun replayProfile(c: Map<String, Any?>): Any? {
        val i = c["input"] as Map<String, Any?>
        return try {
            when (val k = c["kind"]) {
                "approval_psd2" -> linkedMapOf("ok" to true, "linking" to Approval.psd2Linking(i["render"] as Map<String, Any?>))
                "approval_batch" -> {
                    val b = Approval.batch(i["items"] as List<Any?>)
                    linkedMapOf("ok" to true, "batch" to b["batch"], "action_digest" to b["action_digest"], "render_digest" to b["render_digest"], "challenge" to b["challenge"], "words" to b["words"])
                }
                else -> throw AssertionError("unknown approval profile vector kind $k")
            }
        } catch (e: ActionKitError) {
            linkedMapOf("ok" to false, "code" to e.code)
        }
    }

    @Test
    fun approvalProfileVectorsReplay() {
        val dir = ParityVectors.approvalProfilesDir()
        val files = dir.listFiles { f -> f.name.endsWith(".json") }!!.sortedBy { it.name }
        assertTrue("approval profile vectors ${files.size}", files.size >= 12)
        for (f in files) {
            val c = Json.parseLenient(f.readText(Charsets.UTF_8)) as Map<String, Any?>
            assertTrue("${c["id"]}: want ${Json.canonicalize(c["expect"])} got ${Json.canonicalize(replayProfile(c))}", same(replayProfile(c), c["expect"]))
        }
    }

    @Test fun everyVectorReplays() {
        val cs = cases()
        assertTrue("only ${cs.size} action vectors", cs.size >= 781)
        val kinds = HashMap<String, Int>()
        val bad = ArrayList<String>()
        for (c in cs) {
            kinds.merge(c["kind"] as String, 1, Int::plus)
            val got = replay(c)
            if (!same(got, c["expect"])) bad.add("${c["id"]}: want ${Json.canonicalize(c["expect"])} got ${Json.canonicalize(got)}")
        }
        assertEquals("${bad.size}/${cs.size} mismatches:\n" + bad.take(40).joinToString("\n"), 0, bad.size)
        for (k in listOf("parse", "digest", "effective", "expand", "floor", "conform", "pack", "schema_verb", "schema_shape", "rule22", "rule22_schema", "pack_verify", "evolution_verify", "reapproval_verify", "pin", "pack_proof_verify", "tracker", "approval_render", "approval_digest", "approval_challenge", "approval_escalation")) assertTrue("kind $k has only ${kinds[k]}", (kinds[k] ?: 0) >= 8)
    }

    @Test fun pinnedDigests() {
        assertEquals("W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM", Actions.traitsDigest(Actions.CORE_REGISTRY))
        assertEquals("I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU", Actions.tablesDigest())
        assertEquals(22, Actions.CORE_REGISTRY.size)
    }

    @Test fun packProofVerifiesAndTamperFails() {
        val c = cases().first { it["id"] == "pack-builtin" }
        val ds = ((c["input"] as Map<String, Any?>)["digests"] as List<Any?>).map { it as String }
        val root = (c["expect"] as Map<String, Any?>)["root"] as String
        for (d in ds) assertTrue(Actions.verifyPackProof(root, Actions.packProof(ds, d), d))
        assertFalse(Actions.verifyPackProof(root, Actions.packProof(ds, ds[0]), ds[1]))
        assertFalse(Actions.verifyPackProof(root, null, ds[0]))
    }

    @Test fun duplicateAndEmptyPacksAreRefused() {
        for (ds in listOf(listOf("a", "a"), listOf<String>())) {
            try { Actions.packRoot(ds); throw AssertionError("accepted") } catch (e: ActionKitError) { assertTrue(e.code == "duplicate_def" || e.code == "empty_pack") }
        }
    }

    @Test fun wholeDocumentRule22() {
        val c = cases().first { it["id"] == "schema-verb-adv-honest" }
        val doc = linkedMapOf<String, Any?>("verbs" to listOf((c["input"] as Map<String, Any?>)["verb"]))
        assertNull(Actions.schemaFloorError(doc))
        doc["traits_digest"] = "A".repeat(43)
        assertTrue(Actions.schemaFloorError(doc)!!.startsWith("traits_digest_mismatch"))
    }

    // Differential oracle for expand / floor: an independent set-comprehension model of the closure (eight rounds of one-step implication,
    // the model the verified algebra reasons about) against the production DFS closure, over every subset size-2 of the core traits.
    @Test fun closureEqualsEightRoundsOfOneStepImplication() {
        val reg = Actions.CORE_REGISTRY
        val ids = reg.keys.sorted()
        fun model(start: Set<String>): List<String> {
            var s = start
            repeat(8) { s = s + s.flatMap { (reg[it]!!["implies"] as List<*>).map { u -> u as String } } }
            return s.sorted()
        }
        for (a in ids) for (b in ids) {
            assertEquals(model(setOf(a, b)), Actions.closure(reg, listOf(a, b)))
            val f = Actions.floorOf(reg, listOf(a, b))
            assertTrue(Actions.leq(reg[a]!!["floor"] as Map<String, Any?>, f) && Actions.leq(reg[b]!!["floor"] as Map<String, Any?>, f))
        }
    }

    @Test fun floorDecisionIsAntitoneInTheProfile() {
        val reg = Actions.CORE_REGISTRY
        val g = linkedMapOf<String, Any?>("caveats" to listOf("amount_cap", "count_cap", "window"), "max_esc" to 3, "preauth_esc" to 2)
        val call = linkedMapOf<String, Any?>("context" to listOf("idempotency"))
        val rank = mapOf("deny" to 0, "escalate" to 1, "allow" to 2)
        val ids = reg.keys.sorted()
        for (a in ids) for (b in ids) {
            val lo = reg[a]!!["floor"] as Map<String, Any?>
            val hi = Actions.join(lo, reg[b]!!["floor"] as Map<String, Any?>)
            assertTrue(rank[Actions.floorDecision(g, call, hi)]!! <= rank[Actions.floorDecision(g, call, lo)]!!)
        }
    }
}
