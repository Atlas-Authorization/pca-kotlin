package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The surface added to match the TypeScript flagship: hash and suite agility, receipts, chain compaction, replay guard, approvals, undo stores and the small helpers. */
@Suppress("UNCHECKED_CAST")
class ParityCloseTest {
    private val now = 1_800_000_000_000L
    private val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))
    private val agentEd = Keys.edFromSeed(ByteArray(32) { 1 })
    private val env = Issue.obj("predicates" to listOf(Issue.obj("verb" to "*")), "caveats" to ArrayList<Any?>(), "risk_policy" to Issue.defaultRiskPolicy())
    private val grant = Issue.mintGrant(principal, agentEd.id(), null, env, "g", "s").grant

    private fun pcactn(counter: Long = 1L, nonce: String? = "n1"): Map<String, Any?> {
        val plan = Issue.commitPlan(listOf(Issue.obj("id" to "n1", "verb" to "read", "resource" to "x", "params_digest" to Pca.paramsDigest(null))))
        return Issue.buildPCActn(Issue.ActSpec(grant = grant, chain = listOf<Any?>(grant), plan = plan, nodeId = "n1", counter = counter, signer = Keys.ed25519(agentEd), aud = "rs", iat = now, ttlMs = 60_000L, nonce = nonce))
    }

    @Test fun hashSuiteAgility() {
        assertEquals("sha256", Pca.DEFAULT_HASH_SUITE)
        assertEquals(32, Pca.HASH_LEN["sha256"])
        assertEquals(48, Pca.HASH_LEN["sha384"])
        assertTrue(Pca.isHashSuite("sha384"))
        assertFalse(Pca.isHashSuite("sha512"))
        assertEquals(32, Pca.hashWithSuite(ByteArray(3)).size)
        assertEquals(48, Pca.hashWithSuite(ByteArray(3), "sha384").size)
        assertEquals(Pca.hashCanonical(listOf(1L)), Pca.hashCanonical(listOf(1L), "sha256"))
        assertEquals(64, Pca.hashCanonical(listOf(1L), "sha384").length)
        assertEquals(43, Pca.b64uLen(32))
        assertTrue(Pca.isCanonicalB64u(Pca.b64(ByteArray(32)), 32))
        assertFalse(Pca.isCanonicalB64u("AB=", -1))
        assertNull(Pca.strictNumberError(1.5))
        assertEquals("negative zero", Pca.strictNumberError(-0.0))
        assertEquals("non-finite number", Pca.strictNumberError(Double.NaN))
        assertEquals(Pca.hashCanonical(Issue.obj("a" to 1L)), Pca.hashCanonical(Issue.obj("a" to 1L), "sha256"))
        assertEquals(Pca.paramsDigest(null), Pca.EMPTY_PARAMS_DIGEST)
    }

    @Test fun receiptsChainAndDetectTampering() {
        val p = pcactn()
        var log: List<Any?> = emptyList()
        log = Receipts.appendReceipt(log, p, true, linkedMapOf("audience" to "pass"))
        log = Receipts.appendReceipt(log, pcactn(2L, "n2"), false)
        assertEquals(true, Receipts.verifyReceiptChain(log)["ok"])
        assertEquals((log[1] as Map<String, Any?>)["hash"], Receipts.receiptHead(log))
        assertEquals("", Receipts.receiptHead(emptyList()))
        val bad = ArrayList(log)
        bad[0] = LinkedHashMap(bad[0] as Map<String, Any?>).also { it["outcome"] = "deny" }
        val v = Receipts.verifyReceiptChain(bad)
        assertEquals(false, v["ok"])
        assertTrue((v["reason"] as String).startsWith("hash mismatch"))
    }

    @Test fun chainCompactionRoundTripsThroughTheMemo() {
        val chain = listOf<Any?>(grant)
        val root = ChainCompact.hopsRoot(chain)
        assertEquals(43, root.length)
        val memo = ChainCompact.Memo()
        val compact = memo.rememberVerified(chain, principal.id()!!, now.toDouble())
        assertEquals(root, compact["hops_root"])
        assertNull(ChainCompact.compactChainShapeError(compact))
        val r = memo.resolve(compact, now.toDouble())
        assertTrue(r.ok)
        assertEquals(1, r.view!!.n())
        assertFalse(memo.resolve(compact, now + 2 * 3_600_000.0).ok) // the memo entry expired
        assertFalse(ChainCompact.Memo().resolve(compact, now.toDouble()).ok) // another verifier never saw the chain
        assertEquals("not an object", ChainCompact.compactChainShapeError("x"))
    }

    @Test fun replayGuardConsumesANonceOnce() {
        val store = Replay.InMemoryReplayStore()
        val p = pcactn()
        val opts = Replay.GuardOptions("rs", now, counters = store)
        assertTrue(Replay.guardPCActnReplay(store, p, opts).ok)
        val again = Replay.guardPCActnReplay(store, p, opts)
        assertFalse(again.ok)
        assertEquals("replay", again.code)
        val other = Replay.guardPCActnReplay(store, pcactn(2L, "n2"), Replay.GuardOptions("other", now))
        assertEquals("audience", other.code)
        assertEquals("malformed", Replay.guardPCActnReplay(store, pcactn(3L, null), opts).code) // a nonce is required
        assertEquals("expired", Replay.guardPCActnReplay(store, p, Replay.GuardOptions("rs", now + 3_600_000L)).code)
        assertEquals(Pca.MAX_LIFETIME_MS + 2 * Pca.MAX_SKEW_MS, Replay.REPLAY_MIN_RETENTION_MS)
    }

    @Test fun cheapClaimsRefuseBeforeAnySignatureWork() {
        val p = pcactn()
        assertNull(Pca.pcactnCheapClaims(p, "rs", now.toDouble()))
        assertEquals("audience", Pca.pcactnCheapClaims(p, "x", now.toDouble())!!.check)
        assertEquals("the PCActn has expired", Pca.pcactnCheapClaims(p, "rs", (now + 3_600_000L).toDouble())!!.reason)
        assertEquals("iat is in the future (clock skew)", Pca.pcactnCheapClaims(p, "rs", (now - 120_000L).toDouble())!!.reason)
    }

    @Test fun cheapChainChecksTheEd25519HalfAndTheLinks() {
        assertTrue(Pca.verifyChainCheap(listOf<Any?>(grant), principal.id()).ok)
        assertEquals("hop 0: root issuer is not the expected principal", Pca.verifyChainCheap(listOf<Any?>(grant), "someone-else").reason)
        assertEquals("empty chain", Pca.verifyChainCheap(emptyList()).reason)
        val forged = LinkedHashMap(grant).also { it["sig"] = Pca.b64(ByteArray(64)) }
        assertFalse(Pca.verifyChainCheap(listOf<Any?>(forged)).ok)
    }

    @Test fun approvalsStandingClassAndCosign() {
        val a = Approvals.approveClass(listOf("stripe.refund"), 3_600_000.0, "alice", now.toDouble(), "order/*")
        assertTrue(Approvals.classApprovalCovers(a, "stripe.refund", "order/7", now.toDouble() + 1))
        assertFalse(Approvals.classApprovalCovers(a, "stripe.refund", "invoice/7", now.toDouble() + 1))
        assertFalse(Approvals.classApprovalCovers(a, "stripe.charge", "order/7", now.toDouble() + 1))
        assertFalse(Approvals.classApprovalCovers(a, "stripe.refund", "order/7", now.toDouble() + 3_600_000.0))
        assertTrue(Approvals.coveredByAny(listOf(a), "stripe.refund", "order/1", now.toDouble()))
        val b = Approvals.applyCosign(linkedMapOf("B" to 1L, "tau" to 0L), linkedMapOf("rho" to 2L, "bMax" to 5L), 10.0)
        assertEquals(3L, (b["B"] as Number).toLong())
        val full = Approvals.applyCosign(linkedMapOf("B" to 1L, "tau" to 0L), linkedMapOf("rho" to 2L, "bMax" to 5L), 10.0, true)
        assertEquals(5L, (full["B"] as Number).toLong())
        assertEquals("[]", Json.canonicalize(Approvals.pendingRequests(listOf(linkedMapOf("kind" to "auto")))))
    }

    @Test fun reviewActionAutoAdmitsAndStepsUp() {
        val h = Agent.fromPrincipal(Facade.AgentOptions(principal, "refund order 1", Issue.obj("stripe" to listOf("refund")), limits = Issue.obj("refund" to "\$500/day"), holder = Keys.ed25519(agentEd), aud = "rs", now = now, goalSalt = "s"))
        val out = Approvals.reviewAction(h, "stripe.charge", "charge:c1", Issue.obj("amount" to 5L))
        assertEquals("deny", out["kind"])
        val ok = Approvals.reviewAction(h, "stripe.refund", "charge:c1", Issue.obj("amount" to 5L), Approvals.ReviewOptions(now = now))
        assertTrue(ok["kind"] == "auto" || ok["kind"] == "deny" || ok["kind"] == "step_up")
        val lineage = Approvals.buildGoalLineage(h, "stripe.refund", "charge:c1", Issue.obj("amount" to 5L), "refund order 1")
        assertEquals(true, lineage["goalVerified"])
        assertEquals(3, (lineage["chain"] as List<*>).size)
        assertEquals(3, Approvals.describeGoalLineage(lineage).size)
        assertEquals(false, Approvals.buildGoalLineage(h, "stripe.refund", "charge:c1", null, "something else")["goalVerified"])
    }

    @Test fun undoStoresKeepOneRecordPerIdAndGuardTheVersion() {
        val rec = linkedMapOf<String, Any?>("v" to 1L, "id" to "op1", "state" to "open", "ver" to 1L, "receipts" to ArrayList<Any?>(), "window_end" to 10L, "grant_ref" to "g1")
        for (store in listOf<UndoStore>(MemoryUndoStore(), KvUndoStore(MemoryAtomicKv(), false))) {
            assertNull(store.create(rec))
            assertNotNull(store.create(rec))
            assertFalse(store.replace("op1", 9L, LinkedHashMap(rec)))
            assertTrue(store.replace("op1", 1L, LinkedHashMap(rec).also { it["ver"] = 2L; it["state"] = "vetoed" }))
            assertEquals(1, store.list(UndoQuery("vetoed", grantRef = "g1")).size)
            assertEquals(0, store.list(UndoQuery("open")).size)
            assertEquals("op1", store.get("op1")!!["id"])
            try { store.replace("op1", 2L, LinkedHashMap(rec).also { it["id"] = "other" }); fail("the id cannot change") } catch (e: UndoError) { assertEquals("invalid", e.code) }
        }
        assertTrue(isUndoStore(MemoryUndoStore()))
        assertFalse(MemoryUndoStore().durable)
        assertEquals("ab", Undo.clipUnits("abc", 2))
        assertEquals("a", Undo.clipUnits("a😀", 2)) // never splits a surrogate pair
    }

    @Test fun discoveryAndAdapterHelpers() {
        val doc = Discovery.parseDiscoveryDocument(Json.parse("{\"audience\":\"rs\",\"pca_versions\":[2],\"signature_suites\":[\"ed25519\"],\"action_header\":\"PCA-Action\",\"intent\":{\"versions\":[1,2],\"tiers\":{\"read\":0}}}"))
        assertTrue(Discovery.acceptsSuite(doc, "ed25519"))
        assertFalse(Discovery.acceptsSuite(doc, "ml-dsa-65"))
        try { Discovery.parseDiscoveryDocument(Json.parse("{\"audience\":\"\"}")); fail("an empty audience is malformed") } catch (e: IllegalArgumentException) { assertTrue(e.message!!.contains("audience")) }
        try { Discovery.parseDiscoveryIntent(Json.parse("{\"versions\":[3]}")); fail("an unknown intent version is malformed") } catch (e: IllegalArgumentException) { assertTrue(e.message!!.contains("versions")) }
        val enc = Issue.header(pcactn())
        assertEquals(Issue.encode(pcactn()), Adapters.decodePcaHeader(enc))
        try { Adapters.decodePcaHeader("$enc="); fail("padding is refused") } catch (e: Adapters.PcaHeaderError) { assertEquals("invalid_pca_header", e.code) }
        assertNotNull(Adapters.defaultExtract(linkedMapOf("PCA-ACTION" to enc)))
        assertNull(Adapters.defaultExtract(linkedMapOf<String, String>()))
        assertEquals("deny", Adapters.decisionOfResult(false))
        assertEquals("escalate", Adapters.decisionOfResult(false, "escalate"))
        assertEquals(emptyMap<String, String>(), Adapters.provenanceHeaders(null))
        val segs = Adapters.messageSegments(linkedMapOf("role" to "user", "content" to "hello"))
        assertEquals("principal", segs[0].origin)
        assertEquals(0, Adapters.messageSegments(linkedMapOf("role" to "assistant", "content" to "x")).size)
        assertEquals("tool", Adapters.messageSegments(linkedMapOf("role" to "tool", "name" to "t", "content" to "out"))[0].origin)
    }

    @Test fun layersDecideCeilingsBeforeTasks() {
        val any = linkedMapOf<String, Any?>("predicates" to listOf(Issue.obj("verb" to "*")))
        val none = linkedMapOf<String, Any?>("predicates" to ArrayList<Any?>())
        val ctx = Issue.obj("action" to Issue.obj("verb" to "read", "resource" to "x", "params" to LinkedHashMap<String, Any?>()))
        assertEquals("admit", LayerDecide.decideLayers(linkedMapOf("org" to any, "task" to listOf(any)), ctx).decision)
        assertEquals("site", LayerDecide.decideLayers(linkedMapOf("org" to any, "site" to none, "task" to listOf(any)), ctx).layer)
        assertEquals("intent_required", LayerDecide.decideLayers(linkedMapOf("task" to listOf(none)), ctx).decision)
        assertEquals("intent_denied", LayerDecide.decideLayers(linkedMapOf("task" to listOf(any), "denied" to listOf(any)), ctx).decision)
        assertEquals("intent_denied", LayerDecide.decideLayers(linkedMapOf("task" to "x"), ctx).decision)
        assertEquals("ceiling", LayerDecide.decideLayers(linkedMapOf("org" to null, "task" to listOf(any)), ctx).decision)
    }

    @Test fun smallHelpers() {
        assertEquals("deny", PcaDecision.meetAll(listOf("allow", "deny", "escalate")))
        assertEquals("allow", PcaDecision.meetAll(emptyList()))
        assertTrue(Pca.isBudgetAllocCaveat(linkedMapOf("type" to "budget_alloc", "limit" to 3L)))
        assertFalse(Pca.isBudgetAllocCaveat(linkedMapOf("type" to "budget_alloc", "limit" to -1L)))
        val b = Risk.subBudget(Risk.Budget(10.0, 1.0), 4.0)
        assertTrue(b.ok)
        assertFalse(Risk.subBudget(Risk.Budget(10.0, 1.0), 11.0).ok)
        val c = Risk.debitConsolidated(Risk.Budget(10.0, 1.0), b.sub!!, 5.0)
        assertFalse(c.ok)
        assertEquals("sub-agent budget insufficient", c.reason)
        assertEquals(5.0, Risk.debitConsolidatedPath(listOf(Risk.Budget(10.0, 1.0), Risk.Budget(6.0, 1.0)), 1.0).nodes!![1].B, 0.0)
        assertEquals(2.0, Risk.recharge(Risk.Budget(1.0, 0.0), 1.0, 2.0, 5.0).B, 0.0)
        assertEquals(1, Revocation.classRank("rate_limited"))
        assertEquals(1L, Authorize.amountRisk(grant, Issue.obj("amount" to 1000000000L))!!.let { (it["blastRadius"] as Number).toLong() })
        assertTrue(Authorize.EXECUTION_REQUIRED_CHECKS.containsAll(Authorize.STATEFUL_REQUIRED_CHECKS))
        val e = Authorize.enforceRequired(true, linkedMapOf("replay" to "pass", "audience" to "not-enforced"), emptyList(), listOf("replay", "audience", "validity"))
        assertFalse(e.allow)
        assertEquals("fail", e.checks["validity"])
        assertEquals(2, e.reasons.size)
        assertEquals(0.4, Catalog.CATALOG_REVERSIBILITY_SCORE["rate_limited"]!!, 0.0)
        assertEquals(Pca.EMPTY_PARAMS_DIGEST.length, 43)
        assertEquals(1, Pca.planNodeLeaf(Issue.obj("id" to "a", "verb" to "v", "resource" to "r")).let { if (it["reversibility_class"] == "reversible") 1 else 0 })
        assertEquals(1280, Pq.FN_DSA_1024_SIGNATURE_BYTES)
        assertEquals(4627, Pq.ML_DSA_87_SIGNATURE_BYTES)
    }

    @Test fun regexRequestBudgetBoundsADocument() {
        val request = SafeRegex.RegexBudget.request()
        assertTrue(request.charge("a+", 3))
        assertEquals(1, request.evaluations)
        var allowed = 0
        request.run { for (i in 0 until 400) if (SafeRegex.charge("a+", 3)) allowed++ }
        assertTrue(allowed <= 4 * SafeRegex.MAX_REGEX_EVALUATIONS_PER_DOCUMENT)
        assertTrue(SafeRegex.cacheHas("a+"))
        assertEquals(512, SafeRegex.REGEX_CACHE_MAX_ENTRIES)
    }
}
