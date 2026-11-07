package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Deadline tests (BRIEF-deadline): Pca, Issue, Actions, ActionSchema, Caveats, Undo, ArgProvenance, Approval, Sigstore loops. */
class Kill06DeadlineAPcaCoreTest {
    private fun <T> dl(ms: Long = Deadline.DEFAULT_MS, b: () -> T): T = Deadline.within(ms) { b() }
    private fun m(vararg kv: Pair<String, Any?>) = Issue.obj(*kv)

    @Test fun shaAndConcat() = dl {
        assertEquals("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", Pca.b64(Pca.sha("abc".toByteArray())))
        assertEquals(Pca.b64(Pca.sha("abc".toByteArray())), Pca.b64(Pca.sha("a".toByteArray(), "b".toByteArray(), "c".toByteArray())))
        assertArrayEquals("abcde".toByteArray(), Pca.concat("a".toByteArray(), "bc".toByteArray(), "".toByteArray(), "de".toByteArray()))
        assertArrayEquals(ByteArray(0), Pca.concat())
    }

    @Test fun issueObjKeepsOrder() = dl {
        val o = Issue.obj("z" to 1, "a" to 2, "m" to 3, "b" to null)
        assertEquals(listOf("z", "a", "m", "b"), o.keys.toList())
        assertEquals(2, o["a"])
    }

    @Test fun pathShapes() = dl {
        assertEquals(listOf("R", "R", "R"), Pca.pathShape(0, 5))
        assertEquals(listOf("L"), Pca.pathShape(4, 5))
        assertEquals(listOf("L", "R"), Pca.pathShape(1, 3))
        assertEquals(listOf("L"), Pca.pathShape(2, 3))
        assertEquals(listOf("L", "L"), Pca.pathShape(5, 6))
        assertEquals(listOf("L", "L"), Pca.pathShape(6, 7))
        assertEquals(listOf("R", "L", "R"), Pca.pathShape(2, 7))
        assertEquals(emptyList<String>(), Pca.pathShape(0, 1))
        assertEquals(listOf("R"), Pca.pathShape(0, 2))
        assertEquals(listOf("R", "R", "R", "R"), Pca.pathShape(0, 9))
        assertEquals(listOf("L"), Pca.pathShape(8, 9))
    }

    @Test fun planMerkleEverySize() = dl {
        for (n in 1..9) {
            val nodes = (0 until n).map { m("id" to "n$it", "verb" to "v$it", "resource" to "r$it") }
            val plan = Issue.commitPlan(nodes)
            val leaves = nodes.map { Pca.planLeaf(it["id"], it, Pca.conditionsDigest(it["pre"], it["post"])) }
            assertEquals("n=$n", Pca.merkleRoot(leaves), plan.root)
            for (i in 0 until n) {
                val proof = plan.proofFor("n$i")
                assertEquals(i.toLong(), proof["index"])
                assertEquals(n.toLong(), proof["size"])
                assertTrue("n=$n i=$i", Pca.verifyInclusion(plan.root, proof, leaves[i]))
                assertFalse(Pca.verifyInclusion(plan.root, proof, leaves[(i + 1) % n].let { if (n == 1) m("x" to 1) else it }))
            }
        }
    }

    @Test fun coreVectorsVerifyAsPinned() = dl(15_000) {
        @Suppress("UNCHECKED_CAST") val vs = SnapshotTest.core["vectors"] as List<Map<String, Any?>>
        var done = 0
        for (v in vs) {
            val txt = v.toString()
            if (txt.contains("ml-dsa") || txt.contains("slh-dsa") || txt.contains("hybrid")) continue
            @Suppress("UNCHECKED_CAST") val exp = v["expect"] as Map<String, Any?>
            val g = ReasonSnapshot.verify(v)
            assertEquals(v["name"].toString(), exp["allow"], g.allow)
            if (++done >= 30) break
        }
        assertTrue(done > 5)
        for (name in listOf("valid-raw-json-format-insensitive", "delegated-2-hop-chain")) {
            val v = KUtil.vec(name)
            @Suppress("UNCHECKED_CAST") assertEquals(name, (v["expect"] as Map<String, Any?>)["allow"], ReasonSnapshot.verify(v).allow)
        }
        assertNull(Pca.validateWireV2(KUtil.valid()))
        assertTrue(Pca.verifyPcactn(KUtil.valid(), KUtil.validGrant(), KUtil.NOW, KUtil.Of).allow)
    }

    @Test fun allocationChainMonotone() = dl {
        val root = Keys.ed25519(Keys.edGenerate())
        val agent = Keys.ed25519(Keys.edGenerate())
        fun alloc(l: Any?) = m("type" to "budget_alloc", "limit" to l)
        fun chain(parent: List<Any?>, added: List<Any?>): String {
            val r = Issue.mintRoot(root, agent.id()!!, null, parent)
            return Pca.verifyChain(listOf(r, Issue.attenuate(r, added, agent)), root.id()!!, true, null)
        }
        assertEquals("", chain(listOf(alloc(10L), m("type" to "ttl"), alloc(8L)), listOf(alloc(5L), alloc(5L), alloc(0L))))
        assertTrue(chain(listOf(alloc(10L)), listOf(alloc(11L))).startsWith("budget_alloc caveat 1"))
    }

    @Test fun actionsClosureCyclesAndPack() = dl {
        fun t(vararg implies: String) = mapOf<String, Any?>("implies" to implies.toList(), "floor" to emptyMap<String, Any?>())
        val reg = mapOf("a" to t("b"), "b" to t("c", "a"), "c" to t(), "d" to t("d"))
        assertEquals(listOf("a", "b", "c"), Actions.closure(reg, listOf("a")))
        assertEquals(listOf("a", "b", "c"), Actions.closure(reg, listOf("c", "b", "a", "a")))
        assertEquals(listOf("c"), Actions.closure(reg, listOf("c", "c")))
        assertEquals(listOf("d"), Actions.closure(reg, listOf("d")))
        assertEquals(listOf("a", "b", "c", "d"), Actions.closure(reg, listOf("d", "a")))
        try { Actions.closure(reg, listOf("zz")); throw AssertionError("must refuse an unknown trait") } catch (e: ActionKitError) { assertEquals("unknown_trait", e.code) }

        for (n in 1..9) {
            val ds = (0 until n).map { "dig${it}x" }
            val root = Actions.packRoot(ds)
            assertEquals(Pca.merkleRoot(ds.sorted().map { Actions.leaf(it) }), root)
            for (d in ds) {
                val p = Actions.packProof(ds, d)
                assertEquals(n, p["size"])
                assertTrue("n=$n $d", Actions.verifyPackProof(root, p, d))
                assertFalse(Actions.verifyPackProof(root, p, "other"))
            }
        }
    }

    @Test fun schemaMcpOpenapiExactKeys() = dl {
        val base = IntentJs.obj(K042ActionSchemaTest.j(K042ActionSchemaTest.cases("shape").first { it["name"] == "shape/base" }["doc"]))
        fun mod(vararg kv: Pair<String, Any?>): String? {
            val verbs = ArrayList<Any?>(IntentJs.get(base, "verbs") as List<*>)
            val v0 = LinkedHashMap(IntentJs.obj(verbs[0]))
            for ((k, v) in kv) v0[k] = v
            verbs[0] = v0
            val doc = LinkedHashMap(base)
            doc["verbs"] = verbs
            return ActionSchema.shapeError(doc)
        }
        assertNull(mod())
        assertNull(mod("mcp" to m("tool" to "t"), "openapi" to m("operationId" to "o")))
        assertEquals("verb 'a.b': mcp must be {tool}", mod("mcp" to m("tool" to "t", "x" to "y")))
        assertEquals("verb 'a.b': mcp must be {tool}", mod("mcp" to m("other" to "t")))
        assertEquals("verb 'a.b': openapi must be {operationId}", mod("openapi" to m()))
    }

    @Test fun caveatsPolicyAndUndoDigest() = dl {
        val env = m("type" to "envelope")
        val a = m("type" to "a"); val b = m("type" to "b"); val c = m("type" to "c"); val d = m("type" to "d")
        val grant = m("caveats" to listOf(env, a, b))
        val leaf = m("caveats" to listOf(env, a, b, c, d))
        assertEquals(listOf<Any?>(a, b, c, d), Caveats.policyCaveats(grant, listOf(grant, leaf)))
        assertEquals(listOf<Any?>(a, b), Caveats.policyCaveats(grant, listOf(grant)))
        val comp = m("verb" to "v", "resource" to "r", "params" to m(), "undo_of" to "u", "def_digest" to "d")
        val dg = Undo.compensationDigest(comp)
        assertEquals(43, dg.length)
        comp["target_param"] = "p"
        assertNotEquals(dg, Undo.compensationDigest(comp))
        try { Undo.compensationDigest(m("verb" to "v", "resource" to "r", "params" to m(), "undo_of" to "u")); throw AssertionError("absent member") } catch (e: IllegalArgumentException) { assertTrue(e.message!!.contains("def_digest")) }
    }

    @Test fun argProvenanceDirect() = dl {
        assertNull(ArgProvenance.actionInfoError(m("effects" to listOf("read", "write"), "traits" to listOf("t"), "params" to m("a" to "tool", "b" to "agent"))))
        assertEquals("action info 'params' must be an object", ArgProvenance.actionInfoError(m("params" to "x")))
        assertEquals("action info 'effects' must be a list of strings", ArgProvenance.actionInfoError(m("effects" to listOf("a", 1))))
        assertEquals("action info param 'b' must map to first_party | tool | agent", ArgProvenance.actionInfoError(m("params" to m("a" to "tool", "b" to "bad"))))
        assertTrue(ArgProvenance.occursAsToken("xab ab", "ab"))
        assertFalse(ArgProvenance.occursAsToken("xabab", "ab"))
        assertTrue(ArgProvenance.occursAsToken("aab aab-ab", "ab"))
        assertTrue(ArgProvenance.occursAsToken("zzab zzab", "zzab"))
        assertFalse(ArgProvenance.occursAsToken("abc abd", "ab"))
        assertTrue(ArgProvenance.occursAsToken("-ab", "-ab"))
        assertFalse(ArgProvenance.occursAsToken("abab", ""))
    }

    @Test fun approvalRenderAndSigstoreUnderDeadline() = dl(20_000) {
        K05ApprovalDiffTest().render()
        K05SigstoreDiffTest().parseTrustedRoot()
        K05SigstoreDiffTest().verifySigstoreBundle()
    }
}
