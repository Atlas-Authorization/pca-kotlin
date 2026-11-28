package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The vector driver: key lookup by name, the dispatch (an op is matched by its exact text, never by its hash), the refusal texts and
 * the optional-argument paths the shared producer vectors do not reach.
 */
@Suppress("UNCHECKED_CAST")
class Kill15ProducerOpsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("producer-vectors.json") }
    private val pqDoc: Map<String, Any?> by lazy { ParityVectors.load("producer-pq-vectors.json") }

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun canon(o: Any?) = Json.canonicalize(o)
    private fun copyOf(o: Any?): Any? = ParityVectors.parse(Json.canonicalize(o))

    private fun refusal(f: () -> Unit): String {
        try { f() } catch (e: IllegalArgumentException) { return e.message ?: "" }
        fail("expected a refusal")
        return ""
    }

    private fun firstCase(d: Map<String, Any?>, op: String): Map<String, Any?> = l(d["cases"]).map { m(it) }.first { it["op"] == op }

    /** Another string with the same String.hashCode: +1 on the first char and -31 on the second cancel out. */
    private fun collide(s: String): String {
        val c = s.toCharArray()
        c[0] = c[0] + 1
        c[1] = c[1] - 31
        val r = String(c)
        assertEquals(s.hashCode(), r.hashCode())
        assertNotEquals(s, r)
        return r
    }

    @Test fun noKeysAreRefusedByName() {
        val ops = ProducerOps(null, null)
        assertEquals("unknown key 'x'", refusal { ops.ed("x") })
        assertEquals("unknown post-quantum key 'y'", refusal { ops.pq("y") })
        assertNull(ops.pq(null))
    }

    @Test fun aKeyIsFoundByItsOwnNameOnly() {
        val ops = ProducerOps(m(doc["keys"]), null)
        assertEquals(m(m(doc["keys"])["agent"])["public"], ops.ed("agent").id())
        assertNotEquals(ops.ed("agent").id(), ops.ed("principal").id())
        assertEquals("unknown key 'agentx'", refusal { ops.ed("agentx") })
    }

    @Test fun aPostQuantumKeyIsBuiltOncePerName() {
        val ops = ProducerOps(m(pqDoc["ed_keys"]), m(pqDoc["pq_keys"]))
        val a = ops.pq("agent/ml-dsa-65")!!
        assertSame(a, ops.pq("agent/ml-dsa-65"))
        assertNotSame(a, ops.pq("principal/ml-dsa-65"))
        assertNotEquals(a.pkB64u(), ops.pq("principal/ml-dsa-65")!!.pkB64u())
        assertEquals("unsupported_suite: fn-dsa-512", refusal { ops.pq("agent/fn-dsa-512") })
        assertEquals("unknown post-quantum key 'nobody'", refusal { ops.pq("nobody") })
    }

    @Test fun aSeedThatIsNotCanonicalBase64urlIsRefused() {
        val ops = ProducerOps(null, null)
        assertEquals("not canonical base64url", refusal { ops.run("ed25519_sign", Issue.obj("seed" to "***", "message_utf8" to "m")) })
    }

    @Test fun everyFamilyMapsToItsPrimitiveAndNothingElseDoes() {
        assertEquals(Pq.Prim.ML_DSA_65, ProducerOps.prim("ml-dsa-65"))
        assertEquals(Pq.Prim.ML_DSA_87, ProducerOps.prim("ml-dsa-87"))
        assertEquals(Pq.Prim.SLH_DSA_SHA2_128F, ProducerOps.prim("slh-dsa-sha2-128f"))
        assertEquals(Pq.Prim.SLH_DSA_SHA2_256S, ProducerOps.prim("slh-dsa-sha2-256s"))
        assertEquals("unsupported_suite: fn-dsa-512", refusal { ProducerOps.prim("fn-dsa-512") })
        for (f in listOf("ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s")) {
            val c = collide(f)
            assertEquals("unsupported_suite: $c", refusal { ProducerOps.prim(c) })
        }
    }

    /** An op is matched by its exact text: a different string with the same hash is an unsupported op. */
    @Test fun anOpIsMatchedByItsTextNotItsHash() {
        val ops = ProducerOps(m(doc["keys"]), m(pqDoc["pq_keys"]))
        val names = (l(doc["cases"]) + l(pqDoc["cases"])).map { m(it)["op"] as String }.toSortedSet()
        assertTrue("the corpus shrank: ${names.size}", names.size >= 51)
        for (op in names) {
            val c = collide(op)
            assertEquals("unsupported_op: $c", refusal { ops.run(c, Issue.obj()) })
        }
    }

    /** The suite is resolved (and refused by name) before any key argument is looked up. */
    @Test fun anUnknownSuiteIsRefusedBeforeItsKeys() {
        val ops = ProducerOps(m(pqDoc["ed_keys"]), m(pqDoc["pq_keys"]))
        assertEquals("unknown signature alg 'no-such-alg'",
            refusal { ops.run("suite_sign", Issue.obj("alg" to "no-such-alg", "ed" to "nobody", "message_utf8" to "m")) })
        assertEquals("unsupported_suite: fn-dsa-512",
            refusal { ops.run("suite_sign", Issue.obj("alg" to "fn-dsa-512", "ed" to "nobody", "pq" to "nobody", "message_utf8" to "m")) })
    }

    // ---- every key is looked up under the name the case gives it (a renamed key must still be found) -------------------------

    private val edFields = listOf("signer", "principal", "holder", "to_holder", "issuer", "subject", "recorder_key", "key", "ed")
    private val pqFields = listOf("pq", "holder_pq")

    private fun renamed(keys: Map<String, Any?>, prefix: String): Map<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        for ((k, v) in keys) r[prefix + k] = v
        return r
    }

    private fun aliasArgs(args: Map<String, Any?>, ed: Set<String>, pq: Set<String>): Map<String, Any?> {
        val out = LinkedHashMap(args)
        for (f in edFields) { val v = out[f]; if (v is String && v in ed) out[f] = "k-$v" }
        for (f in pqFields) { val v = out[f]; if (v is String && v in pq) out[f] = "q-$v" }
        val sub = out["sub_agent"]
        if (sub is Map<*, *>) {
            val s = LinkedHashMap(m(sub))
            val h = s["holder"]
            if (h is String && h in ed) s["holder"] = "k-$h"
            out["sub_agent"] = s
        }
        return out
    }

    private fun replayRenamed(d: Map<String, Any?>, edName: String, pqName: String?, atLeast: Int, keep: (Map<String, Any?>) -> Boolean) {
        val ed = m(d[edName])
        val pq = pqName?.let { m(d[it]) }
        val ops = ProducerOps(renamed(ed, "k-"), pq?.let { renamed(it, "q-") })
        var n = 0
        for (c in l(d["cases"])) {
            val v = m(c)
            if (v["exact"] != null && "kotlin" !in l(v["exact"])) continue
            val args = m(v["args"])
            if (!keep(args)) continue
            val name = v["name"].toString()
            val want = m(v["expect"])
            val a = aliasArgs(args, ed.keys, pq?.keys ?: emptySet())
            if (want.size == 1 && want["error"] != null) {
                val w = want["error"] as String
                val e = refusal { ops.run(v["op"] as String, a) }
                if (w.startsWith("canonicalize: ")) assertTrue("$name: $e", e.startsWith("canonicalize: ")) else assertEquals(name, w, e)
            } else assertEquals(name, canon(want), canon(ops.run(v["op"] as String, a)))
            n++
        }
        assertTrue("replayed only $n", n >= atLeast)
    }

    @Test fun everyEd25519CaseWorksWithRenamedKeys() = replayRenamed(doc, "keys", null, 80) { true }

    @Test fun theFastSuitesWorkWithRenamedKeys() = replayRenamed(pqDoc, "ed_keys", "pq_keys", 8) { a ->
        a["alg"] in listOf<Any?>("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65") && (a["pq"] as String?)?.contains("ml-dsa-65") != false
    }

    // ---- optional arguments ---------------------------------------------------------------------------------------------

    @Test fun aDelegationWithoutANewHolderKeepsTheParentsHolder() {
        val ops = ProducerOps(m(doc["keys"]), null)
        val a = m(copyOf(m(firstCase(doc, "delegate")["args"])))
        val withTo = LinkedHashMap(a)
        withTo["to_holder"] = "subagent"
        assertEquals(ops.ed("subagent").id(), m(ops.run("delegate", withTo))["holder"])
        val without = LinkedHashMap(a)
        without.remove("to_holder")
        assertEquals(m(a["parent"])["holder"], m(ops.run("delegate", without))["holder"])
    }

    @Test fun aSuiteDelegationWithoutANewHolderKeepsTheParentsHolder() {
        val ops = ProducerOps(m(pqDoc["ed_keys"]), m(pqDoc["pq_keys"]))
        val a = LinkedHashMap(m(copyOf(m(firstCase(pqDoc, "delegate_suite")["args"]))))
        assertEquals(ops.ed("subagent").id(), m(ops.run("delegate_suite", a))["holder"])
        a.remove("to_holder")
        assertEquals(m(a["parent"])["holder"], m(ops.run("delegate_suite", a))["holder"])
    }

    @Test fun anActCarriesTheCallersIssuedAtAndExpiry() {
        val ops = ProducerOps(m(doc["keys"]), null)
        val a = LinkedHashMap(m(copyOf(m(firstCase(doc, "act")["args"]))))
        a["iat"] = 1_800_000_123_456L
        a["exp"] = 1_800_000_123_456L + 12_345L
        val p = m(m(ops.run("act", a))["pcactn"])
        assertEquals(1_800_000_123_456L, Json.asLong(p["iat"]))
        assertEquals(1_800_000_135_801L, Json.asLong(p["exp"]))
    }

    @Test fun theEscalationHistoryHeadFollowsTheLastCounter() {
        val ops = ProducerOps(m(doc["keys"]), null)
        val a = LinkedHashMap(m(copyOf(m(firstCase(doc, "escalation_digests")["args"]))))
        a["last_counter"] = 7L
        assertEquals(Escalation.historyHead(7L), m(ops.run("escalation_digests", a))["history_head"])
        a["last_counter"] = null
        assertEquals(Escalation.historyHead(null), m(ops.run("escalation_digests", a))["history_head"])
        assertNotEquals(Escalation.historyHead(7L), Escalation.historyHead(null))
    }

    @Test fun aFacadeActWithASubAgentChainsOneMoreHop() {
        val ops = ProducerOps(m(doc["keys"]), null)
        val a = LinkedHashMap(m(copyOf(m(firstCase(doc, "facade_act")["args"]))))
        a.remove("sub_agent")
        assertEquals(1, l(m(ops.run("facade_act", a))["chain"]).size)
        a["sub_agent"] = Issue.obj("holder" to "subagent", "added_caveats" to ArrayList<Any?>())
        val r = m(ops.run("facade_act", a))
        assertEquals(2, l(r["chain"]).size)
        assertEquals(ops.ed("subagent").id(), m(l(r["chain"])[1])["holder"])
    }

    @Test fun aFacadeActWithoutCounterOrClockUsesTheNextCounterAndTheCurrentTime() {
        val ops = ProducerOps(m(doc["keys"]), null)
        val a = LinkedHashMap(m(copyOf(m(firstCase(doc, "facade_act")["args"]))))
        a.remove("sub_agent")
        val act = LinkedHashMap(m(a["act"]))
        act.remove("counter")
        act.remove("now")
        a["act"] = act
        val p = m(m(ops.run("facade_act", a))["pcactn"])
        assertEquals(1L, Json.asLong(p["counter"]))
        assertTrue(Json.asLong(p["iat"]) > 1_600_000_000_000L)
    }
}
