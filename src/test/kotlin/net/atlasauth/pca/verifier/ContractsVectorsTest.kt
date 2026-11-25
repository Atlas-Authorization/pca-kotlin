package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** `contracts-vectors.json`: validate, check, advance, verify and the durable enforcer, every row and step. A missing file FAILS. */
@Suppress("UNCHECKED_CAST")
class ContractsVectorsTest {
    private val doc = ParityVectors.load("contracts-vectors.json")

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>

    @Test fun validateRows() {
        val rows = l(doc["validate"])
        assertTrue("validate rows: ${rows.size}", rows.size >= 21)
        for (x in rows) {
            val r = m(x)
            assertEquals(r["name"] as String, l(m(r["expect"])["problems"]), Contracts.validateContract(r["contract"]))
        }
    }

    @Test fun checkRows() {
        val rows = l(doc["check"])
        assertTrue("check rows: ${rows.size}", rows.size >= 10)
        for (x in rows) {
            val r = m(x)
            val got = Contracts.checkContract(r["action"], r["contract"], r["state"])
            assertEquals(r["name"] as String, Json.canonicalize(r["expect"]), Json.canonicalize(got))
        }
    }

    @Test fun advanceRows() {
        val rows = l(doc["advance"])
        assertTrue("advance rows: ${rows.size}", rows.size >= 7)
        for (x in rows) {
            val r = m(x)
            val name = r["name"] as String
            val contract = r["contract"]
            var state: Any? = Prohibitions.emptyState(r["genesis_now"])
            val genesisDigest = Prohibitions.stateDigest(state)
            var i = 0
            for (sx in l(r["steps"])) {
                val st = m(sx)
                val exp = m(st["expect"])
                val o = (st["options"] as? Map<String, Any?>) ?: emptyMap()
                val label = "$name step ${i++}"
                // the "stale digest of genesis" option is the digest of the state the sequence started from
                val digest = if (o["stale_digest_of_genesis"] == true) genesisDigest else null
                val res = Contracts.advanceContract(state, st["action"], contract, o["now"], o["expectedSeq"], digest)
                assertEquals("$label: ok", exp["ok"], res["ok"])
                assertEquals("$label: decidedBy", exp["decidedBy"], res["decidedBy"])
                assertEquals("$label: violated", l(exp["violated"]), l(res["violated"]))
                assertEquals("$label: reasons", l(exp["reasons"]), l(res["reasons"]))
                if (res["ok"] == true) state = res["next"]
                val cur = m(state)
                assertEquals("$label: seq", Prohibitions.dv(exp["seq"]), Prohibitions.dv(cur["seq"]), 0.0)
                assertEquals("$label: deadlines", Json.canonicalize(exp["deadlines"]), Json.canonicalize(if (cur.containsKey("deadlines")) cur["deadlines"] else LinkedHashMap<String, Any?>()))
                assertEquals("$label: latched", l(exp["latched"]).map { it as String }.sorted(), m(cur["latched"]).keys.sorted())
                assertEquals("$label: state digest", exp["state_digest"], Prohibitions.stateDigest(state))
            }
        }
    }

    @Test fun verifyRows() {
        val rows = l(doc["verify"])
        assertTrue("verify rows: ${rows.size}", rows.size >= 7)
        for (x in rows) {
            val r = m(x)
            val why = Contracts.verifyContract(r["contract"], r["principal"] as? String)
            val exp = m(r["expect"])
            assertEquals("${r["name"]} ($why)", exp["ok"], why == null)
            if (exp["ok"] != true) assertEquals(r["name"] as String, exp["reason"], why)
        }
    }

    @Test fun enforcerRows() {
        val rows = l(doc["enforcer"])
        assertTrue("enforcer rows: ${rows.size}", rows.size >= 9)
        val head = m(rows[0])
        val contract = head["contract"]
        val principal = head["principal"] as String
        val clock = Prohibitions.dv(head["clock"])
        var ran = 0
        for (x in rows.subList(1, rows.size)) {
            val r = m(x)
            val name = r["name"] as String
            val opts = (r["options"] as? Map<String, Any?>) ?: emptyMap()
            val kv = MemoryAtomicKv()
            var wall = clock
            val latch = opts["latchOnViolation"] != false
            val en = ContractEnforcer.open(kv, contract, principal, "k", { wall }, latch)
            if (r.containsKey("stored_document")) kv.set("k", r["stored_document"])
            var i = 0
            for (sx in l(r["steps"])) {
                val st = m(sx)
                val exp = m(st["expect"])
                val label = "$name step ${i++}"
                val op = st["op"] as String
                if (st.containsKey("wall")) wall = Prohibitions.dv(st["wall"])
                if (op == "check" || op == "peek") {
                    val res = if (op == "check") en.check(st["action"], st["permitted"] != false) else en.peek(st["action"])
                    assertEquals("$label: allow", exp["allow"], res.allow)
                    assertEquals("$label: reason", exp["reason"], res.reason)
                    assertEquals("$label: violated", l(exp["violated"]), res.violated)
                    assertEquals("$label: reasons", l(exp["reasons"]), res.reasons)
                    assertEquals("$label: seq", Prohibitions.dv(exp["seq"]).toLong(), res.seq)
                } else if (op == "state") {
                    val got = en.state()!!
                    assertEquals("$label: seq", Prohibitions.dv(exp["seq"]), Prohibitions.dv(m(got["state"])["seq"]), 0.0)
                    assertEquals("$label: now", Prohibitions.dv(exp["now"]), Prohibitions.dv(m(got["state"])["now"]), 0.0)
                    assertEquals("$label: latched", exp["latched"], got["latched"])
                    assertEquals("$label: state digest", exp["state_digest"], Prohibitions.stateDigest(got["state"]))
                } else {
                    assertEquals(label, "reset", op)
                    assertEquals("$label: cleared", exp["cleared"], en.reset(st["sig"] as String?))
                }
                ran++
            }
        }
        assertTrue("enforcer steps: $ran", ran >= 20)
    }
}
