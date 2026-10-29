package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The A2A binding corpus (`a2a-vectors.json`). A missing file fails. */
@Suppress("UNCHECKED_CAST")
class A2aVectorsTest {
    private val doc = ParityVectors.load("a2a-vectors.json")
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun strs(o: Any?): List<String> = l(o).map { it as String }

    @Test
    fun needs() {
        assertTrue(l(doc["need"]).size >= 20)
        for (x in l(doc["need"])) {
            val c = m(x)
            val input = c["input"].let { if (it is Json.Num) it.raw else it }
            val d = A2a.decodeNeed(input)
            val e = m(c["expect"])
            assertEquals("${c["name"]}: ok", e["ok"], d.code == null)
            if (d.code == null) assertEquals("${c["name"]}: digest", e["digest"], A2a.needDigest(d.need!!)) else assertEquals("${c["name"]}: code", e["code"], d.code)
        }
    }

    @Test
    fun push() {
        val p = m(doc["push"])
        for (x in l(p["tokens"])) { val t = m(x); assertEquals(t["token"], A2a.pushToken(t["task_id"] as String, strs(t["chain_ids"]), t["salt"])) }
        for (s in l(p["weak_salts"])) assertNull(A2a.pushToken("t", listOf("a"), s))
        for (x in l(p["checks"])) {
            val c = m(x); val e = m(c["expected"]); val d = m(c["delivered"]); val exp = m(c["expect"])
            val got = A2a.checkPush(e["task_id"] as String, strs(e["chain_ids"]), e["salt"] as String, d["token"], d["payload"])
            assertEquals("${c["name"]}: ok", exp["ok"], got == null)
            if (got != null) assertEquals("${c["name"]}: reason", exp["reason"], got)
        }
    }

    @Test
    fun chains() {
        for (x in l(doc["chains"])) {
            val c = m(x); val exp = m(c["expect"])
            val got = A2a.checkChainExtension(l(c["chains"]).map { strs(it) })
            assertEquals("${c["name"]}: ok", exp["ok"], got == null)
            if (got != null) {
                assertEquals("${c["name"]}: reason", exp["reason"], got.second)
                assertEquals("${c["name"]}: hop", IntentJs.lng(exp["failedHop"]), got.first.toLong())
            }
        }
    }

    @Test
    fun resume() {
        for (x in l(doc["resume"])) {
            val c = m(x)
            val pa = c["proof_action"]?.let { m(it) }
            val got = A2a.resumeGate(c["state"] as String, c["need_encoded"], c["answer_need_digest"], pa?.get("verb") as String?, pa?.get("resource") as String?)
            assertEquals(c["name"] as String, c["expect"], got)
        }
    }

    @Test
    fun receipts() {
        val r = m(doc["receipts"])
        val signer = r["signer"] as String
        val recs = l(r["records"])
        for (x in l(r["verify"])) { val v = m(x); assertEquals("verify ${v["record"]}", v["ok"], A2a.verifyReceipt(recs[IntentJs.lng(v["record"]).toInt()], signer)) }
        for (x in l(r["digests"])) { val d = m(x); assertEquals(d["digest"], A2a.receiptDigest(recs[IntentJs.lng(d["record"]).toInt()])) }
        for (x in l(r["scenarios"])) {
            val s = m(x); val exp = m(s["expect"])
            val list = l(s["indices"]).map { recs[IntentJs.lng(it).toInt()] }
            val name = s["name"] as String
            val got = A2a.checkReceiptChain(list, signer, s["task_id"] as String, strs(s["chain_ids"]))
            assertEquals("$name: ok", exp["ok"], got.code == null)
            if (got.code == null) {
                assertEquals("$name: terminal", exp["terminal"], got.terminal)
                assertEquals("$name: state", exp["last_state"], got.lastState)
            } else {
                assertEquals("$name: code", exp["code"], got.code)
                if (exp.containsKey("at")) assertEquals("$name: at", IntentJs.lng(exp["at"]), got.at.toLong())
            }
            assertEquals("$name: may", s["may_trigger_next"], A2a.mayTriggerNext(list, signer, s["task_id"] as String, strs(s["chain_ids"])))
        }
    }
}
