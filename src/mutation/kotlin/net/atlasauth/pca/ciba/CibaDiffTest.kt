package net.atlasauth.pca.ciba

import java.io.IOException
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Replays the reference oracle of the CIBA on-ramp (auth request, gating, brokers, KV store, client) and covers the file stores directly. */
@Suppress("UNCHECKED_CAST")
class CibaDiffTest {
    private val mod = "ref-ciba"
    private val t0 = 1_800_000_000_000L

    @get:Rule val tmp = TemporaryFolder()

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun num(o: Any?): Double = when (o) {
        is Json.Num -> o.raw.toDouble()
        is Number -> o.toDouble()
        else -> throw IllegalArgumentException("not a number")
    }
    // a primitive opts has no members in the reference (reads give undefined)
    private fun opt(a: List<Any?>, i: Int): Map<String, Any?>? = if (a.size > i) (if (a[i] == null || a[i] is Map<*, *>) m(a[i]) else emptyMap()) else null
    private fun each(fn: String, f: (List<Any?>) -> Any?) = OracleCases.each(mod, fn, f)

    // ---- pure functions ----
    @Test fun cibaActionFromStepUp() = each("cibaActionFromStepUp") { Ciba.cibaActionFromStepUp(m(it[0])) }

    @Test fun toCibaAuthRequest() = each("toCibaAuthRequest") { a ->
        if (a.size > 1 && a[1] == null) throw IllegalArgumentException("opts is null") // the reference reads a member of null
        Ciba.toCibaAuthRequest(m(a[0]), opt(a, 1))
    }

    @Test fun asciiForm() = each("asciiForm") { Ciba.asciiForm(it[0] as String) }
    @Test fun requiresCiba() = each("requiresCiba") { Ciba.requiresCiba(it[0]) }
    @Test fun cibaDecisionToCosign() = each("cibaDecisionToCosign") { Ciba.cibaDecisionToCosign(it[0], m(it[1]), m(it[2]), it[3], opt(it, 4)) }

    @Test fun verifyPingCallback() = each("verifyPingCallback") { a ->
        val input = m(a[0])
        CibaClient.verifyPingCallback(input["authorization"] as String?, input["body"], m(a[1]))
    }

    @Test fun createCibaClientConfig() = each("createCibaClientConfig") { a ->
        val c = m(a[0])
        val cfg = CibaClient.Config()
        cfg.backchannelAuthenticationEndpoint = c["backchannelAuthenticationEndpoint"] as String?
        cfg.tokenEndpoint = c["tokenEndpoint"] as String?
        cfg.clientId = c["clientId"] as String?
        cfg.clientSecret = c["clientSecret"] as String?
        cfg.allowInsecureHttp = c["allowInsecureHttp"] == true
        if (c.containsKey("timeoutMs")) cfg.timeoutMs = num(c["timeoutMs"])
        cfg.transport = CibaClient.Transport { _, _, _, _ -> CibaClient.Response(200, "{}") }
        CibaClient.createCibaClient(cfg)
        true
    }

    @Test fun durableBrokerConfig() = each("durableBrokerConfig") { a ->
        val c = m(a[0])
        val o = CibaApproval.DurableBrokerOptions()
        if (c["noStore"] != true) o.store = CibaApproval.createMemoryApprovalStore()
        if (c.containsKey("decisionTtlSec")) o.decisionTtlSec = num(c["decisionTtlSec"])
        try { CibaApproval.createDurableCibaBroker(o); "ok" } catch (e: RuntimeException) { "throws" }
    }

    // ---- brokers as scripted scenarios ----
    private fun redactIds(v: Any?, ids: List<String>): Any? = when (v) {
        is String -> ids.foldIndexed(v) { i, s, id -> s.replace(id, "<ID${i + 1}>") }
        is List<*> -> v.map { redactIds(it, ids) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = redactIds(x, ids) }
        else -> v
    }

    private fun brokerScenario(s: Map<String, Any?>): Any? {
        var clock = t0
        val kind = s["kind"] as String
        val opts = if (s.containsKey("opts")) m(s["opts"]) else emptyMap()
        val oc = opts["onComplete"] as String?
        val completes = ArrayList<Any?>()
        val onComplete: ((Map<String, Any?>) -> Unit)? = if (oc == null) null else ({ sess: Map<String, Any?> ->
            completes.add(sess)
            if (oc == "throws") throw IllegalStateException("notifier down")
        })
        var kv: CibaKv.DurableKv? = null
        var store: CibaApproval.ApprovalStore? = null
        val broker: CibaApproval.ApprovalBroker
        if (kind == "memory") {
            val bo = CibaApproval.BrokerOptions()
            bo.now = { clock }
            bo.onComplete = onComplete
            broker = CibaApproval.createCibaBroker(bo)
        } else {
            if (kind == "durable-kv") { kv = CibaKv.createMemoryKv(); store = CibaKv.createKvApprovalStore(kv) } else store = CibaApproval.createMemoryApprovalStore()
            val o = CibaApproval.DurableBrokerOptions()
            o.store = store
            o.now = { clock }
            if (opts.containsKey("decisionTtlSec")) o.decisionTtlSec = num(opts["decisionTtlSec"])
            o.onComplete = onComplete
            broker = CibaApproval.createDurableCibaBroker(o)
        }
        val ids = ArrayList<String>()
        val trace = ArrayList<Any?>()
        for (so in l(s["steps"])) {
            val st = m(so)
            val op = st["op"] as String
            val entry = linkedMapOf<String, Any?>("op" to op)
            try {
                var value: Any? = null
                val idO = st["id"]
                // a missing id reads as the text "null", as the reference's string concatenation does
                val id = if (idO !is String) "null" else if (idO == "\$id") ids[ids.size - 1] else if (idO.startsWith("\$id")) ids[idO.substring(3).toInt() - 1] else idO
                val lastId = if (ids.isEmpty()) "" else ids[ids.size - 1]
                when (op) {
                    "start" -> {
                        val req = broker.start(m(st["stepUp"]), if (st.containsKey("opts")) m(st["opts"]) else null)
                        val rid = req["auth_req_id"] as String
                        if (rid !in ids) ids.add(rid)
                        value = req
                    }
                    "poll" -> value = broker.poll(id)
                    "token" -> value = broker.token(id)
                    "resolve" -> value = broker.resolve(id, st["decision"] as? String ?: "\u0000invalid", st["by"] as? String)
                    "get" -> value = broker.get(id)
                    "advance" -> { clock += num(st["ms"]).toLong(); value = clock }
                    "storeSet" -> {
                        val key = (st["key"] as String).replace("\$id", lastId)
                        val cur = store!!.get(key)
                        value = store!!.cas(key, cur?.version ?: 0L, st["value"])
                    }
                    "kvRaw" -> {
                        val key = (st["key"] as String).replace("\$id", lastId)
                        value = kv!!.putIfEquals(key, kv!!.get(key), st["raw"] as String)
                    }
                    else -> throw IllegalStateException("unknown step $op")
                }
                entry["ok"] = true
                entry["value"] = value
            } catch (e: CibaKv.ApprovalStoreError) {
                entry["ok"] = false
                entry["msg"] = e.message
                entry["code"] = e.code
            } catch (e: RuntimeException) {
                entry["ok"] = false
                entry["msg"] = e.message
            }
            if (completes.isNotEmpty()) { entry["complete"] = ArrayList(completes); completes.clear() }
            trace.add(entry)
        }
        return redactIds(OracleCases.toJson(trace), ids)
    }

    @Test fun brokerScenario() = each("brokerScenario") { brokerScenario(m(it[0])) }

    // ---- the KV approval store ----
    private fun kvScenario(s: Map<String, Any?>): Any? {
        val kv = CibaKv.createMemoryKv()
        val store = CibaKv.createKvApprovalStore(kv)
        val trace = ArrayList<Any?>()
        for (so in l(s["steps"])) {
            val st = m(so)
            val op = st["op"] as String
            val entry = linkedMapOf<String, Any?>("op" to op)
            try {
                val key = st["key"] as String
                val value: Any? = when (op) {
                    "get" -> store.get(key)?.let { linkedMapOf<String, Any?>("version" to it.version, "value" to it.value) }
                    "cas" -> store.cas(key, num(st["expected"]).toLong(), st["value"])
                    "kvSet" -> kv.putIfEquals(key, kv.get(key), st["raw"] as String)
                    "kvGet" -> kv.get(key)
                    else -> throw IllegalStateException("unknown step $op")
                }
                entry["ok"] = true
                entry["value"] = value
            } catch (e: CibaKv.ApprovalStoreError) {
                entry["ok"] = false
                entry["code"] = e.code
            } catch (e: RuntimeException) {
                entry["ok"] = false
                entry["code"] = "other"
            }
            trace.add(entry)
        }
        return trace
    }

    @Test fun kvScenario() = each("kvScenario") { kvScenario(m(it[0])) }

    // ---- the client ----
    private fun redactToken(v: Any?, nt: String): Any? = when {
        nt.isEmpty() -> v
        v is String -> v.replace(nt, "<NTOKEN>")
        v is List<*> -> v.map { redactToken(it, nt) }
        v is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = redactToken(x, nt) }
        else -> v
    }

    private fun clientScenario(s: Map<String, Any?>): Any? {
        var clock = t0
        val reqs = ArrayList<Any?>()
        val sleeps = ArrayList<Any?>()
        val queue = ArrayList(l(s["responses"]))
        val c = m(s["cfg"])
        val cfg = CibaClient.Config()
        cfg.backchannelAuthenticationEndpoint = c["backchannelAuthenticationEndpoint"] as String?
        cfg.tokenEndpoint = c["tokenEndpoint"] as String?
        cfg.clientId = c["clientId"] as String?
        cfg.clientSecret = c["clientSecret"] as String?
        cfg.allowInsecureHttp = c["allowInsecureHttp"] == true
        cfg.now = { clock }
        cfg.sleep = CibaClient.Sleeper { ms -> sleeps.add(ms); clock += ms }
        cfg.transport = CibaClient.Transport { url, headers, body, _ ->
            reqs.add(linkedMapOf<String, Any?>("url" to url, "method" to "POST", "headers" to LinkedHashMap<String, Any?>(headers), "body" to body))
            if (queue.isEmpty()) throw IOException("no scripted response")
            val resp = m(queue.removeAt(0))
            if (resp["fail"] == true) throw IOException("connection reset")
            val b = resp["body"]
            CibaClient.Response(num(resp["status"]).toInt(), b as? String ?: Json.canonicalize(b))
        }
        val client = CibaClient.createCibaClient(cfg)
        var poller: CibaClient.Poller? = null
        val trace = ArrayList<Any?>()
        var nt = ""
        for (so in l(s["steps"])) {
            val st = m(so)
            val op = st["op"] as String
            val entry = linkedMapOf<String, Any?>("op" to op)
            try {
                var value: Any? = null
                when (op) {
                    "initiate" -> {
                        val flow = client.initiate(m(st["stepUp"]), if (st.containsKey("opts")) m(st["opts"]) else null)
                        poller = client.poller(flow)
                        value = flow
                        val given = st.containsKey("opts") && m(st["opts"]).containsKey("clientNotificationToken")
                        if (flow["clientNotificationToken"] != null && !given) nt = flow["clientNotificationToken"] as String
                    }
                    "poll" -> value = poller!!.poll()
                    "wait" -> value = poller!!.await(null)
                    "notify" -> poller!!.notifyPing()
                    "advance" -> { clock += num(st["ms"]).toLong(); value = clock }
                    "interval" -> value = poller!!.intervalSec()
                    else -> throw IllegalStateException("unknown step $op")
                }
                entry["ok"] = true
                entry["value"] = value
            } catch (e: CibaClient.CibaProviderError) {
                entry["ok"] = false
                entry["error"] = e.error
                entry["status"] = e.status
                entry["retryable"] = e.retryable
                entry["errorDescription"] = e.errorDescription
            } catch (e: RuntimeException) {
                entry["ok"] = false
                entry["other"] = true
            }
            entry["requests"] = ArrayList(reqs)
            reqs.clear()
            entry["sleeps"] = ArrayList(sleeps)
            sleeps.clear()
            trace.add(redactToken(OracleCases.toJson(entry), nt))
        }
        return trace
    }

    @Test fun clientScenario() = each("clientScenario") { clientScenario(m(it[0])) }

    // ---- what the oracle cannot cover: random values, files ----
    @Test fun newClientNotificationTokenShape() {
        val t = CibaClient.newClientNotificationToken()
        assertTrue(Regex("[A-Za-z0-9_-]{43}").matches(t))
        assertFalse(t == CibaClient.newClientNotificationToken())
    }

    @Test fun fileApprovalStoreRoundTrip() {
        val f = java.io.File(tmp.root, "approvals.json")
        val s = CibaApproval.createFileApprovalStore(f)
        assertNull(s.get("k"))
        assertTrue(s.cas("k", 0, linkedMapOf<String, Any?>("a" to 1L)))
        assertFalse(s.cas("k", 0, "again"))
        assertEquals(1L, s.get("k")!!.version)
        assertTrue(s.cas("k", 1, "two"))
        assertEquals("two", CibaApproval.createFileApprovalStore(f).get("k")!!.value) // a second store object over the same file (a restart)
        f.writeText("[1,2]")
        assertThrows(IllegalStateException::class.java) { s.get("k") } // a corrupt file fails closed
    }

    @Test fun directoryKvSwap() {
        val kv = CibaKv.createDirectoryKv(tmp.newFolder("kv"), 200)
        assertNull(kv.get("k"))
        assertTrue(kv.putIfEquals("k", null, "one"))
        assertFalse(kv.putIfEquals("k", null, "two"))
        assertEquals("one", kv.get("k"))
        assertTrue(kv.putIfEquals("k", "one", "three"))
        assertEquals("three", kv.get("k"))
        assertThrows(CibaKv.ApprovalStoreError::class.java) { kv.get("") }
    }

    @Test fun directoryKvLockTimeout() {
        val dir = tmp.newFolder("kv-locked")
        val kv = CibaKv.createDirectoryKv(dir, 50)
        assertTrue(kv.putIfEquals("k", null, "one"))
        // a lock left behind by a dead process: the swap fails closed instead of writing
        val lock = dir.listFiles()!!.single { !it.name.endsWith(".lock") }.let { java.io.File(it.path + ".lock") }
        assertTrue(lock.createNewFile())
        val e = assertThrows(CibaKv.ApprovalStoreError::class.java) { kv.putIfEquals("k", "one", "two") }
        assertEquals("lock_timeout", e.code)
        assertEquals("one", kv.get("k"))
    }

    @Test fun durableBrokerOverDirectoryKv() {
        val dir = tmp.newFolder("broker")
        val clock = t0
        val o = CibaApproval.DurableBrokerOptions()
        o.store = CibaKv.createKvApprovalStore(CibaKv.createDirectoryKv(dir))
        o.now = { clock }
        val b = CibaApproval.createDurableCibaBroker(o)
        val su = linkedMapOf<String, Any?>("id" to "su-1", "verb" to "stripe.payout", "resource" to "acct-1", "tier" to 3L, "goalCommit" to "abcdefghijklmnopqrstuvwxyz")
        val id = b.start(su, null)["auth_req_id"] as String
        assertEquals("pending", b.poll(id)["status"])
        b.resolve(id, "approve", "alice")
        // a restarted broker over the same directory still sees the decision and redeems it once
        val o2 = CibaApproval.DurableBrokerOptions()
        o2.store = CibaKv.createKvApprovalStore(CibaKv.createDirectoryKv(dir))
        o2.now = { clock + 10_000 }
        val b2 = CibaApproval.createDurableCibaBroker(o2)
        assertEquals(true, b2.token(id)["ok"])
        assertEquals("invalid_grant", b2.token(id)["error"])
    }
}
