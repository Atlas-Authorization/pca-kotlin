package net.atlasauth.pca.verifier

import net.atlasauth.pca.explain.ExplainJs
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Guardian-set high availability and the fenced leader lease against the reference corpus (ref-ha, 753 cases): the pure decisions, the fence
 * guard, the scripted lease lifecycles (store faults, a lost compare-and-swap, a store clock moving during the sign step, corrupt records) and
 * the raw compare-and-swap of the key/value lease store. A value the reference stores goes through JSON text first, as its in-memory store does.
 */
@Suppress("UNCHECKED_CAST")
class HaRefDiffTest {
    private val mod = "ref-ha"
    private val key = Ha.DEFAULT_LEASE_KEY

    private fun list(o: Any?): List<Any?> = o as List<Any?>

    private fun nums(v: Any?): Any? = OracleCases.decNum(v)

    /** The inverse for a result: a non-finite number becomes `{"$num": text}`. */
    private fun enc(v: Any?): Any? = when (v) {
        is Json.Num -> if (v.raw == "NaN" || v.raw == "Infinity" || v.raw == "-Infinity") linkedMapOf<String, Any?>("\$num" to v.raw) else v
        is List<*> -> v.map { enc(it) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = enc(x) }
        else -> v
    }

    /** What the reference's in-memory store keeps: the value as JSON text (a non-finite number is null there). */
    private fun stored(v: Any?): Any? = Json.parseLenient(ExplainJs.stringify(v))

    /** One fresh store; the clock, the fault kind and the one-shot lost compare-and-swap are the case's to move. */
    private class Rig : Ha.LeaseStore {
        val kv = MemoryAtomicKv()
        var clock = 0.0
        var fault = "none"
        var loseOnce = false
        val kvs = Ha.KvLeaseStore(kv, null) { clock }

        override fun read(): Any? { if (fault == "read") throw RuntimeException("boom"); return kvs.read() }
        override fun now(): Double { if (fault == "now") throw RuntimeException("boom"); return kvs.now() }
        override fun cas(expected: Any?, next: Any?): Boolean {
            if (fault == "cas") throw RuntimeException("boom")
            if (loseOnce) { loseOnce = false; return false }
            return kvs.cas(expected, next)
        }
    }

    private fun res(refs: Map<String, Any?>, x: Any?): Any? = if (x is String) refs[x] else x

    private fun lease(ops: List<Any?>): List<Any?> {
        val rig = Rig()
        val refs = LinkedHashMap<String, Any?>()
        val out = ArrayList<Any?>()
        for (o in ops) {
            val op = list(o)
            try {
                when (op[0] as String) {
                    "clock" -> { rig.clock = IntentJs.num(op[1])!!; out.add(null) }
                    "fault" -> { if (op[1] == "loseCas") rig.loseOnce = true else rig.fault = op[1] as String; out.add(null) }
                    "raw" -> { rig.kv.set(key, stored(op[1])); out.add(null) }
                    "read" -> out.add(rig.kv.get(key))
                    "acquire" -> {
                        val r = Ha.acquireLease(rig, op[2], op[3])
                        if (r["ok"] == true) refs[op[1] as String] = r["lease"]
                        out.add(r)
                    }
                    "renew" -> {
                        val r = Ha.renewLease(rig, res(refs, op[1]), op[2])
                        if (r["ok"] == true && op[1] is String) refs[op[1] as String] = r["lease"]
                        out.add(r)
                    }
                    "release" -> {
                        val r = Ha.releaseLease(rig, res(refs, op[1]))
                        if (r["ok"] == true && op[1] is String) refs[op[1] as String] = r["lease"]
                        out.add(r)
                    }
                    "fence" -> out.add(Ha.assertFence(rig, res(refs, op[1]), op[2]))
                    "signer" -> {
                        val lz = if (op[1] == null) null else res(refs, op[1])
                        val advance = IntentJs.num(op[3])!!
                        val boom = op[4] == true
                        val f = Ha.fencedSigner(rig, { lz }, { rig.clock += advance; if (boom) throw RuntimeException("sign"); "signed" }, op[2])
                        val r = LinkedHashMap<String, Any?>()
                        try {
                            val s = f()
                            r["ok"] = true
                            r["result"] = s.result
                            r["epoch"] = s.epoch
                        } catch (e: Ha.FenceError) {
                            r["ok"] = false
                            r["reason"] = e.reason
                        } catch (e: Exception) {
                            r["ok"] = false
                            r["error"] = e.message
                        }
                        out.add(r)
                    }
                    else -> throw IllegalArgumentException("bad op")
                }
            } catch (e: RuntimeException) {
                out.add(linkedMapOf<String, Any?>("\$err" to e.message))
            }
        }
        return out
    }

    private fun kvCas(prev: Any?, exp: Any?, next: Any?): Any? {
        val kv = MemoryAtomicKv()
        if (prev != null) kv.set(key, stored(prev))
        val s = Ha.KvLeaseStore(kv, null) { 0.0 }
        val ok = s.cas(exp, next)
        return linkedMapOf("ok" to ok, "stored" to kv.get(key))
    }

    @Test fun everyFunction() {
        OracleCases.each(mod, "liveGuardians") { x -> enc(Ha.liveGuardians(nums(x[0]), nums(x[1]), nums(x[2]))) }
        OracleCases.each(mod, "quorumStatus") { x -> enc(Ha.quorumStatus(nums(x[0]), nums(x[1]), nums(x[2]))) }
        OracleCases.each(mod, "degradeMode") { x -> Ha.degradeMode(nums(x[0]), nums(x[1])) }
        OracleCases.each(mod, "selectSigners") { x -> enc(Ha.selectSigners(nums(x[0]), nums(x[1]), nums(x[2]))) }
        OracleCases.each(mod, "failoverPlan") { x -> enc(Ha.failoverPlan(nums(x[0]), nums(x[1]), nums(x[2]))) }
        OracleCases.each(mod, "validateGuardianSet") { x -> Ha.validateGuardianSet(nums(x[0])) }
        OracleCases.each(mod, "fenceGuard") { x ->
            val g = Ha.createFenceGuard(nums(x[0]))
            val admits = ArrayList<Any?>()
            for (e in list(nums(x[1]))) admits.add(g.admit(e))
            linkedMapOf("admits" to admits, "highest" to g.highest())
        }
        OracleCases.each(mod, "lease") { x -> enc(lease(list(nums(x[0])))) }
        OracleCases.each(mod, "kvCas") { x -> enc(kvCas(nums(x[0]), nums(x[1]), nums(x[2]))) }
        OracleCases.each(mod, "constants") { _ -> linkedMapOf<String, Any?>("MAX_LEASE_TTL_MS" to Ha.MAX_LEASE_TTL_MS, "DEFAULT_LEASE_SKEW_MS" to Ha.DEFAULT_LEASE_SKEW_MS) }
        val fns = setOf("liveGuardians", "quorumStatus", "degradeMode", "selectSigners", "failoverPlan", "validateGuardianSet", "fenceGuard", "lease", "kvCas", "constants")
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(753, fns.sumOf { OracleCases.of(mod, it).size })
    }
}
