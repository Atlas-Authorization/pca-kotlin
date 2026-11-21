package net.atlasauth.pca.verifier

import net.atlasauth.pca.compliance.ComplianceJs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The liveness beacons against the reference (ref-beacons, 174 cases): the signed message, issuing under Ed25519, ML-DSA-65 and the hybrid suite
 * (signature bytes compare), the content address, verification with every refusal reason and JavaScript comparison semantics, monotonic acceptance,
 * the frozen check and the durable acceptor (a fresh in-memory store per case; a store that fails or holds junk refuses). The one case the reference
 * accepts only through its legacy `allowUnboundPq` option is asserted refused (the option is not offered).
 */
@Suppress("UNCHECKED_CAST")
class RefBeaconsDiffTest {
    private val mod = "ref-beacons"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict((o as? Map<*, *>)?.get("\$bytes"), 32) ?: throw IllegalArgumentException("not a signing key")

    private fun signer(secret: Any?, suite: Any?): Keys.SuiteKey {
        val s = suite as Map<String, Any?>?
        val alg = if (s != null && s.containsKey("alg")) s["alg"] as String else "ed25519"
        val pq = s?.get("pqSeed")?.let { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(it)) }
        return Keys.suite(alg, Keys.edFromSeed(seed(secret)), pq)
    }

    private fun verdict(v: Beacons.Verdict): Map<String, Any?> = if (v.reason == null) linkedMapOf("ok" to v.ok) else linkedMapOf("ok" to v.ok, "reason" to v.reason)

    private class FlakyKv(val inner: AtomicKv) : AtomicKv {
        var failNext = false
        override fun get(key: String): Any? = inner.get(key)
        override fun set(key: String, value: Any?) = inner.set(key, value)
        override fun update(key: String, fn: (Any?) -> Any?): Any? {
            if (failNext) { failNext = false; throw RuntimeException("kv down") }
            return inner.update(key, fn)
        }
    }

    private fun acceptor(ops: List<Any?>): Any? {
        val kv = FlakyKv(net.atlasauth.pca.durable.MemoryDurableKv())
        val acc = Beacons.createBeaconAcceptor(kv)
        return ops.map { op ->
            val o = op as List<Any?>
            when (o[0]) {
                "accept" -> verdict(acc.accept(o[1], o[2]))
                "raw" -> { kv.set(Beacons.beaconKey(map(o[1])), o[2]); null }
                "fail" -> { kv.failNext = true; null }
                else -> linkedMapOf("\$err" to "op")
            }
        }
    }

    private fun ctor(spec: Any?): Any? {
        val kv: AtomicKv? = when {
            spec == "ok" -> net.atlasauth.pca.durable.MemoryDurableKv()
            spec is Map<*, *> && spec["update"] == "fn" -> net.atlasauth.pca.durable.MemoryDurableKv()
            else -> null
        }
        return try { Beacons.createBeaconAcceptor(kv); linkedMapOf("built" to true) } catch (e: IllegalArgumentException) { linkedMapOf("built" to false) }
    }

    private fun issue(a: Map<String, Any?>): Any? = Beacons.issueLivenessBeacon(
        signer(a["issuerSecret"], a["suite"]), if (a.containsKey("instance")) a["instance"] else ComplianceJs.UNDEF, a["seq"], a["issuedAt"], a["scope"], a["validityMs"],
    )

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf("GLOBAL_SCOPE" to Beacons.GLOBAL_SCOPE, "BEACON_EPOCH_MS" to Beacons.EPOCH_MS, "BEACON_MAX_VALIDITY_MS" to Beacons.MAX_VALIDITY_MS, "BEACON_CLOCK_SKEW_MS" to Beacons.CLOCK_SKEW_MS)
        "issueLivenessBeacon" -> issue(map(a[0]))
        "livenessBeaconMessage" -> Beacons.livenessBeaconMessage(a[0])
        "beaconRef" -> Beacons.beaconRef(a[0])
        "verifyLivenessBeacon" -> verdict(Beacons.verifyLivenessBeacon(a[0], a[1]))
        "acceptBeacon" -> verdict(Beacons.acceptBeacon(a[0], a[1]))
        "isFrozenLiveness" -> Beacons.isFrozenLiveness(a[0], a[1])
        "acceptor" -> acceptor(a[0] as List<Any?>)
        "ctor" -> ctor(a[0])
        else -> throw AssertionError("unhandled fn $fn")
    }

    private val unboundOnly = setOf("verifyLivenessBeacon/pq-unbound#114")

    @Test fun everyFunction() {
        val fns = setOf("constants", "issueLivenessBeacon", "livenessBeaconMessage", "beaconRef", "verifyLivenessBeacon", "acceptBeacon", "isFrozenLiveness", "acceptor", "ctor")
        var total = 0
        var refused = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val args = OracleCases.decNum(c["args"]) as List<Any?>
                if (c["name"] in unboundOnly) {
                    val r = map(call(fn, args))
                    assertFalse(c["name"].toString(), r["ok"] == true)
                    assertEquals("bad signature", r["reason"])
                    refused++
                    continue
                }
                val case = LinkedHashMap(c)
                case["args"] = args
                OracleCases.diff(case, c["out"]) { x -> call(fn, x) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(1, refused)
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(174, total)
    }
}
