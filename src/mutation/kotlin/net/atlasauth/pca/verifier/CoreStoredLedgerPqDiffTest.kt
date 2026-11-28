package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * StoredLedger with post-quantum and hybrid checkpoint suites: reopening documents the reference signed under different pin and suite
 * settings must give the reference's outcomes (differential), and a natively signed hybrid / pure ML-DSA chain must verify on reopen under
 * the pin and be refused without it or under another pin.
 */
@Suppress("UNCHECKED_CAST")
class CoreStoredLedgerPqDiffTest {
    private val module = "ref-core-stored-ledger-pq-java"
    private val hybrid = "hybrid-ed25519-ml-dsa-65"
    private val pure = "ml-dsa-65"

    private fun pq(b: Int): Keys.PqKey = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { b.toByte() })

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun codeOf(t: Throwable): String = if (t is LedgerStoreError) t.code else "Error"

    private fun suiteOf(mode: Any?, g: Keys.EdKey, key: Keys.PqKey): Keys.SuiteKey? = when (mode) {
        "hybrid" -> Keys.suite(hybrid, g, key)
        "ml" -> Keys.suite(pure, null, key)
        else -> null
    }

    private fun options(store: LedgerStore, g: Keys.EdKey, suite: Keys.SuiteKey?, pin: Map<String, Any?>?): StoredLedger.Options {
        val o = StoredLedger.Options()
        o.store = store
        o.guardianKey = g
        o.instanceId = "inst"
        o.principal = "pr"
        val t0 = net.atlasauth.pca.verifier.BaseOracle.T0.toDouble()
        o.clock = { t0 }
        o.suite = suite
        o.pin = pin
        return o
    }

    @Test fun referenceSignedDocuments() = OracleCases.each(module, "storedLedgerPq") { a ->
        val pins = m(a[0])
        val kv = MemoryAtomicKv()
        val store = KvLedgerStore(kv)
        val g = Keys.edFromSeed(OracleCases.seed("stored-ledger-guardian"))
        val key = pq(7)
        val hs = HashMap<String, StoredLedger>()
        var calls = 0L
        val out = ArrayList<Any?>()
        for (oo in a[1] as List<Any?>) {
            val op = oo as List<Any?>
            try {
                val head = op[0] as String
                val v: Any? = when (head) {
                    "kvSet" -> { kv.set(KvLedgerStore.DOC_KEY, StoreJs.deepCopy(op[1])); null }
                    "open" -> {
                        val c = if (op[2] == null) LinkedHashMap<String, Any?>() else m(op[2])
                        val o = options(store, g, suiteOf(c["suite"], g, key), if (c["pin"] == null) null else m(pins[c["pin"] as String]))
                        o.clock = { net.atlasauth.pca.verifier.BaseOracle.T0.toDouble() + 1000.0 * calls++ }
                        val h = StoredLedger.open(o)
                        hs[op[1] as String] = h
                        linkedMapOf("size" to h.size(), "guardian" to h.guardian())
                    }
                    else -> {
                        val h = hs[head]!!
                        when (op[1] as String) {
                            "append" -> { val c = op[2] as String; linkedMapOf("index" to h.append(c), "commit" to c) }
                            "checkpoint" -> {
                                val s = h.checkpoint()
                                linkedMapOf("size" to s["size"], "alg" to s["alg"], "pq" to s.containsKey("pq_sig"), "root" to s["root"], "prev_root" to s["prev_root"])
                            }
                            "latest" -> h.latestCheckpoint()
                            "chain" -> ArrayList<Any?>(h.checkpointChain())
                            "head" -> h.head()
                            "size" -> h.size()
                            else -> throw IllegalStateException("op")
                        }
                    }
                }
                out.add(v)
            } catch (t: Throwable) {
                out.add(linkedMapOf("\$err" to codeOf(t)))
            }
        }
        out
    }

    private fun failsWith(code: String, f: () -> Any?) {
        try { f() } catch (e: LedgerStoreError) { assertEquals(code, e.code); return }
        throw AssertionError("expected $code")
    }

    private fun roundTrip(alg: String, g: Keys.EdKey, suite: Keys.SuiteKey, key: Keys.PqKey) {
        val pin = Keys.pqPin(Keys.suite(hybrid, g, key))
        val store = KvLedgerStore(MemoryAtomicKv())
        val l = StoredLedger.open(options(store, g, suite, pin))
        for (i in 0 until 3) l.append("c$i")
        val a = l.checkpoint()
        for (i in 3 until 6) l.append("c$i")
        val b = l.checkpoint()
        assertEquals(alg, a["alg"])
        assertEquals(alg, b["alg"])
        assertEquals(hybrid == alg, b.containsKey("pq_sig"))
        assertTrue(Ledger.verifyHeadConsistency(a, b, l.consistencyProofFrom(3), g.id(), null, pin))
        assertTrue("no pin: refused", !Ledger.verifyTreeHead(b, g.id(), null, null))
        assertEquals(Json.canonicalize(b), Json.canonicalize(StoredLedger.open(options(store, g, suite, pin)).latestCheckpoint()))
        assertEquals("an auditor needs only the pin", Json.canonicalize(b), Json.canonicalize(StoredLedger.open(options(store, g, null, pin)).latestCheckpoint()))
        failsWith("forged_checkpoint") { StoredLedger.open(options(store, g, null, null)) }
        val other = Keys.pqPin(Keys.suite(hybrid, g, pq(9)))
        failsWith("forged_checkpoint") { StoredLedger.open(options(store, g, null, other)) }
    }

    @Test fun hybridChainRoundTrips() {
        val g = Keys.edFromSeed(OracleCases.seed("w11-pq-hybrid"))
        val key = pq(3)
        roundTrip(hybrid, g, Keys.suite(hybrid, g, key), key)
    }

    @Test fun pureMlDsaChainRoundTrips() {
        val g = Keys.edFromSeed(OracleCases.seed("w11-pq-pure"))
        val key = pq(4)
        roundTrip(pure, g, Keys.suite(pure, null, key), key)
    }

    @Test fun aPqSuiteNeedsAPin() {
        val g = Keys.edFromSeed(OracleCases.seed("w11-pq-pin"))
        val store = KvLedgerStore(MemoryAtomicKv())
        failsWith("pin_missing") { StoredLedger.open(options(store, g, Keys.suite(hybrid, g, pq(5)), null)) }
        assertNotNull(StoredLedger.open(options(store, g, Keys.ed25519(g), null)))
    }

    @Test fun aPinThatDoesNotMatchTheSigningKeyIsRefusedAndNothingIsStored() {
        val g = Keys.edFromSeed(OracleCases.seed("w11-pq-mismatch"))
        val store = KvLedgerStore(MemoryAtomicKv())
        val wrong = Keys.pqPin(Keys.suite(hybrid, g, pq(9)))
        val l = StoredLedger.open(options(store, g, Keys.suite(hybrid, g, pq(8)), wrong))
        l.append("a")
        l.append("b")
        failsWith("forged_checkpoint") { l.checkpoint() }
        assertEquals(0L, store.checkpointCount())
    }
}
