package net.atlasauth.pca.verifier

import org.junit.Test

/**
 * Differential test of the durable core stores against the TypeScript reference: every oracle case is one scripted op sequence over a
 * fresh store; each op's result (or typed error code) must equal the reference's.
 */
@Suppress("UNCHECKED_CAST")
class CoreStoresDiffTest {
    private val module = "ref-core-stores-java"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    /** The reference's Number.isSafeInteger argument check: anything else is a RangeError. */
    private fun safe(o: Any?): Long {
        // Number.isSafeInteger: negative zero counts (the strict JSON reader would refuse it)
        val d = StoreJs.dbl(o)
        if (d == null || d.isNaN() || d != Math.floor(d) || Math.abs(d) > 9007199254740991.0) throw IllegalArgumentException("not a safe integer")
        return d.toLong()
    }

    private fun maps(o: List<Map<String, Any?>>): List<Any?> = ArrayList<Any?>(o)

    private fun err(name: String): Map<String, Any?> = linkedMapOf("\$err" to name)

    private fun codeOf(t: Throwable): String = when (t) {
        is LedgerStoreError -> t.code
        is BondStoreError -> t.code
        is BudgetLedgerError -> t.code
        is IllegalArgumentException -> "RangeError"
        else -> "Error"
    }

    private fun script(args: List<Any?>, byMessage: Boolean, f: (List<Any?>) -> Any?): List<Any?> {
        val out = ArrayList<Any?>()
        for (o in l(args[0])) {
            try {
                out.add(f(l(o)))
            } catch (t: Throwable) {
                out.add(err(if (byMessage) t.message.toString() else codeOf(t)))
            }
        }
        return out
    }

    private fun strings(o: Any?): List<String> {
        if (o !is List<*>) throw IllegalArgumentException("not an array")
        return o.map { it as? String ?: throw IllegalArgumentException("not a string") }
    }

    private fun dbl(o: Any?): Double = StoreJs.dbl(o)!!

    @Test fun ledgerStore() = OracleCases.each(module, "ledgerStore") { a ->
        val kv = MemoryAtomicKv()
        val s = KvLedgerStore(kv)
        script(a, false) { op ->
            when (op[0] as String) {
                "size" -> s.size()
                "read" -> s.read(safe(op[1]), safe(op[2]))
                "append" -> s.append(safe(op[1]), strings(op[2])).toJson()
                "cpCount" -> s.checkpointCount()
                "cps" -> s.checkpoints(safe(op[1]))
                "appendCp" -> s.appendCheckpoint(safe(op[1]), StoreJs.map(op[2])).toJson()
                "kvSet" -> { kv.set(KvLedgerStore.DOC_KEY, StoreJs.deepCopy(op[1])); null }
                else -> throw IllegalStateException("op")
            }
        }
    }

    @Test fun storedLedger() = OracleCases.each(module, "storedLedger") { a ->
        val kv = MemoryAtomicKv()
        val store = KvLedgerStore(kv)
        val handles = HashMap<String, StoredLedger>()
        var calls = 0L
        val gkey = Keys.edFromSeed(OracleCases.seed("stored-ledger-guardian"))
        script(a, false) { op ->
            val head = op[0] as String
            when (head) {
                "open" -> {
                    val o = StoredLedger.Options()
                    o.store = store
                    o.guardianKey = if (op.size > 2 && op[2] == "other-key") Keys.edFromSeed(OracleCases.seed("other")) else gkey
                    o.instanceId = if (op.size > 3 && op[3] != null) op[3] as String else "inst"
                    o.principal = "pr"
                    o.clock = { 1_800_000_000_000.0 + 1000.0 * calls++ }
                    val h = StoredLedger.open(o)
                    handles[op[1] as String] = h
                    linkedMapOf("size" to h.size(), "guardian" to h.guardian())
                }
                "kvSet" -> { kv.set(KvLedgerStore.DOC_KEY, StoreJs.deepCopy(op[1])); null }
                "kvGet" -> StoreJs.deepCopy(kv.get(KvLedgerStore.DOC_KEY))
                else -> {
                    val h = handles[head]!!
                    when (op[1] as String) {
                        "append" -> { val c = op[2] as String; linkedMapOf("index" to h.append(c), "commit" to c) }
                        "checkpoint" -> h.checkpoint()
                        "catchUp" -> { h.catchUp(); null }
                        "head" -> h.head()
                        "size" -> h.size()
                        "incl" -> h.inclusionProof(safe(op[2]))
                        "consFrom" -> h.consistencyProofFrom(safe(op[2]))
                        "commits" -> ArrayList<Any?>(h.commits())
                        "latest" -> h.latestCheckpoint()
                        "chain" -> maps(h.checkpointChain())
                        "guardian" -> h.guardian()
                        else -> throw IllegalStateException("op")
                    }
                }
            }
        }
    }

    @Test fun bondStore() = OracleCases.each(module, "bondStore") { a ->
        val kv = MemoryAtomicKv()
        val s = KvBondStore(kv)
        script(a, false) { op ->
            when (op[0] as String) {
                "read" -> s.read(op[1] as String, op[2] as String?).toJson()
                "commit" -> s.commit(m(op[1]), dbl(op[2])).toJson()
                "deposit" -> StoreJs.num(s.deposit(op[1] as String, dbl(op[2])))
                "kvSet" -> { kv.set(KvBondStore.DOC_KEY, StoreJs.deepCopy(op[1])); null }
                "kvGet" -> StoreJs.deepCopy(kv.get(KvBondStore.DOC_KEY))
                else -> throw IllegalStateException("op")
            }
        }
    }

    private fun request(o: Any?): BudgetLedger.ReserveRequest {
        val m = m(o)
        val r = BudgetLedger.ReserveRequest()
        r.event = StoreJs.map(m["event"])
        r.accumulators = (m["accumulators"] as? List<*>)?.map { it as Map<String, Any?> }
        r.schema = m["schema"]
        if (m.containsKey("expectedVersion")) r.expectedVersion = safe(m["expectedVersion"])
        if (m.containsKey("expiresAt")) r.expiresAt = safe(m["expiresAt"])
        return r
    }

    private fun reservations(o: Any?): List<Budgets.Reservation> = l(o).map { Budgets.Reservation(m(it)["key"] as String, m(it)["id"] as String) }

    @Test fun budgetLedger() = OracleCases.each(module, "budgetLedger") { a ->
        val rkey = Keys.edFromSeed(OracleCases.seed("release-signer"))
        val kv = MemoryAtomicKv()
        var ledger: KvBudgetLedger? = null
        val log = KvLedgerStore(MemoryAtomicKv())
        script(a, false) { op ->
            when (op[0] as String) {
                "new" -> { ledger = KvBudgetLedger(kv, op[1] as Boolean); ledger!!.durable() }
                "snapshot" -> ledger!!.snapshot(op[1] as String).toJson()
                "reserve" -> ledger!!.reserve(op[1] as String, request(op[2])).toJson()
                "start" -> ledger!!.start(op[1] as String, op[2] as String).toJson()
                "commit" -> ledger!!.commit(op[1] as String, op[2] as String).toJson()
                "release" -> ledger!!.release(op[1] as String, op[2] as String, op[3]?.let { m(it) }).toJson()
                "expire" -> ledger!!.expire(op[1] as String, safe(op[2])).toJson()
                "signRelease" -> Budgets.signRelease(op[1] as String, op[2] as String, op[3] as String, safe(op[4]), rkey)
                "verifyRelease" -> Budgets.verifyRelease(op[1], if (op[2] == "signer") rkey.id() else op[2] as String?)
                "releaseCommit" -> listOf(Budgets.releaseDigest(m(op[1])), Budgets.releaseCommit(m(op[1])))
                "anchor" -> listOf(StoreJs.num(Budgets.anchorRelease(log, m(op[1]))), StoreJs.num(log.size()))
                "scopeKey" -> Budgets.scopeKey(op[1] as String, op[2] as String)
                "kvSet" -> { kv.set(op[1] as String, StoreJs.deepCopy(op[2])); null }
                "admit" -> {
                    val ad = m(op[1])
                    val ids = LinkedHashMap<String, String>()
                    for ((k, v) in m(ad["ids"])) ids[k] = v as String
                    val accs = l(ad["accumulators"]).map { m(it) }
                    val allow = ad["allow"] as Boolean
                    val r = Budgets.admitAggregateAction(
                        ledger, ids, accs, null, m(ad["event"]), { state -> linkedMapOf<String, Any?>("allow" to allow, "state" to state) },
                        if (ad.containsKey("expiresAt")) safe(ad["expiresAt"]) else null, if (ad.containsKey("maxAttempts")) safe(ad["maxAttempts"]).toInt() else null,
                    )
                    val out = LinkedHashMap<String, Any?>()
                    out["admitted"] = r.admitted
                    if (r.reason != null) out["reason"] = r.reason
                    if (r.verdict != null) out["verdict"] = r.verdict
                    if (r.reservations != null) out["reservations"] = r.reservations!!.map { linkedMapOf<String, Any?>("key" to it.key, "id" to it.id) }
                    if (r.state != null) out["state"] = r.state
                    out
                }
                "startAgg" -> Budgets.startAggregate(ledger!!, reservations(op[1]))
                "settleAgg" -> Budgets.settleAggregate(ledger!!, reservations(op[1]), op[2] as String).map { it.toJson() }
                else -> throw IllegalStateException("op")
            }
        }
    }

    @Test fun meshWitness() = OracleCases.each(module, "meshWitness") { a ->
        val stores = HashMap<String, MemoryMeshWitnessStore>()
        val witnesses = HashMap<String, MeshWitness>()
        val domains = HashMap<String, MeshDomain>()
        fun key(label: Any?) = Keys.edFromSeed(OracleCases.seed(label as String))
        script(a, true) { op ->
            when (op[0] as String) {
                "store" -> { stores[op[1] as String] = MemoryMeshWitnessStore(); true }
                "witness" -> {
                    val o = MeshWitness.Options()
                    if (op[2] != null) o.store = stores[op[2] as String]
                    val w = MeshWitness(key(op[3]), o)
                    witnesses[op[1] as String] = w
                    w.id
                }
                "witnessClock" -> {
                    val o = MeshWitness.Options()
                    val now = dbl(op[3])
                    o.clock = { now }
                    if (op[4] != null) o.maxClockSkewMs = dbl(op[4])
                    witnesses[op[1] as String] = MeshWitness(key(op[2]), o)
                    true
                }
                "restart" -> {
                    val o = MeshWitness.Options()
                    o.store = stores[op[2] as String]
                    val w = MeshWitness(key(op[3]), o)
                    witnesses[op[1] as String] = w
                    w.exportState()
                }
                "domain" -> { val d = MeshDomain(op[1] as String, key(op[2])); domains[op[1] as String] = d; d.id }
                "record" -> {
                    val label = op[2] as String
                    val cav = linkedMapOf<String, Any?>("type" to "scope", "actions" to arrayListOf<Any?>(label))
                    domains[op[1] as String]!!.record(linkedMapOf("id" to label, "caveats" to arrayListOf<Any?>(cav)))
                }
                "revoke" -> { domains[op[1] as String]!!.revoke(op[2] as String); null }
                "publish" -> domains[op[1] as String]!!.publishHead(l(op[3]).map { witnesses[it as String]!! }, dbl(op[2]), op[4]?.let { safe(it).toInt() })
                "lastSeen" -> witnesses[op[1] as String]!!.lastSeen(op[2] as String)
                "export" -> witnesses[op[1] as String]!!.exportState()
                "import" -> { witnesses[op[1] as String]!!.importState(m(op[2])); null }
                "load" -> stores[op[1] as String]!!.load()
                "save" -> { stores[op[1] as String]!!.save(m(op[2])); null }
                "domainId" -> domains[op[1] as String]!!.id
                else -> throw IllegalStateException("op")
            }
        }
    }
}
