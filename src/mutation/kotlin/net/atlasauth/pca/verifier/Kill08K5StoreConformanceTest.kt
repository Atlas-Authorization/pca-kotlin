package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Kotlin 0.5 mutation kills for the trust-budget and kv-registry profiles of [StoreConformance] (group k5): each profile is run against
 * a recording backend (every call, every close and every hook is accounted for, which pins the constants of the checks and the handle
 * bookkeeping) and against scripted faulty backends, one per check, so each check is driven to its exact failure note.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K5StoreConformanceTest {
    private object Pass

    private fun ise(): Nothing = throw IllegalStateException("boom")

    // ---- the trust-budget profile ----

    /** A linearisable budget store shared by every handle; `fault(op, key prefix, nth call of that op on that prefix)` answers instead unless it returns Pass. */
    private class BB(val fault: (String, String, Int) -> Any?) {
        val map = HashMap<String, Risk.Budget>()
        val log = ArrayList<String>()
        val calls = HashMap<String, Int>()
        val closes = ArrayList<Int>()
        var opened = 0
        var restarts = 0
        var teardowns = 0

        private fun fmt(b: Risk.Budget?) = if (b == null) "null" else "${b.B}/${b.tau}/${b.asOf}"

        private fun tick(entry: String, op: String, prefix: String): Int = synchronized(this) {
            log.add(entry)
            val c = (calls["$op $prefix"] ?: 0) + 1
            calls["$op $prefix"] = c
            c
        }

        fun budget(id: Int, key: String): Risk.Budget? {
            val prefix = key.substringBefore(':')
            val n = tick("$id get $prefix", "get", prefix)
            val f = fault("get", prefix, n)
            if (f !== Pass) return f as Risk.Budget?
            return synchronized(this) { map[key] }
        }

        fun cas(id: Int, key: String, old: Risk.Budget?, new: Risk.Budget): Boolean {
            val prefix = key.substringBefore(':')
            val n = tick("$id cas $prefix ${fmt(old)}>${fmt(new)}", "cas", prefix)
            val f = fault("cas", prefix, n)
            if (f !== Pass) return f as Boolean
            synchronized(this) {
                if (map[key] == old) {
                    map[key] = new
                    return true
                }
                return false
            }
        }

        @Synchronized fun restart() { restarts++ }
    }

    private class BH(val b: BB, val id: Int, val closeable: Boolean) : Authorize.BudgetStore, AutoCloseable {
        override fun budget(key: String): Risk.Budget? = b.budget(id, key)
        override fun budgetCas(key: String, old: Risk.Budget?, new: Risk.Budget): Boolean = b.cas(id, key, old, new)
        override fun close() { synchronized(b) { b.closes.add(id) } }
    }

    private class BPlain(val b: BB, val id: Int) : Authorize.BudgetStore {
        override fun budget(key: String): Risk.Budget? = b.budget(id, key)
        override fun budgetCas(key: String, old: Risk.Budget?, new: Risk.Budget): Boolean = b.cas(id, key, old, new)
    }

    private fun openB(b: BB, closeable: Boolean): Authorize.BudgetStore = synchronized(b) {
        val id = b.opened++
        if (closeable) BH(b, id, true) else BPlain(b, id)
    }

    private fun runBudget(b: BB, rounds: Int = 2, threads: Int = 3, durable: Boolean = true): StoreConformance.Report =
        StoreConformance.runBudgetStore({ openB(b, true) }, durable = durable, restart = { b.restart() }, teardown = { b.teardowns++ }, threads = threads, rounds = rounds, name = "fake")

    private fun okB(rounds: Int = 2, threads: Int = 3) = listOf(
        "pass budget-absent-then-set", "pass budget-conflict", "pass budget-burst: $rounds rounds x $threads threads", "pass budget-keys-independent", "pass budget-durability",
    )

    private fun withLine(base: List<String>, i: Int, line: String): String = base.toMutableList().also { it[i] = line }.joinToString("\n")

    private fun bud(b: Double) = "$b/1000.0/1000.0"

    private fun expectedBudgetLog(rounds: Int, threads: Int, durable: Boolean = true): List<String> {
        val l = ArrayList<String>()
        l += listOf("0 get b1", "0 cas b1 null>${bud(10.0)}", "0 get b1", "0 cas b1 ${bud(10.0)}>${bud(9.0)}", "0 get b1")
        l += listOf(
            "1 cas b2 null>${bud(5.0)}", "1 cas b2 ${bud(99.0)}>${bud(1.0)}", "1 get b2", "1 cas b2 null>${bud(1.0)}", "1 cas b2-absent ${bud(5.0)}>${bud(4.0)}", "1 get b2-absent",
        )
        l += "2 cas b3 null>${bud(100.0)}"
        for (c in 1..rounds) {
            l += "2 get b3"
            repeat(threads) { l += "2 cas b3 ${bud(100.0 - (c - 1))}>${bud(100.0 - c)}" }
            l += "2 get b3"
        }
        l += listOf("3 cas b4a null>${bud(3.0)}", "3 get b4b", "3 cas b4b null>${bud(7.0)}", "3 get b4a")
        if (durable) l += listOf("4 cas b5 null>${bud(8.0)}", "5 get b5")
        return l.sorted()
    }

    @Test
    fun aCorrectBudgetStorePassesWithEveryCallCloseAndHookAccountedFor() {
        for ((rounds, threads) in listOf(2 to 3, 1 to 2)) {
            val b = BB { _, _, _ -> Pass }
            val r = runBudget(b, rounds, threads)
            assertEquals(okB(rounds, threads).joinToString("\n"), r.render())
            assertTrue(r.ok)
            assertEquals("fake", r.name)
            assertEquals(listOf("", "", "$rounds rounds x $threads threads", "", ""), r.results.map { it.note })
            assertEquals(expectedBudgetLog(rounds, threads), b.log.sorted())
            assertEquals(6, b.opened)
            // the durability test closes the 5 handles open at that point, the finally block every handle
            assertEquals((0..4).toList() + (0..5).toList(), b.closes)
            assertEquals(listOf(1, 1), listOf(b.restarts, b.teardowns))
        }
    }

    @Test
    fun aVolatileBudgetStoreSkipsOnlyTheDurabilityCheck() {
        val b = BB { _, _, _ -> Pass }
        val r = runBudget(b, durable = false)
        assertEquals(withLine(okB(), 4, "skip budget-durability: the caller declares durable = false (state dies with the process)"), r.render())
        assertTrue(r.ok)
        assertEquals(expectedBudgetLog(2, 3, durable = false), b.log.sorted())
        assertEquals(4, b.opened)
        assertEquals((0..3).toList(), b.closes)
        assertEquals(listOf(0, 1), listOf(b.restarts, b.teardowns))
    }

    @Test
    fun withoutHooksAndCloseTheBudgetChecksStillRun() {
        val b = BB { _, _, _ -> Pass }
        val r = StoreConformance.runBudgetStore({ openB(b, false) }, threads = 3, rounds = 2)
        assertEquals(okB().joinToString("\n"), r.render())
        assertEquals("budget store", r.name)
        assertEquals(expectedBudgetLog(2, 3), b.log.sorted())
        assertEquals(emptyList<Int>(), b.closes)
        assertEquals(listOf(0, 0), listOf(b.restarts, b.teardowns))
    }

    private fun faultBudget(i: Int, line: String, fault: (String, String, Int) -> Any?) {
        val r = runBudget(BB(fault))
        assertEquals(line, withLine(okB(), i, line), r.render())
        assertFalse(line, r.ok)
        assertEquals(line, listOf(line.substringAfter("fail ").substringBefore(':')), r.failures().map { it.test })
    }

    private fun ghost() = Risk.Budget(1.0, 1.0, 1.0)

    @Test
    fun everyBudgetCheckHasItsNote() {
        // budget-absent-then-set
        faultBudget(0, "fail budget-absent-then-set: a new key must hold no budget") { op, p, n -> if (op == "get" && p == "b1" && n == 1) ghost() else Pass }
        faultBudget(0, "fail budget-absent-then-set: the first CAS (old absent) was refused") { op, p, n -> if (op == "cas" && p == "b1" && n == 1) false else Pass }
        faultBudget(0, "fail budget-absent-then-set: a CAS from the stored budget was refused") { op, p, n -> if (op == "cas" && p == "b1" && n == 2) false else Pass }
        // budget-conflict
        faultBudget(1, "fail budget-conflict: setup CAS refused") { op, p, n -> if (op == "cas" && p == "b2" && n == 1) false else Pass }
        faultBudget(1, "fail budget-conflict: a CAS from a stale budget was applied") { op, p, n -> if (op == "cas" && p == "b2" && n == 2) true else Pass }
        faultBudget(1, "fail budget-conflict: a CAS that expects no budget was applied over a stored one") { op, p, n -> if (op == "cas" && p == "b2" && n == 3) true else Pass }
        faultBudget(1, "fail budget-conflict: a CAS from a budget against an absent one was applied") { op, p, n -> if (op == "cas" && p == "b2-absent" && n == 1) true else Pass }
        faultBudget(1, "fail budget-conflict: a refused CAS created a budget") { op, p, n -> if (op == "get" && p == "b2-absent" && n == 1) ghost() else Pass }
        // budget-burst
        faultBudget(2, "fail budget-burst: setup CAS refused") { op, p, n -> if (op == "cas" && p == "b3" && n == 1) false else Pass }
        faultBudget(2, "fail budget-burst: round 1: 3 of 3 CAS calls on one budget were applied (want exactly 1)") { op, p, n -> if (op == "cas" && p == "b3" && n >= 2) true else Pass }
        faultBudget(2, "fail budget-burst: 3 of 3 concurrent calls raised: java.lang.IllegalStateException: boom") { op, p, n -> if (op == "cas" && p == "b3" && n >= 2) ise() else Pass }
        // budget-keys-independent
        faultBudget(3, "fail budget-keys-independent: CAS refused") { op, p, n -> if (op == "cas" && p == "b4a" && n == 1) false else Pass }
        faultBudget(3, "fail budget-keys-independent: another key must hold no budget") { op, p, n -> if (op == "get" && p == "b4b" && n == 1) ghost() else Pass }
        faultBudget(3, "fail budget-keys-independent: another key must be independent") { op, p, n -> if (op == "cas" && p == "b4b" && n == 1) false else Pass }
        // budget-durability
        faultBudget(4, "fail budget-durability: CAS refused") { op, p, n -> if (op == "cas" && p == "b5" && n == 1) false else Pass }
        faultBudget(4, "fail budget-durability: the budget was lost across a restart") { op, p, n -> if (op == "get" && p == "b5" && n == 1) null else Pass }
    }

    // ---- the kv-registry profile ----

    private val lease by lazy { ParityVectors.load("lease-vectors.json") }
    private val bg by lazy { ParityVectors.load("break-glass-vectors.json") }
    private val bp by lazy { ParityVectors.load("blueprint-vectors.json") }

    /** The state every handle of one scenario shares: the store itself, a log of every document an update wrote, and the close bookkeeping. */
    private class KB(val mode: String, val inner: AtomicKv = MemoryAtomicKv()) {
        val docs = ArrayList<Pair<String, Any?>>()
        val closes = ArrayList<Int>()
        var opened = 0
        var recUpdates = 0
        var teardowns = 0

        @Synchronized fun note(key: String, doc: Any?) { docs.add(key to doc) }

        @Synchronized fun nextRecord(): Int = ++recUpdates
    }

    private class Boom : Error("boom")

    private companion object {
        fun hasUses(doc: Any?): Boolean {
            val grants = (doc as? Map<String, Any?>)?.get("grants") as? Map<String, Any?> ?: return false
            return grants.values.any { ((it as Map<String, Any?>)["uses"] as? List<*>)?.isNotEmpty() == true }
        }
    }

    private class Kv(val b: KB, val id: Int) : AtomicKv, AutoCloseable {
        override fun get(key: String): Any? = if (b.mode == "noepoch" && key == "blueprint/max_epoch") null else b.inner.get(key)

        override fun set(key: String, value: Any?) = b.inner.set(key, value)

        override fun update(key: String, fn: (Any?) -> Any?): Any? {
            val m = b.mode
            if (m == "leasew" && key.startsWith("lease/")) throw IllegalStateException("down")
            if (m == "bgw" && key.startsWith("breakglass/")) throw IllegalStateException("down")
            if (m == "bpw" && key.startsWith("blueprint/")) throw IllegalStateException("down")
            if (m == "nopin" && key == "lease/meta") return fn(null)
            if (m == "bplost" && key.startsWith("blueprint/record/") && b.nextRecord() == 2) return b.inner.update(key) { fn(null) }
            return b.inner.update(key) inner@{ prev ->
                val r = fn(prev)
                if (m == "revw" && ((r as? Map<String, Any?>)?.get("revocations") as? List<*>)?.isNotEmpty() == true) throw IllegalStateException("disk full")
                if (m == "bgdrop" && hasUses(r)) return@inner null
                if (m == "bgboom" && hasUses(r)) throw Boom()
                if (r != null) b.note(key, r)
                r
            }
        }

        override fun close() { synchronized(b) { b.closes.add(id) } }
    }

    private fun openKv(b: KB): AtomicKv = synchronized(b) { Kv(b, b.opened++) }

    private fun runKv(b: KB, opener: () -> AtomicKv = { openKv(b) }, shared: Boolean = true, hook: Boolean = true): StoreConformance.Report =
        if (hook) StoreConformance.runKvRegistries(opener, lease, bg, bp, shared = shared, teardown = { b.teardowns++ }, threads = 4, handles = 2, name = "fake kv")
        else StoreConformance.runKvRegistries(opener, lease, bg, bp, shared = shared, threads = 4, handles = 2)

    private val kvOk = listOf(
        "pass lease-revocation-survives-reopen", "pass lease-shard-count-is-pinned", "pass break-glass-single-use-across-handles: 4 threads over 2 handles",
        "pass blueprint-stale-epoch-is-refused",
    )

    private fun faultKv(mode: String, i: Int, line: String, startsWith: Boolean = false, b: KB = KB(mode)): KB {
        val r = runKv(b)
        val got = r.render().split("\n")
        assertEquals(r.render(), 4, got.size)
        if (startsWith) {
            assertTrue(r.render(), got[i].startsWith(line))
            for (j in 0 until 4) if (j != i) assertEquals(r.render(), kvOk[j], got[j])
        } else {
            assertEquals(line, withLine(kvOk, i, line), r.render())
        }
        assertFalse(line, r.ok)
        assertEquals(line, listOf(kvOk[i].substringAfter("pass ").substringBefore(':')), r.failures().map { it.test })
        return b
    }

    @Test
    fun aCorrectKvPassesAndEveryWriteConstantIsPinned() {
        val b = KB("ok")
        val r = runKv(b)
        assertEquals(kvOk.joinToString("\n"), r.render())
        assertTrue(r.ok)
        assertEquals("fake kv", r.name)
        assertEquals(listOf("", "", "4 threads over 2 handles", ""), r.results.map { it.note })
        // 2 + 1 + (1 + handles + 1) + 2 handles, every one closed once by the finally block, the teardown hook once
        assertEquals(9, b.opened)
        assertEquals((0..8).toList(), b.closes)
        assertEquals(1, b.teardowns)
        // the lease that is revoked is the one named by the FIRST revocation (a lease target, not a prefix)
        val revs = b.docs.filter { it.first.startsWith("lease/3/") }.flatMap { ((it.second as Map<String, Any?>)["revocations"] as List<Map<String, Any?>>) }
        assertTrue(revs.toString(), revs.isNotEmpty())
        for (r0 in revs) assertEquals(r0.toString(), listOf("lease", "L1"), listOf(r0["target"], r0["value"]))
        // the racing uses carry their own clock: the winner's recorded time is 1800000000000 + its thread index
        val uses = b.docs.filter { it.first == "breakglass/holder/agent" }.flatMap { d ->
            ((d.second as Map<String, Any?>)["grants"] as Map<String, Any?>).values.flatMap { (it as Map<String, Any?>)["uses"] as List<Map<String, Any?>> }
        }
        assertTrue(uses.toString(), uses.isNotEmpty())
        for (u in uses) {
            val i = (u["action_digest"] as String).removePrefix("act-").toLong()
            assertEquals(u.toString(), 1800000000000L + i, IntentJs.lng(u["at"]))
        }
    }

    @Test
    fun withoutAHookTheKvChecksStillRun() {
        val b = KB("ok")
        val r = runKv(b, hook = false)
        assertEquals(kvOk.joinToString("\n"), r.render())
        assertEquals("kv registries", StoreConformance.runKvRegistries({ openKv(KB("ok")) }, lease, bg, bp, shared = false).name)
        assertEquals(0, b.teardowns)
    }

    @Test
    fun aKvThatIsNotSharedSkipsEveryRegistryCheck() {
        val b = KB("ok")
        val r = runKv(b, shared = false)
        assertEquals(
            listOf(
                "skip lease-revocation-survives-reopen: the caller declares shared = false", "skip lease-shard-count-is-pinned: the caller declares shared = false",
                "skip break-glass-single-use-across-handles: the caller declares shared = false", "skip blueprint-stale-epoch-is-refused: the caller declares shared = false",
            ).joinToString("\n"),
            r.render(),
        )
        assertFalse(r.ok)
        assertEquals(0, b.opened)
        assertEquals(1, b.teardowns)
    }

    @Test
    fun everyKvCheckHasItsNote() {
        // both lease checks open with an accept
        run {
            val r = runKv(KB("leasew"))
            assertEquals(
                listOf(
                    "fail lease-revocation-survives-reopen: the lease was refused", "fail lease-shard-count-is-pinned: the lease was refused", kvOk[2], kvOk[3],
                ).joinToString("\n"),
                r.render(),
            )
        }
    }

    @Test
    fun aRefusedRevocationIsReported() {
        faultKv("revw", 0, "fail lease-revocation-survives-reopen: the revocation was refused")
    }

    @Test
    fun aKvThatSharesNothingFailsTheCrossHandleChecks() {
        val b = KB("plain")
        val r = runKv(b, opener = { Kv(KB("plain"), 0) })
        val got = r.render().split("\n")
        assertEquals("fail lease-revocation-survives-reopen: a registry on another handle did not see the revocation", got[0])
        assertEquals(kvOk[1], got[1])
        assertEquals("fail break-glass-single-use-across-handles: 0 concurrent uses of a max_uses=1 grant were allowed (want exactly 1)", got[2])
        assertEquals("fail blueprint-stale-epoch-is-refused: an older epoch was accepted on another handle", got[3])
    }

    @Test
    fun aKvThatDoesNotPinTheShardCountIsCaught() {
        faultKv("nopin", 1, "fail lease-shard-count-is-pinned: a registry with another shard count must be refused as store_unreachable")
    }

    @Test
    fun theBreakGlassChecksHaveTheirNotes() {
        faultKv("bgw", 2, "fail break-glass-single-use-across-handles: the grant was refused")
        // a store that loses every write of a use admits every racing use
        faultKv("bgdrop", 2, "fail break-glass-single-use-across-handles: 4 concurrent uses of a max_uses=1 grant were allowed (want exactly 1)")
        // a racing call that raises is reported before the count
        faultKv("bgboom", 2, "fail break-glass-single-use-across-handles: 4 of 4 concurrent calls raised:", startsWith = true)
    }

    @Test
    fun aLaterUseOnAnotherHandleThatFindsTheGrantUnspentIsCaughtWithItsExactVerdictAndClock() {
        // the late registry (the 7th handle of the run) sits on a store that holds the grant accepted but never used
        val pol = BreakGlass.Policy(listOf(bg["authority"] as String), listOf(bg["reviewer"] as String))
        val bg2 = (bg["grants"] as List<Any?>)[1]
        val unspent = KB("plain")
        val seeded = BreakGlass.Registry(pol, Kv(unspent, 0)).accept(bg2, IntentJs.ofLong(1800000000000L))
        assertTrue(seeded.ok)
        val shared = KB("ok")
        var n = 0
        val r = runKv(shared, opener = { synchronized(shared) { if (++n == 7) Kv(unspent, 1) else openKv(shared) } })
        val line = "fail break-glass-single-use-across-handles: a later use of the spent grant on another handle was not refused as budget_exhausted (got allow null)"
        assertEquals(r.render(), withLine(kvOk, 2, line), r.render())
        // the late use was admitted at exactly 1800000000500, notified
        val last = unspent.docs.last { it.first == "breakglass/holder/agent" }.second
        val use = (((last as Map<String, Any?>)["grants"] as Map<String, Any?>)["bg2"] as Map<String, Any?>)["uses"] as List<Map<String, Any?>>
        assertEquals(1, use.size)
        assertEquals("act-late", use[0]["action_digest"])
        assertEquals(1800000000500L, IntentJs.lng(use[0]["at"]))
    }

    @Test
    fun theBlueprintChecksHaveTheirNotes() {
        faultKv("bpw", 3, "fail blueprint-stale-epoch-is-refused: the epoch 3 record was refused")
        faultKv("noepoch", 3, "fail blueprint-stale-epoch-is-refused: the highest epoch must be visible on another handle")
        faultKv("bplost", 3, "fail blueprint-stale-epoch-is-refused: an older epoch was accepted on another handle")
    }

    /** A store that already holds another grant of the holder `agent`, frozen (its first use + review window elapsed) from `frozenFrom` on. */
    private fun frozenFrom(frozenFrom: Long): KB {
        val b = KB("ok")
        val at = 1799999999995L
        val pre = linkedMapOf<String, Any?>(
            "rec" to linkedMapOf<String, Any?>("review_within" to IntentJs.ofLong(frozenFrom - at)),
            "uses" to arrayListOf<Any?>(linkedMapOf<String, Any?>("at" to IntentJs.ofLong(at))),
        )
        b.inner.set("breakglass/holder/agent", linkedMapOf<String, Any?>("grants" to linkedMapOf<String, Any?>("pre" to pre)))
        return b
    }

    @Test
    fun theBreakGlassClocksOfTheProfileAreExactAtTheFreezeBoundary() {
        // frozen only from 1800000000501: the accept (…000), the racing uses (…000 + i) and the late use (…500) are all before it
        assertEquals(kvOk.joinToString("\n"), runKv(frozenFrom(1800000000501L)).render())
        // frozen from 1800000000001: the accept at …000 is still admitted, only the use at …000 wins the race, the late use at …500 finds the holder frozen
        val late = "fail break-glass-single-use-across-handles: a later use of the spent grant on another handle was not refused as budget_exhausted (got deny holder_frozen)"
        assertEquals(withLine(kvOk, 2, late), runKv(frozenFrom(1800000000001L)).render())
    }
}
