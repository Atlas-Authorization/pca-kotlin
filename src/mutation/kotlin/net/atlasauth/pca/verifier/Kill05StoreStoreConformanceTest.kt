package net.atlasauth.pca.verifier

import java.lang.reflect.Proxy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for StoreConformance: every check of both profiles is driven to its exact failure note by a scripted store, the
 * rendered report is compared byte for byte, and the scripted backend records every call (handle, key, counter / record), every
 * close and every hook, so the loops, the handle bookkeeping and the hooks are pinned too.
 */
@Suppress("UNCHECKED_CAST")
class Kill05StoreStoreConformanceTest {
    private object Pass

    private fun ise(): Nothing = throw IllegalStateException("boom")

    // ---- the replay / counter profile ----

    /** A linearisable store shared by every handle. `fault(prefix, counter, nth call of that prefix)` answers instead unless it returns Pass. */
    private class Backend(val fault: (String, Long, Int) -> Any?) {
        val last = HashMap<String, Long>()
        val log = ArrayList<String>()
        val calls = HashMap<String, Int>()
        val closes = ArrayList<Int>()
        var opened = 0
        var restarts = 0
        var crashes = 0
        var teardowns = 0
        var forgetOnRestart = false

        fun claim(id: Int, key: String, counter: Long): Authorize.ClaimResult? {
            val prefix = key.substringBefore(':')
            val n = synchronized(this) {
                log.add("$id $prefix $counter")
                val c = (calls[prefix] ?: 0) + 1
                calls[prefix] = c
                c
            }
            val f = fault(prefix, counter, n)
            if (f !== Pass) return f as Authorize.ClaimResult?
            synchronized(this) {
                val prev = last[key]
                if (prev != null && counter <= prev) return Authorize.ClaimResult(false, prev)
                last[key] = counter
                return Authorize.ClaimResult(true)
            }
        }

        @Synchronized
        fun restart() {
            restarts++
            if (forgetOnRestart) last.clear()
        }
    }

    private class CloseableHandle(val b: Backend, val id: Int) : Authorize.StateStore, AutoCloseable {
        override fun claim(key: String, counter: Long): Authorize.ClaimResult? = b.claim(id, key, counter)
        override fun close() {
            synchronized(b) { b.closes.add(id) }
        }
    }

    private class Plain(val b: Backend, val id: Int) : Authorize.StateStore {
        override fun claim(key: String, counter: Long): Authorize.ClaimResult? = b.claim(id, key, counter)
    }

    private fun openHandle(b: Backend, closeable: Boolean): Authorize.StateStore = synchronized(b) {
        val id = b.opened++
        if (closeable) CloseableHandle(b, id) else Plain(b, id)
    }

    private fun runState(b: Backend, rounds: Int = 2, threads: Int = 3, handles: Int = 2, durable: Boolean = true, shared: Boolean = true): StoreConformance.Report =
        StoreConformance.runStateStore(
            { openHandle(b, true) }, durable = durable, shared = shared, crash = { b.crashes++ }, restart = { b.restart() },
            teardown = { b.teardowns++ }, threads = threads, rounds = rounds, handles = handles, name = "fake",
        )

    private fun ok(rounds: Int = 2, threads: Int = 3, handles: Int = 2) = listOf(
        "pass claim-sequence", "pass claim-burst: $rounds rounds x $threads threads",
        "pass claim-concurrent: $rounds rounds x $threads threads over $handles handles", "pass claim-durability", "pass crash-after-claim", "pass retry-after-timeout",
    )

    private fun withLine(base: List<String>, i: Int, line: String): String = base.toMutableList().also { it[i] = line }.joinToString("\n")

    private fun faultState(i: Int, line: String, fault: (String, Long, Int) -> Any?) {
        val r = runState(Backend(fault))
        assertEquals(line, withLine(ok(), i, line), r.render())
        assertFalse(line, r.ok)
        assertEquals(line, listOf(line.substringAfter("fail ").substringBefore(':')), r.failures().map { it.test })
    }

    private fun expectedStateLog(rounds: Int, threads: Int, handles: Int): List<String> {
        val l = ArrayList<String>()
        l += listOf("0 seq 1", "0 seq 1", "0 seq 5", "0 seq 3", "0 seq 5", "0 seq-other 1")
        for (c in 1..rounds) repeat(threads) { l += "1 burst $c" }
        for (c in 1..rounds) for (i in 0 until threads) l += "${2 + i % handles} conc $c"
        l += listOf("${2 + handles} dur 7", "${3 + handles} dur 7", "${4 + handles} dur 8")
        l += listOf("${5 + handles} crash 1", "${6 + handles} crash 1", "${6 + handles} crash 2")
        l += listOf("${7 + handles} retry 1", "${8 + handles} retry 1", "${8 + handles} retry 2", "${7 + handles} retry 3", "${8 + handles} retry 3")
        return l.sorted()
    }

    @Test
    fun aCorrectStatePassesWithEveryCallCloseAndHookAccountedFor() {
        for ((rounds, threads, handles) in listOf(Triple(2, 3, 2), Triple(1, 2, 3))) {
            val b = Backend { _, _, _ -> Pass }
            val r = runState(b, rounds, threads, handles)
            assertEquals(ok(rounds, threads, handles).joinToString("\n"), r.render())
            assertTrue(r.ok)
            assertEquals(emptyList<String>(), r.failures().map { it.test })
            assertEquals("fake", r.name)
            assertEquals(listOf("", "$rounds rounds x $threads threads", "$rounds rounds x $threads threads over $handles handles", "", "", ""), r.results.map { it.note })
            assertEquals(expectedStateLog(rounds, threads, handles), b.log.sorted())
            assertEquals(9 + handles, b.opened)
            // the durability test closes the 3 + handles handles open at that point, the finally block every handle
            assertEquals((0 until 3 + handles).toList() + (0 until 9 + handles).toList(), b.closes)
            assertEquals(listOf(2, 1, 1), listOf(b.restarts, b.crashes, b.teardowns))
        }
    }

    @Test
    fun withoutHooksAndCloseTheChecksStillRun() {
        val b = Backend { _, _, _ -> Pass }
        val r = StoreConformance.runStateStore({ openHandle(b, false) }, threads = 3, rounds = 2, handles = 2)
        assertEquals(ok().joinToString("\n"), r.render())
        assertEquals("state store", r.name)
        assertEquals(expectedStateLog(2, 3, 2), b.log.sorted())
        assertEquals(emptyList<Int>(), b.closes)
    }

    @Test
    fun processLocalStoresSkipExactlyTheSharedAndDurableTests() {
        val b = Backend { _, _, _ -> Pass }
        val r = runState(b, durable = false, shared = false)
        assertEquals(
            listOf(
                "pass claim-sequence", "pass claim-burst: 2 rounds x 3 threads",
                "skip claim-concurrent: the caller declares shared = false (a process-local store)",
                "skip claim-durability: the caller declares durable = false (state dies with the process)",
                "skip crash-after-claim: the caller declares durable = false (state dies with the process)",
                "pass retry-after-timeout",
            ).joinToString("\n"),
            r.render(),
        )
        assertTrue(r.ok)
        assertEquals(listOf(0, 1, 2), b.closes)
        assertEquals(listOf(0, 0, 1), listOf(b.restarts, b.crashes, b.teardowns))
        // durable but not shared: only claim-concurrent is skipped; shared but not durable: only the two durability tests
        val r2 = runState(Backend { _, _, _ -> Pass }, durable = true, shared = false)
        assertEquals(listOf("pass", "pass", "skip", "pass", "pass", "pass"), r2.results.map { it.status })
        val r3 = runState(Backend { _, _, _ -> Pass }, durable = false, shared = true)
        assertEquals(listOf("pass", "pass", "pass", "skip", "skip", "pass"), r3.results.map { it.status })
    }

    @Test
    fun everySequenceCheckHasItsNote() {
        val seq = 0
        faultState(seq, "fail claim-sequence: first claim of counter 1 refused") { p, _, n -> if (p == "seq" && n == 1) Authorize.ClaimResult(false) else Pass }
        faultState(seq, "fail claim-sequence: first claim of counter 1 refused") { p, _, n -> if (p == "seq" && n == 1) null else Pass }
        faultState(seq, "fail claim-sequence: counter 1 claimed twice") { p, _, n -> if (p == "seq" && n == 2) Authorize.ClaimResult(true) else Pass }
        faultState(seq, "fail claim-sequence: a refused claim must report lastCounter=1, got null") { p, _, n -> if (p == "seq" && n == 2) Authorize.ClaimResult(false) else Pass }
        faultState(seq, "fail claim-sequence: a refused claim must report lastCounter=1, got 2") { p, _, n -> if (p == "seq" && n == 2) Authorize.ClaimResult(false, 2L) else Pass }
        faultState(seq, "fail claim-sequence: a refused claim must report lastCounter=1, got null") { p, _, n -> if (p == "seq" && n == 2) null else Pass }
        faultState(seq, "fail claim-sequence: a larger counter (a gap) must be admitted") { p, _, n -> if (p == "seq" && n == 3) Authorize.ClaimResult(false, 1L) else Pass }
        faultState(seq, "fail claim-sequence: an older counter was admitted after 5") { p, _, n -> if (p == "seq" && n == 4) Authorize.ClaimResult(true) else Pass }
        faultState(seq, "fail claim-sequence: counter 5 claimed twice") { p, _, n -> if (p == "seq" && n == 5) Authorize.ClaimResult(true) else Pass }
        faultState(seq, "fail claim-sequence: another key must be independent") { p, _, _ -> if (p == "seq-other") Authorize.ClaimResult(false, 1L) else Pass }
        faultState(seq, "fail claim-sequence: IllegalStateException: boom") { p, _, n -> if (p == "seq" && n == 1) ise() else Pass }
    }

    @Test
    fun everyBurstAndConcurrentCheckHasItsNote() {
        faultState(1, "fail claim-burst: round 1: 3 of 3 concurrent claims of counter 1 were admitted (want exactly 1)") { p, _, _ -> if (p == "burst") Authorize.ClaimResult(true) else Pass }
        faultState(1, "fail claim-burst: round 1: 0 of 3 concurrent claims of counter 1 were admitted (want exactly 1)") { p, _, _ -> if (p == "burst") null else Pass }
        faultState(1, "fail claim-burst: round 2: 3 of 3 concurrent claims of counter 2 were admitted (want exactly 1)") { p, c, _ -> if (p == "burst" && c == 2L) Authorize.ClaimResult(true) else Pass }
        faultState(1, "fail claim-burst: 1 of 3 concurrent calls raised: java.lang.IllegalStateException: boom") { p, _, n -> if (p == "burst" && n == 2) ise() else Pass }
        faultState(1, "fail claim-burst: 3 of 3 concurrent calls raised: java.lang.IllegalStateException: boom") { p, _, _ -> if (p == "burst") ise() else Pass }
        faultState(2, "fail claim-concurrent: round 1: 3 of 3 claims over 2 handles were admitted (want exactly 1)") { p, _, _ -> if (p == "conc") Authorize.ClaimResult(true) else Pass }
        faultState(2, "fail claim-concurrent: round 2: 0 of 3 claims over 2 handles were admitted (want exactly 1)") { p, c, _ -> if (p == "conc" && c == 2L) Authorize.ClaimResult(false) else Pass }
        faultState(2, "fail claim-concurrent: 1 of 3 concurrent calls raised: java.lang.IllegalStateException: boom") { p, _, n -> if (p == "conc" && n == 3) ise() else Pass }
    }

    @Test
    fun everyDurabilityAndCrashCheckHasItsNote() {
        faultState(3, "fail claim-durability: claim refused") { p, _, n -> if (p == "dur" && n == 1) Authorize.ClaimResult(false) else Pass }
        faultState(3, "fail claim-durability: counter 7 was admitted again after the handles were closed (the claim was not durable)") { p, _, n -> if (p == "dur" && n == 2) Authorize.ClaimResult(true) else Pass }
        faultState(3, "fail claim-durability: the next counter must be admitted after a restart") { p, c, _ -> if (p == "dur" && c == 8L) Authorize.ClaimResult(false, 7L) else Pass }
        faultState(4, "fail crash-after-claim: claim refused") { p, _, n -> if (p == "crash" && n == 1) Authorize.ClaimResult(false) else Pass }
        faultState(4, "fail crash-after-claim: the proof admitted before the crash was admitted again") { p, _, n -> if (p == "crash" && n == 2) Authorize.ClaimResult(true) else Pass }
        faultState(4, "fail crash-after-claim: the next counter must be admitted after the crash") { p, c, _ -> if (p == "crash" && c == 2L) Authorize.ClaimResult(false, 1L) else Pass }
        // the lost answer: the commit landed, so the retry is a replay; shared handles see it, one handle when not shared
        faultState(5, "fail retry-after-timeout: a retry after a lost answer was admitted (counter 1 ran twice)") { p, c, n -> if (p == "retry" && c == 1L && n == 2) Authorize.ClaimResult(true) else Pass }
        faultState(5, "fail retry-after-timeout: the next counter must be admitted after a lost answer") { p, c, _ -> if (p == "retry" && c == 2L) Authorize.ClaimResult(false, 1L) else Pass }
        faultState(5, "fail retry-after-timeout: 2 of 2 in-flight claims of counter 3 were admitted (want exactly 1)") { p, c, _ -> if (p == "retry" && c == 3L) Authorize.ClaimResult(true) else Pass }
        faultState(5, "fail retry-after-timeout: 0 of 2 in-flight claims of counter 3 were admitted (want exactly 1)") { p, c, _ -> if (p == "retry" && c == 3L) null else Pass }
        faultState(5, "fail retry-after-timeout: 2 of 2 concurrent calls raised: java.lang.IllegalStateException: boom") { p, c, _ -> if (p == "retry" && c == 3L) ise() else Pass }
        // handles that do not share state while the caller says they do: the retry is re-admitted
        val apart = StoreConformance.runStateStore({ Authorize.MemoryStateStore() }, durable = false, shared = true, threads = 2, rounds = 1, handles = 2)
        assertTrue(apart.render(), apart.failures().any { it.test == "retry-after-timeout" && it.note == "a retry after a lost answer was admitted (counter 1 ran twice)" })
        // a store that forgets on restart fails both durability tests
        val b = Backend { _, _, _ -> Pass }
        b.forgetOnRestart = true
        val r = runState(b)
        assertEquals(
            ok().subList(0, 3).joinToString("\n") +
                "\nfail claim-durability: counter 7 was admitted again after the handles were closed (the claim was not durable)" +
                "\nfail crash-after-claim: the proof admitted before the crash was admitted again\npass retry-after-timeout",
            r.render(),
        )
        assertEquals(listOf("claim-durability", "crash-after-claim"), r.failures().map { it.test })
    }

    // ---- the report itself ----

    private fun report(vararg rs: StoreConformance.TestResult) = StoreConformance.Report("r").also { it.results.addAll(rs) }

    private fun t(status: String, name: String = "t", note: String = "") = StoreConformance.TestResult(name, status, note)

    @Test
    fun reportOkFailuresAndRender() {
        val cases = listOf(
            listOf<String>() to false, listOf("pass") to true, listOf("skip") to false, listOf("fail") to false,
            listOf("pass", "fail") to false, listOf("fail", "pass") to false, listOf("skip", "pass") to true,
            listOf("pass", "skip") to true, listOf("skip", "skip") to false, listOf("pass", "pass") to true, listOf("ok") to false,
        )
        for ((statuses, want) in cases) {
            val r = report(*statuses.map { t(it) }.toTypedArray())
            assertEquals(statuses.toString(), want, r.ok)
        }
        val r = report(t("pass", "a"), t("fail", "b", "why"), t("skip", "c", "x"), t("fail", "d"), t("ok", "e"))
        assertEquals(listOf("b", "d"), r.failures().map { it.test })
        assertEquals("pass a\nfail b: why\nskip c: x\nfail d\nok   e", r.render())
        assertEquals("", report().render())
        assertEquals("ok   z", report(t("ok", "z")).render())
        assertEquals(emptyList<String>(), report(t("pass")).failures().map { it.test })
        val one = t("pass", "n", "note")
        assertEquals(listOf("n", "pass", "note"), listOf(one.test, one.status, one.note))
        assertEquals("", StoreConformance.TestResult("n", "pass").note)
        assertEquals("nm", StoreConformance.Report("nm").name)
    }

    // ---- the operation-record profile ----

    /** Copies everywhere; `fault(op, prefix, nth call of op+prefix, args)` answers instead unless it returns Pass. */
    private class OpBackend {
        var fault: (String, String, Int, List<Any?>) -> Any? = { _, _, _, _ -> Pass }
        val recs = HashMap<String, Map<String, Any?>>()
        val calls = HashMap<String, Int>()
        val created = HashSet<String>()
        val nexts = HashSet<String>()
        val closes = ArrayList<Int>()
        var opened = 0
        var restarts = 0
        var teardowns = 0
        var forgetOnRestart = false

        @Synchronized
        fun restart() {
            restarts++
            if (forgetOnRestart) recs.clear()
        }

        fun norm(o: Any?): String = o.toString().replace(Regex("[0-9a-f]{12}"), "R")

        private fun tick(op: String, id: String): Int = synchronized(this) {
            val k = "$op ${norm(id).substringBefore(':')}"
            val n = (calls[k] ?: 0) + 1
            calls[k] = n
            n
        }

        fun create(r: Map<String, Any?>): Map<String, Any?>? {
            val id = r["id"] as String
            synchronized(this) { created.add(norm(r)) }
            val f = fault("create", id.substringBefore(':'), tick("create", id), listOf(r))
            if (f !== Pass) return f as Map<String, Any?>?
            synchronized(this) {
                val cur = recs[id]
                if (cur != null) return LinkedHashMap(cur)
                recs[id] = LinkedHashMap(r)
                return null
            }
        }

        fun get(id: String): Map<String, Any?>? {
            val f = fault("get", id.substringBefore(':'), tick("get", id), listOf(id))
            if (f !== Pass) return f as Map<String, Any?>?
            synchronized(this) { return recs[id]?.let { LinkedHashMap(it) } }
        }

        fun transition(id: String, from: String, next: Map<String, Any?>): Boolean {
            synchronized(this) { nexts.add(norm(next)) }
            val f = fault("transition", id.substringBefore(':'), tick("transition", id), listOf(id, from, next))
            if (f !== Pass) return f as Boolean
            synchronized(this) {
                val cur = recs[id] ?: return false
                if (cur["state"] != from) return false
                recs[id] = LinkedHashMap(next)
                return true
            }
        }
    }

    private class OpHandle(val b: OpBackend, val hid: Int, val closeable: Boolean) : Operations.Store, AutoCloseable {
        override fun create(record: Map<String, Any?>): Map<String, Any?>? = b.create(record)
        override fun get(id: String): Map<String, Any?>? = b.get(id)
        override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean = b.transition(id, from, next)
        override fun close() {
            if (closeable) synchronized(b) { b.closes.add(hid) }
        }
    }

    private class OpPlain(val b: OpBackend) : Operations.Store {
        override fun create(record: Map<String, Any?>): Map<String, Any?>? = b.create(record)
        override fun get(id: String): Map<String, Any?>? = b.get(id)
        override fun transition(id: String, from: String, next: Map<String, Any?>): Boolean = b.transition(id, from, next)
    }

    private fun runOps(b: OpBackend, rounds: Int = 2, threads: Int = 3, handles: Int = 2, durable: Boolean = true, shared: Boolean = true): StoreConformance.Report =
        StoreConformance.runOperationStore(
            { synchronized(b) { OpHandle(b, b.opened++, true) } }, durable = durable, shared = shared,
            restart = { b.restart() }, teardown = { b.teardowns++ },
            threads = threads, rounds = rounds, handles = handles, name = "ops",
        )

    private fun okOps(rounds: Int = 2, threads: Int = 3, handles: Int = 2) = listOf(
        "pass semantics", "pass copies", "pass create-race: $rounds rounds x $threads threads",
        "pass transition-race: $rounds rounds x $threads threads", "pass cross-handle: over $handles handles", "pass durability",
    )

    private fun faultOps(i: Int, line: String, fault: (OpBackend, String, String, Int, List<Any?>) -> Any?) {
        val b = OpBackend()
        b.fault = { op, p, n, a -> fault(b, op, p, n, a) }
        val r = runOps(b)
        assertEquals(line, withLine(okOps(), i, line), r.render())
        assertFalse(line, r.ok)
    }

    private fun rec(id: String, state: String = "pending", verb: String = "v", exec: Long? = null): String =
        "{id=$id, state=$state, verb=$verb, resource=/r, params_digest=d, reversibility=reversible, startedAt=1" +
            (if (exec != null) ", executingAt=$exec" else "") + "}"

    @Test
    fun aCorrectOperationStorePassesWithEveryCallAndRecordAccountedFor() {
        for ((rounds, threads, handles) in listOf(Triple(2, 3, 2), Triple(1, 2, 3))) {
            val b = OpBackend()
            val r = runOps(b, rounds, threads, handles)
            assertEquals(okOps(rounds, threads, handles).joinToString("\n"), r.render())
            assertTrue(r.ok)
            assertEquals("ops", r.name)
            val created = HashSet<String>()
            created += listOf(rec("op-sem:R"), rec("op-sem:R", verb = "other"), rec("op-copy:R"), rec("op-copy:R-b"), rec("op-shared:R"), rec("op-dur:R"))
            for (k in 0 until rounds) created += listOf(rec("op-create:R:$k"), rec("op-cas:R:$k"))
            assertEquals(created, b.created)
            val nexts = HashSet<String>()
            nexts += listOf(rec("nope"), rec("op-sem:R", "executing"), rec("op-sem:R", "executing", exec = 2L), rec("op-sem:R", "aborted"), rec("op-dur:R", "executing", exec = 3L))
            for (n in 0 until threads) {
                nexts += rec("op-shared:R", "executing", exec = n.toLong())
                for (k in 0 until rounds) nexts += rec("op-cas:R:$k", "executing", exec = n.toLong())
            }
            assertEquals(nexts, b.nexts)
            val calls = mapOf(
                "get op-sem" to 4, "create op-sem" to 2, "transition nope" to 1, "transition op-sem" to 3,
                "create op-copy" to 2, "get op-copy" to 3, "create op-create" to rounds * threads,
                "create op-cas" to rounds, "transition op-cas" to rounds * threads,
                "create op-shared" to threads, "transition op-shared" to threads,
                "create op-dur" to 1, "transition op-dur" to 1, "get op-dur" to 1,
            )
            assertEquals(calls, b.calls)
            assertEquals(6 + handles, b.opened)
            assertEquals((0 until 5 + handles).toList() + (0 until 6 + handles).toList(), b.closes)
            assertEquals(listOf(1, 1), listOf(b.restarts, b.teardowns))
        }
    }

    @Test
    fun operationStoreWithoutHooksOrCloseAndProcessLocal() {
        val b = OpBackend()
        val r = StoreConformance.runOperationStore({ OpPlain(b) }, threads = 3, rounds = 2, handles = 2)
        assertEquals(okOps().joinToString("\n"), r.render())
        assertEquals("operation store", r.name)
        val b2 = OpBackend()
        val r2 = runOps(b2, durable = false, shared = false)
        assertEquals(
            okOps().subList(0, 4).joinToString("\n") +
                "\nskip cross-handle: the caller declares shared = false (a process-local store)" +
                "\nskip durability: the caller declares durable = false (state dies with the process)",
            r2.render(),
        )
        assertTrue(r2.ok)
        assertEquals(listOf(0, 1, 2, 3), b2.closes)
        assertEquals(listOf(0, 1), listOf(b2.restarts, b2.teardowns))
    }

    @Test
    fun everySemanticsCheckHasItsNote() {
        val m: Map<String, Any?> = mapOf("id" to "x")
        faultOps(0, "fail semantics: get of an unknown id must be null") { _, op, p, n, _ -> if (op == "get" && p == "op-sem" && n == 1) m else Pass }
        faultOps(0, "fail semantics: create of a new id must return null") { _, op, p, n, _ -> if (op == "create" && p == "op-sem" && n == 1) m else Pass }
        faultOps(0, "fail semantics: create of an existing id must return the existing record unchanged") { _, op, p, n, _ -> if (op == "create" && p == "op-sem" && n == 2) null else Pass }
        // a store that answers with the record it was handed (verb "other"), not the stored one
        faultOps(0, "fail semantics: create of an existing id must return the existing record unchanged") { _, op, p, n, a -> if (op == "create" && p == "op-sem" && n == 2) a[0] else Pass }
        faultOps(0, "fail semantics: transition of an unknown id must be false") { _, op, p, _, _ -> if (op == "transition" && p == "nope") true else Pass }
        faultOps(0, "fail semantics: transition from the wrong state must be false") { _, op, p, n, _ -> if (op == "transition" && p == "op-sem" && n == 1) true else Pass }
        faultOps(0, "fail semantics: a refused transition changed the record") { b, op, p, n, a ->
            if (op == "transition" && p == "op-sem" && n == 1) {
                synchronized(b) { b.recs[a[0] as String] = LinkedHashMap(a[2] as Map<String, Any?>) }
                false
            } else Pass
        }
        // a record that vanishes reads as null state (not a crash)
        faultOps(0, "fail semantics: a refused transition changed the record") { _, op, p, n, _ -> if (op == "get" && p == "op-sem" && n == 2) null else Pass }
        faultOps(0, "fail semantics: transition from the current state must succeed") { _, op, p, n, _ -> if (op == "transition" && p == "op-sem" && n == 2) false else Pass }
        faultOps(0, "fail semantics: the transition did not store the next record") { _, op, p, n, _ -> if (op == "transition" && p == "op-sem" && n == 2) true else Pass }
        faultOps(0, "fail semantics: the transition did not store the next record") { b, op, p, n, a ->
            if (op == "transition" && p == "op-sem" && n == 2) {
                val next = LinkedHashMap(a[2] as Map<String, Any?>)
                next["executingAt"] = 9L
                synchronized(b) { b.recs[a[0] as String] = next }
                true
            } else Pass
        }
        faultOps(0, "fail semantics: the old state must no longer match") { _, op, p, n, _ -> if (op == "transition" && p == "op-sem" && n == 3) true else Pass }
        faultOps(0, "fail semantics: IllegalStateException: boom") { _, op, p, n, _ -> if (op == "get" && p == "op-sem" && n == 1) ise() else Pass }
    }

    /** A read-only view (TypeIntrinsics: not a MutableMap) whose put would write through to the stored record. */
    private fun writeThrough(b: OpBackend, id: String): Map<String, Any?> {
        val marker = Class.forName("kotlin.jvm.internal.markers.KMappedMarker")
        return Proxy.newProxyInstance(javaClass.classLoader, arrayOf(Map::class.java, marker)) { _, m, args ->
            val stored = synchronized(b) { b.recs[id] } as MutableMap<String, Any?>
            when (m.name) {
                "put" -> stored.put(args!![0] as String, args[1])
                "get" -> stored[args!![0]]
                "equals" -> args!![0] === stored
                "hashCode" -> System.identityHashCode(stored)
                "toString" -> stored.toString()
                else -> m.invoke(stored, *(args ?: emptyArray<Any?>()))
            }
        } as Map<String, Any?>
    }

    @Test
    fun copiesAreCheckedBothWays() {
        // get returns the stored record itself
        faultOps(1, "fail copies: get must return a copy, not the stored record") { b, op, p, _, a -> if (op == "get" && p == "op-copy") synchronized(b) { b.recs[a[0] as String] } else Pass }
        // create keeps the caller's map
        faultOps(1, "fail copies: create must store a copy of the record it was given") { b, op, p, _, a ->
            if (op == "create" && p == "op-copy") {
                val r = a[0] as Map<String, Any?>
                synchronized(b) { b.recs[r["id"] as String] = r }
                null
            } else Pass
        }
        // an immutable copy, and a read-only view that is not a MutableMap, are both fine: nothing is written through them
        for (view in listOf("unmodifiable", "read-only")) {
            val b = OpBackend()
            b.fault = { op, p, _, a ->
                if (op == "get" && p == "op-copy" && !(a[0] as String).endsWith("-b")) {
                    val id = a[0] as String
                    if (view == "unmodifiable") java.util.Collections.unmodifiableMap(LinkedHashMap(synchronized(b) { b.recs[id] }!!)) else writeThrough(b, id)
                } else Pass
            }
            val r = runOps(b)
            assertEquals(view, okOps().joinToString("\n"), r.render())
        }
    }

    @Test
    fun everyRaceAndDurabilityCheckHasItsNote() {
        faultOps(2, "fail create-race: round 0: 3 of 3 concurrent creates reported 'created' (want exactly 1)") { _, op, p, _, _ -> if (op == "create" && p == "op-create") null else Pass }
        faultOps(2, "fail create-race: round 1: 3 of 3 concurrent creates reported 'created' (want exactly 1)") { _, op, p, _, a ->
            if (op == "create" && p == "op-create" && ((a[0] as Map<String, Any?>)["id"] as String).endsWith(":1")) null else Pass
        }
        faultOps(2, "fail create-race: 1 of 3 concurrent calls raised: java.lang.IllegalStateException: boom") { _, op, p, n, _ -> if (op == "create" && p == "op-create" && n == 2) ise() else Pass }
        faultOps(3, "fail transition-race: round 0: 3 of 3 concurrent pending->executing transitions succeeded (want exactly 1)") { _, op, p, _, _ -> if (op == "transition" && p == "op-cas") true else Pass }
        faultOps(3, "fail transition-race: round 1: 0 of 3 concurrent pending->executing transitions succeeded (want exactly 1)") { _, op, p, _, a ->
            if (op == "transition" && p == "op-cas" && (a[0] as String).endsWith(":1")) false else Pass
        }
        faultOps(3, "fail transition-race: 1 of 3 concurrent calls raised: java.lang.IllegalStateException: boom") { _, op, p, n, _ -> if (op == "transition" && p == "op-cas" && n == 2) ise() else Pass }
        faultOps(4, "fail cross-handle: creates over 2 handles: not exactly one 'created'") { _, op, p, _, _ -> if (op == "create" && p == "op-shared") null else Pass }
        faultOps(4, "fail cross-handle: transitions over 2 handles: not exactly one success") { _, op, p, _, _ -> if (op == "transition" && p == "op-shared") true else Pass }
        faultOps(4, "fail cross-handle: 1 of 3 concurrent calls raised: java.lang.IllegalStateException: boom") { _, op, p, n, _ -> if (op == "create" && p == "op-shared" && n == 1) ise() else Pass }
        faultOps(4, "fail cross-handle: 1 of 3 concurrent calls raised: java.lang.IllegalStateException: boom") { _, op, p, n, _ -> if (op == "transition" && p == "op-shared" && n == 1) ise() else Pass }
        faultOps(5, "fail durability: the record did not survive closing every handle") { _, op, p, _, _ -> if (op == "transition" && p == "op-dur") false else Pass }
        val b = OpBackend()
        b.forgetOnRestart = true
        val r = runOps(b)
        assertEquals(withLine(okOps(), 5, "fail durability: the record did not survive closing every handle"), r.render())
    }
}
