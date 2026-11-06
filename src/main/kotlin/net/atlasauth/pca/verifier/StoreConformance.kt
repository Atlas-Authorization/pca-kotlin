package net.atlasauth.pca.verifier

import java.util.UUID
import java.util.concurrent.CyclicBarrier

/**
 * A reusable conformance helper for the stores behind `authorize`: run the replay / counter and operation-record contracts against
 * YOUR store. Pass a factory that opens a handle on the backend (one handle = one verifier instance's connection to the shared
 * backend) and read the report.
 *
 * ```kotlin
 * val report = StoreConformance.runStateStore({ MyStateStore(dsn) })   // claim(key, counter) -> ClaimResult
 * check(report.ok) { report.render() }
 * ```
 *
 * The state-store profile runs the store's `claim(key, counter)` as the replay invariant "a counter goes from unconsumed to consumed
 * at most once, however many copies arrive":
 *  - `claim-sequence`    strict increase on one key; replays and older counters refused (with `lastCounter`); keys independent;
 *  - `claim-burst`       N threads race one (key, counter) on ONE handle, every round, then the next counter: exactly one wins;
 *  - `claim-concurrent`  the same race spread over K handles (a store only an in-process lock can serialise fails here);
 *  - `claim-durability`  a claim survives closing every handle and `restart()`;
 *  - `crash-after-claim` the instance dies after the admission (`crash()` when given): the same counter stays consumed and the next
 *    one is admitted.
 *
 * The operation-store profile checks `create` (atomic create-if-absent), `transition` (a compare-and-set on the state), `get` (a copy,
 * never an alias) and durability. A declared `durable = false` / `shared = false` (a process-local store) skips the tests that need
 * them; everything else is a failure, never a skip. Tests run with real threads on this machine's scheduler: a racy store is caught
 * with overwhelming probability per round, so run it more than once for a store you wrote. A handle that is `AutoCloseable` is closed
 * when the durability tests close the handles.
 */
object StoreConformance {
    /** One test's outcome: `status` is `pass`, `fail` or `skip`. */
    class TestResult(val test: String, val status: String, val note: String = "")

    class Report(val name: String) {
        val results = ArrayList<TestResult>()

        // plain loops throughout this helper (no inline collection functions): every branch is one a test can reach
        /** True when nothing failed and at least one test passed. */
        val ok: Boolean
            get() {
                var passed = false
                for (r in results) {
                    if (r.status == "fail") return false
                    if (r.status == "pass") passed = true
                }
                return passed
            }

        fun failures(): List<TestResult> {
            val out = ArrayList<TestResult>()
            for (r in results) if (r.status == "fail") out.add(r)
            return out
        }

        fun render(): String {
            val sb = StringBuilder()
            var first = true
            for (r in results) {
                if (!first) sb.append('\n')
                first = false
                sb.append(r.status.padEnd(4, ' ')).append(' ').append(r.test)
                if (r.note != "") sb.append(": ").append(r.note)
            }
            return sb.toString()
        }
    }

    private class Skip(val msg: String) : RuntimeException(msg)

    private class Failure(val msg: String) : RuntimeException(msg)

    private fun require(cond: Boolean, msg: () -> String) {
        if (!cond) throw Failure(msg())
    }

    /** Run `fn(i)` in `n` threads released together; the results in order (an exception is returned as a value). */
    private fun race(n: Int, fn: (Int) -> Any?): List<Any?> {
        val gate = CyclicBarrier(n)
        val out = arrayOfNulls<Any>(n)
        val ts = ArrayList<Thread>()
        for (i in 0 until n) {
            ts.add(
                Thread {
                    try {
                        gate.await()
                        out[i] = fn(i)
                    } catch (e: Throwable) { // a store that fails under load is reported, not hidden
                        out[i] = e
                    }
                },
            )
        }
        for (t in ts) t.start()
        for (t in ts) t.join()
        return out.toList()
    }

    private fun count(rs: List<Any?>, p: (Any?) -> Boolean): Int {
        var n = 0
        for (r in rs) if (p(r)) n++
        return n
    }

    private fun noErrors(rs: List<Any?>) {
        val errs = ArrayList<Throwable>()
        for (r in rs) if (r is Throwable) errs.add(r)
        require(errs.isEmpty()) { "${errs.size} of ${rs.size} concurrent calls raised: ${errs[0]}" }
    }

    private fun close(h: Any?) {
        if (h is AutoCloseable) h.close()
    }

    private fun run(report: Report, name: String, fn: () -> String?) {
        try {
            report.results.add(TestResult(name, "pass", fn() ?: ""))
        } catch (s: Skip) {
            report.results.add(TestResult(name, "skip", s.msg))
        } catch (f: Failure) {
            report.results.add(TestResult(name, "fail", f.msg))
        } catch (e: Exception) {
            report.results.add(TestResult(name, "fail", "${e.javaClass.simpleName}: ${e.message}"))
        }
    }

    private fun claimed(r: Authorize.ClaimResult?): Boolean = r != null && r.ok

    // ---- replay / counter store ----

    /**
     * Run the replay-store contract (see the object doc). `openStore()` returns a handle; `durable = false` / `shared = false` declare
     * a process-local store (its durability and cross-handle tests are skipped). `crash()` kills the backend / instance abruptly and
     * `restart()` brings it back (both optional); `teardown()` runs last.
     */
    @JvmOverloads
    fun runStateStore(
        openStore: () -> Authorize.StateStore, durable: Boolean = true, shared: Boolean = true, crash: (() -> Unit)? = null,
        restart: (() -> Unit)? = null, teardown: (() -> Unit)? = null, threads: Int = 16, rounds: Int = 5, handles: Int = 4,
        name: String = "state store",
    ): Report {
        val report = Report(name)
        val runId = UUID.randomUUID().toString().replace("-", "").substring(0, 12)
        val opened = ArrayList<Authorize.StateStore>()

        fun handle(): Authorize.StateStore {
            val h = openStore()
            opened.add(h)
            return h
        }

        try {
            run(report, "claim-sequence") {
                val s = handle()
                val k = "seq:$runId"
                val other = "seq-other:$runId"
                require(claimed(s.claim(k, 1))) { "first claim of counter 1 refused" }
                val r = s.claim(k, 1)
                require(!claimed(r)) { "counter 1 claimed twice" }
                require(r != null && r.lastCounter == 1L) { "a refused claim must report lastCounter=1, got ${r?.lastCounter}" }
                require(claimed(s.claim(k, 5))) { "a larger counter (a gap) must be admitted" }
                require(!claimed(s.claim(k, 3))) { "an older counter was admitted after 5" }
                require(!claimed(s.claim(k, 5))) { "counter 5 claimed twice" }
                require(claimed(s.claim(other, 1))) { "another key must be independent" }
                null
            }
            run(report, "claim-burst") {
                val s = handle()
                val k = "burst:$runId"
                for (c in 1..rounds) {
                    val rs = race(threads) { s.claim(k, c.toLong()) }
                    noErrors(rs)
                    val wins = count(rs) { claimed(it as Authorize.ClaimResult?) }
                    require(wins == 1) { "round $c: $wins of $threads concurrent claims of counter $c were admitted (want exactly 1)" }
                }
                "$rounds rounds x $threads threads"
            }
            run(report, "claim-concurrent") {
                if (!shared) throw Skip("the caller declares shared = false (a process-local store)")
                val hs = ArrayList<Authorize.StateStore>()
                for (j in 0 until handles) hs.add(handle())
                val k = "conc:$runId"
                for (c in 1..rounds) {
                    val rs = race(threads) { i -> hs[i % handles].claim(k, c.toLong()) }
                    noErrors(rs)
                    val wins = count(rs) { claimed(it as Authorize.ClaimResult?) }
                    require(wins == 1) { "round $c: $wins of $threads claims over $handles handles were admitted (want exactly 1)" }
                }
                "$rounds rounds x $threads threads over $handles handles"
            }
            run(report, "claim-durability") {
                if (!durable) throw Skip("the caller declares durable = false (state dies with the process)")
                val k = "dur:$runId"
                require(claimed(handle().claim(k, 7))) { "claim refused" }
                for (h in opened) close(h)
                restart?.invoke()
                require(!claimed(handle().claim(k, 7))) { "counter 7 was admitted again after the handles were closed (the claim was not durable)" }
                require(claimed(handle().claim(k, 8))) { "the next counter must be admitted after a restart" }
                null
            }
            run(report, "crash-after-claim") {
                if (!durable) throw Skip("the caller declares durable = false (state dies with the process)")
                val k = "crash:$runId"
                require(claimed(handle().claim(k, 1))) { "claim refused" }
                // the instance dies right after the admission, before its handler ran: no close, no cleanup
                crash?.invoke()
                restart?.invoke()
                val again = handle()
                require(!claimed(again.claim(k, 1))) { "the proof admitted before the crash was admitted again" }
                require(claimed(again.claim(k, 2))) { "the next counter must be admitted after the crash" }
                null
            }
            run(report, "retry-after-timeout") {
                val k = "retry:$runId"
                val first = handle()
                val other = if (shared) handle() else first
                first.claim(k, 1) // the commit lands, its answer is lost: the caller retries (on another instance when shared)
                require(!claimed(other.claim(k, 1))) { "a retry after a lost answer was admitted (counter 1 ran twice)" }
                require(claimed(other.claim(k, 2))) { "the next counter must be admitted after a lost answer" }
                // the first commit is still in flight when the caller retries elsewhere: exactly one of the two is admitted
                val rs = race(2) { i -> (if (i == 0) first else other).claim(k, 3) }
                noErrors(rs)
                val wins = count(rs) { claimed(it as Authorize.ClaimResult?) }
                require(wins == 1) { "$wins of 2 in-flight claims of counter 3 were admitted (want exactly 1)" }
                null
            }
        } finally {
            for (h in opened) try { close(h) } catch (e: Exception) { /* best effort */ }
            teardown?.invoke()
        }
        return report
    }

    // ---- operation-record store ----

    private fun record(id: String, state: String, executingAt: Long?): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["id"] = id
        m["state"] = state
        m["verb"] = "v"
        m["resource"] = "/r"
        m["params_digest"] = "d"
        m["reversibility"] = "reversible"
        m["startedAt"] = 1L
        if (executingAt != null) m["executingAt"] = executingAt
        return m
    }

    /**
     * Run the operation-store contract: `create(record)` returns null or the existing record, `get(id)`, `transition(id, from, next)`
     * (see [Operations.Store]).
     */
    @JvmOverloads
    fun runOperationStore(
        openStore: () -> Operations.Store, durable: Boolean = true, shared: Boolean = true, restart: (() -> Unit)? = null,
        teardown: (() -> Unit)? = null, threads: Int = 16, rounds: Int = 5, handles: Int = 4, name: String = "operation store",
    ): Report {
        val report = Report(name)
        val runId = UUID.randomUUID().toString().replace("-", "").substring(0, 12)
        val opened = ArrayList<Operations.Store>()

        fun handle(): Operations.Store {
            val h = openStore()
            opened.add(h)
            return h
        }

        fun stateOf(s: Operations.Store, id: String): Any? = s.get(id)?.get("state")

        try {
            run(report, "semantics") {
                val s = handle()
                val i = "op-sem:$runId"
                require(s.get(i) == null) { "get of an unknown id must be null" }
                require(s.create(record(i, "pending", null)) == null) { "create of a new id must return null" }
                val dup = record(i, "pending", null)
                dup["verb"] = "other"
                val again = s.create(dup)
                require(again != null && again["verb"] == "v") { "create of an existing id must return the existing record unchanged" }
                require(!s.transition("nope:$runId", "pending", record("nope", "pending", null))) { "transition of an unknown id must be false" }
                require(!s.transition(i, "executing", record(i, "executing", null))) { "transition from the wrong state must be false" }
                require(stateOf(s, i) == "pending") { "a refused transition changed the record" }
                require(s.transition(i, "pending", record(i, "executing", 2L))) { "transition from the current state must succeed" }
                require(stateOf(s, i) == "executing" && IntentJs.num(s.get(i)?.get("executingAt")) == 2.0) { "the transition did not store the next record" }
                require(!s.transition(i, "pending", record(i, "aborted", null))) { "the old state must no longer match" }
                null
            }
            run(report, "copies") {
                val s = handle()
                val i = "op-copy:$runId"
                s.create(record(i, "pending", null))
                val got = s.get(i)
                try { (got as? MutableMap<String, Any?>)?.put("state", "committed") } catch (e: UnsupportedOperationException) { /* immutable: cannot alias */ }
                require(stateOf(s, i) == "pending") { "get must return a copy, not the stored record" }
                val mine = record("$i-b", "pending", null)
                s.create(mine)
                mine["state"] = "failed"
                require(stateOf(s, "$i-b") == "pending") { "create must store a copy of the record it was given" }
                null
            }
            run(report, "create-race") {
                val s = handle()
                for (r in 0 until rounds) {
                    val i = "op-create:$runId:$r"
                    val rs = race(threads) { s.create(record(i, "pending", null)) }
                    noErrors(rs)
                    val wins = count(rs) { it == null }
                    require(wins == 1) { "round $r: $wins of $threads concurrent creates reported 'created' (want exactly 1)" }
                }
                "$rounds rounds x $threads threads"
            }
            run(report, "transition-race") {
                val s = handle()
                for (r in 0 until rounds) {
                    val i = "op-cas:$runId:$r"
                    s.create(record(i, "pending", null))
                    val rs = race(threads) { n -> s.transition(i, "pending", record(i, "executing", n.toLong())) }
                    noErrors(rs)
                    val wins = count(rs) { it == true }
                    require(wins == 1) { "round $r: $wins of $threads concurrent pending->executing transitions succeeded (want exactly 1)" }
                }
                "$rounds rounds x $threads threads"
            }
            run(report, "cross-handle") {
                if (!shared) throw Skip("the caller declares shared = false (a process-local store)")
                val hs = ArrayList<Operations.Store>()
                for (j in 0 until handles) hs.add(handle())
                val i = "op-shared:$runId"
                var rs = race(threads) { n -> hs[n % handles].create(record(i, "pending", null)) }
                noErrors(rs)
                require(count(rs) { it == null } == 1) { "creates over $handles handles: not exactly one 'created'" }
                rs = race(threads) { n -> hs[n % handles].transition(i, "pending", record(i, "executing", n.toLong())) }
                noErrors(rs)
                require(count(rs) { it == true } == 1) { "transitions over $handles handles: not exactly one success" }
                "over $handles handles"
            }
            run(report, "durability") {
                if (!durable) throw Skip("the caller declares durable = false (state dies with the process)")
                val i = "op-dur:$runId"
                val h = handle()
                h.create(record(i, "pending", null))
                h.transition(i, "pending", record(i, "executing", 3L))
                for (o in opened) close(o)
                restart?.invoke()
                val got = handle().get(i)
                require(got != null && got["state"] == "executing" && IntentJs.num(got["executingAt"]) == 3.0) { "the record did not survive closing every handle" }
                null
            }
        } finally {
            for (h in opened) try { close(h) } catch (e: Exception) { /* best effort */ }
            teardown?.invoke()
        }
        return report
    }
}
