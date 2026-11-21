package net.atlasauth.pca.storeconformance

/**
 * The conformance run: every test for every operation the adapter implements, each history checked for linearizability, with a
 * report (text or JSON). A PASS is evidence, not proof: the kit checks the histories it observed. A FAIL is a proof of a contract
 * violation (the counterexample is a recorded history that no sequential order explains), unless the adapter itself is mis-wired.
 */
object Runner {
    /** Workload, checker and crash settings of a run. */
    open class ConformanceOptions : Workloads.WorkloadOptions() {
        /** Which tests to run (default all). */
        var tests: List<String>? = null
        var check: Kit.CheckOptions = Kit.CheckOptions()

        /** The crash test needs an adapter supplier over the shared backend (each "process" opens its own). Without it: skipped. */
        var crash: Crash.CrashOptions? = null
    }

    /** One test's report: `status` is pass, fail, skip or unresolved. */
    class TestReport internal constructor(
        val test: String,
        val kind: String,
        val status: String,
        val ops: Int,
        val keys: Int,
        val errors: Int,
        val violations: List<Kit.KeyResult>,
        val unresolved: Int,
        val note: String?,
    ) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["test"] = test
            m["kind"] = kind
            m["status"] = status
            m["ops"] = ops
            m["keys"] = keys
            m["errors"] = errors
            m["violations"] = Kit.keyResultsJson(violations)
            m["unresolved"] = unresolved
            if (note != null) m["note"] = note
            return m
        }
    }

    class ConformanceReport internal constructor(val adapter: String, val status: String, val tests: List<TestReport>) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["adapter"] = adapter
            m["status"] = status
            val ts = ArrayList<Any?>()
            for (t in tests) ts.add(t.toJson())
            m["tests"] = ts
            return m
        }

        fun format(): String = Kit.formatReport(toJson(), 3.0)
        fun json(): String = Kit.reportJson(toJson())
        fun ok(): Boolean = status == "pass"
    }

    /** Which operations the adapter implements: declared capabilities win, else what its first client exposes. */
    fun detectKinds(adapter: StoreAdapter): List<String> {
        val caps = adapter.capabilities() ?: StoreAdapter.Capabilities()
        val c = adapter.open()
        try {
            val kinds = ArrayList<String>()
            if (caps.consumeOnce ?: c.hasConsumeOnce()) kinds.add("consume")
            if (caps.advance ?: c.hasAdvance()) kinds.add("advance")
            return kinds
        } finally {
            c.close()
        }
    }

    private fun judge(test: String, kind: String, w: Workloads.WorkloadResult, opts: Kit.CheckOptions): TestReport {
        val h = Kit.checkHistory(w.ops, opts)
        val definite = h.outcomes[0] + h.outcomes[1]
        val status = if (h.violations.isNotEmpty()) "fail" else if (h.unresolved.isNotEmpty() || definite == 0) "unresolved" else "pass"
        val notes = ArrayList<String>()
        val wn = w.note
        if (wn != null && wn.isNotEmpty()) notes.add(wn)
        if (definite == 0) notes.add("no definite answer was observed (every call failed or timed out)")
        return TestReport(test, kind, status, h.ops, h.keys, w.errors, h.violations, h.unresolved.size, if (notes.isEmpty()) null else notes.joinToString("; "))
    }

    private fun skip(test: String, kind: String, note: String): TestReport = TestReport(test, kind, "skip", 0, 0, 0, ArrayList(), 0, note)

    fun runTest(adapter: StoreAdapter, test: String, kind: String, opts: ConformanceOptions): TestReport {
        if (test == "durability" && adapter.capabilities()?.durable == false) {
            return skip(test, kind, "the adapter declares durable: false (only correct for one process whose lifetime covers the action lifetime)")
        }
        val crashOpts = opts.crash
        if (test == "crash" && (crashOpts == null || crashOpts.adapters == null)) {
            return skip(test, kind, "needs an adapter supplier over the shared backend (the crash test runs the adapter in several client processes)")
        }
        val w: Workloads.WorkloadResult = when (test) {
            "burst" -> Workloads.runBurst(adapter, kind, opts)
            "concurrent" -> Workloads.runConcurrent(adapter, kind, opts)
            "retention" -> Workloads.runRetention(adapter, kind, opts)
            "durability" -> Workloads.runDurability(adapter, kind, opts)
            "crash" -> {
                val c = crashOpts!!
                c.clients = c.clients ?: opts.clients
                c.durationMs = c.durationMs ?: opts.durationMs
                c.windowMs = c.windowMs ?: opts.windowMs
                c.spread = c.spread ?: opts.spread
                c.values = c.values ?: opts.values
                c.retentionMs = c.retentionMs ?: opts.retentionMs
                c.opTimeoutMs = c.opTimeoutMs ?: opts.opTimeoutMs
                c.namespace = c.namespace ?: opts.namespace
                c.seed = c.seed ?: opts.seed
                Crash.runCrash(kind, c)
            }
            else -> throw IllegalArgumentException("unknown test $test")
        }
        return judge(test, kind, w, opts.check)
    }

    fun runConformance(adapter: StoreAdapter, opts: ConformanceOptions? = null): ConformanceReport {
        val o = opts ?: ConformanceOptions()
        val kinds = detectKinds(adapter)
        if (kinds.isEmpty()) throw IllegalArgumentException(adapter.name() + ": the client implements neither consumeOnce nor advance")
        val tests = ArrayList<TestReport>()
        for (test in o.tests ?: Kit.ALL_TESTS) for (kind in kinds) tests.add(runTest(adapter, test, kind, o))
        return ConformanceReport(adapter.name(), overall(tests), tests)
    }

    fun overall(tests: List<TestReport>): String {
        var unresolved = false
        for (t in tests) {
            if (t.status == "fail") return "fail"
            if (t.status == "unresolved") unresolved = true
        }
        return if (unresolved) "unresolved" else "pass"
    }

    /** Run the kit and fail with the formatted report (counterexamples included) when the store does not pass: the test-runner binding. */
    fun assertConformance(adapter: StoreAdapter, opts: ConformanceOptions? = null): ConformanceReport {
        val r = runConformance(adapter, opts)
        if (!r.ok()) throw AssertionError(r.format())
        return r
    }
}
