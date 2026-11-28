package net.atlasauth.pca.storeconformance

import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import net.atlasauth.pca.doctor.Js
import net.atlasauth.pca.verifier.Json

/**
 * The shared frame of the per-store conformance suites: a named check with a claim, a run that reports pass / fail / skip per check,
 * and the assertion helpers the checks use. A check passes by returning and fails by throwing; the report carries the first line of
 * the failure.
 */
object Suite {
    /** What a check runs against: one isolated backend plus the means to reconnect to it. */
    interface Handle {
        /** True when `crash()` is implemented (a check that needs a crash is skipped otherwise). */
        fun canCrash(): Boolean = false

        /** Release the backend (never drop shared data of another handle). */
        fun close() {}
    }

    /** One claim about a store, driven through an adapter's handle. [needs] is null, `"durable"` or `"crash"`. */
    class Check<H>(val name: String, val claim: String, val needs: String?, val body: (H) -> Unit) {
        constructor(name: String, claim: String, body: (H) -> Unit) : this(name, claim, null, body)
    }

    /** One check's outcome: `pass`, `fail` or `skip`. */
    class Result internal constructor(val name: String, val status: String, val detail: String?)

    /** A run's report. */
    class Report internal constructor(val suite: String, val adapter: String, val checks: List<Result>) {
        val status: String = if (checks.any { it.status == "fail" }) "fail" else "pass"

        fun check(name: String): Result {
            for (r in checks) if (r.name == name) return r
            throw IllegalArgumentException("no check $name")
        }

        fun count(status: String): Int {
            var n = 0
            for (r in checks) if (r.status == status) n++
            return n
        }

        /** The text report. */
        fun format(): String {
            val sb = StringBuilder("pca-store-conformance ($suite): $adapter -> " + status.uppercase())
            for (c in checks) {
                sb.append("\n  [").append(c.status.uppercase()).append("] ").append(c.name)
                if (c.detail != null) sb.append(": ").append(c.detail.split("\n")[0])
            }
            return sb.toString()
        }
    }

    /**
     * Run [checks] (only those named in [only] when non-null) against fresh handles from [make]. A check that needs durability is
     * skipped when [durable] is false; one that needs a crash is skipped when the handle cannot crash.
     */
    fun <H : Handle> run(suite: String, adapter: String, durable: Boolean, make: () -> H, checks: List<Check<H>>, only: Collection<String>?): Report {
        val out = ArrayList<Result>()
        for (c in checks) {
            if (only != null && c.name !in only) continue
            if ("durable" == c.needs && !durable) {
                out.add(Result(c.name, "skip", "the adapter declares durable: false"))
                continue
            }
            var h: H? = null
            try {
                h = make()
                if ("crash" == c.needs && !h.canCrash()) {
                    out.add(Result(c.name, "skip", "the adapter has no crash()"))
                    continue
                }
                c.body(h)
                out.add(Result(c.name, "pass", null))
            } catch (e: Throwable) {
                out.add(Result(c.name, "fail", e.message ?: e.toString()))
            } finally {
                if (h != null) try { h.close() } catch (ignored: Exception) { /* closing is best effort */ }
            }
        }
        return Report(suite, adapter, out)
    }

    // ---- assertions ----

    /** Numbers print as JavaScript prints them; everything else is kept. */
    fun norm(v: Any?): Any? {
        if (v is Json.Num || v is Number) {
            val d = Js.num(v) ?: return v
            return Json.Num(Js.numStr(d))
        }
        if (v is Map<*, *>) {
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in v) out[k as String] = norm(x)
            return out
        }
        if (v is List<*>) {
            val out = ArrayList<Any?>()
            for (x in v) out.add(norm(x))
            return out
        }
        return v
    }

    /** Deep JSON equality (numbers by value, objects by member). */
    fun eq(want: Any?, got: Any?, what: String? = null) {
        val a = Json.canonicalize(norm(want))
        val b = Json.canonicalize(norm(got))
        if (a != b) throw AssertionError((if (what == null) "" else "$what: ") + "expected $a but got $b")
    }

    fun ok(cond: Boolean, what: String) {
        if (!cond) throw AssertionError(what)
    }

    /** The call must throw [type]; anything else (including no throw) fails. */
    fun rejects(type: Class<out Throwable>, f: () -> Any?, what: String) {
        try {
            f()
        } catch (t: Throwable) {
            if (type.isInstance(t)) return
            throw AssertionError(what + ": expected " + type.simpleName + " but got " + t)
        }
        throw AssertionError(what + ": expected " + type.simpleName + " but nothing was thrown")
    }

    /** The call must throw (any exception). */
    fun rejects(f: () -> Any?, what: String) = rejects(Throwable::class.java, f, what)

    /** Run the tasks concurrently (the reference's Promise.all) and return their results in order; a failure rethrows. */
    fun <T> parallel(tasks: List<() -> T>): List<T> {
        val ex = Executors.newFixedThreadPool(Math.max(1, Math.min(tasks.size, 16)))
        try {
            val fs = ArrayList<Future<T>>()
            for (t in tasks) fs.add(ex.submit(java.util.concurrent.Callable<T> { t() }))
            val out = ArrayList<T>()
            for (f in fs) {
                try {
                    out.add(f.get())
                } catch (e: ExecutionException) {
                    val c = e.cause
                    if (c is Exception) throw c
                    throw e
                }
            }
            return out
        } finally {
            ex.shutdownNow()
        }
    }
}
