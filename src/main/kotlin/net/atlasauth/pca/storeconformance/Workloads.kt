package net.atlasauth.pca.storeconformance

import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Workloads that drive a store adapter and record the history: same-key bursts, a windowed concurrent run in which every client
 * contends on the same few keys at once, a retention run (many keys, then every key revisited while still live), and a durability
 * run (write, close every client, restart the backend, read back). Clients are threads.
 */
object Workloads {
    /** Workload settings; null members take the reference defaults. */
    open class WorkloadOptions {
        /** Concurrent clients (each `adapter.open()`), default 16. */
        var clients: Int? = null

        /** Concurrent run length, default 2000 ms. */
        var durationMs: Double? = null

        /** Contention window: every client targets the same `spread` keys within one window (default 5 ms, 3 keys). */
        var windowMs: Double? = null
        var spread: Int? = null

        /** Counter values are drawn from [0, values) so duplicates and reorderings occur (default 20). */
        var values: Int? = null

        /** consumeOnce horizon: retainUntil = now + retentionMs (default 10 minutes, longer than any run). */
        var retentionMs: Double? = null

        /** A call that has not settled after this long is recorded as unknown (open-ended), default 5000 ms. */
        var opTimeoutMs: Long? = null

        /** Same-key burst rounds, default 20. */
        var rounds: Int? = null

        /** Retention run: distinct keys written then revisited, default 500. */
        var revisitKeys: Int? = null

        /** Key prefix. Default: random per run, so runs never collide with each other or with real data. */
        var namespace: String? = null

        /** PRNG seed (default random). */
        var seed: Long? = null
    }

    /** The recorded history of a run, how many calls failed or timed out, and a note. */
    open class WorkloadResult(val ops: List<Op>, val errors: Int, val note: String?)

    internal class Resolved(
        val clients: Int,
        val spread: Int,
        val values: Int,
        val rounds: Int,
        val revisitKeys: Int,
        val durationMs: Double,
        val windowMs: Double,
        val retentionMs: Double,
        val opTimeoutMs: Long,
        val seed: Long,
        val namespace: String,
    )

    internal fun defaults(o: WorkloadOptions): Resolved = Resolved(
        clients = o.clients ?: 16,
        spread = o.spread ?: 3,
        values = o.values ?: 20,
        rounds = o.rounds ?: 20,
        revisitKeys = o.revisitKeys ?: 500,
        durationMs = o.durationMs ?: 2000.0,
        windowMs = o.windowMs ?: 5.0,
        retentionMs = o.retentionMs ?: 600_000.0,
        opTimeoutMs = o.opTimeoutMs ?: 5000L,
        seed = o.seed ?: Math.floor(Math.random() * Math.pow(2.0, 31.0)).toLong(),
        namespace = o.namespace ?: randomNamespace(),
    )

    fun randomNamespace(): String = "pcasc-" + System.currentTimeMillis().toString(36) + "-" + (Math.random() * 2176782336.0).toLong().toString(36)

    /** What every operation needs: where to record, the retention horizon, the per-call timeout and the threads calls run on. */
    class OpContext(val rec: Recorder, val retentionMs: Double, val opTimeoutMs: Long, val pool: ExecutorService)

    internal fun newPool(): ExecutorService = Executors.newCachedThreadPool(ThreadFactory { r ->
        val t = Thread(r, "pcasc")
        t.isDaemon = true
        t
    })

    /** Settle [fn] as a definite boolean, or null (unknown) on a throw or a timeout. */
    fun settle(fn: Callable<Boolean>, timeoutMs: Long, pool: ExecutorService): Boolean? {
        val f: Future<Boolean> = pool.submit(fn)
        return try {
            f.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            f.cancel(true)
            null
        } catch (e: InterruptedException) {
            f.cancel(true)
            Thread.currentThread().interrupt()
            null
        } catch (e: Exception) {
            null
        }
    }

    /** Record and perform one operation. For `advance`, [value] is the counter; for `consume` it is ignored. */
    fun perform(c: StoreClient, client: String, kind: String, key: String, value: Double, ctx: OpContext): Boolean? {
        val now = System.currentTimeMillis().toDouble()
        val consume = kind == "consume"
        val lo = if (consume) now else value
        val w = if (consume) now + ctx.retentionMs else value
        val op = ctx.rec.invoke(client, kind, key, lo, w)
        val r = settle(Callable<Boolean> { if (consume) c.consumeOnce(key, w, now) else c.advance(key, value) }, ctx.opTimeoutMs, ctx.pool)
        ctx.rec.complete(op, r)
        return r
    }

    fun openClients(adapter: StoreAdapter, n: Int): List<StoreClient> {
        val out = ArrayList<StoreClient>()
        try {
            for (i in 0 until n) out.add(adapter.open())
        } catch (e: Exception) {
            try { closeClients(out) } catch (ignored: Exception) { /* the open failure is the error */ }
            throw e
        }
        return out
    }

    fun closeClients(clients: List<StoreClient>) {
        var first: Exception? = null
        for (c in clients) {
            try { c.close() } catch (e: Exception) { if (first == null) first = e }
        }
        if (first != null) throw first
    }

    private fun countUnknown(ops: List<Op>): Int {
        var n = 0
        for (o in ops) if (o.res == "unknown") n++
        return n
    }

    /** Where a windowed client's keys and values come from (shared by every client and process). */
    class Window {
        var namespace: String = ""
        var windowMs: Double = 5.0
        var spread: Int = 3
        var values: Int = 20
        var origin: Double = 0.0
        var deadline: Double = 0.0
        var rand: Kit.Prng = Kit.Prng(0.0)
        var stop: () -> Boolean = { false }
    }

    /**
     * The client loop of the concurrent run, shared with the crash harness: until `deadline`, pick one of the `spread` keys of the
     * current window (all clients compute the same window from `origin`) and operate on it.
     */
    fun driveWindowed(c: StoreClient, client: String, kind: String, ctx: OpContext, o: Window) {
        while (Recorder.clock() < o.deadline && !o.stop()) {
            val win = Math.floor((Recorder.clock() - o.origin) / o.windowMs).toLong()
            val key = o.namespace + ":" + kind + ":" + win + ":" + o.rand.rand(o.spread.toDouble()).toLong()
            perform(c, client, kind, key, o.rand.rand(o.values.toDouble()), ctx)
        }
    }

    private fun closeQuietly(clients: List<StoreClient>) {
        try { closeClients(clients) } catch (ignored: Exception) { /* the run's result stands */ }
    }

    private fun submitPerform(pool: ExecutorService, c: StoreClient, name: String, kind: String, key: String, v: Double, ctx: OpContext): Future<Boolean?> =
        pool.submit(Callable<Boolean?> { perform(c, name, kind, key, v, ctx) })

    /** `rounds` times: every client fires one operation at the SAME fresh key at once. */
    fun runBurst(adapter: StoreAdapter, kind: String, opts: WorkloadOptions): WorkloadResult {
        val o = defaults(opts)
        val rand = Kit.Prng(o.seed.toDouble())
        val rec = Recorder.MemoryRecorder()
        val pool = newPool()
        val ctx = OpContext(rec, o.retentionMs, o.opTimeoutMs, pool)
        val clients = openClients(adapter, o.clients)
        try {
            for (r in 0 until o.rounds) {
                val key = o.namespace + ":" + kind + ":burst:" + r
                val fs = ArrayList<Future<Boolean?>>()
                for (i in clients.indices) {
                    val v = rand.rand(o.values.toDouble())
                    fs.add(submitPerform(pool, clients[i], "c$i", kind, key, v, ctx))
                }
                for (f in fs) f.get()
            }
        } finally {
            closeQuietly(clients)
            pool.shutdownNow()
        }
        val ops = rec.ops()
        return WorkloadResult(ops, countUnknown(ops), null)
    }

    /** Every client loops on the windowed keys for `durationMs`. */
    fun runConcurrent(adapter: StoreAdapter, kind: String, opts: WorkloadOptions): WorkloadResult {
        val o = defaults(opts)
        val rec = Recorder.MemoryRecorder()
        val pool = newPool()
        val ctx = OpContext(rec, o.retentionMs, o.opTimeoutMs, pool)
        val clients = openClients(adapter, o.clients)
        val origin = Recorder.clock()
        try {
            val fs = ArrayList<Future<*>>()
            for (i in clients.indices) {
                val c = clients[i]
                val name = "c$i"
                val w = Window()
                w.namespace = o.namespace
                w.windowMs = o.windowMs
                w.spread = o.spread
                w.values = o.values
                w.origin = origin
                w.deadline = origin + o.durationMs
                w.rand = Kit.Prng((o.seed + i).toDouble())
                fs.add(pool.submit(Callable<Boolean?> { driveWindowed(c, name, kind, ctx, w); null }))
            }
            for (f in fs) f.get()
        } finally {
            closeQuietly(clients)
            pool.shutdownNow()
        }
        val ops = rec.ops()
        return WorkloadResult(ops, countUnknown(ops), null)
    }

    /**
     * Retention: write `revisitKeys` distinct keys (consume once / advance to 1), then revisit every one while it is still live
     * (same counter): each revisit must answer false. Catches early pruning and capacity eviction of live records.
     */
    fun runRetention(adapter: StoreAdapter, kind: String, opts: WorkloadOptions): WorkloadResult {
        val o = defaults(opts)
        val rec = Recorder.MemoryRecorder()
        val pool = newPool()
        val ctx = OpContext(rec, o.retentionMs, o.opTimeoutMs, pool)
        val clients = openClients(adapter, o.clients)
        val keys = ArrayList<String>()
        for (i in 0 until o.revisitKeys) keys.add(o.namespace + ":" + kind + ":keep:" + i)
        try {
            for (pass in listOf("write", "revisit")) {
                var i = 0
                while (i < keys.size) {
                    val fs = ArrayList<Future<Boolean?>>()
                    for (j in clients.indices) {
                        if (i + j >= keys.size) continue
                        fs.add(submitPerform(pool, clients[j], pass + "-c" + j, kind, keys[i + j], 1.0, ctx))
                    }
                    for (f in fs) f.get()
                    i += clients.size
                }
            }
        } finally {
            closeQuietly(clients)
            pool.shutdownNow()
        }
        val ops = rec.ops()
        return WorkloadResult(ops, countUnknown(ops), null)
    }

    /**
     * Durability: consume a key / advance a stream to 7, close the client, `restart()` the backend when the adapter can, open a new
     * client and read back: the key must stay consumed and the counter must not go backwards (7 refused, 8 accepted).
     */
    fun runDurability(adapter: StoreAdapter, kind: String, opts: WorkloadOptions): WorkloadResult {
        val o = defaults(opts)
        val rec = Recorder.MemoryRecorder()
        val pool = newPool()
        val ctx = OpContext(rec, o.retentionMs, o.opTimeoutMs, pool)
        val key = o.namespace + ":" + kind + ":durable"
        try {
            val before = adapter.open()
            try {
                perform(before, "before-restart", kind, key, 7.0, ctx)
            } finally {
                before.close()
            }
            if (adapter.hasRestart()) adapter.restart()
            val after = adapter.open()
            try {
                perform(after, "after-restart", kind, key, 7.0, ctx)
                if (kind == "advance") perform(after, "after-restart", kind, key, 8.0, ctx)
            } finally {
                after.close()
            }
        } finally {
            pool.shutdownNow()
        }
        val ops = rec.ops()
        return WorkloadResult(ops, countUnknown(ops), if (adapter.hasRestart()) "backend restarted between write and read" else "no restart() hook: clients closed and re-opened only")
    }
}
