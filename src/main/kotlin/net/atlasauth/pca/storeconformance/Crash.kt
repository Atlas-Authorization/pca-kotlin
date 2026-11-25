package net.atlasauth.pca.storeconformance

import java.io.File
import java.io.IOException
import java.util.concurrent.ExecutorService

/**
 * Crash harness. Several client "processes" (each a group of client threads with its own history file) run the windowed workload
 * against the same backend; every `killEveryMs` one of them is KILLED (its recorder stops writing, so its in-flight operations
 * stay PENDING, exactly like a SIGKILLed process) and a replacement starts under a new identity. When the adapter has `crash()`,
 * the backend is crashed and restarted once mid-run. Every writer is joined before the histories are read (a partial history can
 * make a FALSE look unexplained). Known limit: a JVM cannot SIGKILL a thread, so a "killed process" stops recording and issuing
 * operations while the call it is inside runs to its end unrecorded; fork JVMs if real process death matters.
 */
object Crash {
    open class CrashOptions : Workloads.WorkloadOptions() {
        /** Opens an adapter over the SHARED backend; called once per client process (and once for the control that crashes the backend). */
        var adapters: (() -> StoreAdapter)? = null

        /** Client processes alive at once (default 3); `clients` is per process (default 4). */
        var processes: Int? = null

        /** Kill one client process this often (default 400 ms; 0 = never). */
        var killEveryMs: Int? = null

        /** Crash + restart the backend once mid-run when the adapter has `crash()` (default true). */
        var backendCrash: Boolean? = null

        /** History directory (default: a fresh temp dir). */
        var dir: File? = null
    }

    class CrashResult internal constructor(
        ops: List<Op>,
        errors: Int,
        val kills: Int,
        val backendCrashes: Int,
        val torn: Int,
        val pending: Int,
        val processes: Int,
    ) : Workloads.WorkloadResult(ops, errors, null)

    private class Proc(val rec: Recorder.FileRecorder) {
        lateinit var thread: Thread

        @Volatile var killed = false
    }

    private fun freshDir(): File {
        return net.atlasauth.pca.durable.OwnerOnly.createTempDirectory("pcasc-hist-").toFile() // owner-only at creation
    }

    fun runCrash(kind: String, o: CrashOptions): CrashResult {
        val adapters = o.adapters ?: throw IllegalArgumentException("runCrash needs an adapter supplier (CrashOptions.adapters)")
        val dir = o.dir ?: freshDir()
        val durationMs = o.durationMs ?: 3000.0
        val killEveryMs = o.killEveryMs ?: 400
        val seed = o.seed ?: Math.floor(Math.random() * Math.pow(2.0, 31.0)).toLong()
        val rand = Kit.Prng(seed.toDouble())
        val origin = Recorder.clock()
        val deadline = origin + durationMs
        val clients = o.clients ?: 4
        val namespace = o.namespace ?: Workloads.randomNamespace()
        val windowMs = o.windowMs ?: 5.0
        val spread = o.spread ?: 3
        val values = o.values ?: 20
        val retentionMs = o.retentionMs ?: 600_000.0
        val opTimeoutMs = o.opTimeoutMs ?: 5000L

        val live = ArrayList<Proc>()
        val all = ArrayList<Proc>()
        var n = 0
        fun spawn() {
            val proc = "p$n"
            val file = File(dir, "h-$proc.jsonl")
            val procSeed = seed + 7919L * n
            n++
            val rec = try {
                Recorder.FileRecorder(file, proc)
            } catch (e: IOException) {
                throw IllegalStateException("cannot start a client process: " + e.message, e)
            }
            val self = Proc(rec)
            val t = Thread({ worker(self, adapters, kind, proc, clients, namespace, windowMs, spread, values, retentionMs, opTimeoutMs, origin, deadline, procSeed) }, "pcasc-$proc")
            self.thread = t
            t.isDaemon = true
            live.add(self)
            all.add(self)
            t.start()
        }
        for (i in 0 until (o.processes ?: 3)) spawn()
        val control: StoreAdapter? = if (o.backendCrash != false) adapters() else null
        var kills = 0
        var backendCrashes = 0
        val half = origin + durationMs / 2
        while (killEveryMs > 0 && Recorder.clock() + killEveryMs < deadline) {
            Thread.sleep(killEveryMs.toLong())
            val victims = ArrayList(live)
            if (victims.isNotEmpty()) {
                val v = victims[rand.rand(victims.size.toDouble()).toInt()]
                v.killed = true
                v.rec.kill()
                live.remove(v)
                kills++
                spawn()
            }
            if (control != null && control.hasCrash() && backendCrashes == 0 && Recorder.clock() >= half) {
                control.crash()
                if (control.hasRestart()) control.restart()
                backendCrashes++
            }
        }
        for (p in all) p.thread.join()
        control?.teardown()
        val text = StringBuilder()
        val files = ArrayList<File>()
        for (f in dir.listFiles() ?: arrayOf<File>()) if (f.name.startsWith("h-") && f.name.endsWith(".jsonl")) files.add(f)
        files.sortBy { it.name }
        for (f in files) text.append(f.readText(Charsets.UTF_8)).append('\n')
        val h = Kit.parseHistory(text.toString())
        var unknown = 0
        for (x in h.ops) if (x.res == "unknown") unknown++
        return CrashResult(h.ops, unknown, kills, backendCrashes, h.torn, h.pending, n)
    }

    /** One client process: open an adapter, run the windowed workload on `clients` threads, record to the process's file. */
    private fun worker(
        self: Proc,
        adapters: () -> StoreAdapter,
        kind: String,
        proc: String,
        clients: Int,
        namespace: String,
        windowMs: Double,
        spread: Int,
        values: Int,
        retentionMs: Double,
        opTimeoutMs: Long,
        origin: Double,
        deadline: Double,
        seed: Long,
    ) {
        val pool: ExecutorService = Workloads.newPool()
        var cs: List<StoreClient> = ArrayList()
        try {
            val adapter = adapters() // the adapter's owner tears the backend down, never a client process
            val ctx = Workloads.OpContext(self.rec, retentionMs, opTimeoutMs, pool)
            cs = Workloads.openClients(adapter, clients)
            val ts = ArrayList<Thread>()
            for (i in cs.indices) {
                val c = cs[i]
                val name = proc + "c" + i
                val w = Workloads.Window()
                w.namespace = namespace
                w.windowMs = windowMs
                w.spread = spread
                w.values = values
                w.origin = origin
                w.deadline = deadline
                w.rand = Kit.Prng((seed + i).toDouble())
                w.stop = { self.killed }
                val t = Thread({ Workloads.driveWindowed(c, name, kind, ctx, w) }, "pcasc-$name")
                t.isDaemon = true
                ts.add(t)
                t.start()
            }
            for (t in ts) t.join()
        } catch (e: Exception) {
            // a worker that cannot run records nothing; the parent sees fewer operations
        } finally {
            try { Workloads.closeClients(cs) } catch (ignored: Exception) { /* best effort */ }
            try { self.rec.close() } catch (ignored: IOException) { /* best effort */ }
            pool.shutdownNow()
        }
    }
}
