package net.atlasauth.pca.verifier

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.SecureRandom
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Semaphore

/**
 * The pca-state conformance profile: run your replay store behind the REAL authorize path ([Authorize.AuthorizeOptions.run], the guard's own call) with real
 * signed PCActns, and check the replay-state invariant: one action id (grant, leaf holder, counter) goes from unconsumed to consumed at most once,
 * however many copies arrive, on however many instances or processes, across crashes after the claim and retries after a timeout.
 *
 * Checks: claim-* (the store's claim on its own, as [StoreConformance.runStateStore] runs them), one-instance (N concurrent copies of one proof to one guard:
 * exactly one admitted, every round), instances (the copies spread over K guards on separate handles, built multi-instance: a store only an in-process lock
 * can serialise is refused there and fails), processes (the same race across K child processes), crash-after-claim (admitted, then the instance dies before
 * its handler runs: the same proof is denied afterwards, the next counter admitted; with a worker the instance is a child process that halts right after the
 * admission) and retry-after-timeout (the commit lands but its answer is lost: the guard fails closed and the retry is denied; and a retry on another
 * instance while the first commit is still in flight: exactly one admitted). A check the store declares it cannot meet is skipped, never passed. The process
 * checks need a worker: a main of yours that calls [workerMain] with a way to open your store.
 */
@Suppress("UNCHECKED_CAST")
object PcaStateConformance {
    /** The store under test: [open] returns a NEW handle onto the SAME backend each call (one handle = one verifier instance's connection). */
    interface Adapter {
        val name: String
        fun open(): Authorize.StateStore

        /** State survives closing every handle (and [restart]). False skips the durability and crash checks. */
        val durable: Boolean get() = false

        /** Several handles can share the backend. False skips the instance and process checks. */
        val shared: Boolean get() = false

        /** Crashes and restarts the backend; it runs between closing the handles and reopening. */
        fun restart() {}
        fun teardown() {}
    }

    /** How to start one worker process: the command that comes before the configuration text, and the options its `open` receives. */
    class Worker(val command: List<String>, val options: Map<String, String> = emptyMap())

    class Options @JvmOverloads constructor(
        val rounds: Int = 10, val copies: Int = 16, val instances: Int = 4, val processes: Int = 3,
        /** The process checks and the process half of crash-after-claim; without it they are skipped. */
        val worker: Worker? = null,
    )

    const val AUD = "pca-state-conformance"
    private val OPERATION = Authorize.Operation("read", "doc:1", LinkedHashMap())
    private val RNG = SecureRandom()

    private enum class Outcome { ADMITTED, REPLAY, ERROR }

    private fun n(raw: String) = Json.Num(raw)

    /** Pre-signed PCActns (counters 1..n) from one agent under one grant, each with the provenance bundle it is sent with. */
    private class Fixture(val grant: Map<String, Any?>, val pin: Map<String, Any?>, val pcactns: List<Map<String, Any?>>, val bundles: List<Map<String, Any?>>) {
        fun json(): Map<String, Any?> = Issue.obj("grant" to grant, "pin" to pin, "pcactns" to pcactns, "bundles" to bundles)

        /** The guard under test: the real authorize path, the store as the replay store. Throws when the store cannot serve a multi-instance guard. */
        fun guardFor(store: Authorize.StateStore, multiInstance: Boolean): Guard {
            val az = Authorize.AuthorizeOptions(
                store, { _, _ -> false }, plan = Authorize.SINGLE_STEP,
                provenance = Authorize.ProvenanceOptions(mediators = listOf(pin)),
                risk = { _, _, _ -> Issue.obj("semanticDistance" to n("0"), "reversibility" to n("1"), "blastRadius" to n("0"), "taint" to n("0"), "confidence" to n("1"), "age" to n("0")) },
                multiInstance = multiInstance,
            )
            return Guard(this, az)
        }

        companion object {
            fun make(count: Int): Fixture {
                val principal = Keys.ed25519(Keys.edGenerate())
                val holder = Keys.ed25519(Keys.edGenerate())
                val weights = Issue.obj("alpha" to n("0"), "beta" to n("0"), "gamma" to n("0"), "delta" to n("0"), "epsilon" to n("0"), "zeta" to n("0"))
                val risk = Issue.obj("weights" to weights, "theta1" to n("0.5"), "theta2" to n("0.8"), "kappa" to n("1"), "lambda" to n("0"), "rho" to n("0"), "bMax" to n("1000"))
                val envelope = Issue.obj(
                    "predicates" to arrayListOf<Any?>(Issue.obj("verb" to "read", "resource" to "doc:*")), "caveats" to ArrayList<Any?>(),
                    "agent_binding" to LinkedHashMap<String, Any?>(), "risk_policy" to risk,
                )
                val grant = Issue.mintGrant(principal, holder.ed!!.id(), null, envelope, "store conformance").grant
                val node = Issue.obj("id" to "n1", "verb" to "read", "resource" to "doc:1", "params_digest" to Pca.paramsDigest(LinkedHashMap<String, Any?>()),
                    "reversibility_class" to "irreversible")
                val plan = Issue.commitPlan(listOf(node))
                val recorder = ArgProvenance.Recorder("pca-state-conformance", "k1")
                val now = System.currentTimeMillis()
                val pcactns = ArrayList<Map<String, Any?>>()
                val bundles = ArrayList<Map<String, Any?>>()
                for (i in 1..Math.max(1, count)) {
                    val nonce = ByteArray(16)
                    RNG.nextBytes(nonce)
                    pcactns.add(Issue.buildPCActn(Issue.ActSpec(
                        grant = grant, chain = arrayListOf<Any?>(grant), plan = plan, nodeId = "n1", counter = i.toLong(), signer = holder, aud = AUD,
                        params = LinkedHashMap(), iat = now, nonce = Pca.b64(nonce), riskClaim = Issue.obj("r" to n("0"), "inputs" to LinkedHashMap<String, Any?>()),
                    )))
                    bundles.add(ArgProvenance.principalDirect(recorder, OPERATION))
                }
                return Fixture(grant, recorder.pin, pcactns, bundles)
            }

            fun from(v: Any?): Fixture {
                val m = v as Map<String, Any?>
                return Fixture(m["grant"] as Map<String, Any?>, m["pin"] as Map<String, Any?>, (m["pcactns"] as List<Any?>).map { it as Map<String, Any?> },
                    (m["bundles"] as List<Any?>).map { it as Map<String, Any?> })
            }
        }
    }

    private class Guard(private val fx: Fixture, private val options: Authorize.AuthorizeOptions) {
        fun handle(counter: Int): Outcome {
            val r = options.run(fx.pcactns[counter - 1], OPERATION, AUD, { ref -> if (ref == fx.grant["id"]) fx.grant else null }, System.currentTimeMillis(),
                provenance = fx.bundles[counter - 1])
            if (r.allow) return Outcome.ADMITTED
            // a replay denial is a counter that was already consumed; "the replay store failed" is a fail-closed error, not a replay
            val storeFailed = (r.reason?.contains("store failed") == true) || r.reasons.any { it.contains("store failed") }
            return if (r.checks["replay"] == "fail" && !storeFailed) Outcome.REPLAY else Outcome.ERROR
        }
    }

    /** A store whose claim lands but whose answer is lost. */
    private class LossyStore(private val inner: Authorize.StateStore) : Authorize.StateStore {
        override val scope: String get() = inner.scope
        override fun claim(key: String, counter: Long): Authorize.ClaimResult? {
            inner.claim(key, counter)
            throw IllegalStateException("the answer was lost (timeout)")
        }
    }

    /** A store whose claim blocks until released, to hold a commit in flight. */
    private class GatedStore(private val inner: Authorize.StateStore) : Authorize.StateStore {
        val entered = Semaphore(0)
        val gate = Semaphore(0)
        override val scope: String get() = inner.scope
        override fun claim(key: String, counter: Long): Authorize.ClaimResult? {
            entered.release()
            gate.acquireUninterruptibly()
            return inner.claim(key, counter)
        }
    }

    private fun close(h: Any?) {
        if (h is AutoCloseable) {
            try { h.close() } catch (e: Exception) { /* best effort */ }
        }
    }

    private fun err(e: Throwable): String = e.javaClass.simpleName + ": " + e.message

    /** Runs every check. */
    @JvmStatic
    @JvmOverloads
    fun run(adapter: Adapter, o: Options = Options()): StoreConformance.Report {
        val rep = StoreConformance.Report(adapter.name)
        val claims = StoreConformance.runStateStore(
            { adapter.open() }, durable = adapter.durable, shared = adapter.shared, restart = { adapter.restart() },
            threads = Math.max(1, o.copies), rounds = Math.max(1, o.rounds), handles = Math.max(1, o.instances), name = adapter.name,
        )
        for (t in claims.results) if (t.test.startsWith("claim-")) rep.results.add(t)
        val rounds = Math.max(1, o.rounds)
        val copies = Math.max(1, o.copies)
        add(rep, "one-instance", raceCheck(adapter, 1, false, rounds, copies))
        if (adapter.shared) add(rep, "instances", raceCheck(adapter, Math.max(1, o.instances), true, rounds, copies))
        else skip(rep, "instances", "shared is false (one instance only)")
        val w = o.worker
        if (!adapter.shared) skip(rep, "processes", "shared is false (one instance only)")
        else if (w == null) skip(rep, "processes", "needs a worker command (the guards run in child processes)")
        else add(rep, "processes", processRace(w, rounds, copies, Math.max(1, o.processes)))
        if (adapter.durable) add(rep, "crash-after-claim", crashAfterClaim(adapter, o)) else skip(rep, "crash-after-claim", "durable is false (state dies with the process)")
        add(rep, "retry-after-timeout", retryAfterTimeout(adapter))
        return rep
    }

    private fun add(rep: StoreConformance.Report, name: String, failure: String?) {
        rep.results.add(StoreConformance.TestResult(name, if (failure == null) "pass" else "fail", failure ?: ""))
    }

    private fun skip(rep: StoreConformance.Report, name: String, why: String) { rep.results.add(StoreConformance.TestResult(name, "skip", why)) }

    /** Run `fn(i)` in `n` threads released together; the results in order (an exception is returned as a value). */
    private fun race(n: Int, fn: (Int) -> Any?): List<Any?> {
        val gate = CyclicBarrier(n)
        val out = arrayOfNulls<Any>(n)
        val ts = ArrayList<Thread>()
        for (i in 0 until n) {
            val t = Thread {
                try {
                    gate.await()
                    out[i] = fn(i)
                } catch (e: Throwable) {
                    out[i] = e
                }
            }
            ts.add(t)
            t.start()
        }
        for (t in ts) t.join()
        return out.toList()
    }

    private fun race(guards: List<Guard>, counter: Int, copies: Int): List<Outcome> =
        race(copies) { i -> guards[i % guards.size].handle(counter) }.map { if (it is Outcome) it else Outcome.ERROR }

    private fun raceCheck(adapter: Adapter, handles: Int, multiInstance: Boolean, rounds: Int, copies: Int): String? {
        val hs = ArrayList<Authorize.StateStore>()
        try {
            for (i in 0 until handles) hs.add(adapter.open())
            val fx = Fixture.make(rounds)
            val guards = ArrayList<Guard>()
            try {
                for (s in hs) guards.add(fx.guardFor(s, multiInstance))
            } catch (e: RuntimeException) { return "refused in multi-instance mode: " + err(e) }
            for (r in 1..rounds) {
                val wins = race(guards, r, copies).count { it == Outcome.ADMITTED }
                if (wins != 1) return "round $r: $wins of $copies copies of one proof were admitted (want exactly 1)"
            }
            return null
        } catch (e: Exception) { return err(e) } finally { for (s in hs) close(s) }
    }

    private fun crashAfterClaim(adapter: Adapter, o: Options): String? {
        val opened = ArrayList<Authorize.StateStore>()
        try {
            val h1 = adapter.open()
            opened.add(h1)
            val fx = Fixture.make(Math.max(4, o.rounds))
            // in process: admitted on handle 1, which is then abandoned (never closed); the backend restarts when it can
            val first = fx.guardFor(h1, adapter.shared).handle(1)
            adapter.restart()
            val h2 = adapter.open()
            opened.add(h2)
            val g = fx.guardFor(h2, adapter.shared)
            val again = g.handle(1)
            val next = g.handle(2)
            if (first != Outcome.ADMITTED || again != Outcome.REPLAY || next != Outcome.ADMITTED)
                return "in process: admitted=$first, same proof after the instance died=$again, next counter=$next"
            val w = o.worker
            return if (w != null) processCrash(adapter, w, fx) else null
        } catch (e: Exception) { return err(e) } finally { for (s in opened) close(s) }
    }

    private fun retryAfterTimeout(adapter: Adapter): String? {
        val hs = ArrayList<Authorize.StateStore>()
        try {
            for (i in 0 until (if (adapter.shared) 2 else 1)) hs.add(adapter.open())
            val fx = Fixture.make(4)
            val other = hs[hs.size - 1]
            // 1. the commit lands, its answer is lost: the guard fails closed, the retry (another instance when shared) is a replay
            val first = fx.guardFor(LossyStore(hs[0]), adapter.shared).handle(1)
            val og = fx.guardFor(other, adapter.shared)
            val retry = og.handle(1)
            val next = og.handle(2)
            if (first != Outcome.ERROR || retry != Outcome.REPLAY || next != Outcome.ADMITTED) return "lost answer: first=$first, retry=$retry, next counter=$next"
            // 2. the first commit is still in flight when the caller retries elsewhere: exactly one of the two is admitted
            val slow = GatedStore(hs[0])
            val sg = fx.guardFor(slow, adapter.shared)
            val res = arrayOfNulls<Outcome>(2)
            val t1 = Thread { res[0] = sg.handle(3) }
            t1.start()
            slow.entered.acquire()
            val t2 = Thread { res[1] = og.handle(3) }
            t2.start()
            slow.gate.release()
            t1.join()
            t2.join()
            val admitted = res.count { it == Outcome.ADMITTED }
            return if (admitted == 1) null else "in-flight retry: $admitted admitted of 2 (want exactly 1)"
        } catch (e: Exception) { return err(e) } finally { for (s in hs) close(s) }
    }

    // ---- child processes ----

    private class WorkerRun(val killed: Boolean, val lines: List<LongArray>) {
        val admitted: Long get() = lines.sumOf { it[1] }
        val replays: Long get() = lines.sumOf { it[2] }
    }

    private fun start(w: Worker, fx: Fixture, cfg: Map<String, Any?>, out: String): Process {
        val c = LinkedHashMap<String, Any?>(cfg)
        c["fixture"] = fx.json()
        c["out"] = out
        c["options"] = LinkedHashMap<String, Any?>(w.options)
        val cmd = ArrayList<String>(w.command)
        cmd.add(Json.canonicalize(c))
        return ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.to(File(if (File("/dev/null").exists()) "/dev/null" else "NUL"))).start()
    }

    private fun finish(p: Process, out: String): WorkerRun {
        val code = p.waitFor()
        val lines = ArrayList<LongArray>()
        val f = File(out)
        if (f.exists()) {
            for (l in Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                if (l.isBlank()) continue
                val m = Json.parseLenient(l) as Map<String, Any?>
                fun num(k: String): Long = IntentJs.num(m[k])?.toLong() ?: 0L
                lines.add(longArrayOf(num("counter"), num("admitted"), num("replays"), num("errors")))
            }
        }
        return WorkerRun(code == 137 || code == -9, lines) // the worker's abrupt stop (SIGKILL or a halt with 137)
    }

    private fun processRace(w: Worker, rounds: Int, copies: Int, processes: Int): String? {
        var dir: File? = null
        try {
            val fx = Fixture.make(rounds)
            dir = net.atlasauth.pca.durable.OwnerOnly.createTempDirectory("pcasc-pstate-").toFile()
            val origin = System.currentTimeMillis() + 3000 // time for every process to start and open its handles
            val ps = ArrayList<Process>()
            val outs = ArrayList<String>()
            for (i in 0 until processes) {
                val out = File(dir, "p$i.jsonl").path
                outs.add(out)
                ps.add(start(w, fx, Issue.obj("mode" to "race", "rounds" to rounds.toLong(), "origin" to origin, "roundMs" to 150L, "copies" to copies.toLong(), "instances" to 2L), out))
            }
            val runs = ps.indices.map { finish(ps[it], outs[it]) }
            for (r in 1..rounds) {
                var admitted = 0L
                for (run in runs) for (l in run.lines) if (l[0] == r.toLong()) admitted += l[1]
                if (admitted != 1L) return "round $r: $admitted presentations admitted across ${runs.size} processes (want exactly 1)"
            }
            for (run in runs) if (run.killed || run.lines.size != rounds) return "a worker did not finish (${run.lines.size} of $rounds rounds recorded)"
            return null
        } catch (e: Exception) { return err(e) } finally { dir?.deleteRecursively() }
    }

    /** A child process admits counter 3 and halts before its handler; a new process retries it; the next counter is admitted. */
    private fun processCrash(adapter: Adapter, w: Worker, fx: Fixture): String? {
        var dir: File? = null
        try {
            dir = net.atlasauth.pca.durable.OwnerOnly.createTempDirectory("pcasc-pstate-").toFile()
            val a = File(dir, "a.jsonl").path
            val b = File(dir, "b.jsonl").path
            val c = File(dir, "c.jsonl").path
            val killed = finish(start(w, fx, Issue.obj("mode" to "admit-then-die", "counter" to 3L, "copies" to 1L, "instances" to 1L), a), a)
            adapter.restart()
            val retried = finish(start(w, fx, Issue.obj("mode" to "race", "counter" to 3L, "copies" to 1L, "instances" to 1L, "rounds" to 1L), b), b)
            val fresh = finish(start(w, fx, Issue.obj("mode" to "race", "counter" to 4L, "copies" to 1L, "instances" to 1L, "rounds" to 1L), c), c)
            if (!(killed.killed && killed.admitted == 1L && retried.admitted == 0L && retried.replays == 1L && fresh.admitted == 1L))
                return "child process: killed after admission=${killed.killed && killed.admitted == 1L}, retry in a new process admitted ${retried.admitted}, next counter admitted ${fresh.admitted}"
            return null
        } catch (e: Exception) { return err(e) } finally { dir?.deleteRecursively() }
    }

    // ---- the worker side ----

    private fun record(out: String, counter: Long, rs: List<Outcome>) {
        val line = Json.canonicalize(Issue.obj(
            "counter" to counter, "admitted" to rs.count { it == Outcome.ADMITTED }.toLong(), "replays" to rs.count { it == Outcome.REPLAY }.toLong(),
            "errors" to rs.count { it == Outcome.ERROR }.toLong(),
        )) + "\n"
        val outPath = File(out).toPath()
        try { net.atlasauth.pca.durable.OwnerOnly.createFile(outPath) } catch (ignored: java.nio.file.FileAlreadyExistsException) {} // owner-only at creation
        Files.write(outPath, line.toByteArray(StandardCharsets.UTF_8), java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND)
    }

    private fun presentations(guards: List<Guard>, counter: Int, copies: Int): List<Outcome> = race(guards, counter, Math.max(1, copies))

    /**
     * The entry of one worker process: [configText] is the last argument the parent passed; [open] opens a handle onto the shared backend from the parent's
     * `options`. Returns the process exit status. Mode `admit-then-die` records the admission and halts the JVM (exit status 137, no hooks, nothing flushed)
     * before any handler.
     */
    @JvmStatic
    fun workerMain(configText: String, open: (Map<String, String>) -> Authorize.StateStore): Int = try {
        val cfg = Json.parseLenient(configText) as Map<String, Any?>
        val fx = Fixture.from(cfg["fixture"])
        val out = cfg["out"] as String
        val options = LinkedHashMap<String, String>()
        for ((k, v) in cfg["options"] as Map<String, Any?>) options[k] = v as String
        fun int(k: String, d: Int): Int = if (cfg[k] == null) d else IntentJs.num(cfg[k])!!.toInt()
        val nInstances = int("instances", 1)
        val copies = int("copies", 1)
        val mode = (cfg["mode"] as String?) ?: "race"
        val guards = ArrayList<Guard>()
        for (i in 0 until Math.max(1, nInstances)) guards.add(fx.guardFor(open(options), true))
        if (mode == "admit-then-die") {
            val counter = int("counter", 1)
            record(out, counter.toLong(), presentations(guards, counter, copies))
            Runtime.getRuntime().halt(137)
        }
        val rounds = int("rounds", 1)
        for (r in 0 until rounds) {
            val counter = if (cfg["counter"] != null) int("counter", 1) else r + 1
            val origin = if (cfg["origin"] == null) System.currentTimeMillis() else IntentJs.num(cfg["origin"])!!.toLong()
            val at = origin + r * (if (cfg["roundMs"] == null) 0L else IntentJs.num(cfg["roundMs"])!!.toLong())
            while (System.currentTimeMillis() < at) Thread.sleep(2)
            record(out, counter.toLong(), presentations(guards, counter, copies))
        }
        0
    } catch (e: Exception) { 1 }
}
