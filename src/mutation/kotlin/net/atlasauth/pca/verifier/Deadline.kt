package net.atlasauth.pca.verifier

import java.lang.management.ManagementFactory
import java.util.concurrent.atomic.AtomicReference

/**
 * Deadline tests (BRIEF: timeouts are not kills by themselves): a mutant whose loop no longer advances must FAIL a test
 * instead of hanging until PIT's timeout. [within] runs [block] on a daemon thread and fails with "deadline" if it has not
 * finished after [ms]. The unmutated code takes milliseconds on these inputs; [DEFAULT_MS] leaves a wide margin for GC pauses
 * and slow runners while staying below PIT's own limit (timeoutFactor x normal + 15 s). A stuck mutant thread is a daemon, so
 * it never keeps the minion alive, and it only spins until PIT ends that minion.
 */
object Deadline {
    const val DEFAULT_MS = 5_000L

    fun <T> within(ms: Long = DEFAULT_MS, block: () -> T): T {
        val out = AtomicReference<Any?>(NONE)
        val err = AtomicReference<Throwable?>(null)
        val t = Thread {
            try { out.set(block()) } catch (e: Throwable) { err.set(e) }
        }
        t.isDaemon = true
        t.start()
        // The budget is the worker's CPU time, not the wall clock: a spinning mutant burns CPU without end, while a loaded runner
        // (20 shards, one cold JVM per mutant) only delays a healthy run, and a wall-clock deadline then failed it at random and so
        // "killed" an unrelated equivalent mutant. A worker that is blocked rather than spinning still ends at twice the budget in wall time.
        val mx = ManagementFactory.getThreadMXBean()
        val cpu = mx.isThreadCpuTimeSupported
        val start = System.nanoTime()
        while (t.isAlive) {
            t.join(25)
            val wallMs = (System.nanoTime() - start) / 1_000_000
            val usedMs = if (cpu) mx.getThreadCpuTime(t.id) / 1_000_000 else wallMs
            if (usedMs >= ms || wallMs >= 2 * ms) break
        }
        err.get()?.let { throw it }
        if (t.isAlive || out.get() === NONE) throw AssertionError("deadline: not finished within $ms ms (a loop that no longer advances)")
        @Suppress("UNCHECKED_CAST")
        return out.get() as T
    }

    private val NONE = Any()
}
