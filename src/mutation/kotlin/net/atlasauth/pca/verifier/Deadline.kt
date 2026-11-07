package net.atlasauth.pca.verifier

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
        t.join(ms)
        err.get()?.let { throw it }
        if (t.isAlive || out.get() === NONE) throw AssertionError("deadline: not finished within $ms ms (a loop that no longer advances)")
        @Suppress("UNCHECKED_CAST")
        return out.get() as T
    }

    private val NONE = Any()
}
