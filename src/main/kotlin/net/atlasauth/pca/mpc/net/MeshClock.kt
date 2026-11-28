package net.atlasauth.pca.mpc.net

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Time source for every DECISION the mesh makes by time (receive deadlines, connect deadline, dial retry window). The default
 * is the real clock; tests inject a virtual clock so an outcome never depends on how loaded the machine is.
 */
interface MeshClock {
    /** Current time in milliseconds (monotonic; only differences matter). */
    fun now(): Long

    /** Run [fn] after [ms] of clock time; returns a handle for [clearTimer]. */
    fun setTimer(fn: Runnable, ms: Long): Any?

    fun clearTimer(handle: Any?)

    companion object {
        /** Real time (monotonic). */
        @JvmField
        val WALL: MeshClock = object : MeshClock {
            private val sch: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
                Thread(r, "mesh-clock").also { it.isDaemon = true }
            }

            override fun now(): Long = System.nanoTime() / 1_000_000L

            override fun setTimer(fn: Runnable, ms: Long): Any? = sch.schedule(fn, maxOf(0L, ms), TimeUnit.MILLISECONDS)

            override fun clearTimer(handle: Any?) {
                if (handle is ScheduledFuture<*>) handle.cancel(false)
            }
        }
    }
}
