package net.atlasauth.pca.storeconformance

import net.atlasauth.pca.verifier.Json

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.Collections
import java.util.IdentityHashMap
import net.atlasauth.pca.doctor.Js

/**
 * History recording. The invocation is recorded BEFORE the request leaves the client and the response after it completes. An
 * operation that errors, times out or whose client dies keeps an open-ended interval (ret infinite, outcome unknown): it may or
 * may not have taken effect, at any time after its invocation.
 */
interface Recorder {
    fun invoke(client: String, kind: String, key: String, lo: Double, w: Double): Op

    /** `true` / `false`: the definite answer; null: the call failed or timed out (stays open-ended). */
    fun complete(op: Op, result: Boolean?)

    companion object {
        private val BASE_MS: Double = System.currentTimeMillis().toDouble()
        private val NANO0: Long = System.nanoTime()

        /** Wall-clock milliseconds with sub-millisecond resolution; comparable across threads (and processes on one host). */
        fun clock(): Double = BASE_MS + (System.nanoTime() - NANO0) / 1e6
    }

    /** In memory (one process). */
    class MemoryRecorder : Recorder {
        private val list: MutableList<Op> = Collections.synchronizedList(ArrayList<Op>())

        fun ops(): List<Op> = synchronized(list) { ArrayList(list) }

        override fun invoke(client: String, kind: String, key: String, lo: Double, w: Double): Op {
            val op = Op(client, kind, key, lo, w, Recorder.clock(), Double.POSITIVE_INFINITY, "unknown")
            list.add(op)
            return op
        }

        override fun complete(op: Op, result: Boolean?) {
            if (result == null) return
            val at = Recorder.clock()
            synchronized(list) {
                op.ret = at
                op.res = if (result) "true" else "false"
            }
        }
    }

    /**
     * Appends `i` / `r` lines to a file, one write per event, so a client that is killed (see [kill]) leaves its in-flight
     * operations PENDING, exactly like a crash in production; torn lines are skipped by [Kit.parseHistory].
     */
    class FileRecorder(path: File, private val proc: String) : Recorder, AutoCloseable {
        private val out = FileOutputStream(path.also {
            try { net.atlasauth.pca.durable.OwnerOnly.createFile(it.toPath()) } catch (ignored: java.nio.file.FileAlreadyExistsException) {} // owner-only at creation
        }, true)
        private var seq = 0L
        private val ids = IdentityHashMap<Op, Long>()

        @Volatile private var killed = false

        /** After a kill nothing more is written: whatever is in flight stays pending. */
        fun kill() { killed = true }

        @Synchronized private fun line(s: String) {
            if (killed) return
            try {
                out.write(Json.utf8((s + "\n")))
                out.flush()
            } catch (e: IOException) {
                throw IllegalStateException("history write failed: " + e.message, e)
            }
        }

        private fun num(d: Double): String = Js.numStr(d)

        @Synchronized override fun invoke(client: String, kind: String, key: String, lo: Double, w: Double): Op {
            val op = Op(client, kind, key, lo, w, Recorder.clock(), Double.POSITIVE_INFINITY, "unknown")
            val id = ++seq
            ids[op] = id
            line("[\"i\"," + Js.quote(proc) + "," + id + "," + num(op.call) + "," + Js.quote(client) + "," + Js.quote(kind) + "," + Js.quote(key) + "," + num(lo) + "," + num(w) + "]")
            return op
        }

        @Synchronized override fun complete(op: Op, result: Boolean?) {
            val at = Recorder.clock()
            val res = if (result == null) "\"unknown\"" else if (result) "\"true\"" else "\"false\""
            line("[\"r\"," + Js.quote(proc) + "," + ids[op] + "," + num(at) + "," + res + "]")
        }

        override fun close() { out.close() }
    }
}
