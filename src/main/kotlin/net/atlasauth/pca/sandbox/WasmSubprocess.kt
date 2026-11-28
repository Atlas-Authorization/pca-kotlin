package net.atlasauth.pca.sandbox

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import net.atlasauth.pca.verifier.Json

/**
 * WebAssembly hosts run as a subprocess of the reference `pca-wasmtime-host` binary: a component (canonical ABI) or, in `core`
 * mode, a core module. The binary does the work (instruction fuel, a wall-clock epoch deadline, a hard memory cap, the import
 * allow-list with no WASI); this class pins it, spawns it with an empty environment and no shell, and serves its handle requests
 * from a [Handles.HandleTable] over JSON lines.
 *
 * Trust in the binary: the path and the SHA-256 come from configuration only. A missing binary, a missing pin or a different hash
 * is refused before anything runs. The verified bytes are copied into a private temp directory and that copy is executed, so there
 * is no window between the hash and the exec.
 *
 * Platform: a JVM feature. It needs `java.nio.file` and `ProcessBuilder`, so on Android it needs API 26+ (the library's minSdk is 24:
 * below 26 a run is refused with host_unavailable, never a crash), and an Android app must also be allowed to execute a binary from
 * its private directory (the reference host is a desktop/server binary; ship it for the device ABI yourself). On a plain JVM there is no
 * gate. The in-process Chicory host (module `pca-wasm-chicory`) is pure JVM and is not part of the Android library.
 *
 * Reasons are the host's (fuel_exhausted, timeout, memory_limits, ambient_import:..., trap:RuntimeError, ...) plus bad_fuel,
 * host_unpinned, host_missing, host_hash_mismatch, host_unavailable, host_protocol, host_exit.
 */
class WasmSubprocess(private val binary: File, expectedSha256: String?) {
    /** Outcome of a run: a value, or a refusal reason. */
    class Result private constructor(@JvmField val ok: Boolean, @JvmField val value: Long, @JvmField val reason: String?) {
        override fun toString(): String = if (ok) "ok:$value" else "fail:$reason"

        companion object {
            @JvmStatic fun ok(v: Long) = Result(true, v, null)

            @JvmStatic fun fail(r: String) = Result(false, 0, r)
        }
    }

    private val expected: String = (expectedSha256 ?: "").lowercase(Locale.ROOT)

    /** Run a component (binary or WAT text). [fuel] has no default: a budget is a decision. */
    @JvmOverloads
    fun runComponent(table: Handles.HandleTable, component: ByteArray, fuel: Long, timeoutMs: Long = 10_000, maxResultBytes: Int = 1 shl 20): Result {
        if (fuel < 1 || fuel > MAX_FUEL) return Result.fail("bad_fuel")
        return run(table, component, listOf(FILE, fuel.toString()), timeoutMs, maxResultBytes)
    }

    /** Run a core module's export [entry] under fuel, a wall-clock deadline and a cap of [maxPages] 64 KiB pages. */
    @JvmOverloads
    fun runCore(
        table: Handles.HandleTable, module: ByteArray, fuel: Long, entry: String = "run", maxPages: Long = 256, timeoutMs: Long = 5000,
        maxModuleBytes: Int = 1 shl 20, maxResultBytes: Int = 1 shl 20,
    ): Result {
        if (fuel < 1 || fuel > MAX_FUEL) return Result.fail("bad_fuel")
        if (maxPages < 1 || maxPages > 65536 || timeoutMs < 1) return Result.fail("bad_limits")
        if (module.isEmpty() || module.size > maxModuleBytes || module.size > (1 shl 20)) return Result.fail("module_size")
        // the host enforces its own deadline; this parent's kill timer is a little longer so the host's reason wins
        return run(table, module, listOf("core", FILE, fuel.toString(), maxPages.toString(), timeoutMs.toString(), entry), timeoutMs + 1000, maxResultBytes)
    }

    private fun run(table: Handles.HandleTable, payload: ByteArray, args: List<String>, timeoutMs: Long, maxResult: Int): Result {
        if (ANDROID_SDK < 26) return Result.fail("host_unavailable")
        if (!PIN.matches(expected)) return Result.fail("host_unpinned")
        val bin = try {
            binary.readBytes()
        } catch (e: Exception) {
            return Result.fail("host_missing")
        }
        val got = MessageDigest.getInstance("SHA-256").digest(bin).joinToString("") { "%02x".format(it.toInt() and 0xff) }
        if (!MessageDigest.isEqual(got.toByteArray(StandardCharsets.US_ASCII), expected.toByteArray(StandardCharsets.US_ASCII))) return Result.fail("host_hash_mismatch")
        var dir: File? = null
        var p: Process? = null
        try {
            dir = Files.createTempDirectory("pca-comp-").toFile()
            val exe = File(dir, "host")
            exe.writeBytes(bin)
            if (!exe.setExecutable(true, true)) return Result.fail("host_unavailable")
            val file = File(dir, "tool.wasm")
            file.writeBytes(payload)
            val pb = ProcessBuilder(listOf(exe.path) + args.map { if (it == FILE) file.path else it })
            pb.environment().clear()
            p = pb.start()
            val proc = p
            Thread { try { proc.errorStream.use { s -> val b = ByteArray(4096); while (s.read(b) >= 0) { /* drained so the child never blocks on a full pipe */ } } } catch (e: Exception) {} }.also { it.isDaemon = true }.start()
            return serve(table, proc, timeoutMs, maxResult)
        } catch (e: Exception) {
            return Result.fail("host_unavailable")
        } finally {
            p?.destroyForcibly()
            dir?.deleteRecursively()
        }
    }

    private fun serve(table: Handles.HandleTable, p: Process, timeoutMs: Long, maxResult: Int): Result {
        val lines = LinkedBlockingQueue<String>()
        Thread {
            try {
                p.inputStream.bufferedReader(StandardCharsets.UTF_8).forEachLine { lines.add(it) }
            } catch (e: Exception) {
                // closed
            }
            lines.add(EOF)
        }.also { it.isDaemon = true }.start()
        val input = p.outputStream
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        while (true) {
            val line = try {
                lines.poll(maxOf(0L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                return Result.fail("host_unavailable")
            } ?: return Result.fail("timeout")
            if (line == EOF) return Result.fail("host_exit")
            val parsed = try { Json.parse(line) } catch (e: IllegalArgumentException) { return Result.fail("host_protocol") }
            if (parsed !is Map<*, *>) return Result.fail("host_protocol")
            val f = parsed["fail"]
            if (f is String) return Result.fail(f)
            if (Json.isSafeInt(parsed["done"])) return Result.ok(Json.asLong(parsed["done"]))
            val h = if (Json.isSafeInt(parsed["h"])) Json.asLong(parsed["h"]) else 0L
            val reply = when (parsed["op"]) {
                "count" -> "{\"n\":${table.size()}}"
                "verb" -> table.verbOf(h)?.let { "{\"ok\":${Json.canonicalize(it)}}" } ?: "{\"err\":-1}"
                "invoke" -> {
                    val r = table.use(h)
                    if (!r.ok) "{\"err\":${Handles.USE_ERR[r.reason] ?: -5}}"
                    else if (r.result!!.size > maxResult) "{\"err\":-3}"
                    else r.result.joinToString(",", "{\"ok\":[", "]}") { (it.toInt() and 0xff).toString() }
                }
                else -> return Result.fail("host_protocol")
            }
            try {
                // requests are answered strictly one at a time, in order
                input.write(Json.utf8((reply + "\n")))
                input.flush()
            } catch (e: java.io.IOException) {
                return Result.fail("host_exit")
            }
        }
    }

    private companion object {
        const val MAX_FUEL = 9007199254740991L
        const val FILE = "@FILE@"
        const val EOF = "\u0000eof"
        val PIN = Regex("[0-9a-f]{64}")

        /** The Android SDK level when running on Android, else MAX_VALUE (a plain JVM has no gate). */
        val ANDROID_SDK: Int = try {
            // the stub android.jar of an Android unit test reports 0: that is a host JVM, not a device below API 26
            Class.forName("android.os.Build\$VERSION").getField("SDK_INT").getInt(null).let { if (it == 0) Int.MAX_VALUE else it }
        } catch (_: Throwable) {
            Int.MAX_VALUE
        }
    }
}
