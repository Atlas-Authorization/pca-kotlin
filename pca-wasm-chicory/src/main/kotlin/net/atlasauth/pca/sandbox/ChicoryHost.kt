package net.atlasauth.pca.sandbox

import net.atlasauth.pca.verifier.Json

import com.dylibso.chicory.runtime.ChicoryInterruptedException
import com.dylibso.chicory.runtime.ExecutionListener
import com.dylibso.chicory.runtime.HostFunction
import com.dylibso.chicory.runtime.ImportValues
import com.dylibso.chicory.runtime.Instance
import com.dylibso.chicory.runtime.Memory
import com.dylibso.chicory.runtime.WasmFunctionHandle
import com.dylibso.chicory.wasm.Parser
import com.dylibso.chicory.wasm.WasmModule
import com.dylibso.chicory.wasm.types.ExternalType
import com.dylibso.chicory.wasm.types.FunctionType
import com.dylibso.chicory.wasm.types.MemoryLimits
import com.dylibso.chicory.wasm.types.ValType
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicReference

/**
 * Core-module WebAssembly host on Chicory (pure JVM, interpreter machine). The tool imports only `pca:act.{invoke,handle_count,
 * handle_verb}`; no WASI is linked, so it has no filesystem, network, clock, random or environment. Limits, none optional: an
 * instruction budget (`fuel`, required, counted by Chicory's per-instruction `ExecutionListener`), a wall-clock deadline (the same
 * listener checks it, and the run thread is interrupted as a second stop), the declared-memory checks of the reference (one memory,
 * a declared maximum, non-shared 32-bit, within the page cap) and Chicory's own maximum-pages enforcement on `memory.grow`.
 *
 * Reasons are the reference's: module_size, malformed_module, memory_limits, ambient_import:module.name, no_entry,
 * trap:RuntimeError, trap:LinkError, plus bad_fuel, fuel_exhausted, timeout.
 *
 * Known differences: the listener API is marked experimental upstream (the build pins 1.7.5); a `memory.grow` past the declared
 * maximum returns -1 to the guest (WebAssembly semantics) instead of trapping; an executor that blocks is not stopped by the
 * deadline (only guest code is).
 */
object ChicoryHost {
    /** Run limits. [fuel] has no default: a budget is a decision. */
    class Options(@JvmField val fuel: Long) {
        @JvmField var timeoutMs: Long = 5000
        @JvmField var maxModuleBytes: Int = 1 shl 20
        @JvmField var maxMemoryPages: Int = 256
        @JvmField var maxResultBytes: Int = 1 shl 20
    }

    private class FuelExhausted : RuntimeException("fuel_exhausted", null, false, false)

    private class DeadlineExceeded : RuntimeException("timeout", null, false, false)

    /** `[count, min, max (-1 = none), shared]` of the first memory; null = no memory section; throws on an unparseable module. */
    internal fun memoryLimits(b: ByteArray): LongArray? {
        require(b.size >= 8 && b[0].toInt() == 0 && b[1].toInt() == 0x61 && b[2].toInt() == 0x73 && b[3].toInt() == 0x6d) { "bad magic" }
        val o = intArrayOf(8)
        while (o[0] < b.size) {
            val id = b[o[0]++].toInt() and 0xff
            val size = leb(b, o)
            val end = o[0] + size
            require(end <= b.size) { "section overruns" }
            if (id == 5) {
                val count = leb(b, o)
                if (count == 0L) return null
                require(o[0] < b.size) { "eof" }
                val flag = b[o[0]++].toInt() and 0xff
                if (flag > 3) return longArrayOf(count, Long.MAX_VALUE, -1, 1) // memory64 and anything newer: refused
                val min = leb(b, o)
                val max = if ((flag and 1) != 0) leb(b, o) else -1L
                return longArrayOf(count, min, max, if ((flag and 2) != 0) 1 else 0)
            }
            o[0] = end.toInt()
        }
        return null
    }

    private fun leb(b: ByteArray, o: IntArray): Long {
        var r = 0L
        var shift = 0
        while (shift < 35) {
            require(o[0] < b.size) { "eof" }
            val x = b[o[0]++].toInt() and 0xff
            r += (x and 0x7f).toLong() shl shift
            if ((x and 0x80) == 0) return r
            shift += 7
        }
        throw IllegalArgumentException("leb")
    }

    private fun chain(t0: Throwable?, c: Class<out Throwable>): Boolean {
        var t = t0
        var i = 0
        while (t != null && i < 16) {
            if (c.isInstance(t)) return true
            t = t.cause
            i++
        }
        return false
    }

    /** Run [bytes] (a core module) and call its export [entry] over [table]. */
    @JvmStatic
    fun run(table: Handles.HandleTable, bytes: ByteArray, entry: String, o: Options): WasmSubprocess.Result {
        if (o.fuel < 1) return WasmSubprocess.Result.fail("bad_fuel")
        if (o.maxMemoryPages < 1 || o.timeoutMs < 1) return WasmSubprocess.Result.fail("bad_limits")
        if (bytes.isEmpty() || bytes.size > o.maxModuleBytes) return WasmSubprocess.Result.fail("module_size")
        try {
            val mem = memoryLimits(bytes)
            if (mem != null && (mem[0] > 1 || mem[3] == 1L || mem[2] < 0 || mem[1] > o.maxMemoryPages || mem[2] > o.maxMemoryPages)) return WasmSubprocess.Result.fail("memory_limits")
        } catch (e: RuntimeException) {
            return WasmSubprocess.Result.fail("malformed_module")
        }
        val module: WasmModule = try {
            Parser.parse(bytes)
        } catch (e: RuntimeException) {
            return WasmSubprocess.Result.fail("malformed_module")
        }
        val imports = module.importSection()
        for (i in 0 until imports.importCount()) {
            val im = imports.getImport(i)
            val allowed = im.module() == Host.IMPORT_MODULE && im.importType() == ExternalType.FUNCTION && im.name() in Host.ALLOWED_IMPORTS
            if (!allowed) return WasmSubprocess.Result.fail("ambient_import:${im.module()}.${im.name()}")
        }

        val deadline = System.nanoTime() + o.timeoutMs * 1_000_000L
        var fuel = o.fuel
        var tick = 0
        val i3 = FunctionType.of(listOf(ValType.I32, ValType.I32, ValType.I32), listOf(ValType.I32))
        val count = HostFunction(Host.IMPORT_MODULE, "handle_count", FunctionType.of(emptyList(), listOf(ValType.I32)), WasmFunctionHandle { _, _ -> longArrayOf(table.size().toLong()) })
        val verb = HostFunction(
            Host.IMPORT_MODULE, "handle_verb", i3,
            WasmFunctionHandle { ins, a ->
                val v = table.verbOf(a[0].toInt().toLong()) ?: return@WasmFunctionHandle code("unknown_handle")
                val m = memory(ins)
                val p = a[1] and 0xFFFFFFFFL
                val l = a[2] and 0xFFFFFFFFL
                if (m == null || p + l > m.pages().toLong() * 65536L) return@WasmFunctionHandle code("bad_memory")
                val enc = Json.utf8(v)
                if (enc.size > l) return@WasmFunctionHandle code("out_too_small")
                m.write(p.toInt(), enc)
                longArrayOf(enc.size.toLong())
            },
        )
        val invoke = HostFunction(
            Host.IMPORT_MODULE, "invoke", i3,
            WasmFunctionHandle { ins, a ->
                // validate the guest's output window before spending the use
                val m = memory(ins)
                val p = a[1] and 0xFFFFFFFFL
                val l = a[2] and 0xFFFFFFFFL
                if (m == null || p + l > m.pages().toLong() * 65536L) return@WasmFunctionHandle code("bad_memory")
                val r = table.use(a[0].toInt().toLong())
                if (!r.ok) return@WasmFunctionHandle code(r.reason!!)
                val res = r.result!!
                if (res.size > o.maxResultBytes || res.size > l) return@WasmFunctionHandle code("out_too_small")
                m.write(p.toInt(), res)
                longArrayOf(res.size.toLong())
            },
        )

        val out = AtomicReference<WasmSubprocess.Result>()
        val t = Thread({
            var instantiated = false
            try {
                val instance = Instance.builder(module)
                    .withImportValues(ImportValues.builder().addFunction(count, verb, invoke).build())
                    .withMemoryLimits(mem(module, o.maxMemoryPages))
                    .withUnsafeExecutionListener(
                        ExecutionListener { _, _ ->
                            if (--fuel < 0) throw FuelExhausted()
                            if ((++tick and 255) == 0 && System.nanoTime() > deadline) throw DeadlineExceeded()
                        },
                    )
                    .build()
                instantiated = true
                val fn = try { instance.exports().function(entry) } catch (e: RuntimeException) { null }
                if (fn == null) {
                    out.set(WasmSubprocess.Result.fail("no_entry"))
                } else {
                    val r = fn.apply()
                    out.set(WasmSubprocess.Result.ok(if (r != null && r.isNotEmpty()) r[0].toInt().toLong() else 0L))
                }
            } catch (e: Throwable) {
                out.set(
                    when {
                        chain(e, FuelExhausted::class.java) -> WasmSubprocess.Result.fail("fuel_exhausted")
                        chain(e, DeadlineExceeded::class.java) || chain(e, ChicoryInterruptedException::class.java) -> WasmSubprocess.Result.fail("timeout")
                        !instantiated -> WasmSubprocess.Result.fail("trap:LinkError")
                        else -> WasmSubprocess.Result.fail("trap:RuntimeError")
                    },
                )
            }
        }, "pca-wasm-chicory")
        t.isDaemon = true
        t.start()
        try {
            t.join(o.timeoutMs + 2000)
            if (t.isAlive) {
                // the listener normally stops the guest first; this is the second stop
                t.interrupt()
                t.join(1000)
                if (t.isAlive) return WasmSubprocess.Result.fail("timeout")
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            t.interrupt()
            return WasmSubprocess.Result.fail("timeout")
        }
        return out.get() ?: WasmSubprocess.Result.fail("trap:RuntimeError")
    }

    private fun mem(module: WasmModule, cap: Int): MemoryLimits? {
        val sec = module.memorySection().orElse(null)
        if (sec == null || sec.memoryCount() == 0) return null
        val d = sec.getMemory(0).limits()
        // declared maximum already checked <= cap; clamp anyway so the engine's own limit is the cap
        return MemoryLimits(d.initialPages(), minOf(d.maximumPages(), cap))
    }

    private fun memory(ins: Instance): Memory? = try { ins.exports().memory("memory") } catch (e: RuntimeException) { null }

    private fun code(reason: String): LongArray = longArrayOf(Handles.USE_ERR.getValue(reason))
}
