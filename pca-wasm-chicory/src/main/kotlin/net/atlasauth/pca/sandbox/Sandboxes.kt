package net.atlasauth.pca.sandbox

import java.util.concurrent.CompletableFuture

/**
 * What [createSandbox] is built from. `executors` run the verbs a handle names (the tool author's connectors); the table's runtime class is
 * the one the [runtimeClaim] PROVES (`{claim, trust}`, see [RuntimeClaims.verifiedRuntimeClass]), capped at what a WASM host can prove; without a
 * claim that verifies it is `none`: an operator's say-so does not count.
 */
class SandboxOptions @JvmOverloads constructor(
    val executors: Map<String, Handles.Executor>,
    val log: Receipts.ReceiptLog? = null,
    val now: (() -> Double)? = null,
    /** Largest tool binary accepted. Default 1 MiB. */
    val maxModuleBytes: Int = 1 shl 20,
    /** Largest linear memory a tool may declare (64 KiB pages). Default 256 (16 MiB). A memory without a declared maximum is refused. */
    val maxMemoryPages: Int = 256,
    /** Largest result one handle use may return to the tool. Default 1 MiB. */
    val maxResultBytes: Int = 1 shl 20,
    val runtimeClaim: Pair<Any?, Any?>? = null,
    /** The instruction budget of one run: there is no default, a budget is a decision. */
    val fuel: Long = 50_000_000,
    /** The wall-clock deadline of one run (ms). */
    val timeoutMs: Long = 5000,
)

/**
 * A WebAssembly host whose only authority is the handles minted into [table]. The tool is a core module that imports nothing but
 * `pca:act.{invoke,handle_count,handle_verb}`: any other import, a memory with no declared maximum, or a shared/64-bit memory is refused
 * before anything runs. Every run is bounded by fuel (instructions) and a wall-clock deadline ([ChicoryHost]).
 */
class Sandbox internal constructor(val table: Handles.HandleTable, val log: Receipts.ReceiptLog, private val o: SandboxOptions) {
    private fun options(timeoutMs: Long): ChicoryHost.Options {
        val c = ChicoryHost.Options(o.fuel)
        c.timeoutMs = timeoutMs
        c.maxModuleBytes = o.maxModuleBytes
        c.maxMemoryPages = o.maxMemoryPages
        c.maxResultBytes = o.maxResultBytes
        return c
    }

    /** Validate and run [bytes], calling its exported [entry]. */
    @JvmOverloads
    fun run(bytes: ByteArray, entry: String = "run"): WasmSubprocess.Result = ChicoryHost.run(table, bytes, entry, options(o.timeoutMs))

    /** The same on a worker thread, with the deadline [timeoutMs] (a tool that never returns is stopped at it). */
    @JvmOverloads
    fun runAsync(bytes: ByteArray, entry: String = "run", timeoutMs: Long = o.timeoutMs): CompletableFuture<WasmSubprocess.Result> =
        CompletableFuture.supplyAsync { ChicoryHost.run(table, bytes, entry, options(timeoutMs)) }
}

/** Build the sandbox: the receipt log, the handle table (minted by the host, never by the tool) and the WebAssembly host. */
fun createSandbox(opts: SandboxOptions): Sandbox {
    val log = opts.log ?: Receipts.ReceiptLog(opts.now?.let { f -> { f() } })
    // a WASM host cannot prove more than wasi_no_ambient, so a stronger claim is capped there
    val proven = opts.runtimeClaim?.let { RuntimeClaims.verifiedRuntimeClass(it.first, it.second) } ?: "none"
    val tableClass = if (proven == "wasi_no_ambient" || proven == "egress_default_deny" || proven == "os_confined") proven else "none"
    val table = Handles.HandleTable(tableClass, log, opts.executors, opts.now)
    return Sandbox(table, log, opts)
}
