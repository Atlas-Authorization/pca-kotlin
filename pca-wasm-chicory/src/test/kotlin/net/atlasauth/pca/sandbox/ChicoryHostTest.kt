package net.atlasauth.pca.sandbox

import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Chicory core host: handle use, fuel, wall-clock, memory cap, import allow-list, egress through the policy. */
class ChicoryHostTest {
    private fun allow(verb: String, resource: String, params: Map<String, Any?>): Authorize.Result =
        Authorize.Result(true, 200, emptyMap(), emptyList(), null, operation = Authorize.AuthorizedOperation(verb, resource, Pca.hashCanonical(params), "op"))

    private fun mint(t: Handles.HandleTable, verb: String, resource: String) {
        val params = LinkedHashMap<String, Any?>()
        t.mint(allow(verb, resource, params), Authorize.Operation(verb, resource, params), Handles.MintOptions())
    }

    private fun fetch(policy: Egress.EgressPolicy, url: String): ByteArray {
        if (policy.claim("GET", url, null)["allow"] != true) throw IllegalStateException("egress denied")
        return byteArrayOf(1)
    }

    /** handles: 1 fs.read, 2 net.ok (admitted), 3 net.evil (no admission). */
    private fun table(): Handles.HandleTable {
        val policy = Egress.EgressPolicy()
        val params = LinkedHashMap<String, Any?>()
        val tmpl = linkedMapOf<String, Any?>("method" to "GET", "scheme" to "https", "host" to "api.example.com", "path" to "/v1")
        policy.admit(allow("net.ok", "api.example.com", params), Authorize.Operation("net.ok", "api.example.com", params), { tmpl }, null, null)
        val ex = linkedMapOf<String, Handles.Executor>(
            "fs.read" to Handles.Executor { _, _, _ -> byteArrayOf(7, 8, 9) },
            "net.ok" to Handles.Executor { _, _, _ -> fetch(policy, "https://api.example.com/v1") },
            "net.evil" to Handles.Executor { _, _, _ -> fetch(policy, "https://evil.example/x") },
        )
        val t = Handles.HandleTable("wasi_no_ambient", Receipts.ReceiptLog(), ex)
        mint(t, "fs.read", "/x")
        mint(t, "net.ok", "api.example.com")
        mint(t, "net.evil", "evil.example")
        return t
    }

    private fun call(h: Int, ptr: Int, cap: Int): Map<String, Any?> = linkedMapOf("handle" to h, "ptr" to ptr, "cap" to cap)

    private fun tool(vararg kv: Pair<String, Any?>): ByteArray = ReferenceTool.buildTool(linkedMapOf(*kv))

    private fun opts() = ChicoryHost.Options(10_000_000L)

    private fun mem(min: Int, max: Int?): Map<String, Any?> = linkedMapOf("min" to min, "max" to max)

    @Test fun handleResultLandsInMemory() {
        val r = ChicoryHost.run(table(), tool("calls" to listOf(call(1, 0, 16)), "returns" to "byte0"), "run", opts())
        assertTrue(r.toString(), r.ok)
        assertEquals(7L, r.value)
    }

    @Test fun infiniteLoopHitsFuel() {
        assertEquals("fuel_exhausted", ChicoryHost.run(table(), tool("calls" to emptyList<Any?>(), "spin" to true), "run", ChicoryHost.Options(10_000)).reason)
    }

    @Test fun infiniteLoopHitsWallClock() {
        val o = ChicoryHost.Options(Long.MAX_VALUE / 2)
        o.timeoutMs = 300
        assertEquals("timeout", ChicoryHost.run(table(), tool("calls" to emptyList<Any?>(), "spin" to true), "run", o).reason)
    }

    @Test fun fuelIsRequired() {
        assertEquals("bad_fuel", ChicoryHost.run(table(), tool("calls" to emptyList<Any?>()), "run", ChicoryHost.Options(0)).reason)
    }

    @Test fun memoryOverCapOrUndeclaredIsRefused() {
        for (m in listOf(mem(1, 257), mem(1, null), mem(257, 257))) {
            assertEquals("memory_limits", ChicoryHost.run(table(), tool("calls" to emptyList<Any?>(), "memory" to m), "run", opts()).reason)
        }
        val o = opts()
        o.maxMemoryPages = 2
        assertEquals("memory_limits", ChicoryHost.run(table(), tool("calls" to emptyList<Any?>(), "memory" to mem(1, 4)), "run", o).reason)
        assertTrue(ChicoryHost.run(table(), tool("calls" to emptyList<Any?>(), "memory" to mem(1, 4)), "run", opts()).ok)
    }

    @Test fun forbiddenImportsAreRefused() {
        for ((m, n) in listOf("wasi_snapshot_preview1" to "fd_write", "env" to "x", "pca:act" to "other")) {
            val imp = linkedMapOf<String, Any?>("module" to m, "name" to n)
            val r = ChicoryHost.run(table(), tool("calls" to emptyList<Any?>(), "extraImports" to listOf(imp)), "run", opts())
            assertEquals("ambient_import:$m.$n", r.reason)
        }
    }

    @Test fun malformedSizeAndEntry() {
        assertEquals("module_size", ChicoryHost.run(table(), ByteArray(0), "run", opts()).reason)
        assertEquals("malformed_module", ChicoryHost.run(table(), byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9), "run", opts()).reason)
        assertEquals("no_entry", ChicoryHost.run(table(), tool("calls" to emptyList<Any?>()), "nope", opts()).reason)
    }

    @Test fun badOutputWindowSpendsNoUse() {
        val t = table()
        assertEquals(-4L, ChicoryHost.run(t, tool("calls" to listOf(call(1, 70000, 16))), "run", opts()).value)
        assertEquals(3L, ChicoryHost.run(t, tool("calls" to listOf(call(1, 0, 16))), "run", opts()).value)
    }

    @Test fun egressInsidePolicyPassesOutsideIsRefused() {
        val t = table()
        assertEquals(1L, ChicoryHost.run(t, tool("calls" to listOf(call(2, 0, 16))), "run", opts()).value)
        assertEquals(-5L, ChicoryHost.run(t, tool("calls" to listOf(call(3, 0, 16))), "run", opts()).value)
    }
}
