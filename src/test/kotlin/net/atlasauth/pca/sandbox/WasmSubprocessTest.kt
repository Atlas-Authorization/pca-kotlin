package net.atlasauth.pca.sandbox

import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** The pinned subprocess hosts: pin refusals, the protocol against a fake host, and real runs when a built reference host is named. */
class WasmSubprocessTest {
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun table(): Handles.HandleTable {
        val ex = linkedMapOf<String, Handles.Executor>("fs.read" to Handles.Executor { _, _, _ -> byteArrayOf(5, 6) })
        val t = Handles.HandleTable("wasi_no_ambient", Receipts.ReceiptLog(), ex)
        val params = LinkedHashMap<String, Any?>()
        val op = Authorize.AuthorizedOperation("fs.read", "/x", Pca.hashCanonical(params), "op")
        t.mint(Authorize.Result(true, 200, emptyMap(), emptyList(), null, operation = op), Authorize.Operation("fs.read", "/x", params), Handles.MintOptions())
        return t
    }

    // the fixtures are /bin/sh scripts: POSIX hosts only
    private fun posix() = assumeTrue("POSIX shell fixtures", !System.getProperty("os.name").lowercase().contains("win"))

    private fun fake(body: String): WasmSubprocess {
        posix()
        val f = File(Files.createTempDirectory("pca-host-test-").toFile(), "host.sh")
        val script = "#!/bin/sh\n$body\n".toByteArray()
        f.writeBytes(script)
        f.setExecutable(true)
        return WasmSubprocess(f, sha(script))
    }

    private fun real(): WasmSubprocess {
        val p = System.getenv("PCA_WASMTIME_HOST_BIN")
        val h = System.getenv("PCA_WASMTIME_HOST_SHA256")
        if (p == null || h == null) check(System.getenv("PCA_REQUIRE_WASMTIME_HOST").isNullOrEmpty()) { "PCA_REQUIRE_WASMTIME_HOST is set: export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256" }
        assumeTrue("PCA_WASMTIME_HOST_BIN / PCA_WASMTIME_HOST_SHA256 not set", p != null && h != null)
        return WasmSubprocess(File(p!!), h)
    }

    private val x = byteArrayOf('x'.code.toByte())

    @Test fun pinRefusals() {
        posix()
        assertEquals("host_missing", WasmSubprocess(File("/nonexistent/pca-wasmtime-host"), "a".repeat(64)).runComponent(table(), x, 100).reason)
        assertEquals("host_unpinned", WasmSubprocess(File("/bin/sh"), "").runComponent(table(), x, 100).reason)
        assertEquals("host_unpinned", WasmSubprocess(File("/bin/sh"), null).runComponent(table(), x, 100).reason)
        assertEquals("host_hash_mismatch", WasmSubprocess(File("/bin/sh"), "0".repeat(64)).runCore(table(), x, 100).reason)
        assertEquals("bad_fuel", WasmSubprocess(File("/bin/sh"), "0".repeat(64)).runComponent(table(), x, 0).reason)
        assertEquals("module_size", WasmSubprocess(File("/bin/sh"), "0".repeat(64)).runCore(table(), ByteArray(0), 10).reason)
    }

    @Test fun protocolAgainstFakeHost() {
        val h = fake("printf '{\"op\":\"count\"}\\n'; read a; printf '{\"op\":\"invoke\",\"h\":1}\\n'; read b; case \"\$b\" in *\"[5,6]\"*) printf '{\"done\":5,\"fuel_used\":1}\\n';; *) printf '{\"fail\":\"bad_reply\"}\\n';; esac")
        val t = table()
        val r = h.runComponent(t, x, 1000, 5000)
        assertTrue(r.toString(), r.ok)
        assertEquals(5L, r.value)
        // the use is spent: the second run is answered err -2 and the fake reports it
        assertEquals("bad_reply", h.runComponent(t, x, 1000, 5000).reason)
    }

    @Test fun hungGarbageAndExitingHosts() {
        assertEquals("timeout", fake("read a").runComponent(table(), x, 1000, 300).reason)
        assertEquals("host_protocol", fake("echo not-json").runComponent(table(), x, 1000, 5000).reason)
        assertEquals("host_exit", fake("exit 0").runComponent(table(), x, 1000, 5000).reason)
        assertEquals("fuel_exhausted", fake("echo '{\"fail\":\"fuel_exhausted\"}'").runComponent(table(), x, 1000, 5000).reason)
    }

    @Test fun realHostLimits() {
        val h = real()
        assertEquals(5L, h.runComponent(table(), ReferenceComponent.referenceComponentWat(null).toByteArray(), 1_000_000).value)
        assertEquals("fuel_exhausted", h.runComponent(table(), ReferenceComponent.referenceComponentWat(mapOf("spin" to true)).toByteArray(), 10_000).reason)
        assertEquals(
            "ambient_import:wasi:cli/environment@0.2.0",
            h.runComponent(table(), ReferenceComponent.referenceComponentWat(mapOf("extraImport" to "wasi:cli/environment@0.2.0")).toByteArray(), 1_000_000).reason,
        )
    }

    @Test fun realHostCoreMode() {
        val h = real()
        val spec = mapOf("calls" to listOf(mapOf("handle" to 1, "ptr" to 0, "cap" to 16)), "returns" to "byte0")
        assertEquals(5L, h.runCore(table(), ReferenceTool.buildTool(spec), 1_000_000).value)
        assertEquals("fuel_exhausted", h.runCore(table(), ReferenceTool.buildTool(mapOf("calls" to emptyList<Any?>(), "spin" to true)), 10_000).reason)
    }
}
