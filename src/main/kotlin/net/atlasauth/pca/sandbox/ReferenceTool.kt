package net.atlasauth.pca.sandbox

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError

/**
 * Hand-assembled core-WebAssembly modules for tests, demos and guides: no toolchain needed to see the sandbox work. Byte-identical to
 * the reference's builders (including its habit of writing a name's UTF-16 length as the length prefix).
 */
@Suppress("UNCHECKED_CAST")
object ReferenceTool {
    private fun u(o: ByteArrayOutputStream, n0: Double) {
        var n = n0
        do {
            var b = n.toLong().toInt() and 0x7f
            n = Math.floor(n / 128)
            if (n > 0) b = b or 0x80
            o.write(b)
        } while (n > 0)
    }

    private fun u(n: Double): ByteArray = ByteArrayOutputStream().also { u(it, n) }.toByteArray()

    private fun sleb(o: ByteArrayOutputStream, d: Double) {
        var n = d.toLong().toInt()
        while (true) {
            val b = n and 0x7f
            n = n shr 7
            if ((n == 0 && (b and 0x40) == 0) || (n == -1 && (b and 0x40) != 0)) { o.write(b); return }
            o.write(b or 0x80)
        }
    }

    private fun i32c(o: ByteArrayOutputStream, n: Double) {
        o.write(0x41)
        sleb(o, n)
    }

    private fun str(o: ByteArrayOutputStream, x: String) {
        u(o, x.length.toDouble())
        val b = Json.utf8(x)
        o.write(b, 0, b.size)
    }

    private fun bytes(o: ByteArrayOutputStream, b: ByteArray) = o.write(b, 0, b.size)

    private fun vec(items: List<ByteArray>): ByteArray {
        val o = ByteArrayOutputStream()
        u(o, items.size.toDouble())
        for (i in items) bytes(o, i)
        return o.toByteArray()
    }

    private fun section(id: Int, body: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(id)
        u(o, body.size.toDouble())
        bytes(o, body)
        return o.toByteArray()
    }

    private fun b(vararg xs: Int): ByteArray = ByteArray(xs.size) { xs[it].toByte() }

    private fun cat(vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        for (p in parts) bytes(o, p)
        return o.toByteArray()
    }

    private fun name(x: String): ByteArray = ByteArrayOutputStream().also { str(it, x) }.toByteArray()

    private fun numOf(o: Any?): Double = Js.num(o) ?: throw JsTypeError("not a number")

    private val HEADER = b(0, 0x61, 0x73, 0x6d, 1, 0, 0, 0)

    /**
     * A module that calls `pca:act.invoke(handle, ptr, cap)` for each call of `spec.calls` and returns either the last
     * call's return code or the first byte of linear memory. [spec]: calls [{handle, ptr, cap}], returns ("last" | "byte0"),
     * extraImports [{module, name}], memory {min, max (null: none declared)}, spin.
     */
    @JvmStatic
    fun buildTool(spec: Map<String, Any?>): ByteArray {
        val extra = (spec["extraImports"] as List<Any?>?) ?: emptyList()
        val calls = spec["calls"] as List<Any?>
        val types = vec(listOf(b(0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f), b(0x60, 0, 1, 0x7f), b(0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f)))
        val imp = ArrayList<ByteArray>()
        imp.add(cat(name("pca:act"), name("invoke"), b(0, 0)))
        for (e in extra) {
            val m = e as Map<String, Any?>
            imp.add(cat(name(Js.template(m["module"])), name(Js.template(m["name"])), b(0, 2)))
        }
        val memV = spec["memory"]
        var min = 1.0
        var max = 1.0
        var noMax = false
        if (memV is Map<*, *>) {
            min = numOf(memV["min"])
            if (memV["max"] == null) noMax = true else max = numOf(memV["max"])
        }
        val memItem = if (noMax) cat(b(0), u(min)) else cat(b(1), u(min), u(max))
        val memory = vec(listOf(memItem))
        val runIndex = 1 + extra.size
        val body = ByteArrayOutputStream()
        body.write(0)
        val last = "byte0" != spec["returns"] // `returns ?? 'last'` is 'last' for anything but byte0 in the supported shapes
        for (i in calls.indices) {
            val c = calls[i] as Map<String, Any?>
            i32c(body, numOf(c["handle"]))
            i32c(body, numOf(c["ptr"]))
            i32c(body, numOf(c["cap"]))
            body.write(0x10)
            body.write(0)
            if (!(i == calls.size - 1 && last)) body.write(0x1a)
        }
        if (Js.truthy(spec["spin"])) bytes(body, b(0x03, 0x40, 0x0c, 0x00, 0x0b))
        if ("byte0" == spec["returns"]) {
            i32c(body, 0.0)
            bytes(body, b(0x2d, 0, 0))
        }
        if (calls.isEmpty()) i32c(body, 0.0)
        body.write(0x0b)
        val bodyB = body.toByteArray()
        val code = vec(listOf(cat(u(bodyB.size.toDouble()), bodyB)))
        val exports = vec(listOf(cat(name("memory"), b(2, 0)), cat(name("run"), b(0), u(runIndex.toDouble()))))
        return cat(HEADER, section(1, types), section(2, vec(imp)), section(3, vec(listOf(b(1)))), section(5, memory), section(7, exports), section(10, code))
    }

    /** A tool that asks the table what it holds: returns `handle_count() * 256 + first byte of handle 1's verb` (the verb window is [capArg] bytes). */
    @JvmStatic
    fun buildProbeTool(capArg: Any?): ByteArray {
        val cap = if (capArg == null) 64.0 else numOf(capArg)
        val types = vec(listOf(b(0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f), b(0x60, 0, 1, 0x7f)))
        val imports = vec(listOf(
            cat(name("pca:act"), name("invoke"), b(0, 0)),
            cat(name("pca:act"), name("handle_count"), b(0, 1)),
            cat(name("pca:act"), name("handle_verb"), b(0, 0)),
        ))
        val body = ByteArrayOutputStream()
        body.write(0)
        i32c(body, 1.0)
        i32c(body, 0.0)
        i32c(body, cap)
        bytes(body, b(0x10, 2, 0x1a, 0x10, 1))
        i32c(body, 256.0)
        body.write(0x6c)
        i32c(body, 0.0)
        bytes(body, b(0x2d, 0, 0, 0x6a, 0x0b))
        val bodyB = body.toByteArray()
        val code = vec(listOf(cat(u(bodyB.size.toDouble()), bodyB)))
        val exports = vec(listOf(cat(name("memory"), b(2, 0)), cat(name("run"), b(0, 3))))
        return cat(HEADER, section(1, types), section(2, imports), section(3, vec(listOf(b(1)))), section(5, vec(listOf(b(1, 1, 1)))), section(7, exports), section(10, code))
    }
}
