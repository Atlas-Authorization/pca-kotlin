package net.atlasauth.pca.actions.importers

import java.util.ArrayDeque
import net.atlasauth.pca.verifier.ActionKitError

/** The bounds every importer enforces before it believes a byte of foreign input: size, depth, node count and reference expansion. */
class ImportLimits(
    @JvmField val maxBytes: Long,
    @JvmField val maxOps: Long,
    @JvmField val maxJsonDepth: Long,
    @JvmField val maxNodes: Long,
    @JvmField val maxRefNodes: Long,
    @JvmField val maxRefDepth: Long,
) {
    private fun of(i: Int): Long = when (i) { 0 -> maxBytes; 1 -> maxOps; 2 -> maxJsonDepth; 3 -> maxNodes; 4 -> maxRefNodes; else -> maxRefDepth }

    /** Size check of a text source (UTF-8 bytes). */
    fun textSizeCheck(text: String) {
        if (text.length.toLong() * 3 > maxBytes && Jx.u8(text) > maxBytes) throw ActionKitError("import_limit", "the source is larger than $maxBytes bytes")
    }

    /**
     * Walk a parsed source iteratively and refuse it when it is not plain JSON data, or is deeper or larger than the limits.
     * Returns the node count.
     */
    fun checkParsed(root: Any?): Long {
        var nodes = 0L
        var bytes = 0L
        val stack = ArrayDeque<Pair<Any?, Int>>()
        stack.push(Pair(root, 0))
        while (!stack.isEmpty()) {
            val top = stack.pop()
            val v = top.first
            val d = top.second
            if (++nodes > maxNodes) throw ActionKitError("import_limit", "the source has more than $maxNodes nodes")
            if (d > maxJsonDepth) throw ActionKitError("import_limit", "the source nests deeper than $maxJsonDepth")
            if (v == null || v is Boolean) bytes += 4
            else if (v is String) bytes += v.length
            else if (v is List<*>) {
                bytes += 2 + v.size
                for (x in v) stack.push(Pair(x, d + 1))
            } else if (v is Map<*, *>) {
                for ((k, x) in v) {
                    bytes += (k as String).length + 4
                    stack.push(Pair(x, d + 1))
                }
            } else {
                val n = Jx.num(v) ?: throw ActionKitError("bad_source", "the source holds a ${v.javaClass.simpleName}")
                if (n.isNaN() || n.isInfinite()) throw ActionKitError("bad_source", "the source holds a non-finite number")
                bytes += 8
            }
            if (bytes > maxBytes) throw ActionKitError("import_limit", "the source is larger than $maxBytes bytes")
        }
        return nodes
    }

    companion object {
        @JvmField val DEFAULT = ImportLimits(64L * 1024 * 1024, 20_000, 64, 6_000_000, 20_000, 8)

        /** Ceilings no caller may raise past: a caller-supplied limit is clamped to these. */
        @JvmField val HARD = ImportLimits(256L * 1024 * 1024, 50_000, 128, 20_000_000, 200_000, 16)

        private val KEYS = listOf("max_bytes", "max_ops", "max_json_depth", "max_nodes", "max_ref_nodes", "max_ref_depth")

        /** Defaults, overridden member by member (clamped to the hard ceilings); a member that is not a positive safe integer is refused. */
        @JvmStatic
        fun resolve(over: Any?): ImportLimits {
            val out = LongArray(6)
            for (i in 0 until 6) {
                out[i] = DEFAULT.of(i)
                if (over !is Map<*, *> || !over.containsKey(KEYS[i])) continue
                val v = over[KEYS[i]]
                if (!Jx.isSafe(v) || Jx.num(v)!! < 1) throw ActionKitError("bad_limit", "limit ${KEYS[i]} must be a positive safe integer")
                out[i] = Math.min(Jx.num(v)!!.toLong(), HARD.of(i))
            }
            return ImportLimits(out[0], out[1], out[2], out[3], out[4], out[5])
        }
    }
}
