package net.atlasauth.pca.mpc.net

/** One un-echoed all-to-all round among the parties; a throw inside [parse] aborts the run naming that peer. */
interface Exchanger {
    /** Send `mine(peer)` to every peer, collect theirs and validate each with [parse]; a null [timeoutMs] means the mesh default. */
    fun <T> exchange(rd: String, mine: (Int) -> Any?, parse: (Int, Any?) -> T, timeoutMs: Long? = null): Map<Int, T>

    /** A malformed-data abort naming peer [p]; callers `throw` the result. */
    fun bad(p: Int, what: String): RuntimeException
}

/** Lowercase hex helpers that work on every supported JVM and Android level. */
internal object NetHex {
    private const val DIGITS = "0123456789abcdef"

    fun enc(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xff
            sb.append(DIGITS[v ushr 4]).append(DIGITS[v and 15])
        }
        return sb.toString()
    }

    fun dec(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex length" }
        return ByteArray(s.length / 2) { i ->
            val hi = Character.digit(s[2 * i], 16)
            val lo = Character.digit(s[2 * i + 1], 16)
            require(hi >= 0 && lo >= 0) { "bad hex digit" }
            ((hi shl 4) or lo).toByte()
        }
    }
}
