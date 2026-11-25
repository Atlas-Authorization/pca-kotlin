package net.atlasauth.pca.invariants

/**
 * mulberry32, the seeded generator behind every generated case of the invariant checks: the same seed always yields the same
 * sequence, so a failing case is reproducible from `(seed, run index)`. No randomness from the platform is used.
 */
class Rng(seed: Long) {
    private var a: Long = seed and 0xffffffffL

    /** A double in [0, 1). */
    fun next(): Double {
        a = (a + 0x6d2b79f5L) and 0xffffffffL
        var t = a.toInt()
        t = (t xor (t ushr 15)) * (t or 1)
        t = t xor (t + (t xor (t ushr 7)) * (t or 61))
        return ((t xor (t ushr 14)).toLong() and 0xffffffffL) / 4294967296.0
    }

    /** An integer in [lo, hi] inclusive. */
    fun integer(lo: Long, hi: Long): Long = lo + Math.floor(next() * (hi - lo + 1)).toLong()

    fun bool(): Boolean = next() < 0.5

    fun <T> pick(xs: List<T>): T = xs[integer(0, (xs.size - 1).toLong()).toInt()]

    fun <T> pick(vararg xs: T): T = xs[integer(0, (xs.size - 1).toLong()).toInt()]

    fun bytes(n: Int): ByteArray = ByteArray(n) { integer(0, 255).toByte() }

    /** A double in [lo, hi], with the endpoints drawn on their own about one time in ten each (the edge cases a property must hold at). */
    fun real(lo: Double, hi: Double): Double {
        val x = next()
        if (x < 0.1) return lo
        if (x < 0.2) return hi
        return lo + next() * (hi - lo)
    }

    /** A printable-ASCII string of `min..max` characters. */
    fun string(min: Int, max: Int): String {
        val n = integer(min.toLong(), max.toLong()).toInt()
        val sb = StringBuilder()
        for (i in 0 until n) sb.append(integer(0x20, 0x7e).toInt().toChar())
        return sb.toString()
    }
}
