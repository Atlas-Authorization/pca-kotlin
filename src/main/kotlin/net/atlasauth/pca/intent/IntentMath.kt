package net.atlasauth.pca.intent

/** Base-2 logarithm with the exact bit pattern of ECMAScript's Math.log2 (the fdlibm algorithm); the JDK has no log2. */
object IntentMath {
    private fun kLog1p(f: Double): Double {
        val lg1 = 6.666666666666735130e-01
        val lg2 = 3.999999999940941908e-01
        val lg3 = 2.857142874366239149e-01
        val lg4 = 2.222219843214978396e-01
        val lg5 = 1.818357216161805012e-01
        val lg6 = 1.531383769920937332e-01
        val lg7 = 1.479819860511658591e-01
        val s = f / (2.0 + f)
        val z = s * s
        val w = z * z
        val t1 = w * (lg2 + w * (lg4 + w * lg6))
        val t2 = z * (lg1 + w * (lg3 + w * (lg5 + w * lg7)))
        val r = t2 + t1
        val hfsq = 0.5 * f * f
        return s * (hfsq + r)
    }

    @JvmStatic
    fun log2(x0: Double): Double {
        val two54 = 1.80143985094819840000e+16
        val ivln2hi = 1.44269504072144627571e+00
        val ivln2lo = 1.67517131648865118353e-10
        var x = x0
        val bits = java.lang.Double.doubleToRawLongBits(x)
        var hx = (bits shr 32).toInt()
        val lx = bits.toInt()
        var k = 0
        if (hx < 0x00100000) {
            if (((hx and 0x7fffffff) or lx) == 0) return Double.NEGATIVE_INFINITY
            if (hx < 0) return Double.NaN
            k -= 54
            x *= two54
            hx = (java.lang.Double.doubleToRawLongBits(x) shr 32).toInt()
        }
        if (hx >= 0x7ff00000) return x + x
        if (hx == 0x3ff00000 && lx == 0) return 0.0
        k += (hx shr 20) - 1023
        hx = hx and 0x000fffff
        val i = (hx + 0x95f64) and 0x100000
        val xb = java.lang.Double.doubleToRawLongBits(x)
        x = java.lang.Double.longBitsToDouble(((hx or (i xor 0x3ff00000)).toLong() shl 32) or (xb and 0xffffffffL))
        k += i shr 20
        val y = k.toDouble()
        val f = x - 1.0
        val hfsq = 0.5 * f * f
        val r = kLog1p(f)
        val hi = java.lang.Double.longBitsToDouble(java.lang.Double.doubleToRawLongBits(f - hfsq) and -0x100000000L)
        val lo = (f - hi) - hfsq + r
        var valHi = hi * ivln2hi
        var valLo = (lo + hi) * ivln2lo + lo * ivln2hi
        val w = y + valHi
        valLo += (y - w) + valHi
        valHi = w
        return valLo + valHi
    }
}
