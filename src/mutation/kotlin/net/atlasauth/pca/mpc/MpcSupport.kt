package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.mpc.Party.DecisionVector
import net.atlasauth.pca.mpc.Spdz.AuthSV
import net.atlasauth.pca.mpc.Spdz.AuthTriple
import net.atlasauth.pca.mpc.Spdz.Deviation
import net.atlasauth.pca.mpc.Spdz.MacContext
import net.atlasauth.pca.mpc.Spdz.MacKey

/** Argument decoding and result encoding shared by the MPC differential tests (bigints travel as decimal strings). */
@Suppress("UNCHECKED_CAST", "FunctionName")
internal object MpcSupport {
    fun B(o: Any?): BigInteger {
        if (o !is String) throw IllegalArgumentException("bigint arg")
        return BigInteger(o)
    }

    /** A JavaScript integer argument (a non-integer is the reference's Number.isInteger failure). */
    fun I(o: Any?): Int {
        val d = Js.num(o)
        if (d == null || d.isInfinite() || d.isNaN() || d != Math.rint(d)) throw IllegalArgumentException("not an integer")
        if (Math.abs(d) > 1e9) return if (d > 0) Int.MAX_VALUE else Int.MIN_VALUE
        return d.toInt()
    }

    fun D(o: Any?): Double = Js.num(o) ?: throw IllegalArgumentException("not a number")

    fun rng(seed: Any?): Field.FieldRng = Field.FieldRng(B(seed))

    /** A big-integer array; a null element is what the reference's strict operations refuse. */
    fun BA(o: Any?): Array<BigInteger> = Array((o as List<Any?>).size) { B(o[it]) }

    /** A big-integer array that may hold nulls (an absent share). */
    fun BAn(o: Any?): Array<BigInteger?> = Array((o as List<Any?>).size) { if (o[it] == null) null else B(o[it]) }

    fun BAA(o: Any?): Array<Array<BigInteger>> = Array((o as List<Any?>).size) { BA(o[it]) }

    fun IA(o: Any?): IntArray = IntArray((o as List<Any?>).size) { I(o[it]) }

    fun L(a: Array<out BigInteger?>): List<Any?> = a.map { it?.toString() }

    fun LL(a: Array<Array<BigInteger>>): List<Any?> = a.map { L(it) }

    fun L(a: IntArray): List<Any?> = a.toList()

    fun M(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = linkedMapOf(*kv)

    fun map(o: Any?): Map<String, Any?> {
        if (o !is Map<*, *>) throw IllegalArgumentException("not an object")
        return o as Map<String, Any?>
    }

    fun vectors(o: Any?): List<DecisionVector> {
        if (o !is List<*>) throw IllegalArgumentException("decision vectors must be an array")
        return o.map { e ->
            if (e !is Map<*, *>) throw IllegalArgumentException("decision vector must be an object")
            val m = map(e)
            DecisionVector(I(m["allow"]), I(m["t"]), I(m["rQuant"]))
        }
    }

    fun authSV(x: AuthSV): Map<String, Any?> = M("value" to L(x.value), "mac" to L(x.mac), "extraMac" to LL(x.extraMac))

    fun triple(t: AuthTriple): Map<String, Any?> = M("a" to authSV(t.a), "b" to authSV(t.b), "c" to authSV(t.c))

    fun key(k: MacKey): Map<String, Any?> = M("alphaShares" to L(k.alphaShares), "alpha" to k.alpha.toString())

    fun ctx(c: MacContext): LinkedHashMap<String, Any?> =
        M("n" to c.n, "alphaShares" to L(c.alphaShares), "alpha" to c.alpha.toString(), "extraKeys" to c.extraKeys.map { key(it) })

    fun devs(o: Any?): List<Deviation> = (o as List<Any?>).map { e ->
        val d = e as List<Any?>
        Deviation(I(d[0]), I(d[1]), if (d[2] == null) null else B(d[2]), if (d[3] == null) null else B(d[3]), if (d[4] == null) null else I(d[4]))
    }

    fun fault(o: Any?): Spdz.DealerFault? {
        if (o == null) return null
        val m = map(o)
        var p: List<BigInteger?>? = null
        if (m["partnerCDelta"] != null) p = (m["partnerCDelta"] as List<Any?>).map { if (it == null) null else B(it) }
        return Spdz.DealerFault(if (m["keepCDelta"] == null) null else B(m["keepCDelta"]), p)
    }
}
