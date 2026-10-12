package net.atlasauth.pca.verifier

import java.lang.reflect.InvocationTargetException
import java.math.BigInteger

/** Test helpers: reflection access to the verifier's private seams (same module, JVM). */
object KUtil {
    fun n(s: String) = Json.Num(s)
    fun m(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> { val r = LinkedHashMap<String, Any?>(); for ((k, v) in kv) r[k] = v; return r }
    fun l(vararg v: Any?): ArrayList<Any?> = ArrayList(v.toList())

    @Suppress("UNCHECKED_CAST") fun mm(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>
    @Suppress("UNCHECKED_CAST") fun ll(o: Any?): MutableList<Any?> = o as MutableList<Any?>

    fun <T> priv(target: Any, name: String, vararg args: Any?): T {
        val cands = target.javaClass.declaredMethods.filter { it.name == name && it.parameterCount == args.size }
        require(cands.isNotEmpty()) { "no method $name/${args.size}" }
        val method = cands.first().also { it.isAccessible = true }
        try {
            @Suppress("UNCHECKED_CAST") return method.invoke(target, *args) as T
        } catch (e: InvocationTargetException) { throw e.targetException }
    }

    fun le(v: BigInteger): ByteArray {
        val b = ByteArray(32)
        val be = v.toByteArray()
        for (i in be.indices) if (i < 32) b[i] = be[be.size - 1 - i]
        return b
    }
    fun rev(a: ByteArray): ByteArray = a.reversedArray()
    val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    val L: BigInteger = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))
    const val NOW = 1800000000000L
    const val AUD = "rs-conformance"
    val B32 = "qK9bTlJxvo3zLOQ4msAVS7_odp-g75Kfsu_Z7L47sqQ"
    val B64 = "A".repeat(86)

    fun vec(name: String): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        for (x in SnapshotTest.core["vectors"] as List<Any?>) if ((x as Map<String, Any?>)["name"] == name) return x
        throw IllegalStateException(name)
    }
    fun valid(): MutableMap<String, Any?> = mm(Json.parse(vec("valid-raw-json-format-insensitive")["pcactn_json"] as String))
    fun validGrant(): Map<String, Any?> = mm(vec("valid-raw-json-format-insensitive")["grant"])
    fun twoHop(): List<Any?> = ll(mm(vec("delegated-2-hop-chain")["pcactn"])["cap_chain"])
    fun deep(chain: List<Any?>): MutableList<Any?> { val r = ArrayList<Any?>(); for (o in chain) r.add(LinkedHashMap(mm(o))); return r }
    fun hopWith(c: Int): Map<String, Any?> { val cv = ArrayList<Any?>(); repeat(c) { cv.add(m("type" to "t")) }; return m("caveats" to cv) }
    val Of = Pca.Audience.Of(AUD)
}
