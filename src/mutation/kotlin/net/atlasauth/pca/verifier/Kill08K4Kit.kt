package net.atlasauth.pca.verifier

import org.junit.Assert.assertTrue

/** Shared helpers of the k4 kill tests (Contracts, ContractEnforcer, ForbidWins); the oracle is packages/pca/src (contracts, forbid-certificate tests). */
@Suppress("UNCHECKED_CAST")
internal object K08K4 {
    val key: Keys.EdKey = Keys.edGenerate()
    val key2: Keys.EdKey = Keys.edGenerate()
    val PRIN: String = key.id()
    const val NOW = 1700000000000.0

    fun q(s: String): Any? = Json.parseLenient(s.replace('\'', '"'))
    fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    fun l(o: Any?): List<Any?> = o as List<Any?>
    fun num(d: Double): Json.Num = Prohibitions.jn(d)
    fun state0(): Map<String, Any?> = Prohibitions.emptyState(num(NOW))
    fun canon(o: Any?): String = Json.canonicalize(o)

    fun act(verb: String, res: String = "/r", params: String? = null): Map<String, Any?> =
        m(q("{'action':{'verb':'$verb','resource':'$res'" + (if (params == null) "" else ",'params':$params") + "}}"))

    fun w(verb: String, extra: String = ""): String = "{'verb':'$verb'$extra}"
    fun amb(verb: String): String = w(verb, ",'where':[{'field':'action.params.x','op':'eq','value':1}]")
    fun always(id: String, verb: String, extra: String = ""): String = "{'id':'$id','kind':'always','p':${w(verb)}$extra}"
    fun never(id: String, verb: String, extra: String = ""): String = "{'id':'$id','kind':'never','p':${w(verb)}$extra}"
    fun arr(vararg c: String): String = c.joinToString(",", "[", "]")
    fun inv(id: String, verb: String = "zzz"): String = "{'id':'$id','kind':'never','when':${w(verb)}}"

    fun contract(clauses: String = "[]", invariants: String = "[]"): Map<String, Any?> =
        m(q("{'version':1,'principal':'$PRIN','invariants':$invariants,'clauses':$clauses}"))

    fun rows(r: Map<String, Any?>): List<String> = l(r["evaluated"]).map { m(it)["id"].toString() + ":" + m(it)["result"] }

    fun withKey(src: Map<String, Any?>, k: String, v: Any?): LinkedHashMap<String, Any?> {
        val out = LinkedHashMap(src)
        out[k] = v
        return out
    }

    fun step(c: Map<String, Any?>, s: Map<String, Any?>, a: Map<String, Any?>, now: Any? = null): Map<String, Any?> {
        val r = Contracts.advanceContract(s, a, c, now)
        assertTrue("step refused: $r", r["ok"] == true)
        return m(r["next"])
    }

    /** A map that serves `after()` for [key] once [okReads] reads have been served (reads counted in [reads]). */
    class Probe(private val base: Map<String, Any?>, private val key: String, private val okReads: Int, private val after: () -> Any?) : Map<String, Any?> by base {
        var reads = 0
        override fun get(key: String): Any? = if (key == this.key && reads++ >= okReads) after() else base[key]
    }

    fun boom(): Any? = throw RuntimeException("boom")
    fun fatal(): Any? = throw InternalError("fatal")
}
