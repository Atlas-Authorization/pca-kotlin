package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** How a verifier assembles the Policy VM input from a PCActn and its own context, and the decision on it, against the reference corpus (240 cases). */
@Suppress("UNCHECKED_CAST")
class DecideDeriveDiffTest {
    private val mod = "ref-decide-derive"

    private fun ctx(a: List<Any?>): Map<String, Any?>? = if (a.size > 1) a[1] as? Map<String, Any?> else null

    @Test fun everyCaseIsReplayed() {
        assertEquals(setOf("deriveDecideInput", "deriveThenDecide"), BaseOracle.fns("$mod.json.gz"))
        assertEquals(240, OracleCases.of(mod, "deriveDecideInput").size + OracleCases.of(mod, "deriveThenDecide").size)
    }

    @Test fun derive() = OracleCases.each(mod, "deriveDecideInput") { a -> Decide.deriveDecideInput(a[0], ctx(a)) }

    /** The inverse of the corpus's non-finite spelling for a result: a non-finite number becomes `{"$num": text}`. */
    private fun enc(v: Any?): Any? = when (v) {
        is Json.Num -> if (v.raw == "NaN" || v.raw == "Infinity" || v.raw == "-Infinity") linkedMapOf<String, Any?>("\$num" to v.raw) else v
        is List<*> -> v.map { enc(it) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = enc(x) }
        else -> v
    }

    @Test fun deriveThenDecide() = OracleCases.each(mod, "deriveThenDecide") { a ->
        val dec = OracleCases.decNum(a) as List<Any?>
        val input = Decide.deriveDecideInput(dec[0], ctx(dec))
        enc(linkedMapOf<String, Any?>("input" to input, "decision" to Decide.decide(input)))
    }
}
