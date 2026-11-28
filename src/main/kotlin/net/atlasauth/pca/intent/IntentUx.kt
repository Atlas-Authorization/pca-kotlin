package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Catalog
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * Question cards (a deterministic, structured form of a cell question: the sentence, one fact line per dimension, the verb's
 * reversibility, the three answers and the typed "partly" slots) and the parser that turns card input into the learner's answer.
 * Cards and inputs are JSON trees.
 */
object IntentUx {
    private val FIELD_RE = Regex("action\\.params\\.[a-z_][a-z0-9_]*|action\\.resource")

    private fun n(d: Double): String = AttestUtil.jsNumString(d)

    private fun fact(d: Dim, i: Int): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["path"] = d.path
        m["label"] = IntentRender.labelOf(d.path)
        if (d is NumDim) {
            val c = IntentOmega.numCells(d)[i]
            m["text"] = if (c.lo == c.hi) "exactly " + n(c.lo) else "any value from " + n(c.lo) + " to " + n(c.hi) + " (for example " + n(IntentOmega.numRep(d, i)) + ")"
        } else {
            val v = (d as CatDim).values[i]
            m["text"] = if (v.kind == "exact") "\"" + v.value + "\"" else if (v.kind == "prefix") "anything under \"" + v.value + "\" not named elsewhere" else "any value not named anywhere in the grant or your request"
        }
        return m
    }

    @JvmOverloads
    fun questionCard(omega: Omega, verb: String, cell: IntArray, catalog: Catalog = Catalog.DEFAULT): MutableMap<String, Any?> {
        val vs = IntentOmega.verbSpace(omega, verb) ?: throw IllegalArgumentException("questionCard: no verb $verb")
        val facts = ArrayList<Any?>()
        val partial = ArrayList<Any?>()
        for (k in vs.dims.indices) {
            val d = vs.dims[k]
            facts.add(fact(d, cell[k]))
            val slot = LinkedHashMap<String, Any?>()
            slot["path"] = d.path
            if (d is NumDim) {
                val c = IntentOmega.numCells(d)[cell[k]]
                slot["kind"] = "num"
                slot["lo"] = c.lo
                slot["hi"] = c.hi
            } else {
                slot["kind"] = "cat"
                slot["options"] = (d as CatDim).values.filter { it.kind == "exact" }.mapTo(ArrayList<Any?>()) { it.value }
            }
            partial.add(slot)
        }
        val body = LinkedHashMap<String, Any?>()
        body["v"] = Json.Num("1")
        body["verb"] = verb
        body["cell"] = cell.mapTo(ArrayList<Any?>()) { Json.Num(it.toString()) }
        body["sentence"] = IntentRender.renderQuestion(vs, cell, catalog)
        body["facts"] = facts
        body["reversibility"] = vs.reversibility
        body["answers"] = arrayListOf<Any?>("yes", "no", "partly")
        body["partial"] = partial
        val card = LinkedHashMap<String, Any?>(body)
        card["digest"] = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to "atlas-pca/intent-card/v1", "c" to IntentRuntime.jsonNums(body)))
        return card
    }

    private fun res(answer: Any?): MutableMap<String, Any?> = linkedMapOf("ok" to true, "answer" to answer)

    private fun err(e: String): MutableMap<String, Any?> = linkedMapOf("ok" to false, "error" to e)

    private fun part(vararg kv: Any?): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i + 1 < kv.size) {
            m[kv[i] as String] = kv[i + 1]
            i += 2
        }
        return m
    }

    /** The distinct non-empty strings of [list] in first-seen order; throws when it is not an array (the reference calls .filter). */
    private fun namedValues(list: Any?): List<Any?> {
        if (list !is List<*>) throw IllegalArgumentException("filter is not a function")
        val out = LinkedHashSet<Any?>()
        for (x in list) if (x is String && x.isNotEmpty()) out.add(x)
        return ArrayList(out)
    }

    private fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)
    private fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    /** Turn the UI input into the learner's answer: {ok: true, answer} or {ok: false, error}. */
    fun parseCardAnswer(card: Any?, input: Any?): MutableMap<String, Any?> {
        if ("partly" != get(input, "answer")) return res(if ("yes" == get(input, "answer")) 1.0 else 0.0)
        val slots = IntentOmega.arr(get(card, "partial"))
        if (has(input, "newField")) {
            val nf = IntentRender.str(get(input, "newField"))
            if (!FIELD_RE.matches(nf)) return err("unknown field $nf")
            for (s in slots) if (nf == get(s, "path")) return err("$nf is already on the card; answer partly for it directly")
            val vals = namedValues(get(input, "notFor"))
            if (vals.isEmpty()) return err("name at least one value")
            val dvals = ArrayList<Any?>()
            for (v in vals) dvals.add(part("kind", "exact", "value", v))
            dvals.add(part("kind", "other", "value", IntentOmega.OTHER))
            return res(part("kind", "partial", "path", nf, "newDim", part("kind", "cat", "path", nf, "values", dvals),
                "parts", arrayListOf<Any?>(part("values", vals, "y", 0.0), part("other", true, "y", 1.0))))
        }
        val path = get(input, "path")
        val slot = if (path is String) slots.firstOrNull { path == get(it, "path") } else null
        if (slot == null) return err("the card has no field " + IntentRender.str(if (has(input, "path")) path else IntentRender.UNDEF))
        val sp = get(slot, "path") as String
        if ("num" == get(slot, "kind")) {
            val lo = IntentOmega.dbl(get(slot, "lo"))
            val hi = IntentOmega.dbl(get(slot, "hi"))
            if (has(input, "upTo")) {
                val x = get(input, "upTo")
                if (!inRange(x, lo, hi) || IntentOmega.dbl(x) == hi) return err("upTo must be an integer in [" + n(lo) + ", " + n(hi - 1) + "]")
                val u = IntentOmega.dbl(x)
                return res(part("kind", "partial", "path", sp, "cuts", arrayListOf<Any?>(u),
                    "parts", arrayListOf<Any?>(part("lo", lo, "hi", u, "y", 1.0), part("lo", u + 1, "hi", hi, "y", 0.0))))
            }
            if (has(input, "from")) {
                val x = get(input, "from")
                if (!inRange(x, lo, hi) || IntentOmega.dbl(x) == lo) return err("from must be an integer in [" + n(lo + 1) + ", " + n(hi) + "]")
                val f = IntentOmega.dbl(x)
                return res(part("kind", "partial", "path", sp, "cuts", arrayListOf<Any?>(f),
                    "parts", arrayListOf<Any?>(part("lo", lo, "hi", f - 1, "y", 0.0), part("lo", f, "hi", hi, "y", 1.0))))
            }
            if (has(input, "except")) {
                val ex0 = get(input, "except")
                if (ex0 != null && ex0 !is List<*> && ex0 !is String) throw IllegalArgumentException("not iterable")
                val ex = ArrayList<Double>()
                var allIn = true
                if (ex0 is List<*>) {
                    val seen = LinkedHashSet<Double>()
                    for (x in ex0) {
                        if (!inRange(x, lo, hi)) allIn = false else seen.add(IntentOmega.dbl(x) + 0.0)
                    }
                    ex.addAll(seen)
                    ex.sortWith { a, b -> java.lang.Double.compare(a, b) }
                } else allIn = false
                if ((ex0 is List<*> && ex0.isEmpty()) || ex0 == null || !allIn) return err("except values must be integers in [" + n(lo) + ", " + n(hi) + "]")
                val parts = ArrayList<Any?>()
                for (x in ex) parts.add(part("lo", x, "hi", x, "y", 0.0))
                parts.add(part("lo", lo, "hi", hi, "y", 1.0))
                return res(part("kind", "partial", "path", sp, "cuts", ArrayList<Any?>(ex), "parts", parts))
            }
            return err("a numeric partly answer needs upTo, from or except")
        }
        if (!has(input, "notFor")) return err("a categorical partly answer needs notFor")
        val vals = namedValues(get(input, "notFor"))
        if (vals.isEmpty()) return err("name at least one value")
        return res(part("kind", "partial", "path", sp, "values", vals, "parts", arrayListOf<Any?>(part("values", vals, "y", 0.0), part("other", true, "y", 1.0))))
    }

    private fun inRange(x: Any?, lo: Double, hi: Double): Boolean {
        if (!IntentOmega.isNumber(x)) return false
        val v = IntentOmega.dbl(x)
        return !v.isNaN() && !v.isInfinite() && v == Math.rint(v) && java.lang.Double.doubleToRawLongBits(v) != java.lang.Double.doubleToRawLongBits(-0.0) && v >= lo && v <= hi
    }
}
