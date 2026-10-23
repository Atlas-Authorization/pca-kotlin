package net.atlasauth.pca.verifier

import java.math.BigDecimal
import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential tests of Predicates / IntentJs against the TS reference (predicates.ts + hash.ts + JavaScript number semantics):
 * test-data/k042-predjs.json from tools/pca-audit/java-mutate/k042-predjs-oracle.mjs; every input is JSON text so both sides
 * parse identical lexemes (1e400, -0, lone surrogates).
 */
@Suppress("UNCHECKED_CAST")
class K042PredJsOracleTest {
    companion object {
        val G: Map<String, Any?> by lazy { Json.parseLenient(Files.readString(Path.of("test-data/k042-predjs.json"))) as Map<String, Any?> }
        fun cases(k: String) = G[k] as List<Map<String, Any?>>
        fun tri(s: String) = when (s) { "true" -> Predicates.Tri.TRUE; "false" -> Predicates.Tri.FALSE; else -> Predicates.Tri.UNKNOWN }
        fun ctx(name: Any?) = Json.parseLenient((G["ctx"] as Map<String, String>)[name as String]) as Map<String, Any?>?
        fun escape(s: String) = s.map { if (it.code < 0x80) it.toString() else String.format("\\u%04x", it.code) }.joinToString("")
    }

    @Test fun conditionsMatchTheReference() {
        val bad = ArrayList<String>(); var n = 0
        for (c in cases("tri")) {
            val cond = Json.parseLenient(c["cond"] as String)
            val want = tri(c["tri"] as String)
            val got = Predicates.evaluateConditionTri(cond, ctx(c["ctx"]))
            val gotB = Predicates.evaluateCondition(cond, ctx(c["ctx"]))
            if (got != want || gotB != (want == Predicates.Tri.TRUE)) bad.add("${c["name"]}: want $want got $got/$gotB")
            n++
        }
        assertTrue("golden too small: $n", n > 400)
        assertEquals(emptyList<String>(), bad)
    }

    @Test fun predicatesMatchTheReference() {
        val bad = ArrayList<String>()
        for (c in cases("preds")) {
            val preds = Json.parseLenient(c["preds"] as String)
            val want = c["allowed"] as Boolean
            val got = Predicates.evaluatePredicates(preds, ctx(c["ctx"]))
            if (got != want) bad.add("${c["name"]}: allowed want $want got $got")
            val each = c["each"] as List<Any?>
            if (preds is List<*>) {
                assertEquals(c["name"] as String, each.size, preds.size)
                for (i in preds.indices) {
                    val m = Predicates.predicateMatches(preds[i], ctx(c["ctx"]))
                    if (m != each[i]) bad.add("${c["name"]}[$i]: want ${each[i]} got $m")
                }
            }
        }
        assertEquals(emptyList<String>(), bad)
    }

    @Test fun jsonEqualsIsTheLenientCanonicalTextEquality() {
        val bad = ArrayList<String>()
        for (c in cases("eq")) {
            val a = Json.parseLenient(c["a"] as String); val b = Json.parseLenient(c["b"] as String)
            if (IntentJs.jsonEquals(a, b) != c["eq"]) bad.add("${c["a"]} == ${c["b"]}: want ${c["eq"]}")
        }
        assertEquals(emptyList<String>(), bad)
    }

    @Test fun numbersMatchJavaScript() {
        val bad = ArrayList<String>()
        for (c in cases("nums")) {
            val raw = c["raw"] as String; val js = c["js"] as String
            val n = Json.Num(raw); val d = raw.toDouble()
            val finite = c["finite"] as Boolean; val safe = c["safe"] as Boolean; val plain = c["plain"] as Boolean
            if (IntentJs.isSafeInteger(n) != safe) bad.add("$raw: isSafeInteger")
            if (IntentJs.isFinite(n) != finite) bad.add("$raw: isFinite")
            if (IntentJs.num(n) != d) bad.add("$raw: num")
            val want = when {
                !finite -> raw
                js == "-0" -> "-0"
                // Kotlin prints JavaScript's own digits for every finite value (above 2^53 the shortest round-trip digits, zero-padded)
                else -> BigDecimal(js).toPlainString()
            }
            if (plain && finite && safe && want != js) bad.add("$raw: safe spelling differs from JS")
            if (plain && finite && d != Math.rint(d) && want != js) bad.add("$raw: decimal spelling differs from JS")
            val got = IntentJs.normNum(raw).raw
            if (got != want) bad.add("$raw: normNum $got want $want")
            val norm = IntentJs.normalize(n)
            if (norm !is Json.Num || norm.raw != want) bad.add("$raw: normalize")
            if (finite) {
                val nd = IntentJs.normalize(d)
                if (nd !is Json.Num || nd.raw != want) bad.add("$raw: normalize(Double) $nd")
            }
        }
        assertEquals(emptyList<String>(), bad)
    }

    @Test fun utf8LengthsAndSurrogates() {
        for (c in cases("u8")) {
            val s = c["s"] as String
            assertEquals("u8len " + escape(s), (c["n"] as Json.Num).raw, IntentJs.u8len(s).toString())
            assertEquals("lone " + escape(s), c["lone"], IntentJs.hasLoneSurrogate(s))
        }
        for (c in cases("cmp")) {
            val a = c["a"] as String; val b = c["b"] as String
            assertEquals(escape(a) + " vs " + escape(b), (c["sign"] as Json.Num).raw.toInt(), Integer.signum(IntentJs.compareUtf8(a, b)))
        }
    }

    private fun chainCtx(n: Int): Map<String, Any?> {
        val g = LinkedHashMap<String, Any?>()
        for (i in 0 until n) g["n$i"] = "n${i + 1}"
        return KUtil.m("action" to KUtil.m("verb" to "v", "resource" to "r"), "subject" to KUtil.m("id" to "n0", "g" to g))
    }
    private fun fanCtx(): Map<String, Any?> {
        val g = LinkedHashMap<String, Any?>(); val s = ArrayList<Any?>(); val cs = ArrayList<Any?>()
        for (j in 0 until 100) cs.add("c$j")
        g["s"] = s
        for (i in 0 until 100) { s.add("a$i"); g["a$i"] = cs }
        g["c0"] = "e"; g["e"] = "t"
        return KUtil.m("action" to KUtil.m("verb" to "v", "resource" to "r"), "subject" to KUtil.m("id" to "s", "g" to g))
    }
    private fun mo(v: String) = KUtil.m("field" to "subject.id", "op" to "member_of", "collection" to "subject.g", "value" to v)

    @Test fun memberClosureIsCappedLikeTheReference() {
        val chain = G["chain"] as Map<String, Any?>; val fan = G["fan"] as Map<String, Any?>
        val cc = chainCtx(10005)
        for ((k, v) in chain) assertEquals(k, tri(v as String), Predicates.evaluateConditionTri(mo(k), cc))
        val fc = fanCtx()
        for ((k, v) in fan) assertEquals(k, tri(v as String), Predicates.evaluateConditionTri(mo(k), fc))
        assertEquals(Predicates.Tri.TRUE, tri(chain["n10000"] as String))
        assertEquals(Predicates.Tri.FALSE, tri(chain["n10001"] as String))
    }
}
