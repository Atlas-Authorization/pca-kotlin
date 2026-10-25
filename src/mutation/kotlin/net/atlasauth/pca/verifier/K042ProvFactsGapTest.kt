package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Gap kills for ParamProvenance / OracleFacts: direct package-level helpers, read-purpose malformed shapes, and number-spelling normalization. */
@Suppress("UNCHECKED_CAST")
class K042ProvFactsGapTest {
    private fun map(vararg kv: Pair<String, Any?>) = linkedMapOf(*kv)
    private fun list(vararg xs: Any?) = ArrayList<Any?>(xs.toList())
    private fun n(s: String) = Json.Num(s)

    @Test fun verifyLabelsRefusesMalformedReceiptsBeforeAnythingElse() {
        val w = ParamProvenance.validateLabelsWire("x")
        assertEquals("label receipt must be an object", w)
        assertEquals(w, ParamProvenance.verifyLabels("x", emptyList<Any?>()))
        assertEquals("label receipt must be an object", ParamProvenance.verifyLabels(null, emptyList<Any?>()))
        assertEquals("label receipt must be an object", ParamProvenance.verifyLabels(emptyList<Any?>(), emptyList<Any?>()))
        val bad = map("v" to n("1"))
        val w2 = ParamProvenance.validateLabelsWire(bad)
        assertNotNull(w2)
        assertEquals(w2, ParamProvenance.verifyLabels(bad, emptyList<Any?>()))
    }

    @Test fun flowRulePrefersTheLongestPrefixInEitherOrder() {
        for (longFirst in listOf(true, false)) {
            val rules = LinkedHashMap<String, Any?>()
            if (longFirst) { rules["pii.identity.*"] = list("a"); rules["pii.*"] = list("b"); rules["*"] = list("c") }
            else { rules["*"] = list("c"); rules["pii.*"] = list("b"); rules["pii.identity.*"] = list("a") }
            assertEquals("longFirst $longFirst", "pii.identity.*", ParamProvenance.flowRuleFor(rules, "pii.identity.passport"))
            assertEquals("pii.*", ParamProvenance.flowRuleFor(rules, "pii.contact"))
            assertEquals("*", ParamProvenance.flowRuleFor(rules, "other"))
            assertEquals("pii.*", ParamProvenance.flowRuleFor(rules, "pii.x.y"))
        }
        val exact = LinkedHashMap<String, Any?>(); exact["pii.*"] = list("b"); exact["pii.identity"] = list("a")
        assertEquals("pii.identity", ParamProvenance.flowRuleFor(exact, "pii.identity"))
        assertEquals("pii.*", ParamProvenance.flowRuleFor(exact, "pii.identity.x"))
        assertNull(ParamProvenance.flowRuleFor(exact, "other"))
        assertNull(ParamProvenance.flowRuleFor(LinkedHashMap(), "pii"))
        assertNull(ParamProvenance.flowRuleFor(exact, "pii"))
        assertNull(ParamProvenance.flowRuleFor(exact, "piix.y"))
    }

    @Test fun labelRefsAreSplitAtTheFirstHash() {
        val d = "A".repeat(43)
        assertNull(ParamProvenance.parseLabelRef("x#y"))
        assertNull(ParamProvenance.parseLabelRef("$d#f"))
        assertNull(ParamProvenance.parseLabelRef("pca-labels:$d"))
        assertNull(ParamProvenance.parseLabelRef("pca-labels:$d#"))
        assertNull(ParamProvenance.parseLabelRef("pca-labels:short#f"))
        assertNull(ParamProvenance.parseLabelRef("pca-labels:#f"))
        assertEquals(d to "f", ParamProvenance.parseLabelRef("pca-labels:$d#f"))
        assertEquals(d to "a#b", ParamProvenance.parseLabelRef("pca-labels:$d#a#b"))
        assertEquals(d to "#", ParamProvenance.parseLabelRef("pca-labels:$d##"))
    }

    private fun read(fields: Any?, purpose: Any?, coverage: Any?, vararg onUncovered: Any?): ParamProvenance.ReadPurposeResult {
        val inp = map("fields" to fields, "purpose" to purpose, "coverage" to coverage)
        if (onUncovered.isNotEmpty()) inp["on_uncovered"] = onUncovered[0]
        return ParamProvenance.decideReadPurpose(inp)
    }
    private fun assertDeny(r: ParamProvenance.ReadPurposeResult?, why: String) {
        assertNotNull(why, r)
        assertEquals(why, "deny", r!!.outcome); assertEquals(why, emptyList<String>(), r.minimise); assertEquals(why, emptyList<String>(), r.uncovered)
    }

    @Test fun readPurposeIsTotalAndStrict() {
        for (bad in listOf(null, n("5"), "x", emptyList<Any?>(), true)) assertDeny(ParamProvenance.decideReadPurpose(bad), "input $bad")
        val cov = map("p" to list("pii.*"))
        val f = list(map("path" to "a", "class" to "pii.x"))
        assertEquals("allow", read(f, "p", cov).outcome)
        assertDeny(read(map(), "p", cov), "fields object"); assertDeny(read(null, "p", cov), "fields null")
        assertDeny(read(f, n("5"), cov), "purpose number"); assertDeny(read(f, null, cov), "purpose null")
        assertDeny(read(f, "p", list()), "coverage list"); assertDeny(read(f, "p", null), "coverage null")
        assertDeny(read(f, "p", cov, "allow"), "on_uncovered allow"); assertDeny(read(f, "p", cov, n("5")), "on_uncovered number"); assertDeny(read(f, "p", cov, null), "on_uncovered null")
        assertEquals("allow", read(f, "p", cov, "deny").outcome); assertEquals("allow", read(f, "p", cov, "question").outcome)
        assertDeny(read(f, "p", map("p" to "pii.*")), "coverage value not a list")
        assertDeny(read(f, "p", map("p" to list(n("5")))), "coverage pattern not a string")
        assertDeny(read(f, "p", map("q" to map())), "coverage value of another purpose is still checked")
        assertDeny(read(list(map("path" to n("5"), "class" to "public")), "p", cov), "path number, class covered")
        assertDeny(read(list(map("class" to "public")), "p", cov), "path missing, class covered")
        assertDeny(read(list(map("path" to "a", "class" to n("5"))), "p", cov), "class number")
        assertDeny(read(list(map("path" to "a")), "p", cov), "class missing")
        assertDeny(read(list("x"), "p", cov), "field not an object")
        assertDeny(read(list(map("path" to "a", "class" to "public", "optional" to "yes")), "p", cov), "optional string")
        assertDeny(read(list(map("path" to "a", "class" to "public", "optional" to n("1"))), "p", cov), "optional number")
        assertDeny(read(list(map("path" to "a", "class" to "public", "optional" to null)), "p", cov), "optional null")
        assertEquals("allow", read(list(map("path" to "a", "class" to "public", "optional" to true)), "p", cov).outcome)
        assertEquals("allow", read(list(map("path" to "a", "class" to "public", "optional" to false)), "p", cov).outcome)
        val r = read(list(map("path" to "z", "class" to "fin.x"), map("path" to "a", "class" to "fin.y", "optional" to true),
            map("path" to "b", "class" to "fin.y", "optional" to true), map("path" to "a", "class" to "fin.y", "optional" to true), map("path" to "c", "class" to "public")), "p", cov)
        assertEquals("question", r.outcome); assertEquals(listOf("a", "b"), r.minimise); assertEquals(listOf("z"), r.uncovered)
        assertEquals("deny", read(list(map("path" to "z", "class" to "fin.x")), "p", cov, "deny").outcome)
        val opt = read(list(map("path" to "a", "class" to "fin.y", "optional" to true)), "p", cov)
        assertEquals("allow", opt.outcome); assertEquals(listOf("a"), opt.minimise); assertEquals(emptyList<String>(), opt.uncovered)
        assertEquals("allow", read(list(), "p", cov).outcome)
        assertEquals("question", read(f, "unknown-purpose", cov).outcome)
        assertEquals("allow", read(list(map("path" to "a", "class" to "public")), "unknown-purpose", cov).outcome)
        assertEquals("allow", read(list(map("path" to "a", "class" to "anything")), "p", map("p" to list("*"))).outcome)
        assertEquals("allow", read(list(map("path" to "a", "class" to "pii")), "p", map("p" to list("pii"))).outcome)
        assertEquals("question", read(list(map("path" to "a", "class" to "piix")), "p", map("p" to list("pii"))).outcome)
        assertEquals("question", read(list(map("path" to "a", "class" to "pii")), "p", cov).outcome)
        assertEquals("allow", read(list(map("path" to "a", "class" to "pii.deep.er")), "p", cov).outcome)
    }

    // ---- number-spelling normalization: the same documents with every integer respelled "N.0" must decide identically ----
    private fun oracleCases(): List<Map<String, Any?>> = GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-oracleprov.json.gz"))).use {
        IntentJs.arr(IntentJs.get(IntentJs.normalize(Json.parseLenient(String(it.readAllBytes(), Charsets.UTF_8))), "cases")) as List<Map<String, Any?>>
    }
    private fun respell(v: Any?): Any? = when (v) {
        is Json.Num -> if (Regex("-?[0-9]+").matches(v.raw)) Json.Num(v.raw + ".0") else v
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { o -> for ((k, x) in v) o[k as String] = respell(x) }
        is List<*> -> ArrayList<Any?>(v.map { respell(it) })
        else -> v
    }
    private fun hasNumber(v: Any?): Boolean = when (v) { is Json.Num -> true; is Map<*, *> -> v.values.any { hasNumber(it) }; is List<*> -> v.any { hasNumber(it) }; else -> false }
    private fun render(r: OracleFacts.WorldResult) = if (r.ok) "ok ${K042OracleProvOracleTest.ser(r.world)}${K042OracleProvOracleTest.ser(r.singleSource)}" else "fail ${r.reason}"
    private fun render(r: ParamProvenance.ProvResult) = listOf(r.outcome, r.reason.toString(), r.friction.toString(), K042OracleProvOracleTest.ser(r.labels), K042OracleProvOracleTest.ser(r.classes), K042OracleProvOracleTest.ser(r.env)).joinToString("|")

    @Test fun worldAndProvenanceNormalizeNumberSpellings() {
        val bad = ArrayList<String>(); var cnt = 0
        for (c in oracleCases()) {
            val kind = c["kind"] as String; val name = c["name"] as String
            if (kind != "world" && kind != "prov") continue
            if (name.contains("k042-input-")) continue
            val plain = c["input"]; val spelled = respell(plain)
            if (!hasNumber(plain)) continue
            cnt++
            val a: String; val b: String
            if (kind == "world") { a = render(OracleFacts.decideIntentWorld(plain)); b = render(OracleFacts.decideIntentWorld(spelled)) }
            else { a = render(ParamProvenance.decide(plain)); b = render(ParamProvenance.decide(spelled)) }
            if (a != b) bad.add("$name\n  plain   $a\n  spelled $b")
        }
        assertTrue("cases with numbers: $cnt", cnt > 300)
        assertTrue("${bad.size} differ:\n" + bad.take(10).joinToString("\n"), bad.isEmpty())
    }
}
