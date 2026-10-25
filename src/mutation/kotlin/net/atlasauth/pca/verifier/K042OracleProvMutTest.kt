package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation-style differential (tools/pca-audit/java-mutate/k042-oracleprov-mut-oracle.mjs -> test-data/k042-oracleprov-mut.json.gz):
 * every structural path of the rule 16/17 corpus and of the predicate corpus is replaced / deleted / extended and the TS reference
 * result recomputed. Compared exactly, except an internal-error reason ("... evaluation error (fail closed): X") is compared up to
 * the colon (the exception name is language-specific).
 */
@Suppress("UNCHECKED_CAST")
class K042OracleProvMutTest {
    companion object {
        val doc: Map<String, Any?> by lazy {
            GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-oracleprov-mut.json.gz"))).use {
                IntentJs.normalize(Json.parseLenient(String(it.readAllBytes(), Charsets.UTF_8))) as Map<String, Any?>
            }
        }
        private val EE = Regex("evaluation error \\(fail closed\\): [A-Za-z]+")
        fun cutAll(s: String) = EE.replace(s, "evaluation error (fail closed): ")
        fun ser(v: Any?) = K042OracleProvOracleTest.ser(v)
        fun dump(bad: List<String>, f: String) { if (Files.isDirectory(Path.of("target"))) Files.writeString(Path.of("target/$f"), bad.joinToString("\n")) }
        fun tri(s: String) = when (s) { "true" -> Predicates.Tri.TRUE; "false" -> Predicates.Tri.FALSE; else -> Predicates.Tri.UNKNOWN }
    }

    @Test fun oracleprov() {
        val cs = doc["oracleprov"] as List<Any?>
        assertTrue("cases ${cs.size}", cs.size > 20000)
        val bad = ArrayList<String>()
        for (co in cs) {
            val c = IntentJs.obj(co)
            val name = c["name"] as String
            var got: String; var want: String
            try {
                when (val kind = c["kind"] as String) {
                    "fn" -> { got = ser(K042OracleProvOracleTest.VALIDATORS[c["fn"] as String]!!(c["arg"])); want = ser(c["want"]) }
                    "active" -> { got = ser(OracleFacts.intentWorldActive(c["committed"], c["policy"])); want = ser(c["expect"]) }
                    "read" -> {
                        val r = ParamProvenance.decideReadPurpose(c["input"]); val e = IntentJs.obj(c["expect"])
                        got = ser(linkedMapOf("outcome" to r.outcome, "minimise" to r.minimise, "uncovered" to r.uncovered))
                        want = ser(linkedMapOf("outcome" to e["outcome"], "minimise" to e["minimise"], "uncovered" to e["uncovered"]))
                    }
                    "world" -> {
                        val r = OracleFacts.decideIntentWorld(c["input"]); val e = IntentJs.obj(c["expect"])
                        got = cutAll(if (r.ok) "ok ${ser(r.world)} ${ser(r.singleSource)}" else "fail ${ser(r.reason)}")
                        want = cutAll(if (e["ok"] == true) "ok ${ser(e["world"])} ${ser(e["single_source"])}" else "fail ${ser(e["reason"])}")
                    }
                    "prov" -> {
                        val r = ParamProvenance.decide(c["input"]); val e = IntentJs.obj(c["expect"])
                        got = cutAll(listOf(r.outcome, ser(r.reason), ser(r.friction), ser(r.labels), ser(r.classes), ser(r.env)).joinToString(" | "))
                        want = cutAll(listOf(e["outcome"] as String, ser(e["reason"]), ser(e["friction"]), ser(e["labels"]), ser(e["classes"]), ser(e["env"])).joinToString(" | "))
                    }
                    else -> throw AssertionError(kind)
                }
            } catch (ex: RuntimeException) { bad.add("$name threw $ex"); continue }
            if (got != want) bad.add("$name\n    got  $got\n    want $want")
        }
        dump(bad, "k042-oracleprov-mut-bad.txt")
        assertTrue("${bad.size} mismatches:\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    @Test fun predicates() {
        val pj = IntentJs.obj(doc["predjs"])
        val ctxs = pj["ctx"] as Map<String, String>
        fun ctx(n: Any?) = Json.parseLenient(ctxs[n as String]) as Map<String, Any?>?
        val bad = ArrayList<String>()
        for (o in pj["tri"] as List<Any?>) {
            val c = IntentJs.obj(o)
            val want = tri(c["tri"] as String)
            val got = Predicates.evaluateConditionTri(Json.parseLenient(c["cond"] as String), ctx(c["ctx"]))
            if (got != want) bad.add("${c["name"]}: want $want got $got")
        }
        for (o in pj["preds"] as List<Any?>) {
            val c = IntentJs.obj(o)
            val preds = Json.parseLenient(c["preds"] as String) as List<Any?>
            val got = Predicates.evaluatePredicates(preds, ctx(c["ctx"]))
            if (got != c["allowed"]) bad.add("${c["name"]}: allowed want ${c["allowed"]} got $got")
            val each = c["each"] as List<Any?>
            for (i in preds.indices) {
                val m = Predicates.predicateMatches(preds[i], ctx(c["ctx"]))
                if (m != each[i]) bad.add("${c["name"]}[$i]: want ${each[i]} got $m")
            }
        }
        dump(bad, "k042-predmut-bad.txt")
        assertTrue("${bad.size} mismatches:\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }
}
