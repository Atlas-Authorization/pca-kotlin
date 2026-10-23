package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Rule 14 differential against the TS reference (test-data/k042-actionschema.json, written by
 * tools/pca-audit/java-mutate/k042-actionschema-oracle.mts): shape / verify / paramValueViolation / conform /
 * accumulationParams / canonProjection on targeted inputs at the boundary of every rule. Inputs are raw JSON text.
 * Exact reasons are compared except the four value-domain reasons that omit the bound (see [kotlinReason]).
 */
class K042ActionSchemaTest {
    companion object {
        const val MALFORMED = "malformed schema: canonicalize: "
        @Suppress("UNCHECKED_CAST")
        val data: Map<String, Any?> by lazy { Json.parseLenient(Files.readString(Path.of("test-data/k042-actionschema.json"))) as Map<String, Any?> }
        @Suppress("UNCHECKED_CAST")
        fun cases(kind: String) = data[kind] as List<Map<String, Any?>>
        fun j(raw: Any?): Any? = IntentJs.normalize(Json.parseLenient(raw as String))
        fun kotlinReason(ts: String?): String? = ts?.replace(Regex("longer than \\d+ UTF-8 bytes$"), "longer than the declared max_len")
            ?.replace(Regex("below min -?\\d+$"), "below min")
            ?.replace(Regex("above max -?\\d+$"), "above max")
            ?.replace(Regex("array items must be strings of at most \\d+ UTF-8 bytes$"), "array items must be strings within max_len UTF-8 bytes")
    }

    private fun report(bad: List<String>, n: Int) = assertEquals("${bad.size}/$n mismatches:\n" + bad.take(60).joinToString("\n"), 0, bad.size)

    @Test fun shape() {
        val bad = ArrayList<String>(); val cs = cases("shape")
        for (c in cs) {
            val want = c["expect"] as String?
            val got = ActionSchema.shapeError(j(c["doc"]))
            if (want != null && want.startsWith(MALFORMED) && got != null && got.startsWith(MALFORMED) && !got.endsWith("null")) continue
            if (want != got) bad.add("${c["name"]}: want <$want> got <$got>")
        }
        report(bad, cs.size)
    }

    @Test fun malformedMessages() {
        val base = cases("shape").first { it["name"] == "shape/base" }["doc"]
        val d = LinkedHashMap(IntentJs.obj(j(base)))
        d["state"] = j("[-0]")
        assertEquals("malformed schema: canonicalize: negative zero is not allowed", ActionSchema.shapeError(d))
        d["state"] = j("[1e21]")
        assertEquals("malformed schema: canonicalize: integer outside the safe range", ActionSchema.shapeError(d))
    }

    @Test fun paramValueViolation() {
        val bad = ArrayList<String>(); val cs = cases("pvv")
        for (c in cs) {
            val e = c["expect"]
            val want = if (e == null) null else "${IntentJs.get(e, "code")}|${kotlinReason(IntentJs.get(e, "reason") as String?)}"
            val r = ActionSchema.paramValueViolation(IntentJs.obj(j(c["d"])), j(c["x"]))
            val got = r?.let { "${it.first}|${it.second}" }
            if (want != got) bad.add("${c["name"]}: want <$want> got <$got>")
        }
        report(bad, cs.size)
    }

    @Test fun conform() {
        val bad = ArrayList<String>(); val cs = cases("conform")
        for (c in cs) {
            val e = IntentJs.obj(c["expect"])
            val want = if (e["ok"] == true) "ok|null|null|null" else "false|${e["code"]}|${e["path"]}|${kotlinReason(e["reason"] as String?)}"
            val got = try {
                val r = ActionSchema.conform(j(c["doc"]), c["verb"] as String, j(c["params"]))
                "${if (r.ok) "ok" else "false"}|${r.code}|${r.path}|${r.reason}"
            } catch (x: RuntimeException) { "threw $x" }
            if (want != got) bad.add("${c["name"]}: want <$want> got <$got>")
        }
        report(bad, cs.size)
    }

    @Test fun verify() {
        val bad = ArrayList<String>(); val cs = cases("verify")
        for (c in cs) {
            val want = c["expect"] as String?
            val got = ActionSchema.verify(j(c["doc"]), j(c["keys"]))
            if (want != got) bad.add("${c["name"]}: want <$want> got <$got>")
        }
        report(bad, cs.size)
    }

    @Test fun accumulationParams() {
        val bad = ArrayList<String>(); val cs = cases("acc")
        for (c in cs) {
            val want = c["expect"]
            val got: Any? = try { ActionSchema.accumulationParams(IntentJs.obj(j(c["v"])), c["unit"] as String) } catch (x: RuntimeException) { "threw $x" }
            if (want != got) bad.add("${c["name"]}: want <$want> got <$got>")
        }
        report(bad, cs.size)
    }

    @Test fun canonProjection() {
        val bad = ArrayList<String>(); val cs = cases("canon")
        for (c in cs) {
            val e = IntentJs.obj(c["expect"])
            val want = if (e["ok"] == true) e["out"] else "threw"
            val got: Any? = try { ActionSchema.canonProjection(j(c["doc"]), c["verb"] as String, IntentJs.obj(j(c["params"]))) } catch (x: RuntimeException) { "threw" }
            if (want != got) bad.add("${c["name"]}: want <$want> got <$got>")
        }
        report(bad, cs.size)
    }

    @Test fun conformRecord() {
        val ok = ActionSchema.Conform(true, "c", "p", "r")
        assertTrue(ok.ok); assertEquals("c", ok.code); assertEquals("p", ok.path); assertEquals("r", ok.reason)
        assertTrue(ActionSchema.Conform.OK.ok); assertNull(ActionSchema.Conform.OK.code)
    }

    @Test fun canonProjectionUnknownVerbIsAFreshMap() {
        val doc = IntentJs.obj(j("{\"verbs\":[{\"verb\":\"v\",\"kind\":\"read\",\"params\":{}}]}"))
        for (verb in listOf("v", "nope")) {
            val out = ActionSchema.canonProjection(doc, verb, LinkedHashMap()) as MutableMap<String, Any?>
            assertTrue(out.isEmpty()); out["x"] = "y"; assertEquals("y", out["x"])
        }
    }
}
