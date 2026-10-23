package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for ActionSchema.kt (rule 14: the signed action schema shape, its signature, and the closed-world
 * conformance). The oracle is packages/pca/src/action-schema.ts (actionSchemaShapeError / verifyActionSchema /
 * paramValueViolation / conformAction / schemaVerb / accumulationParams / actionSchemaDigest) and intent-v2.ts
 * canonProjection, run on boundary inputs by tools/pca-audit/kotlin-mutate/killG-oracle-gen.mjs into
 * test-data/killG-schema.json. Every input is JSON text (so -0, 1.0, 1e400 and lone surrogates survive).
 */
class KillGTest {
    companion object {
        @Suppress("UNCHECKED_CAST")
        val data: Map<String, Any?> by lazy {
            Json.parseLenient(String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("test-data/killG-schema.json")), Charsets.UTF_8)) as Map<String, Any?>
        }

        @Suppress("UNCHECKED_CAST")
        fun cases(k: String): List<Map<String, Any?>> = data[k] as List<Map<String, Any?>>
        fun j(o: Any?): Any? = IntentJs.normalize(Json.parseLenient(o as String))
    }

    private fun check(section: String, body: (Map<String, Any?>) -> String?) {
        val bad = ArrayList<String>()
        for (c in cases(section)) body(c)?.let { bad.add("${c["name"]}: $it") }
        assertTrue("${bad.size} mismatches:\n" + bad.joinToString("\n"), bad.isEmpty())
    }

    @Test fun shape() = check("shape") { c ->
        val got = ActionSchema.shapeError(j(c["doc"]))
        if (got == c["want"] || sameCanonFamily(got, c["want"])) null else "got <$got> want <${c["want"]}>"
    }

    /** A strict-canonicalizer refusal: the canonicalizer's own message text is not ActionSchema's; the family must agree. */
    private fun sameCanonFamily(got: String?, want: Any?): Boolean {
        val p = "malformed schema: canonicalize: "
        return got != null && want is String && got.startsWith(p) && want.startsWith(p)
    }

    @Test fun verify() = check("verify") { c ->
        val got = ActionSchema.verify(j(c["doc"]), j(c["keys"]))
        if (got == c["want"]) null else "got <$got> want <${c["want"]}>"
    }

    @Test fun digest() = check("digest") { c ->
        val got = ActionSchema.digest(j(c["doc"]))
        if (got == c["want"]) null else "got <$got> want <${c["want"]}>"
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun value() = check("value") { c ->
        val got = ActionSchema.paramValueViolation(j(c["decl"]) as Map<String, Any?>, j(c["x"]))
        val w = c["want"] as Map<String, Any?>?
        val want = w?.let { it["code"] to it["reason"] }
        if (got == want) null else "got <$got> want <$want>"
    }

    @Test fun conform() = check("conform") { c ->
        val r = ActionSchema.conform(j(c["doc"]), c["verb"] as String, j(c["params"]))
        val w = IntentJs.obj(c["want"])
        val got = if (r.ok) listOf<Any?>(true, r.code, r.path, r.reason) else listOf(false, r.code, r.path, r.reason)
        val want = if (w["ok"] == true) listOf<Any?>(true, null, null, null) else listOf(false, w["code"], w["path"], w["reason"])
        if (got == want) null else "got <$got> want <$want>"
    }

    @Test fun verbOf() = check("verbOf") { c ->
        val r = ActionSchema.schemaVerb(j(c["doc"]), c["verb"] as String)
        val got = r?.let { Json.canonicalize(it) }
        val want = c["want"]?.let { Json.canonicalize(j(it)) }
        if (got == want) null else "got <$got> want <$want>"
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun canon() = check("canon") { c ->
        val got = ActionSchema.canonProjection(j(c["doc"]), c["verb"] as String, j(c["params"]) as Map<String, Any?>).entries.map { listOf(it.key, it.value) }
        val want = (c["want"] as List<Any?>).map { (it as List<Any?>).toList() }
        if (got == want) null else "got <$got> want <$want>"
    }

    @Suppress("UNCHECKED_CAST")
    @Test fun accum() = check("accum") { c ->
        val got = ActionSchema.accumulationParams(j(c["verb"]) as Map<String, Any?>, c["unit"] as String)
        val want = c["want"] as List<Any?>
        if (got == want) null else "got <$got> want <$want>"
    }

    @Test fun isStrAndConform() {
        assertTrue(ActionSchema.isStr("a", 1)); assertFalse(ActionSchema.isStr("ab", 1))
        assertTrue(ActionSchema.isStr("a".repeat(256))); assertFalse(ActionSchema.isStr("a".repeat(257)))
        assertFalse(ActionSchema.isStr("")); assertFalse(ActionSchema.isStr(null)); assertFalse(ActionSchema.isStr(5, 5))
        assertFalse(ActionSchema.isStr("a\ud800", 10)); assertTrue(ActionSchema.isStr("é", 2)); assertFalse(ActionSchema.isStr("é", 1))
        val ok = ActionSchema.Conform.OK
        assertTrue(ok.ok); assertNull(ok.code); assertNull(ok.path); assertNull(ok.reason)
        val bad = ActionSchema.conform(null, "x", null)
        assertFalse(bad.ok); assertEquals("params_not_object", bad.code)
    }
}
