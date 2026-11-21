package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for the action kit (packages/pca-actions validate, idpattern, traits, normalize,
 * digest, effective, confirmation, rule22, pack): test-data/k05-actions.json.gz from tools/pca-audit/k05-oracles/actions-oracle.mts.
 * Values compare as canonical JSON; a reference throw requires a native throw (an ActionKitError with the same code when the
 * case carries one); cmp = "code" compares only the `<code>:` prefix (the reference's own exception text follows it).
 * Skipped: reviewMessage (no standalone native entry: the review body is built inside the attestation check, covered by
 * isConfirmed); and cases the typed native API cannot express (a non-object verb / document). A -0 is compared like any other
 * case: the reference refuses it per the strict JSON profile, as the native does.
 */
@Suppress("UNCHECKED_CAST")
class K05ActionsDiffTest {
    private class Threw(val t: Throwable)
    private object Typed

    companion object {
        const val FILE = "k05-actions.json.gz"
        val SKIPPED = setOf("reviewMessage")
    }

    private fun of(fn: String) = K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
    private fun isThrow(o: Any?) = o is Map<*, *> && o.containsKey("\$throws")
    private fun show(v: Any?): String = (if (v is Threw) "THROWS ${v.t}" else try { Json.canonicalize(v) } catch (e: Exception) { v.toString() }).let { if (it.length > 300) it.take(300) + "..." else it }
    private fun reg(custom: Any?) = if (custom == null) Actions.CORE_REGISTRY else Actions.extendRegistry(Actions.CORE_REGISTRY, custom)
    private fun obj(o: Any?) = o as Map<String, Any?>
    private fun <T> priv(name: String, vararg a: Any?): T = KUtil.priv(Actions, name, *a)

    private fun check(fn: String, call: (List<Any?>) -> Any?) {
        val bad = ArrayList<String>()
        for (c in of(fn)) {
            val args = c["args"] as List<Any?>
            val want = c["out"]
            val got: Any? = try { call(args) } catch (t: Throwable) { Threw(t) }
            val ok = when {
                got === Typed -> want is String || isThrow(want) // the typed API cannot take it; the reference must refuse it too
                isThrow(want) -> got is Threw && ((want as Map<*, *>)["code"] == null || (got.t as? ActionKitError)?.code == (want as Map<*, *>)["code"])
                got is Threw -> false
                c["cmp"] == "code" -> want is String && got is String && want.substringBefore(": ") == got.substringBefore(": ")
                else -> Json.canonicalize(want) == Json.canonicalize(got)
            }
            if (ok) continue
            bad.add("${c["name"]}\n  want: ${show(want)}\n  got:  ${show(got)}")
        }
        assertTrue("$fn: ${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    @Test fun everyFnIsPortedOrSkipped() {
        val ported = setOf(
            "validateDef", "isRole", "isFormat", "isContextKey", "paramNameError", "jsonProfileError", "idPatternError", "profileError",
            "registryError", "closure", "floorOf", "topTraits", "traitsDigest", "tablesDigest", "floorDecision", "worstReversibility",
            "sensitivityFloor", "impliedFromFacts", "normalize", "defDigest", "declProfile", "hintTraits", "effective", "reviewerPinsError",
            "isConfirmed", "factsDigest", "schemaVerbFloorError", "schemaFloorError", "packRoot", "packProof",
        )
        val unknown = K05Oracle.fns(FILE) - ported - SKIPPED
        assertTrue("oracle fns without a native mapping: $unknown", unknown.isEmpty())
    }

    @Test fun validateDef() = check("validateDef") { Actions.validateDef(it[0]) }
    @Test fun isRole() = check("isRole") { priv<Boolean>("isRole", it[0]) }
    @Test fun isFormat() = check("isFormat") { priv<Boolean>("isFormat", it[0]) }
    @Test fun isContextKey() = check("isContextKey") { Actions.isContextKey(it[0]) }
    @Test fun paramNameError() = check("paramNameError") { priv<String?>("paramNameError", it[0] as String) }
    @Test fun jsonProfileError() = check("jsonProfileError") { Actions.jsonProfileError(it[0]) }
    @Test fun idPatternError() = check("idPatternError") { priv<String?>("idPatternError", it[0]) }
    @Test fun profileError() = check("profileError") { Actions.profileError(it[0]) }
    @Test fun registryError() = check("registryError") { Actions.registryError(it[0], it[1] as Boolean) }
    @Test fun closure() = check("closure") { Deadline.within { Actions.closure(reg(it[0]), it[1] as List<Any?>) } }
    @Test fun floorOf() = check("floorOf") { Deadline.within { Actions.floorOf(reg(it[0]), it[1] as List<Any?>) } }
    @Test fun topTraits() = check("topTraits") { Actions.topTraits(reg(it[0])) }
    @Test fun traitsDigest() = check("traitsDigest") { Actions.traitsDigest(reg(it[0])) }
    @Test fun tablesDigest() = check("tablesDigest") { Actions.tablesDigest() }
    @Test fun floorDecision() = check("floorDecision") { Actions.floorDecision(obj(it[0]), obj(it[1]), obj(it[2])) }
    @Test fun worstReversibility() = check("worstReversibility") { Actions.worstReversibility(it[0], it[1] as Map<String, Map<String, Any?>>) }
    @Test fun sensitivityFloor() = check("sensitivityFloor") { priv<String>("sensitivityFloor", obj(it[0])) }
    @Test fun impliedFromFacts() = check("impliedFromFacts") {
        val f = obj(it[0])
        Actions.impliedFromFacts(f["effects"] as List<*>, (f["params"] as List<*>).map { p -> obj(p) }, f["scope"] as String?, f["worstRev"] as String)
    }
    @Test fun normalize() = check("normalize") { Actions.normalize(obj(it[0])) }
    @Test fun defDigest() = check("defDigest") { Actions.defDigest(obj(it[0])) }
    @Test fun declProfile() = check("declProfile") { Actions.declProfile(obj(it[0])) }
    @Test fun hintTraits() = check("hintTraits") { Actions.hintTraits(obj(it[0])) }
    @Test fun effective() = check("effective") { Actions.effective(obj(it[0]), Actions.CORE_REGISTRY, it[1]) }
    @Test fun reviewerPinsError() = check("reviewerPinsError") { Actions.reviewerPinsError(it[0]) }
    @Test fun isConfirmed() = check("isConfirmed") { Actions.isConfirmed(obj(it[0]), Actions.CORE_REGISTRY, it[1]) }
    @Test fun factsDigest() = check("factsDigest") { Actions.factsDigest(obj(it[0])) }
    @Test fun schemaVerbFloorError() = check("schemaVerbFloorError") { if (it[0] !is Map<*, *>) Typed else Actions.schemaVerbFloorError(obj(it[0]), Actions.CORE_REGISTRY, it[1]) }
    @Test fun schemaFloorError() = check("schemaFloorError") { if (it[0] !is Map<*, *>) Typed else Actions.schemaFloorError(obj(it[0]), it[1]) }
    @Test fun packRoot() = check("packRoot") { Actions.packRoot(it[0] as List<String>) }
    @Test fun packProof() = check("packProof") { Actions.packProof(it[0] as List<String>, it[1] as String) }

    // ---- the reference fixes of d36d91ac7, one each ----
    @Test fun floorDecisionDeniesANonIntegerTier() {
        val call = mapOf<String, Any?>("context" to listOf<Any?>())
        val bottom = mapOf<String, Any?>("esc" to Json.Num("0"), "caveats" to listOf<Any?>(), "context" to listOf<Any?>())
        val tiers = listOf<Pair<Any?, Any?>>(Json.Num("3") to Json.Num("3"), null to Json.Num("2"), "3" to Json.Num("2"), Json.Num("2.5") to Json.Num("2"),
            Json.Num("3") to Json.Num("-1"), Json.Num("-0") to Json.Num("0"), Json.Num("3") to true)
        tiers.forEachIndexed { i, (max, pre) ->
            val g = linkedMapOf<String, Any?>("caveats" to listOf<Any?>(), "preauth_esc" to pre)
            if (max != null) g["max_esc"] = max   // null = missing
            assertEquals("tiers #$i", if (i == 0) "allow" else "deny", Actions.floorDecision(g, call, bottom))
        }
    }

    @Test fun aReadAttestationWithoutAnArrayFinalTraitsIsNotConfirmed() {
        val a = of("isConfirmed").single { it["name"] == "isConfirmed/read good" }["args"] as List<Any?>
        assertTrue("control", Actions.isConfirmed(obj(a[0]), Actions.CORE_REGISTRY, a[1]))
        for (f in listOf<Any?>("missing", null, "")) {
            val d = IntentJs.normalize(Json.parseLenient(Json.canonicalize(a[0]))) as MutableMap<String, Any?>
            val att = (d["review"] as Map<*, *>)["attestation"] as MutableMap<String, Any?>
            if (f == "missing") att.remove("final_traits") else att["final_traits"] = f
            assertFalse("final_traits $f", Actions.isConfirmed(d, Actions.CORE_REGISTRY, a[1]))
        }
    }

    @Test fun aNullMaxItemsImpliesBulk() {
        for (mi in listOf<Any?>("missing", null, Json.Num("10"))) {
            val p = linkedMapOf<String, Any?>("type" to "array")
            if (mi != "missing") p["max_items"] = mi
            assertEquals("max_items $mi", mi !is Json.Num, "pca.bulk" in Actions.impliedFromFacts(listOf("create"), listOf(p), null, "reversible"))
        }
    }
}
