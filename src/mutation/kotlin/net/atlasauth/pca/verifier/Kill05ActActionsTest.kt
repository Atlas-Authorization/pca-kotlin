package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Kill tests for Actions.kt (k05 group "Act"): exact reasons of the attestation check (verbConfirmationError), the JavaScript
 * value semantics the port reads with (truthiness, String(), Object.entries, blank reasons), the reversibility_by path of rule 22
 * on a CONFIRMED verb (only there does the declared reversibility reach the result), and the small public entry points the
 * oracles do not pin (BOTTOM, CORE_TRAIT_DEFS, traitsOf, registryOfSchema). Signatures use IntentTestKit's deterministic keys.
 */
@Suppress("UNCHECKED_CAST")
class Kill05ActActionsTest {
    private fun n(s: String) = Json.Num(s)
    private fun m(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = linkedMapOf(*kv)
    private fun <T> priv(name: String, vararg a: Any?): T = KUtil.priv(Actions, name, *a)
    private fun thrown(f: () -> Any?): Throwable? = try { f(); null } catch (t: Throwable) { t }
    private val reg = Actions.CORE_REGISTRY
    private val pk32 = Pca.b64(ByteArray(32) { 1 })

    // ---- a minimal valid def ----
    private fun def(): LinkedHashMap<String, Any?> = m(
        "v" to n("1"), "kind" to "pca-action-def", "verb" to "acme.thing.read", "title" to "T", "effects" to listOf("read"),
        "resource" to m("type" to "acme.thing", "id" to "*", "scope" to "one"), "params" to m(), "review" to m("state" to "authored"),
    )

    @Test fun verbAndResourceTypeByteBounds() {
        assertNull(Actions.validateDef(def()))
        val s128 = "a".repeat(32) + "." + "b".repeat(32) + "." + "c".repeat(32) + "." + "d".repeat(29)
        assertEquals(128, s128.length)
        assertNull(Actions.validateDef(def().also { it["verb"] = s128 }))
        assertEquals("verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)", Actions.validateDef(def().also { it["verb"] = s128 + "d" }))
        assertNull(Actions.validateDef(def().also { it["resource"] = m("type" to s128, "id" to "*", "scope" to "one") }))
        assertEquals("resource.type is malformed", Actions.validateDef(def().also { it["resource"] = m("type" to s128 + "d", "id" to "*", "scope" to "one") }))
    }

    @Test fun aThrowInsideValidateDefIsReportedWithItsMessage() {
        val r = Actions.validateDef(linkedMapOf<Any?, Any?>(1 to "x"))!!
        assertTrue(r, r.startsWith("malformed def: ") && r != "malformed def: null" && r.length > "malformed def: ".length)
    }

    @Test fun jsonProfileOfNativeNumbersAndForeignValues() {
        assertNull(Actions.jsonProfileError(5))
        assertNull(Actions.jsonProfileError(5L))
        assertNull(Actions.jsonProfileError(n("5")))
        assertEquals("numbers must be safe integers (no floats, no -0)", Actions.jsonProfileError(2.5))
        assertEquals("only JSON values are allowed", Actions.jsonProfileError(Any()))
    }

    @Test fun anUnknownProfileMemberNamedNull() {
        assertEquals("profile: unknown member 'null'", Actions.profileError(linkedMapOf<Any?, Any?>(null to n("0"))))
    }

    @Test fun bottomAndTheCoreTraitTable() {
        assertEquals(Actions.profile(), Actions.BOTTOM)
        val defs = Actions.CORE_TRAIT_DEFS
        assertEquals(22, defs.size)
        assertEquals("pca.money_moving", defs[0]["id"])
        assertEquals(listOf("pca.external_communication"), defs.single { it["id"] == "pca.impersonation" }["implies"])
    }

    // ---- JavaScript value semantics ----

    @Test fun jsTruthiness() {
        val falsy = listOf<Any?>(null, false, "", n("0"), n("-0"), 0, 0L, 0.0, Double.NaN)
        val truthy = listOf<Any?>(true, "a", "0", n("1"), n("-1"), n("0.5"), 2, -1L, 0.5, listOf<Any?>(), m(), listOf<Any?>(0))
        for (v in falsy) assertFalse("$v", priv<Boolean>("jsTruthy", v))
        for (v in truthy) assertTrue("$v", priv<Boolean>("jsTruthy", v))
    }

    @Test fun jsBlankReasons() {
        for (s in listOf("", " ", "\t\n", " ", " ", " ", "\u001C", "\u001F", "﻿", "\u000B", "　  ")) assertTrue("blank '$s'", priv<Boolean>("jsBlank", s))
        for (s in listOf("x", "x ", " x", "  x  ", "​", "\u001B", "\u0000", "῿")) assertFalse("not blank '$s'", priv<Boolean>("jsBlank", s))
    }

    @Test fun jsStringOfTraitIds() {
        fun idErr(t: Any?) = Actions.registryError(listOf(t), false)
        assertEquals("trait id ',a' is malformed", idErr(m("id" to listOf(null, "a"))))
        assertEquals("trait id 'a,b,c' is malformed", idErr(m("id" to listOf("a", listOf("b", "c")))))
        assertEquals("trait id 'undefined' is malformed", idErr(listOf<Any?>()))
        assertEquals("trait id 'undefined' is malformed", idErr(m()))
        assertEquals("trait id '5' is malformed", idErr(m("id" to n("5"))))
    }

    @Test fun jsonCopyIsADeepCopy() {
        val inner = arrayListOf<Any?>("b")
        val src = arrayListOf<Any?>("a", inner, m("k" to arrayListOf<Any?>(n("1"))))
        val out = priv<Any?>("jsonCopy", src) as List<Any?>
        assertEquals(src, out)
        assertNotSame(src, out)
        assertNotSame(inner, out[1])
        val d = def().also { it["bindings"] = m("mcp" to m("tool" to "t")) }
        val nd = Actions.normalize(d)
        assertEquals(d["bindings"], nd["bindings"])
        assertNotSame(d["bindings"], nd["bindings"])
    }

    @Test fun normalizeCopiesOnlyTheReversibilityMembersAndDefaultsTheIdempotencyMode() {
        val d = def().also { it["reversibility"] = m("by" to "p", "map" to m("true" to "reversible"), "x" to n("1")) }
        assertEquals(m("by" to "p", "map" to m("true" to "reversible")), Actions.normalize(d)["reversibility"])
        assertEquals(m("mode" to "none"), Actions.normalize(def().also { it["idempotency"] = m() })["idempotency"])
        assertEquals(m("mode" to "none"), Actions.normalize(def())["idempotency"])
        assertEquals(m("mode" to "key_param", "param" to "k"), Actions.normalize(def().also { it["idempotency"] = m("mode" to "key_param", "param" to "k") })["idempotency"])
    }

    // ---- worstReversibility over whatever JSON the declaration holds ----

    @Test fun worstReversibilityReadsLikeTheReference() {
        fun w(r: Any?, params: Map<String, Map<String, Any?>> = mapOf()) = Actions.worstReversibility(r, params)
        // values: 0 is falsy (no domain): the map plus the default class
        assertEquals("irreversible", w(m("by" to "p", "map" to m("a" to "reversible")), mapOf("p" to m("type" to "string", "values" to n("0")))))
        assertTrue(thrown { w(m("by" to "p", "map" to m("a" to "reversible")), mapOf("p" to m("type" to "string", "values" to n("1")))) } is IllegalArgumentException)
        // an empty enum domain is covered vacuously
        assertEquals("reversible", w(m("by" to "p", "map" to m()), mapOf("p" to m("type" to "string", "values" to listOf<Any?>()))))
        // a boolean map that is not an object owns no "true" / "false"
        assertEquals("irreversible", w(m("by" to "p", "map" to true), mapOf("p" to m("type" to "boolean"))))
        // an array map: Object.values of the array, plus the default
        assertEquals("rate_limited", w(m("by" to "p", "map" to listOf("rate_limited", "reversible"), "default" to "reversible")))
        assertEquals("reversible", w(m("by" to "p", "map" to "abc", "default" to "reversible")))
        val e1 = thrown { w(m("by" to "p")) }
        assertTrue("$e1", e1 is IllegalArgumentException && e1.message == "Cannot convert undefined or null to object")
        val e2 = thrown { w(null) }
        assertTrue("$e2", e2 is IllegalArgumentException && e2.message == "Cannot read properties of null")
    }

    // ---- registry ----

    private fun trait(id: String, vararg implies: String) = m("id" to id, "implies" to implies.toList(), "floor" to Actions.profile(), "card_phrase" to "c")

    @Test fun impliesDepthCountsThroughMemoisedTraits() {
        // leaves first: every walk above the first finds its child already measured
        val defs = (9 downTo 1).map { k -> if (k == 9) trait("x.t9") else trait("x.t$k", "x.t${k + 1}") }
        assertEquals("trait 'x.t1': implies depth 9 exceeds 8", Actions.registryError(defs, false))
        assertNull(Actions.registryError(defs.dropLast(1), false))
    }

    @Test fun closureOfACyclicRawRegistryTerminates() {
        val raw = mapOf<String, Map<String, Any?>>("x.a" to m("implies" to listOf("x.b")), "x.b" to m("implies" to listOf("x.a")))
        // under a deadline: a closure that stopped skipping a visited id spins on this cycle, and without one that hang is a PIT timeout nobody decided
        assertEquals(listOf("x.a", "x.b"), Deadline.within { Actions.closure(raw, listOf("x.a")) })
        assertEquals(listOf("x.a", "x.b"), Deadline.within { Actions.closure(raw, listOf("x.b", "x.a", "x.b")) })
    }

    @Test fun extendRegistryRefusesANonArray() {
        val e = thrown { Actions.extendRegistry(reg, "x") }
        assertTrue("$e", e is ActionKitError && e.code == "bad_registry" && e.message == "custom traits must be an array")
    }

    @Test fun leqComparesEverySet() {
        val q = Actions.profile()
        assertTrue(Actions.leq(Actions.profile(), q))
        assertFalse(Actions.leq(Actions.profile(caveats = listOf("amount_cap")), q))
        assertFalse(Actions.leq(Actions.profile(context = listOf("idempotency")), q))
        assertFalse(Actions.leq(Actions.profile(prules = listOf("array_bounded")), q))
    }

    @Test fun floorsCoverOverCarriedFloors() {
        val q = m("risk" to n("0"), "rev" to "reversible", "blast_ppm" to n("0"), "esc" to n("0"), "caveats" to "x", "context" to n("5"), "prules" to true)
        // empty p lists are covered vacuously, whatever q holds
        assertTrue(priv<Boolean>("floorsCover", Actions.profile(), q))
        // a string q list is refused; any other non-list throws as the reference's b.includes does
        assertFalse(priv<Boolean>("floorsCover", Actions.profile(caveats = listOf("amount_cap")), q))
        val e = thrown { priv<Boolean>("floorsCover", Actions.profile(context = listOf("idempotency")), q) }
        assertTrue("$e", e is IllegalArgumentException && e.message == "b.includes is not a function")
        // a floor is a JSON number, never a string to coerce: every Number() form is refused, the ones JS reads as numbers included
        for (k in listOf("risk", "blast_ppm", "esc")) for (s in listOf("+-Infinity", "-+Infinity", "+0x1", "1_000", "NaN", "1f", "1d", "1L", "", " ", "12", "Infinity", "0x10"))
            assertFalse("$k '$s'", priv<Boolean>("floorsCover", Actions.profile(), LinkedHashMap(q).also { it[k] = s }))
    }

    @Test fun registryOfSchemaFollowsTheReferenceTruthiness() {
        assertEquals(reg.keys, Actions.registryOfSchema(m()).keys)
        for (td in listOf<Any?>(listOf<Any?>(), "", m(), n("5"), n("0"), true, null)) assertEquals("trait_defs $td", reg.keys, Actions.registryOfSchema(m("trait_defs" to td)).keys)
        for (td in listOf<Any?>("x", m("length" to n("0")), m("length" to n("1")))) {
            val e = thrown { Actions.registryOfSchema(m("trait_defs" to td)) }
            assertTrue("trait_defs $td: $e", e is ActionKitError && e.code == "bad_registry")
        }
        assertEquals(reg.size + 1, Actions.registryOfSchema(m("trait_defs" to listOf(trait("x.custom")))).size)
        assertEquals("bad_registry: custom traits must be an array", Actions.schemaFloorError(m("verbs" to listOf<Any?>(), "trait_defs" to "x")))
        val r = Actions.schemaFloorError(m())!!
        assertTrue(r, r.startsWith("bad_registry: ") && r != "bad_registry: null")
    }

    // ---- T(d) facts ----

    @Test fun impliedFromFactsRefusesLikeTheReference() {
        val e1 = thrown { Actions.impliedFromFacts(listOf("bogus"), listOf(), null, "reversible") }
        assertTrue("$e1", e1 is IllegalArgumentException && e1.message == "unknown effect bogus")
        val e2 = thrown { Actions.impliedFromFacts(listOf("read"), listOf(m("role" to n("5"))), null, "reversible") }
        assertTrue("$e2", e2 is IllegalArgumentException && e2.message == "p.role.startsWith is not a function")
        val e3 = thrown { Actions.impliedFromFacts(listOf("create"), listOf(m("tags" to n("5"))), null, "reversible") }
        assertTrue("$e3", e3 is IllegalArgumentException && e3.message == "tags is not iterable")
        assertEquals(listOf<String>(), Actions.impliedFromFacts(listOf("create"), listOf(m("tags" to "pii")), null, "reversible"))
    }

    @Test fun factsDigestRefusesANullMemberName() {
        assertTrue(thrown { Actions.factsDigest(linkedMapOf<Any?, Any?>(null to n("1")) as Map<String, Any?>) } != null)
    }

    @Test fun reviewerPinRoles() {
        fun pins(roles: Any?, vararg extra: Pair<Any?, Any?>): Map<String, Any?> {
            val k = linkedMapOf<Any?, Any?>("kid" to "k", "pk" to pk32, "roles" to roles)
            for ((a, b) in extra) k[a] = b
            return m("keys" to listOf(k))
        }
        val badRoles = "key 'k': roles must be distinct known roles"
        for (r in listOf<Any?>("reviewer", listOf<Any?>(), listOf("reviewer", "reviewer"), listOf("reviewer", "auditor"))) assertEquals("$r", badRoles, Actions.reviewerPinsError(pins(r)))
        for (r in listOf(listOf("importer"), listOf("reviewer"), listOf("model"), listOf("publisher", "reviewer"), listOf("importer", "model"))) assertNull("$r", Actions.reviewerPinsError(pins(r)))
        val mixed = "key 'k': an importer or model key cannot hold the reviewer role"
        assertEquals(mixed, Actions.reviewerPinsError(pins(listOf("reviewer", "importer"))))
        assertEquals(mixed, Actions.reviewerPinsError(pins(listOf("reviewer", "model"))))
        // only not_before / not_after are window members: any other member (even one named null) is not read
        assertNull(Actions.reviewerPinsError(pins(listOf("reviewer"), null to n("-1"))))
        assertEquals("key 'k': not_after must be a non-negative integer", Actions.reviewerPinsError(pins(listOf("reviewer"), "not_after" to n("-1"))))
    }

    // ---- confirmations (signed with IntentTestKit's "act-reviewer" key) ----

    private val pub = IntentTestKit.pub("act-reviewer")
    private fun pins(vararg extra: Pair<String, Any?>): LinkedHashMap<String, Any?> =
        m("keys" to listOf(m("kid" to "rev", "pk" to pub, "roles" to listOf("reviewer"), *extra)))

    private fun verb(): LinkedHashMap<String, Any?> =
        m("verb" to "acme.thing.read", "effects" to listOf("read"), "params" to m(), "traits" to listOf<Any?>(), "floors" to Actions.profile(), "def" to "D1")

    /** Signs a confirmation of `v` (call after every member a fact digest covers is set) and attaches it. */
    private fun confirm(v: LinkedHashMap<String, Any?>, fin: List<String> = listOf(), dis: List<Pair<String, String>> = listOf(), ts: Any? = n("1000")): LinkedHashMap<String, Any?> {
        val body = m(
            "def_digest" to v["def"], "traits_digest" to Actions.traitsDigest(reg), "facts_digest" to Actions.factsDigest(v), "final_traits" to fin.sorted(),
            "dismissed" to dis.sortedBy { it.first }.map { m("trait" to it.first, "reason" to it.second) }, "reviewer_kid" to "rev", "ts" to ts,
        )
        val a = LinkedHashMap(body)
        a["final_traits"] = fin
        a["dismissed"] = dis.map { m("trait" to it.first, "reason" to it.second) }
        a["sig"] = IntentTestKit.sign("act-reviewer", IntentJs.message(Actions.REVIEW_DOMAIN + "\u0000", body))
        v["confirmation"] = a
        return v
    }

    private fun att(v: Map<String, Any?>) = v["confirmation"] as MutableMap<String, Any?>

    @Test fun verbConfirmationReasons() {
        fun e(v: Map<String, Any?>, p: Any? = pins()) = Actions.verbConfirmationError(v, reg, p)
        assertNull(e(confirm(verb())))
        assertEquals("no reviewer keys are pinned", e(confirm(verb()), null))
        assertEquals("bad pins: pins must be {keys: [...]}", e(confirm(verb()), m()))
        assertEquals("no confirmation", e(verb()))
        assertEquals("no confirmation", e(verb().also { it["confirmation"] = "x" }))
        assertEquals("the confirmation is unsigned", e(confirm(verb()).also { att(it).remove("sig") }))
        assertEquals("the confirmation covers a different def digest", e(confirm(verb()).also { it["def"] = "D2" }))
        assertEquals("bad pins: traits_digests must be an array", e(confirm(verb()), pins().also { it["traits_digests"] = "x" }))
        assertEquals("the verb facts differ from the facts the reviewer confirmed", e(confirm(verb()).also { it["effects"] = listOf("create") }))
        for ((k, bad) in listOf<Pair<String, Any?>>("final_traits" to "x", "dismissed" to "x", "ts" to "x", "ts" to n("1.5"), "reviewer_kid" to n("5"), "final_traits" to listOf(n("5"))))
            assertEquals("$k = $bad", "malformed confirmation", e(confirm(verb()).also { att(it)[k] = bad }))
        assertEquals("no pinned key 'nobody'", e(confirm(verb()).also { att(it)["reviewer_kid"] = "nobody" }))
        assertEquals("key 'rev' does not hold the reviewer role", e(confirm(verb()), m("keys" to listOf(m("kid" to "rev", "pk" to pub, "roles" to listOf("publisher"))))))
        val window = "the confirmation time is outside the key validity"
        assertEquals(window, e(confirm(verb()), pins("not_before" to n("2000"))))
        assertEquals(window, e(confirm(verb()), pins("not_after" to n("500"))))
        assertNull(e(confirm(verb()), pins("not_before" to n("1000"), "not_after" to n("1000"))))
        assertEquals("the confirmation signature is invalid", e(confirm(verb()).also { att(it)["ts"] = n("1001") }, pins()))
    }

    @Test fun finalTraitsMustBeCarried() {
        fun e(v: Map<String, Any?>) = Actions.verbConfirmationError(v, reg, pins())
        val bad = "the final traits do not match"
        assertNull(e(confirm(verb().also { it["traits"] = listOf("pca.destructive", "pca.bulk") }, listOf("pca.bulk", "pca.destructive"))))
        assertEquals(bad, e(confirm(verb(), listOf("pca.bulk"))))
        assertEquals(bad, e(confirm(verb().also { it["traits"] = listOf("pca.bulk") }, listOf("pca.bulk", "pca.destructive"))))
        assertEquals(bad, e(confirm(verb().also { it["traits"] = listOf("pca.destructive") }, listOf("pca.bulk", "pca.destructive"))))
        // traits that are not an array carry nothing
        assertEquals(bad, e(confirm(verb().also { it["traits"] = "pca.bulk" }, listOf("pca.bulk"))))
    }

    @Test fun dismissedTraits() {
        fun e(v: Map<String, Any?>) = Actions.verbConfirmationError(v, reg, pins())
        val bad = "a dismissed trait is also final, or has no reason"
        // two dismissals given out of order: the signed body lists them sorted by trait
        assertNull(e(confirm(verb(), dis = listOf("pca.zeta" to "z", "pca.alpha" to "a"))))
        assertNull(e(confirm(verb(), dis = listOf("pca.alpha" to "a", "pca.zeta" to "z"))))
        for (d in listOf<Any?>("x", m("trait" to n("5"), "reason" to "r"), m("trait" to "pca.bulk", "reason" to n("5")), m("trait" to "pca.bulk", "reason" to "  \u001F")))
            assertEquals("$d", bad, e(confirm(verb()).also { att(it)["dismissed"] = listOf(d) }))
        assertEquals(bad, e(confirm(verb().also { it["traits"] = listOf("pca.bulk") }, listOf("pca.bulk"), listOf("pca.bulk" to "r"))))
    }

    @Test fun aThrowInsideTheCheckIsReportedWithItsMessage() {
        val bad = mapOf<String, Map<String, Any?>>("x.a" to m("id" to "x.a", "implies" to listOf(n("5")), "floor" to Actions.profile(), "card_phrase" to "c"))
        val r = Actions.verbConfirmationError(confirm(verb()), bad, pins())!!
        assertTrue(r, r.startsWith("malformed confirmation: ") && r != "malformed confirmation: null")
    }

    @Test fun traitsOfAConfirmedAndAnUnconfirmedDef() {
        val d = def()
        val body = m(
            "def_digest" to Actions.defDigest(d), "traits_digest" to Actions.traitsDigest(reg), "facts_digest" to "f", "final_traits" to listOf<Any?>(),
            "dismissed" to listOf<Any?>(), "reviewer_kid" to "rev", "ts" to n("1000"),
        )
        val a = LinkedHashMap(body)
        a["sig"] = IntentTestKit.sign("act-reviewer", IntentJs.message(Actions.REVIEW_DOMAIN + "\u0000", body))
        d["review"] = m("state" to "confirmed", "attestation" to a)
        assertTrue(Actions.isConfirmed(d, reg, pins()))
        assertEquals(listOf<String>(), Actions.traitsOf(d, reg, pins()))
        assertEquals(Actions.hintTraits(d), Actions.traitsOf(d, reg, pins()))
        assertEquals(Actions.topTraits(reg), Actions.traitsOf(d, reg))
        assertEquals(Actions.topTraits(reg), Actions.traitsOf(d, reg, null))
        assertEquals(22, Actions.traitsOf(d, reg).size)
    }

    // ---- rule 22: reversibility_by ----

    /** An unconfirmed verb that carries every trait and the top floor: consistent whatever its reversibility. */
    private fun topVerb(): LinkedHashMap<String, Any?> {
        val top = Actions.topTraits(reg)
        return verb().also { it["traits"] = top; it["floors"] = Actions.floorOf(reg, top) }
    }

    @Test fun reversibilityByOfAnUnconfirmedVerb() {
        fun e(rb: Any?) = Actions.schemaVerbFloorError(topVerb().also { it["reversibility_by"] = rb }, reg)
        assertNull(Actions.schemaVerbFloorError(topVerb(), reg))
        // falsy reversibility_by values are absent (the reference's `v.reversibility_by ? ... : ...`)
        for (rb in listOf<Any?>(n("0"), "", false, null)) assertNull("$rb", e(rb))
        val undef = "schema_floor_forged: Cannot read properties of undefined (reading 'slice')"
        assertEquals(undef, e(n("1")))
        assertEquals(undef, e(m("map" to m())))
        assertEquals("schema_floor_forged: Cannot read properties of null (reading 'slice')", e(m("param" to null, "map" to m())))
        assertEquals("schema_floor_forged: v.reversibility_by.param.slice is not a function", e(m("param" to n("5"), "map" to m())))
        assertEquals("schema_floor_forged: Cannot read properties of null (reading 'risk')", Actions.schemaVerbFloorError(topVerb().also { it["floors"] = null }, reg))
    }

    /** A confirmed verb with one boolean parameter p, no traits and the bottom floor: its declared reversibility decides. */
    private fun confirmedVerb(rb: Map<String, Any?>, floors: Map<String, Any?> = Actions.profile()): LinkedHashMap<String, Any?> {
        val v = verb()
        v["params"] = m("action.params.p" to m("type" to "boolean"))
        v["reversibility_by"] = rb
        confirm(v)
        v["floors"] = floors
        return v
    }

    @Test fun reversibilityByOfAConfirmedVerb() {
        fun e(v: Map<String, Any?>) = Actions.schemaVerbFloorError(v, reg, pins())
        val both = m("true" to "reversible", "false" to "reversible")
        assertNull(e(confirmedVerb(m("param" to "action.params.p", "map" to both))))
        // an array param slices like the reference: 14 placeholder items, then the name
        assertNull(e(confirmedVerb(m("param" to List(14) { "x" } + "p", "map" to both))))
        val forged = "schema_traits_forged: missing implied trait pca.irreversible"
        assertEquals(forged, e(confirmedVerb(m("param" to List(13) { "x" } + "p", "map" to both))))
        assertEquals(forged, e(confirmedVerb(m("param" to "action.params.q", "map" to both))))
        // the map does not cover false: the default decides
        assertNull(e(confirmedVerb(m("param" to "action.params.p", "map" to m("true" to "reversible"), "default" to "reversible"))))
        assertEquals(forged, e(confirmedVerb(m("param" to "action.params.p", "map" to m("true" to "reversible")))))
        // rate_limited: below the floors' rev unless the floors say so
        val rl = m("param" to "action.params.p", "map" to m("true" to "rate_limited", "false" to "rate_limited"))
        assertEquals("schema_floor_forged: floors.rev is below the declared reversibility", e(confirmedVerb(rl)))
        assertNull(e(confirmedVerb(rl, Actions.profile(rev = "rate_limited"))))
        assertNull(e(confirmedVerb(rl, Actions.profile(rev = "irreversible"))))
    }
}
