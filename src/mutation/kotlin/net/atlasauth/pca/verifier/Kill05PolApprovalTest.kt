package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * Approval.kt survivors the k05 oracle could not reach (its throw match is loose: any throw, or the same ActionKitError code):
 * the exact require() exceptions and messages, lone-surrogate edges, the empty-prefix and depth-3 flatten, hash-colliding
 * `when (type)` labels, an unknown declared type, a non-string non-object currency, and the public WORDS list.
 * Expected answers are the TS reference's (packages/pca/src approval-render.ts, packages/pca-actions approval-render.ts).
 */
@Suppress("UNCHECKED_CAST")
class Kill05PolApprovalTest {
    private fun def(params: Map<String, Any?>): Map<String, Any?> = linkedMapOf(
        "v" to 1L, "kind" to "pca-action-def", "verb" to "acme.t", "title" to "T", "effects" to listOf("pay"),
        "resource" to linkedMapOf("type" to "account", "id" to "*", "scope" to "one"), "params" to params,
    )

    private fun p(type: String, vararg extra: Pair<String, Any?>): Map<String, Any?> = linkedMapOf<String, Any?>("type" to type).also { it.putAll(extra) }

    private fun code(f: () -> Any?): String? = try { f(); null } catch (e: ActionKitError) { e.code }

    private fun iae(msg: String, f: () -> Any?) {
        try { f(); fail("no throw: $msg") } catch (e: IllegalArgumentException) {
            assertEquals(IllegalArgumentException::class.java, e.javaClass)
            assertEquals(msg, e.message)
        }
    }

    private fun fields(r: Map<String, Any?>) = r["fields"] as List<Map<String, Any?>>

    @Test fun wordsList() {
        assertEquals(256, Approval.WORDS.size)
        assertEquals("able", Approval.WORDS[0])
        assertEquals("nice", Approval.WORDS[255])
    }

    @Test fun requireExceptionsAndMessages() {
        iae("approvalRenderDigest: render must be an object") { Approval.renderDigest(null) }
        iae("approvalChallenge: both digests must be canonical 32-byte values") { Approval.challenge("x", KUtil.B32) }
        iae("approvalChallenge: both digests must be canonical 32-byte values") { Approval.challenge(KUtil.B32, 5L) }
        iae("bindingWords: render digest must be a canonical 32-byte value") { Approval.bindingWords("x") }
        iae("bindingWords: render digest must be a canonical 32-byte value") { Approval.bindingWords(null) }
        assertEquals("hint-horn-duck-deer-diet-fill", Approval.bindingWords(KUtil.B32))
    }

    @Test fun unitKindMustBeAListedString() {
        fun shape(unit: Map<String, Any?>): String? = Approval.renderShapeError(linkedMapOf(
            "v" to 1L, "kind" to "pca-approval-render", "verb" to "acme.t", "def_digest" to KUtil.B32, "unreviewed" to false,
            "fields" to listOf(linkedMapOf("id" to "a", "class" to "param", "value" to 1L, "unit" to unit)),
        ))
        assertEquals(null, shape(linkedMapOf("kind" to "count")))
        assertEquals(null, shape(linkedMapOf("kind" to "ratio")))
        // a null kind (present member) is no listed kind: the closed-members test alone would pass it
        assertEquals("unknown unit", shape(linkedMapOf("kind" to null)))
        assertEquals("unknown unit", shape(linkedMapOf("kind" to 5L)))
        assertEquals("unknown unit", shape(linkedMapOf("kind" to "count", "x" to 1L)))
    }

    @Test fun loneSurrogates() {
        val d = def(linkedMapOf("s" to p("string")))
        for (bad in listOf("a\uDC00", "\uD800a", "x\uD800", "\uDC00\uD800")) assertEquals(bad, "render_bad_value", code { Approval.render(d, linkedMapOf("s" to bad)) })
        assertEquals("😀", fields(Approval.render(d, linkedMapOf("s" to "😀")))[0]["value"])
    }

    @Test fun flattenPrefixAndDepth() {
        // an empty top-level key contributes no prefix segment: {"": {x: 1}} renders field "x"
        val r = Approval.render(def(linkedMapOf("x" to p("integer"))), linkedMapOf("" to linkedMapOf("x" to 7L)))
        assertEquals(listOf("x"), fields(r).map { it["id"] })
        // depth 3 is the last path segment: a 4th level stays an object value (bad value), never "a.b.c.d"
        val d = def(linkedMapOf("a.b.c" to p("integer")))
        assertEquals("render_bad_value", code { Approval.render(d, linkedMapOf("a" to linkedMapOf("b" to linkedMapOf("c" to linkedMapOf("d" to 1L))))) })
        assertEquals(listOf("a.b.c"), fields(Approval.render(d, linkedMapOf("a" to linkedMapOf("b" to linkedMapOf("c" to 1L))))).map { it["id"] })
    }

    @Test fun typeLabelsAreExact() {
        // each colliding label has the same String.hashCode as the real type (s[1]+1, s[2]-31); the reference's switch has no
        // such case, so the value is refused whatever it is; the real label accepts the same value
        val rows = listOf(
            Triple("integer", "ioUeger", 3L), Triple("duration", "dvSation", 3L), Triple("boolean", "bpPlean", true),
            Triple("string", "suSing", "s"), Triple("date", "dbUe", "s"), Triple("datetime", "dbUetime", "s"),
            Triple("object_ref", "ocKect_ref", "s"), Triple("set", "sfU", listOf("a")), Triple("array", "asSay", listOf("a")),
        )
        for ((real, twin, value) in rows) {
            assertEquals(real.hashCode(), twin.hashCode())
            assertEquals(real, null, code { Approval.render(def(linkedMapOf("q" to p(real))), linkedMapOf("q" to value)) })
            assertEquals(twin, "render_bad_value", code { Approval.render(def(linkedMapOf("q" to p(twin))), linkedMapOf("q" to value)) })
        }
        assertEquals("render_bad_value", code { Approval.render(def(linkedMapOf("q" to p("object"))), linkedMapOf("q" to "s")) })
    }

    @Test fun currencyForms() {
        val money = { ccy: Any? -> def(linkedMapOf("amt" to p("integer", "unit" to linkedMapOf("kind" to "money", "ccy" to ccy, "exp" to 2L)), "cur" to p("string"))) }
        val params = linkedMapOf<String, Any?>("amt" to 100L, "cur" to "USD")
        assertEquals("render_unresolved_currency", code { Approval.render(money(5L), params) })
        assertEquals("render_unresolved_currency", code { Approval.render(money(true), params) })
        val lit = fields(Approval.render(money("EUR"), params)).first { it["id"] == "amt" }["unit"] as Map<String, Any?>
        assertEquals("EUR", lit["ccy"])
        val from = fields(Approval.render(money(linkedMapOf("from" to "cur")), params)).first { it["id"] == "amt" }["unit"] as Map<String, Any?>
        assertEquals("USD", from["ccy"])
    }
}
