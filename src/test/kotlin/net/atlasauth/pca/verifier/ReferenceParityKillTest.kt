package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Parity with the TypeScript reference on three facade details. Every expected string is the reference's output for the same input:
 * a catalog resource is used as given with only an absent one meaning '*' (facade.ts compilePolicy: `s.resource ?? '*'`), a risk-policy
 * weights override is object-spread (`{...riskPolicy.weights, ...(opts.riskPolicy.weights ?? {})}`), and the risk of a dollar action
 * reads its amount with JavaScript's `Number()` (facade.ts riskFor).
 */
@Suppress("UNCHECKED_CAST")
class ReferenceParityKillTest {
    private val now = 1_800_000_000_000L
    private fun canon(o: Any?) = Json.canonicalize(o)

    // ---- catalog resource -----------------------------------------------------------------------------------------------------

    @Test fun aCatalogResourceIsUsedAsGivenAndOnlyAnAbsentOneIsAny() {
        assertNull(Catalog.Spec("c", "n", "c.n", "reversible", 0.1, null, "d").resource)
        val cat = Catalog(listOf(
            Catalog.Spec("c", "a", "c.a", "reversible", 0.1, null, "d", resource = ""),
            Catalog.Spec("c", "b", "c.b", "reversible", 0.1, null, "d", resource = "repo:x"),
            Catalog.Spec("c", "n", "c.n", "reversible", 0.1, null, "d", resource = null)))
        val p = Facade.compilePolicy(Issue.obj("c" to listOf("a", "b", "n", "z")), null, cat, null, null, 0L)
        // an empty resource stays empty (never widened to '*'); an uncatalogued verb and a null resource are '*'
        assertEquals("[{\"resource\":\"\",\"verb\":\"c.a\"},{\"resource\":\"repo:x\",\"verb\":\"c.b\"},{\"resource\":\"*\",\"verb\":\"c.n\"},"
            + "{\"resource\":\"*\",\"verb\":\"c.z\"}]", canon(p.predicates))
    }

    // ---- weights override: object spread --------------------------------------------------------------------------------------

    private val defaultWeights = "\"alpha\":0.25,\"beta\":0.2,\"delta\":0.2,\"epsilon\":0.1,\"gamma\":0.2,\"zeta\":0.05"

    private fun compiledWith(weights: Any?) =
        Facade.compilePolicy(Issue.obj("github" to listOf("read")), null, null, null, Issue.obj("weights" to weights), 0L).riskPolicy

    private fun policyWith(weights: Any?) = canon(compiledWith(weights))

    private fun expect(extra: String) =
        "{\"bMax\":1,\"kappa\":1,\"lambda\":0.0005,\"rho\":0.5,\"theta1\":0.25,\"theta2\":0.6,\"weights\":{$extra$defaultWeights}}"

    @Test fun aStringOrArrayWeightsSpreadsItsIndicesAndNothingElseIsAdded() {
        assertEquals(expect("\"0\":\"a\",\"1\":\"b\","), policyWith("ab"))
        assertEquals(expect("\"0\":\"x\",\"1\":0.5,"), policyWith(listOf("x", Json.Num("0.5"))))
        assertEquals(expect(""), policyWith(""))
        assertEquals(expect(""), policyWith(listOf<Any?>()))
        assertEquals(expect(""), policyWith(7L))
        assertEquals(expect(""), policyWith(true))
        assertEquals(expect(""), policyWith(null))
        // a string spreads by UTF-16 code unit ("😀" has two), and the lenient canonical form escapes each lone surrogate
        assertEquals(expect("\"0\":\"\\ud83d\",\"1\":\"\\ude00\","), policyWith("\uD83D\uDE00"))
        val w = compiledWith("\uD83D\uDE00")["weights"] as Map<String, Any?>
        assertEquals("\uD83D", w["0"])
        assertEquals("\uDE00", w["1"])
        assertEquals(8, w.size)
        // an object still overrides a named weight
        assertEquals(expect("").replace("\"gamma\":0.2", "\"gamma\":1"), policyWith(Issue.obj("gamma" to 1L)))
    }

    // ---- the amount of a dollar action: JavaScript Number() -------------------------------------------------------------------

    private val refund = Facade.agent(Facade.AgentOptions(Keys.ed25519(Keys.edFromSeed(ByteArray(32))), "goal", Issue.obj("stripe" to listOf("refund")),
        limits = Issue.obj("refund" to "\$500"), holder = Keys.ed25519(Keys.edFromSeed(ByteArray(32) { 1 })), aud = "rs", now = now, goalSalt = "s"))

    private fun claim(amount: Any?): String =
        canon(refund.act("stripe.refund", "charge:1", Issue.obj("amount" to amount), Facade.ActOptions(now = now)).pcactn["risk_claim"])

    private fun r(x: String) = "{\"inputs\":{\"blastRadius\":$x},\"r\":$x}"

    @Test fun anArrayAmountConvertsThroughItsStringForm() {
        assertEquals(r("0.002"), claim(listOf(1L)))
        assertEquals(r("0.004"), claim(listOf(listOf(2L))))
        assertEquals(r("0.025"), claim(listOf(Json.Num("12.5"))))
        assertEquals(r("0.01"), claim(listOf("5")))
        assertEquals(r("0.014"), claim(listOf(" 7 ")))
        assertEquals(r("0.032"), claim(listOf("0x10")))
        assertEquals(r("0"), claim(listOf<Any?>()))
        assertEquals(r("0"), claim(listOf(null)))
        assertEquals(r("0"), claim(listOf(listOf<Any?>())))
        assertEquals(r("0"), claim(listOf("")))
        // two or more elements join with a comma; String([true]) is "true"; String([{}]) is "[object Object]": all NaN, the blast radius
        assertEquals(r("0.9"), claim(listOf(1L, 2L)))
        assertEquals(r("0.9"), claim(listOf(listOf(1L, 2L))))
        assertEquals(r("0.9"), claim(listOf(true)))
        assertEquals(r("0.9"), claim(listOf(false)))
        assertEquals(r("0.9"), claim(listOf(listOf(true))))
        assertEquals(r("0.9"), claim(listOf(Issue.obj())))
        // outside an array a boolean is 1 or 0
        assertEquals(r("0.002"), claim(true))
        assertEquals(r("0"), claim(false))
    }

    @Test fun aStringAmountIsReadAsJavaScriptReadsIt() {
        assertEquals(r("0.032"), claim("0x10"))
        assertEquals(r("0.062"), claim("0X1f"))
        assertEquals(r("0.03"), claim("0o17"))
        assertEquals(r("0.01"), claim("0b101"))
        assertEquals(r("0.001"), claim("+.5"))
        assertEquals(r("0.01"), claim("5."))
        // NaN in JavaScript (Kotlin's toDouble takes some of these): the blast radius
        for (s in listOf("-0x10", "1f", "1d", "0x1p3", "NaN", "Infinity", "1e400"))
            assertEquals(s, r("0.9"), claim(s))
    }

    @Test fun aDeeplyNestedOneElementArrayIsUnwrappedWithoutRecursion() {
        var x: Any? = 5L
        repeat(1000) { x = listOf(x) }
        assertEquals(5.0, Facade.jsNumberOf(x), 0.0)
        assertEquals(0.0, Facade.jsNumberOf(null), 0.0)
        assertEquals(Double.NaN, Facade.jsNumberOf(Issue.obj()), 0.0)
    }
}
