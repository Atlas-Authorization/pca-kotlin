package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The facade: number text, limit parsing, policy compilation and the agent handle (dry run, risk claim, counters, sub-agents). */
@Suppress("UNCHECKED_CAST")
class Kill15FacadeTest {
    private val now = 1_800_000_000_000L
    private val principal = Keys.ed25519(Keys.edFromSeed(ByteArray(32)))
    private val agentEd = Keys.edFromSeed(ByteArray(32) { 1 })
    private val agentS = Keys.ed25519(agentEd)

    private fun m(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun canon(o: Any?) = Json.canonicalize(o)

    private fun refusal(f: () -> Unit): String {
        try { f() } catch (e: IllegalArgumentException) { return e.message ?: "" }
        fail("expected a refusal")
        return ""
    }

    private fun perms(vararg kv: Pair<String, List<String>>): Map<String, Any?> = Issue.obj(*kv)

    private fun opts(permissions: Map<String, Any?>, limits: Map<String, Any?>? = null, riskPolicy: Map<String, Any?>? = null, catalog: Catalog? = null,
                     budgetModel: String? = null, aud: String? = "rs", at: Long? = now) =
        Facade.AgentOptions(principal, "goal", permissions, limits = limits, holder = agentS, riskPolicy = riskPolicy, budgetModel = budgetModel,
            catalog = catalog, aud = aud, now = at, goalSalt = "s")

    private fun handle(permissions: Map<String, Any?>, limits: Map<String, Any?>? = null, riskPolicy: Map<String, Any?>? = null, catalog: Catalog? = null,
                       budgetModel: String? = null, aud: String? = "rs", at: Long? = now) =
        Facade.agent(opts(permissions, limits, riskPolicy, catalog, budgetModel, aud, at))

    // ---- numbers in the reference's JSON form --------------------------------------------------------------------------------

    @Test fun aSafeIntegerIsALongAndAnythingElseIsTheShortestDecimal() {
        assertEquals(5L, Facade.jn(5.0))
        assertEquals(-3L, Facade.jn(-3.0))
        assertEquals(0L, Facade.jn(0.0))
        assertEquals(0L, Facade.jn(-0.0))
        assertEquals(1L, Facade.jn(1.0))
        assertEquals(9007199254740991L, Facade.jn(9007199254740991.0))
        assertEquals(-9007199254740991L, Facade.jn(-9007199254740991.0))
        for ((d, raw) in listOf(0.5 to "0.5", 12.5 to "12.5", 9007199254740992.0 to "9007199254740992", -9007199254740992.0 to "-9007199254740992",
            1e21 to "1e+21", 1.5e-7 to "1.5e-7", 0.1 to "0.1", -0.25 to "-0.25")) {
            val j = Facade.jn(d)
            assertTrue("$d", j is Json.Num)
            assertEquals(raw, (j as Json.Num).raw)
        }
    }

    @Test fun theTextOfANumberIsWhatJavaScriptPrints() {
        assertEquals("5", Facade.jsText(5.0))
        assertEquals("500", Facade.jsText(500.0))
        assertEquals("12.5", Facade.jsText(12.5))
        assertEquals("0.5", Facade.jsText(0.5))
        assertEquals("1e+21", Facade.jsText(1e21))
        assertEquals("9007199254740991", Facade.jsText(9007199254740991.0))
        assertEquals("9007199254740992", Facade.jsText(9007199254740992.0))
    }

    // ---- trimming ------------------------------------------------------------------------------------------------------------

    @Test fun trimStripsJavaScriptWhiteSpaceFromBothEndsOnly() {
        assertEquals("a", Facade.jsTrim("a"))
        assertEquals("ab", Facade.jsTrim("ab"))
        assertEquals("a b", Facade.jsTrim(" a b "))
        assertEquals("a", Facade.jsTrim("  a  "))
        assertEquals("a", Facade.jsTrim("a  "))
        assertEquals("a", Facade.jsTrim("  a"))
        assertEquals("", Facade.jsTrim(""))
        assertEquals("", Facade.jsTrim("   "))
        assertEquals("a  b", Facade.jsTrim("\ta  b\n"))
        // tab, line feed, vertical tab, form feed, carriage return, space
        assertEquals("x", Facade.jsTrim("\t\n\u000B\u000C\r x \r\u000C\u000B\n\t"))
        // no-break space, figure space, narrow no-break space
        assertEquals("x", Facade.jsTrim("\u00A0x\u00A0"))
        assertEquals("x", Facade.jsTrim("\u2007x\u202F"))
        assertEquals("x", Facade.jsTrim("\u2028x\u2029"))
        // the byte order mark is white space in JavaScript
        assertEquals("x", Facade.jsTrim("\uFEFFx\uFEFF"))
        assertEquals("", Facade.jsTrim("\uFEFF"))
        assertEquals("x", Facade.jsTrim("\u1680\u2000\u200A\u205F\u3000x\u3000\u205F\u200A\u2000\u1680"))
        assertEquals("\uFEFEx", Facade.jsTrim("\uFEFEx"))
        assertEquals("x\uFF00", Facade.jsTrim("x\uFF00"))
        // JavaScript does not count the control separators, the next-line character, the Mongolian vowel separator or the zero-width space
        for (c in listOf("\u001C", "\u001F", "\u0085", "\u180E", "\u200B", "\u2060")) assertEquals(c, c + "x" + c, Facade.jsTrim(c + "x" + c))
        // a long run of white space is cut in one pass
        assertEquals("x", Facade.jsTrim(" ".repeat(200_000) + "x" + " ".repeat(200_000)))
        assertEquals("x" + " ".repeat(100_000) + "y", Facade.jsTrim(" x" + " ".repeat(100_000) + "y "))
    }

    // ---- limit parsing -------------------------------------------------------------------------------------------------------

    @Test fun aLimitIsAnAmountAnOptionalDollarSignAndAnOptionalPeriod() {
        fun j(s: Any?) = canon(Facade.parseLimit(s).toJson())
        assertEquals("{\"amount\":500,\"periodMs\":86400000,\"unit\":\"usd\"}", j("\$500/day"))
        assertEquals("{\"amount\":12.5,\"unit\":\"usd\"}", j("\$12.50"))
        assertEquals("{\"amount\":10,\"periodMs\":3600000,\"unit\":\"count\"}", j("10 / Hours"))
        assertEquals("{\"amount\":3,\"unit\":\"count\"}", j("3"))
        assertEquals("{\"amount\":0,\"unit\":\"count\"}", j("0"))
        assertEquals("{\"amount\":0,\"periodMs\":86400000,\"unit\":\"usd\"}", j("\$0/day"))
        assertEquals("{\"amount\":0.5,\"unit\":\"count\"}", j("0.5"))
        assertEquals("{\"amount\":5,\"periodMs\":1000,\"unit\":\"usd\"}", j(" \$ 5 / s "))
        assertEquals("{\"amount\":5,\"periodMs\":1000,\"unit\":\"count\"}", j("\u00A05/SEC\uFEFF"))
        val p = Facade.parseLimit("\$7.25/week")
        assertEquals(7.25, p.amount, 0.0)
        assertEquals("usd", p.unit)
        assertEquals(604_800_000L, p.periodMs)
        assertNull(Facade.parseLimit("7").periodMs)
        assertEquals("count", Facade.parseLimit("7").unit)
    }

    @Test fun everyPeriodNameHasItsLength() {
        val s = 1000L
        val groups = listOf(
            listOf("s", "sec", "second", "seconds") to s,
            listOf("m", "min", "minute", "minutes") to 60 * s,
            listOf("h", "hr", "hour", "hours") to 3600 * s,
            listOf("d", "day", "days") to 86_400 * s,
            listOf("w", "week", "weeks") to 604_800 * s,
            listOf("mo", "month", "months") to 2_592_000 * s,
        )
        for ((names, ms) in groups) for (n in names) {
            assertEquals(n, ms, Facade.parseLimit("1/$n").periodMs)
            assertEquals(n, ms, Facade.parseLimit("1/${n.uppercase()}").periodMs)
        }
        for (bad in listOf("fortnight", "y", "ms", "years", "constructor", "toString", "secs", "dayss"))
            assertEquals("parseLimit: unknown period '$bad' in '5/$bad'", refusal { Facade.parseLimit("5/$bad") })
    }

    @Test fun aMalformedLimitIsRefusedWithTheReferenceText() {
        for (e in listOf<Any?>(null, "", "   ", "\u00A0\uFEFF", 5L, Json.Num("5"), listOf("5"), Issue.obj()))
            assertEquals("parseLimit: empty limit", refusal { Facade.parseLimit(e) })
        for (bad in listOf("abc", " abc ", "5.", ".5", "-5", "5/", "5/day/x", "5/3", "\$\$5", "5 day", "5/da y", "1e3", "\u0661", "5/d\u00E9")) {
            assertEquals("parseLimit: cannot parse limit '$bad'", refusal { Facade.parseLimit(bad) })
        }
        val longest = "1".repeat(64)
        assertEquals("1".repeat(64).length, Facade.MAX_LIMIT_LENGTH)
        assertEquals("count", Facade.parseLimit(longest).unit)
        assertEquals("parseLimit: limit is longer than 64 characters", refusal { Facade.parseLimit("1".repeat(65)) })
        assertEquals("parseLimit: limit is longer than 64 characters", refusal { Facade.parseLimit(" " + "1".repeat(64)) })
    }

    // ---- the catalog fallback ------------------------------------------------------------------------------------------------

    @Test fun aCataloguedVerbIsUsedAsIs() {
        val s = Catalog.DEFAULT.get("stripe.refund")!!
        assertSame(s, Facade.specFor(Catalog.DEFAULT, "stripe.refund"))
        assertSame(s, Facade.specFor(Catalog.DEFAULT, "stripe.issue_refund"))
    }

    @Test fun anUncataloguedVerbIsIrreversibleAndWide() {
        val a = Facade.specFor(Catalog.DEFAULT, "stripe.unknown")
        assertEquals(listOf("stripe", "unknown", "stripe.unknown", "irreversible", "(uncatalogued) stripe.unknown"),
            listOf(a.connector, a.action, a.verb, a.reversibility, a.description))
        assertEquals(0.8, a.blastRadius, 0.0)
        assertNull(a.amountField)
        assertTrue(a.aliases.isEmpty())
        assertTrue(a.traits.isEmpty())
        val b = Facade.specFor(Catalog.DEFAULT, "foo")
        assertEquals(listOf("foo", "foo", "foo", "irreversible", "(uncatalogued) foo"), listOf(b.connector, b.action, b.verb, b.reversibility, b.description))
        val c = Facade.specFor(Catalog.DEFAULT, "a.b.c")
        assertEquals(listOf("a", "b.c", "a.b.c"), listOf(c.connector, c.action, c.verb))
        val d = Facade.specFor(Catalog.DEFAULT, "a.")
        assertEquals(listOf("a", "a.", "a."), listOf(d.connector, d.action, d.verb))
        val e = Facade.specFor(Catalog.DEFAULT, ".x")
        assertEquals(listOf("", "x", ".x"), listOf(e.connector, e.action, e.verb))
        val f = Facade.specFor(Catalog.DEFAULT, "")
        assertEquals(listOf("", "", ""), listOf(f.connector, f.action, f.verb))
    }

    @Test fun anAliasLookupNeedsAConnectorBeforeTheDot() {
        val cat = Catalog(listOf(Catalog.Spec("", "y", ".y", "reversible", 0.1, null, "d", listOf("x"))))
        val s = Facade.specFor(cat, ".x")
        assertEquals("(uncatalogued) .x", s.description)
        val cat2 = Catalog(listOf(Catalog.Spec("c", "y", "c.y", "reversible", 0.1, null, "d", listOf("x"))))
        assertEquals("c.y", Facade.specFor(cat2, "c.x").verb)
        assertEquals("(uncatalogued) c.z", Facade.specFor(cat2, "c.z").description)
    }

    // ---- policy compilation --------------------------------------------------------------------------------------------------

    private fun compile(permissions: Map<String, Any?>, limits: Map<String, Any?>? = null, catalog: Catalog? = null, budgetModel: String? = null,
                        riskPolicy: Map<String, Any?>? = null, at: Long = 1_000_000L) =
        Facade.compilePolicy(permissions, limits, catalog, budgetModel, riskPolicy, at)

    private val defaultPolicy = canon(Issue.defaultRiskPolicy())

    @Test fun aPermissionWithoutLimitsIsOnePredicateAndTheReversibilityCeiling() {
        val p = compile(perms("github" to listOf("read")))
        assertEquals("[{\"resource\":\"*\",\"verb\":\"github.read\"}]", canon(p.predicates))
        assertEquals("[{\"class\":\"reversible\",\"type\":\"reversibility_max\"}]", canon(p.caveats))
        assertEquals("risk", p.budgetModel)
        assertEquals(defaultPolicy, canon(p.riskPolicy))
        assertTrue(p.limits.isEmpty())
        assertTrue(p.approximations.isEmpty())
        assertTrue(p.inputLimits.isEmpty())
        assertEquals(1, p.actions.size)
        assertSame(Catalog.DEFAULT.get("github.read"), p.actions[0])
    }

    @Test fun aDollarLimitBoundsTheAmountAndOpensOneWindow() {
        val limits = Issue.obj("refund" to "\$500/day")
        val p = compile(perms("stripe" to listOf("refund", "charge")), limits)
        val where = "[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":500},{\"field\":\"action.params.amount\",\"op\":\"gte\",\"value\":0}]"
        assertEquals("[{\"resource\":\"*\",\"verb\":\"stripe.refund\",\"where\":$where},{\"resource\":\"*\",\"verb\":\"stripe.charge\"}]", canon(p.predicates))
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"},{\"at\":87400000,\"type\":\"expires\"}]", canon(p.caveats))
        assertEquals("dollars", p.budgetModel)
        assertEquals("{\"stripe.refund\":{\"amount\":500,\"periodMs\":86400000,\"unit\":\"usd\"}}", canon(p.limits.mapValues { it.value.toJson() }))
        assertEquals(listOf("stripe.refund: \$500/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"), p.approximations)
        assertEquals(canon(limits), canon(p.inputLimits))
        assertEquals(listOf("stripe.refund", "stripe.charge"), p.actions.map { it.verb })
        val rp = Issue.obj("weights" to Issue.obj("alpha" to 0L, "beta" to 0L, "gamma" to 1L, "delta" to 0L, "epsilon" to 0L, "zeta" to 0L),
            "theta1" to Json.Num("0.25"), "theta2" to Json.Num("0.6"), "kappa" to 500L, "lambda" to 0L, "rho" to Json.Num("0.5"), "bMax" to 500L)
        assertEquals(canon(rp), canon(p.riskPolicy))
    }

    @Test fun theLimitOfAnActionIsFoundByVerbThenActionThenAliasInOrder() {
        fun amount(limits: Map<String, Any?>): Long? {
            val p = compile(perms("stripe" to listOf("refund")), limits)
            return p.limits["stripe.refund"]?.amount?.toLong()
        }
        assertEquals(7L, amount(Issue.obj("stripe.refund" to "\$7", "refund" to "\$5")))
        assertEquals(5L, amount(Issue.obj("refund" to "\$5", "issue_refund" to "\$9")))
        assertEquals(5L, amount(Issue.obj("issue_refund" to "\$5", "reimburse" to "\$9")))
        assertEquals(9L, amount(Issue.obj("reimburse" to "\$9")))
        assertEquals(4L, amount(Issue.obj("refund_charge" to "\$4")))
        assertNull(amount(Issue.obj("charge" to "\$9")))
        assertNull(amount(Issue.obj()))
    }

    @Test fun countLimitsAddOneRateCaveatEachAndTheShortestWindowExpiresTheGrant() {
        val p = compile(perms("slack" to listOf("post_message"), "github" to listOf("comment", "read")),
            Issue.obj("post_message" to "10/hour", "github.comment" to "3/min", "read" to "2/sec"), at = 5_000L)
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"},{\"at\":6000,\"type\":\"expires\"}," +
            "{\"max\":10,\"per_secs\":3600,\"type\":\"rate\"},{\"max\":3,\"per_secs\":60,\"type\":\"rate\"},{\"max\":2,\"per_secs\":1,\"type\":\"rate\"}]", canon(p.caveats))
        assertEquals("risk", p.budgetModel)
        assertTrue(p.approximations.isEmpty())
        assertEquals(defaultPolicy, canon(p.riskPolicy))
        // a count limit without a window adds no rate caveat and no expiry
        val q = compile(perms("github" to listOf("comment")), Issue.obj("comment" to "5"))
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"}]", canon(q.caveats))
    }

    @Test fun anAmountLimitNeedsAnAmountFieldAndACountLimitDoesNot() {
        assertEquals("compilePolicy: '\$' limit on 'github.read' but the catalog gives that verb no amount field, so the limit could not be enforced",
            refusal { compile(perms("github" to listOf("read")), Issue.obj("read" to "\$5")) })
        val q = compile(perms("github" to listOf("read")), Issue.obj("read" to "5/day"))
        assertEquals(1, q.limits.size)
        assertEquals("count", q.limits["github.read"]!!.unit)
    }

    @Test fun aLimitThatIsNotAStringIsRefused() {
        assertEquals("parseLimit: empty limit", refusal { compile(perms("stripe" to listOf("refund")), Issue.obj("refund" to 5L)) })
    }

    @Test fun permissionsMustBeNonEmptyArrays() {
        assertEquals("compilePolicy: permissions.stripe must be an array", refusal { compile(Issue.obj("stripe" to "refund")) })
        assertEquals("compilePolicy: permissions.stripe must be an array", refusal { compile(Issue.obj("stripe" to null)) })
        assertEquals("compilePolicy: no permissions granted", refusal { compile(Issue.obj()) })
        assertEquals("compilePolicy: no permissions granted", refusal { compile(Issue.obj("stripe" to ArrayList<Any?>())) })
        val ok = compile(Issue.obj("stripe" to ArrayList<Any?>(), "github" to listOf("read")))
        assertEquals(listOf("github.read"), ok.actions.map { it.verb })
    }

    @Test fun nothingIrreversibleLetsAWithinCapActionAutoApprove() {
        val cat = Catalog(listOf(Catalog.Spec("bank", "transfer", "bank.transfer", "reversible", 0.3, "amt", "t")))
        val p = compile(perms("bank" to listOf("transfer")), Issue.obj("transfer" to "\$100"), cat)
        assertEquals("[{\"resource\":\"*\",\"verb\":\"bank.transfer\",\"where\":[{\"field\":\"action.params.amt\",\"op\":\"lte\",\"value\":100}," +
            "{\"field\":\"action.params.amt\",\"op\":\"gte\",\"value\":0}]}]", canon(p.predicates))
        assertEquals("[{\"class\":\"reversible\",\"type\":\"reversibility_max\"}]", canon(p.caveats))
        assertEquals("dollars", p.budgetModel)
        assertEquals("{\"bank.transfer\":{\"amount\":100,\"unit\":\"usd\"}}", canon(p.limits.mapValues { it.value.toJson() }))
        assertTrue(p.approximations.isEmpty())
        val rp = Issue.obj("weights" to Issue.obj("alpha" to 0L, "beta" to 0L, "gamma" to 1L, "delta" to 0L, "epsilon" to 0L, "zeta" to 0L),
            "theta1" to 1L, "theta2" to 1L, "kappa" to 100L, "lambda" to 0L, "rho" to Json.Num("0.5"), "bMax" to 100L)
        assertEquals(canon(rp), canon(p.riskPolicy))
        assertEquals(1, p.actions.size)
        assertSame(cat.get("bank.transfer"), p.actions[0])
    }

    @Test fun theLargestLimitIsTheCapAndTheSumIsTheBudget() {
        val p = compile(perms("stripe" to listOf("refund", "payout", "charge")), Issue.obj("refund" to "\$100", "payout" to "\$250.5", "charge" to "\$20"))
        val rp = m(p.riskPolicy)
        assertEquals("250.5", canon(rp["kappa"]))
        assertEquals("370.5", canon(rp["bMax"]))
        // a cap below one is kept as it is
        val half = compile(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$0.5"))
        assertEquals("0.5", canon(m(half.riskPolicy)["kappa"]))
        assertEquals("0.5", canon(m(half.riskPolicy)["bMax"]))
        // a zero limit cannot be the cap: the policy keeps a unit cap and budget
        val z = compile(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$0"))
        assertEquals("1", canon(m(z.riskPolicy)["kappa"]))
        assertEquals("1", canon(m(z.riskPolicy)["bMax"]))
        assertEquals("dollars", z.budgetModel)
        val two = compile(perms("stripe" to listOf("refund", "payout")), Issue.obj("refund" to "\$100", "payout" to "\$60"))
        assertEquals("100", canon(m(two.riskPolicy)["kappa"]))
        assertEquals("160", canon(m(two.riskPolicy)["bMax"]))
        val rev = compile(perms("stripe" to listOf("refund", "payout")), Issue.obj("refund" to "\$60", "payout" to "\$100"))
        assertEquals("100", canon(m(rev.riskPolicy)["kappa"]))
        assertEquals("160", canon(m(rev.riskPolicy)["bMax"]))
    }

    @Test fun theBudgetModelIsChosenFromTheLimitsUnlessForced() {
        val usd = Issue.obj("refund" to "\$5")
        val stripe = perms("stripe" to listOf("refund"))
        assertEquals("dollars", compile(stripe, usd).budgetModel)
        assertEquals("dollars", compile(stripe, usd, budgetModel = "other").budgetModel)
        assertEquals("dollars", compile(stripe, usd, budgetModel = "auto").budgetModel)
        assertEquals("risk", compile(stripe, usd, budgetModel = "risk").budgetModel)
        assertEquals(defaultPolicy, canon(compile(stripe, usd, budgetModel = "risk").riskPolicy))
        assertEquals("risk", compile(stripe).budgetModel)
        assertEquals("risk", compile(stripe, null, budgetModel = "auto").budgetModel)
        // forced dollars with no dollar limit: the label, but the default policy
        val forced = compile(stripe, null, budgetModel = "dollars")
        assertEquals("dollars", forced.budgetModel)
        assertEquals(defaultPolicy, canon(forced.riskPolicy))
        val count = compile(stripe, Issue.obj("refund" to "5/day"), budgetModel = "dollars")
        assertEquals("dollars", count.budgetModel)
        assertEquals(defaultPolicy, canon(count.riskPolicy))
        assertEquals("risk", compile(stripe, Issue.obj("refund" to "5/day")).budgetModel)
    }

    @Test fun aRiskPolicyOverrideIsMergedOverTheDerivedOne() {
        val stripe = perms("stripe" to listOf("refund"))
        val p = compile(stripe, Issue.obj("refund" to "\$100"), riskPolicy = Issue.obj("rho" to Json.Num("0.9"), "weights" to Issue.obj("alpha" to Json.Num("0.5"))))
        val rp = m(p.riskPolicy)
        assertEquals("0.9", canon(rp["rho"]))
        assertEquals("100", canon(rp["kappa"]))
        assertEquals("100", canon(rp["bMax"]))
        assertEquals("{\"alpha\":0.5,\"beta\":0,\"delta\":0,\"epsilon\":0,\"gamma\":1,\"zeta\":0}", canon(rp["weights"]))
        val q = compile(perms("github" to listOf("read")), riskPolicy = Issue.obj("theta1" to Json.Num("0.1"), "weights" to 5L))
        assertEquals("0.1", canon(m(q.riskPolicy)["theta1"]))
        assertEquals(canon(Issue.defaultRiskPolicy()["weights"]), canon(m(q.riskPolicy)["weights"]))
        val none = compile(perms("github" to listOf("read")), riskPolicy = Issue.obj())
        assertEquals(defaultPolicy, canon(none.riskPolicy))
        val bad = refusal { compile(perms("github" to listOf("read")), riskPolicy = Issue.obj("kappa" to "x")) }
        assertTrue(bad, bad.startsWith("compilePolicy: derived risk policy invalid: "))
        assertTrue(bad.length > "compilePolicy: derived risk policy invalid: ".length)
    }

    @Test fun theCompiledPolicySerialisesWithTheReferencesMemberNames() {
        val p = compile(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$5/day"))
        val j = p.toJson()
        assertEquals(listOf("predicates", "caveats", "riskPolicy", "budgetModel", "limits", "approximations"), j.keys.toList())
        assertEquals(canon(p.predicates), canon(j["predicates"]))
        assertEquals(canon(p.caveats), canon(j["caveats"]))
        assertEquals(canon(p.riskPolicy), canon(j["riskPolicy"]))
        assertEquals("dollars", j["budgetModel"])
        assertEquals(1, l(j["approximations"]).size)
        assertEquals("{\"stripe.refund\":{\"amount\":5,\"periodMs\":86400000,\"unit\":\"usd\"}}", canon(j["limits"]))
    }

    // ---- options -------------------------------------------------------------------------------------------------------------

    @Test fun theOptionsKeepEveryMemberTheyAreGiven() {
        val rec = ArgProvenance.Recorder("m1", "k9")
        val cat = Catalog(emptyList())
        val permissions = perms("stripe" to listOf("refund"))
        val limits = Issue.obj("refund" to "\$5")
        val binding = Issue.obj("operator" to "acme")
        val risk = Issue.obj("rho" to Json.Num("0.9"))
        val o = Facade.AgentOptions(principal, "the goal", permissions, limits, agentS, binding, risk, "risk", cat, "aud-1", 77L, "salt-1", rec)
        assertSame(principal, o.principal)
        assertEquals("the goal", o.goal)
        assertSame(permissions, o.permissions)
        assertSame(limits, o.limits)
        assertSame(agentS, o.holder)
        assertSame(binding, o.agentBinding)
        assertSame(risk, o.riskPolicy)
        assertEquals("risk", o.budgetModel)
        assertSame(cat, o.catalog)
        assertEquals("aud-1", o.aud)
        assertEquals(77L, o.now)
        assertEquals("salt-1", o.goalSalt)
        assertSame(rec, o.provenance)
        val d = Facade.AgentOptions(principal, "g", permissions)
        assertNull(d.limits)
        assertNull(d.holder)
        assertNull(d.agentBinding)
        assertNull(d.riskPolicy)
        assertNull(d.budgetModel)
        assertNull(d.catalog)
        assertNull(d.aud)
        assertNull(d.now)
        assertNull(d.goalSalt)
        assertNull(d.provenance)
    }

    @Test fun thePerCallOptionsKeepEveryMemberTheyAreGiven() {
        val c = Json.Num("0.5")
        val o = Facade.ActOptions(3L, 5L, 7L, "a", "n", c, 0.25)
        assertEquals(3L, o.counter)
        assertEquals(5L, o.now)
        assertEquals(7L, o.ttlMs)
        assertEquals("a", o.aud)
        assertEquals("n", o.nonce)
        assertSame(c, o.caution)
        assertEquals(0.25, o.risk!!, 0.0)
        val d = Facade.ActOptions()
        assertNull(d.counter)
        assertNull(d.now)
        assertNull(d.ttlMs)
        assertNull(d.aud)
        assertNull(d.nonce)
        assertNull(d.caution)
        assertNull(d.risk)
    }

    // ---- the agent handle ----------------------------------------------------------------------------------------------------

    @Test fun aHandleExposesTheGrantTheChainAndTheKeys() {
        val rec = ArgProvenance.Recorder("m1", "k9")
        val binding = Issue.obj("operator" to "acme")
        val h = Facade.agent(Facade.AgentOptions(principal, "goal", perms("github" to listOf("read")), null, agentS, binding, null, null, null, "rs", now, "salt-1", rec))
        assertEquals(1, h.chain.size)
        assertSame(h.grant, h.chain[0])
        assertEquals("salt-1", h.goalSalt)
        assertSame(agentS, h.holder)
        assertEquals(principal.ed!!.id(), h.principalPublic)
        assertSame(rec, h.provenance)
        assertEquals(agentEd.id(), h.grant["holder"])
        assertEquals(principal.ed!!.id(), h.grant["issuer"])
        val env = m(l(h.grant["caveats"])[0])
        assertEquals(canon(binding), canon(env["agent_binding"]))
        assertEquals(canon(Issue.obj("mediators" to listOf(rec.pin))), canon(env["provenance"]))
        assertEquals(Issue.goalCommit("goal", "salt-1"), env["goal_commit"])
        assertEquals(canon(h.policy.predicates), canon(env["predicates"]))
        assertEquals(canon(h.policy.caveats), canon(env["caveats"]))
        assertEquals(canon(h.policy.riskPolicy), canon(env["risk_policy"]))
        assertEquals(Json.canonicalize(h.grant), h.encodeGrant())
    }

    @Test fun aHandleBuiltWithDefaultsGeneratesItsKeySaltAndRecorder() {
        val h = Facade.agent(Facade.AgentOptions(principal, "goal", perms("github" to listOf("read"))))
        assertEquals("ed25519", h.holder.alg)
        assertNotNull(h.holder.ed)
        assertEquals(h.holder.ed!!.id(), h.grant["holder"])
        assertEquals(22, h.goalSalt.length)
        assertEquals("agent-harness", h.provenance.pin["mediator"])
        assertEquals("k1", h.provenance.pin["kid"])
        assertTrue(Json.asLong(h.budget()["tau"]) > 1_600_000_000_000L)
        val other = Facade.agent(Facade.AgentOptions(principal, "goal", perms("github" to listOf("read"))))
        assertNotEquals(h.goalSalt, other.goalSalt)
        assertNotEquals(h.holder.ed!!.id(), other.holder.ed!!.id())
        val env = m(l(h.grant["caveats"])[0])
        assertEquals("{}", canon(env["agent_binding"]))
    }

    @Test fun aHandleNeedsAnEd25519HolderAndPrincipal() {
        val pq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 7 })
        val purePq = Keys.suite("ml-dsa-65", null, pq)
        assertEquals("agent: the holder needs an Ed25519 identity",
            refusal { Facade.agent(Facade.AgentOptions(principal, "g", perms("github" to listOf("read")), holder = purePq)) })
        assertEquals("agent: the principal needs an Ed25519 identity",
            refusal { Facade.agent(Facade.AgentOptions(purePq, "g", perms("github" to listOf("read")), holder = agentS)) })
    }

    @Test fun aHandleUsesTheCatalogItWasGiven() {
        val cat = Catalog(listOf(Catalog.Spec("bank", "transfer", "bank.transfer", "reversible", 0.3, "amt", "t")))
        val h = handle(perms("bank" to listOf("transfer")), Issue.obj("transfer" to "\$100"), catalog = cat)
        assertEquals(listOf("bank.transfer"), h.policy.actions.map { it.verb })
        val r = h.act("bank.transfer", "acct:1", Issue.obj("amt" to 50L))
        assertEquals("reversible", m(r.pcactn["action"])["reversibility_class"])
        assertTrue(r.dryRun.allowed)
    }

    @Test fun theStartingBudgetAndTheAutonomyBoundFollowThePolicy() {
        val h = handle(perms("stripe" to listOf("refund", "payout")), Issue.obj("refund" to "\$200", "payout" to "\$200"))
        assertEquals("{\"B\":400,\"asOf\":$now,\"tau\":$now}", canon(h.budget()))
        assertEquals(400.0, h.autonomyBound(), 0.0)
        val risk = handle(perms("github" to listOf("read")))
        assertEquals("{\"B\":1,\"asOf\":$now,\"tau\":$now}", canon(risk.budget()))
        assertEquals(1.0, risk.autonomyBound(), 0.0)
        val frac = handle(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$12.5"))
        assertEquals("12.5", canon(frac.budget()["B"]))
        assertEquals(12.5, frac.autonomyBound(), 0.0)
        val small = handle(perms("github" to listOf("read")), riskPolicy = Issue.obj("bMax" to Json.Num("0.4")))
        assertEquals("0.4", canon(small.budget()["B"]))
        assertEquals(0.4, small.autonomyBound(), 1e-12)
    }

    // ---- the advisory pre-check ----------------------------------------------------------------------------------------------

    @Test fun aDryRunSaysWhichTierAdmissionWouldAssign() {
        val h = handle(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$500"))
        val low = h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 100L), now)
        assertTrue(low.allowed)
        assertNull(low.reason)
        assertEquals(1, low.t)
        val mid = h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 300L), now)
        assertTrue(mid.allowed)
        assertEquals(2, mid.t)
        val high = h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 400L), now)
        assertTrue(high.allowed)
        assertEquals(3, high.t)
        // exactly at the first threshold (125 / 500 = 0.25) is still the machine-only tier
        assertEquals(1, h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 125L), now).t)
        assertEquals(2, h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 126L), now).t)
        assertEquals(2, h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 300L), now).t)
        assertEquals(3, h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 301L), now).t)
    }

    @Test fun aDryRunEscalatesWhenTheBudgetDoesNotCoverTheCost() {
        val h = handle(perms("slack" to listOf("post_message")), riskPolicy = Issue.obj("bMax" to Json.Num("0.4")))
        // blast radius 0.5: tier 2 on the default policy, cost 0.5 > the 0.4 budget: a human co-sign
        assertEquals(3, h.dryRun("slack.post_message", "chan:1", null, now).t)
        val ok = handle(perms("slack" to listOf("post_message")))
        assertEquals(2, ok.dryRun("slack.post_message", "chan:1", null, now).t)
        val equalBudget = handle(perms("slack" to listOf("post_message")), riskPolicy = Issue.obj("bMax" to Json.Num("0.5")))
        assertEquals(2, equalBudget.dryRun("slack.post_message", "chan:1", null, now).t)
    }

    @Test fun aDryRunRefusesWhatNoPredicatePermits() {
        val h = handle(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$500"))
        val r = h.dryRun("stripe.charge", "charge:1", Issue.obj("amount" to 5L), now)
        assertFalse(r.allowed)
        assertEquals("no predicate permits stripe.charge on charge:1", r.reason)
        assertNull(r.t)
        val over = h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 501L), now)
        assertFalse(over.allowed)
        assertEquals("no predicate permits stripe.refund on charge:1", over.reason)
        assertNull(over.t)
        val negative = h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to -1L), now)
        assertFalse(negative.allowed)
        assertTrue(h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 500L), now).allowed)
        assertTrue(h.dryRun("stripe.refund", "charge:1", Issue.obj("amount" to 0L), now).allowed)
    }

    @Test fun aDryRunNamesEveryFailedCaveatInOrder() {
        val h = handle(perms("github" to listOf("comment")), Issue.obj("comment" to "0/hour"))
        val within = h.dryRun("github.comment", "pr:1", null, now + 1000)
        assertFalse(within.allowed)
        assertEquals("caveat(s) failed: rate", within.reason)
        assertNull(within.t)
        val late = h.dryRun("github.comment", "pr:1", null, now + 3_600_000L + 1)
        assertFalse(late.allowed)
        assertEquals("caveat(s) failed: expires, rate", late.reason)
        // the grant lifetime ends at the window: valid one millisecond before, expired at the instant
        val h2 = handle(perms("github" to listOf("comment")), Issue.obj("comment" to "5/hour"))
        assertTrue(h2.dryRun("github.comment", "pr:1", null, now + 3_600_000L - 1).allowed)
        assertEquals("caveat(s) failed: expires", h2.dryRun("github.comment", "pr:1", null, now + 3_600_000L).reason)
        // a rate limit with room is satisfied: there is no admitted-action history locally
        assertTrue(h2.dryRun("github.comment", "pr:1", null, now).allowed)
    }

    @Test fun aDryRunWithoutAClockUsesTheCurrentTime() {
        val old = handle(perms("github" to listOf("comment")), Issue.obj("comment" to "5/day"), at = 1_000L)
        val r = old.dryRun("github.comment", "pr:1")
        assertFalse(r.allowed)
        assertEquals("caveat(s) failed: expires", r.reason)
        val fresh = handle(perms("github" to listOf("comment")), Issue.obj("comment" to "5/day"), at = System.currentTimeMillis())
        assertTrue(fresh.dryRun("github.comment", "pr:1").allowed)
        assertTrue(fresh.dryRun("github.comment", "pr:1", null, null).allowed)
    }

    // ---- the risk claim ------------------------------------------------------------------------------------------------------

    private fun claim(h: Facade.Handle, params: Map<String, Any?>?, o: Facade.ActOptions = Facade.ActOptions(now = now)): String {
        val r = h.act("stripe.refund", "charge:1", params, o)
        return canon(r.pcactn["risk_claim"])
    }

    private fun claimOf(r: Double): String =
        "{\"inputs\":{\"blastRadius\":${canon(Facade.jn(r))}},\"r\":${canon(Facade.jn(r))}}"

    @Test fun theRiskOfADollarActionIsItsShareOfTheCap() {
        val h = handle(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$500"))
        assertEquals(claimOf(0.2), claim(h, Issue.obj("amount" to 100L)))
        assertEquals(claimOf(0.2), claim(h, Issue.obj("amount" to "100")))
        assertEquals(claimOf(0.2), claim(h, Issue.obj("amount" to " 100 ")))
        assertEquals(claimOf(0.2), claim(h, Issue.obj("amount" to "1e2")))
        assertEquals(claimOf(0.2), claim(h, Issue.obj("amount" to Json.Num("100"))))
        assertEquals(claimOf(0.025), claim(h, Issue.obj("amount" to Json.Num("12.5"))))
        assertEquals(claimOf(0.002), claim(h, Issue.obj("amount" to true)))
        assertEquals(claimOf(0.0), claim(h, Issue.obj("amount" to false)))
        assertEquals(claimOf(0.0), claim(h, Issue.obj("amount" to null)))
        assertEquals(claimOf(0.0), claim(h, Issue.obj("amount" to "")))
        assertEquals(claimOf(0.0), claim(h, Issue.obj("amount" to "  ")))
        assertEquals(claimOf(0.0), claim(h, Issue.obj("amount" to 0L)))
        assertEquals(claimOf(0.0), claim(h, Issue.obj("amount" to -50L)))
        assertEquals(claimOf(1.0), claim(h, Issue.obj("amount" to 500L)))
        assertEquals(claimOf(1.0), claim(h, Issue.obj("amount" to 5000L)))
    }

    @Test fun anAmountThatIsNotANumberFallsBackToTheBlastRadius() {
        val h = handle(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$500"))
        val blast = claimOf(0.9)
        assertEquals(blast, claim(h, null))
        assertEquals(blast, claim(h, Issue.obj()))
        assertEquals(blast, claim(h, Issue.obj("other" to 1L)))
        assertEquals(blast, claim(h, Issue.obj("amount" to "abc")))
        assertEquals(blast, claim(h, Issue.obj("amount" to "NaN")))
        assertEquals(blast, claim(h, Issue.obj("amount" to "Infinity")))
        assertEquals(blast, claim(h, Issue.obj("amount" to listOf(1L))))
        assertEquals(blast, claim(h, Issue.obj("amount" to Issue.obj())))
    }

    @Test fun aCapBelowOneStillScalesTheAmount() {
        val h = handle(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$0.5"))
        assertEquals(claimOf(0.5), claim(h, Issue.obj("amount" to Json.Num("0.25"))))
        assertEquals(claimOf(1.0), claim(h, Issue.obj("amount" to Json.Num("0.5"))))
    }

    @Test fun theBlastRadiusOfAnActionIsClampedToZeroAndOne() {
        val cat = Catalog(listOf(Catalog.Spec("c", "wide", "c.wide", "reversible", 5.0, null, "d"), Catalog.Spec("c", "neg", "c.neg", "reversible", -0.5, null, "d")))
        val h = handle(perms("c" to listOf("wide", "neg")), catalog = cat)
        assertEquals(claimOf(1.0), canon(h.act("c.wide", "r", null, Facade.ActOptions(now = now)).pcactn["risk_claim"]))
        assertEquals(claimOf(0.0), canon(h.act("c.neg", "r", null, Facade.ActOptions(now = now)).pcactn["risk_claim"]))
        assertEquals(3, h.dryRun("c.wide", "r", null, now).t)
        assertEquals(1, h.dryRun("c.neg", "r", null, now).t)
    }

    @Test fun aRiskModelIgnoresTheAmountAndAnActionWithoutAnAmountFieldUsesItsBlastRadius() {
        val risk = handle(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$500"), budgetModel = "risk")
        assertEquals(claimOf(0.9), claim(risk, Issue.obj("amount" to 100L)))
        val h = handle(perms("github" to listOf("read")))
        val r = h.act("github.read", "repo:1", null, Facade.ActOptions(now = now))
        assertEquals(claimOf(0.05), canon(r.pcactn["risk_claim"]))
        val dollars = handle(perms("stripe" to listOf("refund"), "gmail" to listOf("draft")), Issue.obj("refund" to "\$500"))
        val d = dollars.act("gmail.draft", "mail:1", Issue.obj("amount" to 400L), Facade.ActOptions(now = now))
        assertEquals(claimOf(0.2), canon(d.pcactn["risk_claim"]))
    }

    @Test fun aClaimedRiskOverridesTheDerivedOneWithinZeroAndOne() {
        val h = handle(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$500"))
        val params = Issue.obj("amount" to 100L)
        assertEquals(claimOf(0.7), claim(h, params, Facade.ActOptions(now = now, risk = 0.7)))
        assertEquals(claimOf(1.0), claim(h, params, Facade.ActOptions(now = now, risk = 5.0)))
        assertEquals(claimOf(0.0), claim(h, params, Facade.ActOptions(now = now, risk = -1.0)))
        assertEquals(claimOf(0.0), claim(h, params, Facade.ActOptions(now = now, risk = 0.0)))
        assertEquals(claimOf(0.2), claim(h, params, Facade.ActOptions(now = now, risk = null)))
    }

    // ---- acting --------------------------------------------------------------------------------------------------------------

    @Test fun anActionIsAOneNodePlanTheRiskClaimAndTheNextCounter() {
        val h = handle(perms("stripe" to listOf("refund")), Issue.obj("refund" to "\$500"))
        val params = Issue.obj("amount" to 100L)
        val r = h.act("stripe.refund", "charge:1", params, Facade.ActOptions(now = now))
        val p = r.pcactn
        assertEquals(1L, p["counter"])
        assertEquals("rs", p["aud"])
        assertEquals(now, p["iat"])
        assertEquals(now + Issue.DEFAULT_TTL_MS, p["exp"])
        assertEquals("n0", m(p["plan"])["node_id"])
        val a = m(p["action"])
        assertEquals("stripe.refund", a["verb"])
        assertEquals("charge:1", a["resource"])
        assertEquals("irreversible", a["reversibility_class"])
        assertEquals(Pca.paramsDigest(params), a["params_digest"])
        assertFalse(p.containsKey("nonce"))
        assertFalse(p.containsKey("caution"))
        assertEquals(h.grant["id"], p["grant_ref"])
        assertEquals(r.encoded, Issue.encode(p))
        assertEquals(setOf("PCA-Action", ArgProvenance.HEADER), r.headers.keys)
        assertEquals(Issue.header(p), r.headers["PCA-Action"])
        assertEquals(Json.canonicalizeStrict(r.provenance), String(Pca.decodeB64uStrict(r.headers[ArgProvenance.HEADER], -1)!!, Charsets.UTF_8))
        assertTrue(r.dryRun.allowed)
        assertTrue(Pca.verifyPcactn(p, h.grant, now + 1000, Pca.Audience.Of("rs"), insecureSkipPlanRootCheck = true).allow)
    }

    @Test fun theCounterAdvancesAndNeverGoesBack() {
        val h = handle(perms("github" to listOf("read")))
        fun c(o: Facade.ActOptions = Facade.ActOptions(now = now)) = Json.asLong(h.act("github.read", "r", null, o).pcactn["counter"])
        assertEquals(1L, c())
        assertEquals(2L, c())
        assertEquals(10L, c(Facade.ActOptions(counter = 10L, now = now)))
        assertEquals(11L, c())
        assertEquals(3L, c(Facade.ActOptions(counter = 3L, now = now)))
        assertEquals(12L, c())
        assertEquals(0L, c(Facade.ActOptions(counter = 0L, now = now)))
        assertEquals(13L, c())
    }

    @Test fun anActionCarriesTheCallersNonceCautionLifetimeAndAudience() {
        val h = handle(perms("github" to listOf("read")))
        val caution = Json.Num("0.5")
        val p = h.act("github.read", "r", null, Facade.ActOptions(counter = null, now = 1234L, ttlMs = 5000L, aud = "other", nonce = "nonce-1", caution = caution)).pcactn
        assertEquals("other", p["aud"])
        assertEquals("nonce-1", p["nonce"])
        assertEquals("0.5", canon(p["caution"]))
        assertEquals(1234L, p["iat"])
        assertEquals(6234L, p["exp"])
        val d = h.act("github.read", "r", null, Facade.ActOptions(now = 1234L)).pcactn
        assertEquals("rs", d["aud"])
        assertEquals(1234L + Issue.DEFAULT_TTL_MS, d["exp"])
        val t = System.currentTimeMillis()
        val u = h.act("github.read", "r", null).pcactn
        assertTrue(Json.asLong(u["iat"]) >= t)
        assertTrue(Json.asLong(u["iat"]) < t + 60_000L)
    }

    @Test fun anActionNeedsAnAudience() {
        val text = "act: aud (resource-server / instance id) is required (pass opts.aud or AgentOptions.aud)"
        val none = handle(perms("github" to listOf("read")), aud = null)
        assertEquals(text, refusal { none.act("github.read", "r") })
        assertEquals(text, refusal { none.act("github.read", "r", null, Facade.ActOptions(aud = "")) })
        assertEquals("given", none.act("github.read", "r", null, Facade.ActOptions(aud = "given")).pcactn["aud"])
        val empty = handle(perms("github" to listOf("read")), aud = "")
        assertEquals(text, refusal { empty.act("github.read", "r") })
        assertEquals("x", empty.act("github.read", "r", null, Facade.ActOptions(aud = "x")).pcactn["aud"])
    }

    @Test fun anActionRecordsItselfWithTheProvenanceRecorder() {
        val h = handle(perms("github" to listOf("read")))
        val r = h.act("github.read", "repo:1", Issue.obj("x" to 1L), Facade.ActOptions(now = now))
        assertEquals(Json.canonicalizeStrict(r.provenance), String(Pca.decodeB64uStrict(r.headers[ArgProvenance.HEADER], -1)!!, Charsets.UTF_8))
        assertTrue(r.provenance.isNotEmpty())
    }

    // ---- sub-agents ----------------------------------------------------------------------------------------------------------

    @Test fun aSubAgentIsOneMoreHopSignedByTheParentKey() {
        val h = handle(perms("github" to listOf("read")))
        val childEd = Keys.edFromSeed(ByteArray(32) { 2 })
        val child = Keys.ed25519(childEd)
        val added = listOf<Any?>(Issue.obj("type" to "expires", "at" to 5L))
        val s = h.subAgent(child, added)
        assertEquals(2, s.chain.size)
        assertSame(h.chain[0], s.chain[0])
        val hop = m(s.chain[1])
        assertEquals(childEd.id(), hop["holder"])
        assertEquals(agentEd.id(), hop["issuer"])
        val cav = l(hop["caveats"])
        assertEquals(l(m(s.chain[0])["caveats"]).size + 1, cav.size)
        assertEquals("{\"at\":5,\"type\":\"expires\"}", canon(cav.last()))
        assertSame(h.grant, s.grant)
        assertEquals(h.goalSalt, s.goalSalt)
        assertSame(h.policy, s.policy)
        assertEquals(h.principalPublic, s.principalPublic)
        assertSame(h.provenance, s.provenance)
        assertSame(child, s.holder)
        // the parent is unchanged
        assertEquals(1, h.chain.size)
        // the sub-agent counts on its own and acts under the same audience
        val a = s.act("github.read", "r", null, Facade.ActOptions(now = now))
        assertEquals(1L, a.pcactn["counter"])
        assertEquals("rs", a.pcactn["aud"])
        assertEquals(2, l(a.pcactn["cap_chain"]).size)
        assertEquals(1L, h.act("github.read", "r", null, Facade.ActOptions(now = now)).pcactn["counter"])
    }

    @Test fun aSubAgentWithoutAKeyGetsAFreshEd25519One() {
        val h = handle(perms("github" to listOf("read")))
        val s = h.subAgent()
        assertEquals("ed25519", s.holder.alg)
        assertNull(s.holder.pq)
        assertNotEquals(h.holder.ed!!.id(), s.holder.ed!!.id())
        assertEquals(s.holder.ed!!.id(), m(s.chain[1])["holder"])
        assertFalse(m(s.chain[1]).containsKey("holder_pq"))
        assertEquals(l(m(h.chain[0])["caveats"]).size, l(m(s.chain[1])["caveats"]).size)
        assertNotEquals(s.holder.ed!!.id(), h.subAgent().holder.ed!!.id())
    }

    @Test fun aPostQuantumParentGetsAFreshKeyOfTheSameSuiteForItsSubAgent() {
        val pq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 7 })
        val me = Keys.suite("hybrid-ed25519-ml-dsa-65", agentEd, pq)
        val h = Facade.agent(Facade.AgentOptions(principal, "goal", perms("github" to listOf("read")), holder = me, aud = "rs", now = now, goalSalt = "s"))
        assertEquals(Pca.holderPqCommitment(pq.pkB64u()), h.grant["holder_pq"])
        val s = h.subAgent()
        assertEquals("hybrid-ed25519-ml-dsa-65", s.holder.alg)
        assertNotNull(s.holder.pq)
        assertNotEquals(pq.pkB64u(), s.holder.pq!!.pkB64u())
        assertNotEquals(agentEd.id(), s.holder.ed!!.id())
        assertEquals(Pca.holderPqCommitment(s.holder.pq!!.pkB64u()), m(s.chain[1])["holder_pq"])
        assertEquals("hybrid-ed25519-ml-dsa-65", m(s.chain[1])["alg"])
        assertEquals(pq.pkB64u(), m(s.chain[1])["pq_pk"])
    }

    @Test fun aSubAgentNeedsAnEd25519Identity() {
        val h = handle(perms("github" to listOf("read")))
        val purePq = Keys.suite("ml-dsa-65", null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ByteArray(32) { 7 }))
        assertEquals("subAgent: the sub-agent needs an Ed25519 identity", refusal { h.subAgent(purePq) })
    }
}
