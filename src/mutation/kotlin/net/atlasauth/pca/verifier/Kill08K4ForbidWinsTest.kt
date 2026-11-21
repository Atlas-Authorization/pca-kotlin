package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.K08K4.act
import net.atlasauth.pca.verifier.K08K4.canon
import net.atlasauth.pca.verifier.K08K4.l
import net.atlasauth.pca.verifier.K08K4.m
import net.atlasauth.pca.verifier.K08K4.num
import net.atlasauth.pca.verifier.K08K4.q
import net.atlasauth.pca.verifier.K08K4.withKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for ForbidWins (k4): validateCondition / validateWhen (mutation-kill-prohibitions.test.ts), whenMatches,
 * the clause list rules and the decision / certificate (forbid-certificate.test.ts and its vectors). Reasons are the reference's.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K4ForbidWinsTest {
    private fun vc(json: String, depth: Int = 0): String? = ForbidWins.validateCondition(q(json), depth)
    private fun vw(json: String, label: String = "L"): String? = ForbidWins.validateWhen(q(json), label)
    private fun cond(f: String = "a", op: String = "eq", extra: String = ""): String = "{'field':'$f','op':'$op'$extra}"
    private fun nestNot(n: Int): String {
        var c = cond()
        for (i in 0 until n) c = "{'not':$c}"
        return c
    }
    private fun nestAll(n: Int): String {
        var c = cond()
        for (i in 0 until n) c = "{'all_of':[$c]}"
        return c
    }
    private fun wm(json: String, ctx: Map<String, Any?>?): Boolean = ForbidWins.whenMatches(q(json), ctx)

    // ---- Options

    @Test fun optionsKeepEveryField() {
        val cl: (Authorize.Operation, Map<String, Any?>?) -> List<Any?> = { _, _ -> emptyList() }
        val cx: (Authorize.Operation) -> Map<String, Any?>? = { null }
        val o = ForbidWins.Options(cl, cx, listOf("a"), listOf("b"), true)
        assertSame(cl, o.clauses)
        assertSame(cx, o.context)
        assertEquals(listOf("a"), o.precedence)
        assertEquals(listOf("b"), o.permitSigners)
        assertTrue(o.requireCertificate)
        val d = ForbidWins.Options(cl)
        assertNull(d.context)
        assertNull(d.precedence)
        assertNull(d.permitSigners)
        assertFalse(d.requireCertificate)
        assertEquals(1, ForbidWins.CERT_VERSION)
        assertEquals("forbid-wins", ForbidWins.CERT_KIND)
        assertEquals(512, ForbidWins.MAX_CLAUSES)
    }

    // ---- validateCondition

    @Test fun conditionLeaf() {
        assertNull(vc("{'field':'a','op':'eq','value':1}"))
        for (op in listOf("eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of")) assertNull(op, vc(cond(op = op)))
        for (body in listOf("{'op':'eq'}", "{'field':'','op':'eq'}", "{'field':5,'op':'eq'}", "{'field':null,'op':'eq'}", "{'field':{},'op':'eq'}")) {
            assertEquals(body, "condition.field missing", vc(body))
        }
        assertEquals("unknown condition op zz", vc(cond(op = "zz")))
        assertEquals("unknown condition op undefined", vc("{'field':'a'}"))
        assertEquals("unknown condition op 5", vc("{'field':'a','op':5}"))
        assertEquals("unknown condition op null", vc("{'field':'a','op':null}"))
        assertEquals("unknown condition op EQ", vc(cond(op = "EQ")))
        assertEquals("unknown condition op toString", vc(cond(op = "toString")))
        assertNull(vc(cond(extra = ",'ref':'b'")))
        for (r in listOf("''", "5", "null", "{}")) assertEquals(r, "bad condition.ref", vc(cond(extra = ",'ref':$r")))
        assertNull(vc(cond(op = "member_of", extra = ",'collection':'c'")))
        for (col in listOf("''", "5", "null", "{}")) assertEquals(col, "bad condition.collection", vc(cond(op = "member_of", extra = ",'collection':$col")))
        assertNull(vc(cond(extra = ",'collection':5")))
        assertEquals("condition.field missing", vc("{'field':'','op':'zz','ref':''}"))
        assertEquals("unknown condition op zz", vc("{'field':'a','op':'zz','ref':''}"))
        assertEquals("bad condition.ref", vc("{'field':'a','op':'member_of','ref':'','collection':5}"))
    }

    @Test fun conditionNotObject() {
        for (bad in listOf<Any?>(null, "x", num(5.0), ArrayList<Any?>())) assertEquals("condition not an object", ForbidWins.validateCondition(bad, 0))
        assertEquals("condition not an object", vc("{'not':5}"))
        // the object check comes before the depth check
        assertEquals("condition not an object", ForbidWins.validateCondition(num(5.0), 99))
    }

    @Test fun conditionGroups() {
        val leaf = cond()
        assertNull(vc("{'all_of':[$leaf,$leaf]}"))
        assertNull(vc("{'any_of':[$leaf]}"))
        assertNull(vc("{'not':$leaf}"))
        assertEquals("condition.all_of must be a non-empty array", vc("{'all_of':[]}"))
        assertEquals("condition.any_of must be a non-empty array", vc("{'any_of':[]}"))
        assertEquals("condition.all_of must be a non-empty array", vc("{'all_of':'x'}"))
        assertEquals("condition.any_of must be a non-empty array", vc("{'any_of':{}}"))
        assertEquals("condition.all_of must be a non-empty array", vc("{'all_of':null}"))
        assertEquals("condition.field missing", vc("{'not':{'field':'','op':'eq'}}"))
        assertEquals("condition not an object", vc("{'all_of':[$leaf,{'not':5}]}"))
        assertEquals("condition.all_of must be a non-empty array", vc("{'any_of':[$leaf,{'all_of':[]}]}"))
        // several group keys: not wins, then all_of, then any_of
        assertNull(vc("{'not':$leaf,'all_of':[]}"))
        assertNull(vc("{'all_of':[$leaf],'any_of':[]}"))
        assertEquals("condition.all_of must be a non-empty array", vc("{'all_of':[],'any_of':[$leaf]}"))
        assertNull(vc("{'any_of':[$leaf],'field':''}"))
    }

    @Test fun conditionNestingDepth() {
        assertNull(vc(nestNot(32)))
        assertEquals("condition nesting too deep", vc(nestNot(33)))
        assertNull(vc(nestAll(32)))
        assertEquals("condition nesting too deep", vc(nestAll(33)))
        assertEquals("condition nesting too deep", vc(nestAll(40)))
        // the child of a group sits one level deeper than the group
        assertNull(vc(cond(), 32))
        assertEquals("condition nesting too deep", vc(cond(), 33))
        assertEquals("condition nesting too deep", vc("{'not':${cond()}}", 32))
        assertEquals("condition nesting too deep", vc("{'all_of':[${cond()}]}", 32))
        assertEquals("condition nesting too deep", vc("{'any_of':[${cond()}]}", 32))
        assertNull(vc("{'not':${cond()}}", 31))
    }

    // ---- validateWhen

    @Test fun whenShapeVerbResourceAndWhere() {
        for (bad in listOf<Any?>(null, "x", num(5.0), ArrayList<Any?>())) assertEquals("L: not an object", ForbidWins.validateWhen(bad, "L"))
        assertNull(vw("{'verb':'x'}"))
        assertNull(vw("{'verb':['x','y']}"))
        for (v in listOf("''", "[]", "['']", "['x','']", "[5]", "['x',5]", "null", "5", "{}")) assertEquals(v, "L: bad verb", vw("{'verb':$v}"))
        assertEquals("L: bad verb", vw("{}"))
        assertEquals("other: bad verb", vw("{'verb':''}", "other"))
        assertNull(vw("{'verb':'x','resource':'/a'}"))
        assertNull(vw("{'verb':'x','resource':''}"))
        for (r in listOf("5", "null", "[]", "{}")) assertEquals(r, "L: bad resource", vw("{'verb':'x','resource':$r}"))
        assertNull(vw("{'verb':'x','where':[]}"))
        for (wh in listOf("{}", "'x'", "5", "null")) assertEquals(wh, "L: where not an array", vw("{'verb':'x','where':$wh}"))
        assertEquals("L: condition not an object", vw("{'verb':'x','where':[5]}"))
        assertEquals("L: condition.field missing", vw("{'verb':'x','where':[${cond()},${cond("")}]}"))
        assertNull(vw("{'verb':'x','where':[${cond()}]}", "other"))
        assertEquals("W: condition nesting too deep", vw("{'verb':'x','where':[${nestNot(33)}]}", "W"))
        assertNull(vw("{'verb':'x','where':[${nestNot(32)}]}", "W"))
    }

    @Test fun whenRegexResources() {
        assertNull(vw("{'verb':'x','resource':'re:/a/[a-z]+'}", "P"))
        assertNull(vw("{'verb':'x','resource':'re:${"a".repeat(200)}'}", "P"))
        assertEquals("P: unsafe regex resource", vw("{'verb':'x','resource':'re:${"a".repeat(201)}'}", "P"))
        assertEquals("P: unsafe regex resource", vw("{'verb':'x','resource':'re:(a+)+'}", "P"))
        assertEquals("P: unsafe regex resource", vw("{'verb':'x','resource':'re:\\\\1'}", "P"))
        assertEquals("P: unsafe regex resource", vw("{'verb':'x','resource':'re:('}", "P"))
        assertEquals("P: unsafe regex resource", vw("{'verb':'x','resource':'re:a{'}", "P"))
        // only the exact "re:" prefix selects regex handling
        assertNull(vw("{'verb':'x','resource':'Re:('}", "P"))
        assertNull(vw("{'verb':'x','resource':'xre:('}", "P"))
        assertNull(vw("{'verb':'x','resource':'re('}", "P"))
    }

    @Test fun anUncompilableRegexThatPassedTheSafetyCheckIsInvalid() {
        // seam: isSafeSource already implies compile != null, so the guard is only reachable with the safety check stubbed
        assertEquals("P: invalid regex resource", ForbidWins.validateWhen(q("{'verb':'x','resource':'re:('}"), "P") { true })
        assertNull(ForbidWins.validateWhen(q("{'verb':'x','resource':'re:a+'}"), "P") { true })
        assertEquals("P: unsafe regex resource", ForbidWins.validateWhen(q("{'verb':'x','resource':'re:a'}"), "P") { false })
    }

    // ---- whenMatches

    @Test fun whenMatchesVerbAndResourceDecideFirst() {
        assertTrue(wm("{'verb':'a'}", act("a")))
        assertFalse(wm("{'verb':'a'}", act("b")))
        assertTrue(wm("{'verb':['a','b']}", act("b")))
        assertTrue(wm("{'verb':'*'}", act("zzz")))
        assertTrue(wm("{'verb':'a','resource':'/r'}", act("a", "/r")))
        assertFalse(wm("{'verb':'a','resource':'/x'}", act("a", "/r")))
        assertTrue(wm("{'verb':'a','resource':'/r*'}", act("a", "/rzz")))
        assertTrue(wm("{'verb':'a','resource':'re:/[a-z]'}", act("a", "/q")))
        assertFalse(wm("{'verb':'a','resource':'re:/[a-z]'}", act("a", "/Q")))
        assertFalse(wm(amb("a"), act("b", "/r", "{}")))
    }

    private fun amb(v: String): String = "{'verb':'$v','where':[{'field':'action.params.x','op':'eq','value':1}]}"

    @Test fun whenMatchesWhereIsConservative() {
        assertTrue(wm(amb("a"), act("a", "/r", "{'x':1}")))
        assertFalse(wm(amb("a"), act("a", "/r", "{'x':2}")))
        assertTrue(wm(amb("a"), act("a", "/r", "{}")))
        assertTrue(wm(amb("a"), act("a")))
        val two = "{'verb':'a','where':[{'field':'action.params.x','op':'eq','value':1},{'field':'action.params.y','op':'eq','value':1}]}"
        assertFalse(wm(two, act("a", "/r", "{'x':1,'y':2}")))
        assertFalse(wm(two, act("a", "/r", "{'x':2,'y':1}")))
        assertTrue(wm(two, act("a", "/r", "{'x':1,'y':1}")))
        assertTrue(wm(two, act("a", "/r", "{'x':1}")))
        val grp = "{'verb':'a','where':[{'not':{'field':'action.params.x','op':'eq','value':1}}]}"
        assertFalse(wm(grp, act("a", "/r", "{'x':1}")))
        assertTrue(wm(grp, act("a", "/r", "{'x':2}")))
        assertTrue(wm(grp, act("a", "/r", "{}")))
        assertTrue(wm("{'verb':'a','where':[]}", act("a")))
    }

    @Test fun aMalformedTriggerOrActionIsMatched() {
        for (w in listOf("null", "5", "{}", "{'verb':''}", "{'verb':'a','resource':5}", "{'verb':'a','where':'x'}", "{'verb':'a','where':[{'field':'','op':'eq'}]}", "{'verb':'a','resource':'re:(a+)+'}")) {
            assertTrue(w, wm(w, act("zzz")))
        }
        val ctxs = listOf<Map<String, Any?>?>(
            null, m(q("{}")), m(q("{'action':null}")), m(q("{'action':{'verb':5,'resource':'/r'}}")), m(q("{'action':{'verb':'a','resource':5}}")), m(q("{'action':{'verb':'a'}}")),
            m(q("{'action':{'resource':'/r'}}")),
        )
        for (c in ctxs) assertTrue(c.toString(), wm("{'verb':'a'}", c))
    }

    @Test fun anOversizedSubjectOfARegexResourceCannotBeEvaluatedSoTheVetoApplies() {
        val w = "{'verb':'a','resource':'re:b'}"
        assertFalse(wm(w, act("a", "a".repeat(512))))
        assertTrue(wm(w, act("a", "a".repeat(513))))
        assertFalse(wm(w, act("z", "a".repeat(513))))
        assertFalse(wm("{'verb':'a','resource':'b'}", act("a", "a".repeat(513))))
        assertFalse(wm("{'verb':'a','resource':'b*'}", act("a", "a".repeat(513))))
        assertTrue(wm("{'verb':'a'}", act("a", "a".repeat(513))))
        val wh = "{'verb':'a','resource':'re:b','where':[{'field':'action.params.x','op':'eq','value':1}]}"
        assertFalse(wm(wh, act("a", "a".repeat(513), "{'x':2}")))
        assertTrue(wm(wh, act("a", "a".repeat(513), "{'x':1}")))
    }

    @Test fun aRegexRefusedByTheDocumentBudgetIsNotACleanNo() {
        val w = "{'verb':'a','resource':'re:b'}"
        val a = act("a", "/zzz")
        assertFalse(wm(w, a))
        val wh = "{'verb':'a','resource':'re:b','where':[{'field':'action.params.x','op':'eq','value':1}]}"
        val r = SafeRegex.withBudget {
            for (i in 0 until 64) SafeRegex.charge("a", 1)
            listOf(wm(w, a), wm(wh, act("a", "/zzz", "{'x':2}")), wm(wh, act("a", "/zzz", "{'x':1}")))
        }
        assertEquals(listOf(true, false, true), r)
    }

    @Test fun whenMatchesNeverThrowsButNeverSwallowsAFatalError() {
        val hostile = K08K4.Probe(m(q("{'verb':'a'}")), "verb", 0) { K08K4.boom() }
        assertTrue(ForbidWins.whenMatches(hostile, act("a")))
        assertFalse(Prohibitions.whenAffirmative(hostile, act("a")))
        val fatal = K08K4.Probe(m(q("{'verb':'a'}")), "verb", 0) { K08K4.fatal() }
        assertThrows(InternalError::class.java) { ForbidWins.whenMatches(fatal, act("a")) }
    }

    // ---- clausesError

    private fun ce(json: String): String? = ForbidWins.clausesError(q(json))
    private fun one(extra: String = ""): String = "{'id':'a','kind':'permit','when':{}$extra}"

    @Test fun clausesErrorNamesTheFirstProblem() {
        assertEquals("clauses must be an array", ce("'x'"))
        assertEquals("clauses must be an array", ce("{}"))
        assertEquals("clauses[0] must be an object", ce("[null]"))
        assertEquals("clauses[1] must be an object", ce("[${one()},5]"))
        assertEquals("clauses[0].id must be a string of 1..128 characters", ce("[{'id':'','kind':'permit','when':{}}]"))
        assertEquals("clauses[0].id must be a string of 1..128 characters", ce("[{'id':5,'kind':'permit','when':{}}]"))
        assertEquals("clauses[0].id must be a string of 1..128 characters", ce("[{'kind':'permit','when':{}}]"))
        assertEquals("clauses[0].kind must be permit, forbid or escalate", ce("[{'id':'a','kind':'allow','when':{}}]"))
        assertEquals("clauses[0].kind must be permit, forbid or escalate", ce("[{'id':'a','kind':5,'when':{}}]"))
        assertEquals("clauses[0].kind must be permit, forbid or escalate", ce("[{'id':'a','when':{}}]"))
        assertEquals("clauses[0].signer must be a string of at most 256 characters", ce("[${one(",'signer':5")}]"))
        assertEquals("clauses[0].signer must be a string of at most 256 characters", ce("[${one(",'signer':null")}]"))
        assertEquals("clauses[0].when must be a predicate object", ce("[{'id':'a','kind':'permit','when':5}]"))
        assertEquals("clauses[0].when must be a predicate object", ce("[{'id':'a','kind':'permit'}]"))
        assertNull(ce("[${one()},{'id':'b','kind':'forbid','signer':'s','when':{}},{'id':'c','kind':'escalate','when':{}}]"))
        assertNull(ce("[]"))
    }

    @Test fun clausesErrorBoundaries() {
        fun mk(n: Int): String = (0 until n).joinToString(",", "[", "]") { "{'id':'c$it','kind':'permit','when':{'verb':'v'}}" }
        assertNull(ce(mk(512)))
        assertEquals("more than 512 clauses", ce(mk(513)))
        assertNull(ce("[{'id':'${"a".repeat(128)}','kind':'permit','when':{}}]"))
        assertEquals("clauses[0].id must be a string of 1..128 characters", ce("[{'id':'${"a".repeat(129)}','kind':'permit','when':{}}]"))
        assertNull(ce("[${one(",'signer':'${"s".repeat(256)}'")}]"))
        assertEquals("clauses[0].signer must be a string of at most 256 characters", ce("[${one(",'signer':'${"s".repeat(257)}'")}]"))
        assertEquals("clauses[1].id 'a' is a duplicate", ce("[${one()},{'id':'a','kind':'forbid','when':{}}]"))
    }

    // ---- decide

    private val CL = "[" +
        "{'id':'p-small','kind':'permit','signer':'user','when':{'verb':'pay.send','where':[{'field':'action.params.amount','op':'lte','value':100}]}}," +
        "{'id':'p-vip','kind':'permit','signer':'user','when':{'verb':'pay.send','resource':'/vip/*'}}," +
        "{'id':'f-blocked','kind':'forbid','signer':'org','when':{'verb':'pay.send','resource':'/blocked/*'}}," +
        "{'id':'f-large','kind':'forbid','signer':'user','when':{'verb':'pay.send','where':[{'field':'action.params.amount','op':'gt','value':5000}]}}," +
        "{'id':'e-review','kind':'escalate','signer':'org','when':{'verb':'pay.send','where':[{'field':'action.params.amount','op':'gt','value':80}]}}]"
    private val clauses: Any? = q(CL)

    private fun values(d: ForbidWins.Decision): List<Any?> = d.values.map { it["value"] }

    private fun assertDecision(
        d: ForbidWins.Decision,
        decision: String,
        kind: String,
        id: String?,
        shadowed: List<String>,
        vals: List<String>,
    ) {
        assertEquals(decision, d.decision)
        assertEquals(kind, d.winnerKind)
        assertEquals(id, d.winnerId)
        assertEquals(shadowed, d.shadowed)
        assertEquals(vals, values(d))
        assertEquals(listOf("p-small", "p-vip", "f-blocked", "f-large", "e-review"), d.values.map { it["id"] })
        assertEquals(listOf("permit", "permit", "forbid", "forbid", "escalate"), d.values.map { it["kind"] })
    }

    @Test fun theDecisionTableOfTheSharedVectors() {
        val pay = "pay.send"
        assertDecision(ForbidWins.decide(clauses, act(pay, "/acct/1", "{'amount':10}")), "allow", "permit", "p-small", emptyList(), listOf("true", "false", "false", "false", "false"))
        assertDecision(ForbidWins.decide(clauses, act(pay, "/acct/1", "{'amount':90}")), "escalate", "escalate", "e-review", listOf("p-small"), listOf("true", "false", "false", "false", "true"))
        assertDecision(ForbidWins.decide(clauses, act(pay, "/vip/1", "{'amount':6000}")), "deny", "forbid", "f-large", listOf("p-vip", "e-review"), listOf("false", "true", "false", "true", "true"))
        val blocked = act(pay, "/blocked/x", "{'amount':6000}")
        val all = listOf("false", "false", "true", "true", "true")
        assertDecision(ForbidWins.decide(clauses, blocked, listOf("org", "user")), "deny", "forbid", "f-blocked", listOf("f-large", "e-review"), all)
        assertDecision(ForbidWins.decide(clauses, blocked, listOf("user", "org")), "deny", "forbid", "f-large", listOf("f-blocked", "e-review"), all)
        assertDecision(ForbidWins.decide(clauses, blocked), "deny", "forbid", "f-blocked", listOf("f-large", "e-review"), all)
        assertDecision(ForbidWins.decide(clauses, act(pay, "/vip/2")), "deny", "forbid", "f-large", listOf("p-vip", "e-review"), listOf("false", "true", "false", "unknown", "unknown"))
        assertDecision(ForbidWins.decide(clauses, act("pay.refund", "/acct/1", "{'amount':1}")), "deny", "none", null, emptyList(), listOf("false", "false", "false", "false", "false"))
        assertDecision(ForbidWins.decide(clauses, act(pay, "/vip/3", "{'amount':10}"), null, listOf("org")), "deny", "none", null, emptyList(), listOf("false", "false", "false", "false", "false"))
        assertDecision(ForbidWins.decide(clauses, act(pay, "/vip/3", "{'amount':10}")), "allow", "permit", "p-small", listOf("p-vip"), listOf("true", "true", "false", "false", "false"))
    }

    @Test fun malformedInputIsADenyWithNothingToName() {
        for (bad in listOf<Any?>(
            "x", q("[{'id':'a','kind':'permit','when':{}},{'id':'a','kind':'permit','when':{}}]"), q("[{'id':'a','kind':'allow','when':{}}]"),
        )) {
            val d = ForbidWins.decide(bad, act("v", "/x"))
            assertEquals("deny", d.decision)
            assertEquals("malformed", d.winnerKind)
            assertNull(d.winnerId)
            assertTrue(d.shadowed.isEmpty())
            assertTrue(d.values.isEmpty())
        }
        val ctxs = listOf<Map<String, Any?>?>(
            null, m(q("{}")), m(q("{'action':{}}")), m(q("{'action':null}")), m(q("{'action':{'verb':5,'resource':'/x'}}")), m(q("{'action':{'verb':'a'}}")),
            m(q("{'action':{'verb':'a','resource':5}}")), m(q("{'action':{'resource':'/x'}}")),
        )
        for (c in ctxs) {
            val d = ForbidWins.decide(clauses, c)
            assertEquals(c.toString(), "malformed", d.winnerKind)
            assertEquals("deny", d.decision)
            assertTrue(d.values.isEmpty())
        }
        val none = ForbidWins.decide(q("[]"), act("v", "/x"))
        assertEquals("deny", none.decision)
        assertEquals("none", none.winnerKind)
        assertNull(none.winnerId)
        assertTrue(none.values.isEmpty())
    }

    @Test fun noPermitMatchedStillNamesTheMatchedEscalate() {
        val cl = q("[{'id':'e','kind':'escalate','when':{'verb':'v'}},{'id':'p','kind':'permit','when':{'verb':'w'}}]")
        val d = ForbidWins.decide(cl, act("v", "/x"))
        assertEquals("deny", d.decision)
        assertEquals("none", d.winnerKind)
        assertNull(d.winnerId)
        assertEquals(listOf("e"), d.shadowed)
        assertEquals(listOf("true", "false"), values(d))
    }

    @Test fun decideFailsClosedAndNeverSwallowsAFatalError() {
        val hostile = K08K4.Probe(act("pay.send", "/x"), "action", 0) { K08K4.boom() }
        val d = ForbidWins.decide(clauses, hostile)
        assertEquals("deny", d.decision)
        assertEquals("malformed", d.winnerKind)
        assertNull(d.winnerId)
        assertTrue(d.shadowed.isEmpty())
        assertTrue(d.values.isEmpty())
        val fatal = K08K4.Probe(act("pay.send", "/x"), "action", 0) { K08K4.fatal() }
        assertThrows(InternalError::class.java) { ForbidWins.decide(clauses, fatal) }
    }

    @Test fun forbidBeatsPermitWhoeverSignedEither() {
        val cl = q("[{'id':'org-forbid','kind':'forbid','signer':'org','when':{'verb':'v','resource':'/secret/*'}},{'id':'user-permit','kind':'permit','signer':'user','when':{'verb':'v'}}]")
        assertEquals("deny", ForbidWins.decide(cl, act("v", "/secret/1"), listOf("user", "org")).decision)
        assertEquals("allow", ForbidWins.decide(cl, act("v", "/open/1")).decision)
    }

    @Test fun anEscalateCapsAllowButNeverLiftsADeny() {
        val cl = q("[{'id':'p','kind':'permit','when':{'verb':'v'}},{'id':'e','kind':'escalate','when':{'verb':'v','resource':'/big/*'}}]")
        assertEquals("escalate", ForbidWins.decide(cl, act("v", "/big/1")).decision)
        assertEquals("allow", ForbidWins.decide(cl, act("v", "/small/1")).decision)
        assertEquals("deny", ForbidWins.decide(cl, act("w", "/big/1")).decision)
    }

    @Test fun theDecisionIsOrderIndependent() {
        val rev = l(clauses).reversed()
        for (c in listOf(act("pay.send", "/vip/1", "{'amount':6000}"), act("pay.send", "/acct/1", "{'amount':90}"), act("pay.send", "/blocked/x", "{'amount':1}"))) {
            assertEquals(ForbidWins.decide(rev, c).decision, ForbidWins.decide(clauses, c).decision)
        }
    }

    private fun f(id: String, signer: String? = null): String = "{'id':'$id','kind':'forbid'" + (if (signer == null) "" else ",'signer':'$signer'") + ",'when':{'verb':'v'}}"
    private fun p(id: String, signer: String? = null): String = "{'id':'$id','kind':'permit'" + (if (signer == null) "" else ",'signer':'$signer'") + ",'when':{'verb':'v'}}"

    @Test fun whichForbidIsNamed() {
        val ctx = act("v", "/x")
        val opts = listOf("org")
        fun win(vararg c: String, prec: List<String>? = null) = ForbidWins.decide(q(c.joinToString(",", "[", "]")), ctx, prec)
        assertEquals("z", win(f("a", "other"), f("z", "org"), prec = opts).winnerId)
        assertEquals("z", win(f("z", "org"), f("a", "other"), prec = opts).winnerId)
        assertEquals("a", win(f("b"), f("a", "other"), prec = opts).winnerId)
        assertEquals("a", win(f("a", "other"), f("b"), prec = opts).winnerId)
        assertEquals("z", win(f("a"), f("z", "org"), prec = opts).winnerId)
        assertEquals("z", win(f("b"), f("z", "org"), prec = opts).winnerId)
        val d = win(f("c"), f("a"), f("b"))
        assertEquals("forbid", d.winnerKind)
        assertEquals("a", d.winnerId)
        assertEquals(listOf("b", "c"), d.shadowed)
        assertEquals(listOf("b", "c"), win(f("b"), f("c"), f("a")).shadowed)
        assertEquals("a", win(f("b"), f("a")).winnerId)
        assertEquals("a", win(f("a"), f("b")).winnerId)
        // a signer that is listed first ranks before one listed second
        assertEquals("y", win(f("x", "two"), f("y", "one"), prec = listOf("one", "two")).winnerId)
        assertEquals("x", win(f("x", "two"), f("y", "one"), prec = listOf("two", "one")).winnerId)
    }

    @Test fun permitSignersDropOtherPermits() {
        val ctx = act("v", "/x")
        fun d(c: String, ps: List<String>?) = ForbidWins.decide(q("[$c]"), ctx, null, ps)
        assertEquals("allow", d(p("a", "org"), listOf("org")).decision)
        assertEquals("deny", d(p("a", "user"), listOf("org")).decision)
        assertEquals("deny", d(p("a"), listOf("org")).decision)
        assertEquals("deny", d(p("a"), emptyList()).decision)
        assertEquals("allow", d(p("a"), null).decision)
        assertEquals(listOf(mapOf("id" to "a", "kind" to "permit", "value" to "false")), d(p("a", "user"), listOf("org")).values)
        // a forbid is never dropped by permitSigners
        assertEquals("deny", ForbidWins.decide(q("[${p("a", "org")},${f("b", "user")}]"), ctx, null, listOf("org")).decision)
    }

    // ---- the certificate

    private fun certOf(c: Any?, ctx: Map<String, Any?>?, prec: List<String>? = null, ps: List<String>? = null) = ForbidWins.certify(c, ctx, prec, ps)

    private fun clone(c: Map<String, Any?>): LinkedHashMap<String, Any?> = LinkedHashMap(m(Json.parseLenient(canon(c))))

    @Test fun certifyShape() {
        val ctx = act("pay.send", "/acct/1", "{'amount':10}")
        val c = certOf(clauses, ctx)
        assertEquals(setOf("v", "kind", "policy", "action", "decision", "winner", "shadowed", "clauses"), c.keys)
        assertEquals(1.0, Prohibitions.dv(c["v"]), 0.0)
        assertEquals("forbid-wins", c["kind"])
        assertEquals(Pca.hashCanonical(clauses), c["policy"])
        assertEquals(Pca.hashCanonical(ctx), c["action"])
        assertEquals("allow", c["decision"])
        assertEquals(mapOf("kind" to "permit", "id" to "p-small"), c["winner"])
        assertEquals(emptyList<Any?>(), c["shadowed"])
        val rows = l(c["clauses"])
        assertEquals(5, rows.size)
        assertEquals(mapOf("id" to "p-small", "kind" to "permit", "signer" to "user", "value" to "true"), rows[0])
        assertEquals(mapOf("id" to "e-review", "kind" to "escalate", "signer" to "org", "value" to "false"), rows[4])
        // a clause with no signer has no signer key in its row
        val bare = q("[${p("a")}]")
        assertEquals(mapOf("id" to "a", "kind" to "permit", "value" to "true"), l(certOf(bare, act("v", "/x"))["clauses"])[0])
        val none = certOf(clauses, act("pay.refund", "/acct/1", "{'amount':1}"))
        val w = m(none["winner"])
        assertEquals(setOf("kind", "id"), w.keys)
        assertEquals("none", w["kind"])
        assertNull(w["id"])
        val mal = certOf(clauses, null)
        assertEquals("deny", mal["decision"])
        assertEquals("malformed", m(mal["winner"])["kind"])
        assertEquals(emptyList<Any?>(), mal["clauses"])
        assertEquals(emptyList<Any?>(), mal["shadowed"])
    }

    @Test fun aGenuineCertificateChecksAndAForgeryDoesNot() {
        val ctx = act("pay.send", "/blocked/x", "{'amount':6000}")
        val prec = listOf("org", "user")
        val cert = certOf(clauses, ctx, prec)
        assertNull(ForbidWins.check(cert, clauses, ctx, prec))
        assertTrue(ForbidWins.consistent(cert, prec))
        assertTrue(ForbidWins.consistent(cert, prec))
        // another action or another policy
        assertEquals("certificate does not match the recomputed decision", ForbidWins.check(cert, clauses, act("pay.send", "/acct/1", "{'amount':1}"), prec))
        assertEquals("certificate does not match the recomputed decision", ForbidWins.check(cert, q(CL.replace("p-vip", "p-vap")), ctx, prec))
        // a table that does not entail its decision
        val forged = clone(cert)
        forged["decision"] = "allow"
        assertEquals("certificate table does not entail its decision", ForbidWins.check(forged, clauses, ctx, prec))
        // the wrong precedence reads the table differently
        assertEquals("certificate table does not entail its decision", ForbidWins.check(cert, clauses, ctx, listOf("user", "org")))
        // self-consistent but not the recomputed decision: the certificate of a smaller payment, checked against a vip one
        val small = certOf(clauses, act("pay.send", "/vip/3", "{'amount':10}"))
        assertTrue(ForbidWins.consistent(small))
        val other = certOf(clauses, act("pay.send", "/acct/1", "{'amount':10}"))
        assertTrue(ForbidWins.consistent(other))
        assertNull(ForbidWins.check(other, clauses, act("pay.send", "/acct/1", "{'amount':10}")))
        assertEquals("certificate does not match the recomputed decision", ForbidWins.check(other, clauses, act("pay.send", "/vip/3", "{'amount':10}")))
        // garbage
        assertEquals("malformed clauses", ForbidWins.check(cert, "x", ctx))
        assertEquals("malformed clauses", ForbidWins.check(cert, q("[{'id':'','kind':'permit','when':{}}]"), ctx))
        assertEquals("certificate table does not entail its decision", ForbidWins.check(q("{}"), clauses, ctx))
        assertFalse(ForbidWins.consistent(null))
        // a malformed-action certificate recomputes to itself
        val mal = certOf(clauses, null)
        assertNull(ForbidWins.check(mal, clauses, null))
    }

    @Test fun eachMalformedHeaderIsInconsistentOnItsOwn() {
        val base = certOf(clauses, act("pay.send", "/acct/1", "{'amount':10}"))
        assertTrue(ForbidWins.consistent(base))
        assertFalse(ForbidWins.consistent(withKey(base, "v", num(2.0))))
        assertFalse(ForbidWins.consistent(withKey(base, "kind", "other")))
        assertFalse(ForbidWins.consistent(withKey(base, "clauses", "x")))
        val c = certOf(clauses, act("pay.send", "/blocked/x", "{'amount':6000}"), listOf("org", "user"))
        assertEquals(2, l(c["shadowed"]).size)
        assertTrue(ForbidWins.consistent(c, listOf("org", "user")))
        assertFalse(ForbidWins.consistent(withKey(c, "shadowed", l(c["shadowed"]).reversed()), listOf("org", "user")))
    }

    @Test fun checkFailsClosedAndNeverSwallowsAFatalError() {
        val ctx = act("pay.send", "/acct/1", "{'amount':10}")
        val cert = certOf(clauses, ctx)
        assertEquals("certificate check error (fail closed)", ForbidWins.check(withKey(cert, "extra", "\uD800"), clauses, ctx))
        val fatal = K08K4.Probe(cert, "v", 0) { K08K4.fatal() }
        assertThrows(InternalError::class.java) { ForbidWins.check(fatal, clauses, ctx) }
    }
}
