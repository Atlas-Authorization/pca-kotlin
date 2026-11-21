package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.K08K4.PRIN
import net.atlasauth.pca.verifier.K08K4.always
import net.atlasauth.pca.verifier.K08K4.amb
import net.atlasauth.pca.verifier.K08K4.arr
import net.atlasauth.pca.verifier.K08K4.act
import net.atlasauth.pca.verifier.K08K4.canon
import net.atlasauth.pca.verifier.K08K4.contract
import net.atlasauth.pca.verifier.K08K4.inv
import net.atlasauth.pca.verifier.K08K4.key
import net.atlasauth.pca.verifier.K08K4.key2
import net.atlasauth.pca.verifier.K08K4.l
import net.atlasauth.pca.verifier.K08K4.m
import net.atlasauth.pca.verifier.K08K4.never
import net.atlasauth.pca.verifier.K08K4.num
import net.atlasauth.pca.verifier.K08K4.q
import net.atlasauth.pca.verifier.K08K4.state0
import net.atlasauth.pca.verifier.K08K4.step
import net.atlasauth.pca.verifier.K08K4.w
import net.atlasauth.pca.verifier.K08K4.withKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for Contracts (k4): a port of packages/pca/src/mutation-kill-contracts.test.ts. Every message, boundary and
 * verdict row is the TypeScript reference's; the monitor, the CAS refusals and the fail-closed catches are pinned exactly.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K4ContractsTest {
    private fun vc(json: String, seen: MutableSet<String> = HashSet<String>(), depth: Int = 1): List<String> = Contracts.validateClause(q(json), seen, depth)
    private fun vk(json: String): List<String> = Contracts.validateContract(q(json))
    private fun head(rest: String = ""): String = "{'version':1,'principal':'$PRIN'$rest}"
    private fun flat(n: Int, pre: String = "c"): String = (0 until n).joinToString(",", "[", "]") { always("$pre$it", "x") }
    private fun many(n: Int): String = (0 until n).joinToString(",", "[", "]") { inv("i$it") }
    private fun andOf(id: String, children: String): String = "{'id':'$id','kind':'and','clauses':$children}"
    private fun nest(n: Int): String {
        var c = always("leaf", "x")
        for (i in 0 until n - 1) c = andOf("and$i", "[$c]")
        return c
    }
    private fun row(id: String, kind: String, result: String, reason: String? = null): Map<String, Any?> =
        if (reason == null) mapOf("id" to id, "kind" to kind, "result" to result) else mapOf("id" to id, "kind" to kind, "result" to result, "reason" to reason)
    private fun verdict(r: Map<String, Any?>, ok: Boolean, violated: List<String>, reasons: List<String>, evaluated: List<Map<String, Any?>>) {
        assertEquals(ok, r["ok"])
        assertEquals(violated, r["violated"])
        assertEquals(reasons, r["reasons"])
        assertEquals(evaluated, r["evaluated"])
    }
    private fun ev(cl: String, a: Map<String, Any?> = act("x"), s: Map<String, Any?> = state0()): Map<String, Any?> = Contracts.evalClause(m(q(cl)), a, s, num(K08K4.NOW))
    private fun rw(id: String, p: String, q: String, within: Int, extra: String = ""): String = "{'id':'$id','kind':'responds_within','p':$p,'q':$q,'within':$within$extra}"
    private fun withDeadlines(json: String): Map<String, Any?> = withKey(state0(), "deadlines", q(json))
    private val DEFAULT_ALWAYS = "always-invariant violated (action does not satisfy p)"
    private val DEFAULT_NEVER = "never-invariant violated (forbidden action)"
    private val DEFAULT_PREC = "precedence violated (prerequisite p not yet admitted before q)"

    // ---- validateClause

    @Test fun validateClauseDepthBoundary() {
        assertEquals(16, Contracts.MAX_CLAUSE_DEPTH)
        assertEquals(256, Contracts.MAX_CLAUSES)
        assertEquals(emptyList<String>(), vc(always("a", "x"), HashSet<String>(), 16))
        assertEquals(listOf("clause nesting too deep"), vc(always("a", "x"), HashSet<String>(), 17))
        assertEquals(listOf("clause nesting too deep"), Contracts.validateClause(null, HashSet<String>(), 17))
        assertEquals(emptyList<String>(), vc(nest(16)))
        assertEquals(listOf("clause nesting too deep"), vc(nest(17)))
    }

    @Test fun validateClauseNonObjectsAndIds() {
        for (bad in listOf<Any?>(null, "x", num(5.0), true, ArrayList<Any?>())) {
            assertEquals(listOf("clause not an object"), Contracts.validateClause(bad, HashSet<String>(), 1))
        }
        for (idPart in listOf("", "'id':'',", "'id':5,", "'id':null,", "'id':['a'],")) {
            assertEquals(idPart, listOf("<no id>: missing clause id"), vc("{${idPart}'kind':'always','p':${w("x")}}"))
        }
        val id128 = "a".repeat(128)
        assertEquals(emptyList<String>(), vc(always(id128, "x")))
        assertEquals(listOf("${id128}a: id too long"), vc(always(id128 + "a", "x")))
        for (f in listOf("__proto__", "constructor", "prototype")) assertEquals(listOf("$f: forbidden id"), vc(always(f, "x")))
        assertEquals(emptyList<String>(), vc(always("protot", "x")))
    }

    @Test fun validateClauseDuplicateIdsAreRecordedOnlyWhenAccepted() {
        val seen = HashSet<String>()
        assertEquals(emptyList<String>(), vc(always("a", "x"), seen))
        assertEquals(setOf("a"), seen)
        assertEquals(listOf("a: duplicate id"), vc(always("a", "y"), seen))
        val seen2 = HashSet<String>()
        vc(always("b".repeat(129), "x"), seen2)
        assertEquals(0, seen2.size)
        val seen3 = hashSetOf("pre")
        assertEquals(listOf("pre: duplicate id"), vc(never("pre", "x"), seen3))
    }

    @Test fun validateClauseAlwaysNeverNeedAValidWhen() {
        for (kind in listOf("always", "never")) {
            assertEquals(emptyList<String>(), vc("{'id':'c','kind':'$kind','p':${w("x")}}"))
            assertEquals(listOf("c: p: not an object"), vc("{'id':'c','kind':'$kind','p':'x'}"))
            assertEquals(listOf("c: p: bad verb"), vc("{'id':'c','kind':'$kind','p':${w("")}}"))
            assertEquals(listOf("c: p: not an object"), vc("{'id':'c','kind':'$kind'}"))
        }
    }

    @Test fun validateClausePrecedesChecksPBeforeQ() {
        for (kind in listOf("precedes", "requires_prior")) {
            fun pq(p: String?, qq: String?): String = "{'id':'c','kind':'$kind'" + (if (p == null) "" else ",'p':$p") + (if (qq == null) "" else ",'q':$qq") + "}"
            assertEquals(emptyList<String>(), vc(pq(w("x"), w("y"))))
            assertEquals(listOf("c: p: not an object"), vc(pq("1", w("y"))))
            assertEquals(listOf("c: q: not an object"), vc(pq(w("x"), "1")))
            assertEquals(listOf("c: p: not an object"), vc(pq("1", "1")))
            assertEquals(listOf("c: q: not an object"), vc(pq(w("x"), null)))
        }
    }

    @Test fun validateClauseRespondsWithin() {
        fun rwc(p: String = w("x"), qq: String = w("y"), within: String? = "3"): String =
            "{'id':'c','kind':'responds_within','p':$p,'q':$qq" + (if (within == null) "" else ",'within':$within") + "}"
        val msg = listOf("c: within must be an integer in [1, MAX_DEADLINE]")
        assertEquals(emptyList<String>(), vc(rwc()))
        assertEquals(listOf("c: p: not an object"), vc(rwc(p = "1")))
        assertEquals(listOf("c: q: not an object"), vc(rwc(qq = "1")))
        assertEquals(listOf("c: p: not an object"), vc(rwc(p = "1", qq = "1", within = "0")))
        assertEquals(listOf("c: q: not an object"), vc(rwc(qq = "1", within = "0")))
        assertEquals(1000000, Prohibitions.MAX_DEADLINE)
        assertEquals(emptyList<String>(), vc(rwc(within = "1")))
        assertEquals(emptyList<String>(), vc(rwc(within = "1000000")))
        for (bad in listOf("0", "-1", "1000001", "1.5", "'3'", "null", null)) assertEquals(bad ?: "absent", msg, vc(rwc(within = bad)))
    }

    @Test fun validateClauseAnd() {
        val seen = HashSet<String>()
        assertEquals(emptyList<String>(), vc(andOf("and", arr(always("a", "x"), never("b", "y"))), seen))
        assertEquals(listOf("a", "and", "b"), seen.sorted())
        val msg = listOf("and: and.clauses must be a non-empty array")
        assertEquals(msg, vc(andOf("and", "[]")))
        assertEquals(msg, vc("{'id':'and','kind':'and'}"))
        assertEquals(msg, vc(andOf("and", "'x'")))
        val bad = andOf("and", arr("{'id':'a','kind':'always','p':1}", "{'id':'b','kind':'never','p':2}", never("and", "x")))
        assertEquals(listOf("a: p: not an object", "b: p: not an object", "and: duplicate id"), vc(bad))
    }

    @Test fun validateClauseUnknownKinds() {
        assertEquals(listOf("c: unknown clause kind eventually"), vc("{'id':'c','kind':'eventually'}"))
        assertEquals(listOf("c: unknown clause kind undefined"), vc("{'id':'c'}"))
        assertEquals(listOf("c: unknown clause kind 5"), vc("{'id':'c','kind':5}"))
    }

    // ---- validateContract

    @Test fun validateContractShapeVersionPrincipal() {
        for (bad in listOf<Any?>(null, "x", num(5.0), ArrayList<Any?>())) assertEquals(listOf("contract not an object"), Contracts.validateContract(bad))
        assertEquals(emptyList<String>(), vk(head()))
        assertEquals(listOf("unsupported version 2"), vk("{'version':2,'principal':'$PRIN'}"))
        assertEquals(listOf("unsupported version undefined"), vk("{'principal':'$PRIN'}"))
        assertEquals(listOf("unsupported version 1"), vk("{'version':'1','principal':'$PRIN'}"))
        assertEquals(listOf("principal missing"), vk("{'version':1}"))
        assertEquals(listOf("principal missing"), vk("{'version':1,'principal':''}"))
        assertEquals(listOf("principal missing"), vk("{'version':1,'principal':5}"))
        assertEquals(listOf("unsupported version 0", "principal missing"), vk("{'version':0,'principal':''}"))
    }

    @Test fun validateContractInvariants() {
        assertEquals(listOf("invariants not an array"), vk(head(",'invariants':'x'")))
        assertEquals(listOf("unsupported version 2", "principal missing", "invariants not an array"), vk("{'version':2,'principal':'','invariants':{}}"))
        assertEquals(emptyList<String>(), vk(head(",'invariants':${many(256)}")))
        assertEquals(listOf("too many invariants"), vk(head(",'invariants':${many(257)}")))
        assertEquals(listOf("a: duplicate id"), vk(head(",'invariants':${arr(inv("a"), inv("a"))}")))
        assertEquals(listOf("a: unknown invariant kind nope"), vk(head(",'invariants':[{'id':'a','kind':'nope'}]")))
        assertEquals(listOf("invariant not an object"), vk(head(",'invariants':[5]")))
        assertEquals(listOf("invariant not an object", "invariant not an object"), vk(head(",'invariants':[5,6]")))
        assertEquals(
            listOf("<no id>: missing id", "<no id>: missing id"),
            vk(head(",'invariants':[{'id':5,'kind':'never','when':${w("x")}},{'id':5,'kind':'never','when':${w("x")}}]")),
        )
        assertEquals(listOf("a: duplicate id"), vk(head(",'invariants':${arr(inv("a"), inv("b"), inv("a"))}")))
    }

    @Test fun validateContractClausesCountAndIds() {
        assertEquals(listOf("clauses not an array"), vk(head(",'clauses':'x'")))
        assertEquals(listOf("unsupported version 3", "clauses not an array"), vk("{'version':3,'principal':'$PRIN','clauses':{}}"))
        assertEquals(emptyList<String>(), vk(head(",'clauses':${flat(256)}")))
        assertEquals(listOf("too many clauses"), vk(head(",'clauses':${flat(257)}")))
        assertEquals(emptyList<String>(), vk(head(",'clauses':[${andOf("A", flat(255))}]")))
        assertEquals(listOf("too many clauses"), vk(head(",'clauses':[${andOf("A", flat(256))}]")))
        assertEquals(emptyList<String>(), vk(head(",'clauses':[${andOf("A", flat(128))},${andOf("B", flat(126, "d"))}]")))
        assertEquals(listOf("x: duplicate id"), vk(head(",'invariants':${arr(inv("x"))},'clauses':${arr(always("x", "y"))}")))
        assertEquals(listOf("x: duplicate id"), vk(head(",'clauses':${arr(always("x", "y"), never("x", "y"))}")))
        assertEquals(listOf("x: duplicate id"), vk(head(",'clauses':${arr(andOf("A", arr(always("x", "y"))), never("x", "y"))}")))
        assertEquals(
            listOf("a: unknown invariant kind zz", "b: unknown clause kind yy"),
            vk(head(",'invariants':[{'id':'a','kind':'zz'}],'clauses':[{'id':'b','kind':'yy'}]")),
        )
    }

    @Test fun validateContractNestingCountIsBounded() {
        // a 17-deep clause is refused by the depth rule only; an 18-deep nest is "too many" at once (the count recursion is bounded)
        assertEquals(listOf("clause nesting too deep"), vk(head(",'clauses':[${nest(17)}]")))
        assertEquals(listOf("too many clauses", "clause nesting too deep"), vk(head(",'clauses':[${nest(18)}]")))
        assertEquals(emptyList<String>(), vk(head(",'clauses':[${nest(16)}]")))
    }

    @Test fun validateContractCountsOnlyAndChildren() {
        val odd = "{'id':'N','kind':'never','p':${w("x")},'clauses':${flat(300)}}"
        assertEquals(emptyList<String>(), vk(head(",'clauses':[$odd]")))
        assertEquals(
            listOf("clause not an object", "a: and.clauses must be a non-empty array"),
            vk(head(",'clauses':[null,{'id':'a','kind':'and','clauses':'x'}]")),
        )
    }

    // ---- id, signature, verification

    private fun base(): Map<String, Any?> = contract(arr(always("a", "read")))

    @Test fun contractIdIsTheCanonicalHashOfTheBody() {
        val c = base()
        assertEquals(Pca.hashCanonical(c), Contracts.contractId(c))
        val sc = Contracts.signContract(c, key.seed)
        assertEquals(Contracts.contractId(c), sc["id"])
        assertEquals(sc["id"], Contracts.contractId(sc))
        assertEquals(Contracts.contractId(c), Contracts.contractId(withKey(withKey(c, "id", "zzz"), "sig", "yyy")))
        assertTrue(Contracts.contractId(withKey(c, "issued_at", num(5.0))) != Contracts.contractId(c))
    }

    @Test fun signContractShapeAndSignatureBytes() {
        val c = base()
        val sc = Contracts.signContract(c, key.seed)
        assertEquals(listOf("clauses", "id", "invariants", "principal", "sig", "version"), sc.keys.sorted())
        assertEquals(PRIN, sc["principal"])
        assertEquals(c["clauses"], sc["clauses"])
        assertEquals("atlas-pca/contract/v1\u0000", Contracts.CONTRACT_SIG_DOMAIN)
        assertEquals(1, Contracts.CONTRACT_VERSION)
        val id = sc["id"] as String
        val msg = Pca.concat(Contracts.CONTRACT_SIG_DOMAIN.toByteArray(Charsets.UTF_8), AttestUtil.sha256(id.toByteArray(Charsets.UTF_8)))
        assertEquals(Pca.b64(key.sign(msg)), sc["sig"])
        assertTrue(IntentJs.verifyEd(PRIN, msg, sc["sig"]))
        val again = Contracts.signContract(withKey(withKey(sc, "id", "stale"), "sig", "stale"), key.seed)
        assertEquals(canon(sc), canon(again))
    }

    @Test fun signContractRefusesAMalformedContractWithEveryProblem() {
        val e = assertThrows(IllegalArgumentException::class.java) { Contracts.signContract(m(q("{'version':9,'principal':''}")), key.seed) }
        assertEquals("signContract: unsupported version 9; principal missing", e.message)
        assertThrows(IllegalArgumentException::class.java) { Contracts.signContract(withKey(base(), "extra", "\uD800"), key.seed) }
    }

    @Test fun verifyContractEveryOutcome() {
        val sc = Contracts.signContract(base(), key.seed)
        val other = key2.id()
        assertNull(Contracts.verifyContract(sc, null))
        assertNull(Contracts.verifyContract(sc, PRIN))
        assertEquals("principal mismatch", Contracts.verifyContract(sc, other))
        assertEquals("unsupported version 7", Contracts.verifyContract(withKey(sc, "version", num(7.0)), null))
        assertEquals("unsupported version 7", Contracts.verifyContract(withKey(sc, "version", num(7.0)), other))
        assertEquals("principal mismatch", Contracts.verifyContract(withKey(sc, "id", "x"), other))
        assertEquals("id does not match content", Contracts.verifyContract(withKey(sc, "id", "x"), null))
        assertEquals("id does not match content", Contracts.verifyContract(withKey(sc, "id", num(5.0)), null))
        assertEquals("id does not match content", Contracts.verifyContract(withKey(sc, "clauses", m(q("{'c':" + arr(always("a", "write")) + "}"))["c"]), null))
        assertEquals("bad signature", Contracts.verifyContract(withKey(sc, "sig", num(5.0)), null))
        val noSig = LinkedHashMap(sc)
        noSig.remove("sig")
        assertEquals("bad signature", Contracts.verifyContract(noSig, null))
        assertEquals("bad signature", Contracts.verifyContract(withKey(sc, "sig", "AAAA"), null))
        val o = Contracts.signContract(base(), key2.seed)
        assertEquals(sc["id"], o["id"])
        assertTrue(o["sig"] != sc["sig"])
    }

    @Test fun theSignatureIsOverTheContractDomain() {
        val c = base()
        val id = Contracts.contractId(c)
        val idb = id.toByteArray(Charsets.UTF_8)
        val dom = Contracts.CONTRACT_SIG_DOMAIN.toByteArray(Charsets.UTF_8)
        fun mk(msg: ByteArray): Map<String, Any?> = withKey(withKey(c, "id", id), "sig", Pca.b64(key.sign(msg)))
        assertNull(Contracts.verifyContract(mk(Pca.concat(dom, AttestUtil.sha256(idb))), null))
        assertEquals("bad signature", Contracts.verifyContract(mk(AttestUtil.sha256(idb)), null))
        assertEquals("bad signature", Contracts.verifyContract(mk(Pca.concat("atlas-pca/constitution/v1\u0000".toByteArray(Charsets.UTF_8), AttestUtil.sha256(idb))), null))
        assertEquals("bad signature", Contracts.verifyContract(mk(Pca.concat(AttestUtil.sha256(idb), dom)), null))
        assertEquals("bad signature", Contracts.verifyContract(mk(Pca.concat(dom, idb)), null))
        val good = mk(Pca.concat(dom, AttestUtil.sha256(idb)))
        assertEquals("bad signature", Contracts.verifyContract(withKey(good, "sig", Pca.b64(key2.sign(Pca.concat(dom, AttestUtil.sha256(idb))))), null))
    }

    @Test fun verifyContractNeverThrowsButNeverSwallowsAFatalError() {
        val sc = Contracts.signContract(base(), key.seed)
        assertEquals("verification error (fail closed)", Contracts.verifyContract(withKey(sc, "extra", "\uD800"), null))
        assertThrows(InternalError::class.java) { Contracts.verifyContract(K08K4.Probe(sc, "id", 0) { K08K4.fatal() }, null) }
    }

    @Test fun embeddedConstitution() {
        val i = m(q(inv("n")))
        val e = Contracts.embeddedConstitution(m(q("{'version':5,'principal':'P','invariants':[${inv("n")}]}")))
        assertEquals(1.0, Prohibitions.dv(e["version"]), 0.0)
        assertEquals("P", e["principal"])
        assertEquals(listOf<Any?>(i), e["invariants"])
        assertEquals(setOf("version", "principal", "invariants"), e.keys)
        assertEquals(emptyList<Any?>(), Contracts.embeddedConstitution(m(q("{'version':1,'principal':'P'}")))["invariants"])
        assertEquals(emptyList<Any?>(), Contracts.embeddedConstitution(m(q("{'version':1,'principal':'P','invariants':'x'}")))["invariants"])
    }

    // ---- checkContract: structural refusals

    @Test fun structuralRefusalsAndTheirOrder() {
        val r = Contracts.checkContract(LinkedHashMap<String, Any?>(), m(q("{'version':5,'principal':''}")), m(q("{'bad':true}")))
        verdict(r, false, listOf("<contract>"), listOf("<contract>: unsupported version 5"), listOf(row("<contract>", "structural", "violated", "unsupported version 5")))
        val c = contract()
        val actions = listOf<Any?>(
            null, q("{}"), q("{'action':null}"), q("{'action':{'verb':1,'resource':'/r'}}"), q("{'action':{'verb':'x'}}"),
            q("{'action':{'verb':'x','resource':5}}"), q("{'action':{'resource':'/r'}}"),
        )
        for (a in actions) {
            verdict(Contracts.checkContract(a, c, state0()), false, listOf("<action>"), listOf("<action>: malformed action"), listOf(row("<action>", "structural", "violated", "malformed action")))
        }
        assertEquals(listOf("<action>"), Contracts.checkContract(q("{}"), c, m(q("{'bad':1}")))["violated"])
        verdict(Contracts.checkContract(act("x"), c, m(q("{'bad':1}"))), false, listOf("<state>"), listOf("<state>: malformed monitor state"), listOf(row("<state>", "structural", "violated", "malformed monitor state")))
        assertEquals(listOf("<state>"), Contracts.checkContract(act("x"), c, null)["violated"])
        assertEquals(listOf("<state>: malformed monitor state: missing chain link"), Contracts.checkContract(act("x"), c, withKey(state0(), "seq", num(1.0)))["reasons"])
        verdict(Contracts.checkContract(act("x"), c, state0()), true, emptyList(), emptyList(), emptyList())
        verdict(Contracts.checkContract(act("x"), m(q(head())), state0()), true, emptyList(), emptyList(), emptyList())
    }

    @Test fun aHostileActionIsAMonitorRefusalAndAFatalErrorEscapes() {
        val hostile = K08K4.Probe(act("x"), "action", 0) { K08K4.boom() }
        verdict(Contracts.checkContract(hostile, contract(), state0()), false, listOf("<monitor>"), listOf("<monitor>: monitor error (fail closed)"), listOf(row("<monitor>", "structural", "violated", "monitor error (fail closed)")))
        val fatal = K08K4.Probe(act("x"), "action", 0) { K08K4.fatal() }
        assertThrows(InternalError::class.java) { Contracts.checkContract(fatal, contract(), state0()) }
    }

    // ---- checkContract: verdict rows

    @Test fun alwaysRows() {
        val c = contract(arr(always("A", "read")))
        verdict(Contracts.checkContract(act("read"), c, state0()), true, emptyList(), emptyList(), listOf(row("A", "always", "pass")))
        verdict(Contracts.checkContract(act("write"), c, state0()), false, listOf("A"), listOf("A: $DEFAULT_ALWAYS"), listOf(row("A", "always", "violated", DEFAULT_ALWAYS)))
        val d = contract(arr(always("A", "read", ",'description':'must read'")))
        assertEquals(listOf("A: must read"), Contracts.checkContract(act("write"), d, state0())["reasons"])
    }

    @Test fun alwaysIsAffirmative() {
        val c = contract(arr("{'id':'A','kind':'always','p':${w("read", ",'where':[{'field':'action.params.amount','op':'lt','value':10}]")}}"))
        assertEquals(true, Contracts.checkContract(act("read", "/r", "{'amount':5}"), c, state0())["ok"])
        assertEquals(false, Contracts.checkContract(act("read", "/r", "{'amount':50}"), c, state0())["ok"])
        assertEquals(false, Contracts.checkContract(act("read", "/r", "{}"), c, state0())["ok"])
        assertEquals(false, Contracts.checkContract(act("read"), c, state0())["ok"])
    }

    @Test fun neverRowsAndVetoPolarity() {
        val c = contract(arr(never("N", "drop")))
        assertEquals(listOf(row("N", "never", "pass")), Contracts.checkContract(act("read"), c, state0())["evaluated"])
        verdict(Contracts.checkContract(act("drop"), c, state0()), false, listOf("N"), listOf("N: $DEFAULT_NEVER"), listOf(row("N", "never", "violated", DEFAULT_NEVER)))
        assertEquals(listOf("N: no drops"), Contracts.checkContract(act("drop"), contract(arr(never("N", "drop", ",'description':'no drops'"))), state0())["reasons"])
        val a = contract(arr("{'id':'N','kind':'never','p':${w("drop", ",'where':[{'field':'action.params.x','op':'eq','value':1}]")}}"))
        assertEquals(true, Contracts.checkContract(act("drop", "/r", "{'x':2}"), a, state0())["ok"])
        assertEquals(false, Contracts.checkContract(act("drop", "/r", "{'x':1}"), a, state0())["ok"])
        assertEquals(false, Contracts.checkContract(act("drop", "/r", "{}"), a, state0())["ok"])
        assertEquals(false, Contracts.checkContract(act("drop"), a, state0())["ok"])
    }

    @Test fun anEmptyDescriptionIsNotAReason() {
        val r = Contracts.checkContract(act("drop"), contract(arr(never("N", "drop", ",'description':''"))), state0())
        assertEquals(listOf(row("N", "never", "violated")), r["evaluated"])
        assertEquals(listOf("N: violated"), r["reasons"])
        val r2 = Contracts.checkContract(act("write"), contract(arr(always("A", "read", ",'description':''"))), state0())
        assertEquals(listOf(row("A", "always", "violated")), r2["evaluated"])
        assertEquals(listOf("A: violated"), r2["reasons"])
    }

    @Test fun precedesAndRequiresPriorHoldQBackUntilPIsAdmitted() {
        for (kind in listOf("precedes", "requires_prior")) {
            val c = contract(arr("{'id':'P','kind':'$kind','p':${w("review")},'q':${w("deploy")}}"))
            assertEquals(listOf(row("P", kind, "pass")), Contracts.checkContract(act("other"), c, state0())["evaluated"])
            verdict(Contracts.checkContract(act("deploy"), c, state0()), false, listOf("P"), listOf("P: $DEFAULT_PREC"), listOf(row("P", kind, "violated", DEFAULT_PREC)))
            val d = contract(arr("{'id':'P','kind':'$kind','p':${w("review")},'q':${w("deploy")},'description':'review first'}"))
            assertEquals(listOf("P: review first"), Contracts.checkContract(act("deploy"), d, state0())["reasons"])
            var s = step(c, state0(), act("review"))
            assertEquals("{\"P\":1700000000000}", canon(s["latched"]))
            verdict(Contracts.checkContract(act("deploy"), c, s), true, emptyList(), emptyList(), listOf(row("P", kind, "pass")))
            s = step(c, s, act("deploy"))
            assertEquals("{\"P\":1700000000000}", canon(s["latched"]))
        }
    }

    @Test fun precedesQIsConservativeAndPIsAffirmative() {
        val c = contract(arr("{'id':'P','kind':'precedes','p':${amb("review")},'q':${amb("deploy")}}"))
        assertEquals(false, Contracts.checkContract(act("deploy", "/r", "{}"), c, state0())["ok"])
        assertEquals(true, Contracts.checkContract(act("deploy", "/r", "{'x':2}"), c, state0())["ok"])
        assertEquals("{}", canon(step(c, state0(), act("review", "/r", "{}"))["latched"]))
        assertEquals("{}", canon(step(c, state0(), act("review", "/r", "{'x':2}"))["latched"]))
        assertEquals("{\"P\":1700000000000}", canon(step(c, state0(), act("review", "/r", "{'x':1}"))["latched"]))
    }

    @Test fun respondsWithinRows() {
        val c = contract(arr(rw("R", w("open"), w("close"), 2)))
        assertEquals(listOf(row("R", "responds_within", "pass")), Contracts.checkContract(act("open"), c, state0())["evaluated"])
        val s2 = step(c, step(c, state0(), act("open")), act("x"))
        val msg = "bounded-liveness deadline missed (no q within 2 actions of p)"
        verdict(Contracts.checkContract(act("y"), c, s2), false, listOf("R"), listOf("R: $msg"), listOf(row("R", "responds_within", "violated", msg)))
        val d = contract(arr(rw("R", w("open"), w("close"), 2, ",'description':'close it'")))
        assertEquals(listOf("R: close it"), Contracts.checkContract(act("y"), d, s2)["reasons"])
    }

    @Test fun andRollsUpItsChildrenOnly() {
        val c = contract(arr(andOf("AND", arr(always("a1", "read"), never("n1", "read"), never("n2", "read", ",'description':'second'")))))
        val r = Contracts.checkContract(act("read"), c, state0())
        assertEquals(listOf("a1:pass", "n1:violated", "n2:violated"), K08K4.rows(r))
        assertEquals(listOf("n1", "n2"), r["violated"])
        assertEquals(false, r["ok"])
        assertEquals(row("a1", "always", "pass"), l(r["evaluated"])[0])
        val ok = Contracts.checkContract(act("read"), contract(arr(andOf("AND", arr(always("a1", "read"), never("n1", "zzz"))))), state0())
        verdict(ok, true, emptyList(), emptyList(), listOf(row("a1", "always", "pass"), row("n1", "never", "pass")))
    }

    @Test fun everyClauseIsEvaluatedInvariantsFirst() {
        val c = contract(arr(always("A", "write"), never("N", "read")), arr(inv("inv1", "read")))
        val r = Contracts.checkContract(act("read"), c, state0())
        assertEquals(listOf("inv1:violated", "A:violated", "N:violated"), K08K4.rows(r))
        assertEquals(listOf("inv1", "A", "N"), r["violated"])
        assertEquals(listOf("inv1: forbidden action", "A: $DEFAULT_ALWAYS", "N: $DEFAULT_NEVER"), r["reasons"])
        assertEquals(listOf("A:pass"), K08K4.rows(Contracts.checkContract(act("read"), contract(arr(always("A", "read"))), state0())))
        assertEquals(listOf("inv1:pass"), K08K4.rows(Contracts.checkContract(act("x"), contract("[]", arr(inv("inv1", "read"))), state0())))
    }

    @Test fun theEmbeddedConstitutionRunsLikeTheProhibitionMonitor() {
        val cap = "{'id':'cap1','kind':'cap','when':${w("spend")},'amount':'action.params.amt','max':10}"
        val c = contract("[]", arr(cap))
        val s1 = step(c, state0(), act("spend", "/r", "{'amt':6}"))
        assertEquals("{\"cap1\":[{\"amount\":6,\"t\":1700000000000}]}", canon(s1["ledger"]))
        val r = Contracts.checkContract(act("spend", "/r", "{'amt':5}"), c, s1)
        assertEquals(listOf("cap1"), r["violated"])
        assertEquals(listOf("cap1: cap exceeded: 6 + 5 > 10"), r["reasons"])
        assertEquals(true, Contracts.checkContract(act("spend", "/r", "{'amt':4}"), c, s1)["ok"])
    }

    // ---- evalClause, directly

    @Test fun evalClauseResultShapes() {
        val keys = setOf("ok", "rows", "latchSet", "deadlineSet")
        val a = ev(always("A", "x"))
        assertEquals(keys, a.keys)
        assertEquals(true, a["ok"])
        assertEquals(listOf(row("A", "always", "pass")), a["rows"])
        assertTrue(m(a["latchSet"]).isEmpty())
        assertTrue(m(a["deadlineSet"]).isEmpty())
        val b = ev(always("A", "y"))
        assertEquals(keys + "reason", b.keys)
        assertEquals(false, b["ok"])
        assertEquals(DEFAULT_ALWAYS, b["reason"])
        assertEquals(listOf(row("A", "always", "violated", DEFAULT_ALWAYS)), b["rows"])
        val n = ev(never("N", "x"))
        assertEquals(keys + "reason", n.keys)
        assertEquals(false, n["ok"])
        assertEquals(DEFAULT_NEVER, n["reason"])
        val n2 = ev(never("N", "y"))
        assertEquals(keys, n2.keys)
        assertEquals(true, n2["ok"])
        assertEquals(listOf(row("N", "never", "pass")), n2["rows"])
        assertEquals("custom", ev(never("N", "x", ",'description':'custom'"))["reason"])
        assertEquals("custom", ev(always("A", "y", ",'description':'custom'"))["reason"])
    }

    @Test fun evalClausePrecedes() {
        val c = "{'id':'P','kind':'precedes','p':${w("review")},'q':${w("deploy")}}"
        val keys = setOf("ok", "rows", "latchSet", "deadlineSet")
        val ok = ev(c, act("other"))
        assertEquals(keys, ok.keys)
        assertEquals(true, ok["ok"])
        assertTrue(m(ok["latchSet"]).isEmpty())
        val bad = ev(c, act("deploy"))
        assertEquals(keys + "reason", bad.keys)
        assertEquals(false, bad["ok"])
        assertEquals(DEFAULT_PREC, bad["reason"])
        val latch = ev(c, act("review"))
        assertEquals(true, latch["ok"])
        assertEquals("{\"P\":1700000000000}", canon(latch["latchSet"]))
        val held = withKey(state0(), "latched", q("{'P':1700000000000}"))
        assertEquals(true, ev(c, act("deploy"), held)["ok"])
        assertTrue(m(ev(c, act("review"), held)["latchSet"]).isEmpty())
        assertTrue(m(ev(c, act("deploy"), held)["latchSet"]).isEmpty())
    }

    @Test fun evalClauseRespondsWithin() {
        val c = rw("R", w("open"), w("close"), 3)
        val keys = setOf("ok", "rows", "latchSet", "deadlineSet")
        val idle = ev(c, act("x"))
        assertEquals(keys, idle.keys)
        assertEquals(true, idle["ok"])
        assertEquals(listOf(row("R", "responds_within", "pass")), idle["rows"])
        assertTrue(m(idle["latchSet"]).isEmpty())
        val ds0 = m(idle["deadlineSet"])
        assertEquals(setOf("R"), ds0.keys)
        assertNull(ds0["R"])
        assertEquals(3.0, Prohibitions.dv(m(ev(c, act("open"))["deadlineSet"])["R"]), 0.0)
        val open3 = withDeadlines("{'R':3}")
        assertEquals(2.0, Prohibitions.dv(m(ev(c, act("x"), open3)["deadlineSet"])["R"]), 0.0)
        assertNull(m(ev(c, act("close"), open3)["deadlineSet"])["R"])
        assertTrue(m(ev(c, act("close"), open3)["deadlineSet"]).containsKey("R"))
        val last = ev(c, act("x"), withDeadlines("{'R':1}"))
        assertEquals(setOf("ok", "reason", "rows", "latchSet", "deadlineSet"), last.keys)
        assertEquals(false, last["ok"])
        val msg = "bounded-liveness deadline missed (no q within 3 actions of p)"
        assertEquals(msg, last["reason"])
        assertEquals(listOf(row("R", "responds_within", "violated", msg)), last["rows"])
        assertTrue(m(last["latchSet"]).isEmpty())
        assertTrue(m(last["deadlineSet"]).isEmpty())
        // the response arrives with the final budget unit: discharge wins
        val done = ev(c, act("close"), withDeadlines("{'R':1}"))
        assertEquals(true, done["ok"])
        assertNull(m(done["deadlineSet"])["R"])
        // the smaller of the carried and the fresh budget survives; equal values keep the carried (canonical) number
        val c5 = rw("R", w("open"), w("close"), 5)
        assertEquals(3.0, Prohibitions.dv(m(ev(c5, act("open"), withDeadlines("{'R':4}"))["deadlineSet"])["R"]), 0.0)
        val c2 = rw("R", w("open"), w("close"), 2)
        assertEquals(1.0, Prohibitions.dv(m(ev(c2, act("open"), withDeadlines("{'R':2}"))["deadlineSet"])["R"]), 0.0)
        // a carried budget larger than the clause's own is replaced by it
        assertEquals(2.0, Prohibitions.dv(m(ev(c2, act("open"), withDeadlines("{'R':9}"))["deadlineSet"])["R"]), 0.0)
        val c2raw = "{'id':'R','kind':'responds_within','p':${w("open")},'q':${w("close")},'within':2.0}"
        assertEquals("2", (m(ev(c2raw, act("open"), withDeadlines("{'R':3}"))["deadlineSet"])["R"] as Json.Num).raw)
    }

    @Test fun evalClauseAnd() {
        val keys = setOf("ok", "rows", "latchSet", "deadlineSet")
        val good = ev(andOf("AND", arr(always("a1", "x"), never("n1", "zzz"))))
        assertEquals(keys, good.keys)
        assertEquals(true, good["ok"])
        assertEquals(listOf(row("a1", "always", "pass"), row("n1", "never", "pass")), good["rows"])
        val bad = ev(andOf("AND", arr(always("a1", "x"), never("n1", "x"), never("n2", "x", ",'description':'second'"))))
        assertEquals(keys + "reason", bad.keys)
        assertEquals(false, bad["ok"])
        assertEquals(DEFAULT_NEVER, bad["reason"])
        assertEquals(3, l(bad["rows"]).size)
        val merged = ev(
            andOf(
                "AND",
                arr(
                    rw("R", w("open"), w("close"), 3),
                    "{'id':'P','kind':'precedes','p':${w("review")},'q':${w("deploy")}}",
                    rw("R2", w("review"), w("close"), 2),
                ),
            ),
            act("review"),
            withDeadlines("{'R':3}"),
        )
        assertEquals(true, merged["ok"])
        assertEquals("{\"P\":1700000000000}", canon(merged["latchSet"]))
        assertEquals("{\"R\":2,\"R2\":2}", canon(merged["deadlineSet"]))
    }

    @Test fun evalClauseFailsClosed() {
        val u = ev("{'id':'x','kind':'bogus'}")
        assertEquals(false, u["ok"])
        assertEquals("unknown clause kind (fail closed)", u["reason"])
        assertEquals(listOf(row("x", "bogus", "violated", "unknown clause kind (fail closed)")), u["rows"])
        assertTrue(m(u["latchSet"]).isEmpty())
        assertTrue(m(u["deadlineSet"]).isEmpty())
        val e = ev("{'id':'x','kind':5}")
        assertEquals(false, e["ok"])
        assertEquals("clause evaluation error (fail closed)", e["reason"])
        assertEquals("clause evaluation error (fail closed)", m(l(e["rows"])[0])["reason"])
        val base = m(q(never("x", "a")))
        val thrown = ev0(K08K4.Probe(base, "p", 0) { K08K4.boom() })
        assertEquals("clause evaluation error (fail closed)", thrown["reason"])
        assertEquals(listOf(row("x", "never", "violated", "clause evaluation error (fail closed)")), thrown["rows"])
        assertThrows(InternalError::class.java) { ev0(K08K4.Probe(base, "p", 0) { K08K4.fatal() }) }
    }

    private fun ev0(cl: Map<String, Any?>): Map<String, Any?> = Contracts.evalClause(cl, act("x"), state0(), num(K08K4.NOW))

    // ---- responds_within deadline arithmetic through advanceContract

    private fun rwc(within: Int, extra: String = ""): Map<String, Any?> = contract(arr(rw("R", w("open"), w("close"), within, extra)))
    private fun dl(s: Map<String, Any?>): String = canon(s["deadlines"])

    @Test fun noStimulusNoObligation() {
        val s = step(rwc(3), state0(), act("x"))
        assertFalse(s.containsKey("deadlines"))
        assertEquals(1.0, Prohibitions.dv(s["seq"]), 0.0)
    }

    @Test fun anObligationBurnsOneBudgetUnitPerAction() {
        val c = rwc(3)
        var s = step(c, state0(), act("open"))
        assertEquals("{\"R\":3}", dl(s))
        s = step(c, s, act("x"))
        assertEquals("{\"R\":2}", dl(s))
        s = step(c, s, act("x"))
        assertEquals("{\"R\":1}", dl(s))
        val r = Contracts.advanceContract(s, act("x"), c)
        assertEquals(false, r["ok"])
        assertEquals(listOf("R"), r["violated"])
        assertEquals("contract", r["decidedBy"])
        assertSame(s, r["next"])
    }

    @Test fun withinOneMeansTheVeryNextActionMustRespond() {
        val c = rwc(1)
        val s = step(c, state0(), act("open"))
        assertEquals("{\"R\":1}", dl(s))
        assertEquals(false, Contracts.advanceContract(s, act("x"), c)["ok"])
        assertFalse(step(c, s, act("close")).containsKey("deadlines"))
    }

    @Test fun aResponseDischargesTheObligation() {
        val c = rwc(5)
        var s = step(c, state0(), act("open"))
        s = step(c, s, act("x"))
        assertEquals("{\"R\":4}", dl(s))
        s = step(c, s, act("close"))
        assertFalse(s.containsKey("deadlines"))
        s = step(c, s, act("x"))
        s = step(c, s, act("x"))
        assertEquals(5.0, Prohibitions.dv(s["seq"]), 0.0)
        val c2 = rwc(2)
        var t = step(c2, state0(), act("open"))
        t = step(c2, t, act("x"))
        assertEquals("{\"R\":1}", dl(t))
        assertFalse(step(c2, t, act("close")).containsKey("deadlines"))
    }

    @Test fun aRestimulusKeepsTheMostUrgentBudget() {
        val c = rwc(5)
        var s = step(c, state0(), act("open"))
        s = step(c, s, act("x"))
        s = step(c, s, act("open"))
        assertEquals("{\"R\":3}", dl(s))
        val c2 = rwc(2)
        var t = step(c2, state0(), act("open"))
        t = step(c2, t, act("open"))
        assertEquals("{\"R\":1}", dl(t))
        val c3 = contract(arr("{'id':'R','kind':'responds_within','p':{'verb':['open','open2']},'q':${w("close")},'within':4}"))
        var u = step(c3, state0(), act("open"))
        u = step(c3, u, act("open2"))
        assertEquals("{\"R\":3}", dl(u))
    }

    @Test fun anActionMatchingBothPAndQDischargesThenReopens() {
        val c = contract(arr(rw("R", w("both"), w("both"), 3)))
        var s = step(c, state0(), act("both"))
        assertEquals("{\"R\":3}", dl(s))
        s = step(c, s, act("both"))
        assertEquals("{\"R\":3}", dl(s))
    }

    @Test fun stimulusIsConservativeResponseIsAffirmative() {
        val c = contract(arr(rw("R", amb("open"), amb("close"), 3)))
        var s = step(c, state0(), act("open", "/r", "{}"))
        assertEquals("{\"R\":3}", dl(s))
        s = step(c, s, act("close", "/r", "{}"))
        assertEquals("{\"R\":2}", dl(s))
        s = step(c, s, act("close", "/r", "{'x':1}"))
        assertFalse(s.containsKey("deadlines"))
        assertFalse(step(c, state0(), act("open", "/r", "{'x':2}")).containsKey("deadlines"))
    }

    @Test fun obligationsAreTrackedPerClauseAndUnrelatedEntriesSurvive() {
        val c = contract(arr(rw("R1", w("open"), w("close1"), 2), rw("R2", w("open"), w("close2"), 4)))
        var s = step(c, state0(), act("open"))
        assertEquals("{\"R1\":2,\"R2\":4}", dl(s))
        s = step(c, s, act("close1"))
        assertEquals("{\"R2\":3}", dl(s))
        assertEquals("{\"gone\":7}", dl(step(contract(), withDeadlines("{'gone':7}"), act("x"))))
    }

    @Test fun nestedStateIsMergedIntoTheOverlay() {
        val c = contract(
            arr(
                andOf(
                    "AND",
                    arr(
                        rw("R", w("open"), w("close"), 3),
                        "{'id':'P','kind':'precedes','p':${w("review")},'q':${w("deploy")}}",
                        rw("R2", w("review"), w("close"), 2),
                    ),
                ),
            ),
        )
        var s = step(c, state0(), act("open"))
        assertEquals("{\"R\":3}", dl(s))
        s = step(c, s, act("review"))
        assertEquals("{\"R\":2,\"R2\":2}", dl(s))
        assertEquals("{\"P\":1700000000000}", canon(s["latched"]))
    }

    // ---- advanceContract

    @Test fun advanceSuccess() {
        val c = contract(arr(always("A", "read")))
        val s0 = state0()
        val r = Contracts.advanceContract(s0, act("read"), c)
        assertEquals(true, r["ok"])
        assertEquals("none", r["decidedBy"])
        assertEquals(emptyList<Any?>(), r["violated"])
        assertEquals(emptyList<Any?>(), r["reasons"])
        assertEquals(listOf(row("A", "always", "pass")), r["evaluated"])
        val next = m(r["next"])
        assertEquals(1.0, Prohibitions.dv(next["seq"]), 0.0)
        assertEquals(K08K4.NOW, Prohibitions.dv(next["now"]), 0.0)
        val parent = Pca.hashCanonical(Prohibitions.map("d", "atlas-pca/monitor-state-link/v1", "state", Prohibitions.stateDigest(s0), "action", Pca.hashCanonical(act("read"))))
        assertEquals(parent, next["parent"])
        assertEquals(0.0, Prohibitions.dv(s0["seq"]), 0.0)
        assertEquals("{}", canon(s0["latched"]))
        assertEquals(setOf("ok", "violated", "reasons", "evaluated", "next", "decidedBy"), r.keys)
    }

    @Test fun aClauselessContractAdvancesLikeTheProhibitionMonitorByteForByte() {
        val invs = arr(
            "{'id':'cap1','kind':'cap','when':${w("spend")},'amount':'action.params.amt','max':100,'window_secs':60}",
            "{'id':'rate1','kind':'rate','when':${w("spend")},'max':5,'window_secs':60}",
            "{'id':'na','kind':'never_after','after':${w("lock")},'forbid':${w("write")}}",
            "{'id':'rp','kind':'require_prior','when':${w("deploy")},'prior':${w("review")}}",
        )
        val k = contract("[]", invs)
        val cons = Contracts.embeddedConstitution(k)
        var s = state0()
        var t = state0()
        for (a in listOf(act("spend", "/r", "{'amt':5}"), act("review"), act("lock"), act("deploy"), act("spend", "/r", "{'amt':7}"))) {
            val ar = Contracts.advanceContract(s, a, k)
            val br = Prohibitions.advanceStateStrict(a, cons, t)
            assertEquals(br["ok"], ar["ok"])
            assertEquals(true, br["ok"])
            assertEquals(canon(br["state"]), canon(ar["next"]))
            assertEquals(Prohibitions.stateDigest(br["state"]), Prohibitions.stateDigest(ar["next"]))
            s = m(ar["next"])
            t = m(br["state"])
        }
        assertEquals(5.0, Prohibitions.dv(s["seq"]), 0.0)
        assertEquals("{\"na\":1700000000000,\"rp\":1700000000000}", canon(s["latched"]))
    }

    @Test fun clauseLatchesNeverOverwriteAnExistingLatch() {
        val k = contract(arr("{'id':'P','kind':'precedes','p':${w("review")},'q':${w("deploy")}}"))
        val s1 = step(k, state0(), act("review"), num(K08K4.NOW + 10))
        assertEquals("{\"P\":1700000000010}", canon(s1["latched"]))
        val s2 = step(k, s1, act("review"), num(K08K4.NOW + 20))
        assertEquals("{\"P\":1700000000010}", canon(s2["latched"]))
        assertEquals(K08K4.NOW + 20, Prohibitions.dv(s2["now"]), 0.0)
    }

    @Test fun theNowOptionAndItsRegression() {
        val k = contract(arr("{'id':'P','kind':'precedes','p':${w("review")},'q':${w("deploy")}}"))
        val a = Contracts.advanceContract(state0(), act("review"), k, num(K08K4.NOW + 5))
        assertEquals(K08K4.NOW + 5, Prohibitions.dv(m(a["next"])["now"]), 0.0)
        assertEquals("{\"P\":1700000000005}", canon(m(a["next"])["latched"]))
        val b = Contracts.advanceContract(state0(), act("review"), k)
        assertEquals(K08K4.NOW, Prohibitions.dv(m(b["next"])["now"]), 0.0)
        val r = Contracts.advanceContract(state0(), act("review"), k, num(K08K4.NOW - 1))
        assertEquals(false, r["ok"])
        assertEquals("state", r["decidedBy"])
        assertEquals(listOf("<state>"), r["violated"])
        assertEquals(listOf("<state>: advance failed: clock regression"), r["reasons"])
        assertEquals(listOf(row("P", "precedes", "pass")), r["evaluated"])
        assertEquals(true, Contracts.advanceContract(state0(), act("review"), k, num(K08K4.NOW))["ok"])
    }

    @Test fun casOnTheSequenceNumber() {
        val c = contract(arr(always("A", "read")))
        val s1 = step(c, state0(), act("read"))
        val r = Contracts.advanceContract(s1, act("read"), c, null, num(0.0))
        assertEquals(setOf("ok", "violated", "reasons", "evaluated", "next", "decidedBy"), r.keys)
        verdict(r, false, listOf("<state>"), listOf("<state>: stale state head (seq)"), listOf(row("A", "always", "pass")))
        assertEquals("state", r["decidedBy"])
        assertSame(s1, r["next"])
        assertEquals(true, Contracts.advanceContract(s1, act("read"), c, null, num(1.0))["ok"])
        assertEquals(true, Contracts.advanceContract(state0(), act("read"), c, null, num(0.0))["ok"])
        val v = Contracts.advanceContract(s1, act("write"), c, null, num(5.0))
        assertEquals("state", v["decidedBy"])
        assertEquals(listOf("A", "<state>"), v["violated"])
        assertEquals(listOf("A: $DEFAULT_ALWAYS", "<state>: stale state head (seq)"), v["reasons"])
        val n = Contracts.advanceContract(null, act("read"), c, null, num(0.0))
        assertEquals(false, n["ok"])
        assertEquals(listOf("<state>"), n["violated"])
        assertEquals(listOf("<state>: malformed monitor state", "<state>: stale state head (seq)"), n["reasons"])
        assertEquals("state", n["decidedBy"])
        // a state whose seq is not a number is stale under CAS too
        val odd = withKey(state0(), "seq", "0")
        assertEquals(listOf("<state>: malformed monitor state: seq", "<state>: stale state head (seq)"), Contracts.advanceContract(odd, act("read"), c, null, num(0.0))["reasons"])
    }

    @Test fun casOnTheStateDigest() {
        val c = contract(arr(always("A", "read")))
        val s1 = step(c, state0(), act("read"))
        val d = Prohibitions.stateDigest(s1)
        assertEquals(true, Contracts.advanceContract(s1, act("read"), c, null, null, d)["ok"])
        val r = Contracts.advanceContract(s1, act("read"), c, null, null, d + "x")
        assertEquals(false, r["ok"])
        assertEquals("state", r["decidedBy"])
        assertEquals(listOf("<state>"), r["violated"])
        assertEquals(listOf("<state>: stale state head (digest)"), r["reasons"])
        assertSame(s1, r["next"])
        val bad = Contracts.advanceContract(m(q("{'bad':1}")), act("read"), c, null, null, "<unhashable>")
        assertEquals(false, bad["ok"])
        assertEquals(listOf("<state>: malformed monitor state"), bad["reasons"])
        assertEquals(listOf("<state>: stale state head (seq)"), Contracts.advanceContract(s1, act("read"), c, null, num(9.0), d)["reasons"])
        assertEquals(listOf("<state>: stale state head (digest)"), Contracts.advanceContract(s1, act("read"), c, null, num(1.0), "nope")["reasons"])
    }

    @Test fun violationsAreDecidedByTheContractOrByTheState() {
        val c = contract(arr(always("A", "read")))
        val s0 = state0()
        val v = Contracts.advanceContract(s0, act("write"), c)
        assertEquals(false, v["ok"])
        assertEquals("contract", v["decidedBy"])
        assertSame(s0, v["next"])
        assertEquals(listOf("A"), v["violated"])
        val cases = listOf<Triple<Map<String, Any?>, Map<String, Any?>?, Map<String, Any?>>>(
            Triple(act("read"), m(q("{'version':9,'principal':'$PRIN'}")), s0),
            Triple(m(q("{}")), c, s0),
            Triple(act("read"), c, m(q("{'bad':1}"))),
        )
        for ((a, k, st) in cases) {
            val r = Contracts.advanceContract(st, a, k)
            assertEquals(false, r["ok"])
            assertEquals("state", r["decidedBy"])
            assertSame(st, r["next"])
        }
        assertEquals("contract", Contracts.advanceContract(s0, act("write"), contract(arr(always("<odd", "read"))))["decidedBy"])
        assertEquals("contract", Contracts.advanceContract(s0, act("write"), contract(arr(always("odd>", "read"))))["decidedBy"])
        assertEquals("state", Contracts.advanceContract(s0, act("write"), contract(arr(always("<odd>", "read"))))["decidedBy"])
        val both = Contracts.advanceContract(s0, act("x"), contract(arr(never("<a>", "x"), never("b", "x"))))
        assertEquals(listOf("<a>", "b"), both["violated"])
        assertEquals("state", both["decidedBy"])
        assertEquals("contract", Contracts.advanceContract(s0, act("x"), contract(arr(never("b", "x"), never("c", "x"))))["decidedBy"])
    }

    @Test fun anUnresolvableCapAmountIsRefusedByTheCheck() {
        val k = contract("[]", arr("{'id':'cap1','kind':'cap','when':${w("spend")},'amount':'action.params.amt','max':10}"))
        val r = Contracts.advanceContract(state0(), act("spend", "/r", "{}"), k)
        assertEquals(false, r["ok"])
        assertEquals("contract", r["decidedBy"])
        assertEquals(listOf("cap1: amount unresolvable (fail closed)"), r["reasons"])
    }

    @Test fun aResultingStateThatBreaksTheStateInvariantsIsRefused() {
        val dls = (0 until 1024).joinToString(",", "{", "}") { "'d$it':3" }
        val full = withDeadlines(dls)
        val k = contract(arr(rw("new", w("open"), w("close"), 2)))
        val ok = Contracts.advanceContract(full, act("x"), k)
        assertEquals(true, ok["ok"])
        assertEquals(1024, m(m(ok["next"])["deadlines"]).size)
        val r = Contracts.advanceContract(full, act("open"), k)
        assertEquals(false, r["ok"])
        assertEquals("state", r["decidedBy"])
        assertEquals(listOf("<state>"), r["violated"])
        assertEquals(listOf("<state>: resulting state invalid: malformed monitor state: too many deadline keys"), r["reasons"])
        assertEquals(listOf(row("new", "responds_within", "pass")), r["evaluated"])
        assertSame(full, r["next"])
    }

    @Test fun aClauselessContractAdvancesWithoutDeadlines() {
        val c = m(q(head()))
        val r = Contracts.advanceContract(state0(), act("x"), c)
        assertEquals(true, r["ok"])
        assertEquals(1.0, Prohibitions.dv(m(r["next"])["seq"]), 0.0)
        assertEquals("{}", canon(m(r["next"])["latched"]))
        assertFalse(m(r["next"]).containsKey("deadlines"))
    }

    @Test fun anAdvanceFailureIsFailClosedAndAFatalErrorEscapes() {
        val c = contract(arr(always("A", "read")))
        val clauses = c["clauses"]
        val counter = K08K4.Probe(c, "clauses", Int.MAX_VALUE) { K08K4.boom() }
        Contracts.checkContract(act("read"), counter, state0())
        val n1 = counter.reads
        var thrown = false
        val flaky = K08K4.Probe(c, "clauses", n1) {
            if (!thrown) {
                thrown = true
                K08K4.boom()
            } else {
                clauses
            }
        }
        val r = Contracts.advanceContract(state0(), act("read"), flaky)
        assertEquals(false, r["ok"])
        assertEquals("state", r["decidedBy"])
        assertEquals(listOf("<state>"), r["violated"])
        assertEquals(listOf("<state>: advance error (fail closed)"), r["reasons"])
        assertEquals(listOf(row("A", "always", "pass")), r["evaluated"])
        val fatal = K08K4.Probe(c, "clauses", n1) { K08K4.fatal() }
        assertThrows(InternalError::class.java) { Contracts.advanceContract(state0(), act("read"), fatal) }
    }

    // ---- checkContract catches: a clause whose reads change after validation, a state that fails after the shape check

    private fun readsOf(clause: Map<String, Any?>, key: String): Int {
        val p = K08K4.Probe(clause, key, Int.MAX_VALUE) { K08K4.boom() }
        assertEquals(emptyList<String>(), Contracts.validateContract(withKey(contract(), "clauses", arrayListOf<Any?>(p))))
        return p.reads
    }

    private fun lateState(): Map<String, Any?> {
        val probe = K08K4.Probe(state0(), "latched", Int.MAX_VALUE) { K08K4.boom() }
        Contracts.checkContract(act("zzz"), contract(), probe)
        return K08K4.Probe(state0(), "latched", probe.reads) { K08K4.boom() }
    }

    @Test fun aClauseWhoseKindChangesAfterValidationFailsClosed() {
        val base = m(q("{'id':'x','p':${w("a")},'kind':'never'}"))
        val cl = K08K4.Probe(base, "kind", readsOf(base, "kind")) { "bogus" }
        val r = Contracts.checkContract(act("zzz"), withKey(contract(), "clauses", arrayListOf<Any?>(cl)), state0())
        verdict(r, false, listOf("x"), listOf("x: unknown clause kind (fail closed)"), listOf(row("x", "bogus", "violated", "unknown clause kind (fail closed)")))
    }

    @Test fun aClauseWhosePThrowsAfterValidationIsAViolation() {
        val base = m(q(never("x", "a")))
        val cl = K08K4.Probe(base, "p", readsOf(base, "p")) { K08K4.boom() }
        val r = Contracts.checkContract(act("zzz"), withKey(contract(), "clauses", arrayListOf<Any?>(cl)), state0())
        verdict(r, false, listOf("x"), listOf("x: clause evaluation error (fail closed)"), listOf(row("x", "never", "violated", "clause evaluation error (fail closed)")))
        val fatal = K08K4.Probe(base, "p", readsOf(base, "p")) { K08K4.fatal() }
        assertThrows(InternalError::class.java) { Contracts.checkContract(act("zzz"), withKey(contract(), "clauses", arrayListOf<Any?>(fatal)), state0()) }
    }

    @Test fun aFailureBeforeTheClausesOwnTryIsCaughtPerClause() {
        val c = withKey(contract(), "clauses", arrayListOf<Any?>(m(q(never("x", "a")))))
        val r = Contracts.checkContract(act("zzz"), c, lateState())
        verdict(r, false, listOf("x"), listOf("x: clause evaluation error (fail closed)"), listOf(row("x", "never", "violated", "clause evaluation error (fail closed)")))
        val base = m(q("{'id':'x','p':${w("a")},'kind':'never'}"))
        val cl = K08K4.Probe(base, "kind", readsOf(base, "kind")) { null }
        val r2 = Contracts.checkContract(act("zzz"), withKey(contract(), "clauses", arrayListOf<Any?>(cl)), lateState())
        assertEquals(listOf(row("x", "clause", "violated", "clause evaluation error (fail closed)")), r2["evaluated"])
        assertEquals(listOf("x: clause evaluation error (fail closed)"), r2["reasons"])
        val fatalState = K08K4.Probe(state0(), "latched", lateStateReads()) { K08K4.fatal() }
        assertThrows(InternalError::class.java) { Contracts.checkContract(act("zzz"), c, fatalState) }
    }

    private fun lateStateReads(): Int {
        val probe = K08K4.Probe(state0(), "latched", Int.MAX_VALUE) { K08K4.boom() }
        Contracts.checkContract(act("zzz"), contract(), probe)
        return probe.reads
    }

    // ---- checkAndAdvanceContract

    @Test fun checkAndAdvanceAllowed() {
        val c = contract(arr(always("A", "read")))
        val r = Contracts.checkAndAdvanceContract(true, state0(), act("read"), c)
        assertEquals(true, r["allow"])
        assertEquals(true, r["permitted"])
        assertEquals(true, r["ok"])
        assertEquals("none", r["decidedBy"])
        assertEquals(1.0, Prohibitions.dv(m(r["next"])["seq"]), 0.0)
        assertEquals(setOf("ok", "violated", "reasons", "evaluated", "next", "decidedBy", "allow", "permitted"), r.keys)
    }

    @Test fun checkAndAdvancePermissionDenied() {
        val c = contract(arr(always("A", "read")))
        val s0 = state0()
        val r = Contracts.checkAndAdvanceContract(false, s0, act("read"), c)
        assertEquals(false, r["ok"])
        assertEquals(emptyList<Any?>(), r["violated"])
        assertEquals(listOf("<permission>: not permitted"), r["reasons"])
        assertEquals(listOf(row("A", "always", "pass")), r["evaluated"])
        assertSame(s0, r["next"])
        assertEquals("contract", r["decidedBy"])
        assertEquals(false, r["allow"])
        assertEquals(false, r["permitted"])
        assertEquals(setOf("ok", "violated", "reasons", "evaluated", "next", "decidedBy", "allow", "permitted"), r.keys)
    }

    @Test fun checkAndAdvanceKeepsTheContractsOwnRefusal() {
        val c = contract(arr(always("A", "read")))
        for (permitted in listOf(true, false)) {
            val r = Contracts.checkAndAdvanceContract(permitted, state0(), act("write"), c)
            assertEquals(false, r["allow"])
            assertEquals(permitted, r["permitted"])
            assertEquals(false, r["ok"])
            assertEquals("contract", r["decidedBy"])
            assertEquals(listOf("A"), r["violated"])
            assertEquals(listOf("A: $DEFAULT_ALWAYS"), r["reasons"])
        }
        val s1 = step(c, state0(), act("read"))
        val stale = Contracts.checkAndAdvanceContract(true, s1, act("read"), c, null, num(0.0))
        assertEquals(false, stale["allow"])
        assertEquals("state", stale["decidedBy"])
        assertEquals(true, stale["permitted"])
    }
}
