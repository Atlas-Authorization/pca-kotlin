package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.pub
import net.atlasauth.pca.verifier.IntentTestKit.sign
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for [GrantResource] (packages/pca-grants/src/grant-resource.ts): the authority order (verbs, wildcard resources,
 * ceilings, expiry), the order-free digest (UTF-8 key order), the merge, the shape bounds and every amendment / revocation / needs
 * approval code in its normative order.
 */
class Kill05LeaseGrantResourceTest {
    private val P = "k05-grant/principal"
    private val A = "k05-grant/agent"
    private fun n(s: String) = Json.Num(s)

    private fun au(verbs: List<Any?>, resources: List<Any?>, limits: Map<String, Any?>? = null, exp: Any? = null): LinkedHashMap<String, Any?> {
        val m = jm("verbs", ArrayList(verbs), "resources", ArrayList(resources))
        if (limits != null) m["limits"] = LinkedHashMap(limits)
        if (exp != null) m["expires_at"] = exp
        return m
    }

    private fun cmp(old: Map<String, Any?>, new: Map<String, Any?>) = GrantResource.compareAuthority(old, new)

    @Test fun authorityOrder() {
        val base = au(listOf("r", "w"), listOf("docs/*"), jm("n", n("5")), 1000L)
        assertEquals("equal", cmp(base, au(listOf("w", "r"), listOf("docs/*"), jm("n", n("5")), 1000L)))
        assertEquals("narrower", cmp(base, au(listOf("r"), listOf("docs/*"), jm("n", n("5")), 1000L)))
        assertEquals("wider", cmp(au(listOf("r"), listOf("docs/*"), jm("n", n("5")), 1000L), base))
        assertEquals("incomparable", cmp(au(listOf("r"), listOf("x")), au(listOf("w"), listOf("x"))))
        // resources: a wildcard covers its prefix; a narrower wildcard is narrower; a literal never covers a wildcard
        assertEquals("narrower", cmp(au(listOf("r"), listOf("docs/*")), au(listOf("r"), listOf("docs/a"))))
        assertEquals("narrower", cmp(au(listOf("r"), listOf("docs/*")), au(listOf("r"), listOf("docs/sub*"))))
        assertEquals("wider", cmp(au(listOf("r"), listOf("docs/sub*")), au(listOf("r"), listOf("docs/*"))))
        assertEquals("equal", cmp(au(listOf("r"), listOf("a*")), au(listOf("r"), listOf("a*"))))
        assertEquals("wider", cmp(au(listOf("r"), listOf("a")), au(listOf("r"), listOf("a*"))))
        assertEquals("incomparable", cmp(au(listOf("r"), listOf("a")), au(listOf("r"), listOf("b"))))
        assertEquals("narrower", cmp(au(listOf("r"), listOf("a", "b")), au(listOf("r"), listOf("b"))))
        assertEquals("narrower", cmp(au(listOf("r"), listOf("a")), au(listOf("r"), emptyList())))
        // ceilings
        val lim = au(listOf("r"), listOf("x"), jm("n", n("5")))
        assertEquals("narrower", cmp(lim, au(listOf("r"), listOf("x"), jm("n", n("3")))))
        assertEquals("equal", cmp(lim, au(listOf("r"), listOf("x"), jm("n", n("5")))))
        assertEquals("wider", cmp(lim, au(listOf("r"), listOf("x"), jm("n", n("7")))))
        assertEquals("wider", cmp(lim, au(listOf("r"), listOf("x"))))
        assertEquals("wider", cmp(lim, au(listOf("r"), listOf("x"), jm())))
        assertEquals("narrower", cmp(au(listOf("r"), listOf("x"), jm()), lim))
        assertEquals("incomparable", cmp(lim, au(listOf("r"), listOf("x"), jm("m", n("1")))))
        assertEquals("narrower", cmp(lim, au(listOf("r"), listOf("x"), jm("n", n("5"), "m", n("1")))))
        // a non-number ceiling never compares (fail closed): neither side is below the other
        assertEquals("incomparable", cmp(au(listOf("r"), listOf("x"), jm("n", "x")), au(listOf("r"), listOf("x"), jm("n", n("0.5")))))
        assertEquals("incomparable", cmp(au(listOf("r"), listOf("x"), jm("n", "x")), au(listOf("r"), listOf("x"), jm("n", n("2")))))
        assertEquals("incomparable", cmp(au(listOf("r"), listOf("x"), jm("n", n("0.5"))), au(listOf("r"), listOf("x"), jm("n", "x"))))
        assertEquals("incomparable", cmp(au(listOf("r"), listOf("x"), jm("n", "x")), au(listOf("r"), listOf("x"), jm("n", n("0")))))
        assertEquals("incomparable", cmp(au(listOf("r"), listOf("x"), jm("n", null)), au(listOf("r"), listOf("x"), jm("n", n("0")))))
        // expiry (absent = never)
        val ex = au(listOf("r"), listOf("x"), null, 100L)
        assertEquals("narrower", cmp(ex, au(listOf("r"), listOf("x"), null, 50L)))
        assertEquals("equal", cmp(ex, au(listOf("r"), listOf("x"), null, 100L)))
        assertEquals("wider", cmp(ex, au(listOf("r"), listOf("x"), null, 101L)))
        assertEquals("wider", cmp(ex, au(listOf("r"), listOf("x"))))
        assertEquals("narrower", cmp(au(listOf("r"), listOf("x")), ex))
        // non-string verbs and resources are ignored
        assertEquals("equal", cmp(au(listOf("r", 5L), listOf("x", null)), au(listOf("r"), listOf("x"))))
        assertEquals("equal", cmp(jm("verbs", "r", "resources", "x"), jm()))
    }

    @Test fun digestIsOrderFreeInUtf8Order() {
        val smile = "😀"
        val fw = "！"
        val d = GrantResource.authorityDigest(au(listOf(smile, fw, "a"), listOf("z", "b", fw, smile), jm("n", n("5")), 9L))
        val want = Pca.hashCanonical(jm("d", "atlas-pca/authority/v1", "a", jm(
            "verbs", jl("a", fw, smile), "resources", jl("b", "z", fw, smile), "limits", jm("n", n("5")), "expires_at", 9L,
        )))
        assertEquals(want, d)
        assertEquals(d, GrantResource.authorityDigest(au(listOf("a", fw, smile), listOf("b", fw, "z", smile), jm("n", n("5")), 9L)))
        assertEquals(GrantResource.authorityDigest(au(listOf("r"), listOf("x"))), GrantResource.authorityDigest(au(listOf("r", 1L), listOf("x", true))))
        assertNotEquals(GrantResource.authorityDigest(au(listOf("r"), listOf("x"))), GrantResource.authorityDigest(au(listOf("r"), listOf("x"), jm("n", n("1")))))
        assertNotEquals(GrantResource.authorityDigest(au(listOf("r"), listOf("x"))), GrantResource.authorityDigest(au(listOf("r"), listOf("y"))))
        assertEquals(Pca.hashCanonical(jm("d", "atlas-pca/authority/v1", "a", jm("verbs", jl(), "resources", jl()))), GrantResource.authorityDigest(jm()))
    }

    @Test fun mergeRaisesOnly() {
        val a = au(listOf("r", "w"), listOf("x"), jm("n", n("5"), "m", n("2")), 100L)
        val got = GrantResource.mergeAuthority(a, au(listOf("w", "d"), listOf("y", "x"), jm("n", n("7"), "m", n("1"), "z", n("9")), 50L))
        assertEquals(jm("verbs", jl("r", "w", "d"), "resources", jl("x", "y"), "limits", jm("n", n("7"), "m", n("2")), "expires_at", 100L), got)
        assertEquals(n("150"), GrantResource.mergeAuthority(a, au(listOf(), listOf(), null, n("150")))["expires_at"])
        val kept = GrantResource.mergeAuthority(a, au(listOf(), listOf()))
        assertEquals(jm("n", n("5"), "m", n("2")), kept["limits"])
        assertEquals(100L, kept["expires_at"])
        val bare = GrantResource.mergeAuthority(au(listOf("r"), listOf("x")), au(listOf("r"), listOf("x"), jm("n", n("9")), 500L))
        assertEquals(jm("verbs", jl("r"), "resources", jl("x")), bare)
        assertFalse(bare.containsKey("limits"))
        assertFalse(bare.containsKey("expires_at"))
        assertFalse(GrantResource.mergeAuthority(au(listOf("r"), listOf("x"), jm()), au(listOf(), listOf())).containsKey("limits"))
        // a non-number on either side never wins over a number, and never displaces the kept value
        assertEquals(jm("n", n("0.5")), GrantResource.mergeAuthority(au(listOf(), listOf(), jm("n", n("0.5"))), au(listOf(), listOf(), jm("n", "x")))["limits"])
        assertEquals(jm("n", n("0.5")), GrantResource.mergeAuthority(au(listOf(), listOf(), jm("n", "x")), au(listOf(), listOf(), jm("n", n("0.5"))))["limits"])
        assertEquals(jm("n", "x"), GrantResource.mergeAuthority(au(listOf(), listOf(), jm("n", "x")), au(listOf(), listOf(), jm("n", "y")))["limits"])
        assertEquals(jm("n", n("-3")), GrantResource.mergeAuthority(au(listOf(), listOf(), jm("n", n("-3"))), au(listOf(), listOf(), jm("n", n("-4"))))["limits"])
        assertEquals("x", GrantResource.mergeAuthority(au(listOf(), listOf(), null, "x"), au(listOf(), listOf(), null, "y"))["expires_at"])
        assertEquals(n("0.5"), GrantResource.mergeAuthority(au(listOf(), listOf(), null, "x"), au(listOf(), listOf(), null, n("0.5")))["expires_at"])
        assertEquals(n("0.5"), GrantResource.mergeAuthority(au(listOf(), listOf(), null, n("0.5")), au(listOf(), listOf(), null, "x"))["expires_at"])
    }

    @Test fun authorityShape() {
        val ok = au(listOf("r"), listOf("x"))
        assertTrue(GrantResource.authorityOk(ok))
        assertFalse(GrantResource.authorityOk(null))
        assertFalse(GrantResource.authorityOk(jl()))
        assertFalse(GrantResource.authorityOk(jm("resources", jl())))
        assertFalse(GrantResource.authorityOk(jm("verbs", jl())))
        assertFalse(GrantResource.authorityOk(jm("verbs", "r", "resources", jl())))
        assertFalse(GrantResource.authorityOk(jm("verbs", jl(), "resources", "x")))
        assertTrue(GrantResource.authorityOk(au(emptyList(), emptyList())))
        fun many(k: Int, len: Int = 1): List<Any?> = (1..k).map { "v$it".padEnd(len, 'x') }
        assertTrue(GrantResource.authorityOk(au(many(256), listOf())))
        assertFalse(GrantResource.authorityOk(au(many(257), listOf())))
        assertTrue(GrantResource.authorityOk(au(listOf("x".repeat(128)), listOf())))
        assertFalse(GrantResource.authorityOk(au(listOf("r", "x".repeat(129)), listOf())))
        assertFalse(GrantResource.authorityOk(au(listOf("r", ""), listOf())))
        assertFalse(GrantResource.authorityOk(au(listOf("r", 5L), listOf())))
        assertTrue(GrantResource.authorityOk(au(listOf(), many(1024))))
        assertFalse(GrantResource.authorityOk(au(listOf(), many(1025))))
        assertTrue(GrantResource.authorityOk(au(listOf(), listOf("x".repeat(512)))))
        assertFalse(GrantResource.authorityOk(au(listOf(), listOf("r", "x".repeat(513)))))
        assertFalse(GrantResource.authorityOk(au(listOf(), listOf("r", null))))
        assertTrue(GrantResource.authorityOk(au(listOf(), listOf(), jm())))
        assertTrue(GrantResource.authorityOk(au(listOf(), listOf(), jm("a", n("0"), "b", n("1.5"), "c", 7L))))
        assertFalse(GrantResource.authorityOk(au(listOf(), listOf(), jm("a", n("0"), "b", n("-1")))))
        assertFalse(GrantResource.authorityOk(au(listOf(), listOf(), jm("a", n("0"), "b", "5"))))
        assertFalse(GrantResource.authorityOk(au(listOf(), listOf(), jm("a", n("0"), "b", null))))
        assertFalse(GrantResource.authorityOk(jm("verbs", jl(), "resources", jl(), "limits", null)))
        assertFalse(GrantResource.authorityOk(jm("verbs", jl(), "resources", jl(), "limits", jl())))
        assertTrue(GrantResource.authorityOk(au(listOf(), listOf(), null, 0L)))
        assertTrue(GrantResource.authorityOk(au(listOf(), listOf(), null, 5L)))
        assertFalse(GrantResource.authorityOk(au(listOf(), listOf(), null, -1L)))
        assertFalse(GrantResource.authorityOk(au(listOf(), listOf(), null, "5")))
        assertFalse(GrantResource.authorityOk(au(listOf(), listOf(), null, n("1.5"))))
        assertFalse(GrantResource.authorityOk(jm("verbs", jl(), "resources", jl(), "expires_at", null)))
    }

    private val curAuth = au(listOf("r", "w"), listOf("docs/*"), jm("n", n("5")), 1000L)
    private fun cur(status: String = "active", auth: Any? = curAuth) =
        jm("id", "G1", "rev", 3L, "principal", pub(P), "agent", pub(A), "status", status, "authority", auth)

    private fun req(action: Any?, authority: Any?, signedBy: Any?, key: String?, c: Map<String, Any?> = cur()): LinkedHashMap<String, Any?> {
        val m = jm("action", action, "authority", authority, "signed_by", signedBy)
        if (key != null) {
            @Suppress("UNCHECKED_CAST")
            m["sig"] = sign(key, IntentJs.message(GrantResource.GRANT_AMEND_DOMAIN, GrantResource.amendMessage(c, action, authority as Map<String, Any?>)))
        }
        return m
    }

    private fun amendFail(a: GrantResource.Amendment, code: String) {
        assertFalse(code, a.ok)
        assertEquals(code, a.code)
        assertFalse(a.widens)
        assertEquals("", a.nextDigest)
        assertEquals(jm("ok", false, "code", code), a.toJson())
    }

    private fun amendOk(a: GrantResource.Amendment, widens: Boolean, next: Map<String, Any?>) {
        assertTrue(a.code, a.ok)
        assertEquals(widens, a.widens)
        assertEquals("", a.code)
        val d = GrantResource.authorityDigest(next)
        assertEquals(d, a.nextDigest)
        assertEquals(jm("ok", true, "widens", widens, "next_digest", d), a.toJson())
    }

    @Test fun amendmentCodesInOrder() {
        val narrow = au(listOf("r"), listOf("docs/a"), jm("n", n("3")), 900L)
        val wider = au(listOf("r", "w", "d"), listOf("docs/*"), jm("n", n("5")), 1000L)
        val v = { r: Any?, up: Boolean -> GrantResource.verifyAmendment(cur(), r, up) }
        amendFail(v(null, true), "bad_request")
        amendFail(v("narrow", true), "bad_request")
        amendFail(v(jm("authority", narrow), true), "bad_request")
        amendFail(v(req("widen", narrow, "holder", A), true), "bad_request")
        amendFail(v(jm("action", "narrow"), true), "bad_request")
        amendFail(v(jm("action", "narrow", "authority", jm("verbs", 5L, "resources", jl())), true), "bad_request")
        amendFail(GrantResource.verifyAmendment(cur("revoked"), req("narrow", narrow, "holder", A), true), "not_active")
        amendFail(GrantResource.verifyAmendment(cur(auth = "x"), req("narrow", narrow, "holder", A), true), "bad_request")
        amendFail(v(req("narrow", curAuth, "holder", A), true), "not_narrower")
        amendFail(v(req("narrow", wider, "principal", P), true), "not_narrower")
        amendFail(v(req("narrow", au(listOf("x"), listOf("docs/a")), "principal", P), true), "not_narrower")
        amendFail(v(req("narrow", narrow, "holder", null), true), "signature_required")
        amendFail(v(LinkedHashMap(req("narrow", narrow, "holder", A)).also { it["sig"] = 5L }, true), "signature_required")
        amendFail(v(req("narrow", narrow, "admin", A), true), "signature_required")
        amendFail(v(req("narrow", narrow, null, A), true), "signature_required")
        amendFail(v(req("narrow", narrow, "holder", P), true), "bad_signature")
        amendFail(v(req("narrow", narrow, "principal", A), true), "bad_signature")
        amendFail(v(LinkedHashMap(req("narrow", narrow, "holder", A)).also { it["sig"] = "abc" }, true), "bad_signature")
        amendOk(v(req("narrow", narrow, "holder", A), false), false, narrow)
        amendOk(v(req("narrow", narrow, "principal", P), false), false, narrow)
        amendOk(v(req("replace", curAuth, "holder", A), false), false, curAuth)
        // widening: only the principal, and only with the step-up
        amendFail(v(req("replace", wider, "holder", A), true), "signature_required")
        amendFail(v(req("replace", wider, "principal", A), true), "bad_signature")
        amendFail(v(req("replace", wider, "principal", P), false), "step_up_required")
        amendOk(v(req("replace", wider, "principal", P), true), true, wider)
        val sideways = au(listOf("x"), listOf("docs/*"), jm("n", n("5")), 1000L)
        amendFail(v(req("replace", sideways, "holder", A), true), "signature_required")
        amendOk(v(req("replace", sideways, "principal", P), true), true, sideways)
        // merge classifies the merged result, but the signature covers the delta
        val delta = au(listOf("d"), listOf("docs/*"))
        amendFail(v(req("merge", delta, "holder", A), true), "signature_required")
        amendFail(v(req("merge", delta, "principal", P), false), "step_up_required")
        amendOk(v(req("merge", delta, "principal", P), true), true, GrantResource.mergeAuthority(curAuth, delta))
        val sub = au(listOf("r"), listOf("docs/*"))
        amendOk(v(req("merge", sub, "holder", A), false), false, GrantResource.mergeAuthority(curAuth, sub))
        // an authority the strict canonical form refuses (exponent number) cannot be digested: a malformed request, never a throw
        val expo = au(listOf("r"), listOf("docs/a"), jm("n", n("1e0")), 900L)
        assertTrue(GrantResource.authorityOk(expo))
        amendFail(v(jm("action", "narrow", "authority", expo, "signed_by", "holder", "sig", "x"), true), "bad_request")
    }

    private fun revSig(scope: Any?, key: String) = sign(key, IntentJs.message(GrantResource.GRANT_REVOKE_DOMAIN, GrantResource.grantRevokeMessage("G1", scope)))

    @Test fun revocationSignature() {
        val root = cur()
        for (scope in listOf("grant", "agent", "subtree")) {
            val r = GrantResource.verifyRevokeSignature(root, scope, revSig(scope, P))
            assertTrue(scope, r.ok)
            assertEquals(scope, r.scope)
            assertEquals("", r.code)
            assertEquals(jm("ok", true, "scope", scope), r.toJson())
        }
        for ((scope, sig) in listOf<Pair<Any?, Any?>>("tree" to revSig("tree", P), null to revSig(null, P))) {
            val r = GrantResource.verifyRevokeSignature(root, scope, sig)
            assertFalse(r.ok); assertEquals("bad_request", r.code); assertEquals("", r.scope)
            assertEquals(jm("ok", false, "code", "bad_request"), r.toJson())
        }
        for (sig in listOf<Any?>(revSig("grant", A), revSig("agent", P), null, 5L, "abc")) {
            val r = GrantResource.verifyRevokeSignature(root, "grant", sig)
            assertFalse(r.ok); assertEquals("bad_signature", r.code); assertEquals("", r.scope)
            assertEquals(jm("ok", false, "code", "bad_signature"), r.toJson())
        }
        assertEquals(jm("grant", "G1", "scope", "agent"), GrantResource.grantRevokeMessage("G1", "agent"))
    }

    private fun need(verb: String, res: String, limits: Map<String, Any?>?, adjustable: Any? = null): LinkedHashMap<String, Any?> {
        val m = jm("verb", verb, "resource", res)
        if (limits != null) m["limits"] = LinkedHashMap(limits)
        if (adjustable != null) m["adjustable"] = adjustable
        return m
    }

    private val gAuth = au(listOf("r"), listOf("docs/*"), jm("amt", n("10"), "debt", n("-10")))
    private fun g(auth: Any? = gAuth) = jm("id", "G1", "rev", 3L, "principal", pub(P), "agent", pub(A), "status", "active", "authority", auth)
    private fun nr(needs: Any?, status: String = "pending") = jm("id", "N1", "grant_id", "G1", "status", status, "needs", needs)
    private fun apSig(n: Map<String, Any?>, approved: Any?, key: String = P) =
        sign(key, IntentJs.message(GrantResource.NEED_APPROVE_DOMAIN, GrantResource.needApproveMessage(n, 3L, approved)))

    private fun approve(needs: Any?, approved: Any?, stepUp: Boolean = true, auth: Any? = gAuth, key: String = P): GrantResource.Approval {
        val n = nr(needs)
        return GrantResource.verifyNeedApproval(n, g(auth), approved, apSig(n, approved, key), stepUp)
    }

    private fun apFail(a: GrantResource.Approval, code: String) {
        assertFalse(code, a.ok)
        assertEquals(code, a.code)
        assertEquals("", a.authorityDigest)
        assertEquals(jm("ok", false, "code", code), a.toJson())
    }

    private fun apOk(a: GrantResource.Approval, merged: Map<String, Any?>) {
        assertTrue(a.code, a.ok)
        assertEquals("", a.code)
        val d = GrantResource.authorityDigest(merged)
        assertEquals(d, a.authorityDigest)
        assertEquals(jm("ok", true, "authority_digest", d), a.toJson())
    }

    @Test fun needApprovalCodesInOrder() {
        val pay = need("pay", "acct/1", jm("amt", n("100")), true)
        val read = need("read", "docs/a", null)
        val needs = jl(pay, read)
        val n0 = nr(needs, "approved")
        apFail(GrantResource.verifyNeedApproval(n0, g(), jl(), apSig(n0, jl()), true), "conflict")
        apFail(approve(needs, jl(pay, read), key = A), "bad_signature")
        apFail(approve(needs, "all"), "need_not_lowered_only")
        apFail(approve("x", jl(pay, read)), "need_not_lowered_only")
        apFail(approve(needs, jl(pay)), "need_not_lowered_only")
        apFail(approve(needs, jl(pay, read, read)), "need_not_lowered_only")
        apFail(approve(needs, jl(pay, "read")), "need_not_lowered_only")
        apFail(approve(jl(pay, "read"), jl(pay, read)), "need_not_lowered_only")
        apFail(approve(needs, jl(pay, need("write", "docs/a", null))), "need_not_lowered_only")
        apFail(approve(needs, jl(pay, need("read", "docs/b", null))), "need_not_lowered_only")
        // amounts: only names the need has, only lowered, only when adjustable, only numbers
        apFail(approve(needs, jl(pay, need("read", "docs/a", jm("amt", n("1"))))), "need_not_lowered_only")
        apFail(approve(needs, jl(need("pay", "acct/1", jm("other", n("1"))), read)), "need_not_lowered_only")
        apFail(approve(needs, jl(need("pay", "acct/1", jm("amt", n("101"))), read)), "need_not_lowered_only")
        apFail(approve(needs, jl(need("pay", "acct/1", jm("amt", "50")), read)), "need_not_lowered_only")
        apFail(approve(jl(need("pay", "acct/1", jm("amt", "x"), true), read), jl(need("pay", "acct/1", jm("amt", n("1"))), read)), "need_not_lowered_only")
        apFail(approve(jl(need("pay", "acct/1", jm("amt", n("100"))), read), jl(need("pay", "acct/1", jm("amt", n("99"))), read)), "need_not_adjustable")
        apFail(approve(jl(need("pay", "acct/1", jm("amt", n("100")), "true"), read), jl(need("pay", "acct/1", jm("amt", n("99"))), read)), "need_not_adjustable")
        apFail(approve(needs, jl(pay, read), stepUp = false), "step_up_required")
        apFail(approve(needs, jl(pay, read), auth = "x"), "bad_request")
        // the merged authority: verbs and resources added, a ceiling raised only where the grant already has one
        apOk(approve(needs, jl(pay, read)), au(listOf("r", "pay", "read"), listOf("docs/*", "acct/1", "docs/a"), jm("amt", n("100"), "debt", n("-10"))))
        apOk(approve(jl(need("pay", "acct/1", jm("amt", n("100")))), jl(need("pay", "acct/1", jm("amt", n("100"))))),
            au(listOf("r", "pay"), listOf("docs/*", "acct/1"), jm("amt", n("100"), "debt", n("-10"))))
        apOk(approve(needs, jl(need("pay", "acct/1", jm("amt", n("40"))), read)),
            au(listOf("r", "pay", "read"), listOf("docs/*", "acct/1", "docs/a"), jm("amt", n("40"), "debt", n("-10"))))
        // an omitted limit is not granted: no amount at all
        apOk(approve(needs, jl(need("pay", "acct/1", null), read)), au(listOf("r", "pay", "read"), listOf("docs/*", "acct/1", "docs/a"), jm("amt", n("10"), "debt", n("-10"))))
        // the highest approved amount per name wins, whatever the order; the floor is 0
        val two = jl(need("pay", "acct/1", jm("amt", n("60"), "debt", n("-5")), true), need("pay", "acct/2", jm("amt", n("30")), true))
        apOk(approve(two, two), au(listOf("r", "pay"), listOf("docs/*", "acct/1", "acct/2"), jm("amt", n("60"), "debt", n("0"))))
        val owt = jl(two[1], two[0])
        apOk(approve(owt, owt), au(listOf("r", "pay"), listOf("docs/*", "acct/2", "acct/1"), jm("amt", n("60"), "debt", n("0"))))
        // a grant authority the strict canonical form refuses: a malformed request, never a throw
        apFail(approve(needs, jl(pay, read), auth = au(listOf("r"), listOf("x"), jm("zz", n("1e0")))), "bad_request")
        assertEquals(jm("need", "N1", "grant", "G1", "rev", 3L, "approved", jl()), GrantResource.needApproveMessage(nr(needs), 3L, jl()))
    }
}
