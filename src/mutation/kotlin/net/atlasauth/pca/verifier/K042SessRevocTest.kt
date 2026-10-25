package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential for IntentSession (rule 13: the intent_session wire member, the grant caveat, the signed session root) and
 * IntentRevocation (rule 13 step 7) against the TS reference: cases and exact reasons from
 * tools/pca-audit/java-mutate/k042-sessrevoc-oracle.mts (test-data/k042-sessrevoc-cases.json); the JavaScript-semantics helpers and
 * the inputs JSON cannot carry (NaN, Infinity, -0 as a double) are pinned inline.
 */
@Suppress("UNCHECKED_CAST")
class K042SessRevocTest {
    companion object {
        const val FAIL_CLOSED = "(fail closed): "
        val all: Map<String, Any?> by lazy { Json.parseLenient(String(Files.readAllBytes(Path.of("test-data/k042-sessrevoc-cases.json")), Charsets.UTF_8)) as Map<String, Any?> }
        fun list(kind: String) = all[kind] as List<Map<String, Any?>>
        fun json(text: Any?): Any? = IntentJs.normalize(Json.parseLenient(text as String))
        fun dbl(n: Any?) = (n as Json.Num).raw.toDouble()
        fun same(name: String, want: Any?, got: String?) {
            if (want is String && want.endsWith(FAIL_CLOSED)) {
                assertNotNull(name, got); assertTrue("$name: $got", got!!.startsWith(want))
            } else assertEquals(name, want, got)
        }
        fun map(vararg kv: Pair<String, Any?>) = KUtil.m(*kv)
        fun lst(vararg xs: Any?) = ArrayList<Any?>(xs.toList())
        val AUTH = Pca.b64(ByteArray(32))
        fun n(s: String) = Json.Num(s)
    }

    @Test fun wire() {
        val cs = list("wire"); assertTrue(cs.size >= 60)
        for (c in cs) same("wire ${c["name"]}", c["reason"], IntentSession.validateWire(json(c["v"])))
    }

    @Test fun caveat() {
        val cs = list("caveat"); assertTrue(cs.size >= 17)
        for (c in cs) same("caveat ${c["name"]}", c["reason"], IntentSession.caveatError(json(c["c"])))
    }

    @Test fun root() {
        val cs = list("root"); assertTrue(cs.size >= 150)
        for (c in cs) {
            val nm = c["name"] as String
            val s = json(c["s"])
            same("shape $nm", c["shape"], IntentSession.rootShapeError(s))
            val pins = if (c.containsKey("pq_pins")) json(c["pq_pins"]) else null
            same("verify $nm", c["verify"], IntentSession.verifyRoot(s, pins))
        }
    }

    @Test fun revocation() {
        val cs = list("rev"); assertTrue(cs.size >= 100)
        for (c in cs) {
            val ev = if (c["ev"] == null) null else json(c["ev"])
            val ids = if (c["ids"] == null) null else json(c["ids"])
            val lastPresent = c["last"] != null
            val last = if (lastPresent) json(c["last"]) else null
            val got = IntentRevocation.checkSessionRevocation(ev, c["session"] as String?, json(c["authority"]), ids as? List<*>,
                dbl(c["now"]), dbl(c["maxAge"]), c["scope"] as String?, null, lastPresent, last)
            same("rev ${c["name"]}", c["reason"], got)
        }
    }

    @Test fun primitive() {
        val cs = list("prim"); assertTrue(cs.size >= 27)
        for (c in cs) {
            val inp = Json.parseLenient(c["text"] as String)
            same("prim ${c["name"]}", c["reason"], IntentRevocation.primitiveReason(inp))
            assertEquals("prim ok ${c["name"]}", c["reason"] == null, IntentRevocation.checkPrimitive(inp))
        }
    }

    @Test fun nonFiniteAndNegZeroClock() {
        val mis = "revocation max age misconfigured (fail closed)"; val clk = "the verifier clock is not a safe integer (fail closed)"
        val ids = lst()
        fun chk(now: Double, age: Double, a: Any? = AUTH, i: List<*>? = ids) = IntentRevocation.checkSessionRevocation(null, "s", a, i, now, age, null, null, false, null)
        assertEquals(mis, chk(0.0, Double.NaN)); assertEquals(mis, chk(0.0, Double.POSITIVE_INFINITY)); assertEquals(mis, chk(0.0, -0.0)); assertEquals(mis, chk(0.0, 0.5))
        assertEquals(clk, chk(Double.NaN, 0.0)); assertEquals(clk, chk(Double.NEGATIVE_INFINITY, 0.0)); assertEquals(clk, chk(-0.0, 0.0)); assertEquals(clk, chk(-1.5, 0.0))
        val none = "no session revocation epoch supplied"
        assertEquals(none, chk(0.0, 0.0)); assertEquals(none, chk(-1.0, 0.0)); assertEquals(none, chk(IntentJs.MAX_SAFE, IntentJs.MAX_SAFE))
        assertEquals(none, chk(-IntentJs.MAX_SAFE, 0.0))
        assertEquals(clk, chk(-IntentJs.MAX_SAFE - 1, 0.0))
        assertEquals(mis, chk(0.0, IntentJs.MAX_SAFE + 1))
        assertEquals("ids must be an array and the authority a key", chk(0.0, 0.0, AUTH, null))
        assertEquals("ids must be an array and the authority a key", chk(0.0, 0.0, null))
    }

    @Test fun primitiveNotAnObject() {
        assertEquals("session revocation check error (fail closed)", IntentRevocation.primitiveReason(lst(n("1"))))
        assertEquals("session revocation check error (fail closed)", IntentRevocation.primitiveReason("x"))
        assertFalse(IntentRevocation.checkPrimitive(lst(n("1"))))
    }

    @Test fun revocationIds() {
        assertEquals("pca-intent:session:S", IntentRevocation.sessionRevocationId("S"))
        assertEquals("pca-intent:map:M", IntentRevocation.mapRevocationId("M"))
        assertEquals("pca-intent:delta:D", IntentRevocation.deltaRevocationId("D"))
        assertEquals("pca-intent:profile:travel@2", IntentRevocation.profileRevocationId("travel", "2"))
        assertEquals("pca-intent-session:S", IntentRevocation.sessionRevocationScope("S"))
        assertTrue(IntentRevocation.revsetRoot(emptyList()) != IntentRevocation.revsetRoot(listOf("a")))
    }

    @Test fun jsText() {
        assertEquals("undefined", IntentRevocation.jsText("x", false))
        assertEquals("undefined", IntentRevocation.jsText(null, false))
        assertEquals("null", IntentRevocation.jsText(null, true))
        assertEquals("0", IntentRevocation.jsText(n("-0"), true))
        assertEquals("-1", IntentRevocation.jsText(n("-1"), true))
        assertEquals("1.5", IntentRevocation.jsText(n("1.5"), true))
        assertEquals("abc", IntentRevocation.jsText("abc", true))
        assertEquals("", IntentRevocation.jsText("", true))
        assertEquals("true", IntentRevocation.jsText(true, true))
        assertEquals("false", IntentRevocation.jsText(false, true))
        assertEquals("[object Object]", IntentRevocation.jsText(map("a" to n("1")), true))
        assertEquals("[object Object]", IntentRevocation.jsText(map(), true))
        assertEquals("", IntentRevocation.jsText(lst(), true))
        assertEquals("a,b", IntentRevocation.jsText(lst("a", "b"), true))
        assertEquals("1,,x,2,3,[object Object],0,true", IntentRevocation.jsText(lst(n("1"), null, "x", lst(n("2"), n("3")), map("k" to "v"), n("-0"), true), true))
        assertEquals(",", IntentRevocation.jsText(lst(null, null), true))
        assertEquals(",a", IntentRevocation.jsText(lst(null, "a"), true))
        assertEquals("a,", IntentRevocation.jsText(lst("a", null), true))
        assertEquals("", IntentRevocation.jsText(lst(lst()), true))
        assertEquals(",", IntentRevocation.jsText(lst(lst(), lst()), true))
    }

    @Test fun truthy() {
        assertFalse(IntentRevocation.truthy(null)); assertTrue(IntentRevocation.truthy(true)); assertFalse(IntentRevocation.truthy(false))
        assertFalse(IntentRevocation.truthy("")); assertTrue(IntentRevocation.truthy("0")); assertTrue(IntentRevocation.truthy("false"))
        assertFalse(IntentRevocation.truthy(n("0"))); assertFalse(IntentRevocation.truthy(n("-0")))
        assertTrue(IntentRevocation.truthy(n("1"))); assertTrue(IntentRevocation.truthy(n("-1"))); assertTrue(IntentRevocation.truthy(n("0.5")))
        assertTrue(IntentRevocation.truthy(map())); assertTrue(IntentRevocation.truthy(lst()))
    }

    @Test fun grantSessionCaveat() {
        val sc = map("type" to "intent_session", "session" to "s", "seq" to n("0"), "root" to "r")
        val sc2 = map("type" to "intent_session", "session" to "t")
        val env = map("type" to "envelope")
        assertSame(sc, IntentSession.grantSessionCaveat(map("caveats" to lst(env, "x", lst(n("1")), null, sc, sc2))))
        assertSame(sc, IntentSession.grantSessionCaveat(map("caveats" to lst(sc, sc2))))
        assertSame(sc2, IntentSession.grantSessionCaveat(map("caveats" to lst(map("type" to "intent_sessionx"), sc2))))
        assertNull(IntentSession.grantSessionCaveat(map("caveats" to lst(env, "intent_session", map("kind" to "intent_session")))))
        assertNull(IntentSession.grantSessionCaveat(map("caveats" to lst())))
        assertNull(IntentSession.grantSessionCaveat(map("caveats" to map("a" to sc))))
        assertNull(IntentSession.grantSessionCaveat(map("caveats" to null)))
        assertNull(IntentSession.grantSessionCaveat(map()))
        assertNull(IntentSession.grantSessionCaveat(lst(sc)))
        assertNull(IntentSession.grantSessionCaveat(null))
        assertNull(IntentSession.grantSessionCaveat("x"))
    }

    @Test fun caveatNonJsonShapes() {
        assertEquals("not an intent_session caveat", IntentSession.caveatError(null))
        assertEquals("not an intent_session caveat", IntentSession.caveatError(lst(map("type" to "intent_session"))))
        assertEquals("not an intent_session caveat", IntentSession.caveatError(map()))
    }

    @Test fun goals() {
        assertEquals("pca-intent:v2:S:M", IntentSession.intentGoalV2("S", "M"))
        assertEquals("pca-intent:v2c:S:M", IntentSession.intentGoalV2c("S", "M"))
    }

    private fun seed(label: String) = MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/$label".toByteArray(Charsets.UTF_8))
    private fun pub(label: String): String { val pk = ByteArray(32); org.bouncycastle.math.ec.rfc8032.Ed25519.generatePublicKey(seed(label), 0, pk, 0); return Pca.b64(pk) }
    private fun sign(label: String, msg: ByteArray): String { val sig = ByteArray(64); org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed(label), 0, msg, 0, msg.size, sig, 0); return Pca.b64(sig) }

    @Test fun loneSurrogateRevokedFailsClosedWithTheExceptionName() {
        val rev = "k042sr/rev"; val now = 1_800_000_000_000L
        val body = map("instance_id" to "ana", "grant_ref" to "pca-intent-session:S", "epoch" to IntentJs.ofLong(1), "set_size" to IntentJs.ofLong(1),
            "root" to IntentRevocation.revsetRoot(listOf("x")), "issued_at" to IntentJs.ofLong(now - 1000), "not_after" to IntentJs.ofLong(now + 1000))
        val ep = LinkedHashMap(body)
        ep["guardian"] = pub(rev)
        ep["sig"] = sign(rev, Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.toByteArray(Charsets.UTF_8), IntentJs.canonBytes(body)))
        val ok = map("epoch" to ep, "revoked" to lst("x"))
        fun chk(e: Any?, ids: List<*>, scope: String? = null, session: String = "S", lastPresent: Boolean = false, last: Any? = null) =
            IntentRevocation.checkSessionRevocation(e, session, pub(rev), ids, now.toDouble(), 60_000.0, scope, null, lastPresent, last)
        assertNull(chk(ok, lst("y")))
        assertEquals("'x' is revoked", chk(ok, lst("y", "x")))
        assertEquals("session revocation check error (fail closed): IllegalArgumentException", chk(map("epoch" to ep, "revoked" to lst("\uD800")), lst("y")))
        val ep2 = LinkedHashMap(ep); ep2["instance_id"] = "\uD800"
        assertEquals("revocation epoch check error", chk(map("epoch" to ep2, "revoked" to lst("x")), lst("y")))
        assertEquals("revocation epoch check error", IntentRevocation.checkRevocationEpoch(ep2, pub(rev), now.toDouble(), "pca-intent-session:S", null))
        assertNull(IntentRevocation.checkRevocationEpoch(ep, pub(rev), now.toDouble(), "pca-intent-session:S", null))
        assertEquals("revocation epoch not signed by the pinned guardian", IntentRevocation.checkRevocationEpoch(ep, AUTH, now.toDouble(), "pca-intent-session:S", null))
        val ep3 = LinkedHashMap(ep); ep3["alg"] = "nope-dsa"
        assertEquals("revocation epoch not signed by the pinned guardian", IntentRevocation.checkRevocationEpoch(ep3, pub(rev), now.toDouble(), "pca-intent-session:S", null))
        assertEquals("revocation epoch is for a different grant", chk(ok, lst("y"), scope = "pca-intent-session:T"))
        assertNull(chk(ok, lst("y"), scope = "pca-intent-session:S", session = "T"))
        assertNull(chk(ok, lst("y"), lastPresent = true, last = map("epoch" to LinkedHashMap(ep), "revoked" to lst("x"))))
    }
}
