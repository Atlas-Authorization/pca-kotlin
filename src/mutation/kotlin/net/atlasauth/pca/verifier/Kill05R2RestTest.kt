package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * k05 round 2, shard 18 ("rest") of run 41911466407: V8Json context window / special-document / surrogate-pair edges (expected
 * messages are Node's JSON.parse), FreshAt counter keys that share a String hashCode with a real key and the Java static bridges,
 * the escalation request's resource, blueprint issuer length and a record without max_depth, passport evidence with a negative
 * max age, and obligations with a non-String kind.
 */
@Suppress("UNCHECKED_CAST")
class Kill05R2RestTest {
    private fun n(s: String) = Json.Num(s)

    // ---- V8Json (AttestJws.kt) ----

    @Test fun v8JsonEdges() {
        val rows = listOf(
            // a token exactly 10 units before the end: the end-of-text context (no trailing "...")
            "[1,1,1,1,1,1,1,x,1,1,1,1]" to "Unexpected token 'x', ...\"1,1,1,1,1,x,1,1,1,1]\" is not valid JSON",
            // documents whose String hashCode equals one of the four special documents, but which are not them
            "Nb/" to "Unexpected token 'N', \"Nb/\" is not valid JSON",
            "InfiniuZ" to "Unexpected token 'I', \"InfiniuZ\" is not valid JSON",
            "undefinfE" to "Unexpected token 'u', \"undefinfE\" is not valid JSON",
            "[object Objecu>" to "Unexpected token 'o', \"[object Objecu>\" is not valid JSON",
            // a surrogate pair in the quoted context stays one character
            "[\"😀\",x]" to "Unexpected token 'x', \"[\"😀\",x]\" is not valid JSON",
        )
        assertEquals("Nb/".hashCode(), "NaN".hashCode())
        assertEquals("InfiniuZ".hashCode(), "Infinity".hashCode())
        assertEquals("undefinfE".hashCode(), "undefined".hashCode())
        assertEquals("[object Objecu>".hashCode(), "[object Object]".hashCode())
        for ((doc, want) in rows) assertEquals(doc, want, V8Json.error(doc))
    }

    // ---- FreshAt ----

    @Test fun freshAtCounterHashCollisions() {
        val s = FreshAt.State(1, 2, 3, 4, "d")
        for (k in listOf("revocation_epodI", "ledger_tree_si{F", "budget_versipO")) assertEquals(k, 4L, s.counter(k))
        assertEquals("revocation_epoch".hashCode(), "revocation_epodI".hashCode())
        assertEquals("ledger_tree_size".hashCode(), "ledger_tree_si{F".hashCode())
        assertEquals("budget_version".hashCode(), "budget_versipO".hashCode())
    }

    @Test fun freshAtJavaStaticBridges() {
        val local = Json.parse("""{"revocation_epoch":1,"ledger_tree_size":2,"budget_version":3,"policy_revision":4,"policy_digest":"d"}""")
        val st = FreshAt.State::class.java.getMethod("fromJson", Any::class.java).invoke(null, local) as FreshAt.State?
        assertNotNull(st)
        assertEquals(4L, st!!.policyRevision)
        assertNull(FreshAt.State::class.java.getMethod("fromJson", Any::class.java).invoke(null, "x"))
        val pol = linkedMapOf<String, Any?>("signer" to "s", "scope" to "sc", "local" to local)
        val p = FreshAt.Policy::class.java.getMethod("fromJson", Any::class.java).invoke(null, pol) as FreshAt.Policy?
        assertNotNull(p)
        assertEquals("sc", p!!.scope)
        assertNull(FreshAt.Policy::class.java.getMethod("fromJson", Any::class.java).invoke(null, "x"))
    }

    // ---- Escalation ----

    @Test fun escalationRequestCarriesTheResource() {
        val action = linkedMapOf<String, Any?>("verb" to "read", "resource" to "invoice/7")
        val got = Escalation.buildRequest(null, mapOf("issuer" to "g"), linkedMapOf<String, Any?>("action" to action), null, emptyList(), 0L)
        assertEquals("invoice/7", got["resource"])
        assertEquals("read", got["verb"])
        action["resource"] = null
        assertEquals("null", Escalation.buildRequest(null, mapOf("issuer" to "g"), linkedMapOf<String, Any?>("action" to action), null, emptyList(), 0L)["resource"])
    }

    // ---- Blueprint ----

    private val bpLabel = "k05-blueprint-operator"
    private val bpOp = IntentTestKit.pub(bpLabel)
    private val bpKeys = listOf("v", "id", "key", "ceiling", "max_depth", "expires_at", "epoch", "status", "issued_at", "operator")

    private fun bpRecord(): LinkedHashMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        b["v"] = n("1"); b["id"] = "bp1"; b["key"] = "K1"; b["ceiling"] = ArrayList<Any?>(); b["epoch"] = n("1")
        b["status"] = "active"; b["issued_at"] = n("100"); b["operator"] = bpOp
        val body = LinkedHashMap<String, Any?>()
        for (k in bpKeys) if (b.containsKey(k)) body[k] = b[k]
        b["sig"] = IntentTestKit.sign(bpLabel, IntentJs.message(Blueprint.DOMAIN, body))
        return b
    }

    private fun hop(i: String, h: String) = LinkedHashMap<String, Any?>(mapOf("issuer" to i, "holder" to h))

    @Test fun blueprintIssuerLengthAndNoMaxDepth() {
        val reg = Blueprint.Registry(listOf(bpOp))
        assertNull(reg.accept(bpRecord()).code)
        // no max_depth: any depth below the blueprint hop is governed
        val deep = Blueprint.check(listOf(hop("P", "K1"), hop("K1", "a"), hop("a", "b"), hop("b", "c")), reg, n("999"), "require")
        assertEquals("allow", deep.decision)
        assertEquals(listOf("bp1"), deep.governed)
        val long = Blueprint.check(listOf(hop("P", "K1"), hop("i".repeat(129), "inst")), reg, n("999"), "any")
        assertEquals("deny", long.decision)
        assertEquals("bad_input", long.code)
        assertEquals("allow", Blueprint.check(listOf(hop("P", "K1"), hop("i".repeat(128), "inst")), reg, n("999"), "any").decision)
    }

    // ---- Passport ----

    private val now = 1_000_000L
    private val pLabel = "k05-passport-issuer"
    private val iss = IntentTestKit.pub(pLabel)
    private val sub = IntentTestKit.pub("k05-passport-subject")

    private fun identity(hw: Boolean): LinkedHashMap<String, Any?> =
        linkedMapOf("model_id" to "m1", "operator" to "op", "hardware_rooted" to hw, "weights_digest" to "wd", "weights_measured" to true)

    private fun hardware(at: Long): LinkedHashMap<String, Any?> {
        val p = identity(true)
        val pp = LinkedHashMap(p)
        pp["id"] = Passport.fingerprint(p)
        val b = linkedMapOf<String, Any?>("typ" to "atlas-pca/passport", "ver" to 1L, "passport" to pp, "iss" to iss, "sub" to sub,
            "iat" to 500_000L, "nbf" to 500_000L, "exp" to 2_000_000L, "evidence" to mapOf("document" to mapOf("nonce" to "n"), "at" to at))
        val out = LinkedHashMap(b)
        out["sig"] = IntentTestKit.sign(pLabel, IntentJs.message(Passport.SIG_DOMAIN, b))
        return out
    }

    @Test fun passportNegativeMaxAgeRefusesFutureEvidence() {
        val good: HardwareAttester = { _, _ -> Attest.Result(true, true, "", identity(true)) }
        fun opts(maxAge: Long) = Passport.Options(listOf(iss), now, 10L, maxAge, null, null, good, null, { _, _, _ -> false })
        // evidence 5 ms ahead (inside the 10 ms skew): the age tests alone pass, only maxAge < 0 refuses it
        assertEquals(null, Passport.verify(hardware(now + 5), opts(0L)).reason)
        assertEquals("hardware_evidence_stale", Passport.verify(hardware(now + 5), opts(-1L)).reason)
    }

    // ---- Obligations ----

    @Test fun obligationKindMustBeAKnownString() {
        assertEquals("unknown obligation kind '1'", Obligations.obligationError(linkedMapOf<String, Any?>("kind" to n("1"))))
        assertEquals("unknown obligation kind 'undefined'", Obligations.obligationError(linkedMapOf<String, Any?>()))
        assertNull(Obligations.obligationError(linkedMapOf<String, Any?>("kind" to "log")))
    }
}
