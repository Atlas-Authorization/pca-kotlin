package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.pub
import net.atlasauth.pca.verifier.IntentTestKit.sign
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for [Bundle] (packages/pca-grants/src/bundle.ts): version order, every shape reason with its bounds, the k-of-n
 * signature count, the verifier-version gate, rollback / chain, log heads, record inclusion and the decision-batch receiver.
 */
class Kill05LeaseBundleTest {
    private val S1 = "k05-bundle/s1"
    private val S2 = "k05-bundle/s2"
    private val L = "k05-bundle/log"
    private fun s(n: Int) = "x".repeat(n)

    private fun body(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = jm("v", 1L, "kind", "pca-policy-bundle", "revision", 1L, "issued_at", 1000L, "grants", jl("g1"), "template_digests", jl("t1"), "min_verifier_version", "1.2")
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    private fun sigOf(b: Map<String, Any?>, key: String, signer: Any? = pub(key)) =
        jm("signer", signer, "sig", sign(key, IntentJs.message(Bundle.BUNDLE_DOMAIN, K3Sig.without(b, "sigs"))))

    private fun signed(b: Map<String, Any?>, vararg keys: String): LinkedHashMap<String, Any?> =
        LinkedHashMap(b).also { m -> m["sigs"] = ArrayList<Any?>(keys.map { sigOf(b, it) }) }

    private val pinned = listOf(pub(S1), pub(S2))
    private fun ver(b: Any?, threshold: Long = 1, version: String = "1.2", last: Bundle.Last? = null) = Bundle.verify(b, pinned, threshold, version, last)

    private fun bad(v: Bundle.Verdict, code: String, reason: String) {
        assertFalse(reason, v.ok)
        assertEquals(code, v.code)
        assertEquals(reason, v.reason)
        assertEquals(0L, v.revision)
        assertEquals("", v.digest)
        assertTrue(v.signers.isEmpty())
        assertEquals(jm("ok", false, "code", code, "reason", reason), v.toJson())
    }

    private fun good(v: Bundle.Verdict, b: Map<String, Any?>, revision: Long, vararg keys: String) {
        assertTrue(v.reason, v.ok)
        assertEquals(revision, v.revision)
        assertEquals(Bundle.digest(b), v.digest)
        assertEquals(keys.map { pub(it) }, v.signers)
        assertEquals("", v.code)
        assertEquals("", v.reason)
        assertEquals(jm("ok", true, "revision", revision, "digest", Bundle.digest(b), "signers", keys.map { pub(it) }), v.toJson())
    }

    @Test fun versionOrder() {
        for ((a, b, want) in listOf(
            Triple("1.2", "1.2", 0), Triple("1.2", "1.10", -1), Triple("1.10", "1.2", 1), Triple("1", "1.0", 0), Triple("1.0", "1", 0),
            Triple("1", "1.1", -1), Triple("1.1", "1", 1), Triple("2", "10", -1), Triple("10", "9", 1), Triple("1.2.3.4", "1.2.3.5", -1),
            Triple("a", "1", 1), Triple("1", "a", 1), Triple("", "0", 0), Triple("", "1", -1), Triple("1..2", "1.0.2", 0), Triple("0.5", "0.4", 1),
            Triple("12.3", "12.30", -1), Triple("3.12", "3.2", 1), Triple(".1", "0.1", 0), Triple("1.", "1", 0),
        )) assertEquals("$a vs $b", want, Bundle.compareVersion(a, b))
    }

    @Test fun shapeReasons() {
        assertNull(Bundle.shapeError(body()))
        val nb = "not a policy bundle"
        for (x in listOf<Any?>(null, "b", jl(), body("v", 2L), body("v", "1"), body("kind", "bundle"), body("kind", null))) assertEquals(nb, Bundle.shapeError(x))
        val rt = "bad revision or time"
        for (x in listOf(body("revision", 0L), body("revision", -1L), body("revision", "1"), body("revision", Json.Num("1.5")), body("issued_at", -1L), body("issued_at", null)))
            assertEquals(rt, Bundle.shapeError(x))
        assertNull(Bundle.shapeError(body("issued_at", 0L)))
        val pv = "prev must be absent at revision 1 and present after"
        assertEquals(pv, Bundle.shapeError(body("prev", "p")))
        assertEquals(pv, Bundle.shapeError(body("prev", null)))
        assertEquals(pv, Bundle.shapeError(body("revision", 2L)))
        assertEquals(pv, Bundle.shapeError(body("revision", 2L, "prev", "")))
        assertEquals(pv, Bundle.shapeError(body("revision", 2L, "prev", s(129))))
        assertEquals(pv, Bundle.shapeError(body("revision", 2L, "prev", 5L)))
        assertNull(Bundle.shapeError(body("revision", 2L, "prev", s(128))))
        for ((k, reason) in listOf("grants" to "bad grants", "template_digests" to "bad template_digests")) {
            assertNull(k, Bundle.shapeError(body(k, jl())))
            assertNull(k, Bundle.shapeError(body(k, ArrayList<Any?>((1..4096).map { "g$it" }))))
            assertEquals(k, reason, Bundle.shapeError(body(k, ArrayList<Any?>((1..4097).map { "g$it" }))))
            assertNull(k, Bundle.shapeError(body(k, jl("a", s(128)))))
            assertEquals(k, reason, Bundle.shapeError(body(k, jl("a", s(129)))))
            assertEquals(k, reason, Bundle.shapeError(body(k, jl("a", ""))))
            assertEquals(k, reason, Bundle.shapeError(body(k, jl("a", 1L))))
            assertEquals(k, reason, Bundle.shapeError(body(k, "a")))
            assertEquals(k, reason, Bundle.shapeError(body(k, null)))
        }
        for (k in listOf("schema_digest", "constitution_digest", "flow_rules_digest")) {
            assertNull(k, Bundle.shapeError(body(k, s(128))))
            assertEquals("bad $k", Bundle.shapeError(body(k, s(129))))
            assertEquals("bad $k", Bundle.shapeError(body(k, "")))
            assertEquals("bad $k", Bundle.shapeError(body(k, null)))
            assertEquals("bad $k", Bundle.shapeError(body("schema_digest", "s", "constitution_digest", "c", "flow_rules_digest", "f", k, 3L)))
        }
        val mv = "bad min_verifier_version"
        for (v in listOf<Any?>(null, 1L, "", "1.2.3.4.5", "v1", "1234567", "1.", " 1")) assertEquals("$v", mv, Bundle.shapeError(body("min_verifier_version", v)))
        assertNull(Bundle.shapeError(body("min_verifier_version", "123456.0.0.1")))
        // shadow (optional): 1..16 distinct bounded strings
        val sh = "bad shadow"
        assertNull(Bundle.shapeError(body("shadow", jl("a"))))
        assertNull(Bundle.shapeError(body("shadow", ArrayList<Any?>((1..16).map { "s$it" }))))
        assertNull(Bundle.shapeError(body("shadow", jl("a", s(128)))))
        for (v in listOf<Any?>(null, "a", jl(), ArrayList<Any?>((1..17).map { "s$it" }), jl("a", s(129)), jl("a", ""), jl("a", 2L), jl("a", "b", "a")))
            assertEquals("$v", sh, Bundle.shapeError(body("shadow", v)))
        // the shape gate comes first in verify
        bad(ver(signed(body("shadow", jl("a", "a")), S1)), "malformed", sh)
        bad(ver(null), "malformed", nb)
    }

    @Test fun verifySignaturesAndGates() {
        val b = body()
        good(ver(signed(b, S1)), b, 1L, S1)
        good(ver(signed(b, S1, S2), threshold = 2), b, 1L, S1, S2)
        good(ver(signed(b, S2, S1), threshold = 2), b, 1L, S2, S1)
        // sigs and threshold
        bad(ver(b), "malformed", "bad sigs or threshold")
        bad(ver(LinkedHashMap(b).also { it["sigs"] = "x" }), "malformed", "bad sigs or threshold")
        bad(ver(signed(b, S1), threshold = 0), "malformed", "bad sigs or threshold")
        val full = ArrayList<Any?>(); repeat(63) { full.add("junk") }; full.add(sigOf(b, S1))
        good(ver(LinkedHashMap(b).also { it["sigs"] = full }), b, 1L, S1)
        val over = ArrayList<Any?>(full); over.add(sigOf(b, S2))
        bad(ver(LinkedHashMap(b).also { it["sigs"] = over }), "malformed", "bad sigs or threshold")
        // only distinct, pinned, string signers with a valid signature over the body count
        val mixed = jl("x", jm("signer", 5L, "sig", "s"), sigOf(b, "k05-bundle/stranger"), sigOf(b, S2, pub(S1)), jm("signer", pub(S1)), sigOf(b, S1), sigOf(b, S1))
        good(ver(LinkedHashMap(b).also { it["sigs"] = mixed }), b, 1L, S1)
        bad(ver(LinkedHashMap(b).also { it["sigs"] = mixed }, threshold = 2), "below_threshold", "1 valid pinned signature(s), need 2")
        bad(ver(LinkedHashMap(b).also { it["sigs"] = jl() }), "below_threshold", "0 valid pinned signature(s), need 1")
        bad(ver(LinkedHashMap(signed(b, S1)).also { it["grants"] = jl("g2") }), "below_threshold", "0 valid pinned signature(s), need 1")
        good(ver(signed(b, S1), threshold = 1), b, 1L, S1)
        bad(Bundle.verify(signed(b, S1, S2), listOf(pub(S2)), 2, "1.2"), "below_threshold", "1 valid pinned signature(s), need 2")
        // this verifier's version
        val nv = "needs verifier >= 1.2"
        bad(ver(signed(b, S1), version = "1.1"), "verifier_too_old", nv)
        bad(ver(signed(b, S1), version = "1"), "verifier_too_old", nv)
        bad(ver(signed(b, S1), version = "x"), "verifier_too_old", nv)
        bad(ver(signed(b, S1), version = "9.9.9.9.9"), "verifier_too_old", nv)
        good(ver(signed(b, S1), version = "1.10"), b, 1L, S1)
        good(ver(signed(b, S1), version = "1.2.0"), b, 1L, S1)
        good(ver(signed(b, S1), version = "2"), b, 1L, S1)
    }

    @Test fun rollbackAndChain() {
        val b1 = body()
        val d1 = Bundle.digest(b1)
        good(ver(signed(b1, S1), last = Bundle.Last(1, d1)), b1, 1L, S1)
        bad(ver(signed(b1, S1), last = Bundle.Last(2, d1)), "rollback", "revision 1 < accepted 2")
        bad(ver(signed(b1, S1), last = Bundle.Last(1, "other")), "broken_chain", "same revision, different content")
        val b2 = body("revision", 2L, "prev", d1, "issued_at", 2000L)
        good(ver(signed(b2, S1), last = Bundle.Last(1, d1)), b2, 2L, S1)
        bad(ver(signed(body("revision", 2L, "prev", "nope"), S1), last = Bundle.Last(1, d1)), "broken_chain", "prev does not chain to the accepted revision")
        good(ver(signed(body("revision", 3L, "prev", "anything"), S1), last = Bundle.Last(1, d1)), body("revision", 3L, "prev", "anything"), 3L, S1)
        bad(ver(signed(b2, S1), last = Bundle.Last(3, "x")), "rollback", "revision 2 < accepted 3")
        good(ver(signed(b2, S1), last = Bundle.Last(2, Bundle.digest(b2))), b2, 2L, S1)
        // the digest ignores the signatures and is that of an empty body for a non-object
        assertEquals(d1, Bundle.digest(signed(b1, S1, S2)))
        assertEquals(Pca.hashCanonical(jm("d", Bundle.BUNDLE_REF_DOMAIN, "b", b1)), d1)
        assertEquals(Pca.hashCanonical(jm("d", Bundle.BUNDLE_REF_DOMAIN, "b", jm())), Bundle.digest(null))
        assertEquals(Pca.hashCanonical(jm("d", Bundle.BUNDLE_REF_DOMAIN, "b", jm())), Bundle.digest(jl()))
        // a body at the strict depth limit signs, but its digest (one level deeper) cannot be formed: malformed, never a throw
        var deep: Any? = jl()
        repeat(30) { deep = jl(deep) }
        val bd = body("deep", deep)
        bad(ver(signed(bd, S1)), "malformed", "malformed bundle")
    }

    private fun head(size: Long, last: String, root: String = "R", key: String = L, vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = jm("v", 1L, "signer", pub(key), "size", size, "issued_at", 5L, "root", root, "last_commit", last)
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return LinkedHashMap(m).also { it["sig"] = sign(key, IntentJs.message(Bundle.LOG_HEAD_DOMAIN, m)) }
    }

    @Test fun logHeadsAndInclusion() {
        val sp = pub(L)
        assertTrue(Bundle.verifyLogHead(head(1, "c"), sp))
        assertFalse(Bundle.verifyLogHead(null, sp))
        assertFalse(Bundle.verifyLogHead(jl(), sp))
        assertFalse(Bundle.verifyLogHead(head(1, "c"), pub(S1)))
        assertFalse(Bundle.verifyLogHead(head(1, "c", key = S1), pub(L)))
        for ((k, v) in listOf<Pair<String, Any?>>("v" to 2L, "size" to -1L, "size" to "1", "issued_at" to null, "root" to 5L, "last_commit" to null))
            assertFalse("$k", Bundle.verifyLogHead(head(1, "c", "R", L, k, v), sp))
        assertFalse(Bundle.verifyLogHead(LinkedHashMap(head(1, "c")).also { it["size"] = 2L }, sp))
        assertTrue(Bundle.verifyLogHead(head(0, "", "", L, "v", Json.Num("1")), sp))
        val rec = jm("v", 1L, "seq", 0L, "prev", "", "decision", "allow")
        val commit = Bundle.recordCommit(rec)
        assertEquals(Pca.hashCanonical(jm("d", Bundle.RECORD_DOMAIN, "r", rec)), commit)
        val h = head(1, commit, Pca.merkleRoot(listOf(commit)))
        val proof = jm("index", 0L, "size", 1L, "path", jl())
        assertTrue(Bundle.verifyRecordInclusion(rec, proof, h, sp))
        assertFalse(Bundle.verifyRecordInclusion(jm("seq", 1L), proof, h, sp))
        assertFalse(Bundle.verifyRecordInclusion(rec, proof, h, pub(S1)))
        assertFalse(Bundle.verifyRecordInclusion(rec, jm("index", 1L, "size", 1L, "path", jl()), h, sp))
        assertFalse(Bundle.verifyRecordInclusion(rec, null, h, sp))
        assertFalse(Bundle.verifyRecordInclusion(rec, proof, null, sp))
        // a record the strict canonical form refuses has no commit: false, never a throw
        assertFalse(Bundle.verifyRecordInclusion(jm("seq", Json.Num("1e0")), proof, h, sp))
    }

    @Test fun batchReceiver() {
        val sp = pub(L)
        val r5 = jm("seq", 5L, "prev", "S", "x", "a")
        val c5 = Bundle.recordCommit(r5)
        val r6 = jm("seq", 6L, "prev", c5)
        val c6 = Bundle.recordCommit(r6)
        fun batch(from: Any?, records: Any?, h: Any?) = jm("from", from, "records", records, "head", h)
        fun no(v: Bundle.BatchVerdict, reason: String) {
            assertFalse(reason, v.ok)
            assertEquals(reason, v.reason)
            assertEquals(0L, v.next)
            assertEquals("", v.lastCommit)
            assertEquals(jm("ok", false, "reason", reason), v.toJson())
        }
        fun yes(v: Bundle.BatchVerdict, next: Long, last: String) {
            assertTrue(v.reason, v.ok)
            assertEquals(next, v.next)
            assertEquals(last, v.lastCommit)
            assertEquals("", v.reason)
            assertEquals(jm("ok", true, "next", next, "lastCommit", last), v.toJson())
        }
        yes(Bundle.verifyBatch(batch(5L, jl(r5, r6), head(7, c6)), 5, "S", sp), 7, c6)
        yes(Bundle.verifyBatch(batch(5L, jl(r5), head(7, c6)), 5, "S", sp), 6, c5)
        yes(Bundle.verifyBatch(batch(5L, jl(), head(9, c6)), 5, "S", sp), 5, "S")
        yes(Bundle.verifyBatch(batch(5L, jl(r5, r6), head(8, "other")), 5, "S", sp), 7, c6)
        no(Bundle.verifyBatch(null, 5, "S", sp), "malformed batch")
        no(Bundle.verifyBatch(jl(), 5, "S", sp), "malformed batch")
        no(Bundle.verifyBatch(batch(4L, jl(r5), head(7, c6)), 5, "S", sp), "gap or replay: batch starts at 4, expected 5")
        no(Bundle.verifyBatch(batch("5", jl(r5), head(7, c6)), 5, "S", sp), "gap or replay: batch starts at 5, expected 5")
        no(Bundle.verifyBatch(jm("records", jl(r5), "head", head(7, c6)), 5, "S", sp), "gap or replay: batch starts at undefined, expected 5")
        no(Bundle.verifyBatch(batch(null, jl(r5), head(7, c6)), 5, "S", sp), "gap or replay: batch starts at null, expected 5")
        no(Bundle.verifyBatch(batch(5L, jl(r5), head(7, c6, key = S1)), 5, "S", sp), "head not signed by the pinned log signer")
        no(Bundle.verifyBatch(batch(5L, jl(r5), null), 5, "S", sp), "head not signed by the pinned log signer")
        no(Bundle.verifyBatch(batch(5L, "r", head(7, c6)), 5, "S", sp), "malformed batch")
        no(Bundle.verifyBatch(batch(5L, jl(r5, "r"), head(7, c6)), 5, "S", sp), "malformed batch")
        no(Bundle.verifyBatch(batch(5L, jl(r6), head(7, c6)), 5, "S", sp), "chain broken at seq 6")
        no(Bundle.verifyBatch(batch(5L, jl(r5), head(7, c6)), 5, "T", sp), "chain broken at seq 5")
        no(Bundle.verifyBatch(batch(5L, jl(jm("prev", "S")), head(7, c6)), 5, "S", sp), "chain broken at seq undefined")
        no(Bundle.verifyBatch(batch(5L, jl(r5, r5), head(7, c6)), 5, "S", sp), "chain broken at seq 5")
        no(Bundle.verifyBatch(batch(5L, jl(r5, r6), head(6, c6)), 5, "S", sp), "batch is longer than the signed head")
        no(Bundle.verifyBatch(batch(5L, jl(r5, r6), head(7, c5)), 5, "S", sp), "batch end does not match the signed head")
        no(Bundle.verifyBatch(batch(5L, jl(r5), head(6, "other")), 5, "S", sp), "batch end does not match the signed head")
        // a record the strict canonical form refuses: malformed, never a throw
        no(Bundle.verifyBatch(batch(5L, jl(jm("seq", 5L, "prev", "S", "x", Json.Num("1e0"))), head(7, c6)), 5, "S", sp), "malformed batch")
    }
}
