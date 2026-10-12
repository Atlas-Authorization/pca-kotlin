package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.AUD
import net.atlasauth.pca.verifier.KUtil.B32
import net.atlasauth.pca.verifier.KUtil.B64
import net.atlasauth.pca.verifier.KUtil.NOW
import net.atlasauth.pca.verifier.KUtil.deep
import net.atlasauth.pca.verifier.KUtil.hopWith
import net.atlasauth.pca.verifier.KUtil.l
import net.atlasauth.pca.verifier.KUtil.ll
import net.atlasauth.pca.verifier.KUtil.m
import net.atlasauth.pca.verifier.KUtil.mm
import net.atlasauth.pca.verifier.KUtil.n
import net.atlasauth.pca.verifier.KUtil.priv
import net.atlasauth.pca.verifier.KUtil.twoHop
import net.atlasauth.pca.verifier.KUtil.valid
import net.atlasauth.pca.verifier.KUtil.validGrant
import net.atlasauth.pca.verifier.KUtil.vec
import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** Direct unit tests of the verifier's seams (mutation-kill suite; the corpus pins are in SnapshotTest). Mirrors java-pca's PcaUnitTest. */
class PcaUnitTest {
    private fun at(s: String) = assertEquals(s, s)

    @Test fun artifactSize() {
        assertFalse(Pca.artifactTooLarge(""))
        assertFalse(Pca.artifactTooLarge("a".repeat(524288)))
        assertTrue(Pca.artifactTooLarge("a".repeat(524289)))
        assertTrue(Pca.artifactTooLarge("€".repeat(174763)))
        assertFalse(Pca.artifactTooLarge("€".repeat(174762)))
    }

    @Test fun coercions() {
        assertTrue(Pca.asList("x").isEmpty())
        assertTrue(Pca.asMap("x").isEmpty())
        assertEquals("", Pca.asStr(5))
        assertEquals("s", Pca.asStr("s"))
        val li = l(1)
        assertEquals(li, Pca.asList(li))
        val mm = m("a" to 1)
        assertEquals(mm, Pca.asMap(mm))
    }

    private fun bad(b: ByteArray, off: Int): Boolean = priv(Pca, "badPointEncoding", b, off)

    @Test fun badPoint() {
        val P = KUtil.P
        assertTrue(bad(KUtil.le(P), 0))
        assertTrue(bad(KUtil.le(P.add(BigInteger.ONE)), 0))
        assertTrue(bad(KUtil.le(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE)), 0))
        assertFalse(bad(KUtil.le(P.subtract(BigInteger.TWO)), 0))
        val hi = KUtil.le(P.subtract(BigInteger.TWO)); hi[31] = (hi[31].toInt() or 0x80).toByte()
        assertFalse(bad(hi, 0))
        val hiP = KUtil.le(P); hiP[31] = (hiP[31].toInt() or 0x80).toByte()
        assertTrue(bad(hiP, 0))
        for (y in listOf(BigInteger.ONE, P.subtract(BigInteger.ONE), BigInteger.ZERO,
            BigInteger("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16),
            BigInteger("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826", 16))) {
            assertTrue(y.toString(16), bad(KUtil.le(y), 0))
            val s = KUtil.le(y); s[31] = (s[31].toInt() or 0x80).toByte()
            assertTrue("signbit " + y.toString(16), bad(s, 0))
        }
        assertFalse(bad(KUtil.le(BigInteger.TWO), 0))
        assertFalse(bad(KUtil.le(BigInteger.valueOf(3)), 0))
        val big = ByteArray(70); System.arraycopy(KUtil.le(P), 0, big, 5, 32)
        assertTrue(bad(big, 5)); assertFalse(bad(big, 6))
        val big2 = ByteArray(70); System.arraycopy(KUtil.le(BigInteger.TWO), 0, big2, 33, 32)
        assertFalse(bad(big2, 33))
        assertThrows(RuntimeException::class.java) { bad(ByteArray(40), 10) }
    }

    @Test fun ed25519() {
        val msg = byteArrayOf(1, 2, 3)
        assertFalse(Pca.ed25519Strict(null, msg, ByteArray(64)))
        assertFalse(Pca.ed25519Strict(ByteArray(32), msg, null))
        assertFalse(Pca.ed25519Strict(ByteArray(31), msg, ByteArray(64)))
        assertFalse(Pca.ed25519Strict(ByteArray(33), msg, ByteArray(64)))
        assertFalse(Pca.ed25519Strict(ByteArray(32), msg, ByteArray(63)))
        assertFalse(Pca.ed25519Strict(ByteArray(32), msg, ByteArray(65)))
        assertFalse(Pca.ed25519Strict(ByteArray(32), msg, ByteArray(64)))
        val p = valid()
        val holder = mm(ll(p["cap_chain"])[0])["holder"] as String
        val pk = Pca.decodeB64uStrict(holder, 32)!!
        val sig = Pca.decodeB64uStrict(p["sig"], 64)!!
        val tm = Pca.thresholdMessage(p)
        assertTrue(Pca.ed25519Strict(pk, tm, sig))
        assertTrue(Pca.verifyB64u(holder, tm, p["sig"] as String))
        assertFalse(Pca.verifyB64u(holder, tm, "bad"))
        assertFalse(Pca.verifyB64u("bad", tm, p["sig"] as String))
        assertFalse(Pca.verifyB64u(null, tm, p["sig"] as String))
        assertFalse(Pca.verifyB64u(holder, tm, null))
        assertFalse(Pca.ed25519Strict(pk, byteArrayOf(9), sig))
        assertFalse(Pca.ed25519Strict(pk.copyOf(33), tm, sig))
        assertFalse(Pca.ed25519Strict(pk, tm, sig.copyOf(65)))
        assertFalse(Pca.ed25519Strict(pk.copyOf(31), tm, sig))
        assertFalse(Pca.ed25519Strict(pk, tm, sig.copyOf(63)))
        val s = BigInteger(1, KUtil.rev(sig.copyOfRange(32, 64)))
        for (bad in listOf(s.add(KUtil.L), KUtil.L, KUtil.L.subtract(BigInteger.ONE), s.setBit(255))) {
            val sg = sig.clone(); System.arraycopy(KUtil.le(bad), 0, sg, 32, 32)
            assertFalse(Pca.ed25519Strict(pk, tm, sg))
        }
        val s5 = sig.clone(); s5[0] = (s5[0].toInt() xor 1).toByte()
        assertFalse(Pca.ed25519Strict(pk, tm, s5))
        // BouncyCastle repeats the strict checks (documented defence in depth)
        for (y in 0..19) for (sign in 0..1) {
            val e = KUtil.le(KUtil.P.add(BigInteger.valueOf(y.toLong()))); if (sign == 1) e[31] = (e[31].toInt() or 0x80).toByte()
            assertFalse(org.bouncycastle.math.ec.rfc8032.Ed25519.validatePublicKeyFull(e, 0))
        }
    }

    @Test fun b64u() {
        assertNull(Pca.decodeB64uStrict(5, -1)); assertNull(Pca.decodeB64uStrict(null, -1))
        assertArrayEquals(ByteArray(0), Pca.decodeB64uStrict("", -1)); assertArrayEquals(ByteArray(0), Pca.decodeB64uStrict("", 0))
        assertNull(Pca.decodeB64uStrict("AAAA", 0)); assertArrayEquals(ByteArray(3), Pca.decodeB64uStrict("AAAA", 3))
        assertNull(Pca.decodeB64uStrict("AAAA", 2)); assertNull(Pca.decodeB64uStrict("AAAA", 4)); assertNull(Pca.decodeB64uStrict("AAAAA", 3))
        assertArrayEquals(ByteArray(1), Pca.decodeB64uStrict("AA", 1)); assertArrayEquals(ByteArray(2), Pca.decodeB64uStrict("AAA", 2))
        assertNull(Pca.decodeB64uStrict("AAA", 1)); assertNull(Pca.decodeB64uStrict("AA", 2))
        for (k in 0..9) {
            val s = "A".repeat(k)
            if (k % 4 == 1) assertNull("len $k", Pca.decodeB64uStrict(s, -1)) else assertNotNull("len $k", Pca.decodeB64uStrict(s, -1))
        }
        assertNull(Pca.decodeB64uStrict("AB", -1)); assertNull(Pca.decodeB64uStrict("AAB", -1)); assertNotNull(Pca.decodeB64uStrict("AAE", -1))
        assertNotNull(Pca.decodeB64uStrict("A".repeat(43), 32)); assertNull(Pca.decodeB64uStrict("A".repeat(44), 32)); assertNull(Pca.decodeB64uStrict("A".repeat(42), 32))
        for (c in 0 until 256) {
            val ok = (c >= 'A'.code && c <= 'Z'.code) || (c >= 'a'.code && c <= 'z'.code) || (c >= '0'.code && c <= '9'.code) || c == '-'.code || c == '_'.code
            val ch = c.toChar()
            assertEquals("last $c", ok, Pca.decodeB64uStrict("AAA$ch", -1) != null)
            assertEquals("first $c", ok, Pca.decodeB64uStrict("${ch}AAA", -1) != null)
            assertEquals("mid $c", ok, Pca.decodeB64uStrict("A${ch}AA", -1) != null)
        }
        assertNull(Pca.decodeB64uStrict("AA==", -1)); assertNull(Pca.decodeB64uStrict("AA\n\n", -1))
    }

    @Test fun caveatLimits() {
        assertFalse(Pca.caveatLimitExceeded(ArrayList()))
        assertFalse(Pca.caveatLimitExceeded(l(hopWith(256))))
        assertTrue(Pca.caveatLimitExceeded(l(hopWith(257))))
        assertFalse(Pca.caveatLimitExceeded(l(hopWith(256), hopWith(256), hopWith(256), hopWith(256))))
        assertTrue(Pca.caveatLimitExceeded(l(hopWith(256), hopWith(256), hopWith(256), hopWith(256), hopWith(1))))
        assertTrue(Pca.caveatLimitExceeded(l(hopWith(205), hopWith(205), hopWith(205), hopWith(205), hopWith(205))))
        assertFalse(Pca.caveatLimitExceeded(l(hopWith(205), hopWith(205), hopWith(205), hopWith(205))))
        val many = ArrayList<Any?>(); repeat(1100) { many.add(m("caveats" to "not-a-list")) }
        assertFalse(Pca.caveatLimitExceeded(many))
        val many2 = ArrayList<Any?>(); repeat(1100) { many2.add(m()) }
        assertFalse(Pca.caveatLimitExceeded(many2))
        assertFalse(Pca.caveatLimitExceeded(l("x", 5, null, hopWith(3))))
        assertFalse(Pca.caveatLimitExceeded(l(listOf(1), hopWith(1))))
        assertEquals("chain exceeds caveat limit (max 256 per hop, 1024 per chain)", Pca.CAVEAT_LIMIT_REASON)
        assertEquals("artifact exceeds size limit (max 524288 bytes)", Pca.ARTIFACT_SIZE_REASON)
    }

    @Test fun merkleAndPlan() {
        assertEquals("empty leaf set", assertThrows(IllegalArgumentException::class.java) { Pca.merkleRoot(ArrayList()) }.message)
        assertFalse(Pca.paramsDigest(m("a" to n("1"))) == Pca.paramsDigest(null))
        assertEquals(Pca.paramsDigest(null), Pca.paramsDigest(m()))
        val action = m("verb" to "v", "resource" to "r")
        val e = assertThrows(IllegalArgumentException::class.java) { priv<Any>(Pca, "planLeaf", null, action, "c") }
        assertEquals("missing node_id", e.message)
        val leaf: Map<String, Any?> = priv(Pca, "planLeaf", "n1", action, "cond")
        assertEquals(Pca.paramsDigest(null), leaf["params_digest"]); assertEquals("reversible", leaf["reversibility_class"])
        assertEquals("cond", leaf["conditions"]); assertEquals("n1", leaf["node_id"]); assertEquals("v", leaf["verb"]); assertEquals("r", leaf["resource"])
        assertEquals(listOf("node_id", "verb", "resource", "params_digest", "reversibility_class", "conditions"), leaf.keys.toList())
        val a2 = m("verb" to "v", "resource" to "r", "params_digest" to "PD", "reversibility_class" to "irreversible")
        val l2: Map<String, Any?> = priv(Pca, "planLeaf", "n1", a2, "c")
        assertEquals("PD", l2["params_digest"]); assertEquals("irreversible", l2["reversibility_class"])
        assertEquals(Pca.hashCanonical(m("pre" to null, "post" to null)), priv<String>(Pca, "conditionsDigest", null, null))
        assertFalse(priv<String>(Pca, "conditionsDigest", "a", null) == priv<String>(Pca, "conditionsDigest", null, "a"))
    }

    @Test fun inclusion() {
        val p = valid()
        val plan = mm(p["plan"]); val action = mm(p["action"])
        val leaf: Any = priv(Pca, "planLeaf", plan["node_id"], action, plan["conditions_digest"] as String)
        val root = plan["root"] as String
        val proof = mm(plan["inclusion_proof"])
        assertTrue(Pca.verifyInclusion(root, proof, leaf))
        assertFalse(Pca.verifyInclusion(root, null, leaf))
        assertFalse(Pca.verifyInclusion(root, m("index" to n("1"), "size" to n("5")), leaf))
        assertFalse(Pca.verifyInclusion(root, m("path" to "x", "index" to n("1"), "size" to n("5")), leaf))
        for ((i, s) in listOf("1.5" to "5", "1" to "5.5", "-1" to "5", "5" to "5", "6" to "5", "0" to "0", "0" to "-1", "9007199254740992" to "9007199254740993", "-0" to "5", "0" to "-0")) {
            val pr = LinkedHashMap(proof); pr["index"] = n(i); pr["size"] = n(s)
            assertFalse("$i/$s", Pca.verifyInclusion(root, pr, leaf))
        }
        var pr = LinkedHashMap(proof); pr["index"] = "x"; assertFalse(Pca.verifyInclusion(root, pr, leaf))
        pr = LinkedHashMap(proof); pr["size"] = null; assertFalse(Pca.verifyInclusion(root, pr, leaf))
        val one = l(leaf); val r1 = Pca.merkleRoot(one)
        assertTrue(Pca.verifyInclusion(r1, m("index" to n("0"), "size" to n("1"), "path" to ArrayList<Any?>()), leaf))
        assertTrue(Pca.verifyInclusion(r1, m("index" to 0, "size" to 1L, "path" to ArrayList<Any?>()), leaf))
        assertFalse(Pca.verifyInclusion(r1, m("index" to n("1"), "size" to n("1"), "path" to ArrayList<Any?>()), leaf))
        assertFalse(Pca.verifyInclusion(r1, m("index" to n("-1"), "size" to n("1"), "path" to ArrayList<Any?>()), leaf))
        assertFalse(Pca.verifyInclusion(r1, m("index" to n("0"), "size" to n("1"), "path" to l(m("side" to "L", "hash" to B32))), leaf))
        assertFalse(Pca.verifyInclusion(r1 + "x", m("index" to n("0"), "size" to n("1"), "path" to ArrayList<Any?>()), leaf))
        val path = ll(proof["path"])
        pr = LinkedHashMap(proof); pr["path"] = ArrayList(path.subList(0, 2)); assertFalse(Pca.verifyInclusion(root, pr, leaf))
        var p2 = ArrayList(path); p2[1] = "x"; pr = LinkedHashMap(proof); pr["path"] = p2; assertFalse(Pca.verifyInclusion(root, pr, leaf))
        p2 = ArrayList(path); p2[1] = m("side" to "L", "hash" to mm(path[1])["hash"]); pr = LinkedHashMap(proof); pr["path"] = p2; assertFalse(Pca.verifyInclusion(root, pr, leaf))
        p2 = ArrayList(path); p2[2] = m("side" to "R", "hash" to "bad"); pr = LinkedHashMap(proof); pr["path"] = p2; assertFalse(Pca.verifyInclusion(root, pr, leaf))
        assertFalse(Pca.verifyInclusion("A" + root.substring(1), proof, leaf))
        assertFalse(Pca.verifyInclusion(root, proof, Any()))
        val other = m("k" to n("2"))
        val two = Pca.merkleRoot(l(m("k" to n("1")), other))
        val sib = Pca.b64(priv(Pca, "leafHash", other))
        val step = m("side" to "R", "hash" to sib)
        assertTrue(Pca.verifyInclusion(two, m("index" to n("0"), "size" to n("2"), "path" to l(step)), m("k" to n("1"))))
        assertFalse(Pca.verifyInclusion(two, m("index" to n("0"), "size" to n("2"), "path" to l(step, step)), m("k" to n("1"))))
        assertFalse(Pca.verifyInclusion(two, m("index" to n("0"), "size" to n("2"), "path" to l(m("side" to "R", "hash" to sib + "A"))), m("k" to n("1"))))
        assertEquals(listOf("R"), priv<List<String>>(Pca, "pathShape", 0L, 2L)); assertEquals(listOf("L"), priv<List<String>>(Pca, "pathShape", 1L, 2L))
        assertEquals(listOf("L", "R", "R"), priv<List<String>>(Pca, "pathShape", 1L, 5L)); assertEquals(listOf("L"), priv<List<String>>(Pca, "pathShape", 4L, 5L))
        assertEquals(listOf("R", "R", "R"), priv<List<String>>(Pca, "pathShape", 0L, 5L))
    }

    @Test fun signableHop() {
        assertNull(priv<Any?>(Pca, "signableHopBody", m("alg" to "nope")))
        assertNull(priv<Any?>(Pca, "signableHopBody", m("alg" to 5)))
        val c = m("issuer" to "i", "holder" to "h", "caveats" to ArrayList<Any?>(), "parent" to "p")
        var b: Map<String, Any?> = priv(Pca, "signableHopBody", c)
        assertEquals(listOf("issuer", "holder", "caveats", "parent"), b.keys.toList())
        c["alg"] = "ed25519"
        assertFalse(priv<Map<String, Any?>>(Pca, "signableHopBody", c).containsKey("alg"))
        c["alg"] = "ml-dsa-65"; c["pq_pk"] = "PK"
        b = priv(Pca, "signableHopBody", c)
        assertEquals("ml-dsa-65", b["alg"]); assertEquals("PK", b["pq_pk"])
        c["pq_pk"] = 5
        assertFalse(priv<Map<String, Any?>>(Pca, "signableHopBody", c).containsKey("pq_pk"))
        c["alg"] = "hybrid-ed25519-ml-dsa-65"; c["pq_pk"] = "PK"; c["holder_pq"] = "HP"
        b = priv(Pca, "signableHopBody", c)
        assertEquals("hybrid-ed25519-ml-dsa-65", b["alg"]); assertEquals("PK", b["pq_pk"]); assertEquals("HP", b["holder_pq"])
        val bo: Map<String, Any?> = priv(Pca, "bodyOf", m("issuer" to "i", "holder" to "h", "caveats" to 1, "parent" to null))
        assertEquals(4, bo.size); assertTrue(bo.containsKey("parent"))
        assertFalse(priv<Map<String, Any?>>(Pca, "bodyOf", m("issuer" to "i")).containsKey("holder_pq"))
        assertEquals("X", priv<Map<String, Any?>>(Pca, "bodyOf", m("holder_pq" to "X"))["holder_pq"])
    }

    @Test fun bindingAndPolicy() {
        val commit = Pca.holderPqCommitment("PK")
        fun pb(alg: Any?, present: Boolean, pk: Any?, committed: Any?): String? = priv(Pca, "pqBindingError", alg, present, pk, committed, "L")
        assertNull(pb("bogus", true, "PK", null)); assertNull(pb(5, true, "PK", null)); assertNull(pb(null, false, "PK", null)); assertNull(pb("ed25519", true, "PK", null))
        val noCommit = "L: suite 'ml-dsa-65' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)"
        assertEquals(noCommit, pb("ml-dsa-65", true, "PK", null))
        assertEquals(noCommit.replace("ml-dsa-65", "hybrid-ed25519-ml-dsa-65"), pb("hybrid-ed25519-ml-dsa-65", true, "PK", 5))
        val mismatch = "L: pq_pk does not match the signer's committed holder_pq (F-2)"
        assertEquals(mismatch, pb("ml-dsa-65", true, "PK2", commit)); assertEquals(mismatch, pb("ml-dsa-65", true, 5, commit)); assertEquals(mismatch, pb("ml-dsa-65", true, null, commit))
        assertNull(pb("ml-dsa-65", true, "PK", commit)); assertNull(pb("hybrid-ed25519-ml-dsa-65", true, "PK", commit))
        fun sp(alg: Any?, present: Boolean, allowed: List<String>?): String? = priv(Pca, "suitePolicyError", alg, present, "H", allowed)
        val msg = "H: signature suite is not allowed by this verifier's suite policy"
        assertNull(sp("zzz", true, null)); assertNull(sp(null, false, listOf("ed25519"))); assertEquals(msg, sp(null, false, listOf("ml-dsa-65"))); assertEquals(msg, sp(null, false, listOf()))
        assertNull(sp("ml-dsa-65", true, listOf("ml-dsa-65"))); assertEquals(msg, sp("ml-dsa-65", true, listOf("ed25519"))); assertEquals(msg, sp(5, true, listOf("ed25519", "5")))
        assertEquals(msg, sp(null, true, listOf("ed25519"))); assertNull(sp("ed25519", true, listOf("x", "ed25519")))
    }

    private fun cs(c: Map<String, Any?>, signer: String, label: String): String = priv(Pca, "checkSig", c, signer, label, null)

    @Test fun checkSigPaths() {
        val root = mm(ll(valid()["cap_chain"])[0]); val issuer = root["issuer"] as String
        assertEquals("", cs(root, issuer, "hop 0"))
        assertEquals("hop 0: bad signature (not signed by expected key)", cs(root, root["holder"] as String, "hop 0"))
        var c = LinkedHashMap(root); c["alg"] = "bogus"; assertEquals("X: unknown signature alg 'bogus'", cs(c, issuer, "X"))
        c["alg"] = 5; assertEquals("X: unknown signature alg '5'", cs(c, issuer, "X"))
        c = LinkedHashMap(root); c["caveats"] = l(Any()); assertEquals("X: malformed body", cs(c, issuer, "X"))
        c = LinkedHashMap(root); c["id"] = B32.replace('q', 'r'); assertEquals("X: body digest mismatch", cs(c, issuer, "X"))
        c = LinkedHashMap(root); c["body_digest"] = B32.replace('q', 'r'); assertEquals("X: body digest mismatch", cs(c, issuer, "X"))
        c = LinkedHashMap(root); c.remove("id"); assertEquals("X: body digest mismatch", cs(c, issuer, "X"))
        c = LinkedHashMap(root); c.remove("body_digest"); assertEquals("X: body digest mismatch", cs(c, issuer, "X"))
        c = LinkedHashMap(root); c["sig"] = B64; assertEquals("X: bad signature (not signed by expected key)", cs(c, issuer, "X"))
        c["sig"] = 5; assertEquals("X: bad signature (not signed by expected key)", cs(c, issuer, "X"))
    }

    @Test fun chain() {
        val ch = twoHop(); val issuer = mm(ch[0])["issuer"] as String
        fun vc(c: List<Any?>, exp: String = issuer, have: Boolean = true, allowed: List<String>? = null) = Pca.verifyChain(c, exp, have, allowed)
        assertEquals("", vc(ch)); assertEquals("", vc(ch, "other", false))
        assertEquals("hop 0: root issuer is not the expected principal", vc(ch, "other", true))
        assertEquals("empty chain", vc(ArrayList()))
        val big = ArrayList<Any?>(); repeat(17) { big.add(ch[0]) }
        assertEquals("chain too long (max 16 hops)", vc(big))
        val sixteen = ArrayList<Any?>(); repeat(16) { sixteen.add(ch[0]) }
        assertEquals("hop 1: broken parent link", vc(sixteen))
        assertEquals(Pca.CAVEAT_LIMIT_REASON, vc(l(hopWith(257))))
        assertEquals(Pca.CAVEAT_LIMIT_REASON, vc(l(hopWith(205), hopWith(205), hopWith(205), hopWith(205), hopWith(205))))
        var mal = ArrayList(ch); mal[1] = "x"; assertEquals("hop 1: malformed capability", vc(mal))
        mal = ArrayList(ch); mal[0] = "x"; assertEquals("hop 0: malformed capability", vc(mal))
        var d = deep(ch); mm(d[0])["parent"] = B32; assertEquals("hop 0: root must not have a parent", vc(d))
        assertEquals("hop 0: signature suite is not allowed by this verifier's suite policy", vc(ch, allowed = listOf("ml-dsa-65")))
        assertEquals("", vc(ch, allowed = listOf("ed25519")))
        d = deep(ch); mm(d[0])["sig"] = B64; assertEquals("hop 0: bad signature (not signed by expected key)", vc(d))
        d = deep(ch); mm(d[1])["parent"] = B32; assertEquals("hop 1: broken parent link", vc(d))
        d = deep(ch); mm(d[1]).remove("parent"); assertEquals("hop 1: broken parent link", vc(d))
        d = deep(ch); mm(d[0])["caveats"] = l(Any()); assertEquals("hop 0: malformed capability", vc(d)) // R6-05: reference wellTyped
        d = deep(ch); mm(d[1])["issuer"] = B32; assertEquals("hop 1: issuer is not the parent's bound holder", vc(d))
        d = deep(ch); mm(d[1])["sig"] = B64; assertEquals("hop 1: bad signature (not signed by expected key)", vc(d))
        d = deep(ch); mm(d[1])["alg"] = "ml-dsa-65"
        assertTrue(vc(d).startsWith("hop 1: suite 'ml-dsa-65' needs a PQ key bound to the signer"))
        d = deep(ch); mm(d[1])["alg"] = "bogus"; assertEquals("hop 1: unknown signature alg 'bogus'", vc(d))
        var c1 = ll(mm(vec("chain-dropped-caveat")["pcactn"])["cap_chain"])
        assertEquals("hop 1: caveat 1 altered or reordered", vc(c1, mm(c1[0])["issuer"] as String))
        c1 = ll(mm(vec("chain-reordered-caveat")["pcactn"])["cap_chain"])
        assertEquals("hop 1: caveat 0 altered or reordered", vc(c1, mm(c1[0])["issuer"] as String))
        c1 = ll(mm(vec("chain-edited-caveat")["pcactn"])["cap_chain"])
        assertTrue(vc(c1, mm(c1[0])["issuer"] as String).startsWith("hop 1: caveat "))
        val rootCap = mm(ch[0])
        val dropped = PqChainTest.signedEd(rootCap["holder"], mm(ch[1])["holder"], ArrayList(ll(rootCap["caveats"]).subList(0, 1)), Pca.capHash(rootCap), "agent", "agent")
        assertEquals("hop 1: drops parent caveat(s)", vc(l(rootCap, dropped)))
        val same = PqChainTest.signedEd(rootCap["holder"], mm(ch[1])["holder"], ArrayList(ll(rootCap["caveats"])), Pca.capHash(rootCap), "agent", "agent")
        assertEquals("", vc(l(rootCap, same)))
        val ext = ArrayList(ll(rootCap["caveats"])); ext.add(m("type" to "extra"))
        assertEquals("", vc(l(rootCap, PqChainTest.signedEd(rootCap["holder"], mm(ch[1])["holder"], ext, Pca.capHash(rootCap), "agent", "agent"))))
        d = deep(ch); mm(d[1])["caveats"] = l(Any(), Any()); assertEquals("hop 1: malformed capability", vc(d))
        val dc = PqChainTest.twoHopOf("valid-chain-at-depth-cap-16")
        assertEquals("", vc(dc, "ignored", false)); assertEquals("", vc(dc, mm(dc[0])["issuer"] as String, true))
        // root PQ refusal / non-string handling
        val pk = "A".repeat(2603)
        for (alg in listOf("ml-dsa-65", "hybrid-ed25519-ml-dsa-65")) {
            val r = LinkedHashMap(rootCap); r["alg"] = alg; r["pq_pk"] = pk
            val want = "hop 0: root suite '$alg' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)"
            fun vr(pins: Map<String, Any?>?, trusted: Map<String, Any?>?, rr: Map<String, Any?> = r, ex: String = issuer, have: Boolean = true) = Pca.verifyChain(l(rr), ex, have, null, pins, trusted)
            assertEquals(want, vr(null, null)); assertEquals(want, vr(m(), null)); assertEquals(want, vr(m(issuer to "other"), null)); assertEquals(want, vr(m(issuer to 5), null))
            assertEquals(want, vr(null, rootCap))
            val rn = LinkedHashMap(r); rn["issuer"] = 5
            assertEquals("hop 0: malformed capability", vr(m("5" to pk), null, rn, "", false))
            val rno = LinkedHashMap(r); rno.remove("pq_pk"); assertEquals(want, vr(m(issuer to pk), null, rno))
            val rnum = LinkedHashMap(r); rnum["pq_pk"] = 5; assertEquals("hop 0: malformed capability", vr(null, rnum, rnum))
            assertEquals("hop 0: body digest mismatch", vr(m(issuer to pk), null)); assertEquals("hop 0: body digest mismatch", vr(null, r))
            val bt = LinkedHashMap(r); bt["zz"] = Any(); assertEquals(want, vr(null, bt))
        }
        val bogus = LinkedHashMap(rootCap); bogus["alg"] = "bogus"
        assertEquals("hop 0: unknown signature alg 'bogus'", vc(l(bogus)))
        bogus["alg"] = 7; assertEquals("hop 0: malformed capability", vc(l(bogus)))
        val weirdRoot = LinkedHashMap(rootCap); weirdRoot["zz"] = Any()
        assertEquals("hop 1: broken parent link", vc(l(weirdRoot, ch[1])))
        val numRoot = PqChainTest.signedEd(rootCap["issuer"], 5, ArrayList(), null, "principal", "agent")
        val kid = PqChainTest.signedEd(5, mm(ch[1])["holder"], ArrayList(), Pca.capHash(numRoot), "agent", "agent")
        assertEquals("hop 0: malformed capability", vc(l(numRoot, kid)))
    }

    @Test fun wireTop() {
        assertNull(Pca.validateWireV2(valid()))
        assertEquals("PCActn is not an object", Pca.validateWireV2("x")); assertEquals("PCActn is not an object", Pca.validateWireV2(null))
        var p = valid(); p["zzz"] = n("1"); assertEquals("unknown field 'zzz'", Pca.validateWireV2(p))
        for (k in listOf("ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig")) {
            p = valid(); p.remove(k); assertEquals(k, "missing field '$k'", Pca.validateWireV2(p))
        }
        for (k in listOf("ver", "counter", "iat", "exp")) {
            p = valid(); p[k] = n("1.5"); assertEquals(k, "'$k' must be a safe integer", Pca.validateWireV2(p))
            p = valid(); p[k] = "1"; assertEquals(k, "'$k' must be a safe integer", Pca.validateWireV2(p))
        }
        p = valid(); p["counter"] = n("1.50"); assertEquals("canonicalize: trailing fractional zero is not canonical", Pca.validateWireV2(p))
        p = valid(); p["sig"] = "\ud800"; assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", Pca.validateWireV2(p))
        p = valid(); p["threshold"] = m("shares" to ArrayList<Any?>(), "extra" to n("1e5")); assertNull(Pca.validateWireV2(p))
        p = valid(); p["aud"] = ""; assertEquals("'aud' must be a non-empty string", Pca.validateWireV2(p))
        p = valid(); p["aud"] = n("1"); assertEquals("'aud' must be a non-empty string", Pca.validateWireV2(p))
        p = valid(); p["aud"] = "x".repeat(256); assertNull(Pca.validateWireV2(p))
        p = valid(); p["aud"] = "x".repeat(257); assertEquals("'aud' must be a non-empty string", Pca.validateWireV2(p))
        p = valid(); p["aud"] = "€".repeat(85); assertNull(Pca.validateWireV2(p))
        p = valid(); p["aud"] = "€".repeat(86); assertEquals("'aud' must be a non-empty string", Pca.validateWireV2(p))
        p = valid(); p["nonce"] = "n".repeat(128); assertNull(Pca.validateWireV2(p))
        p = valid(); p["nonce"] = "n".repeat(129); assertEquals("'nonce' must be a non-empty string", Pca.validateWireV2(p))
        p = valid(); p["nonce"] = ""; assertEquals("'nonce' must be a non-empty string", Pca.validateWireV2(p))
        p = valid(); p["nonce"] = n("1"); assertEquals("'nonce' must be a non-empty string", Pca.validateWireV2(p))
        p = valid(); p["nonce"] = "€".repeat(42); assertNull(Pca.validateWireV2(p))
        p = valid(); p["nonce"] = "€".repeat(43); assertEquals("'nonce' must be a non-empty string", Pca.validateWireV2(p))
        p = valid(); p["grant_ref"] = "x"; assertEquals("'grant_ref' is not canonical base64url (32 bytes)", Pca.validateWireV2(p))
        p = valid(); p["alg"] = 5; assertEquals("'alg' must be a string", Pca.validateWireV2(p))
        p = valid(); p["alg"] = "bogus"; assertEquals("unknown signature alg 'bogus'", Pca.validateWireV2(p))
        p = valid(); p["pq_pk"] = B32; assertEquals("'pq_pk' must be absent for alg 'ed25519'", Pca.validateWireV2(p))
        p = valid(); p["pq_sig"] = B32; assertEquals("'pq_sig' must be absent for alg 'ed25519'", Pca.validateWireV2(p))
        p = valid(); p["alg"] = "ml-dsa-65"; assertEquals("'sig' is not canonical base64url (3309 bytes) for alg 'ml-dsa-65'", Pca.validateWireV2(p))
        val pk = "A".repeat(2603); val sg = "A".repeat(4412)
        p = valid(); p["alg"] = "hybrid-ed25519-ml-dsa-65"; p["pq_pk"] = pk; p["pq_sig"] = sg; assertNull(Pca.validateWireV2(p))
        p["pq_sig"] = "\ud800"; assertEquals("'pq_sig' is not canonical base64url (3309 bytes)", Pca.validateWireV2(p))
        p["pq_sig"] = sg; p["pq_pk"] = "x"; assertEquals("'pq_pk' is not canonical base64url (1952 bytes)", Pca.validateWireV2(p))
        p["pq_pk"] = pk; p.remove("pq_sig"); assertEquals("'pq_sig' is not canonical base64url (3309 bytes)", Pca.validateWireV2(p))
        p = valid(); p["alg"] = "ml-dsa-65"; p["pq_pk"] = pk; p["sig"] = sg; assertNull(Pca.validateWireV2(p))
        p["pq_sig"] = sg; assertEquals("'pq_sig' must be absent for alg 'ml-dsa-65'", Pca.validateWireV2(p))
    }

    @Test fun wireNested() {
        fun w(f: (MutableMap<String, Any?>) -> Unit): String? { val p = valid(); f(p); return Pca.validateWireV2(p) }
        fun act(p: MutableMap<String, Any?>) = mm(p["action"])
        fun pl(p: MutableMap<String, Any?>) = mm(p["plan"])
        fun ip(p: MutableMap<String, Any?>) = mm(pl(p)["inclusion_proof"])
        fun hop(p: MutableMap<String, Any?>) = mm(ll(p["cap_chain"])[0])
        assertEquals("unknown field 'action.zz'", w { act(it)["zz"] = "x" })
        assertEquals("'action' must be an object", w { it["action"] = "x" })
        for (k in listOf("verb", "resource", "reversibility_class")) assertEquals(k, "action.verb/resource/reversibility_class must be strings", w { act(it)[k] = n("1") })
        assertEquals("'action.params_digest' is not canonical base64url (32 bytes)", w { act(it)["params_digest"] = "x" })
        assertEquals("'plan' must be an object", w { it["plan"] = "x" })
        assertEquals("unknown field 'plan.zz'", w { pl(it)["zz"] = "x" })
        assertEquals("'plan.root' is not canonical base64url (32 bytes)", w { pl(it)["root"] = "x" })
        assertEquals("'plan.node_id' must be a string", w { pl(it)["node_id"] = n("1") })
        assertEquals("'plan.conditions_digest' must be a canonical base64url string (32 bytes)", w { pl(it)["conditions_digest"] = "x" })
        assertNull(w { pl(it).remove("conditions_digest") })
        assertEquals("'plan.inclusion_proof' must be an object", w { pl(it)["inclusion_proof"] = "x" })
        assertEquals("unknown field 'plan.inclusion_proof.zz'", w { ip(it)["zz"] = "x" })
        assertEquals("'plan.inclusion_proof.index' must be a safe integer", w { ip(it)["index"] = "x" })
        assertEquals("'plan.inclusion_proof.size' must be a safe integer", w { ip(it)["size"] = "x" })
        assertEquals("'plan.inclusion_proof.path' must be an array", w { ip(it)["path"] = "x" })
        assertEquals("proof step 1 must be an object", w { ll(ip(it)["path"])[1] = "x" })
        assertEquals("unknown field 'path[2].zz'", w { mm(ll(ip(it)["path"])[2])["zz"] = "x" })
        assertEquals("proof step 1: side must be 'L' or 'R'", w { mm(ll(ip(it)["path"])[1])["side"] = "X" })
        assertNull(w { mm(ll(ip(it)["path"])[0])["side"] = "R" })
        assertEquals("proof step 1: hash is not canonical base64url (32 bytes)", w { mm(ll(ip(it)["path"])[1])["hash"] = "x" })
        assertEquals("'cap_chain' must be an array", w { it["cap_chain"] = "x" })
        assertEquals("cap_chain[0] must be an object", w { ll(it["cap_chain"])[0] = "x" })
        assertEquals("unknown field 'cap_chain[0].zz'", w { hop(it)["zz"] = "x" })
        for (k in listOf("id", "issuer", "holder", "body_digest")) assertEquals(k, "cap_chain[0].$k is not canonical base64url (32 bytes)", w { hop(it)[k] = "x" })
        assertEquals("cap_chain[0]: unknown signature alg 'bogus'", w { hop(it)["alg"] = "bogus" })
        assertEquals("cap_chain[0].parent is not canonical base64url (32 bytes)", w { hop(it)["parent"] = "x" })
        assertNull(w { hop(it)["parent"] = B32 })
        assertEquals("cap_chain[0].holder_pq is not canonical base64url (32 bytes)", w { hop(it)["holder_pq"] = "x" })
        assertNull(w { hop(it)["holder_pq"] = B32 })
        assertEquals("cap_chain[0].caveats must be an array of {type,...} objects", w { hop(it)["caveats"] = "x" })
        assertEquals("cap_chain[0].caveats must be an array of {type,...} objects", w { ll(hop(it)["caveats"])[1] = "x" })
        assertEquals("cap_chain[0].caveats must be an array of {type,...} objects", w { mm(ll(hop(it)["caveats"])[1])["type"] = n("1") })
        assertEquals("'attestation' must be an object with an integer 'epoch'", w { it["attestation"] = "x" })
        assertEquals("'attestation' must be an object with an integer 'epoch'", w { mm(it["attestation"])["epoch"] = "x" })
        for (k in listOf("quote_digest", "model_id", "measurement", "operator")) assertEquals(k, "attestation string fields must be strings", w { mm(it["attestation"])[k] = n("1") })
        assertEquals("'provenance' is malformed", w { it["provenance"] = "x" })
        assertEquals("'provenance' is malformed", w { mm(it["provenance"])["causal_hash"] = n("1") })
        assertEquals("'provenance' is malformed", w { mm(it["provenance"])["taint_level"] = "x" })
        assertEquals("'provenance' is malformed", w { mm(it["provenance"])["trusted_refs"] = "x" })
        assertEquals("'provenance' is malformed", w { mm(it["provenance"])["trusted_refs"] = l("a", n("1")) })
        assertNull(w { mm(it["provenance"])["trusted_refs"] = l("a", "b") })
        assertNull(w { mm(it["provenance"])["taint_level"] = n("0.5") })
        assertEquals("'freshness' is malformed", w { it["freshness"] = "x" })
        assertEquals("'freshness' is malformed", w { mm(it["freshness"])["epoch"] = "x" })
        assertEquals("'freshness' is malformed", w { mm(it["freshness"])["beacon_ref"] = n("1") })
        assertEquals("'freshness' is malformed", w { mm(it["freshness"])["accumulator_witness"] = n("1") })
        assertEquals("'risk_claim' is malformed", w { it["risk_claim"] = "x" })
        assertEquals("'risk_claim' is malformed", w { mm(it["risk_claim"])["r"] = "x" })
        assertEquals("'risk_claim' is malformed", w { mm(it["risk_claim"])["inputs"] = "x" })
        for ((c, ok) in listOf("0" to true, "1" to true, "0.5" to true, "0.000001" to true, "-0.5" to false, "1.5" to false, "2" to false, "-1" to false))
            assertEquals(c, if (ok) null else "'caution' must be a number in [0,1]", w { it["caution"] = n(c) })
        assertEquals("'caution' must be a number in [0,1]", w { it["caution"] = "x" })
        assertEquals("'rationale_commitment' is not canonical base64url (32 bytes)", w { it["rationale_commitment"] = "x" })
        assertNull(w { it["rationale_commitment"] = B32 })
        assertEquals("'tool_binding' is not canonical base64url (32 bytes)", w { it["tool_binding"] = "x" })
        assertNull(w { it["tool_binding"] = B32 })
        assertEquals("'progress_step' must be an object", w { it["progress_step"] = "x" })
        assertNull(w { it["progress_step"] = m() })
        assertEquals("'prohibition_evidence' must be an object or array", w { it["prohibition_evidence"] = "x" })
        assertNull(w { it["prohibition_evidence"] = ArrayList<Any?>() }); assertNull(w { it["prohibition_evidence"] = m() })
        assertEquals("'threshold' must be {shares:[...]}", w { it["threshold"] = "x" })
        assertEquals("'threshold' must be {shares:[...]}", w { it["threshold"] = m("shares" to "x") })
        assertEquals("'threshold' must be {shares:[...]}", w { it["threshold"] = m() })
        assertEquals("threshold.shares[0] is malformed", w { it["threshold"] = m("shares" to l("x")) })
        assertEquals("threshold.shares[0] is malformed", w { it["threshold"] = m("shares" to l(m("role" to n("1")))) })
        val good = m("role" to "agent", "publicKey" to B32, "sig" to B64)
        assertNull(w { it["threshold"] = m("shares" to l(good)) })
        assertEquals("threshold.shares[1].publicKey is not canonical base64url (32 bytes)", w { it["threshold"] = m("shares" to l(good, m("role" to "x"))) })
        assertEquals("threshold.shares[1].sig is not canonical base64url (64 bytes)", w { it["threshold"] = m("shares" to l(good, m("role" to "x", "publicKey" to B32))) })
        assertEquals("threshold.shares[0].publicKey is not canonical base64url (32 bytes)", w { it["threshold"] = m("shares" to l(m("role" to "x", "publicKey" to "bad", "sig" to B64), good)) })
        val weird = LinkedHashMap<Any, Any?>(); weird[5] = "x"
        assertTrue(Pca.validateWireV2(weird)!!.startsWith("malformed: java.lang.ClassCastException"))
    }

    @Test fun verifyApi() {
        val raw = vec("valid-raw-json-format-insensitive")["pcactn_json"] as String
        var g = Pca.verifyPcactnJson(raw, validGrant(), NOW, KUtil.Of)
        assertTrue(g.allow); assertEquals("", g.reason)
        assertEquals(listOf("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter"), g.checks.keys.toList())
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, KUtil.Of); assertTrue(g.allow)
        // audience tri-state
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, Pca.Audience.Any); assertTrue(g.allow)
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, Pca.Audience.Unset)
        assertFalse(g.allow); assertEquals("audience: PCActn carries a signed aud but this verifier supplied no audience", g.reason)
        assertEquals(false, g.checks["audience"]); assertEquals(true, g.checks["counter"]); assertEquals(true, g.checks["leaf_signature"])
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, Pca.Audience.Of("other"))
        assertEquals("audience: aud does not match this resource server / instance", g.reason)
        // wire
        g = Pca.verifyPcactn("x", validGrant(), NOW, KUtil.Of); assertEquals("wire: PCActn is not an object", g.reason)
        assertEquals(listOf("wire"), g.checks.keys.toList()); assertEquals(false, g.checks["wire"])
        g = Pca.verifyPcactnJson(" ".repeat(524289), validGrant(), NOW, KUtil.Of); assertEquals("wire: artifact exceeds size limit (max 524288 bytes)", g.reason)
        assertTrue(Pca.verifyPcactnJson(raw + " ".repeat(10), validGrant(), NOW, KUtil.Of).allow)
        g = Pca.verifyPcactnJson("{", validGrant(), NOW, KUtil.Of); assertEquals("wire: strict JSON: expected key at 1", g.reason)
        var p = mm(Json.parse(raw)); p["ver"] = n("3")
        assertEquals("version: unsupported ver (this verifier requires 2)", Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).reason)
        val iat = 1800000000000L
        p = mm(Json.parse(raw)); p["exp"] = n("$iat")
        assertEquals("validity: exp must be greater than iat", Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).reason)
        p["exp"] = n("${iat + 3600001}"); assertEquals("validity: lifetime exceeds 3600000 ms", Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).reason)
        p["exp"] = n("${iat + 3600000}"); assertEquals(true, Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).checks["validity"])
        p["exp"] = n("${iat + 600000}")
        assertEquals("validity: iat is in the future (clock skew)", Pca.verifyPcactn(p, validGrant(), NOW - 60001, KUtil.Of).reason)
        assertEquals(true, Pca.verifyPcactn(p, validGrant(), NOW - 60000, KUtil.Of).checks["validity"])
        assertEquals("validity: the PCActn has expired", Pca.verifyPcactn(p, validGrant(), iat + 600001, KUtil.Of).reason)
        assertEquals(true, Pca.verifyPcactn(p, validGrant(), iat + 600000, KUtil.Of).checks["validity"])
        p = mm(Json.parse(raw)); p["counter"] = n("-1")
        g = Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of)
        assertEquals(false, g.checks["counter"]); assertEquals("leaf_signature: signature does not verify under the leaf holder key", g.reason)
        p["counter"] = n("0"); assertEquals(true, Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).checks["counter"])
        p = mm(Json.parse(raw)); p["cap_chain"] = ArrayList<Any?>()
        g = Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of)
        assertEquals("chain: empty chain", g.reason)
        assertEquals(listOf(false, false, false, true, true), listOf(g.checks["chain"], g.checks["grant_ref_bound"], g.checks["leaf_signature"], g.checks["plan_inclusion"], g.checks["counter"]))
        p = mm(Json.parse(raw)); val first = ll(p["cap_chain"])[0]
        p["cap_chain"] = ArrayList<Any?>().also { c -> repeat(17) { c.add(first) } }
        assertEquals("chain: chain too long (max 16 hops)", Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).reason)
        p["cap_chain"] = ArrayList<Any?>().also { c -> repeat(16) { c.add(first) } }
        assertEquals("chain: hop 1: broken parent link", Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).reason)
        p = mm(Json.parse(raw)); mm(ll(p["cap_chain"])[0])["caveats"] = ArrayList<Any?>().also { c -> repeat(257) { c.add(m("type" to "t")) } }
        assertEquals("chain: " + Pca.CAVEAT_LIMIT_REASON, Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).reason)
        p = mm(Json.parse(raw)); val g2 = LinkedHashMap(validGrant()); g2["holder"] = B32
        assertEquals("chain: chain root is not the grant", Pca.verifyPcactn(p, g2, NOW, KUtil.Of).reason)
        val g4 = LinkedHashMap(validGrant()); g4["weird"] = Any()
        g = Pca.verifyPcactn(Json.parse(raw), g4, NOW, KUtil.Of)
        assertTrue(g.reason, g.reason.startsWith("malformed PCActn: java.lang.IllegalArgumentException: canonicalize: unsupported type")); assertFalse(g.allow)
        assertEquals(true, g.checks["wire"]); assertEquals(true, g.checks["version"]); assertEquals(false, g.checks["chain"]); assertEquals(false, g.checks["counter"]); assertEquals(false, g.checks["leaf_signature"])
        p = mm(Json.parse(raw)); p["ver"] = n("3")
        assertEquals("version: unsupported ver (this verifier requires 2)", Pca.verifyPcactn(p, g4, NOW, KUtil.Of).reason)
        p = mm(Json.parse(raw)); p["grant_ref"] = B32.replace('q', 'r')
        g = Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of)
        assertEquals(false, g.checks["grant_ref_bound"]); assertEquals("grant_ref_bound: grant_ref is not the id of the root capability in cap_chain", g.reason)
        p = mm(Json.parse(raw)); mm(p["action"])["verb"] = "other"
        assertEquals("plan_inclusion: action is not a node of the committed plan", Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).reason)
        p = mm(Json.parse(raw)); mm(p["plan"])["node_id"] = "n2x"; assertEquals(false, Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).checks["plan_inclusion"])
        p = mm(Json.parse(raw)); mm(p["plan"]).remove("conditions_digest"); assertEquals(true, Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).checks["plan_inclusion"])
        p = mm(Json.parse(raw)); p["sig"] = B64
        assertEquals("leaf_signature: signature does not verify under the leaf holder key", Pca.verifyPcactn(p, validGrant(), NOW, KUtil.Of).reason)
        g = Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, KUtil.Of, listOf())
        assertEquals("chain: hop 0: signature suite is not allowed by this verifier's suite policy", g.reason); assertEquals(false, g.checks["leaf_signature"])
        assertTrue(Pca.verifyPcactn(Json.parse(raw), validGrant(), NOW, KUtil.Of, listOf("ed25519")).allow)
        // Verdict.fail keeps the FIRST reason
        val v = Pca.Verdict(); assertEquals("", v.reason); assertFalse(v.allow)
        v.fail("chain", "bad"); assertEquals("chain: bad", v.reason); assertEquals(false, v.checks["chain"])
        v.fail("audience", "worse"); assertEquals("chain: bad", v.reason); assertEquals(false, v.checks["audience"])
    }

    @Test fun thresholdMessageShape() {
        val p = valid(); val a = Pca.thresholdMessage(p)
        p["threshold"] = m("shares" to ArrayList<Any?>()); p["pq_sig"] = "zz"; p["sig"] = "other"
        assertArrayEquals(a, Pca.thresholdMessage(p))
        p["alg"] = "ed25519"; assertFalse(a.contentEquals(Pca.thresholdMessage(p)))
        assertArrayEquals("atlas-pca/actn/v2\u0000".toByteArray(), a.copyOf(18)); assertEquals(18 + 32, a.size)
    }

    @Test fun hashing() {
        assertEquals("AVq9f1zFei3ZS3WQ8ErYCEJzkF7jPsXOvq5iJ2qX-GI", Pca.hashStrict(m("a" to n("1"))))
        assertEquals("AVq9f1zFei3ZS3WQ8ErYCEJzkF7jPsXOvq5iJ2qX-GI", Pca.hashCanonical(m("a" to n("1"))))
        // protocol digests are strict (hash.ts canonicalBytes): a non-canonical lexeme is refused, not hashed as its value
        assertEquals("canonicalize: trailing fractional zero is not canonical", assertThrows(IllegalArgumentException::class.java) { Pca.hashCanonical(m("a" to n("1.0"))) }.message)
        assertThrows(IllegalArgumentException::class.java) { Pca.hashStrict(m("a" to n("1.0"))) }
        assertEquals(Pca.capHash(m("a" to n("1"))), Pca.hashCanonical(m("a" to n("1"))))
        assertEquals(2, Pca.concat(ByteArray(1), ByteArray(1)).size)
        assertEquals("AQID", Pca.b64(byteArrayOf(1, 2, 3))); assertEquals("AQI", Pca.b64(byteArrayOf(1, 2)))
        assertArrayEquals(Pca.sha(byteArrayOf(1, 2)), Pca.sha(byteArrayOf(1), byteArrayOf(2)))
        assertEquals("reversible", Pca.DEFAULT_REV); assertEquals(16, Pca.MAX_CHAIN_HOPS); assertEquals(2L, Pca.WIRE_VERSION)
        assertEquals(3_600_000L, Pca.MAX_LIFETIME_MS); assertEquals(60_000L, Pca.MAX_SKEW_MS); assertEquals(256, Pca.MAX_AUD_LEN); assertEquals(128, Pca.MAX_NONCE_LEN)
        assertEquals(256, Pca.MAX_CAVEATS_PER_HOP); assertEquals(1024, Pca.MAX_CAVEATS_PER_CHAIN); assertEquals(524288, Pca.MAX_ARTIFACT_BYTES)
    }
}
