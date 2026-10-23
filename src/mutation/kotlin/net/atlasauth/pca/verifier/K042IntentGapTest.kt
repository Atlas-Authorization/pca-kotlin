package net.atlasauth.pca.verifier

import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** Gap kills for IntentJs / ActionSchema / IntentV2 context validation / IntentMap audit paths / Pq guards. */
@Suppress("UNCHECKED_CAST")
class K042IntentGapTest {
    private fun map(vararg kv: Pair<String, Any?>) = linkedMapOf(*kv)
    private fun n(s: String) = Json.Num(s)

    private fun refLen(s: String): Int {
        var len = 0; var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c.code < 0x80) len += 1
            else if (c.code < 0x800) len += 2
            else if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { len += 4; i++ }
            else len += 3
            i++
        }
        return len
    }

    @Test fun u8lenAgreesWithTheReferenceOverAllShortStrings() {
        val alpha = charArrayOf('a', 'é', '€', '\ud800', '\udbff', '\udc00', '\udfff', '\u007f', '\u0080', '߿', 'ࠀ', '￿')
        val all = ArrayList<String>(); all.add("")
        var prev = listOf("")
        for (len in 1..4) { val next = prev.flatMap { p -> alpha.map { p + it } }; all.addAll(next); prev = next }
        for (s in all) assertEquals("u8len", refLen(s), IntentJs.u8len(s))
        assertEquals(5, IntentJs.u8len("é\udc00")); assertEquals(4, IntentJs.u8len("a\udc00"))
        assertEquals(4, IntentJs.u8len("😀")); assertEquals(6, IntentJs.u8len("\ud83d\ud83d"))
    }

    private class BoomMap : AbstractMap<String, Any?>() {
        override val entries: Set<Map.Entry<String, Any?>> get() = throw IllegalStateException("boom")
        override fun containsKey(key: String): Boolean = throw IllegalStateException("boom")
        override fun get(key: String): Any? = throw IllegalStateException("boom")
    }

    @Test fun actionSchemaVerifyFailsClosedWithTheCause() {
        val ok = K042ActionSchemaTest.cases("verify").first { it["name"] == "verify/valid" }
        val doc = K042ActionSchemaTest.j(ok["doc"])
        assertNull(ActionSchema.verify(doc, K042ActionSchemaTest.j(ok["keys"])))
        assertEquals("schema verification error: boom", ActionSchema.verify(doc, arrayListOf<Any?>(BoomMap())))
    }

    private fun ctxErr(json: Any?) = IntentV2.contextError(IntentV2.Context.fromJson(json))

    @Test fun policyMembersAreOptionalAndTyped() {
        assertNull(ctxErr(map("policy" to map("schema" to map()))))
        assertNull(ctxErr(map("policy" to map("session" to map()))))
        assertNull(ctxErr(map("policy" to map("acc" to map()))))
        assertNull(ctxErr(map("policy" to map("map" to map()))))
        assertNull(ctxErr(map("policy" to map("schema" to map("closed_world" to true)))))
        assertEquals("policy.schema.closed_world must be a boolean", ctxErr(map("policy" to map("schema" to map("closed_world" to "x")))))
        assertEquals("policy.schema.closed_world must be a boolean", ctxErr(map("policy" to map("schema" to map("closed_world" to null)))))
        assertEquals("policy.session.require must be a boolean", ctxErr(map("policy" to map("session" to map("require" to "x")))))
        assertEquals("policy.map.require must be a boolean", ctxErr(map("policy" to map("map" to map("require" to null)))))
        assertEquals("policy.acc.max_receipt_age_s must be a non-negative safe integer", ctxErr(map("policy" to map("acc" to map("max_receipt_age_s" to "x")))))
        assertEquals("policy.acc.max_keyset_age_s must be a non-negative safe integer", ctxErr(map("policy" to map("acc" to map("max_keyset_age_s" to n("-1"))))))
        assertNull(ctxErr(map("policy" to map("acc" to map("max_receipt_age_s" to n("0"), "max_keyset_age_s" to n("5"))))))
        assertNull(ctxErr(map("wb" to map("artifacts" to map()))))
        assertNull(ctxErr(map("wb" to map("policy" to map()))))
        assertNull(ctxErr(map("wb" to map("artifacts" to map("offer_set" to map())))))
        assertNull(ctxErr(map("layers" to map("site" to map("predicates" to ArrayList<Any?>())))))
        assertEquals("layers.site must be {predicates: [...]}", ctxErr(map("layers" to map("site" to "x"))))
        assertEquals("layers.site must be {predicates: [...]}", ctxErr(map("layers" to map("site" to map()))))
        assertEquals("layers.site must be {predicates: [...]}", ctxErr(map("layers" to map("site" to map("predicates" to map())))))
        for (k in listOf("facts", "labels", "verdicts")) assertEquals("wb.artifacts.$k must be an array", ctxErr(map("wb" to map("artifacts" to map(k to "x")))))
        assertEquals("wb.artifacts.offer_set must be an object", ctxErr(map("wb" to map("artifacts" to map("offer_set" to ArrayList<Any?>())))))
        assertEquals("wb.policy.world / provenance must be objects", ctxErr(map("wb" to map("policy" to map("world" to "x")))))
        assertEquals("wb.policy.world / provenance must be objects", ctxErr(map("wb" to map("policy" to map("provenance" to "x")))))
        assertEquals("wb.policy.classifiers must be an array", ctxErr(map("wb" to map("policy" to map("classifiers" to map())))))
        assertEquals("wb.artifacts must be an object", ctxErr(map("wb" to map("artifacts" to "x"))))
        assertEquals("wb.policy must be an object", ctxErr(map("wb" to map("policy" to "x"))))
        for (k in listOf("schema", "session", "acc")) assertEquals("$k must be an object", ctxErr(map(k to "x")))
        assertEquals("params must be an object", ctxErr(map("params" to "x")))
        assertEquals("map must be an object", ctxErr(map("map" to "x")))
        assertEquals("map: unknown member 'zz'", ctxErr(map("map" to map("zz" to n("1")))))
        assertEquals("policy: unknown member 'zz'", ctxErr(map("policy" to map("zz" to n("1")))))
        assertEquals("layers: unknown member 'zz'", ctxErr(map("layers" to map("zz" to map("predicates" to ArrayList<Any?>())))))
        assertNull(ctxErr(map("schema" to map())))
    }

    // ---- RFC 9162 audit paths against an independent reference tree ----
    private fun leaf(i: Int) = MessageDigest.getInstance("SHA-256").digest("leaf-$i".toByteArray())
    private fun mth(d: List<ByteArray>): ByteArray {
        if (d.size == 1) return d[0]
        var k = 1; while (k * 2 < d.size) k *= 2
        return IntentMap.nodeHash(mth(d.subList(0, k)), mth(d.subList(k, d.size)))
    }
    private fun path(m: Int, d: List<ByteArray>): MutableList<ByteArray> {
        if (d.size == 1) return ArrayList()
        var k = 1; while (k * 2 < d.size) k *= 2
        val out: MutableList<ByteArray>
        if (m < k) { out = path(m, d.subList(0, k)); out.add(mth(d.subList(k, d.size))) }
        else { out = path(m - k, d.subList(k, d.size)); out.add(mth(d.subList(0, k))) }
        return out
    }

    @Test fun auditPathsFoldToTheTreeRootForEverySizeAndLeaf() {
        for (n in 1..70) {
            val d = (0 until n).map { leaf(it) }
            val root = mth(d)
            for (m in 0 until n) {
                val p = path(m, d)
                val got = IntentMap.rootFromPath(m.toLong(), n.toLong(), d[m], p)
                assertNotNull("n=$n m=$m", got); assertArrayEquals("n=$n m=$m", root, got)
                assertNull("long n=$n m=$m", IntentMap.rootFromPath(m.toLong(), n.toLong(), d[m], p + leaf(999)))
                if (p.isNotEmpty()) assertNull("short n=$n m=$m", IntentMap.rootFromPath(m.toLong(), n.toLong(), d[m], p.subList(0, p.size - 1)))
                val other = IntentMap.rootFromPath(m.toLong(), n.toLong(), leaf(1000), p)
                assertFalse("wrong leaf n=$n m=$m", other != null && other.contentEquals(root))
                if (n > 1) {
                    val w = IntentMap.rootFromPath(((m + 1) % n).toLong(), n.toLong(), d[m], p)
                    assertFalse("wrong index n=$n m=$m", w != null && w.contentEquals(root))
                }
            }
            assertNull("index=size n=$n", IntentMap.rootFromPath(n.toLong(), n.toLong(), leaf(0), ArrayList())); assertNull("index<0 n=$n", IntentMap.rootFromPath(-1, n.toLong(), leaf(0), ArrayList()))
        }
        assertArrayEquals(leaf(0), IntentMap.rootFromPath(0, 1, leaf(0), ArrayList())); assertNull(IntentMap.rootFromPath(0, 0, leaf(0), ArrayList()))
    }

    // ---- Pq guards ----
    @Test fun pqVerifyRefusesNullsAndWrongLengthsWithoutThrowing() {
        val p = Pq.Prim.ML_DSA_65
        val pk = ByteArray(p.pkBytes); val msg = byteArrayOf(1, 2, 3); val sig = ByteArray(3309)
        assertFalse(Pq.pqVerify(p, ByteArray(p.pkBytes - 1), msg, sig)); assertFalse(Pq.pqVerify(p, ByteArray(p.pkBytes + 1), msg, sig))
        assertFalse(Pq.pqVerify(p, pk, msg, ByteArray(3308))); assertFalse(Pq.pqVerify(p, pk, msg, ByteArray(3310))); assertFalse(Pq.pqVerify(p, pk, msg, sig))
        for (q in Pq.Prim.values()) { if (q == Pq.Prim.LESS_CAT1) continue; assertFalse(q.name, Pq.pqVerify(q, ByteArray(q.pkBytes), ByteArray(0), ByteArray(1))) }
    }
}
