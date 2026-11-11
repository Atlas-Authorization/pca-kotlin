package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mesh.kt private helpers called directly (KUtil.priv): number predicates, table shapes, effective authority, narrowing, admission,
 * revocation leaf proofs and RFC 9162 consistency, each at its boundaries. End-to-end cases are in Kill05IntelMeshMeshProofTest.
 */
class Kill05IntelMeshMeshUnitTest {
    private fun n(s: String) = Json.Num(s)
    private fun m(vararg kv: Pair<String, Any?>) = KUtil.m(*kv)
    private fun l(vararg v: Any?) = KUtil.l(*v)
    private fun <T> call(name: String, vararg a: Any?): T = KUtil.priv(Mesh, name, *a)
    private fun b(x: ByteArray) = Pca.b64(x)
    private fun node(x: ByteArray, y: ByteArray) = Pca.nodeHash(x, y)

    @Test fun verdictToString() = assertEquals("Mesh.Verdict(ok=false, reason=r, hop=2)", Mesh.Verdict(false, "r", 2).toString())

    @Test fun numberPredicates() {
        assertTrue(call<Boolean>("nat", n("3")))
        assertTrue(call<Boolean>("nat", 0L))
        assertFalse(call<Boolean>("nat", n("1.0"))) // its value is a non-negative integer, but it is not a strict safe integer
        assertFalse(call<Boolean>("nat", n("-1")))
        assertFalse(call<Boolean>("nat", 2.0))
        assertTrue(call<Boolean>("num", n("5")))
        assertTrue(call<Boolean>("num", n("-2.5")))
        assertFalse(call<Boolean>("num", n("1e400")))
        assertFalse(call<Boolean>("num", Double.NaN))
        assertFalse(call<Boolean>("num", Double.POSITIVE_INFINITY))
        assertFalse(call<Boolean>("num", Double.NEGATIVE_INFINITY))
        assertFalse(call<Boolean>("num", "5"))
        assertFalse(call<Boolean>("num", null))
        assertEquals(7L, call<Long>("natV", n("7")))
        assertEquals(0L, call<Long>("natV", "7"))
        assertEquals(0L, call<Long>("natV", n("1.5")))
        assertEquals(2.5, call<Double>("f", n("2.5")), 0.0)
        assertTrue(call<Double>("f", "x").isNaN())
        assertTrue(call<Double>("f", null).isNaN())
    }

    @Test fun consistencyAndInclusionShapes() {
        fun strs(k: Int, v: Any?): ArrayList<Any?> = ArrayList<Any?>().also { a -> repeat(k) { a.add(v) } }
        fun vc(x: Any?) = call<Map<String, Any?>?>("validConsistency", x)
        assertNull(vc(5L))
        assertNull(vc(m("oldSize" to "x", "newSize" to 1L, "path" to l())))
        assertNull(vc(m("oldSize" to 1L, "newSize" to n("1.5"), "path" to l())))
        assertNull(vc(m("oldSize" to 1L, "newSize" to 2L, "path" to "a")))
        assertNull(vc(m("oldSize" to 1L, "newSize" to 2L, "path" to strs(129, "a"))))
        assertNull(vc(m("oldSize" to 1L, "newSize" to 2L, "path" to strs(1, 5L))))
        assertNull(vc(m("oldSize" to 1L, "newSize" to 2L, "path" to l("a", null))))
        val full = m("oldSize" to 1L, "newSize" to 2L, "path" to strs(128, "a"))
        assertSame(full, vc(full))
        val one = m("oldSize" to 0L, "newSize" to 0L, "path" to l("a"))
        assertSame(one, vc(one))
        fun vi(x: Any?) = call<Map<String, Any?>?>("validInclusion", x)
        assertNull(vi(5L))
        assertNull(vi(m("index" to n("-1"), "size" to 1L, "path" to l())))
        assertNull(vi(m("index" to 0L, "size" to "1", "path" to l())))
        assertNull(vi(m("index" to 0L, "size" to 1L, "path" to "p")))
        assertNull(vi(m("index" to 0L, "size" to 1L, "path" to strs(129, "a"))))
        val inc = m("index" to 0L, "size" to 1L, "path" to strs(128, "a"))
        assertSame(inc, vi(inc))
    }

    // ---- effective authority / narrowing / admission ----

    private fun authority(): Any =
        Class.forName("net.atlasauth.pca.verifier.Mesh\$Authority").getDeclaredConstructor().also { it.isAccessible = true }.newInstance()
    private fun get(o: Any, f: String): Any? = o.javaClass.getDeclaredField(f).also { it.isAccessible = true }.get(o)
    private fun set(o: Any, f: String, v: Any?) = o.javaClass.getDeclaredField(f).also { it.isAccessible = true }.set(o, v)
    private fun eff(cs: Any?): Pair<String, Any> {
        val a = authority()
        return Pair(call<String>("effective", cs, a), a)
    }

    @Test fun effectiveFoldsEveryCaveatType() {
        val (why, a) = eff(l(
            m("type" to "scope", "actions" to l("b", "a", "b")),
            m("type" to "scope", "actions" to l("a", "c")),
            m("type" to "resource", "prefix" to "/o/"),
            m("type" to "max_amount", "max" to n("50")),
            m("type" to "max_amount", "max" to n("20.5")),
            m("type" to "expires", "at" to 900L),
            m("type" to "audience", "domains" to l("y", "x")),
            m("type" to "max_hops", "n" to 3L),
        ))
        assertEquals("", why)
        assertEquals(listOf("a"), get(a, "actions"))
        assertEquals(true, get(a, "hasAct"))
        assertEquals(listOf("/o/"), get(a, "prefixes"))
        assertEquals(20.5, get(a, "maxAmount"))
        assertEquals(true, get(a, "hasAmount"))
        assertEquals(900.0, get(a, "expiresAt"))
        assertEquals(true, get(a, "hasExp"))
        assertEquals(listOf("x", "y"), get(a, "audience"))
        assertEquals(true, get(a, "hasAud"))
        assertEquals(3.0, get(a, "maxHops"))
        assertEquals(true, get(a, "hasHops"))
        val (none, e) = eff(l())
        assertEquals("", none)
        assertEquals(false, get(e, "hasAct"))
    }

    @Test fun effectiveRefusals() {
        assertEquals("malformed proof", eff("x").first)
        assertEquals("malformed proof", eff(null).first)
        assertEquals("malformed proof", eff(l(5L)).first)
        assertEquals("malformed scope caveat", eff(l(m("type" to "scope"))).first)
        assertEquals("malformed resource caveat", eff(l(m("type" to "resource"))).first)
        assertEquals("malformed max_amount caveat", eff(l(m("type" to "max_amount"))).first)
        assertEquals("malformed expires caveat", eff(l(m("type" to "expires"))).first)
        assertEquals("malformed audience caveat", eff(l(m("type" to "audience"))).first)
        assertEquals("malformed max_hops caveat", eff(l(m("type" to "max_hops"))).first)
        // the type is printed as the reference prints the parsed value (1.50 -> 1.5)
        assertEquals("unknown caveat type \"1.5\" (fail closed)", eff(l(m("type" to n("1.50")))).first)
        assertEquals("unknown caveat type \"undefined\" (fail closed)", eff(l(m())).first)
        // same String.hashCode as a known type, different text: the `when` must still compare the text
        for (s in listOf("tDope", "sFsource", "nBx_amount", "fYpires", "bVdience", "nBx_hops"))
            assertEquals("unknown caveat type \"$s\" (fail closed)", eff(l(m("type" to s))).first)
        assertEquals("tDope".hashCode(), "scope".hashCode())
        assertEquals("nBx_hops".hashCode(), "max_hops".hashCode())
    }

    private fun auth(
        act: List<String>? = null, aud: List<String>? = null, amt: Double? = null, exp: Double? = null, hops: Double? = null,
        pre: List<String> = emptyList(),
    ): Any {
        val a = authority()
        if (act != null) { set(a, "actions", act); set(a, "hasAct", true) }
        if (aud != null) { set(a, "audience", aud); set(a, "hasAud", true) }
        if (amt != null) { set(a, "maxAmount", amt); set(a, "hasAmount", true) }
        if (exp != null) { set(a, "expiresAt", exp); set(a, "hasExp", true) }
        if (hops != null) { set(a, "maxHops", hops); set(a, "hasHops", true) }
        @Suppress("UNCHECKED_CAST") val prefixes = get(a, "prefixes") as ArrayList<String>
        prefixes.addAll(pre)
        return a
    }

    private fun narrows(child: Any, parent: Any): Boolean = call("narrows", child, parent)

    @Test fun narrowsEveryDimension() {
        assertTrue(narrows(auth(), auth()))
        assertFalse(narrows(auth(), auth(act = listOf("a", "b"))))
        assertFalse(narrows(auth(act = listOf("c")), auth(act = listOf("a", "b"))))
        assertTrue(narrows(auth(act = listOf("a")), auth(act = listOf("a", "b"))))
        assertTrue(narrows(auth(act = listOf("c")), auth()))
        assertFalse(narrows(auth(), auth(aud = listOf("d", "e"))))
        assertFalse(narrows(auth(aud = listOf("f")), auth(aud = listOf("d", "e"))))
        assertTrue(narrows(auth(aud = listOf("e")), auth(aud = listOf("d", "e"))))
        assertTrue(narrows(auth(aud = listOf("f")), auth()))
        assertFalse(narrows(auth(), auth(amt = 5.0)))
        assertFalse(narrows(auth(amt = 6.0), auth(amt = 5.0)))
        assertTrue(narrows(auth(amt = 5.0), auth(amt = 5.0)))
        assertTrue(narrows(auth(amt = 4.0), auth(amt = 5.0)))
        assertTrue(narrows(auth(amt = 9.0), auth()))
        assertFalse(narrows(auth(), auth(exp = 5.0)))
        assertFalse(narrows(auth(exp = 6.0), auth(exp = 5.0)))
        assertTrue(narrows(auth(exp = 5.0), auth(exp = 5.0)))
        assertTrue(narrows(auth(exp = 9.0), auth()))
        assertFalse(narrows(auth(), auth(hops = 5.0)))
        assertFalse(narrows(auth(hops = 6.0), auth(hops = 5.0)))
        assertTrue(narrows(auth(hops = 5.0), auth(hops = 5.0)))
        assertTrue(narrows(auth(hops = 9.0), auth()))
        assertFalse(narrows(auth(), auth(pre = listOf("/a"))))
        assertTrue(narrows(auth(pre = listOf("/b", "/a")), auth(pre = listOf("/a"))))
        assertTrue(narrows(auth(pre = listOf("/x")), auth()))
        val all = auth(act = listOf("a"), aud = listOf("d"), amt = 5.0, exp = 5.0, hops = 5.0, pre = listOf("/a"))
        assertTrue(narrows(auth(act = listOf("a"), aud = listOf("d"), amt = 5.0, exp = 5.0, hops = 5.0, pre = listOf("/a")), all))
    }

    private fun admits(e: Any, a: Map<String, Any?>, len: Int = 1): String = call("admits", e, a, 0.0, len)

    @Test fun admitsReadsOnlyStringMembers() {
        // a non-string member is read as "" (which these all-"" constraints admit), never cast and never null
        val blank = auth(act = listOf(""), aud = listOf(""), pre = listOf(""))
        assertEquals("", admits(blank, m("type" to n("5"), "resource" to n("5"), "service_domain" to n("5"))))
        assertEquals("", admits(blank, m()))
        val s = auth(act = listOf("t"), aud = listOf("d"), pre = listOf("/r"))
        assertEquals("", admits(s, m("type" to "t", "resource" to "/r/1", "service_domain" to "d")))
        assertEquals("action \"\" not in scope", admits(s, m("type" to n("5"), "resource" to "/r/1", "service_domain" to "d")))
        assertEquals("resource \"\" outside prefix \"/r\"", admits(s, m("type" to "t", "resource" to n("5"), "service_domain" to "d")))
        assertEquals("service domain not in audience", admits(s, m("type" to "t", "resource" to "/r/1", "service_domain" to n("5"))))
        // without a max_hops caveat the chain length is never compared
        assertEquals("", admits(auth(), m(), 1))
        assertEquals("", admits(auth(hops = 2.0), m(), 2))
        assertEquals("chain exceeds max_hops 1", admits(auth(hops = 1.0), m(), 2))
    }

    // ---- heads / tables ----

    @Test fun revocationSetRollbackIsRefused() {
        fun head(rs: Long, rr: String) = m("domain" to "d", "size" to 1L, "root" to "r", "rev_root" to rr, "rev_size" to rs, "timestamp" to 0L)
        fun adv(prev: Any?, next: Any?) = call<String>("checkHeadAdvance", prev, next, null)
        assertEquals("head rolls back", adv(head(2L, "x"), head(1L, "y")))
        assertEquals("", adv(head(2L, "x"), head(3L, "y")))
        assertEquals("", adv(head(2L, "x"), head(2L, "x")))
        assertEquals("equivocation (revocation set)", adv(head(2L, "x"), head(2L, "y")))
    }

    @Test fun truthiness() {
        fun t(v: Any?) = call<Boolean>("truthy", v)
        assertFalse(t(null))
        assertTrue(t(true))
        assertFalse(t(false))
        assertFalse(t(""))
        assertTrue(t("a"))
        assertFalse(t(n("0")))
        assertTrue(t(n("2")))
        assertFalse(t(0L))
        assertTrue(t(-1L))
        assertFalse(t(Double.NaN))
        assertTrue(t(0.5))
        assertTrue(t(m()))
        assertTrue(t(l()))
    }

    @Test fun expandNmRefusesWithNull() {
        fun x(c: Any?, leaves: List<Any?>) = call<Map<String, Any?>?>("expandNm", c, leaves)
        assertNull(x(5L, l()))
        assertNull(x(m("size" to "1"), l()))
        assertNull(x(m("size" to 1L, "lo" to 0L), l()))
        assertNull(x(m("size" to 1L, "hi" to "0"), l("L")))
        assertEquals(m("size" to 1L, "lo" to "L"), x(m("size" to 1L, "lo" to 0L), l("L")))
        assertEquals(m("size" to 2L, "hi" to "H"), x(m("size" to 2L, "hi" to 1L), l("x", "H")))
        assertEquals(m("size" to 0L), x(m("size" to 0L), l()))
    }

    // ---- revocation leaf proofs ----

    private fun mth(h: List<ByteArray>): ByteArray {
        if (h.size == 1) return h[0]
        var k = 1
        while (k * 2 < h.size) k *= 2
        return node(mth(h.subList(0, k)), mth(h.subList(k, h.size)))
    }
    private fun bindRev(size: Long, tree: ByteArray): String = call("bindRevRoot", size, b(tree))
    private fun leafOk(root: String, size: Long, id: String, proof: Map<String, Any?>): Boolean = call("leafOk", root, size, id, proof)
    private fun step(side: Any?, h: ByteArray) = m("side" to side, "hash" to b(h))
    private fun lp(size: Long, index: Any?, vararg path: Any?) = m("size" to size, "index" to index, "path" to l(*path))

    @Test fun leafProofs() {
        val hs = listOf("a", "b", "c").map { Pca.leafHash(it) }
        val root3 = bindRev(3L, mth(hs))
        assertTrue(leafOk(root3, 3L, "a", lp(3L, 0L, step("R", hs[1]), step("R", hs[2]))))
        assertTrue(leafOk(root3, 3L, "b", lp(3L, 1L, step("L", hs[0]), step("R", hs[2]))))
        assertTrue(leafOk(root3, 3L, "c", lp(3L, 2L, step("L", node(hs[0], hs[1])))))
        assertFalse(leafOk(root3, 3L, "c", lp(3L, 2L, step("R", node(hs[0], hs[1])))))
        assertFalse(leafOk(root3, 3L, "c", lp(3L, 2L, step(5L, node(hs[0], hs[1])))))
        assertFalse(leafOk(root3, 3L, "c", lp(3L, 2L, m("side" to "L", "hash" to 5L))))
        assertFalse(leafOk(root3, 3L, "c", lp(2L, 1L, step("L", hs[0]))))
        // an index outside [0, size) is refused even when its path folds to the bound root
        val sib = hs[1]
        val atSize = bindRev(2L, node(sib, hs[0]))
        assertFalse(leafOk(atSize, 2L, "a", lp(2L, 2L, step("L", sib))))
        assertTrue(leafOk(atSize, 2L, "a", lp(2L, 1L, step("L", sib))))
        val below = bindRev(2L, node(hs[0], sib))
        assertFalse(leafOk(below, 2L, "a", lp(2L, n("-1"), step("R", sib))))
        assertTrue(leafOk(below, 2L, "a", lp(2L, 0L, step("R", sib))))
    }

    // ---- RFC 9162 consistency ----

    private val leaves = (0 until 9).map { Pca.leafHash("leaf$it") }
    private val empty = Pca.b64(Pca.sha(ByteArray(0)))
    private fun cons(old: String, nw: String, proof: Map<String, Any?>): Boolean = call("consistency", old, nw, proof)
    private fun cp(o: Any?, nw: Any?, path: Any?) = m("oldSize" to o, "newSize" to nw, "path" to path)

    /** RFC 9162 section 2.1.4.1 SUBPROOF. */
    private fun sub(k0: Int, d: List<ByteArray>, whole: Boolean): List<ByteArray> {
        if (k0 == d.size) return if (whole) emptyList() else listOf(mth(d))
        var k = 1
        while (k * 2 < d.size) k *= 2
        return if (k0 <= k) sub(k0, d.subList(0, k), whole) + mth(d.subList(k, d.size))
        else sub(k0 - k, d.subList(k, d.size), false) + mth(d.subList(0, k))
    }

    @Test fun consistencyAcceptsEveryRealProof() {
        for (a in 1..8) for (z in a + 1..9) {
            val path = sub(a, leaves.subList(0, z), true).map { b(it) }
            val old = b(mth(leaves.subList(0, a)))
            val nw = b(mth(leaves.subList(0, z)))
            assertTrue("$a->$z", cons(old, nw, cp(a.toLong(), z.toLong(), ArrayList<Any?>(path))))
            assertFalse("$a->$z wrong new root", cons(old, old, cp(a.toLong(), z.toLong(), ArrayList<Any?>(path))))
            assertFalse("$a->$z wrong old root", cons(nw, nw, cp(a.toLong(), z.toLong(), ArrayList<Any?>(path))))
            // a trailing entry after the fold is complete is refused
            assertFalse("$a->$z extra entry", cons(old, nw, cp(a.toLong(), z.toLong(), ArrayList<Any?>(path + b(leaves[0])))))
        }
    }

    @Test fun consistencyGuards() {
        val p0 = leaves[0]
        val c1 = leaves[1]
        val c2 = leaves[2]
        // first < 0 / first > second: the size guards alone refuse paths that would otherwise fold to these roots
        assertFalse(cons(b(node(c2, p0)), b(node(c2, node(p0, c1))), cp(n("-1"), 3L, l(b(p0), b(c1), b(c2)))))
        assertFalse(cons(b(p0), b(node(p0, c1)), cp(3L, 2L, l(b(p0), b(c1)))))
        // equal sizes: an empty path and the same root
        assertTrue(cons("r", "r", cp(2L, 2L, l())))
        assertFalse(cons("r", "s", cp(2L, 2L, l())))
        assertFalse(cons("r", "r", cp(2L, 2L, l(b(p0)))))
        // an empty old tree: vacuous for a larger new tree (a missing or non-list path is empty)
        assertTrue(cons(empty, "anything", cp(0L, 5L, l())))
        assertTrue(cons(empty, "anything", m("oldSize" to 0L, "newSize" to 5L)))
        assertTrue(cons(empty, "anything", cp(0L, 5L, "x")))
        assertTrue(cons(empty, empty, cp(0L, 0L, l())))
        assertFalse(cons(empty, "x", cp(0L, 0L, l())))
        assertFalse(cons("x", "y", cp(0L, 5L, l())))
        assertFalse(cons(empty, "y", cp(0L, 5L, l(b(p0)))))
        // sizes must be strict safe integers
        assertFalse(cons("r", "r", cp("x", 2L, l())))
        assertFalse(cons("r", "r", cp(2L, n("2.5"), l())))
        // more than MAX_PATH entries
        assertFalse(cons(b(p0), b(c1), cp(3L, 4L, ArrayList<Any?>((0 until 129).map { b(p0) }))))
        // a power-of-two old size starts from the old root, which must decode
        assertFalse(cons("!!", b(c1), cp(2L, 3L, l(b(c1)))))
        // a non-string path entry reads as "", which does not decode
        assertFalse(cons(b(p0), b(c1), cp(3L, 4L, l(5L))))
    }
}
