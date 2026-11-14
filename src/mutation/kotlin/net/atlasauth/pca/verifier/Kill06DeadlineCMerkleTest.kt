package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** RFC 6962 / 9162 reference tree for the deadline tests: roots, inclusion paths and consistency paths over fixed leaves. */
internal object Kill06DeadlineCTree {
    fun node(l: ByteArray, r: ByteArray): ByteArray = Pca.sha(byteArrayOf(1), l, r)
    fun leaves(n: Int): List<ByteArray> = (0 until n).map { Pca.leafHash("leaf$it") }
    private fun split(n: Int): Int { var k = 1; while (k * 2 < n) k *= 2; return k }
    fun mth(h: List<ByteArray>): ByteArray {
        if (h.size == 1) return h[0]
        val k = split(h.size)
        return node(mth(h.subList(0, k)), mth(h.subList(k, h.size)))
    }
    /** RFC 6962 PATH(m, D). */
    fun inclusion(m: Int, d: List<ByteArray>): List<ByteArray> {
        if (d.size == 1) return emptyList()
        val k = split(d.size)
        return if (m < k) inclusion(m, d.subList(0, k)) + mth(d.subList(k, d.size)) else inclusion(m - k, d.subList(k, d.size)) + mth(d.subList(0, k))
    }
    /** RFC 6962 SUBPROOF(m, D, whole). */
    fun consistency(m: Int, d: List<ByteArray>, whole: Boolean): List<ByteArray> {
        if (m == d.size) return if (whole) emptyList() else listOf(mth(d))
        val k = split(d.size)
        return if (m <= k) consistency(m, d.subList(0, k), whole) + mth(d.subList(k, d.size))
        else consistency(m - k, d.subList(k, d.size), false) + mth(d.subList(0, k))
    }
    fun b(x: ByteArray): String = Pca.b64(x)
}

/**
 * Deadline tests (Mesh.consistency, Ledger.consistency / pick, ProvenanceGate.verifyRfc9162Inclusion): ordinary real RFC proofs
 * through the folding loops, each block under [Deadline.within] so a loop that no longer advances fails instead of hanging.
 */
class Kill06DeadlineCMerkleTest {
    private val t = Kill06DeadlineCTree

    private fun proof(a: Int, z: Int, path: List<ByteArray>) =
        linkedMapOf<String, Any?>("oldSize" to a.toLong(), "newSize" to z.toLong(), "path" to ArrayList<Any?>(path.map { t.b(it) }))

    @Test fun ledgerConsistencyAcceptsEveryRealProof() {
        val lv = t.leaves(9)
        Deadline.within {
            for (a in 1..8) for (z in a + 1..9) {
                val old = t.b(t.mth(lv.subList(0, a)))
                val nw = t.b(t.mth(lv.subList(0, z)))
                val p = t.consistency(a, lv.subList(0, z), true)
                assertTrue("$a->$z", Ledger.verifyConsistency(old, nw, proof(a, z, p)))
                assertFalse("$a->$z swapped roots", Ledger.verifyConsistency(nw, old, proof(a, z, p)))
                assertFalse("$a->$z extra entry", Ledger.verifyConsistency(old, nw, proof(a, z, p + lv[0])))
            }
            assertTrue(Ledger.verifyConsistency("r", "r", proof(3, 3, emptyList())))
            assertFalse(Ledger.verifyConsistency("r", "s", proof(3, 3, emptyList())))
            assertTrue(Ledger.verifyConsistency(Ledger.EMPTY_TREE_ROOT, "x", proof(0, 4, emptyList())))
        }
    }

    @Test fun meshConsistencyAcceptsEveryRealProof() {
        val lv = t.leaves(9)
        Deadline.within {
            for (a in 1..8) for (z in a + 1..9) {
                val old = t.b(t.mth(lv.subList(0, a)))
                val nw = t.b(t.mth(lv.subList(0, z)))
                val p = t.consistency(a, lv.subList(0, z), true)
                assertTrue("$a->$z", KUtil.priv<Boolean>(Mesh, "consistency", old, nw, proof(a, z, p)))
                assertFalse("$a->$z wrong new root", KUtil.priv<Boolean>(Mesh, "consistency", old, old, proof(a, z, p)))
                assertFalse("$a->$z extra entry", KUtil.priv<Boolean>(Mesh, "consistency", old, nw, proof(a, z, p + lv[0])))
            }
        }
    }

    @Test fun rfc9162InclusionAcceptsEveryRealProof() {
        Deadline.within {
            for (n in 1..9) {
                val lv = t.leaves(n)
                val root = t.mth(lv)
                for (i in 0 until n) {
                    val p = t.inclusion(i, lv)
                    assertTrue("$i/$n", ProvenanceGate.verifyRfc9162Inclusion(lv[i], i.toLong(), n.toLong(), p, root))
                    assertFalse("$i/$n wrong root", ProvenanceGate.verifyRfc9162Inclusion(lv[i], i.toLong(), n.toLong(), p, ByteArray(root.size) { 7 }))
                    assertFalse("$i/$n extra", ProvenanceGate.verifyRfc9162Inclusion(lv[i], i.toLong(), n.toLong(), p + lv[0], root))
                }
            }
        }
    }

    @Test fun ledgerPickKeepsOrderAndRefusesAMissingMember() {
        val m = linkedMapOf<String, Any?>("a" to 1L, "b" to null, "c" to "x", "d" to 4L)
        Deadline.within {
            val got = KUtil.priv<LinkedHashMap<String, Any?>?>(Ledger, "pick", m, arrayOf("c", "a", "b"))
            assertEquals(listOf("c", "a", "b"), got!!.keys.toList())
            assertEquals(listOf<Any?>("x", 1L, null), got.values.toList())
            assertNull(KUtil.priv<LinkedHashMap<String, Any?>?>(Ledger, "pick", m, arrayOf("a", "zz")))
            assertTrue(KUtil.priv<LinkedHashMap<String, Any?>?>(Ledger, "pick", m, arrayOf<String>())!!.isEmpty())
        }
    }
}
