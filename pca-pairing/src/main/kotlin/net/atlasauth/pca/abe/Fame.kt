package net.atlasauth.pca.abe

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import net.atlasauth.pca.pairing.Bls12
import net.atlasauth.pca.pairing.Gt
import supranational.blst.P1
import supranational.blst.P2

/**
 * FAME (Agrawal and Chase, ACM CCS 2017, ePrint 2017/807): ciphertext-policy ABE in the type-3 pairing setting, the group
 * arithmetic only (the wire format, validation and AEAD are in [Abe]). G1/G2 work is blst through jblst, GT work is blst
 * through [Gt]. Same equations, hashing and span program as the TypeScript reference:
 *
 * ```
 *   Setup     MPK = (h^a1, h^a2, e(g,h)^(d1 a1 + d3), e(g,h)^(d2 a2 + d3)),  MSK = (a1, a2, b1, b2, g^d1, g^d2, g^d3)
 *   KeyGen    pow = (b1 r1, b2 r2, r1 + r2), K0 = h^pow,
 *             K_y,t = (H(y,0,t)^pow0 H(y,1,t)^pow1 H(y,2,t)^pow2 g^sigma_y)^(1/a_(t+1)), K_y,2 = g^-sigma_y,
 *             K'_t = (H0(0,0,t)^pow0 H0(0,1,t)^pow1 H0(0,2,t)^pow2 g^sigma')^(1/a_(t+1)) g^d_(t+1), K'_2 = g^-sigma' g^d3
 *   Encrypt   C0 = (h1^s1, h2^s2, h^(s1+s2)),
 *             C_i,l = H(rho(i),l,0)^s1 H(rho(i),l,1)^s2 prod_j (H0(j,l,0)^s1 H0(j,l,1)^s2)^M[i][j],  K = T1^s1 T2^s2
 *   Decrypt   K = prod_l e(keyProd_l, C0_l) / e(ctProd_l, K0_l) with the tree's Lagrange reconstruction weights
 * ```
 *
 * The span program is a Shamir sharing down the threshold tree (each t-of-n gate adds t-1 columns; child i gets its parent's
 * row plus i^k in the gate's k-th new column). rho must be injective: a policy naming one attribute twice is refused by the caller.
 */
object Fame {
    /** Domain-separation tag of the attribute / column random oracles (RFC 9380 SSWU_RO into G1). */
    const val ATTR_DST = "ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1"

    private val G1: P1 = P1.generator()
    private val G2: P2 = P2.generator()

    class Mpk(val h1: P2, val h2: P2, val t1: ByteArray, val t2: ByteArray)

    class Msk(val a: Array<BigInteger>, val b: Array<BigInteger>, val g: Array<P1>)

    class Key(val k0: Array<P2>, val kp: Array<P1>, val attrs: Map<String, Array<P1>>)

    class Ciphertext(val ct0: Array<P2>, val rows: List<Array<P1>>)

    /** Setup output. */
    class Master internal constructor(val mpk: Mpk, val msk: Msk)

    /** Encrypt output: the ciphertext and the KEM key (a GT element). */
    class Encapsulation internal constructor(val ct: Ciphertext, val k: ByteArray)

    // ---- scalar multiplication with the reference's zero rule ----------------------------------------------------

    /** k*P for k non-zero mod r; a zero scalar throws (the reference refuses it). */
    private fun mul(p: P1, k: BigInteger): P1 {
        if (Bls12.mod(k).signum() == 0) throw ArithmeticException("scalar is zero")
        return Bls12.mul(p, k)
    }

    private fun mul(p: P2, k: BigInteger): P2 {
        if (Bls12.mod(k).signum() == 0) throw ArithmeticException("scalar is zero")
        return Bls12.mul(p, k)
    }

    /** k*P, the identity when k is zero mod r. */
    private fun mulZ(p: P1, k: BigInteger): P1 = Bls12.mul(p, k)

    // ---- random oracles -------------------------------------------------------------------------------------------

    private fun hashToG1(msg: ByteArray): P1 = P1().hash_to(msg, ATTR_DST)

    private fun u32(n: Int): ByteArray = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())

    /** H(y, l, t): kind byte 1, length-prefixed UTF-8 attribute, l, t. */
    fun hAttr(attr: String, l: Int, t: Int): P1 {
        val a = Json.utf8(attr)
        val o = ByteArrayOutputStream()
        o.write(1)
        o.write(u32(a.size))
        o.write(a)
        o.write(l)
        o.write(t)
        return hashToG1(o.toByteArray())
    }

    /** H0(j, l, t): the column-indexed oracle (kind byte 2). */
    fun hCol(j: Int, l: Int, t: Int): P1 {
        val o = ByteArrayOutputStream()
        o.write(2)
        o.write(u32(j))
        o.write(l)
        o.write(t)
        return hashToG1(o.toByteArray())
    }

    // ---- setup / keygen ---------------------------------------------------------------------------------------------

    fun setup(a: Array<BigInteger>, b: Array<BigInteger>, d: Array<BigInteger>): Master {
        val egh = Gt.pairing(G1, G2)
        val mpk = Mpk(
            mul(G2, a[0]), mul(G2, a[1]),
            Gt.pow(egh, Bls12.add(Bls12.mul(d[0], a[0]), d[2])), Gt.pow(egh, Bls12.add(Bls12.mul(d[1], a[1]), d[2])),
        )
        return Master(mpk, Msk(a, b, arrayOf(mul(G1, d[0]), mul(G1, d[1]), mul(G1, d[2]))))
    }

    private fun keyTerm(oracle: (Int) -> P1, pow: Array<BigInteger>, sigma: BigInteger, aInv: BigInteger): P1 {
        val sum = mulZ(oracle(0), pow[0]).add(mulZ(oracle(1), pow[1])).add(mulZ(oracle(2), pow[2])).add(mul(G1, sigma))
        return mul(sum, aInv)
    }

    fun keygen(msk: Msk, attrs: List<String>, r: Array<BigInteger>, sigmas: List<BigInteger>, sigmaPrime: BigInteger): Key {
        val pow = arrayOf(Bls12.mul(msk.b[0], r[0]), Bls12.mul(msk.b[1], r[1]), Bls12.add(r[0], r[1]))
        val aInv = arrayOf(Bls12.inv(msk.a[0]), Bls12.inv(msk.a[1]))
        val k0 = arrayOf(mul(G2, pow[0]), mul(G2, pow[1]), mul(G2, pow[2]))
        val out = LinkedHashMap<String, Array<P1>>()
        for ((i, y) in attrs.withIndex()) {
            if (i >= sigmas.size) throw IllegalArgumentException("fameKeygen: one sigma per attribute is required")
            val sg = sigmas[i]
            out[y] = arrayOf(
                keyTerm({ l -> hAttr(y, l, 0) }, pow, sg, aInv[0]),
                keyTerm({ l -> hAttr(y, l, 1) }, pow, sg, aInv[1]),
                mul(G1, Bls12.sub(BigInteger.ZERO, sg)),
            )
        }
        val kp = arrayOf(
            keyTerm({ l -> hCol(0, l, 0) }, pow, sigmaPrime, aInv[0]).add(msk.g[0]),
            keyTerm({ l -> hCol(0, l, 1) }, pow, sigmaPrime, aInv[1]).add(msk.g[1]),
            mul(G1, Bls12.sub(BigInteger.ZERO, sigmaPrime)).add(msk.g[2]),
        )
        return Key(k0, kp, out)
    }

    // ---- span program ---------------------------------------------------------------------------------------------

    private class Row(val attr: String, val vec: Map<Int, BigInteger>)

    /** Leaves in depth-first order, each with its sparse span-program row (column 0 is the secret column, always 1). */
    private fun buildRows(tree: Map<String, Any?>): List<Row> {
        val rows = ArrayList<Row>()
        walk(tree, linkedMapOf(0 to BigInteger.ONE), rows, intArrayOf(1))
        return rows
    }

    private fun walk(node: Map<String, Any?>, vec: Map<Int, BigInteger>, rows: MutableList<Row>, ncols: IntArray) {
        if (AbePolicy.isLeaf(node)) {
            rows.add(Row(node["attr"] as String, vec))
            return
        }
        val t = AbePolicy.t(node)
        val base = ncols[0]
        ncols[0] += t - 1
        for ((idx, child) in AbePolicy.of(node).withIndex()) {
            val cv = LinkedHashMap(vec)
            val x = BigInteger.valueOf((idx + 1).toLong())
            var pw = BigInteger.ONE
            for (k in 1 until t) {
                pw = Bls12.mul(pw, x)
                cv[base + k - 1] = pw
            }
            walk(child, cv, rows, ncols)
        }
    }

    internal fun leafCount(tree: Map<String, Any?>): Int =
        if (AbePolicy.isLeaf(tree)) 1 else AbePolicy.of(tree).sumOf { leafCount(it) }

    /** First attribute named by two leaves, or null (FAME needs an injective row labelling). */
    internal fun firstRepeatedAttribute(tree: Map<String, Any?>): String? {
        val seen = HashSet<String>()
        return AbePolicy.leaves(tree).firstOrNull { !seen.add(it) }
    }

    // ---- encrypt --------------------------------------------------------------------------------------------------

    fun encrypt(mpk: Mpk, tree: Map<String, Any?>, s: Array<BigInteger>): Encapsulation {
        val colMemo = HashMap<String, P1>()
        val out = ArrayList<Array<P1>>()
        for (row in buildRows(tree)) {
            out.add(Array(3) { l ->
                var acc = mul(hAttr(row.attr, l, 0), s[0]).add(mul(hAttr(row.attr, l, 1), s[1]))
                for ((j, w) in row.vec) {
                    val col = colMemo.getOrPut("$j:$l") { mul(hCol(j, l, 0), s[0]).add(mul(hCol(j, l, 1), s[1])) }
                    acc = acc.add(mulZ(col, w))
                }
                acc
            })
        }
        val ct = Ciphertext(arrayOf(mul(mpk.h1, s[0]), mul(mpk.h2, s[1]), mul(G2, Bls12.add(s[0], s[1]))), out)
        return Encapsulation(ct, Gt.mul(Gt.pow(mpk.t1, s[0]), Gt.pow(mpk.t2, s[1])))
    }

    // ---- decrypt --------------------------------------------------------------------------------------------------

    /** A decryption plan: a leaf row, or a gate with the chosen children and their evaluation points. */
    private class Plan(val row: Int, val xs: List<BigInteger>?, val subs: List<Plan>?) {
        constructor(row: Int) : this(row, null, null)
        constructor(xs: List<BigInteger>, subs: List<Plan>) : this(-1, xs, subs)
    }

    /** Bottom-up, the first t satisfiable children of every gate; null when the subtree is not satisfied. */
    private fun plan(node: Map<String, Any?>, has: (String) -> Boolean, offset: Int): Plan? {
        if (AbePolicy.isLeaf(node)) return if (has(node["attr"] as String)) Plan(offset) else null
        val t = AbePolicy.t(node)
        val xs = ArrayList<BigInteger>()
        val subs = ArrayList<Plan>()
        var off = offset
        val of = AbePolicy.of(node)
        for (i in of.indices) {
            val sub = plan(of[i], has, off)
            if (sub != null) {
                xs.add(BigInteger.valueOf((i + 1).toLong()))
                subs.add(sub)
            }
            if (subs.size >= t) break
            off += leafCount(of[i])
        }
        return if (subs.size < t) null else Plan(xs, subs)
    }

    private fun weights(p: Plan, w: BigInteger, out: MutableMap<Int, BigInteger>): Boolean {
        val subs = p.subs
        if (subs == null) {
            out[p.row] = w
            return true
        }
        val lambda = lagrangeAtZero(p.xs!!) ?: return false
        return subs.indices.all { weights(subs[it], Bls12.mul(w, lambda[it]), out) }
    }

    /** Lagrange coefficients L_i(0) over Z_r; null on an empty set, a zero point, or coinciding points. */
    internal fun lagrangeAtZero(xs: List<BigInteger>): List<BigInteger>? {
        if (xs.isEmpty()) return null
        val seen = HashSet<BigInteger>()
        for (x in xs) {
            val xr = Bls12.mod(x)
            if (xr.signum() == 0 || !seen.add(xr)) return null
        }
        return xs.indices.map { i ->
            var num = BigInteger.ONE
            var den = BigInteger.ONE
            for (j in xs.indices) {
                if (j == i) continue
                num = Bls12.mul(num, xs[j])
                den = Bls12.mul(den, Bls12.sub(xs[j], xs[i]))
            }
            Bls12.mul(num, Bls12.inv(den))
        }
    }

    /** Row index -> reconstruction weight over the rows the key can use; null when the attribute set does not satisfy the tree. */
    internal fun reconstructionWeights(tree: Map<String, Any?>, has: (String) -> Boolean): Map<Int, BigInteger>? {
        val p = plan(tree, has, 0) ?: return null
        val out = LinkedHashMap<Int, BigInteger>()
        return if (weights(p, BigInteger.ONE, out)) out else null
    }

    /** The KEM key, or null when the key does not satisfy the tree (or a pairing input is the identity). */
    fun decrypt(key: Key, tree: Map<String, Any?>, ct: Ciphertext): ByteArray? {
        val rows = AbePolicy.leaves(tree)
        if (rows.size != ct.rows.size) return null
        val w = reconstructionWeights(tree) { key.attrs.containsKey(it) } ?: return null
        val g1 = ArrayList<P1>()
        val g2 = ArrayList<P2>()
        for (l in 0 until 3) {
            var ctProd = P1()
            var keyProd = key.kp[l].dup()
            for ((idx, weight) in w) {
                val comp = key.attrs[rows[idx]] ?: return null
                val cRow = ct.rows.getOrNull(idx) ?: return null
                ctProd = ctProd.add(mulZ(cRow[l], weight))
                keyProd = keyProd.add(mulZ(comp[l], weight))
            }
            g1.add(keyProd)
            g2.add(ct.ct0[l])
            g1.add(ctProd.dup().neg())
            g2.add(key.k0[l])
        }
        return try {
            Gt.pairingProduct(g1, g2)
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
