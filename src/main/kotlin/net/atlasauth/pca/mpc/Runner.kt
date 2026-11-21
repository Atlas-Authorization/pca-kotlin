package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.mpc.Beaver.OpenedMsg
import net.atlasauth.pca.mpc.Compose.ComposedDecision
import net.atlasauth.pca.mpc.Party.DecisionVector
import net.atlasauth.pca.mpc.Sharing.notBitSV
import net.atlasauth.pca.mpc.Sharing.reconstruct
import net.atlasauth.pca.mpc.Sharing.share
import net.atlasauth.pca.mpc.Sharing.shareConstant

/**
 * The simulated multi-party runner: all N parties in one process, exchanging shares and Beaver openings through inspectable
 * structures. [composeSecure] computes exactly [Compose.composeClear] under MPC.
 */
object Runner {
    private const val T_M = 3

    /** The full additive sharing of one party's secret bit (test inspection only). */
    class SharingRecord(val label: String, val party: Int, val secret: BigInteger, val shares: Array<BigInteger>)

    /** One party's complete view (a semi-honest corruption of that party). */
    class PartyView(val party: Int, val heldShares: List<BigInteger>, val opened: List<OpenedMsg>, val output: ComposedDecision)

    class MpcResult(
        val composed: ComposedDecision,
        val parties: Int,
        val q: Int,
        val opened: List<OpenedMsg>,
        val sharings: List<SharingRecord>,
        val views: List<PartyView>,
        val multiplications: Int,
    )

    /** Composes under MPC. [seed] null means CSPRNG sharing randomness; a seed is for reproducible tests only. */
    @JvmStatic fun composeSecure(vectors: List<DecisionVector>, qOpt: Int?, seed: BigInteger?): MpcResult {
        val n = vectors.size
        require(n != 0) { "composeSecure: no parties (fail closed)" }
        val q = qOpt ?: Party.DEFAULT_Q
        Compose.assertDecisionVectors(vectors, q)
        val rng: FieldSource = if (seed == null) Field.SecureFieldRng() else Field.FieldRng(seed)

        val opened = ArrayList<OpenedMsg>()
        val sharings = ArrayList<SharingRecord>()
        var mults = 0

        fun shareBit(bit: Int, label: String, party: Int): Array<BigInteger> {
            val s = share(BigInteger.valueOf(bit.toLong()), n, rng)
            sharings.add(SharingRecord(label, party, BigInteger.valueOf(bit.toLong()), s.clone()))
            return s
        }

        fun andAll(bits: List<Array<BigInteger>>): Array<BigInteger> {
            if (bits.isEmpty()) return shareConstant(BigInteger.ONE, n)
            var acc = bits[0]
            for (i in 1 until bits.size) {
                acc = Beaver.beaverMul(acc, bits[i], Beaver.genTriple(n, rng), opened)
                mults++
            }
            return acc
        }

        fun orAll(bits: List<Array<BigInteger>>): Array<BigInteger> {
            if (bits.isEmpty()) return shareConstant(BigInteger.ZERO, n)
            var prod = notBitSV(bits[0])
            for (i in 1 until bits.size) {
                prod = Beaver.beaverMul(prod, notBitSV(bits[i]), Beaver.genTriple(n, rng), opened)
                mults++
            }
            return notBitSV(prod)
        }

        val allowBits = ArrayList<Array<BigInteger>>()
        for (p in 0 until n) allowBits.add(shareBit(vectors[p].allow, "p$p.allow", p))
        val allow = if (reconstruct(andAll(allowBits)) == BigInteger.ONE) 1 else 0

        val tTherm = Array(n) { p -> Thermometer.thermometerEncode(vectors[p].t.toDouble(), T_M) }
        val tGe = IntArray(T_M)
        for (k in 0 until T_M) {
            val bitsAtK = ArrayList<Array<BigInteger>>()
            for (p in 0 until n) bitsAtK.add(shareBit(tTherm[p][k], "p$p.t.ge${k + 1}", p))
            tGe[k] = if (reconstruct(orAll(bitsAtK)) == BigInteger.ONE) 1 else 0
        }
        val t = Math.min(3, Math.max(1, Thermometer.thermometerDecode(tGe)))

        val rTherm = Array(n) { p -> Thermometer.thermometerEncode(vectors[p].rQuant.toDouble(), q) }
        val rGe = IntArray(q)
        for (k in 0 until q) {
            val bitsAtK = ArrayList<Array<BigInteger>>()
            for (p in 0 until n) bitsAtK.add(shareBit(rTherm[p][k], "p$p.r.ge${k + 1}", p))
            rGe[k] = if (reconstruct(orAll(bitsAtK)) == BigInteger.ONE) 1 else 0
        }
        val rQuant = Thermometer.thermometerDecode(rGe)

        val composed = ComposedDecision(allow, t, rQuant)
        val views = ArrayList<PartyView>()
        for (p in 0 until n) {
            val held = ArrayList<BigInteger>()
            for (s in sharings) held.add(s.shares[p])
            views.add(PartyView(p, held, opened, composed))
        }
        return MpcResult(composed, n, q, opened, sharings, views, mults)
    }
}
