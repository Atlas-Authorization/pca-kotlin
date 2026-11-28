package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.mpc.Compose.ComposedDecision
import net.atlasauth.pca.mpc.Party.DecisionVector
import net.atlasauth.pca.mpc.Spdz.AuthSV
import net.atlasauth.pca.mpc.Spdz.AuthTriple
import net.atlasauth.pca.mpc.Spdz.DealerFault
import net.atlasauth.pca.mpc.Spdz.Deviation
import net.atlasauth.pca.mpc.Spdz.SpdzEngine

/**
 * The malicious-secure (SPDZ) runner: the same composition as [Runner.composeSecure], but every shared value carries a MAC and nothing is
 * accepted as output until the batched MAC-check passes (correct result or [Spdz.MacCheckAbort]). Offline phase: a no-dealer provider
 * (the default, OT-based), or an explicit trusted dealer with sacrifice-certified triples.
 */
object SpdzRunner {
    /** Trusted-dealer options (honoured only with insecureTrustedDealer). Null verifyTriples means true. */
    class DealerOptions {
        @JvmField var verifyTriples: Boolean? = null
        @JvmField var partners: Int? = null
        @JvmField var fault: DealerFault? = null
    }

    class MaliciousMpcConfig {
        @JvmField var q: Int? = null
        @JvmField var seed: BigInteger? = null
        @JvmField var deviations: List<Deviation>? = null
        @JvmField var offline: OfflineProvider? = null
        @JvmField var insecureTrustedDealer: Boolean = false
        @JvmField var dealer: DealerOptions? = null
    }

    class MaliciousMpcResult(
        val composed: ComposedDecision,
        val parties: Int,
        val q: Int,
        val opens: Int,
        val multiplications: Int,
        val offlineMode: String,
        val triplesVerified: Boolean,
        val macChecked: Boolean,
    )

    private const val T_M = 3

    @JvmStatic fun composeSecureMalicious(vectors: List<DecisionVector>, cfg0: MaliciousMpcConfig?): MaliciousMpcResult {
        val c = cfg0 ?: MaliciousMpcConfig()
        val n = vectors.size
        require(n != 0) { "composeSecureMalicious: no parties (fail closed)" }
        val q = c.q ?: Party.DEFAULT_Q
        Compose.assertDecisionVectors(vectors, q)
        val rng: FieldSource = if (c.seed == null) Field.SecureFieldRng() else Field.FieldRng(c.seed!!)

        val cOffline = c.offline
        val dealer = c.dealer
        check(!(cOffline != null && c.insecureTrustedDealer)) { "composeSecureMalicious: offline and insecureTrustedDealer are mutually exclusive (fail closed)" }
        check(!(dealer != null && !c.insecureTrustedDealer && cOffline == null)) { "composeSecureMalicious: dealer options require insecureTrustedDealer: true (fail closed)" }
        val offline: OfflineProvider? = cOffline ?: if (c.insecureTrustedDealer) null else Mascot.makeNoDealerOffline(n, c.seed)
        check(!(offline != null && offline.n() != n)) { "composeSecureMalicious: offline provider party count != number of vectors" }
        val ctx = offline?.macContext() ?: Spdz.setupMac(n, rng)
        val engine = SpdzEngine(ctx, c.deviations ?: emptyList())
        var mults = 0
        val verify = dealer == null || dealer.verifyTriples == null || dealer.verifyTriples == true

        fun nextTriple(): AuthTriple {
            if (offline != null) return offline.genAuthTriple()
            if (!verify) {
                return if (dealer != null && dealer.fault != null) Spdz.genTripleWithPartners(ctx, rng, 1, dealer.fault).keep else Spdz.genAuthTriple(ctx, rng)
            }
            val partners = dealer?.partners ?: Spdz.SACRIFICE_PARTNERS
            val dealt = Spdz.genTripleWithPartners(ctx, rng, partners, dealer?.fault)
            return Spdz.sacrificeVerify(listOf(dealt), ctx, rng, emptyList())[0]
        }

        fun shareBit(bit: Int, owner: Int): AuthSV =
            if (offline != null) offline.authInput(BigInteger.valueOf(bit.toLong()), owner) else Spdz.authShare(BigInteger.valueOf(bit.toLong()), ctx, rng)

        fun andAll(bits: List<AuthSV>): AuthSV {
            if (bits.isEmpty()) return Spdz.authConstant(BigInteger.ONE, ctx)
            var acc = bits[0]
            for (i in 1 until bits.size) {
                acc = Spdz.beaverMulAuth(acc, bits[i], nextTriple(), ctx, engine, "and$i")
                mults++
            }
            return acc
        }

        fun orAll(bits: List<AuthSV>): AuthSV {
            if (bits.isEmpty()) return Spdz.authConstant(BigInteger.ZERO, ctx)
            var prod = Spdz.notBitAuth(bits[0], ctx)
            for (i in 1 until bits.size) {
                prod = Spdz.beaverMulAuth(prod, Spdz.notBitAuth(bits[i], ctx), nextTriple(), ctx, engine, "or$i")
                mults++
            }
            return Spdz.notBitAuth(prod, ctx)
        }

        val allowBits = ArrayList<AuthSV>()
        for (p in 0 until n) allowBits.add(shareBit(vectors[p].allow, p))
        val allowSV = andAll(allowBits)

        val tTherm = Array(n) { p -> Thermometer.thermometerEncode(vectors[p].t.toDouble(), T_M) }
        val tGe = ArrayList<AuthSV>()
        for (k in 0 until T_M) {
            val bits = ArrayList<AuthSV>()
            for (p in 0 until n) bits.add(shareBit(tTherm[p][k], p))
            tGe.add(orAll(bits))
        }
        val rTherm = Array(n) { p -> Thermometer.thermometerEncode(vectors[p].rQuant.toDouble(), q) }
        val rGe = ArrayList<AuthSV>()
        for (k in 0 until q) {
            val bits = ArrayList<AuthSV>()
            for (p in 0 until n) bits.add(shareBit(rTherm[p][k], p))
            rGe.add(orAll(bits))
        }

        val allowOpen = engine.open(allowSV, "out:allow")
        val tOpen = IntArray(T_M) { k -> if (engine.open(tGe[k], "out:t.ge${k + 1}") == BigInteger.ONE) 1 else 0 }
        val rOpen = IntArray(q) { k -> if (engine.open(rGe[k], "out:r.ge${k + 1}") == BigInteger.ONE) 1 else 0 }

        engine.macCheck(rng)

        val allow = if (allowOpen == BigInteger.ONE) 1 else 0
        val t = Math.min(3, Math.max(1, Thermometer.thermometerDecode(tOpen)))
        val rQuant = Thermometer.thermometerDecode(rOpen)
        return MaliciousMpcResult(
            ComposedDecision(allow, t, rQuant), n, q, engine.openCount(), mults,
            if (offline != null) "no-dealer" else "trusted-dealer", offline != null || verify, true,
        )
    }
}
