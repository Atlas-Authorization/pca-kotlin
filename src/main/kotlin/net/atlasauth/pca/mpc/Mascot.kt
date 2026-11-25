package net.atlasauth.pca.mpc

import java.math.BigInteger
import java.util.TreeSet
import net.atlasauth.pca.mpc.Enc.EncShare
import net.atlasauth.pca.mpc.Field.fadd
import net.atlasauth.pca.mpc.Field.fmul
import net.atlasauth.pca.mpc.Field.fneg
import net.atlasauth.pca.mpc.Field.fsub
import net.atlasauth.pca.mpc.Field.mod
import net.atlasauth.pca.mpc.Ot.OtChannel
import net.atlasauth.pca.mpc.Ot.OtRandom
import net.atlasauth.pca.mpc.Spdz.AuthSV
import net.atlasauth.pca.mpc.Spdz.AuthTriple
import net.atlasauth.pca.mpc.Spdz.MacCheckAbort
import net.atlasauth.pca.mpc.Spdz.MacContext
import net.atlasauth.pca.mpc.Spdz.MacKey
import net.atlasauth.pca.mpc.Spdz.SpdzEngine
import net.atlasauth.pca.mpc.Spdz.TripleWithPartners

/**
 * The no-dealer SPDZ offline phase (MASCOT-style): every product of two additively shared values is built from real oblivious transfers
 * (Gilboa multiplication over OT extension), the MAC key is distributed and never reconstructed, and every produced triple is certified by
 * the sacrifice check. When a check fails the OT transcripts are searched to blame the cheating party.
 */
object Mascot {
    /** A MAC-check abort raised by the offline phase, naming the party the OT transcripts convict (when one can be named). */
    class OfflineCheatingAbort(message: String, val blamed: List<Int>) :
        MacCheckAbort(if (blamed.isEmpty()) message else message + "; offline OT transcript names party " + blamed.joinToString(", "))

    private class OtRecord(val receiver: Int, val sender: Int, val msg0: Array<BigInteger>, val msg1: Array<BigInteger>, val received: Array<BigInteger>)

    private class ProductClaim(val claimed: Array<BigInteger>, val implied: Array<BigInteger>)

    /** TEST-ONLY: the productMul-th product's claimed share is shifted by delta (a cheating party lying about a product). */
    class OfflineDeviation(val productMul: Int, val delta: BigInteger)

    /** Options (null fields mean the defaults). */
    class NoDealerOptions {
        @JvmField var sacrifice: Boolean? = null
        @JvmField var sacrificePartners: Int? = null
        @JvmField var macKeys: Int? = null
        @JvmField var deviation: OfflineDeviation? = null
        @JvmField var statSec: Int? = null
        @JvmField var unsafeStatSec: Boolean = false
    }

    /** One operand of a multiplication request: either a plain value (BigInteger) or an encoded (value, choice bits) share. */
    private class Req(val x: List<Any>, val y: Array<BigInteger>)

    private class Part(val bits: IntArray, val gad: Array<BigInteger>)

    private class Piece(val value: BigInteger, val parts: List<Part>)

    private class Seg(val q: Int, val start: Int, val len: Int, val senderSum: BigInteger)

    class NoDealerOffline(val n: Int, seed: BigInteger?, opts0: NoDealerOptions?) : OfflineProvider {
        val alphaShares: Array<BigInteger>
        private val keyShares: Array<Array<BigInteger>>
        private val keyEnc: Array<Array<EncShare>>
        private val gadget: Array<BigInteger>
        val statSec: Int
        private val sacrificePartners: Int
        private val rng: Field.FieldRng
        private val seed: BigInteger
        private val deterministic: Boolean
        private val channels = HashMap<String, OtChannel>()
        private val sacrificeOn: Boolean
        private val deviation: OfflineDeviation?
        private var productMulCount = 0
        private var log: MutableList<OtRecord>? = null
        private var claims: MutableList<ProductClaim> = ArrayList()

        init {
            val opts = opts0 ?: NoDealerOptions()
            require(n >= 1) { "NoDealerOffline: n must be a positive integer" }
            deterministic = seed != null
            this.seed = seed ?: BigInteger("abcdef12345", 16)
            rng = if (deterministic) Field.FieldRng(this.seed) else Field.SecureFieldRng()
            sacrificeOn = opts.sacrifice == null || opts.sacrifice == true
            deviation = opts.deviation
            val keys = opts.macKeys ?: Spdz.MAC_KEYS
            require(keys in 1..16) { "NoDealerOffline: macKeys must be an integer in [1, 16]" }
            statSec = opts.statSec ?: Enc.STAT_SEC
            gadget = Enc.makeGadget(statSec, rng, opts.unsafeStatSec)
            keyEnc = Array(keys) { Array(n) { Enc.sampleEnc(gadget, rng) } }
            keyShares = Array(keys) { l -> Array(n) { i -> keyEnc[l][i].value } }
            alphaShares = keyShares[0]
            sacrificePartners = opts.sacrificePartners ?: Spdz.SACRIFICE_PARTNERS
            require(sacrificePartners in 1..8) { "NoDealerOffline: sacrificePartners must be an integer in [1, 8]" }
        }

        override fun n(): Int = n

        /** The MAC context: the shares of each key and (for tests and the check only) their sums. */
        override fun macContext(): MacContext {
            val keys = ArrayList<MacKey>()
            for (shares in keyShares) {
                var alpha = BigInteger.ZERO
                for (ai in shares) alpha = fadd(alpha, ai)
                keys.add(MacKey(shares.clone(), alpha))
            }
            return MacContext(n, keys[0].alphaShares, keys[0].alpha, ArrayList(keys.subList(1, keys.size)))
        }

        private fun channel(i: Int, j: Int): OtChannel {
            val key = "$i->$j"
            var ch = channels[key]
            if (ch == null) {
                val otRng: OtRandom = if (deterministic) {
                    Ot.otRandom(
                        Ot.splitMix64(
                            seed.xor(BigInteger.valueOf((i + 1).toLong()).multiply(BigInteger("100000001b3", 16)))
                                .xor(BigInteger.valueOf((j + 1).toLong()).multiply(BigInteger("1000000000", 16))),
                        ),
                    )
                } else {
                    Ot.secureOtRandom()
                }
                ch = OtChannel(otRng)
                channels[key] = ch
            }
            return ch
        }

        private fun sampleShare(): EncShare = Enc.sampleEnc(gadget, rng)

        /** Batched Gilboa multiplication: one OT-extension call per ordered party pair for every request. */
        private fun mulBatch(reqs: List<Req>): Array<Array<BigInteger>> {
            for (r in reqs) require(!(r.x.size != n || r.y.size != n)) { "otShareMultiply: wrong length" }
            val pieces = ArrayList<List<Piece>>()
            for (r in reqs) {
                val row = ArrayList<Piece>()
                for (xi in r.x) {
                    if (xi is EncShare) {
                        row.add(Piece(xi.value, listOf(Part(xi.bits, gadget))))
                    } else {
                        val v = mod(xi as BigInteger)
                        val e = Enc.sampleEnc(gadget, rng)
                        val d = Enc.plainShare(fsub(v, e.value))
                        row.add(Piece(v, listOf(Part(e.bits, gadget), Part(d.bits, Enc.plainGadget()))))
                    }
                }
                pieces.add(row)
            }
            val z = Array(reqs.size) { q -> Array(n) { i -> fmul(pieces[q][i].value, reqs[q].y[i]) } }
            for (i in 0 until n) {
                for (j in 0 until n) {
                    if (i == j) continue
                    var rows = 0
                    for (q in reqs.indices) for (part in pieces[q][i].parts) rows += part.bits.size
                    val bits = IntArray(rows)
                    val msg0 = Array<BigInteger>(rows) { BigInteger.ZERO }
                    val msg1 = Array<BigInteger>(rows) { BigInteger.ZERO }
                    val segs = ArrayList<Seg>()
                    var at = 0
                    for (q in reqs.indices) {
                        val y = mod(reqs[q].y[j])
                        for (part in pieces[q][i].parts) {
                            val len = part.bits.size
                            var senderSum = BigInteger.ZERO
                            for (k in 0 until len) {
                                val rho = rng.next()
                                senderSum = fadd(senderSum, rho)
                                bits[at + k] = part.bits[k]
                                msg0[at + k] = rho
                                msg1[at + k] = fadd(rho, fmul(part.gad[k], y))
                            }
                            segs.add(Seg(q, at, len, senderSum))
                            at += len
                        }
                    }
                    val received = channel(i, j).extend(bits, msg0, msg1).received
                    log?.add(OtRecord(i, j, msg0, msg1, received))
                    for (sg in segs) {
                        var receiverSum = BigInteger.ZERO
                        for (k in 0 until sg.len) receiverSum = fadd(receiverSum, mod(received[sg.start + k]))
                        z[sg.q][i] = fadd(z[sg.q][i], receiverSum)
                        z[sg.q][j] = fadd(z[sg.q][j], fneg(sg.senderSum))
                    }
                }
            }
            return z
        }

        /** Additive shares of x*y where party i holds x_i and y_i (all cross terms via OT). */
        fun otShareMultiply(x: List<Any>, y: Array<BigInteger>): Array<BigInteger> = mulBatch(listOf(Req(x, y)))[0]

        private fun keyReq(l: Int): List<Any> = keyEnc[l].toList()

        private fun authenticate(valueShares: Array<BigInteger>): AuthSV {
            val reqs = ArrayList<Req>()
            for (l in keyEnc.indices) reqs.add(Req(keyReq(l), valueShares))
            return toAuth(valueShares, mulBatch(reqs))
        }

        private fun toAuth(value: Array<BigInteger>, macs: Array<Array<BigInteger>>): AuthSV = AuthSV(value, macs[0], macs.copyOfRange(1, macs.size))

        private fun claimProduct(implied: Array<BigInteger>): Array<BigInteger> {
            val z = implied.clone()
            val idx = productMulCount++
            val dv = deviation
            if (dv != null && dv.productMul == idx) z[0] = fadd(z[0], dv.delta)
            claims.add(ProductClaim(z, implied))
            return z
        }

        private fun rawTripleWithPartners(partners: Int): TripleWithPartners {
            val kk = keyEnc.size
            val aEnc = Array(n) { sampleShare() }
            val bShares = Array(n) { rng.next() }
            val ahEnc = Array(partners) { Array(n) { sampleShare() } }
            val aVal = Array(n) { i -> aEnc[i].value }
            val ahVal = Array(partners) { r -> Array(n) { i -> ahEnc[r][i].value } }
            val reqs = ArrayList<Req>()
            reqs.add(Req(aEnc.toList(), bShares))
            for (r in 0 until partners) reqs.add(Req(ahEnc[r].toList(), bShares))
            val macStart = reqs.size
            for (l in 0 until kk) {
                reqs.add(Req(keyReq(l), aVal))
                reqs.add(Req(keyReq(l), bShares))
                for (r in 0 until partners) reqs.add(Req(keyReq(l), ahVal[r]))
            }
            val z1 = mulBatch(reqs)
            val cShares = claimProduct(z1[0])
            val chShares = Array(partners) { r -> claimProduct(z1[1 + r]) }
            val per = 2 + partners
            val reqs2 = ArrayList<Req>()
            for (l in 0 until kk) {
                reqs2.add(Req(keyReq(l), cShares))
                for (r in 0 until partners) reqs2.add(Req(keyReq(l), chShares[r]))
            }
            val z2 = mulBatch(reqs2)
            val per2 = 1 + partners
            val b = toAuth(bShares, macOf(z1, macStart, per, 1, kk))
            val keep = AuthTriple(toAuth(aVal, macOf(z1, macStart, per, 0, kk)), b, toAuth(cShares, macOf(z2, 0, per2, 0, kk)))
            val parts = ArrayList<AuthTriple>()
            for (r in 0 until partners) {
                parts.add(AuthTriple(toAuth(ahVal[r], macOf(z1, macStart, per, 2 + r, kk)), b, toAuth(chShares[r], macOf(z2, 0, per2, 1 + r, kk))))
            }
            return TripleWithPartners(keep, parts)
        }

        private fun macOf(z: Array<Array<BigInteger>>, start: Int, per: Int, off: Int, kk: Int): Array<Array<BigInteger>> =
            Array(kk) { l -> z[start + l * per + off] }

        private fun attribute(abort: MacCheckAbort): MacCheckAbort {
            val blamed = TreeSet<Int>()
            val lg = log
            if (lg != null) {
                for (r in lg) {
                    for (k in r.received.indices) {
                        val got = mod(r.received[k])
                        if (got != r.msg0[k] && got != r.msg1[k]) {
                            blamed.add(r.sender)
                            break
                        }
                    }
                }
            }
            for (c in claims) {
                for (i in c.claimed.indices) if (c.claimed[i] != c.implied[i]) blamed.add(i)
            }
            return OfflineCheatingAbort(abort.message ?: "", ArrayList(blamed))
        }

        /** One authenticated triple, certified by the sacrifice check (or raw when sacrifice is switched off). */
        override fun genAuthTriple(): AuthTriple {
            if (!sacrificeOn) return rawTripleWithPartners(0).keep
            log = ArrayList()
            claims = ArrayList()
            try {
                val t = rawTripleWithPartners(sacrificePartners)
                return Spdz.sacrificeVerify(listOf(t), macContext(), rng, emptyList())[0]
            } catch (e: MacCheckAbort) {
                throw attribute(e)
            } finally {
                log = null
                claims = ArrayList()
            }
        }

        fun genAuthTriples(count: Int): List<AuthTriple> {
            val out = ArrayList<AuthTriple>()
            for (k in 0 until count) out.add(genAuthTriple())
            return out
        }

        /** An authenticated sharing of a value contributed by [owner], MACed by OT under the distributed key. */
        override fun authInput(value: BigInteger, owner: Int): AuthSV {
            require(owner >= 0 && owner < n) { "authInput: owner out of range" }
            return authenticate(Sharing.share(mod(value), n, rng))
        }

        /** Verifies that every supplied input's MAC matches its value via a random combination (aborts otherwise). */
        fun checkInputConsistency(inputs: List<AuthSV>) {
            if (inputs.isEmpty()) return
            for (inp in inputs) require(!(inp.value.size != n || inp.mac.size != n)) { "checkInputConsistency: input party count mismatch" }
            val ctx = macContext()
            val engine = SpdzEngine(ctx, emptyList())
            val rShares = Array(n) { rng.next() }
            var w = authenticate(rShares)
            for (inp in inputs) {
                var e = rng.next()
                if (e.signum() == 0) e = BigInteger.ONE
                w = Spdz.addAuth(w, Spdz.scaleAuth(inp, e))
            }
            engine.open(w, "input-check:w")
            engine.macCheck(rng)
        }
    }

    /** The no-dealer offline provider of [n] parties; a non-null seed makes every draw reproducible (tests only). */
    @JvmStatic @JvmOverloads fun makeNoDealerOffline(n: Int, seed: BigInteger?, opts: NoDealerOptions? = null): NoDealerOffline = NoDealerOffline(n, seed, opts)
}
