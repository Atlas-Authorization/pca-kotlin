package net.atlasauth.pca.mpc.net

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.util.TreeMap
import net.atlasauth.pca.mpc.Ec
import net.atlasauth.pca.mpc.Ec.Point
import net.atlasauth.pca.mpc.Ec.SchnorrProof
import net.atlasauth.pca.mpc.Enc
import net.atlasauth.pca.mpc.Enc.EncShare
import net.atlasauth.pca.mpc.Field
import net.atlasauth.pca.mpc.Field.fadd
import net.atlasauth.pca.mpc.Field.fmul
import net.atlasauth.pca.mpc.Field.fsub
import net.atlasauth.pca.mpc.Field.mod
import net.atlasauth.pca.mpc.FieldSource
import net.atlasauth.pca.mpc.NetCodec
import net.atlasauth.pca.mpc.NetForensics.SlotDisclosure
import net.atlasauth.pca.mpc.NetPa.AW
import net.atlasauth.pca.mpc.NetPa.PA
import net.atlasauth.pca.mpc.NetWire
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.mpc.NetWire.hx
import net.atlasauth.pca.mpc.Ot
import net.atlasauth.pca.mpc.Ot.BaseOtAbort
import net.atlasauth.pca.mpc.Ot.BaseOtBinding
import net.atlasauth.pca.mpc.Ot.ExtRoundMsg
import net.atlasauth.pca.mpc.Ot.MalOtAbort
import net.atlasauth.pca.mpc.Ot.OtExtReceiver
import net.atlasauth.pca.mpc.Ot.OtExtSender
import net.atlasauth.pca.mpc.Otx
import net.atlasauth.pca.mpc.Thermometer

/**
 * The NO-DEALER offline phase over the mutual-TLS mesh. Each party holds only its own shares; every party samples its own MAC
 * key shares and triple shares, and the products needed for the triples and MACs are computed by Gilboa OT multiplication
 * between every ordered pair (kappa = 128 base OTs per ordered pair, OT extension with the KOS correlation check). Two
 * multiplication layers (products and the MACs of known values, then the MACs of the products) and a third layer giving every
 * share pairwise tags T_ij = K_ij + Delta_j * x_i, so the online phase can name a party that lies. Receivers choose with the
 * privacy-amplified encoding of their share (selective-failure remedy) under a gadget all parties contribute a signed seed to.
 * The triple sacrifice and the input-consistency check run online. No security proof; a wrong OT operand in the offline
 * triple products is attributable from the OT transcript only after the sacrifice fails.
 */
object OfflineNet {
    /** Most OT rows per extension round (bounds frame size and memory). */
    private const val ROWS_PER_ROUND = 128 * Enc.FIELD_BITS
    private const val T_M = 3
    private val HEX128 = Regex("^(0|[1-9a-f][0-9a-f]{0,31})$")

    /** The OT multiplication item: my choice bits (weights [gad], public) against my sender operand [y]. */
    private class Item(val bits: IntArray, val gad: Array<BigInteger>, val y: BigInteger)

    private class Kept(
        val recv: MutableMap<Int, MutableMap<Int, Array<BigInteger>>>,
        val rho: MutableMap<Int, MutableMap<Int, Array<BigInteger>>>,
    )

    private class Rows(val recv: Map<Int, Array<BigInteger>>, val sendSum: Map<Int, Array<BigInteger>>, val kept: Kept)

    private class Layer(val z: Array<BigInteger>, val kept: Kept)

    private class Cipher(val y0: Array<BigInteger>, val y1: Array<BigInteger>)

    private class PointMsg(val S: Point, val proof: SchnorrProof)

    private class BaseCt(val ct: Array<Array<ByteArray>>, val com: Array<Array<ByteArray>>)

    private class Triple(val a: EncShare, val b: BigInteger, val ah: List<EncShare>)

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val h = MessageDigest.getInstance("SHA-256")
        for (p in parts) h.update(p)
        return h.digest()
    }

    private fun utf8(s: String): ByteArray = Json.utf8(s)

    private fun le8(v: Long): ByteArray = Otx.bigToBytes(BigInteger.valueOf(v), 8)

    private fun fromLe8(b: ByteArray): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[i].toLong() and 0xffL)
        return v
    }

    /** The public gadget: H(all seeds in party order, session) expanded by a hash chain; every party contributed a committed seed. */
    @JvmStatic
    internal fun gadgetFromSeeds(sessionId: String, seeds: Array<ByteArray>): Array<BigInteger> {
        val input = ByteArrayOutputStream()
        val tag = utf8("atlas-pca-mpc/enc-gadget")
        input.write(tag, 0, tag.size)
        val sb = utf8(sessionId)
        input.write(sb, 0, sb.size)
        for (sd in seeds) input.write(sd, 0, sd.size)
        val seed = sha256(input.toByteArray())
        var ctr = 0L
        val mask = (1L shl 61) - 1
        val src = object : FieldSource {
            override fun next(): BigInteger {
                while (true) {
                    val v = fromLe8(sha256(seed, le8(ctr++))) and mask
                    if (v != mask) return BigInteger.valueOf(v)
                }
            }
        }
        return Enc.makeGadget(Enc.STAT_SEC, src, false)
    }

    /** Produces this party's [Prep] by running the no-dealer offline phase. */
    @JvmStatic
    fun run(ctx: Protocol.OfflineCtx): Prep = Run(ctx).go()

    private fun hex128(s: Any?): BigInteger {
        require(s is String && HEX128.matches(s)) { "bad 128-bit value" }
        return BigInteger(s, 16)
    }

    private fun pairsB64(ps: Array<Array<ByteArray>>): List<Any?> = ps.map { p -> arrayListOf<Any?>(NetCodec.b64(p[0]), NetCodec.b64(p[1])) }

    private fun parsePairs(raw: Any?, count: Int, len: Int): Array<Array<ByteArray>> {
        require(raw is List<*> && raw.size == count) { "bad pair array" }
        return Array(count) { i ->
            val p = raw[i]
            require(p is List<*> && p.size == 2) { "bad pair" }
            arrayOf(NetCodec.unb64(p[0], len), NetCodec.unb64(p[1], len))
        }
    }

    private fun encodeU(msg: ExtRoundMsg, mExt: Int): Any {
        val cb = (mExt + 7) / 8
        val bo = ByteArrayOutputStream()
        for (c in msg.u!!) {
            val b = Otx.bigToBytes(c, cb)
            bo.write(b, 0, b.size)
        }
        val m = LinkedHashMap<String, Any?>()
        m["u"] = NetCodec.b64(bo.toByteArray())
        m["x"] = msg.x!!.toString(16)
        m["t"] = msg.tComb!!.toString(16)
        return m
    }

    private fun decodeU(raw: Any?, mExt: Int): ExtRoundMsg {
        require(raw is Map<*, *>) { "bad extension message" }
        val cb = (mExt + 7) / 8
        val bytes = NetCodec.unb64(raw["u"], Ot.KAPPA * cb)
        val u = Array(Ot.KAPPA) { i -> Otx.bytesToBig(bytes.copyOfRange(i * cb, (i + 1) * cb)) }
        return ExtRoundMsg(u, hex128(raw["x"]), hex128(raw["t"]))
    }

    private fun packLe8(vs: Array<BigInteger>): ByteArray {
        val out = ByteArray(vs.size * 8)
        for (i in vs.indices) System.arraycopy(Otx.bigToBytes(vs[i], 8), 0, out, i * 8, 8)
        return out
    }

    private fun unpackLe8(b: ByteArray, m: Int): Array<BigInteger> =
        Array(m) { i -> Otx.bytesToBig(b.copyOfRange(i * 8, i * 8 + 8)) }

    private fun encodeY(c: Cipher): Any {
        val m = LinkedHashMap<String, Any?>()
        m["y0"] = NetCodec.b64(packLe8(c.y0))
        m["y1"] = NetCodec.b64(packLe8(c.y1))
        return m
    }

    private fun decodeY(raw: Any?, m: Int): Cipher {
        require(raw is Map<*, *>) { "bad ciphertext message" }
        return Cipher(unpackLe8(NetCodec.unb64(raw["y0"], m * 8), m), unpackLe8(NetCodec.unb64(raw["y1"], m * 8), m))
    }

    private class Run(val a: Protocol.OfflineCtx) {
        val mesh: Mesh = a.mesh
        val id: Int = a.id
        val n: Int = a.n
        val C: Int = a.C
        val K: Int = a.keys
        val P: Int = a.partners
        val io: Exchanger = a.io
        val others = ArrayList<Int>()
        val rng: Ot.OtRandom = Ot.secureOtRandom()
        val frng = Field.SecureFieldRng()
        val sid: ByteArray = sha256(utf8("atlas-pca-mpc/net-session/v2"), utf8(mesh.sessionId()))
        val behKind: String = a.behavior?.kind ?: ""
        var delta: BigInteger = BigInteger.ZERO
        lateinit var gadget: Array<BigInteger>
        val recvCh = TreeMap<Int, OtExtReceiver>()
        val sendCh = TreeMap<Int, OtExtSender>()

        init {
            for (i in 0 until n) if (i != id) others.add(i)
        }

        /** Binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is [recv] and extension sender is [send]. */
        fun chan(recv: Int, send: Int, round: String): BaseOtBinding = BaseOtBinding(sid, recv.toLong(), send.toLong(), round)

        fun <T> otGuard(peer: Int, what: String, f: () -> T): T {
            try {
                return f()
            } catch (e: NetAbort) {
                throw e
            } catch (e: RuntimeException) {
                val kind = if (e is BaseOtAbort || e is MalOtAbort || e is Ec.PointValidationError) "ot-check" else "malformed"
                val ne = NetAbort(kind, peer, id, what + ": " + e.message)
                mesh.fail(ne, null)
                throw ne
            }
        }

        fun arr(p: Int, raw: Any?, len: Int): Array<BigInteger> =
            NetWire.unhxArray(raw, len) ?: throw io.bad(p, "expected $len canonical field elements")

        fun go(): Prep {
            delta = frng.next()
            while (delta.signum() == 0) delta = frng.next()

            // ---- base OTs (kappa per ordered pair, both roles)
            val seeds = TreeMap<Int, Array<Array<ByteArray>>>()
            val mySetup = TreeMap<Int, Ot.SenderSetup>()
            val selector = TreeMap<Int, IntArray>()
            for (p in others) {
                val r = OtExtReceiver(rng, Ot.bindingBytes(chan(id, p, "iknp-kos")))
                seeds[p] = r.makeSeeds()
                recvCh[p] = r
                mySetup[p] = Ot.malBaseOtSenderSetup(rng, chan(id, p, "offline-kappa"))
                val s = OtExtSender(rng, Ot.bindingBytes(chan(p, id, "iknp-kos")))
                selector[p] = s.makeSelector()
                sendCh[p] = s
            }
            val theirS: Map<Int, PointMsg> = io.exchange("ob-S", { peer ->
                val st = mySetup[peer]!!
                val z = if (behKind == "ot-proof-lie") st.proof.z.add(BigInteger.ONE) else st.proof.z
                val m = LinkedHashMap<String, Any?>()
                m["S"] = NetCodec.ptJ(st.S)
                m["U"] = NetCodec.ptJ(st.proof.U)
                m["z"] = hx(z)
                m
            }, { p, raw ->
                if (raw !is Map<*, *>) throw io.bad(p, "bad S message")
                val proof = SchnorrProof(NetCodec.jPt(raw["U"]), NetCodec.hexBig(raw["z"]))
                PointMsg(NetCodec.jPt(raw["S"]), proof)
            })
            val respond = TreeMap<Int, Ot.ReceiverResponse>()
            for (p in others) {
                val st = theirS[p]!!
                respond[p] = otGuard(p, "base OT (receiver)") {
                    Ot.malBaseOtReceiverRespond(st.S, st.proof, selector[p]!!, rng, chan(p, id, "offline-kappa"))
                }
            }
            val theirR: Map<Int, Array<Point>> = io.exchange("ob-R", { peer ->
                val out = ArrayList<Any?>()
                for (pt in respond[peer]!!.R) out.add(NetCodec.ptJ(pt))
                out
            }, { p, raw ->
                if (raw !is List<*> || raw.size != Ot.KAPPA) throw io.bad(p, "bad R array")
                Array(Ot.KAPPA) { i -> NetCodec.jPt(raw[i]) }
            })
            val enc = TreeMap<Int, Array<Array<Array<ByteArray>>>>()
            for (p in others) {
                val st = mySetup[p]!!
                enc[p] = otGuard(p, "base OT (sender)") {
                    val pads = Ot.malBaseOtSenderDerive(st.y, st.T, theirR[p]!!, st.S, chan(id, p, "offline-kappa"))
                    Ot.baseOtSenderEncrypt(seeds[p]!!, pads)
                }
            }
            val theirCt: Map<Int, BaseCt> = io.exchange("ob-C", { peer ->
                val m = LinkedHashMap<String, Any?>()
                m["ct"] = pairsB64(enc[peer]!![0])
                m["com"] = pairsB64(enc[peer]!![1])
                m
            }, { p, raw ->
                if (raw !is Map<*, *>) throw io.bad(p, "bad ciphertext message")
                BaseCt(parsePairs(raw["ct"], Ot.KAPPA, 16), parsePairs(raw["com"], Ot.KAPPA, 32))
            })
            for (p in others) {
                val m = theirCt[p]!!
                val got = otGuard(p, "base OT (receiver)") {
                    Ot.baseOtReceiverDecrypt(selector[p]!!, respond[p]!!.recvPads, m.ct, m.com)
                }
                sendCh[p]!!.setSeeds(got)
            }

            // ---- the jointly contributed choice-bit gadget (signed commit / reveal / echo)
            val seedsAgreed = Gadget.agreeGadgetSeeds(mesh, n, io)
            gadget = gadgetFromSeeds(mesh.sessionId(), seedsAgreed)

            // ---- my randomness and the input sharings
            val alphaEnc = ArrayList<EncShare>()
            for (l in 0 until K) alphaEnc.add(Enc.sampleEnc(gadget, frng))
            val alphaShare = Array(K) { alphaEnc[it].value }
            val tb = Thermometer.thermometerEncode(a.input.t.toDouble(), T_M)
            val rb = Thermometer.thermometerEncode(a.input.rQuant.toDouble(), a.Q)
            val myBits = IntArray(1 + tb.size + rb.size)
            myBits[0] = a.input.allow
            System.arraycopy(tb, 0, myBits, 1, tb.size)
            System.arraycopy(rb, 0, myBits, 1 + tb.size, rb.size)
            if (myBits.size != C) throw NetAbort("local", null, id, "input chain count mismatch")
            val outShares = TreeMap<Int, Array<BigInteger>>()
            for (p in others) outShares[p] = Array(C) { frng.next() }
            val myOwn = Array(C) { c ->
                var s = BigInteger.valueOf(myBits[c].toLong())
                for (p in others) s = fsub(s, outShares[p]!![c])
                s
            }
            val gotShares: Map<Int, Array<BigInteger>> = io.exchange("in-share", { peer ->
                val out = ArrayList<Any?>()
                for (v in outShares[peer]!!) out.add(hx(v))
                out
            }, { p, raw -> arr(p, raw, C) })
            // my value share of every (owner, chain)
            val inputValue = Array(n * C) { q -> if (q / C == id) myOwn[q % C] else gotShares[q / C]!![q % C] }
            val maskShare = frng.next() // my share of the input-check mask

            val nT = (n - 1) * C
            val trs = List(nT) {
                val ae = Enc.sampleEnc(gadget, frng)
                val b = frng.next()
                val ah = List(P) { Enc.sampleEnc(gadget, frng) }
                Triple(ae, b, ah)
            }
            val aE = Array(nT) { trs[it].a }
            val bS = Array(nT) { trs[it].b }
            val ahE = Array(nT) { t -> Array(P) { r -> trs[t].ah[r] } }
            val aS = Array(nT) { aE[it].value }
            val ahS = Array(nT) { t -> Array(P) { r -> ahE[t][r].value } }

            // ---- layer 1: products and the MACs of known values
            val xs1 = ArrayList<EncShare>()
            val ys1 = ArrayList<BigInteger>()
            val iC = IntArray(nT)
            val iCh = Array(nT) { IntArray(P) }
            val iMa = Array(nT) { IntArray(K) }
            val iMb = Array(nT) { IntArray(K) }
            val iMah = Array(nT) { Array(P) { IntArray(K) } }
            for (t in 0 until nT) {
                iC[t] = push(xs1, ys1, aE[t], bS[t])
                for (r in 0 until P) iCh[t][r] = push(xs1, ys1, ahE[t][r], bS[t])
                for (l in 0 until K) iMa[t][l] = push(xs1, ys1, alphaEnc[l], aS[t])
                for (l in 0 until K) iMb[t][l] = push(xs1, ys1, alphaEnc[l], bS[t])
                for (r in 0 until P) for (l in 0 until K) iMah[t][r][l] = push(xs1, ys1, alphaEnc[l], ahS[t][r])
            }
            val iIn = Array(n * C) { IntArray(K) }
            for (q in 0 until n * C) for (l in 0 until K) iIn[q][l] = push(xs1, ys1, alphaEnc[l], inputValue[q])
            val iMask = IntArray(K)
            for (l in 0 until K) iMask[l] = push(xs1, ys1, alphaEnc[l], maskShare)
            val keepItems = HashSet<Int>()
            for (t in 0 until nT) {
                keepItems.add(iC[t])
                for (r in 0 until P) keepItems.add(iCh[t][r])
            }
            val l1 = mulLayer("1", xs1.toTypedArray(), ys1.toTypedArray(), if (behKind == "offline-lie" && nT > 0) iC[0] else -1, keepItems)
            val z1 = l1.z

            // ---- layer 2: the MACs of the products
            val cS = Array(nT) { z1[iC[it]] }
            val chS = Array(nT) { t -> Array(P) { r -> z1[iCh[t][r]] } }
            val xs2 = ArrayList<EncShare>()
            val ys2 = ArrayList<BigInteger>()
            val iMc = Array(nT) { IntArray(K) }
            val iMch = Array(nT) { Array(P) { IntArray(K) } }
            for (t in 0 until nT) {
                for (l in 0 until K) iMc[t][l] = push(xs2, ys2, alphaEnc[l], cS[t])
                for (r in 0 until P) for (l in 0 until K) iMch[t][r][l] = push(xs2, ys2, alphaEnc[l], chS[t][r])
            }
            val z2 = mulLayer("2", xs2.toTypedArray(), ys2.toTypedArray(), -1, null).z

            // ---- assemble, then pairwise-tag every share
            val triples = Array(nT) { t ->
                val sh = ArrayList<AW>()
                sh.add(aw(aS[t], iMa[t], z1))
                sh.add(aw(bS[t], iMb[t], z1))
                sh.add(aw(cS[t], iMc[t], z2))
                for (r in 0 until P) {
                    sh.add(aw(ahS[t][r], iMah[t][r], z1))
                    sh.add(aw(chS[t][r], iMch[t][r], z2))
                }
                sh.toTypedArray()
            }
            val inputs = Array(n * C) { q -> aw(inputValue[q], iIn[q], z1) }
            val checkMask = aw(maskShare, iMask, z1)
            val alpha = Array(K) { pa(alphaShare[it]) }
            val allPA = ArrayList<PA>()
            allPA.addAll(alpha)
            for (row in triples) for (w in row) addAll(allPA, w)
            for (w in inputs) addAll(allPA, w)
            addAll(allPA, checkMask)
            val plain = Array(allPA.size) { allPA[it].x }
            val tk = tagLayer("3", plain)
            for (u in plain.indices) {
                for (p in others) {
                    allPA[u].tag[p] = tk.first[p]!![u]
                    allPA[u].key[p] = tk.second[p]!![u]
                }
            }
            val myPlain = Array(C) { BigInteger.valueOf(myBits[it].toLong()) }
            val kept1 = l1.kept
            val fx = Prep.Forensics(gadget, gadget.size, 1 + P) { t ->
                val out = ArrayList<SlotDisclosure>()
                out.add(slot(kept1, iC[t], aE[t], bS[t], cS[t]))
                for (r in 0 until P) out.add(slot(kept1, iCh[t][r], ahE[t][r], bS[t], chS[t][r]))
                out
            }
            return Prep("no-dealer", true, delta, alpha, triples, inputs, myPlain, checkMask, fx)
        }

        fun slot(kept: Kept, item: Int, x: EncShare, y: BigInteger, z: BigInteger): SlotDisclosure {
            val recv = LinkedHashMap<Int, Array<BigInteger>>()
            val rho = LinkedHashMap<Int, Array<BigInteger>>()
            for (p in others) {
                recv[p] = kept.recv[p]!![item]!!
                rho[p] = kept.rho[p]!![item]!!
            }
            return SlotDisclosure(x.bits.clone(), y, z, recv, rho)
        }

        fun pa(x: BigInteger): PA = PA(x, Array(n) { BigInteger.ZERO }, Array(n) { BigInteger.ZERO })

        fun aw(value: BigInteger, macIdx: IntArray, z: Array<BigInteger>): AW = AW(pa(value), Array(macIdx.size) { pa(z[macIdx[it]]) })

        fun addAll(out: MutableList<PA>, w: AW) {
            out.add(w.v)
            out.addAll(w.m)
        }

        fun push(xs: MutableList<EncShare>, ys: MutableList<BigInteger>, x: EncShare, y: BigInteger): Int {
            xs.add(x)
            ys.add(y)
            return xs.size - 1
        }

        /**
         * The Gilboa OT core. For every peer p: as the OT RECEIVER towards p I choose with the bits of my xs[t] and get
         * recv[p][t] = x_t*y^p_t + sum(rho^p_t); as the OT SENDER I offer (rho_k, rho_k + gad_k*ys[t]) with fresh masks and keep
         * sendSum[p][t] = sum(rho). So recv - sendSum over the pair is an additive sharing of x_t*y_t.
         */
        fun otRows(layer: String, items: Array<Item>, keep: Set<Int>?): Rows {
            val T = items.size
            val recv = TreeMap<Int, Array<BigInteger>>()
            val sendSum = TreeMap<Int, Array<BigInteger>>()
            val kept = Kept(TreeMap(), TreeMap())
            for (p in others) {
                recv[p] = Array(T) { BigInteger.ZERO }
                sendSum[p] = Array(T) { BigInteger.ZERO }
                kept.recv[p] = TreeMap()
                kept.rho[p] = TreeMap()
            }
            if (T == 0 || others.isEmpty()) return Rows(recv, sendSum, kept)
            var rows = 0
            for (it in items) rows += it.bits.size
            val rowItem = IntArray(rows)
            val choice = IntArray(rows)
            val m0 = TreeMap<Int, Array<BigInteger>>()
            val m1 = TreeMap<Int, Array<BigInteger>>()
            for (p in others) {
                m0[p] = Array(rows) { BigInteger.ZERO }
                m1[p] = Array(rows) { BigInteger.ZERO }
            }
            var off = 0
            val itemOff = IntArray(T)
            for (t in 0 until T) {
                val it = items[t]
                val len = it.bits.size
                itemOff[t] = off
                val keepIt = keep != null && keep.contains(t)
                if (keepIt) for (p in others) kept.recv[p]!![t] = Array(len) { BigInteger.ZERO }
                for (k in 0 until len) {
                    choice[off + k] = it.bits[k]
                    rowItem[off + k] = t
                }
                for (p in others) {
                    val a0 = m0[p]!!
                    val a1 = m1[p]!!
                    var sumRho = BigInteger.ZERO
                    for (k in 0 until len) {
                        val rho = frng.next()
                        sumRho = fadd(sumRho, rho)
                        a0[off + k] = rho
                        a1[off + k] = fadd(rho, fmul(it.gad[k], it.y))
                    }
                    sendSum[p]!![t] = sumRho
                    if (keepIt) kept.rho[p]!![t] = a0.copyOfRange(off, off + len)
                }
                off += len
            }
            var chunk = 0
            var start = 0
            while (start < rows) {
                val s0 = start
                val e0 = minOf(rows, start + ROWS_PER_ROUND)
                val m = e0 - s0
                val mExt = m + Ot.KAPPA + Ot.SSEC
                val tag = "ox$layer.$chunk"
                val begun = TreeMap<Int, OtExtReceiver.Begin>()
                if (behKind == "ot-u-lie") {
                    // an inconsistent matrix: flip the first row in 64 of the 128 columns only (not a different choice vector)
                    for (p in others) recvCh[p]!!.tamperU = { u, _ -> for (i in 0 until 64) u[i] = u[i].xor(BigInteger.ONE) }
                }
                for (p in others) begun[p] = recvCh[p]!!.begin(choice.copyOfRange(s0, e0))
                val us: Map<Int, ExtRoundMsg> = io.exchange("$tag.u", { peer -> encodeU(begun[peer]!!.msg, mExt) }, { _, raw -> decodeU(raw, mExt) })
                val ys = TreeMap<Int, OtExtSender.Response>()
                for (p in others) {
                    ys[p] = otGuard(p, "OT extension ($tag)") {
                        sendCh[p]!!.respond(us[p]!!, m0[p]!!.copyOfRange(s0, e0), m1[p]!!.copyOfRange(s0, e0))
                    }
                }
                val cts: Map<Int, Cipher> = io.exchange("$tag.y", { peer -> encodeY(Cipher(ys[peer]!!.y0, ys[peer]!!.y1)) }, { _, raw -> decodeY(raw, m) })
                for (p in others) {
                    val got = otGuard(p, "OT extension ($tag)") { recvCh[p]!!.finish(begun[p]!!.pending, cts[p]!!.y0, cts[p]!!.y1) }
                    val rv = recv[p]!!
                    for (j in 0 until m) {
                        val t = rowItem[s0 + j]
                        rv[t] = fadd(rv[t], mod(got[j]))
                        if (keep != null && keep.contains(t)) kept.recv[p]!![t]!![s0 + j - itemOff[t]] = mod(got[j])
                    }
                }
                start += ROWS_PER_ROUND
                chunk++
            }
            return Rows(recv, sendSum, kept)
        }

        /** My additive share of X_t*Y_t = (sum x)(sum y): the diagonal x_i*y_i locally plus the Gilboa OT product of every ordered pair. */
        fun mulLayer(layer: String, xs: Array<EncShare>, ys: Array<BigInteger>, lieAt: Int, keep: Set<Int>?): Layer {
            val z = Array(xs.size) { t -> fmul(xs[t].value, ys[t]) }
            val items = Array(xs.size) { t -> Item(xs[t].bits, gadget, if (t == lieAt) fadd(ys[t], BigInteger.ONE) else ys[t]) }
            val r = otRows(layer, items, keep)
            for (p in others) {
                val rv = r.recv[p]!!
                val ss = r.sendSum[p]!!
                for (t in z.indices) z[t] = fsub(fadd(z[t], rv[t]), ss[t])
            }
            return Layer(z, r.kept)
        }

        /**
         * Pairwise tags for my shares: for every peer j a tag T_ij (mine) and a key K_ji with T_ij = K_ij + Delta_j*x_i. One OT
         * product of my x with j's Delta per item; each x is split as x = e + d with a fresh encoded e (a derived value has no
         * uniform choice-bit encoding of its own), both halves multiplied with Delta and added. Returns (tag, key) by peer.
         */
        fun tagLayer(layer: String, xs: Array<BigInteger>): Pair<Map<Int, Array<BigInteger>>, Map<Int, Array<BigInteger>>> {
            val plainGadget = Enc.plainGadget()
            val list = ArrayList<Item>()
            for (u in xs.indices) {
                val e = Enc.sampleEnc(gadget, frng)
                val d = Enc.plainShare(fsub(xs[u], e.value))
                list.add(Item(e.bits, gadget, delta))
                list.add(Item(d.bits, plainGadget, delta))
            }
            val r = otRows(layer, list.toTypedArray(), null)
            val tag = TreeMap<Int, Array<BigInteger>>()
            val key = TreeMap<Int, Array<BigInteger>>()
            for (p in others) {
                val rv = r.recv[p]!!
                val kv = r.sendSum[p]!!
                tag[p] = Array(xs.size) { u -> fadd(rv[2 * u], rv[2 * u + 1]) }
                key[p] = Array(xs.size) { u -> fadd(kv[2 * u], kv[2 * u + 1]) }
            }
            return Pair(tag, key)
        }
    }
}
