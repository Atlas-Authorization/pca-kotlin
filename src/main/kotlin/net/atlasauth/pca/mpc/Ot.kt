package net.atlasauth.pca.mpc

import net.atlasauth.pca.verifier.Json

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import net.atlasauth.pca.mpc.Ec.Point
import net.atlasauth.pca.mpc.Ec.SchnorrProof
import net.atlasauth.pca.mpc.Otx.COLS
import org.bouncycastle.crypto.digests.SHAKEDigest

/**
 * Oblivious transfer, the root of the no-dealer offline phase. (1) A maliciously secure Chou-Orlandi base OT over the Ed25519 subgroup:
 * the sender proves knowledge of its discrete log with a Schnorr NIZK, every received point is validated, and the core runs as a random
 * OT so there is no selective-failure surface. (2) IKNP OT extension with the KOS consistency check (a deviating receiver is caught and
 * the protocol aborts). Both roles run in one process; the functions take both parties' inputs and return the receiver's outputs plus an
 * inspectable transcript.
 */
object Ot {
    /** IKNP security parameter (number of base OTs / width of the selector s). */
    const val KAPPA = 128

    /** KOS statistical parameter: extra random check rows beyond the kappa that mask the revealed combination. */
    const val SSEC = 128
    internal const val SEED_BYTES = KAPPA / 8

    /** The KOS correlation check failed: a cheating OT-extension receiver is detected. */
    class MalOtAbort(message: String) : RuntimeException(message)

    /** A base OT aborted: a cheating sender (bad proof / inconsistent ciphertext) is detected. */
    class BaseOtAbort(message: String) : RuntimeException(message)

    /** A source of scalars and seeds for OT needs. */
    interface OtRandom {
        /** A uniform scalar in [1, L). */
        fun scalar(): BigInteger

        /** n random bytes. */
        fun bytes(n: Int): ByteArray
    }

    /** The CSPRNG-backed default: scalars by rejection over 32 random bytes. */
    @JvmStatic fun secureOtRandom(): OtRandom {
        val rnd = SecureRandom()
        return object : OtRandom {
            override fun scalar(): BigInteger {
                val bound = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE.shiftLeft(256).mod(Ec.L))
                val b = ByteArray(32)
                while (true) {
                    rnd.nextBytes(b)
                    val acc = BigInteger(1, b)
                    if (acc >= bound) continue
                    val s = acc.mod(Ec.L)
                    if (s.signum() != 0) return s
                }
            }

            override fun bytes(n: Int): ByteArray {
                val b = ByteArray(n)
                rnd.nextBytes(b)
                return b
            }
        }
    }

    /** A raw SplitMix64 stream (deterministic; for reproducible tests only). */
    @JvmStatic fun splitMix64(seed: BigInteger): () -> Long {
        var s = seed.toLong()
        return {
            s += -0x61c8864680b583ebL // 0x9e3779b97f4a7c15
            var z = s
            z = (z xor (z ushr 30)) * -0x40a7b892e31b1a47L // 0xbf58476d1ce4e5b9
            z = (z xor (z ushr 27)) * -0x6b2fb644ecceee15L // 0x94d049bb133111eb
            z xor (z ushr 31)
        }
    }

    private val M64: BigInteger = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)

    private fun u64(v: Long): BigInteger = BigInteger.valueOf(v).and(M64)

    /** An OtRandom from a 64-bit stream (each long is an unsigned 64-bit value). */
    @JvmStatic fun otRandom(next64: () -> Long): OtRandom = object : OtRandom {
        override fun scalar(): BigInteger {
            for (attempt in 0 until 8) {
                var acc = BigInteger.ZERO
                for (i in 0 until 4) acc = acc.shiftLeft(64).or(u64(next64()))
                val s = acc.mod(Ec.L)
                if (s.signum() != 0) return s
            }
            throw IllegalStateException("otRandom: entropy stream returned zero scalars repeatedly (RNG failure)")
        }

        override fun bytes(n: Int): ByteArray {
            val out = ByteArray(n)
            var have = 0
            while (have < n) {
                var v = next64()
                var i = 0
                while (i < 8 && have < n) {
                    out[have++] = v.toByte()
                    v = v ushr 8
                    i++
                }
            }
            return out
        }
    }

    private fun sha256(vararg chunks: ByteArray): ByteArray {
        val h = MessageDigest.getInstance("SHA-256")
        for (c in chunks) h.update(c)
        return h.digest()
    }

    internal fun u32(x: Long): ByteArray = byteArrayOf((x ushr 24).toByte(), (x ushr 16).toByte(), (x ushr 8).toByte(), x.toByte())

    private fun utf8(s: String): ByteArray = Json.utf8(s)

    private fun concat(vararg parts: ByteArray): ByteArray {
        var n = 0
        for (p in parts) n += p.size
        val out = ByteArray(n)
        var o = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, o, p.size)
            o += p.size
        }
        return out
    }

    /** Session binding of one base OT: who runs it, in which session and round (indices are uint32). */
    class BaseOtBinding(val sessionId: ByteArray?, val senderIndex: Long, val receiverIndex: Long, val round: String)

    private val TAG_BINDING = utf8("atlas-pca-mpc/base-ot-binding")
    private val TAG_TRANSCRIPT = utf8("atlas-pca-mpc/base-ot-transcript")
    private val TAG_KDF = utf8("atlas-pca-mpc/ot-kdf")
    private val TAG_KOS = utf8("atlas-pca-mpc/ot-kos")
    private val TAG_COMMIT = utf8("atlas-pca-mpc/ot-msg-commit")

    /** Canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input). */
    @JvmStatic fun bindingBytes(b: BaseOtBinding): ByteArray {
        val sid = b.sessionId
        require(!(sid == null || sid.size < 8 || sid.size > 64)) { "base-OT binding: sessionId must be 8..64 bytes" }
        require(!(b.senderIndex < 0 || b.senderIndex > 0xffffffffL)) { "base-OT binding: senderIndex must be a uint32" }
        require(!(b.receiverIndex < 0 || b.receiverIndex > 0xffffffffL)) { "base-OT binding: receiverIndex must be a uint32" }
        require(b.senderIndex != b.receiverIndex) { "base-OT binding: sender and receiver must be different parties" }
        val round = utf8(b.round)
        require(!(round.isEmpty() || round.size > 64)) { "base-OT binding: round label must be 1..64 bytes" }
        return concat(TAG_BINDING, u32(sid.size.toLong()), sid, u32(b.senderIndex), u32(b.receiverIndex), u32(round.size.toLong()), round)
    }

    /** A fresh binding for an in-process OT: a random 16-byte session id from [rng]. */
    @JvmStatic @JvmOverloads fun randomBinding(rng: OtRandom, round: String, senderIndex: Long = 0, receiverIndex: Long = 1): BaseOtBinding =
        BaseOtBinding(rng.bytes(16), senderIndex, receiverIndex, round)

    /** Hash of the whole base-OT transcript: binding, S and every receiver point, in order. */
    @JvmStatic fun baseOtTranscriptHash(binding: BaseOtBinding, s: Point, r: Array<Point>): ByteArray {
        val parts = ArrayList<ByteArray>()
        parts.add(TAG_TRANSCRIPT)
        parts.add(bindingBytes(binding))
        parts.add(Ec.encodePoint(s))
        parts.add(u32(r.size.toLong()))
        for (p in r) parts.add(Ec.encodePoint(p))
        return sha256(*parts.toTypedArray())
    }

    /** H("ot-kdf" || H(transcript) || index || R_i || P), SEED_BYTES bytes. */
    @JvmStatic fun baseOtKdf(transcriptHash: ByteArray, index: Int, ri: Point, p: Point): ByteArray =
        sha256(TAG_KDF, transcriptHash, u32(index.toLong()), Ec.encodePoint(ri), Ec.encodePoint(p)).copyOf(SEED_BYTES)

    /** The KOS row-weights as little-endian u32 words (4 per row): SHAKE256 over the binding, round and every column of u. */
    @JvmStatic fun kosChiWords(binding: ByteArray, round: Int, u: Array<BigInteger>, mExt: Int, colBytesList: Array<ByteArray>?): IntArray {
        val colBytes = (mExt + 7) / 8
        val xof = SHAKEDigest(256)
        absorb(xof, TAG_KOS)
        absorb(xof, u32(binding.size.toLong()))
        absorb(xof, binding)
        absorb(xof, u32(round.toLong()))
        absorb(xof, u32(mExt.toLong()))
        absorb(xof, u32(u.size.toLong()))
        if (colBytesList != null) {
            for (cb in colBytesList) absorb(xof, cb)
        } else {
            for (col in u) absorb(xof, Otx.bigToBytes(col, colBytes))
        }
        val out = ByteArray(mExt * 16)
        xof.doFinal(out, 0, out.size)
        return Otx.wordsFromLeBytes(out, mExt * 4)
    }

    private fun absorb(d: SHAKEDigest, b: ByteArray) = d.update(b, 0, b.size)

    @JvmStatic fun kosChallenges(binding: ByteArray, round: Int, u: Array<BigInteger>, mExt: Int): Array<BigInteger> {
        val w = kosChiWords(binding, round, u, mExt, null)
        return Array(mExt) { j -> Otx.gfToBig(w, 4 * j) }
    }

    private fun xorBytes(a: ByteArray, b: ByteArray): ByteArray = ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }

    // ---- base OT ----

    /** TEST-ONLY injection points modelling a malicious sender or receiver in the base OT (null = honest). */
    class BaseOtTamper {
        @JvmField var tamperS: ((Point) -> Point)? = null
        @JvmField var tamperProof: ((SchnorrProof) -> SchnorrProof)? = null
        @JvmField var tamperR: ((Array<Point>) -> Unit)? = null
        @JvmField var tamperCiphertext: ((Array<Array<ByteArray>>) -> Unit)? = null
    }

    /** The base-OT transcript. ct and com hold [i][0/1] byte strings. */
    class BaseOtTranscript(val S: Point, val proof: SchnorrProof, val R: Array<Point>, val ct: Array<Array<ByteArray>>, val com: Array<Array<ByteArray>>)

    class BaseOtResult(val received: Array<ByteArray>, val transcript: BaseOtTranscript)

    /** A pluggable chosen-message base OT: messages[i] = {m0, m1}; returns the receiver's recovered messages. */
    fun interface BaseOtFn {
        fun run(messages: Array<Array<ByteArray>>, choices: IntArray, rng: OtRandom): Array<ByteArray>
    }

    /** Output of the malicious-secure random base OT: validated points and the two RO pads per index. */
    class MalRandomOtResult(val S: Point, val proof: SchnorrProof, val R: Array<Point>, val senderPads: Array<Array<ByteArray>>, val recvPads: Array<ByteArray>)

    private fun otCommit(i: Int, b: Int, msg: ByteArray, pad: ByteArray): ByteArray =
        sha256(TAG_COMMIT, u32(i.toLong()), byteArrayOf((b and 1).toByte()), msg, pad)

    @JvmStatic fun malBaseRandomOT(choices: IntArray, rng0: OtRandom?, tamper: BaseOtTamper?, binding0: BaseOtBinding?): MalRandomOtResult {
        val rng = rng0 ?: secureOtRandom()
        val binding = binding0 ?: randomBinding(rng, "base-ot")
        val setup = malBaseOtSenderSetup(rng, binding)
        val ts = tamper?.tamperS
        val s = if (ts != null) ts(setup.S) else setup.S
        val tp = tamper?.tamperProof
        val proof = if (tp != null) tp(setup.proof) else setup.proof
        val rr = malBaseOtReceiverRespond(s, proof, choices, rng, binding)
        tamper?.tamperR?.invoke(rr.R)
        val senderPads = malBaseOtSenderDerive(setup.y, setup.T, rr.R, s, binding)
        return MalRandomOtResult(s, proof, rr.R, senderPads, rr.recvPads)
    }

    class SenderSetup(val y: BigInteger, val T: Point, val S: Point, val proof: SchnorrProof)

    @JvmStatic fun malBaseOtSenderSetup(rng: OtRandom, binding: BaseOtBinding): SenderSetup {
        val ctx = bindingBytes(binding)
        val y = rng.scalar()
        val s = Ec.mulBase(y)
        val t = Ec.mul(y, s)
        val proof = Ec.schnorrProve(y, s, { rng.scalar() }, ctx)
        return SenderSetup(y, t, s, proof)
    }

    class ReceiverResponse(val R: Array<Point>, val recvPads: Array<ByteArray>)

    @JvmStatic fun malBaseOtReceiverRespond(s: Point, proof: SchnorrProof, choices: IntArray, rng: OtRandom, binding: BaseOtBinding): ReceiverResponse {
        val ctx = bindingBytes(binding)
        Ec.assertInSubgroup(s, "base-OT S (received by receiver)")
        if (!Ec.schnorrVerify(s, proof, ctx)) throw BaseOtAbort("base OT: sender Schnorr proof-of-knowledge of S=y·B failed; aborting")
        val xs = ArrayList<BigInteger>()
        val r = ArrayList<Point>()
        for (i in choices.indices) {
            val x = rng.scalar()
            val ci = choices[i] and 1
            r.add(if (ci == 1) Ec.addPoints(Ec.mulBase(x), s) else Ec.mulBase(x))
            xs.add(x)
        }
        val ra = r.toTypedArray()
        val th = baseOtTranscriptHash(binding, s, ra)
        val recvPads = Array(choices.size) { i -> baseOtKdf(th, i, ra[i], Ec.mul(xs[i], s)) }
        return ReceiverResponse(ra, recvPads)
    }

    @JvmStatic fun malBaseOtSenderDerive(y: BigInteger, t: Point, r: Array<Point>, s: Point, binding: BaseOtBinding): Array<Array<ByteArray>> {
        for (i in r.indices) Ec.assertInSubgroup(r[i], "base-OT R_$i (received by sender)")
        val th = baseOtTranscriptHash(binding, s, r)
        return Array(r.size) { i ->
            val yR = Ec.mul(y, r[i])
            arrayOf(baseOtKdf(th, i, r[i], yR), baseOtKdf(th, i, r[i], Ec.sub(yR, t)))
        }
    }

    /** One-time-pads the messages under the sender pads and commits to each (message, pad). Returns {ct, com}. */
    @JvmStatic fun baseOtSenderEncrypt(messages: Array<Array<ByteArray>>, senderPads: Array<Array<ByteArray>>): Array<Array<Array<ByteArray>>> {
        require(messages.size == senderPads.size) { "baseOT: messages/pads length mismatch" }
        for (i in messages.indices) {
            val m0 = messages[i][0]
            val m1 = messages[i][1]
            require(!(m0.size > SEED_BYTES || m1.size > SEED_BYTES || m0.size != m1.size)) {
                "baseOT: message pair $i must be equal length and at most $SEED_BYTES bytes (pad width)"
            }
        }
        val ct = Array(messages.size) { i -> arrayOf(xorBytes(messages[i][0], senderPads[i][0]), xorBytes(messages[i][1], senderPads[i][1])) }
        val com = Array(messages.size) { i ->
            arrayOf(otCommit(i, 0, messages[i][0], senderPads[i][0]), otCommit(i, 1, messages[i][1], senderPads[i][1]))
        }
        return arrayOf(ct, com)
    }

    @JvmStatic fun baseOtReceiverDecrypt(choices: IntArray, recvPads: Array<ByteArray>, ct: Array<Array<ByteArray>>, com: Array<Array<ByteArray>>): Array<ByteArray> {
        if (ct.size != choices.size || com.size != choices.size || recvPads.size != choices.size) {
            throw BaseOtAbort("base OT: ciphertext/commitment count does not match the number of choices; aborting")
        }
        return Array(choices.size) { i ->
            val ci = choices[i] and 1
            val c0 = ct[i][0]
            val c1 = ct[i][1]
            if (c0.size != c1.size || c0.size > SEED_BYTES) throw BaseOtAbort("base OT (index $i): malformed ciphertext shape; aborting")
            val m = xorBytes(ct[i][ci], recvPads[i])
            val check = otCommit(i, ci, m, recvPads[i])
            if (!MessageDigest.isEqual(check, com[i][ci])) throw BaseOtAbort("base OT (index $i): sender ciphertext inconsistent with its commitment; aborting")
            m
        }
    }

    /** Chosen-message 1-of-2 OT for `choices.size` transfers, built over the random base OT. */
    @JvmStatic fun baseOT(messages: Array<Array<ByteArray>>, choices: IntArray, rng0: OtRandom?, tamper: BaseOtTamper?, binding0: BaseOtBinding?): BaseOtResult {
        val rng = rng0 ?: secureOtRandom()
        val binding = binding0 ?: randomBinding(rng, "base-ot")
        require(messages.size == choices.size) { "baseOT: messages/choices length mismatch" }
        val ro = malBaseRandomOT(choices, rng, tamper, binding)
        val enc = baseOtSenderEncrypt(messages, ro.senderPads)
        val ct = enc[0]
        val com = enc[1]
        tamper?.tamperCiphertext?.invoke(ct)
        val received = baseOtReceiverDecrypt(choices, ro.recvPads, ct, com)
        return BaseOtResult(received, BaseOtTranscript(ro.S, ro.proof, ro.R, ct, com))
    }

    // ---- OT extension (IKNP + KOS) ----

    /** The receiver's extension-round message: the u columns and the KOS values (x, t). */
    class ExtRoundMsg(val u: Array<BigInteger>?, val x: BigInteger?, val tComb: BigInteger?)

    /** The receiver's per-round state between `begin` and `finish`. */
    class ExtPending(val m: Int, val choiceBits: IntArray, val t: IntArray, val W: Int, val rowOffset: Long)

    private fun checkExtInputs(choiceBits: IntArray, msg0: Array<BigInteger>?, msg1: Array<BigInteger>?) {
        val m = choiceBits.size
        val limit = BigInteger.ONE.shiftLeft(64)
        for (j in 0 until m) require(!(choiceBits[j] != 0 && choiceBits[j] != 1)) { "OtChannel.extend: choice bit $j must be 0 or 1" }
        if (msg0 != null && msg1 != null) {
            for (j in 0 until m) {
                val a = if (j < msg0.size) msg0[j] else null
                val b = if (j < msg1.size) msg1[j] else null
                require(!(a == null || b == null || a.signum() < 0 || b.signum() < 0 || a >= limit || b >= limit)) {
                    "OtChannel.extend: message $j must be a bigint in [0, 2^64) (the pad is 64 bits wide)"
                }
            }
        }
    }

    /** The extension receiver (base-OT sender): makes the seed pairs, then per round the u matrix and KOS values. */
    class OtExtReceiver(private val rng: OtRandom, private val kosBinding: ByteArray) {
        private val seed0 = ArrayList<ByteArray>()
        private val seed1 = ArrayList<ByteArray>()
        private val blk0 = LongArray(KAPPA)
        private val blk1 = LongArray(KAPPA)
        private var round = 0
        private var rowsDone = 0L
        private val tweakDomain: IntArray = Otx.otTweakDomain(kosBinding)
        @JvmField var ready = false

        /** TEST-ONLY: mutate the u columns on the wire (a malicious receiver). */
        @JvmField var tamperU: ((Array<BigInteger>, Int) -> Unit)? = null

        /** The kappa seed pairs, to be transferred by the base OT with the sender's selector as choices. */
        fun makeSeeds(): Array<Array<ByteArray>> {
            val messages = Array(KAPPA) {
                val k0 = rng.bytes(SEED_BYTES)
                val k1 = rng.bytes(SEED_BYTES)
                seed0.add(k0)
                seed1.add(k1)
                arrayOf(k0, k1)
            }
            ready = true
            return messages
        }

        class Begin(val msg: ExtRoundMsg, val pending: ExtPending)

        fun begin(choiceBits: IntArray): Begin {
            check(ready) { "OtExtReceiver: base OT not done" }
            checkExtInputs(choiceBits, null, null)
            val m = choiceBits.size
            val roundIdx = round++
            val rowOffset = rowsDone
            rowsDone += m
            val pad = KAPPA + SSEC
            val mExt = m + pad
            val W = (mExt + 31) ushr 5
            val colBytes = (mExt + 7) / 8
            val bvec = IntArray(W)
            for (j in 0 until m) if ((choiceBits[j] and 1) != 0) bvec[j ushr 5] = bvec[j ushr 5] or (1 shl (j and 31))
            val padBytes = rng.bytes(pad)
            for (p in 0 until pad) {
                if ((padBytes[p].toInt() and 1) != 0) {
                    val j = m + p
                    bvec[j ushr 5] = bvec[j ushr 5] or (1 shl (j and 31))
                }
            }
            val blocks = (W + 3) / 4
            val t = IntArray(COLS * W)
            val u = Array<BigInteger>(COLS) { BigInteger.ZERO }
            val uw = IntArray(W)
            val ubytes = Array(COLS) { ByteArray(0) }
            for (i in 0 until KAPPA) {
                val ti = Otx.prgColumn(seed0[i], blk0[i], W)
                val gi = Otx.prgColumn(seed1[i], blk1[i], W)
                blk0[i] += blocks.toLong()
                blk1[i] += blocks.toLong()
                Otx.maskTail(ti, mExt)
                Otx.maskTail(gi, mExt)
                System.arraycopy(ti, 0, t, i * W, W)
                for (w in 0 until W) uw[w] = gi[w] xor ti[w] xor bvec[w]
                val all = ByteArray(4 * W)
                for (w in 0 until W) {
                    all[4 * w] = uw[w].toByte()
                    all[4 * w + 1] = (uw[w] ushr 8).toByte()
                    all[4 * w + 2] = (uw[w] ushr 16).toByte()
                    all[4 * w + 3] = (uw[w] ushr 24).toByte()
                }
                ubytes[i] = all.copyOf(colBytes)
                u[i] = Otx.bytesToBig(ubytes[i])
            }
            tamperU?.invoke(u, roundIdx)
            val pending = ExtPending(m, choiceBits.clone(), t, W, rowOffset)
            val limit = BigInteger.ONE.shiftLeft(mExt)
            for (c in u) {
                if (c.signum() < 0 || c >= limit) return Begin(ExtRoundMsg(u, BigInteger.ZERO, BigInteger.ZERO), pending)
            }
            val chi = kosChiWords(kosBinding, roundIdx, u, mExt, if (tamperU != null) null else ubytes)
            val x = IntArray(4)
            Otx.accumColumn(bvec, 0, W, chi, x)
            val tComb = Otx.kosCombine(t, W, chi)
            return Begin(ExtRoundMsg(u, Otx.gfToBig(x), Otx.gfToBig(tComb)), pending)
        }

        /** The receiver's outputs: m_{c_j} for every row j, from the sender's ciphertexts. */
        fun finish(pending: ExtPending, y0: Array<BigInteger>, y1: Array<BigInteger>): Array<BigInteger> {
            val m = pending.m
            if (y0.size != m || y1.size != m) throw MalOtAbort("OT extension: ciphertext count does not match the number of rows; aborting")
            val rows = Otx.transposeCols(pending.t, pending.W, m)
            val h = Otx.tmmoCrh(rows, m, Otx.OtTweak(pending.rowOffset, tweakDomain))
            return Array(m) { j -> (if (pending.choiceBits[j] == 1) y1[j] else y0[j]).xor(Otx.word64(h, j)) }
        }
    }

    /** The extension sender (base-OT receiver): holds the secret selector s and answers each round after the KOS check. */
    class OtExtSender(private val rng: OtRandom, private val kosBinding: ByteArray) {
        private var s = IntArray(0)
        private var sBits = BigInteger.ZERO
        private var seeds: Array<ByteArray> = emptyArray()
        private var blk = LongArray(0)
        private var round = 0
        private var rowsDone = 0L
        private val tweakDomain: IntArray = Otx.otTweakDomain(kosBinding)
        @JvmField var ready = false

        fun makeSelector(): IntArray {
            s = IntArray(KAPPA) { rng.bytes(1)[0].toInt() and 1 }
            return s.clone()
        }

        fun setSeeds(seeds: Array<ByteArray>) {
            check(!(seeds.size != KAPPA || s.size != KAPPA)) { "OtExtSender: wrong base-OT output size" }
            this.seeds = seeds
            this.blk = LongArray(KAPPA)
            var acc = BigInteger.ZERO
            for (i in 0 until KAPPA) if (s[i] == 1) acc = acc.setBit(i)
            this.sBits = acc
            this.ready = true
        }

        fun selector(): BigInteger = sBits

        class Response(val y0: Array<BigInteger>, val y1: Array<BigInteger>)

        fun respond(msg: ExtRoundMsg, msg0: Array<BigInteger>, msg1: Array<BigInteger>): Response {
            check(ready) { "OtExtSender: base OT not done" }
            val m = msg0.size
            require(msg1.size == m) { "OtChannel.extend: length mismatch" }
            checkExtInputs(IntArray(m), msg0, msg1)
            val roundIdx = round++
            val rowOffset = rowsDone
            rowsDone += m
            val mExt = m + KAPPA + SSEC
            val u = msg.u
            if (u == null || u.size != KAPPA) {
                throw MalOtAbort("KOS check (round $roundIdx): wrong number of u columns; a cheating OT-extension receiver was detected; aborting")
            }
            val colLimit = BigInteger.ONE.shiftLeft(mExt)
            for (i in 0 until KAPPA) {
                val ui = u[i]
                if (ui.signum() < 0 || ui >= colLimit) {
                    throw MalOtAbort("KOS check (round $roundIdx): malformed u column $i; a cheating OT-extension receiver was detected; aborting")
                }
            }
            val lim128 = BigInteger.ONE.shiftLeft(128)
            val mx = msg.x
            val mt = msg.tComb
            if (mx == null || mt == null || mx.signum() < 0 || mx >= lim128 || mt.signum() < 0 || mt >= lim128) {
                throw MalOtAbort("KOS check (round $roundIdx): malformed (x, t); a cheating OT-extension receiver was detected; aborting")
            }
            val W = (mExt + 31) ushr 5
            val colBytes = (mExt + 7) / 8
            val blocks = (W + 3) / 4
            val q = IntArray(COLS * W)
            val ubytes = Array(COLS) { ByteArray(0) }
            for (i in 0 until KAPPA) {
                ubytes[i] = Otx.bigToBytes(u[i], colBytes)
                val ks = Otx.prgColumn(seeds[i], blk[i], W)
                blk[i] += blocks.toLong()
                Otx.maskTail(ks, mExt)
                if (s[i] == 1) {
                    val ub = ByteArray(4 * W)
                    System.arraycopy(ubytes[i], 0, ub, 0, ubytes[i].size)
                    val uw = Otx.wordsFromLeBytes(ub, W)
                    for (w in 0 until W) ks[w] = ks[w] xor uw[w]
                }
                System.arraycopy(ks, 0, q, i * W, W)
            }
            val chi = kosChiWords(kosBinding, roundIdx, u, mExt, ubytes)
            val qComb = Otx.gfToBig(Otx.kosCombine(q, W, chi))
            val expected = mt.xor(Gf128.mul(mx, sBits))
            if (qComb != expected) {
                throw MalOtAbort("KOS correlation check FAILED (round $roundIdx): a cheating OT-extension receiver was detected; aborting")
            }
            val rows = Otx.transposeCols(q, W, m)
            val tweak = Otx.OtTweak(rowOffset, tweakDomain)
            val h0 = Otx.tmmoCrh(rows, m, tweak)
            val sw = Otx.gfFromBig(sBits)
            val row = IntArray(4)
            for (j in 0 until m) {
                System.arraycopy(rows, 4 * j, row, 0, 4)
                Otx.gfXorInto(row, sw, 0)
                System.arraycopy(row, 0, rows, 4 * j, 4)
            }
            val h1 = Otx.tmmoCrh(rows, m, tweak)
            val y0 = Array(m) { j -> msg0[j].xor(Otx.word64(h0, j)) }
            val y1 = Array(m) { j -> msg1[j].xor(Otx.word64(h1, j)) }
            return Response(y0, y1)
        }
    }

    /**
     * An in-process OT-extension channel: one base-OT setup (kappa transfers) is amortised over every later extend(). The base OT is
     * the EC base OT unless [baseOtFn] supplies another (for example a post-quantum one).
     */
    class OtChannel @JvmOverloads constructor(rng: OtRandom?, private val baseOtFn: BaseOtFn? = null, private val bindingOpt: BaseOtBinding? = null) {
        private val rng: OtRandom = rng ?: secureOtRandom()
        private var recv: OtExtReceiver? = null
        private var send: OtExtSender? = null
        private var ready = false

        /** The EC base-OT transcript of the kappa setup transfers (null when a custom base OT is used). */
        @JvmField var baseTranscript: BaseOtTranscript? = null

        /** TEST-ONLY: mutate the extension receiver's u matrix. */
        @JvmField var tamperU: ((Array<BigInteger>, Int) -> Unit)? = null

        private fun setup() {
            val base = bindingOpt ?: randomBinding(rng, "x")
            val kos = bindingBytes(BaseOtBinding(base.sessionId, base.senderIndex, base.receiverIndex, "iknp-kos"))
            val r = OtExtReceiver(rng, kos)
            val sd = OtExtSender(rng, kos)
            val messages = r.makeSeeds()
            val sel = sd.makeSelector()
            val fn = baseOtFn
            if (fn != null) {
                sd.setSeeds(fn.run(messages, sel, rng))
            } else {
                val res = baseOT(messages, sel, rng, null, BaseOtBinding(base.sessionId, base.senderIndex, base.receiverIndex, "iknp-kappa-setup"))
                sd.setSeeds(res.received)
                baseTranscript = res.transcript
            }
            recv = r
            send = sd
            ready = true
        }

        fun selector(): BigInteger {
            if (!ready) setup()
            return send!!.selector()
        }

        class Extended(val received: Array<BigInteger>, val uMatrix: Array<BigInteger>)

        fun extend(choiceBits: IntArray, msg0: Array<BigInteger>, msg1: Array<BigInteger>): Extended {
            if (!ready) setup()
            val m = choiceBits.size
            require(!(msg0.size != m || msg1.size != m)) { "OtChannel.extend: length mismatch" }
            if (m == 0) return Extended(emptyArray(), emptyArray())
            checkExtInputs(choiceBits, msg0, msg1)
            val rc = recv!!
            rc.tamperU = tamperU
            val b = rc.begin(choiceBits)
            val r = send!!.respond(b.msg, msg0, msg1)
            return Extended(rc.finish(b.pending, r.y0, r.y1), b.msg.u!!)
        }
    }
}
