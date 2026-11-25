package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.mpc.MpcSupport.B
import net.atlasauth.pca.mpc.MpcSupport.BA
import net.atlasauth.pca.mpc.MpcSupport.D
import net.atlasauth.pca.mpc.MpcSupport.I
import net.atlasauth.pca.mpc.MpcSupport.IA
import net.atlasauth.pca.mpc.MpcSupport.L
import net.atlasauth.pca.mpc.MpcSupport.M
import net.atlasauth.pca.mpc.Ot.BaseOtBinding
import net.atlasauth.pca.mpc.Ot.BaseOtTamper
import net.atlasauth.pca.mpc.Ot.OtRandom
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Differential tests of the MPC oblivious-transfer stack against the TypeScript reference corpus (every draw from a seeded stream). */
@Suppress("UNCHECKED_CAST", "FunctionName")
class MpcOtDiffTest {
    private val MOD = "ref-mpc-ot"

    // ---- argument / result codecs ----
    private fun by(o: Any?): ByteArray {
        if (o !is Map<*, *> || o["\$bytes"] !is String) throw IllegalArgumentException("expected a byte array")
        return Keys.unb64u(o["\$bytes"] as String)
    }

    private fun words(o: Any?): IntArray {
        val l = o as List<Any?>
        return IntArray(l.size) { i -> Js.num(l[i])!!.toLong().toInt() }
    }

    private fun W(w: IntArray): List<Any?> = w.map { it.toLong() and 0xffffffffL }

    private fun P(o: Any?): Ec.Point {
        val l = o as List<Any?>
        return Ec.Point(B(l[0]), B(l[1]), B(l[2]), B(l[3]))
    }

    private fun aff(p: Ec.Point): Map<String, Any?> {
        val xy = Ec.toAffine(p)
        return M("x" to xy[0].toString(), "y" to xy[1].toString())
    }

    private fun BL(a: Array<ByteArray>): List<Any?> = a.toList()

    private fun PAIRS(a: Array<Array<ByteArray>>): List<Any?> = a.map { listOf<Any?>(it[0], it[1]) }

    private fun pairs(o: Any?): Array<Array<ByteArray>> {
        val l = o as List<Any?>
        return Array(l.size) { i -> arrayOf(by((l[i] as List<Any?>)[0]), by((l[i] as List<Any?>)[1])) }
    }

    private fun orng(seed: Any?): OtRandom = Ot.otRandom(Ot.splitMix64(B(seed)))

    private val ORDER2 = Ec.Point(BigInteger.ZERO, Ec.Q.subtract(BigInteger.ONE), BigInteger.ONE, BigInteger.ZERO)

    private fun flip(b: ByteArray, mask: Int): ByteArray = ByteArray(b.size) { i -> (b[i].toInt() xor mask).toByte() }

    private fun tamper(name: String): BaseOtTamper? {
        val t = BaseOtTamper()
        when (name) {
            "none" -> return null
            "S_identity" -> t.tamperS = { Ec.IDENTITY }
            "S_order2" -> t.tamperS = { ORDER2 }
            "S_other" -> t.tamperS = { p -> Ec.addPoints(p, Ec.BASE) }
            "proof_z" -> t.tamperProof = { p -> Ec.SchnorrProof(p.U, p.z.add(BigInteger.ONE).mod(Ec.L)) }
            "proof_U" -> t.tamperProof = { p -> Ec.SchnorrProof(Ec.addPoints(p.U, Ec.BASE), p.z) }
            "R0_identity" -> t.tamperR = { r -> r[0] = Ec.IDENTITY }
            "R1_order2" -> t.tamperR = { r -> if (r.size > 1) r[1] = ORDER2 }
            "R_swap" -> t.tamperR = { r ->
                if (r.size > 1) {
                    val x = r[0]
                    r[0] = r[1]
                    r[1] = x
                }
            }
            "ct_flip" -> t.tamperCiphertext = { ct -> ct[0][0] = flip(ct[0][0], 1) }
            "ct_flip1" -> t.tamperCiphertext = { ct -> ct[ct.size - 1][1] = flip(ct[ct.size - 1][1], 0x80) }
            else -> throw IllegalArgumentException(name)
        }
        return t
    }

    private fun binding(sess: Any?, a: Any?, b: Any?, round: Any?): BaseOtBinding =
        BaseOtBinding(Keys.unb64u(sess as String), idx(a), idx(b), round as String)

    private fun idx(o: Any?): Long {
        val d = D(o)
        if (d != Math.rint(d)) throw IllegalArgumentException("not an integer")
        return d.toLong()
    }

    // ---- Ed25519 group ----
    @Test fun genCorpusIsPresent() = net.atlasauth.pca.verifier.BaseOracle.requireGen(MOD)

    @Test fun ec() {
        OracleCases.each(MOD, "ecOp") { a ->
            when (val op = a[0] as String) {
                "mulBase" -> {
                    val p = Ec.mulBase(B(a[1]))
                    M("p" to aff(p), "enc" to Ec.encodePoint(p), "comp" to Ec.compressPoint(p))
                }
                "mul" -> aff(Ec.mul(B(a[1]), P(a[2])))
                "add" -> aff(Ec.addPoints(P(a[1]), P(a[2])))
                "sub" -> aff(Ec.sub(P(a[1]), P(a[2])))
                "neg" -> aff(Ec.neg(P(a[1])))
                "dbl" -> aff(Ec.dbl(P(a[1])))
                "decompress" -> {
                    val p = Ec.decompressPoint(by(a[1]))
                    M("p" to aff(p), "onCurve" to Ec.isOnCurve(p), "identity" to Ec.isIdentity(p), "prime" to Ec.hasPrimeOrder(p), "inSub" to Ec.isInSubgroup(p))
                }
                else -> throw IllegalArgumentException(op)
            }
        }
        OracleCases.each(MOD, "ecValidate") { a ->
            val p = P(a[0])
            M("onCurve" to Ec.isOnCurve(p), "identity" to Ec.isIdentity(p), "prime" to Ec.hasPrimeOrder(p), "inSubgroup" to Ec.isInSubgroup(p))
        }
        OracleCases.each(MOD, "ecAssert") { a ->
            Ec.assertInSubgroup(P(a[0]), "p")
            true
        }
        OracleCases.each(MOD, "schnorr") { a ->
            val y = B(a[0])
            val nonce = B(a[1])
            val ctx = Keys.unb64u(a[2] as String)
            val s = Ec.mulBase(y)
            val proof = Ec.schnorrProve(y, s, { nonce }, ctx)
            val other = "other-ctx".toByteArray(Charsets.UTF_8)
            val forged = Ec.SchnorrProof(proof.U, proof.z.add(BigInteger.ONE).mod(Ec.L))
            val oor = Ec.SchnorrProof(proof.U, Ec.L)
            M(
                "S" to aff(s), "U" to aff(proof.U), "z" to proof.z.toString(), "ok" to Ec.schnorrVerify(s, proof, ctx), "badCtx" to Ec.schnorrVerify(s, proof, other),
                "forged" to Ec.schnorrVerify(s, forged, ctx), "oor" to Ec.schnorrVerify(s, oor, ctx),
                "wrongS" to Ec.schnorrVerify(Ec.mulBase(y.add(BigInteger.ONE)), proof, ctx), "identityS" to Ec.schnorrVerify(Ec.IDENTITY, proof, ctx),
            )
        }
    }

    // ---- word-array kernels ----
    @Test fun kernels() {
        OracleCases.each(MOD, "prg") { a -> W(Otx.prgColumn(Keys.unb64u(a[0] as String), D(a[1]).toLong(), I(a[2]))) }
        OracleCases.each(MOD, "maskTail") { a ->
            val w = words(a[0])
            Otx.maskTail(w, I(a[1]))
            W(w)
        }
        OracleCases.each(MOD, "transpose32") { a ->
            val w = words(a[0])
            Otx.transpose32(w, 0)
            W(w)
        }
        OracleCases.each(MOD, "transposeCols") { a -> W(Otx.transposeCols(words(a[0]), I(a[1]), I(a[2]))) }
        OracleCases.each(MOD, "gfMulX") { a ->
            val w = words(a[0])
            Otx.gfMulX(w)
            W(w)
        }
        OracleCases.each(MOD, "gfXorInto") { a ->
            val w = words(a[0])
            Otx.gfXorInto(w, words(a[1]), 0)
            W(w)
        }
        OracleCases.each(MOD, "gfBig") { a ->
            val w = words(a[0])
            val v = Otx.gfToBig(w)
            M("big" to v.toString(), "back" to W(Otx.gfFromBig(v)))
        }
        OracleCases.each(MOD, "accumColumn") { a ->
            val c = words(a[0])
            val acc = IntArray(4)
            Otx.accumColumn(c, 0, c.size, words(a[1]), acc)
            W(acc)
        }
        OracleCases.each(MOD, "kosCombine") { a -> W(Otx.kosCombine(words(a[0]), I(a[1]), words(a[2]))) }
        OracleCases.each(MOD, "tmmo") { a -> W(Otx.tmmoCrh(words(a[0]), I(a[1]), Otx.OtTweak(D(a[2]).toLong(), words(a[3])))) }
        OracleCases.each(MOD, "tweakDomain") { a -> W(Otx.otTweakDomain(Keys.unb64u(a[0] as String))) }
        OracleCases.each(MOD, "bigBytes") { a -> Otx.bigToBytes(B(a[0]), I(a[1])) }
        OracleCases.each(MOD, "bytesBig") { a -> Otx.bytesToBig(Keys.unb64u(a[0] as String)).toString() }
        OracleCases.each(MOD, "word64") { a -> Otx.word64(words(a[0]), I(a[1])).toString() }
    }

    // ---- base OT, KOS extension ----
    @Test fun baseOt() {
        OracleCases.each(MOD, "bindingBytes") { a -> Ot.bindingBytes(binding(a[0], a[1], a[2], a[3])) }
        OracleCases.each(MOD, "baseOtKdf") { a ->
            val b0 = Ot.randomBinding(orng("4242"), "base-ot")
            val r = arrayOf(Ec.mulBase(BigInteger.valueOf(5)), Ec.mulBase(BigInteger.valueOf(6)))
            val th = Ot.baseOtTranscriptHash(b0, Ec.mulBase(BigInteger.valueOf(3)), r)
            M("th" to th, "k" to Ot.baseOtKdf(th, I(a[0]), r[0], Ec.mulBase(BigInteger.valueOf(9))))
        }
        OracleCases.each(MOD, "randomOt") { a ->
            val r = Ot.malBaseRandomOT(IA(a[0]), orng(a[1]), tamper(a[2] as String), null)
            M(
                "S" to aff(r.S), "U" to aff(r.proof.U), "z" to r.proof.z.toString(), "R" to r.R.map { aff(it) },
                "senderPads" to PAIRS(r.senderPads), "recvPads" to BL(r.recvPads),
            )
        }
        OracleCases.each(MOD, "baseOt") { a ->
            val res = Ot.baseOT(pairs(a[0]), IA(a[1]), orng(a[2]), tamper(a[3] as String), null)
            val t = res.transcript
            M(
                "received" to BL(res.received), "S" to aff(t.S), "U" to aff(t.proof.U), "z" to t.proof.z.toString(), "R" to t.R.map { aff(it) },
                "ct" to PAIRS(t.ct), "com" to PAIRS(t.com),
            )
        }
    }

    @Test fun extension() {
        OracleCases.each(MOD, "channel") { a ->
            val ch = Ot.OtChannel(orng(a[3]))
            val tn = a[5] as String?
            when (tn) {
                "flip00" -> ch.tamperU = { u, _ -> u[0] = u[0].xor(BigInteger.ONE) }
                "flipLast" -> ch.tamperU = { u, _ -> u[127] = u[127].xor(BigInteger.ONE.shiftLeft(5)) }
                "oversize" -> ch.tamperU = { u, _ -> u[3] = u[3].or(BigInteger.ONE.shiftLeft(5000)) }
                "negative" -> ch.tamperU = { u, _ -> u[3] = BigInteger.ONE.negate() }
                "round2flip" -> ch.tamperU = { u, round -> if (round == 1) u[10] = u[10].xor(BigInteger.valueOf(2)) }
                else -> {}
            }
            val outs = ArrayList<Any?>()
            for (k in 0 until I(a[4])) {
                val e = ch.extend(IA(a[0]), BA(a[1]), BA(a[2]))
                outs.add(M("received" to L(e.received), "uMatrix" to L(e.uMatrix)))
            }
            val sel = ch.selector().toString()
            val bt = ch.baseTranscript
            val base: Any? = if (bt == null) null else M("S" to aff(bt.S), "R" to bt.R.size)
            M("selector" to sel, "outs" to outs, "base" to base)
        }
        OracleCases.each(MOD, "kosChi") { a ->
            val b = Keys.unb64u(a[0] as String)
            val u = BA(a[2])
            val mExt = I(a[3])
            val chi = Ot.kosChallenges(b, I(a[1]), u, mExt)
            M("w" to W(Ot.kosChiWords(b, I(a[1]), u, mExt, null)), "chi" to L(chi))
        }
    }

    // ---- ML-KEM base OT, hybrid ----
    private fun kemTamper(tn: String?): KemOt.KemMalTamper? {
        val t = KemOt.KemMalTamper()
        if (tn == "badKey") {
            t.tamperOpenedKeys = { pk ->
                val x = pk[0][0]
                pk[0][0] = pk[0][1]
                pk[0][1] = x
            }
        } else if (tn == "badSid") {
            t.tamperReceiverSid = { s -> flip(s, 1) }
        } else {
            return null
        }
        return t
    }

    @Test fun kem() {
        OracleCases.each(MOD, "kemOt") { a ->
            val fn = a[0] as String
            val g = orng(a[3])
            val choices = IA(a[2])
            val tn = a[4] as String?
            if (fn == "kemBaseOT") {
                val r = KemOt.kemBaseOT(pairs(a[1]), choices, g)
                val t = r.transcript
                return@each M("received" to BL(r.received), "transcript" to M("publicKeys" to PAIRS(t.publicKeys), "ciphertexts" to PAIRS(t.ciphertexts), "encrypted" to PAIRS(t.encrypted)))
            }
            if (fn == "kemBaseOtMal") {
                val r = KemOt.kemBaseOtMal(pairs(a[1]), choices, g, kemTamper(tn))
                val t = r.transcript
                return@each M(
                    "received" to BL(r.received),
                    "transcript" to M(
                        "rn" to t.rn, "commitments" to BL(t.commitments), "sn" to t.sn, "publicKeys" to PAIRS(t.publicKeys),
                        "ciphertexts" to PAIRS(t.ciphertexts), "encrypted" to PAIRS(t.encrypted),
                    ),
                )
            }
            val r = KemOt.kemBaseOtMalRandom(choices, g, kemTamper(tn))
            val t = r.transcript
            M(
                "senderSecrets" to PAIRS(r.senderSecrets), "recvSecrets" to BL(r.recvSecrets), "sid" to r.sid,
                "transcript" to M("rn" to t.rn, "commitments" to BL(t.commitments), "sn" to t.sn, "publicKeys" to PAIRS(t.publicKeys), "ciphertexts" to PAIRS(t.ciphertexts)),
            )
        }
        OracleCases.each(MOD, "kemPad") { a ->
            val ss = ByteArray(32) { k -> k.toByte() }
            if (a.size == 1) KemOt.kemOtPad(0, 0, ByteArray(32), I(a[0])) else KemOt.kemOtPad(I(a[0]), I(a[1]), ss, I(a[2]))
        }
        OracleCases.each(MOD, "hybridOt") { a ->
            val tn = a[3] as String?
            var t: HybridOt.HybridBaseOtTamper? = null
            if (tn != null) {
                t = HybridOt.HybridBaseOtTamper()
                when (tn) {
                    "ec" -> t.ec = tamper("ct_flip")
                    "ecS" -> t.ec = tamper("S_identity")
                    "enc" -> t.tamperEncrypted = { e -> e[0][0] = flip(e[0][0], 1) }
                    "kem" -> t.kem = kemTamper("badKey")
                }
            }
            val r = HybridOt.hybridBaseOT(pairs(a[0]), IA(a[1]), orng(a[2]), t)
            val tr = r.transcript
            M(
                "received" to BL(r.received), "sid" to tr.sid, "ecS" to aff(tr.ecS), "kemSid" to tr.kemSid,
                "encrypted" to PAIRS(tr.encrypted), "commitments" to PAIRS(tr.commitments),
            )
        }
        OracleCases.each(MOD, "hybridKey") { a -> HybridOt.hybridTransferKey(fill(32, 1), 3, 1, fill(16, 2), fill(32, 3), I(a[0])) }
    }

    private fun fill(n: Int, v: Int): ByteArray = ByteArray(n) { v.toByte() }
}
