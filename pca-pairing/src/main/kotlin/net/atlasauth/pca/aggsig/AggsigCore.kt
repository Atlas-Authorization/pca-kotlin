package net.atlasauth.pca.aggsig

import net.atlasauth.pca.verifier.Json

import java.math.BigInteger
import java.security.SecureRandom
import net.atlasauth.pca.pairing.Bls12
import supranational.blst.BLST_ERROR
import supranational.blst.P1
import supranational.blst.P1_Affine
import supranational.blst.P2
import supranational.blst.P2_Affine
import supranational.blst.Pairing

/**
 * BLS signatures on BLS12-381, aggregation-ready (draft-irtf-cfrg-bls-signature, proof-of-possession ciphersuite,
 * minimal-pubkey-size: 48-byte G1 public keys, 96-byte G2 signatures). Every curve operation is blst's (via jblst); nothing
 * here implements a pairing or a field. INTERNAL: the raw aggregate verifiers take unvetted public keys and are only
 * sound after a proof-of-possession check; the public surface is [Aggsig], which takes only [RegisteredKey]s.
 * Verification is total: any malformed input is a `false`, never an exception.
 */
internal object AggsigCore {
    const val SIG_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    const val POP_DST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    const val PUBLIC_KEY_LENGTH = 48
    const val SIGNATURE_LENGTH = 96
    val R: BigInteger = Bls12.R

    private fun fatal(t: Throwable) = Bls12.fatal(t)

    private fun isCompressed(b: ByteArray?, len: Int): Boolean = b != null && b.size == len && (b[0].toInt() and 0x80) != 0

    /** A 96-byte compressed G2 point that is exactly the re-encoding of the point it decodes to (no second encoding per signature). */
    fun isCanonicalSignature(sig: ByteArray?): Boolean {
        if (!isCompressed(sig, SIGNATURE_LENGTH)) return false
        return try {
            val p = P2_Affine(sig)
            p.compress().contentEquals(sig) && p.in_group() // the reference's point parse also rejects an off-subgroup point
        } catch (t: Throwable) {
            fatal(t)
            false
        }
    }

    /** KeyValidate (draft 2.5): canonical compressed G1 point, not the identity, in the prime-order subgroup. */
    fun keyValidate(pk: ByteArray?): Boolean {
        if (!isCompressed(pk, PUBLIC_KEY_LENGTH)) return false
        return try {
            val p = P1_Affine(pk)
            if (p.is_inf() || !p.on_curve() || !p.compress().contentEquals(pk)) false else p.in_group()
        } catch (t: Throwable) {
            fatal(t)
            false
        }
    }

    fun scalar(sk: ByteArray?): BigInteger {
        if (sk == null || sk.size != 32) throw IllegalArgumentException("secret key must be 32 bytes")
        val s = BigInteger(1, sk)
        if (s.signum() == 0 || s >= R) throw IllegalArgumentException("secret key must be a scalar in [1, r-1]")
        return s
    }

    fun publicKeyOf(sk: ByteArray?): ByteArray = Bls12.mul(P1.generator(), scalar(sk)).compress()

    /** A fresh key pair; refuses the degenerate key 1 (a stuck entropy source). */
    fun keyGen(rng: SecureRandom): Aggsig.KeyPair {
        val wide = ByteArray(64)
        rng.nextBytes(wide)
        val s = BigInteger(1, wide).mod(R.subtract(BigInteger.ONE)).add(BigInteger.ONE)
        if (s == BigInteger.ONE) throw IllegalStateException("keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue")
        val sk = Bls12.i2osp(s, 32)
        return Aggsig.KeyPair(sk, publicKeyOf(sk))
    }

    fun signWith(dst: String, sk: ByteArray?, msg: ByteArray?): ByteArray {
        val s = scalar(sk)
        if (msg == null) throw IllegalArgumentException("msg is required")
        return Bls12.mul(P2().hash_to(msg, dst), s).compress()
    }

    fun sign(sk: ByteArray?, msg: ByteArray?): ByteArray = signWith(SIG_DST, sk, msg)

    fun verifyWith(dst: String, pk: ByteArray?, msg: ByteArray?, sig: ByteArray?): Boolean {
        try {
            if (!isCanonicalSignature(sig)) return false
            if (!keyValidate(pk)) return false
            if (msg == null) return false
            return P2_Affine(sig).core_verify(P1_Affine(pk), true, msg, dst) == BLST_ERROR.BLST_SUCCESS
        } catch (t: Throwable) {
            fatal(t)
            return false
        }
    }

    fun verify(pk: ByteArray?, msg: ByteArray?, sig: ByteArray?): Boolean = verifyWith(SIG_DST, pk, msg, sig)

    fun aggregate(sigs: List<ByteArray>): ByteArray {
        if (sigs.isEmpty()) throw IllegalArgumentException("aggregate: need at least one signature")
        for (s in sigs) if (!isCanonicalSignature(s)) throw IllegalArgumentException("aggregate: every signature must be a 96-byte compressed G2 point")
        val sum = P2()
        for (s in sigs) sum.add(P2_Affine(s))
        return sum.compress()
    }

    private fun distinct(msgs: List<ByteArray>): Boolean {
        val seen = HashSet<String>()
        for (m in msgs) if (!seen.add(Aggsig.hex(m))) return false
        return true
    }

    /** AggregateVerify (draft 3.1.1) over pairwise-distinct messages: one pairing-product check. */
    fun aggregateVerify(pks: List<ByteArray>, msgs: List<ByteArray>, aggSig: ByteArray?): Boolean {
        try {
            if (!isCanonicalSignature(aggSig)) return false
            if (pks.isEmpty() || pks.size != msgs.size) return false
            if (!distinct(msgs)) return false
            for (pk in pks) if (!keyValidate(pk)) return false
            val ctx = Pairing(true, SIG_DST)
            val sig = P2_Affine(aggSig)
            for (i in pks.indices) {
                val s: P2_Affine? = if (i == 0) sig else null
                val e = ctx.aggregate(P1_Affine(pks[i]), s, msgs[i])
                if (e != BLST_ERROR.BLST_SUCCESS) return false
            }
            ctx.commit()
            return ctx.finalverify()
        } catch (t: Throwable) {
            fatal(t)
            return false
        }
    }

    /** FastAggregateVerify (draft 3.3.4): one message, many signers; the aggregate key is KeyValidate'd too ({P,-P} sums to the identity). */
    fun fastAggregateVerify(pks: List<ByteArray>, msg: ByteArray?, aggSig: ByteArray?): Boolean {
        try {
            if (!isCanonicalSignature(aggSig)) return false
            if (pks.isEmpty() || msg == null) return false
            val agg = P1()
            for (pk in pks) {
                if (!keyValidate(pk)) return false
                agg.add(P1_Affine(pk))
            }
            if (agg.is_inf()) return false
            val aggPk = agg.compress()
            if (!keyValidate(aggPk)) return false
            return P2_Affine(aggSig).core_verify(P1_Affine(aggPk), true, msg, SIG_DST) == BLST_ERROR.BLST_SUCCESS
        } catch (t: Throwable) {
            fatal(t)
            return false
        }
    }

    fun popProve(sk: ByteArray?): ByteArray = signWith(POP_DST, sk, publicKeyOf(sk))

    fun popVerify(pk: ByteArray?, pop: ByteArray?): Boolean = verifyWith(POP_DST, pk, pk, pop)

    fun utf8(s: String): ByteArray = Json.utf8(s)
}
