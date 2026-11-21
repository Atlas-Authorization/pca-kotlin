package net.atlasauth.pca.bbs

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.TreeSet
import net.atlasauth.pca.pairing.Bls12
import supranational.blst.P1
import supranational.blst.P2

/**
 * BBS signatures over BLS12-381, ciphersuite BLS12-381-SHA-256 (BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_), faithful to
 * draft-irtf-cfrg-bbs-signatures (core protocol and octet encodings; validated against the draft's official fixtures).
 * Signatures and generators live in G1 (48 bytes compressed), public keys in G2 (96 bytes), scalars are 32 bytes big-endian.
 * All curve work is blst's (via jblst); scalar-field arithmetic is BigInteger (see [Bls12]).
 */
object Bbs {
    /** Implementation limit on the number of messages in one credential (a verifier derives the count from attacker-supplied lengths). */
    const val MAX_MESSAGES = 1024
    val R: BigInteger = Bls12.R
    const val CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
    const val API_ID = CIPHERSUITE_ID + "H2G_HM2S_"

    private const val SCALAR_LEN = 32
    private const val POINT_LEN = 48
    private const val EXPAND_LEN = 48
    private const val H2S_DST = API_ID + "H2S_"
    private const val MAP_DST = API_ID + "MAP_MSG_TO_SCALAR_AS_HASH_"
    private const val SEED_DST = API_ID + "SIG_GENERATOR_SEED_"
    private const val GEN_DST = API_ID + "SIG_GENERATOR_DST_"
    private const val GEN_SEED = API_ID + "MESSAGE_GENERATOR_SEED"
    private const val KEYGEN_DST = API_ID + "KEYGEN_DST_"

    /** P1: the fixed G1 generator of the ciphersuite (draft 7.2.2). */
    private const val P1_HEX = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9"

    private val P1_GEN: P1 = Bls12.decodeG1(hex(P1_HEX))
    private val BP2: P2 = P2.generator()

    // ---- helpers ----

    internal fun hex(s: String): ByteArray = ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }

    private fun ascii(s: String): ByteArray = s.toByteArray(Charsets.US_ASCII)

    private fun i2osp(n: BigInteger, len: Int): ByteArray = Bls12.i2osp(n, len)

    private fun i2osp(n: Long, len: Int): ByteArray = Bls12.i2osp(BigInteger.valueOf(n), len)

    private fun concat(vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        for (p in parts) o.write(p, 0, p.size)
        return o.toByteArray()
    }

    private fun expand(msg: ByteArray, dst: String, len: Int): ByteArray = Bls12.expandMessageXmd(msg, ascii(dst), len)

    /** hash_to_scalar(msg, dst) = OS2IP(expand_message_xmd(msg, dst, 48)) mod r (draft 4.2.2). */
    fun hashToScalar(msg: ByteArray, dst: String): BigInteger = Bls12.mod(Bls12.os2ip(expand(msg, dst, EXPAND_LEN)))

    /** MapMessageToScalarAsHash: one message octet string to one scalar (draft 4.2). */
    fun mapMessageToScalarAsHash(message: ByteArray): BigInteger = hashToScalar(message, MAP_DST)

    fun messagesToScalars(messages: List<ByteArray>): List<BigInteger> = messages.map { mapMessageToScalarAsHash(it) }

    private fun gens(count: Int): List<P1> {
        if (count < 0) throw IllegalArgumentException("bbs: generator count must be a non-negative integer")
        if (count > MAX_MESSAGES + 1) throw IllegalArgumentException("bbs: at most $MAX_MESSAGES messages are supported")
        val out = ArrayList<P1>()
        var v = expand(ascii(GEN_SEED), SEED_DST, EXPAND_LEN)
        for (i in 1..count) {
            v = expand(concat(v, i2osp(i.toLong(), 8)), SEED_DST, EXPAND_LEN)
            out.add(P1().hash_to(v, GEN_DST))
        }
        return out
    }

    /** create_generators(count): the compressed generator sequence (Q_1, H_1, ..., H_{count-1}) (draft 4.1). */
    fun createGenerators(count: Int): List<ByteArray> = gens(count).map { it.compress() }

    // ---- key generation ----

    /** KeyGen (draft 3.4.1): at least 32 octets of key material. Never returns 0. */
    fun keyGen(keyMaterial: ByteArray, keyInfo: ByteArray = ByteArray(0)): BigInteger {
        if (keyMaterial.size < 32) throw IllegalArgumentException("bbs: key material must be at least 32 octets")
        if (keyInfo.size > 65535) throw IllegalArgumentException("bbs: key info must be at most 65535 octets")
        val sk = hashToScalar(concat(keyMaterial, i2osp(keyInfo.size.toLong(), 2), keyInfo), KEYGEN_DST)
        if (sk.signum() == 0) throw IllegalStateException("bbs: derived SK is zero (retry with different key material)")
        return sk
    }

    /** SkToPk: the 96-byte public key SK * BP2 (draft 3.4.2). */
    fun skToPk(sk: BigInteger): ByteArray = Bls12.mul(BP2, sk).compress()

    class KeyPair(val sk: BigInteger, val pk: ByteArray)

    /** A fresh (SK, PK) pair from the system CSPRNG; refuses an all-zero entropy source. */
    fun generateKeyPair(): KeyPair {
        val ikm = ByteArray(32)
        SecureRandom().nextBytes(ikm)
        if (ikm.all { it.toInt() == 0 }) throw IllegalStateException("bbs: entropy source returned all zeros (RNG failure); refusing to generate a key")
        val sk = keyGen(ikm)
        return KeyPair(sk, skToPk(sk))
    }

    fun skToBytes(sk: BigInteger): ByteArray = i2osp(sk, SCALAR_LEN)

    fun skFromBytes(bytes: ByteArray): BigInteger {
        if (bytes.size != SCALAR_LEN) throw IllegalArgumentException("bbs: SK must be 32 octets")
        val sk = Bls12.os2ip(bytes)
        if (sk.signum() == 0 || sk >= R) throw IllegalArgumentException("bbs: SK out of range")
        return sk
    }

    // ---- serialization (draft 4.2.4) ----

    /** serialize(): points compressed, scalars 32 octets, integers 8 octets. Elements are P1, P2, BigInteger (scalar) or Int (count/index). */
    private fun serialize(els: List<Any>): ByteArray {
        val o = ByteArrayOutputStream()
        for (el in els) {
            val b = when (el) {
                is P1 -> el.compress()
                is P2 -> el.compress()
                is BigInteger -> i2osp(el, SCALAR_LEN)
                else -> i2osp((el as Int).toLong(), 8)
            }
            o.write(b, 0, b.size)
        }
        return o.toByteArray()
    }

    // ---- signature octets ----

    private class ParsedSignature(val a: P1, val e: BigInteger)

    private fun signatureToOctets(a: P1, e: BigInteger): ByteArray = concat(a.compress(), i2osp(e, SCALAR_LEN))

    private fun octetsToSignature(sig: ByteArray): ParsedSignature {
        if (sig.size != POINT_LEN + SCALAR_LEN) throw IllegalArgumentException("bbs: signature must be 80 octets")
        val a = Bls12.decodeG1(sig.copyOfRange(0, POINT_LEN))
        if (a.is_inf()) throw IllegalArgumentException("bbs: signature point A is the identity")
        val e = Bls12.os2ip(sig.copyOfRange(POINT_LEN, sig.size))
        if (e.signum() <= 0 || e >= R) throw IllegalArgumentException("bbs: signature scalar e out of range")
        return ParsedSignature(a, e)
    }

    // ---- domain (draft 4.2.3) ----

    private fun calculateDomain(pk: ByteArray, q1: P1, h: List<P1>, header: ByteArray): BigInteger {
        val els = ArrayList<Any>()
        els.add(h.size)
        els.add(q1)
        els.addAll(h)
        val domOcts = concat(serialize(els), ascii(API_ID))
        val domInput = concat(pk, domOcts, i2osp(header.size.toLong(), 8), header)
        return hashToScalar(domInput, H2S_DST)
    }

    /** B = P1 + Q_1*domain + sum H_i*msg_i. */
    private fun computeB(q1: P1, h: List<P1>, domain: BigInteger, msgScalars: List<BigInteger>): P1 {
        var b = Bls12.add(P1_GEN, Bls12.mul(q1, domain))
        for (i in msgScalars.indices) b = Bls12.add(b, Bls12.mul(h[i], msgScalars[i]))
        return b
    }

    // ---- Sign / Verify ----

    /** Sign(SK, PK, header, messages): an 80-octet BBS signature over the ordered message vector. */
    fun sign(sk: BigInteger, pk: ByteArray, header: ByteArray, messages: List<ByteArray>): ByteArray {
        val ms = messagesToScalars(messages)
        val g = gens(ms.size + 1)
        val q1 = g[0]
        val h = g.subList(1, g.size)
        val domain = calculateDomain(pk, q1, h, header)
        val eEls = ArrayList<Any>()
        eEls.add(sk)
        eEls.addAll(ms)
        eEls.add(domain)
        val e = hashToScalar(serialize(eEls), H2S_DST)
        val b = computeB(q1, h, domain, ms)
        val a = Bls12.mul(b, Bls12.inv(Bls12.add(sk, e)))
        return signatureToOctets(a, e)
    }

    /** Result of a verification: ok, or the stable machine-readable reason. */
    class Result(val ok: Boolean, val reason: String?) {
        internal companion object {
            val OK = Result(true, null)
            fun fail(reason: String) = Result(false, reason)
        }
    }

    const val MALFORMED_SIGNATURE = "malformed-signature"
    const val MALFORMED_PUBLIC_KEY = "malformed-public-key"
    const val MALFORMED_PROOF = "malformed-proof"
    const val DISCLOSED_LENGTH_MISMATCH = "disclosed-length-mismatch"
    const val INVALID_DISCLOSED_INDEXES = "invalid-disclosed-indexes"
    const val PAIRING_MISMATCH = "pairing-mismatch"
    const val CHALLENGE_MISMATCH = "challenge-mismatch"

    /** Decode a public key: strict G2, not the identity; null when malformed. */
    private fun decodePk(pk: ByteArray): P2? = try {
        val w = Bls12.decodeG2(pk)
        if (w.is_inf()) null else w
    } catch (e: IllegalArgumentException) {
        null
    }

    /** Verify(PK, signature, header, messages) with a rejection reason; fails closed on any malformed input. */
    fun verifyDetailed(pk: ByteArray, signature: ByteArray, header: ByteArray, messages: List<ByteArray>): Result {
        val parsed = try {
            octetsToSignature(signature)
        } catch (e: IllegalArgumentException) {
            return Result.fail(MALFORMED_SIGNATURE)
        }
        val w = decodePk(pk) ?: return Result.fail(MALFORMED_PUBLIC_KEY)
        if (messages.size > MAX_MESSAGES) return Result.fail(DISCLOSED_LENGTH_MISMATCH)
        val ms = messagesToScalars(messages)
        val g = gens(ms.size + 1)
        val q1 = g[0]
        val h = g.subList(1, g.size)
        val domain = calculateDomain(pk, q1, h, header)
        val b = computeB(q1, h, domain, ms)
        // e(A, W + BP2*e) == e(B, BP2)
        val ok = Bls12.pairingEq(parsed.a, Bls12.add(w, Bls12.mul(BP2, parsed.e)), b, BP2)
        return if (ok) Result.OK else Result.fail(PAIRING_MISMATCH)
    }

    fun verify(pk: ByteArray, signature: ByteArray, header: ByteArray, messages: List<ByteArray>): Boolean =
        verifyDetailed(pk, signature, header, messages).ok

    // ---- challenge (draft 3.7.4) ----

    private fun calculateChallenge(
        abar: P1, bbar: P1, d: P1, t1: P1, t2: P1, idx: List<Int>, msgs: List<BigInteger>, domain: BigInteger, ph: ByteArray,
    ): BigInteger {
        val els = ArrayList<Any>()
        els.add(idx.size)
        for (k in idx.indices) {
            els.add(idx[k])
            els.add(msgs[k])
        }
        els.add(abar)
        els.add(bbar)
        els.add(d)
        els.add(t1)
        els.add(t2)
        els.add(domain)
        return hashToScalar(concat(serialize(els), i2osp(ph.size.toLong(), 8), ph), H2S_DST)
    }

    // ---- proof octets ----

    private class ParsedProof(
        val abar: P1, val bbar: P1, val d: P1, val eHat: BigInteger, val r1Hat: BigInteger, val r3Hat: BigInteger,
        val mHat: List<BigInteger>, val c: BigInteger,
    )

    private fun proofToOctets(p: ParsedProof): ByteArray {
        val parts = ArrayList<ByteArray>()
        parts.add(p.abar.compress())
        parts.add(p.bbar.compress())
        parts.add(p.d.compress())
        parts.add(i2osp(p.eHat, SCALAR_LEN))
        parts.add(i2osp(p.r1Hat, SCALAR_LEN))
        parts.add(i2osp(p.r3Hat, SCALAR_LEN))
        for (m in p.mHat) parts.add(i2osp(m, SCALAR_LEN))
        parts.add(i2osp(p.c, SCALAR_LEN))
        return concat(*parts.toTypedArray())
    }

    private fun readScalar(proof: ByteArray, offset: Int): BigInteger {
        val v = Bls12.os2ip(proof.copyOfRange(offset, offset + SCALAR_LEN))
        if (v >= R) throw IllegalArgumentException("bbs: proof scalar out of range")
        return v
    }

    private fun octetsToProof(proof: ByteArray): ParsedProof {
        val fixed = 3 * POINT_LEN + 4 * SCALAR_LEN
        if (proof.size < fixed || (proof.size - fixed) % SCALAR_LEN != 0) throw IllegalArgumentException("bbs: malformed proof length")
        var o = 0
        val abar = Bls12.decodeG1(proof.copyOfRange(o, o + POINT_LEN))
        o += POINT_LEN
        val bbar = Bls12.decodeG1(proof.copyOfRange(o, o + POINT_LEN))
        o += POINT_LEN
        val d = Bls12.decodeG1(proof.copyOfRange(o, o + POINT_LEN))
        o += POINT_LEN
        val eHat = readScalar(proof, o)
        o += SCALAR_LEN
        val r1Hat = readScalar(proof, o)
        o += SCALAR_LEN
        val r3Hat = readScalar(proof, o)
        o += SCALAR_LEN
        val u = (proof.size - fixed) / SCALAR_LEN
        val mHat = ArrayList<BigInteger>()
        for (i in 0 until u) {
            mHat.add(readScalar(proof, o))
            o += SCALAR_LEN
        }
        val c = readScalar(proof, o)
        if (abar.is_inf() || bbar.is_inf() || d.is_inf()) throw IllegalArgumentException("bbs: proof contains the identity point")
        return ParsedProof(abar, bbar, d, eHat, r1Hat, r3Hat, mHat, c)
    }

    // ---- index-set helpers ----

    private fun validateIndexes(indexes: List<Int>, l: Int) {
        val seen = TreeSet<Int>()
        for (i in indexes) {
            if (i < 0 || i >= l) throw IllegalArgumentException("bbs: disclosed index $i out of range [0, $l)")
            if (!seen.add(i)) throw IllegalArgumentException("bbs: duplicate disclosed index $i")
        }
    }

    private fun undisclosedAscending(disclosed: Set<Int>, l: Int): List<Int> = (0 until l).filter { it !in disclosed }

    // ---- ProofGen ----

    /**
     * ProofGen(PK, signature, header, ph, messages, disclosed_indexes): a zero-knowledge proof of knowledge of the signature that
     * discloses the messages at the given indexes. `fixedRandomScalars` (5 + undisclosed count scalars) pins the randomness
     * for test vectors ONLY; reusing it across proofs breaks zero-knowledge and unlinkability. Null draws fresh randomness from the system CSPRNG.
     */
    fun proofGen(
        pk: ByteArray, signature: ByteArray, header: ByteArray, ph: ByteArray, messages: List<ByteArray>, disclosedIndexes: List<Int>,
        fixedRandomScalars: List<BigInteger>? = null,
    ): ByteArray {
        val sig = octetsToSignature(signature)
        val a = sig.a
        val e = sig.e
        val ms = messagesToScalars(messages)
        val l = ms.size
        validateIndexes(disclosedIndexes, l)
        val disclosedSet = TreeSet(disclosedIndexes)
        val disclosed = ArrayList(disclosedSet)
        val undisclosed = undisclosedAscending(disclosedSet, l)
        val u = undisclosed.size

        val g = gens(l + 1)
        val q1 = g[0]
        val h = g.subList(1, g.size)
        val domain = calculateDomain(pk, q1, h, header)
        val b = computeB(q1, h, domain, ms)

        val rs: List<BigInteger>
        if (fixedRandomScalars == null) {
            val fresh = ArrayList<BigInteger>()
            val rng = SecureRandom()
            for (i in 0 until 5 + u) {
                val wide = ByteArray(EXPAND_LEN)
                rng.nextBytes(wide)
                fresh.add(Bls12.mod(Bls12.os2ip(wide)))
            }
            rs = fresh
        } else {
            rs = ArrayList(fixedRandomScalars)
        }
        if (rs.size != 5 + u) throw IllegalArgumentException("bbs: expected ${5 + u} random scalars, got ${rs.size}")
        if (rs[0].signum() == 0 || rs[1].signum() == 0) throw IllegalArgumentException("bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)")
        val r1 = rs[0]
        val r2 = rs[1]
        val eTilde = rs[2]
        val r1Tilde = rs[3]
        val r3Tilde = rs[4]
        val mTilde = rs.subList(5, rs.size)

        val d = Bls12.mul(b, r2)
        val abar = Bls12.mul(a, Bls12.mul(r1, r2))
        val bbar = Bls12.sub(Bls12.mul(d, r1), Bls12.mul(abar, e))
        val t1 = Bls12.add(Bls12.mul(abar, eTilde), Bls12.mul(d, r1Tilde))
        var t2 = Bls12.mul(d, r3Tilde)
        for (k in 0 until u) t2 = Bls12.add(t2, Bls12.mul(h[undisclosed[k]], mTilde[k]))

        val disclosedMsgs = disclosed.map { ms[it] }
        val c = calculateChallenge(abar, bbar, d, t1, t2, disclosed, disclosedMsgs, domain, ph)

        val r3 = Bls12.inv(r2)
        val eHat = Bls12.add(eTilde, Bls12.mul(e, c))
        val r1Hat = Bls12.sub(r1Tilde, Bls12.mul(r1, c))
        val r3Hat = Bls12.sub(r3Tilde, Bls12.mul(r3, c))
        val mHat = ArrayList<BigInteger>()
        for (k in 0 until u) mHat.add(Bls12.add(mTilde[k], Bls12.mul(ms[undisclosed[k]], c)))
        return proofToOctets(ParsedProof(abar, bbar, d, eHat, r1Hat, r3Hat, mHat, c))
    }

    // ---- ProofVerify ----

    /** ProofVerify with a rejection reason. `disclosedMessages[k]` corresponds to `disclosedIndexes[k]`. */
    fun proofVerifyDetailed(
        pk: ByteArray, proof: ByteArray, header: ByteArray, ph: ByteArray, disclosedMessages: List<ByteArray>, disclosedIndexes: List<Int>,
    ): Result {
        val p = try {
            octetsToProof(proof)
        } catch (e: IllegalArgumentException) {
            return Result.fail(MALFORMED_PROOF)
        }
        val w = decodePk(pk) ?: return Result.fail(MALFORMED_PUBLIC_KEY)
        if (disclosedMessages.size != disclosedIndexes.size) return Result.fail(DISCLOSED_LENGTH_MISMATCH)
        val u = p.mHat.size
        val l = disclosedIndexes.size + u
        if (l > MAX_MESSAGES) return Result.fail(MALFORMED_PROOF)

        val scalars = try {
            validateIndexes(disclosedIndexes, l)
            messagesToScalars(disclosedMessages)
        } catch (e: IllegalArgumentException) {
            return Result.fail(INVALID_DISCLOSED_INDEXES)
        }
        // {index, position in the caller's lists}, sorted by index
        val order = disclosedIndexes.indices.map { k -> intArrayOf(disclosedIndexes[k], k) }.sortedBy { it[0] }
        val disclosedSet = TreeSet(disclosedIndexes)
        val undisclosed = undisclosedAscending(disclosedSet, l)

        val g = gens(l + 1)
        val q1 = g[0]
        val h = g.subList(1, g.size)
        val domain = calculateDomain(pk, q1, h, header)

        val t1 = Bls12.add(Bls12.add(Bls12.mul(p.bbar, p.c), Bls12.mul(p.abar, p.eHat)), Bls12.mul(p.d, p.r1Hat))
        var bv = Bls12.add(P1_GEN, Bls12.mul(q1, domain))
        val sortedIdx = ArrayList<Int>()
        val sortedMsgs = ArrayList<BigInteger>()
        for (o in order) {
            sortedIdx.add(o[0])
            sortedMsgs.add(scalars[o[1]])
            bv = Bls12.add(bv, Bls12.mul(h[o[0]], scalars[o[1]]))
        }
        var t2 = Bls12.add(Bls12.mul(bv, p.c), Bls12.mul(p.d, p.r3Hat))
        for (k in 0 until u) t2 = Bls12.add(t2, Bls12.mul(h[undisclosed[k]], p.mHat[k]))

        val cv = calculateChallenge(p.abar, p.bbar, p.d, t1, t2, sortedIdx, sortedMsgs, domain, ph)
        if (cv != p.c) return Result.fail(CHALLENGE_MISMATCH)
        return if (Bls12.pairingEq(p.abar, w, p.bbar, BP2)) Result.OK else Result.fail(PAIRING_MISMATCH)
    }

    fun proofVerify(
        pk: ByteArray, proof: ByteArray, header: ByteArray, ph: ByteArray, disclosedMessages: List<ByteArray>, disclosedIndexes: List<Int>,
    ): Boolean = proofVerifyDetailed(pk, proof, header, ph, disclosedMessages, disclosedIndexes).ok
}
