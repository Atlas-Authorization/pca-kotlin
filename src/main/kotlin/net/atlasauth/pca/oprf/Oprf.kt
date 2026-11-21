package net.atlasauth.pca.oprf

import net.atlasauth.pca.verifier.Json

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import net.atlasauth.pca.ratchet.RistrettoElement

/**
 * RFC 9497 Oblivious Pseudorandom Functions on the `ristretto255-SHA512` ciphersuite (OPRF 0x00, VOPRF 0x01, POPRF 0x02).
 * The group is the shared ristretto255 implementation (RFC 9496, libsodium) the ratchet package already carries; the XMD expander
 * (RFC 9380 section 5.3.1) is written here and checked against the RFC 9497 Appendix A.1 vectors. Only this ciphersuite exists in the
 * reference (no P-256 / P-384 / P-521 / decaf448).
 */
object Oprf {
    const val ELEMENT_BYTES = 32
    const val SCALAR_BYTES = 32
    const val OUTPUT_BYTES = 64
    const val SUITE_ID = "ristretto255-SHA512"
    private val ORDER: BigInteger = RistrettoElement.ORDER
    private const val MAX_FRAMED_BYTES = 0xffff
    private val RNG = SecureRandom()

    /** The mode byte folded into every domain-separation tag. */
    internal fun modeByte(mode: String): Int = when (mode) {
        "oprf" -> 0x00
        "voprf" -> 0x01
        "poprf" -> 0x02
        else -> throw IllegalArgumentException("unknown OPRF mode: $mode")
    }

    // ---- byte helpers ----

    private fun utf8(s: String): ByteArray = Json.utf8(s)

    private fun cat(vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        for (p in parts) o.write(p, 0, p.size)
        return o.toByteArray()
    }

    private fun sha512(m: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(m)

    /** I2OSP: non-negative integer to a fixed-length big-endian byte string; refuses a value that does not fit. */
    internal fun i2osp(n0: Long, len: Int): ByteArray {
        var n = n0
        require(!(n < 0 || (len < 8 && n >= (1L shl (8 * len))))) { "I2OSP: value does not fit in $len bytes" }
        val out = ByteArray(len)
        for (i in len - 1 downTo 0) { out[i] = n.toByte(); n = n ushr 8 }
        return out
    }

    private fun lenPrefixed2(b: ByteArray): ByteArray = cat(i2osp(b.size.toLong(), 2), b)

    private fun assertBytes(v: ByteArray?, what: String, maxLen: Int) {
        requireNotNull(v) { "$what: expected a byte array" }
        require(v.size <= maxLen) { "$what: ${v.size} bytes exceeds the $maxLen-byte limit (RFC 9497 2-byte length framing)" }
    }

    private fun contextString(mode: String): ByteArray = cat(utf8("OPRFV1-"), i2osp(modeByte(mode).toLong(), 1), utf8("-$SUITE_ID"))

    private fun littleEndian(n: BigInteger, len: Int): ByteArray {
        val out = ByteArray(len)
        val be = n.toByteArray()
        var i = 0
        while (i < len && i < be.size) { out[i] = be[be.size - 1 - i]; i++ }
        return out
    }

    private fun fromLittleEndian(le: ByteArray): BigInteger {
        val be = ByteArray(le.size)
        for (i in le.indices) be[le.size - 1 - i] = le[i]
        return BigInteger(1, be)
    }

    // ---- element / scalar encodings ----

    @JvmStatic
    fun serializeElement(p: RistrettoElement): ByteArray = p.toRawBytes()

    /** Canonical 32-byte ristretto255 decoding; rejects the identity element and every non-canonical encoding. */
    @JvmStatic
    fun deserializeElement(bytes: ByteArray?): RistrettoElement {
        assertBytes(bytes, "DeserializeElement", Int.MAX_VALUE)
        val p = RistrettoElement.fromBytes(bytes!!)
        require(!p.isIdentity()) { "DeserializeElement: identity element is not a valid input" }
        return p
    }

    @JvmStatic
    fun serializeScalar(s: BigInteger): ByteArray = littleEndian(s.mod(ORDER), SCALAR_BYTES)

    /** 32-byte little-endian scalar; rejects any value >= the group order (one valid encoding per scalar). */
    @JvmStatic
    fun deserializeScalar(bytes: ByteArray?): BigInteger {
        assertBytes(bytes, "DeserializeScalar", Int.MAX_VALUE)
        require(bytes!!.size == SCALAR_BYTES) { "DeserializeScalar: expected $SCALAR_BYTES bytes, got ${bytes.size}" }
        val n = fromLittleEndian(bytes)
        require(n < ORDER) { "DeserializeScalar: non-canonical scalar (value >= group order)" }
        return n
    }

    // ---- hashing to the group / scalar field ----

    /** RFC 9380 section 5.3.1 expand_message_xmd with SHA-512 (block size 128, output 64). */
    internal fun expandMessageXmd(msg: ByteArray, dst: ByteArray, lenInBytes: Int): ByteArray {
        val bInBytes = 64
        val sInBytes = 128
        val ell = (lenInBytes + bInBytes - 1) / bInBytes
        require(!(ell > 255 || lenInBytes > 65535 || dst.size > 255)) { "expand_message_xmd: parameters out of range" }
        val dstPrime = cat(dst, i2osp(dst.size.toLong(), 1))
        val b0 = sha512(cat(ByteArray(sInBytes), msg, i2osp(lenInBytes.toLong(), 2), i2osp(0, 1), dstPrime))
        var bi = sha512(cat(b0, i2osp(1, 1), dstPrime))
        val uniform = ByteArrayOutputStream()
        uniform.write(bi, 0, bi.size)
        for (i in 2..ell) {
            val x = ByteArray(bInBytes)
            for (j in 0 until bInBytes) x[j] = (b0[j].toInt() xor bi[j].toInt()).toByte()
            bi = sha512(cat(x, i2osp(i.toLong(), 1), dstPrime))
            uniform.write(bi, 0, bi.size)
        }
        return uniform.toByteArray().copyOfRange(0, lenInBytes)
    }

    /** `HashToGroup(input)` with the mode's DST. */
    @JvmStatic
    fun hashToGroup(input: ByteArray, mode: String): RistrettoElement {
        val dst = cat(utf8("HashToGroup-"), contextString(mode))
        return RistrettoElement.fromUniformBytes(expandMessageXmd(input, dst, 64))
    }

    private fun hashToScalarWithDst(input: ByteArray, dst: ByteArray): BigInteger = fromLittleEndian(expandMessageXmd(input, dst, 64)).mod(ORDER)

    private fun hashToScalar(input: ByteArray, mode: String): BigInteger = hashToScalarWithDst(input, cat(utf8("HashToScalar-"), contextString(mode)))

    private fun scalarBaseMult(k: BigInteger): RistrettoElement = RistrettoElement.BASE.multiply(k.mod(ORDER))

    /** A uniformly random non-zero scalar; fails closed if the entropy source keeps returning zero. */
    @JvmStatic
    fun randomScalar(): BigInteger {
        for (attempt in 0 until 8) {
            val b = ByteArray(64)
            RNG.nextBytes(b)
            val s = fromLittleEndian(b).mod(ORDER)
            if (s.signum() != 0) return s
        }
        throw IllegalStateException("randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue")
    }

    private fun scalarInvert(s: BigInteger): BigInteger = RistrettoElement.scalarInvert(s)

    // ---- keys ----

    /** A server key pair, both halves serialized. */
    class KeyPair internal constructor(val secretKey: ByteArray, val publicKey: ByteArray)

    /** `DeriveKeyPair(seed, info)` (RFC 9497 section 3.2): the seed is exactly 32 bytes. */
    @JvmStatic
    fun deriveKeyPair(seed: ByteArray?, info: ByteArray?, mode: String): KeyPair {
        require(seed != null && seed.size == SCALAR_BYTES) { "DeriveKeyPair: seed must be exactly $SCALAR_BYTES bytes" }
        assertBytes(info, "DeriveKeyPair(info)", MAX_FRAMED_BYTES)
        val dst = cat(utf8("DeriveKeyPair"), contextString(mode))
        val deriveInput = cat(seed, i2osp(info!!.size.toLong(), 2), info)
        for (counter in 0..255) {
            val skS = hashToScalarWithDst(cat(deriveInput, i2osp(counter.toLong(), 1)), dst)
            if (skS.signum() != 0) return KeyPair(serializeScalar(skS), serializeElement(scalarBaseMult(skS)))
        }
        throw IllegalStateException("DeriveKeyPair: failed to derive a non-zero key after 256 attempts")
    }

    @JvmStatic
    fun randomKeyPair(): KeyPair {
        val skS = randomScalar()
        return KeyPair(serializeScalar(skS), serializeElement(scalarBaseMult(skS)))
    }

    @JvmStatic
    fun publicKeyFor(secretKey: ByteArray?): ByteArray = serializeElement(scalarBaseMult(deserializeScalar(secretKey)))

    // ---- DLEQ proof (RFC 9497 section 2.2) ----

    private fun compositesSeed(bSer: ByteArray, mode: String): ByteArray {
        val seedDst = cat(utf8("Seed-"), contextString(mode))
        return sha512(cat(i2osp(bSer.size.toLong(), 2), bSer, i2osp(seedDst.size.toLong(), 2), seedDst))
    }

    private fun compositeCoefficient(seed: ByteArray, index: Int, cSer: ByteArray, dSer: ByteArray, mode: String): BigInteger =
        hashToScalar(
            cat(
                i2osp(seed.size.toLong(), 2), seed, i2osp(index.toLong(), 2), i2osp(cSer.size.toLong(), 2), cSer,
                i2osp(dSer.size.toLong(), 2), dSer, utf8("Composite"),
            ),
            mode,
        )

    /** Single-element `ComputeComposites`: returns {M, Z}; when [k] is non-null this is the prover path (Z = k * M). */
    private fun composites(k: BigInteger?, b: RistrettoElement, c: RistrettoElement, d: RistrettoElement, mode: String): Array<RistrettoElement> {
        val seed = compositesSeed(serializeElement(b), mode)
        val coeff = compositeCoefficient(seed, 0, serializeElement(c), serializeElement(d), mode)
        val m = c.multiplyPublic(coeff).add(RistrettoElement.ZERO)
        val z = if (k != null) m.multiply(k.mod(ORDER)) else d.multiplyPublic(coeff).add(RistrettoElement.ZERO)
        return arrayOf(m, z)
    }

    private fun challenge(b: RistrettoElement, m: RistrettoElement, z: RistrettoElement, t2: RistrettoElement, t3: RistrettoElement, mode: String): BigInteger {
        val transcript = cat(
            lenPrefixed2(serializeElement(b)), lenPrefixed2(serializeElement(m)), lenPrefixed2(serializeElement(z)),
            lenPrefixed2(serializeElement(t2)), lenPrefixed2(serializeElement(t3)), utf8("Challenge"),
        )
        return hashToScalar(transcript, mode)
    }

    private fun generateProof(
        k: BigInteger, a: RistrettoElement, b: RistrettoElement, c: RistrettoElement, d: RistrettoElement, mode: String, fixedRandomness: ByteArray?,
    ): ByteArray {
        val mz = composites(k, b, c, d, mode)
        val r = if (fixedRandomness == null) randomScalar() else deserializeScalar(fixedRandomness)
        val t2 = a.multiply(r)
        val t3 = mz[0].multiply(r)
        val cc = challenge(b, mz[0], mz[1], t2, t3, mode)
        val s = r.subtract(cc.multiply(k)).mod(ORDER)
        return cat(serializeScalar(cc), serializeScalar(s))
    }

    private fun verifyProof(a: RistrettoElement, b: RistrettoElement, c: RistrettoElement, d: RistrettoElement, proof: ByteArray, mode: String): Boolean {
        if (proof.size != 2 * SCALAR_BYTES) return false
        val cc = deserializeScalar(proof.copyOfRange(0, SCALAR_BYTES))
        val s = deserializeScalar(proof.copyOfRange(SCALAR_BYTES, 2 * SCALAR_BYTES))
        val mz = composites(null, b, c, d, mode)
        val t2 = a.multiplyPublic(s).add(b.multiplyPublic(cc))
        val t3 = mz[0].multiplyPublic(s).add(mz[1].multiplyPublic(cc))
        val expected = challenge(b, mz[0], mz[1], t2, t3, mode)
        return expected.subtract(cc).mod(ORDER).signum() == 0
    }

    // ---- finalize hashes ----

    private fun finalizeHash(input: ByteArray, issued: ByteArray): ByteArray =
        sha512(cat(i2osp(input.size.toLong(), 2), input, i2osp(issued.size.toLong(), 2), issued, utf8("Finalize")))

    private fun finalizeHashPoprf(input: ByteArray, info: ByteArray, issued: ByteArray): ByteArray =
        sha512(cat(i2osp(input.size.toLong(), 2), input, i2osp(info.size.toLong(), 2), info, i2osp(issued.size.toLong(), 2), issued, utf8("Finalize")))

    // ---- OPRF + VOPRF ----

    /** The client's retained blind plus the element to send. */
    open class BlindResult internal constructor(val blind: ByteArray, val blindedElement: ByteArray)

    /** A server blind-evaluation; [proof] is null for plain OPRF. */
    class EvaluateResult(val evaluatedElement: ByteArray, val proof: ByteArray?)

    /** `Blind(input)`; [fixedBlind] (null normally) pins the blind for test vectors. */
    @JvmStatic
    @JvmOverloads
    fun blind(input: ByteArray?, mode: String, fixedBlind: ByteArray? = null): BlindResult {
        assertBytes(input, "Blind(input)", MAX_FRAMED_BYTES)
        val r = if (fixedBlind == null) randomScalar() else deserializeScalar(fixedBlind)
        val inputElement = hashToGroup(input!!, mode)
        check(!inputElement.isIdentity()) { "Blind: input maps to identity" }
        return BlindResult(serializeScalar(r), serializeElement(inputElement.multiply(r)))
    }

    /**
     * Server `BlindEvaluate` for mode "oprf" or "voprf" (anything else is refused). For VOPRF a DLEQ proof against [publicKey] (derived
     * from the secret key when null) is attached; [fixedProofRandomness] is for test vectors only.
     */
    @JvmStatic
    @JvmOverloads
    fun blindEvaluate(secretKey: ByteArray?, blindedElement: ByteArray?, mode: String, publicKey: ByteArray? = null, fixedProofRandomness: ByteArray? = null): EvaluateResult {
        require(mode == "oprf" || mode == "voprf") { "blindEvaluate: mode must be oprf or voprf" }
        val skS = deserializeScalar(secretKey)
        val r = deserializeElement(blindedElement)
        val evaluated = r.multiply(skS)
        if (mode == "oprf") return EvaluateResult(serializeElement(evaluated), null)
        val pk = if (publicKey == null) scalarBaseMult(skS) else deserializeElement(publicKey)
        val proof = generateProof(skS, RistrettoElement.BASE, pk, r, evaluated, "voprf", fixedProofRandomness)
        return EvaluateResult(serializeElement(evaluated), proof)
    }

    /**
     * Client `Finalize` for "oprf" / "voprf". For VOPRF the DLEQ proof is verified first (proof, publicKey and blindedElement are
     * required) and a bad proof throws.
     */
    @JvmStatic
    @JvmOverloads
    fun finalizeOprf(
        input: ByteArray?, blindScalar: ByteArray?, evaluatedElement: ByteArray?, mode: String,
        proof: ByteArray? = null, publicKey: ByteArray? = null, blindedElement: ByteArray? = null,
    ): ByteArray {
        require(mode == "oprf" || mode == "voprf") { "finalize: mode must be oprf or voprf" }
        assertBytes(input, "Finalize(input)", MAX_FRAMED_BYTES)
        val r = deserializeScalar(blindScalar)
        val evaluated = deserializeElement(evaluatedElement)
        if (mode == "voprf") {
            require(proof != null && publicKey != null && blindedElement != null) { "Finalize(voprf): proof, publicKey and blindedElement are required" }
            val pk = deserializeElement(publicKey)
            val blinded = deserializeElement(blindedElement)
            if (!verifyProof(RistrettoElement.BASE, pk, blinded, evaluated, proof, "voprf")) throw SecurityException("Finalize(voprf): DLEQ proof verification failed")
        }
        return finalizeHash(input!!, serializeElement(evaluated.multiply(scalarInvert(r))))
    }

    /** The server's non-blinded reference output for "oprf" / "voprf". */
    @JvmStatic
    fun evaluate(secretKey: ByteArray?, input: ByteArray?, mode: String): ByteArray {
        require(mode == "oprf" || mode == "voprf") { "evaluate: mode must be oprf or voprf" }
        assertBytes(input, "Evaluate(input)", MAX_FRAMED_BYTES)
        val skS = deserializeScalar(secretKey)
        val inputElement = hashToGroup(input!!, mode)
        check(!inputElement.isIdentity()) { "Evaluate: input maps to identity" }
        return finalizeHash(input, serializeElement(inputElement.multiply(skS)))
    }

    // ---- POPRF ----

    private fun poprfInfoScalar(info: ByteArray?): BigInteger {
        assertBytes(info, "info", MAX_FRAMED_BYTES)
        return hashToScalar(cat(utf8("Info"), i2osp(info!!.size.toLong(), 2), info), "poprf")
    }

    /** The POPRF client state: blind, blinded element and the tweaked key (m*G + pkS) it must verify against. */
    class PoprfBlindResult internal constructor(b: BlindResult, val tweakedKey: ByteArray) : BlindResult(b.blind, b.blindedElement)

    @JvmStatic
    @JvmOverloads
    fun blindPoprf(input: ByteArray?, info: ByteArray?, publicKey: ByteArray?, fixedBlind: ByteArray? = null): PoprfBlindResult {
        assertBytes(input, "Blind(input)", MAX_FRAMED_BYTES)
        val m = poprfInfoScalar(info)
        val tweaked = scalarBaseMult(m).add(deserializeElement(publicKey))
        check(!tweaked.isIdentity()) { "Blind(poprf): tweaked key is identity" }
        val base = blind(input, "poprf", fixedBlind)
        return PoprfBlindResult(base, serializeElement(tweaked))
    }

    @JvmStatic
    @JvmOverloads
    fun blindEvaluatePoprf(secretKey: ByteArray?, blindedElement: ByteArray?, info: ByteArray?, fixedProofRandomness: ByteArray? = null): EvaluateResult {
        val skS = deserializeScalar(secretKey)
        val m = poprfInfoScalar(info)
        val t = skS.add(m).mod(ORDER)
        check(t.signum() != 0) { "BlindEvaluate(poprf): inverse of zero (bad info/key)" }
        val blinded = deserializeElement(blindedElement)
        val evaluated = blinded.multiply(scalarInvert(t))
        val tweakedKey = scalarBaseMult(t)
        val proof = generateProof(t, RistrettoElement.BASE, tweakedKey, evaluated, blinded, "poprf", fixedProofRandomness)
        return EvaluateResult(serializeElement(evaluated), proof)
    }

    @JvmStatic
    fun finalizePoprf(
        input: ByteArray?, blindScalar: ByteArray?, evaluatedElement: ByteArray?, info: ByteArray?, proof: ByteArray?, blindedElement: ByteArray?, tweakedKey: ByteArray?,
    ): ByteArray {
        assertBytes(input, "Finalize(input)", MAX_FRAMED_BYTES)
        assertBytes(info, "info", MAX_FRAMED_BYTES)
        val r = deserializeScalar(blindScalar)
        val evaluated = deserializeElement(evaluatedElement)
        val blinded = deserializeElement(blindedElement)
        val tweaked = deserializeElement(tweakedKey)
        if (proof == null || !verifyProof(RistrettoElement.BASE, tweaked, evaluated, blinded, proof, "poprf")) throw SecurityException("Finalize(poprf): DLEQ proof verification failed")
        return finalizeHashPoprf(input!!, info!!, serializeElement(evaluated.multiply(scalarInvert(r))))
    }

    @JvmStatic
    fun evaluatePoprf(secretKey: ByteArray?, input: ByteArray?, info: ByteArray?): ByteArray {
        assertBytes(input, "Evaluate(input)", MAX_FRAMED_BYTES)
        val skS = deserializeScalar(secretKey)
        val m = poprfInfoScalar(info)
        val t = skS.add(m).mod(ORDER)
        check(t.signum() != 0) { "Evaluate(poprf): inverse of zero (bad info/key)" }
        val inputElement = hashToGroup(input!!, "poprf")
        check(!inputElement.isIdentity()) { "Evaluate(poprf): input maps to identity" }
        return finalizeHashPoprf(input, info!!, serializeElement(inputElement.multiply(scalarInvert(t))))
    }

    // ---- utilities ----

    @JvmStatic
    fun toHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(Character.forDigit(v shr 4, 16)).append(Character.forDigit(v and 15, 16))
        }
        return sb.toString()
    }

    /** Length check first, then a full-width constant-time compare. */
    @JvmStatic
    fun bytesEqual(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)
}
