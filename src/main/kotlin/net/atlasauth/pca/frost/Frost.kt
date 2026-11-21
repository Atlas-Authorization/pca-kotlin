package net.atlasauth.pca.frost

import net.atlasauth.pca.verifier.Json

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Collections
import java.util.WeakHashMap
import net.atlasauth.pca.ratchet.EdwardsPoint
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * FROST (Flexible Round-Optimized Schnorr Threshold) signatures for Ed25519, RFC 9591, ciphersuite FROST(Ed25519, SHA-512)
 * ("FROST-ED25519-SHA512-v1"). A trusted-dealer split, the two signing rounds, per-share verification and aggregation; the aggregate is an
 * ordinary 64-byte Ed25519 signature under the group public key. Group arithmetic is the shared Edwards25519 implementation
 * ([EdwardsPoint], libsodium); scalars are BigInteger mod L.
 *
 * Safety checks mirror the reference: strict canonical, prime-order, non-small-order points everywhere; one-shot nonces (a nonce array is
 * zeroised after use and its commitment is remembered, so reuse, which would leak the signing share, is refused); every signature share is
 * verified before aggregation; the aggregate is verified as strict Ed25519 before it is returned.
 * shortcut: BigInteger scalar arithmetic is not constant time in the operand values; move to a constant-time scalar library if signing
 * shares must run next to untrusted code.
 */
object Frost {
    @JvmField val L: BigInteger = EdwardsPoint.ORDER
    const val CONTEXT_STRING = "FROST-ED25519-SHA512-v1"
    private val CTX = CONTEXT_STRING.toByteArray(Charsets.UTF_8)
    private const val MAX_ID = 9007199254740991L // Number.MAX_SAFE_INTEGER
    const val SPENT_COMMITMENT_CAP = 262_144
    private val RNG = SecureRandom()

    // ---- records ----

    class FrostParticipantShare(val identifier: Long, val share: ByteArray, val publicKey: ByteArray)

    class FrostKeygenOpts {
        var secret: ByteArray? = null
        var coefficients: List<ByteArray>? = null
        var identifiers: LongArray? = null
    }

    class FrostKeygenResult internal constructor(val groupPublicKey: ByteArray, val participantShares: List<FrostParticipantShare>, val groupCommitment: List<ByteArray>)

    /** One participant's one-shot secret nonces; the arrays are zeroised by [sign]. */
    class FrostNonces(var hiding: ByteArray?, var binding: ByteArray?)

    class FrostCommitment(val identifier: Long, val hiding: ByteArray, val binding: ByteArray)

    class FrostCommitResult internal constructor(val hidingNonce: ByteArray, val bindingNonce: ByteArray, val commitment: FrostCommitment) {
        fun nonces(): FrostNonces = FrostNonces(hidingNonce, bindingNonce)
    }

    class FrostSignatureShare(val identifier: Long, val sigShare: ByteArray)

    /** A participant's public verification share (share * B). */
    class VerificationShare(val identifier: Long, val publicKey: ByteArray)

    class FrostSignOpts {
        var threshold: Int? = null
        var verificationShare: ByteArray? = null
        var verificationShares: List<VerificationShare>? = null
    }

    // ---- scalars and hashes ----

    private fun mod(a: BigInteger): BigInteger = a.mod(L)

    private fun le32(n: BigInteger): ByteArray {
        val out = ByteArray(32)
        val be = n.toByteArray()
        var i = 0
        while (i < 32 && i < be.size) { out[i] = be[be.size - 1 - i]; i++ }
        return out
    }

    private fun fromLe(b: ByteArray): BigInteger {
        val be = ByteArray(b.size)
        for (i in b.indices) be[b.size - 1 - i] = b[i]
        return BigInteger(1, be)
    }

    @JvmStatic
    fun scalarToBytes(s: BigInteger): ByteArray = le32(mod(s))

    /** Little-endian 0..64 bytes reduced mod L (the wide reduction HashToScalar needs); more than 64 bytes throws, like the reference. */
    @JvmStatic
    fun bytesToScalar(b: ByteArray): BigInteger {
        if (b.isEmpty()) return BigInteger.ZERO
        require(b.size <= 64) { "ct-scalar: reduce takes 1..64 bytes" }
        return mod(fromLe(b))
    }

    @JvmStatic
    fun isCanonicalScalar(b: ByteArray?): Boolean = b != null && b.size == 32 && fromLe(b) < L

    private fun concat(vararg parts: ByteArray): ByteArray {
        var n = 0
        for (p in parts) n += p.size
        val out = ByteArray(n)
        var i = 0
        for (p in parts) { System.arraycopy(p, 0, out, i, p.size); i += p.size }
        return out
    }

    private fun sha512(m: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(m)

    private fun utf8(s: String): ByteArray = Json.utf8(s)

    private fun hashToScalar(m: ByteArray): BigInteger = bytesToScalar(sha512(m))

    @JvmStatic fun H1(m: ByteArray): BigInteger = hashToScalar(concat(CTX, utf8("rho"), m))
    @JvmStatic fun H2(m: ByteArray): BigInteger = hashToScalar(m)
    @JvmStatic fun H3(m: ByteArray): BigInteger = hashToScalar(concat(CTX, utf8("nonce"), m))
    @JvmStatic fun H4(m: ByteArray): ByteArray = sha512(concat(CTX, utf8("msg"), m))
    @JvmStatic fun H5(m: ByteArray): ByteArray = sha512(concat(CTX, utf8("com"), m))

    // ---- points ----

    private fun mulBase(s: BigInteger): EdwardsPoint {
        val v = mod(s)
        return if (v.signum() == 0) EdwardsPoint.ZERO else EdwardsPoint.BASE.multiply(v)
    }

    private fun mulPoint(pt: EdwardsPoint, s: BigInteger): EdwardsPoint {
        val v = mod(s)
        return if (v.signum() == 0) EdwardsPoint.ZERO else pt.multiply(v)
    }

    /** Strict decode: canonical encoding, on the curve, not small order, in the prime-order subgroup. Throws otherwise. */
    @JvmStatic
    fun decodeSafePoint(b: ByteArray?): EdwardsPoint {
        require(!(b == null || b.size != 32)) { "frost: point must be 32 bytes" }
        val pt = try {
            EdwardsPoint.fromBytes(b)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("frost: invalid point encoding")
        }
        require(!pt.isSmallOrder()) { "frost: small-order point rejected" }
        require(pt.isTorsionFree()) { "frost: point is not in the prime-order subgroup" }
        require(pt.toBytes().contentEquals(b)) { "frost: non-canonical point encoding" }
        return pt
    }

    private fun assertValidId(id: Long) {
        require(!(id <= 0 || id > MAX_ID)) { "frost: participant identifier must be a positive safe integer" }
    }

    private fun validateCommitments(list: List<FrostCommitment>?, threshold: Int?) {
        require(!(list == null || list.isEmpty())) { "frost: empty commitment list" }
        if (threshold != null) {
            require(threshold >= 1) { "frost: invalid threshold" }
            require(list.size >= threshold) { "frost: need at least t=$threshold commitments (got ${list.size})" }
        }
        val seen = HashSet<Long>()
        for (c in list) {
            assertValidId(c.identifier)
            require(seen.add(c.identifier)) { "frost: duplicate commitment identifier ${c.identifier}" }
            decodeSafePoint(c.hiding)
            decodeSafePoint(c.binding)
        }
    }

    // ---- key generation ----

    private fun randomScalarBytes(): ByteArray { val b = ByteArray(32); RNG.nextBytes(b); return b }

    /** Trusted-dealer Shamir split of a (given or fresh) group secret into n shares with threshold t (RFC 9591 appendix C). */
    @JvmStatic
    @JvmOverloads
    fun trustedDealerKeygen(t: Int, n: Int, opts: FrostKeygenOpts? = null): FrostKeygenResult {
        val o = opts ?: FrostKeygenOpts()
        require(!(t < 1 || n < t)) { "frostTrustedDealerKeygen: need 1 <= t <= n (got t=$t, n=$n)" }
        val ids = o.identifiers ?: LongArray(n) { (it + 1).toLong() }
        require(ids.size == n) { "frostTrustedDealerKeygen: identifiers.length must equal n" }
        require(ids.toSet().size == n) { "frostTrustedDealerKeygen: identifiers must be distinct" }
        for (x in ids) require(!(x <= 0 || x > MAX_ID)) { "frostTrustedDealerKeygen: identifiers must be positive integers" }

        val secret = bytesToScalar(o.secret ?: randomScalarBytes())
        val coeffs = ArrayList<BigInteger>()
        coeffs.add(secret)
        for (i in 1 until t) {
            val given = o.coefficients
            val c = if (given != null && i - 1 < given.size) given[i - 1] else null
            coeffs.add(bytesToScalar(c ?: randomScalarBytes()))
        }
        val shares = ArrayList<FrostParticipantShare>()
        for (id in ids) {
            val x = BigInteger.valueOf(id)
            var acc = BigInteger.ZERO
            for (j in coeffs.size - 1 downTo 0) acc = mod(acc.multiply(x).add(coeffs[j]))
            shares.add(FrostParticipantShare(id, scalarToBytes(acc), mulBase(acc).toBytes()))
        }
        val commitment = ArrayList<ByteArray>()
        for (a in coeffs) commitment.add(mulBase(a).toBytes())
        return FrostKeygenResult(commitment[0], shares, commitment)
    }

    /** share * B, the participant's public verification share. */
    @JvmStatic
    fun verifyingShare(share: ByteArray): ByteArray = mulBase(bytesToScalar(share)).toBytes()

    // ---- round 1 ----

    private fun nonceGenerate(randomness: ByteArray, secretShare: ByteArray): BigInteger {
        require(randomness.size == 32) { "frostCommit: nonce randomness must be 32 bytes" }
        return H3(concat(randomness, scalarToBytes(bytesToScalar(secretShare))))
    }

    /** Round 1: the one-shot nonce pair and its public commitment. Randomness is drawn fresh unless given (tests / vectors). */
    @JvmStatic
    @JvmOverloads
    fun commit(p: FrostParticipantShare, hidingRandomness: ByteArray? = null, bindingRandomness: ByteArray? = null): FrostCommitResult {
        val hr = hidingRandomness ?: randomScalarBytes()
        val br = bindingRandomness ?: randomScalarBytes()
        val h = nonceGenerate(hr, p.share)
        val b = nonceGenerate(br, p.share)
        return FrostCommitResult(scalarToBytes(h), scalarToBytes(b), FrostCommitment(p.identifier, mulBase(h).toBytes(), mulBase(b).toBytes()))
    }

    // ---- round 2 helpers ----

    private fun sortCommitments(list: List<FrostCommitment>): List<FrostCommitment> = list.sortedWith(Comparator { a, b -> java.lang.Long.compare(a.identifier, b.identifier) })

    private fun encodeCommitmentList(list: List<FrostCommitment>): ByteArray {
        val parts = ArrayList<ByteArray>()
        for (c in list) {
            parts.add(scalarToBytes(BigInteger.valueOf(c.identifier)))
            parts.add(c.hiding)
            parts.add(c.binding)
        }
        return concat(*parts.toTypedArray())
    }

    private fun computeBindingFactors(groupPublicKey: ByteArray, list: List<FrostCommitment>, msg: ByteArray): Map<Long, BigInteger> {
        val prefix = concat(groupPublicKey, H4(msg), H5(encodeCommitmentList(list)))
        val out = HashMap<Long, BigInteger>()
        for (c in list) out[c.identifier] = H1(concat(prefix, scalarToBytes(BigInteger.valueOf(c.identifier))))
        return out
    }

    private fun computeGroupCommitment(list: List<FrostCommitment>, bindingFactors: Map<Long, BigInteger>): EdwardsPoint {
        var r = EdwardsPoint.ZERO
        for (c in list) r = r.add(decodeSafePoint(c.hiding)).add(mulPoint(decodeSafePoint(c.binding), bindingFactors[c.identifier]!!))
        return r
    }

    private fun computeChallenge(r: ByteArray, groupPublicKey: ByteArray, msg: ByteArray): BigInteger = H2(concat(r, groupPublicKey, msg))

    private fun deriveInterpolatingValue(participants: List<Long>, i: Long): BigInteger {
        require(participants.contains(i)) { "frost: identifier not in participant list" }
        var num = BigInteger.ONE
        var den = BigInteger.ONE
        val xi = BigInteger.valueOf(i)
        for (j in participants) {
            if (j == i) continue
            val xj = BigInteger.valueOf(j)
            num = mod(num.multiply(xj))
            den = mod(den.multiply(xj.subtract(xi)))
        }
        require(den.signum() != 0) { "frost: modular inverse of zero" }
        val lam = mod(num.multiply(den.modInverse(L)))
        require(lam.signum() != 0) { "frost: zero Lagrange coefficient" }
        return lam
    }

    // ---- one-shot nonce registry ----

    private val SPENT_NONCES: MutableSet<ByteArray> = Collections.synchronizedSet(Collections.newSetFromMap(WeakHashMap<ByteArray, Boolean>()))
    private val SPENT_COMMITMENTS = LinkedHashSet<String>()

    private fun commitmentKey(kind: Char, point: ByteArray): String = kind + Keys.b64u(point)

    private fun claimCommitment(key: String) {
        synchronized(SPENT_COMMITMENTS) {
            SPENT_COMMITMENTS.add(key)
            if (SPENT_COMMITMENTS.size > SPENT_COMMITMENT_CAP) {
                val it = SPENT_COMMITMENTS.iterator()
                it.next()
                it.remove()
            }
        }
    }

    private fun commitmentSpent(key: String): Boolean = synchronized(SPENT_COMMITMENTS) { SPENT_COMMITMENTS.contains(key) }

    private fun isZero(b: ByteArray): Boolean {
        var acc = 0
        for (x in b) acc = acc or x.toInt()
        return acc == 0
    }

    // ---- round 2 ----

    /**
     * Round 2: this participant's signature share. Consumes the nonces (zeroised, and remembered so the same nonce can never be signed with
     * twice). With `verificationShare(s)` in the options the share and the group key are cross-checked before any secret is used.
     */
    @JvmStatic
    @JvmOverloads
    fun sign(
        identifier: Long, share: ByteArray, groupPublicKey: ByteArray, nonces: FrostNonces?, message: ByteArray,
        signingCommitments: List<FrostCommitment>?, opts: FrostSignOpts? = null,
    ): FrostSignatureShare {
        val o = opts ?: FrostSignOpts()
        assertValidId(identifier)
        validateCommitments(signingCommitments, o.threshold)
        decodeSafePoint(groupPublicKey)
        val nh = nonces?.hiding
        val nb = nonces?.binding
        require(!(nonces == null || nh == null || nb == null)) { "frostSign: malformed nonces" }
        require(!(SPENT_NONCES.contains(nh) || SPENT_NONCES.contains(nb))) { "frostSign: nonces already used (one-shot; reuse would leak the signing share)" }
        require(!(isZero(nh) || isZero(nb))) { "frostSign: zero/zeroized nonce" }
        require(nh !== nb) { "frostSign: hiding and binding nonce must differ" }

        val list = sortCommitments(signingCommitments!!)
        val mine = list.firstOrNull { it.identifier == identifier } ?: throw IllegalArgumentException("frostSign: this identifier has no commitment in the set")

        val hiding = bytesToScalar(nh)
        val binding = bytesToScalar(nb)
        val sk = bytesToScalar(share)
        require(mulBase(hiding).sameAs(decodeSafePoint(mine.hiding)) && mulBase(binding).sameAs(decodeSafePoint(mine.binding))) { "frostSign: own commitment does not match nonces" }
        val hKey = commitmentKey('h', mine.hiding)
        val bKey = commitmentKey('b', mine.binding)
        require(!(commitmentSpent(hKey) || commitmentSpent(bKey))) { "frostSign: nonces already used (one-shot; reuse would leak the signing share)" }
        val vs1 = o.verificationShare
        if (vs1 != null) require(mulBase(sk).sameAs(decodeSafePoint(vs1))) { "frostSign: share does not match verification share" }
        val participants = list.map { it.identifier }
        val vss = o.verificationShares
        if (vss != null) {
            var acc = EdwardsPoint.ZERO
            for (id in participants) {
                val vs = vss.firstOrNull { it.identifier == id } ?: throw IllegalArgumentException("frostSign: missing verification share for $id")
                acc = acc.add(mulPoint(decodeSafePoint(vs.publicKey), deriveInterpolatingValue(participants, id)))
            }
            require(acc.sameAs(decodeSafePoint(groupPublicKey))) { "frostSign: group public key does not match the verification shares" }
        }

        val bindingFactors = computeBindingFactors(groupPublicKey, list, message)
        val bf = bindingFactors[identifier]!!
        val r = computeGroupCommitment(list, bindingFactors)
        val lambda = deriveInterpolatingValue(participants, identifier)
        val c = computeChallenge(r.toBytes(), groupPublicKey, message)
        val z = mod(hiding.add(binding.multiply(bf)).add(lambda.multiply(sk).multiply(c)))

        SPENT_NONCES.add(nh)
        SPENT_NONCES.add(nb)
        claimCommitment(hKey)
        claimCommitment(bKey)
        java.util.Arrays.fill(nh, 0.toByte())
        java.util.Arrays.fill(nb, 0.toByte())
        return FrostSignatureShare(identifier, scalarToBytes(z))
    }

    /** RFC 9591 section 5.3: one signature share checked against its verification share. Never throws; any malformed input is false. */
    @JvmStatic
    fun verifySigShare(
        identifier: Long, publicKey: ByteArray, commitment: FrostCommitment, sigShare: FrostSignatureShare,
        signingCommitments: List<FrostCommitment>?, groupPublicKey: ByteArray, message: ByteArray,
    ): Boolean = try {
        validateCommitments(signingCommitments, null)
        val list = sortCommitments(signingCommitments!!)
        val bindingFactors = computeBindingFactors(groupPublicKey, list, message)
        val bf = bindingFactors[identifier]
        if (bf == null) {
            false
        } else {
            val r = computeGroupCommitment(list, bindingFactors)
            val commShare = decodeSafePoint(commitment.hiding).add(mulPoint(decodeSafePoint(commitment.binding), bf))
            val c = computeChallenge(r.toBytes(), groupPublicKey, message)
            val participants = list.map { it.identifier }
            val lambda = deriveInterpolatingValue(participants, identifier)
            if (!isCanonicalScalar(sigShare.sigShare)) {
                false // z and z + L must not both verify
            } else {
                val lhs = mulBase(bytesToScalar(sigShare.sigShare))
                val rhs = commShare.add(mulPoint(decodeSafePoint(publicKey), mod(c.multiply(lambda))))
                lhs.sameAs(rhs)
            }
        }
    } catch (e: RuntimeException) {
        false
    }

    /**
     * Combine the signature shares into the 64-byte Ed25519 signature. Every share is verified against its verification share first, a
     * missing or extra share is refused, and the result must verify as strict Ed25519 under the group key.
     */
    @JvmStatic
    fun aggregate(
        message: ByteArray, signingCommitments: List<FrostCommitment>?, sigShares: List<FrostSignatureShare>?, groupPublicKey: ByteArray?,
        threshold: Int?, verificationShares: List<VerificationShare>?,
    ): ByteArray {
        validateCommitments(signingCommitments, threshold)
        decodeSafePoint(groupPublicKey)
        val list = sortCommitments(signingCommitments!!)
        require(!(sigShares == null || sigShares.size != list.size)) { "frostAggregate: need exactly one signature share per commitment" }
        val shareIds = HashSet<Long>()
        for (s in sigShares) {
            require(list.any { it.identifier == s.identifier }) { "frostAggregate: share from non-signer" }
            require(shareIds.add(s.identifier)) { "frostAggregate: duplicate signature share" }
        }
        requireNotNull(verificationShares) { "frostAggregate: verificationShares are required (every signature share is verified before aggregation)" }
        for (s in sigShares) {
            val vs = verificationShares.firstOrNull { it.identifier == s.identifier }
            val commitment = list.first { it.identifier == s.identifier }
            require(vs != null && verifySigShare(s.identifier, vs.publicKey, commitment, s, list, groupPublicKey!!, message)) {
                "frostAggregate: invalid signature share from participant ${s.identifier}"
            }
        }
        val r = computeGroupCommitment(list, computeBindingFactors(groupPublicKey!!, list, message))
        var z = BigInteger.ZERO
        for (s in sigShares) z = mod(z.add(bytesToScalar(s.sigShare)))
        val sig = concat(r.toBytes(), scalarToBytes(z))
        require(Pca.ed25519Strict(groupPublicKey, message, sig)) { "frostAggregate: aggregate signature does not verify (a share is invalid)" }
        return sig
    }

    /**
     * Run both rounds in-process for a quorum of participant shares (each carries its verification share) and return the aggregate
     * signature. Fails closed: an empty or sub-threshold quorum, a duplicate participant, or any invalid share throws.
     */
    @JvmStatic
    fun cosign(groupPublicKey: ByteArray, quorum: List<FrostParticipantShare>?, message: ByteArray, threshold: Int?): ByteArray {
        require(!(quorum == null || quorum.isEmpty())) { "frostCosign: empty signing quorum" }
        require(!(threshold != null && quorum.size < threshold)) { "frostCosign: quorum of ${quorum.size} is below the threshold t=$threshold" }
        val ids = HashSet<Long>()
        for (p in quorum) {
            assertValidId(p.identifier)
            require(ids.add(p.identifier)) { "frostCosign: duplicate participant ${p.identifier} in quorum" }
        }
        val vss = quorum.map { VerificationShare(it.identifier, it.publicKey) }
        val commits = quorum.map { commit(it) }
        val commitments = commits.map { it.commitment }
        val sigShares = ArrayList<FrostSignatureShare>()
        for (i in quorum.indices) {
            val p = quorum[i]
            val o = FrostSignOpts()
            o.threshold = threshold
            o.verificationShare = p.publicKey
            o.verificationShares = vss
            sigShares.add(sign(p.identifier, p.share, groupPublicKey, commits[i].nonces(), message, commitments, o))
        }
        return aggregate(message, commitments, sigShares, groupPublicKey, threshold, vss)
    }
}
