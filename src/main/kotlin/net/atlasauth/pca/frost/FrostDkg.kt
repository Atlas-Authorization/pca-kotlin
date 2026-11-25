package net.atlasauth.pca.frost

import net.atlasauth.pca.ratchet.EdwardsPoint
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.ZkJs
import java.math.BigDecimal
import java.math.BigInteger
import java.security.MessageDigest

/**
 * Trustless FROST distributed key generation: the two-round Pedersen DKG with a proof of possession (PedPoP), session binding, non-repudiable signed shares, a
 * justified-complaint blame round with the accused's rebuttal, an echo-broadcast agreement round and finalize over the qualified set. No dealer: nobody holds the
 * group secret, and the group key is the sum of the QUALIFIED participants' constant-term commitments. The output is a drop-in for the FROST signing primitives
 * (`signingShare` is a Shamir share of the group secret, `groupPublicKey` is f(0)*B), so a quorum signs an ordinary Ed25519 signature under the group key.
 *
 * Session binding: every run carries a caller-supplied `sessionId` folded into the proof-of-possession challenge and stamped on every package and share, so
 * nothing captured in one run replays into another. Every round-2 share is SIGNED by its sender under its constant-term key C0 (the key the round-1 proof
 * already proved possession of) over (session, sender, recipient, share, the whole commitment vector): a recipient holds a token the sender cannot deny, and a
 * complaint convicts the accused only when it exhibits the accused's OWN signature over a share that fails the VSS check; a share not validly signed by the
 * accused is inadmissible (a griefer cannot frame an honest party). A cheater who delivers garbage WITHOUT a valid signature is rejected at receipt and shows up
 * as a missing share at finalize, not as an attributable conviction.
 *
 * Honest scope: RFC 9591 is signing-only, so there is no published DKG vector; this is validated by round trip through the vector-exact signing path and by the
 * protocol invariants. It assumes an AUTHENTICATED BROADCAST channel for round-1 packages, complaints, rebuttals and echoes and PRIVATE authenticated delivery of
 * round-2 shares (see [FrostDkgChannel]); the module only produces and verifies the protocol messages. Scalar arithmetic is not constant time. It needs an
 * independent audit before production threshold custody.
 *
 * Packages, complaints, rebuttals and echoes are decoded JSON (maps with base64url text); shares and keys are byte arrays; results are JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object FrostDkg {
    private val L = Frost.L
    private val CTX = Frost.CONTEXT_STRING.toByteArray(Charsets.UTF_8)
    private val DKG_POP_DST = "dkg-pop".toByteArray(Charsets.UTF_8)
    private val DKG_SHARE_DST = "dkg-share".toByteArray(Charsets.UTF_8)
    private val DKG_SHARE_NONCE_DST = "dkg-share-nonce".toByteArray(Charsets.UTF_8)

    // ---- helpers ----

    private fun field(o: Any?, k: String): Any? = (o as? Map<*, *>)?.get(k)

    private fun concat(vararg parts: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        for (p in parts) out.write(p)
        return out.toByteArray()
    }

    private fun hashToScalar(msg: ByteArray): BigInteger = Frost.bytesToScalar(MessageDigest.getInstance("SHA-512").digest(msg))

    private fun mulBase(s: BigInteger): EdwardsPoint {
        val v = s.mod(L)
        return if (v.signum() == 0) EdwardsPoint.ZERO else EdwardsPoint.BASE.multiply(v)
    }

    private fun mulPoint(p: EdwardsPoint, s: BigInteger): EdwardsPoint {
        val v = s.mod(L)
        return if (v.signum() == 0) EdwardsPoint.ZERO else p.multiply(v)
    }

    private fun unb64u(s: Any?): ByteArray = Pca.decodeB64uStrict(s, -1) ?: throw IllegalArgumentException("invalid base64url")

    private fun b64(b: ByteArray): String = Keys.b64u(b)

    /** JavaScript `BigInt(x)`: a whole number or a decimal string; anything else throws. */
    private fun bigOf(x: Any?): BigInteger {
        if (x is String) return x.trim().let { if (it.isEmpty()) BigInteger.ZERO else BigInteger(it) }
        val d = IntentJs.num(x) ?: throw IllegalArgumentException("cannot convert to a BigInt")
        if (d.isNaN() || d.isInfinite() || d != Math.floor(d)) throw IllegalArgumentException("cannot convert a non-integer to a BigInt")
        return BigDecimal(d).toBigInteger()
    }

    private fun idBytes(x: Any?): ByteArray = Frost.scalarToBytes(bigOf(x))

    private fun isInteger(x: Any?): Boolean {
        val d = IntentJs.num(x) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.floor(d)
    }

    private fun canonicalScalar(b: ByteArray): BigInteger {
        if (!Frost.isCanonicalScalar(b)) throw IllegalArgumentException("dkg: scalar must be 32 bytes and < the group order")
        return Frost.bytesToScalar(b)
    }

    /** A number as a result id: the value the caller supplied, normalised to a JSON number. */
    private fun same(a: Any?, b: Any?): Boolean = if (IntentJs.num(a) != null && IntentJs.num(b) != null) IntentJs.num(a) == IntentJs.num(b) else a == b

    private fun key(x: Any?): Any? = IntentJs.num(x) ?: x

    // ---- commitment vector, polynomial, VSS ----

    private class CommitVec(val c0: EdwardsPoint, val bytes: ByteArray)

    /** The FULL commitment vector as bound into every challenge: `u32be(count) || each 32-byte point` (a dealer cannot show different higher-degree commitments to different parties). */
    private fun commitVecOf(commitments: Any?): CommitVec {
        if (commitments !is List<*> || commitments.isEmpty()) throw IllegalArgumentException("dkg: empty commitment vector")
        val pts = commitments.map { Frost.decodeSafePoint(unb64u(it)) }
        val n = pts.size
        val hdr = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())
        return CommitVec(pts[0], concat(hdr, *pts.map { it.toBytes() }.toTypedArray()))
    }

    private fun evalPoly(coeffs: List<BigInteger>, x: BigInteger): BigInteger {
        var acc = BigInteger.ZERO
        for (j in coeffs.size - 1 downTo 0) acc = acc.multiply(x).add(coeffs[j]).mod(L)
        return acc
    }

    /** Pedersen VSS: `g^share == product of commitments[k]^(atId^k)`. Shared by receipt checking and blame so detection and blame use the SAME predicate. */
    private fun vssCheck(share: BigInteger, commitments: Any?, atId: Any?): Boolean {
        if (commitments !is List<*> || commitments.isEmpty()) return false
        val lhs = mulBase(share)
        var rhs = EdwardsPoint.ZERO
        val x = bigOf(atId)
        var xk = BigInteger.ONE
        for (c in commitments) {
            rhs = rhs.add(mulPoint(Frost.decodeSafePoint(unb64u(c)), xk))
            xk = xk.multiply(x).mod(L)
        }
        return lhs.sameAs(rhs)
    }

    // ---- challenges and share signatures ----

    private fun popChallenge(sessionId: ByteArray, identifier: Any?, cv: CommitVec, r: EdwardsPoint): BigInteger =
        hashToScalar(concat(CTX, DKG_POP_DST, sessionId, idBytes(identifier), cv.bytes, r.toBytes()))

    private fun shareChallenge(sessionId: ByteArray, from: Any?, to: Any?, share: ByteArray, cv: CommitVec, rs: EdwardsPoint): BigInteger =
        hashToScalar(concat(CTX, DKG_SHARE_DST, sessionId, idBytes(from), idBytes(to), share, cv.bytes, rs.toBytes()))

    /** The per-share nonce is derived from the secret a0 and the full binding: deterministic and UNIQUE per (session, from, to, share), never reused across two shares. */
    private fun shareNonce(a0: BigInteger, sessionId: ByteArray, from: Any?, to: Any?, share: ByteArray, cv: CommitVec): BigInteger =
        hashToScalar(concat(CTX, DKG_SHARE_NONCE_DST, Frost.scalarToBytes(a0), sessionId, idBytes(from), idBytes(to), share, cv.bytes))

    private fun signShareScalar(a0: BigInteger, cv: CommitVec, sessionId: ByteArray, from: Any?, to: Any?, share: ByteArray): String {
        val k = shareNonce(a0, sessionId, from, to, share, cv)
        val rs = mulBase(k)
        val e = shareChallenge(sessionId, from, to, share, cv, rs)
        val s = k.add(a0.multiply(e)).mod(L)
        return b64(concat(rs.toBytes(), Frost.scalarToBytes(s)))
    }

    private fun verifyShareSig(sig: String, sessionId: ByteArray, from: Any?, to: Any?, share: ByteArray, cv: CommitVec): Boolean = try {
        val raw = unb64u(sig)
        if (raw.size != 64) {
            false
        } else {
            val rs = Frost.decodeSafePoint(raw.copyOfRange(0, 32))
            val s = canonicalScalar(raw.copyOfRange(32, 64))
            val e = shareChallenge(sessionId, from, to, share, cv, rs)
            mulBase(s).sameAs(rs.add(mulPoint(cv.c0, e)))
        }
    } catch (e: RuntimeException) {
        false
    }

    private fun verifyShareSigAgainstPackage(sig: Any?, sessionId: ByteArray, from: Any?, to: Any?, share: ByteArray, senderPackage: Any?): Boolean = try {
        val cc = field(senderPackage, "coefficientCommitments")
        if (sig !is String || cc !is List<*> || cc.isEmpty()) false else verifyShareSig(sig, sessionId, from, to, share, commitVecOf(cc))
    } catch (e: RuntimeException) {
        false
    }

    // ---- state ----

    /** A participant's RETAINED SECRET state after round 1: the secret polynomial, never broadcast. `pkg` is the participant's own public round-1 package. */
    class State(val identifier: Any?, val t: Int, val n: Int, val sessionId: ByteArray, val coefficients: List<ByteArray>, val pkg: Map<String, Any?>)

    class Round1Result(val pkg: Map<String, Any?>, val state: State)

    private fun num(x: Any?): Long = IntentJs.num(x)!!.toLong()

    /**
     * Sign the share `shareBytes` this participant sends to `to`, as the sender's non-repudiable token, exactly as [dkgRound2] attaches it. Throws on a share that is
     * not bytes or an identifier that is not a whole number.
     */
    @JvmStatic
    fun dkgSignShare(state: State, to: Any?, shareBytes: Any?): String {
        val share = shareBytes as? ByteArray ?: throw IllegalArgumentException("dkgSignShare: share must be bytes")
        val a0 = Frost.bytesToScalar(state.coefficients[0])
        val cv = commitVecOf(state.pkg["coefficientCommitments"])
        return signShareScalar(a0, cv, state.sessionId, state.identifier, to, share)
    }

    // ---- round 1 ----

    /**
     * ROUND 1. Participant `identifier` samples a degree-(t-1) secret polynomial (`coefficients`, each 32 bytes little endian, fixed for deterministic runs;
     * otherwise t draws of `rng`), publishes VSS commitments to its coefficients and a Schnorr proof of possession of the constant term bound to `sessionId`
     * (`popNonce` fixes the proof nonce; otherwise one more draw). Returns the PUBLIC package `{identifier, sessionId, coefficientCommitments,
     * proofOfKnowledge: {R, mu}}` and the SECRET [State].
     */
    @JvmStatic @JvmOverloads
    fun dkgRound1(identifier: Any?, t: Any?, n: Any?, sessionId: Any?, coefficients: Any? = null, popNonce: Any? = null, rng: Random32 = FrostNet.SECURE_RANDOM32): Round1Result {
        if (!isInteger(identifier) || IntentJs.num(identifier)!! <= 0) throw IllegalArgumentException("dkgRound1: identifier must be a positive integer")
        if (!isInteger(t) || !isInteger(n) || IntentJs.num(t)!! < 1 || IntentJs.num(n)!! < IntentJs.num(t)!!) throw IllegalArgumentException("dkgRound1: need 1 <= t <= n (got t=${ZkJs.string(t)}, n=${ZkJs.string(n)})")
        if (sessionId !is ByteArray || sessionId.isEmpty()) throw IllegalArgumentException("dkgRound1: sessionId must be a non-empty byte string")
        val tt = num(t).toInt()
        val coeffs = ArrayList<BigInteger>()
        val coeffBytes = ArrayList<ByteArray>()
        if (coefficients != null) {
            val given = coefficients as? List<Any?> ?: throw IllegalArgumentException("dkgRound1: coefficients must be a list")
            if (given.size != tt) throw IllegalArgumentException("dkgRound1: coefficients.length must equal t ($tt)")
            for (c in given) {
                val s = Frost.bytesToScalar(c as? ByteArray ?: throw IllegalArgumentException("dkgRound1: coefficient must be bytes"))
                coeffs.add(s)
                coeffBytes.add(Frost.scalarToBytes(s))
            }
        } else {
            for (j in 0 until tt) {
                val s = Frost.bytesToScalar(rng.next())
                coeffs.add(s)
                coeffBytes.add(Frost.scalarToBytes(s))
            }
        }
        val commitments = coeffs.map { b64(mulBase(it).toBytes()) }
        val a0 = coeffs[0]
        val cv = commitVecOf(commitments)
        val k = if (popNonce != null) Frost.bytesToScalar(popNonce as? ByteArray ?: throw IllegalArgumentException("dkgRound1: popNonce must be bytes")) else Frost.bytesToScalar(rng.next())
        val r = mulBase(k)
        val c = popChallenge(sessionId, identifier, cv, r)
        val mu = k.add(a0.multiply(c)).mod(L)
        val pkg = linkedMapOf<String, Any?>(
            "identifier" to identifier, "sessionId" to b64(sessionId), "coefficientCommitments" to commitments,
            "proofOfKnowledge" to linkedMapOf("R" to b64(r.toBytes()), "mu" to b64(Frost.scalarToBytes(mu))),
        )
        return Round1Result(pkg, State(identifier, tt, num(n).toInt(), sessionId.clone(), coeffBytes, pkg))
    }

    /**
     * Verify a peer's round-1 proof of possession against the constant-term commitment in the SAME package AND the expected `sessionId`: the stamped session must
     * match and the recomputed challenge (which binds the identifier and the session) must satisfy `mu*B == R + c*C0`. Never throws.
     */
    @JvmStatic
    fun dkgVerifyRound1(fromIdentifier: Any?, pkg: Any?, sessionId: Any?): Boolean = try {
        val sid = sessionId as? ByteArray ?: throw IllegalArgumentException("session")
        if (field(pkg, "sessionId") != b64(sid)) {
            false
        } else {
            val cc = field(pkg, "coefficientCommitments")
            if (cc is List<*> && cc.isEmpty()) {
                false
            } else {
                val cv = commitVecOf(cc)
                val pok = field(pkg, "proofOfKnowledge")
                val r = Frost.decodeSafePoint(unb64u(field(pok, "R")))
                val mu = canonicalScalar(unb64u(field(pok, "mu")))
                val c = popChallenge(sid, fromIdentifier, cv, r)
                mulBase(mu).sameAs(r.add(mulPoint(cv.c0, c)))
            }
        }
    } catch (e: RuntimeException) {
        false
    }

    // ---- round 2 ----

    /**
     * ROUND 2. The secret share `f_i(j)` this participant sends to EACH OTHER participant `j` of `allRound1Packages` (which must include its own package), in package
     * order, each stamped with the session and SIGNED by the sender: `[{from, to, sessionId, share (bytes), sig}]`. Each share is SECRET: deliver it to `to` over a
     * private authenticated channel. A package from another session is refused.
     */
    @JvmStatic
    fun dkgRound2(state: State, allRound1Packages: List<Any?>): List<Map<String, Any?>> {
        val ids = allRound1Packages.map { field(it, "identifier") }
        if (ids.map { key(it) }.toSet().size != ids.size) throw IllegalArgumentException("dkgRound2: duplicate identifiers in round-1 packages")
        if (ids.none { same(it, state.identifier) }) throw IllegalArgumentException("dkgRound2: my own round-1 package is missing")
        val sid = b64(state.sessionId)
        for (p in allRound1Packages) if (field(p, "sessionId") != sid) throw IllegalArgumentException("dkgRound2: participant ${ZkJs.string(field(p, "identifier"))} round-1 package is from a different session")
        val coeffs = state.coefficients.map { Frost.bytesToScalar(it) }
        val a0 = coeffs[0]
        val cv = commitVecOf(state.pkg["coefficientCommitments"])
        val out = ArrayList<Map<String, Any?>>()
        for (j in ids) {
            if (same(j, state.identifier)) continue
            val share = Frost.scalarToBytes(evalPoly(coeffs, bigOf(j)))
            val sig = signShareScalar(a0, cv, state.sessionId, state.identifier, j, share)
            out.add(linkedMapOf("from" to state.identifier, "to" to j, "sessionId" to sid, "share" to share, "sig" to sig))
        }
        return out
    }

    /**
     * Verify a received share `{from, share (bytes), sig}` against the sender's published round-1 package. All three must hold: the sender's package is valid
     * for THIS session; the sender's signature verifies under the package's C0 for `(session, from, myIdentifier, share)` (a share with no or an invalid
     * signature is rejected outright); and the Pedersen VSS check passes. Never throws.
     */
    @JvmStatic
    fun dkgVerifyShare(received: Any?, senderPackage: Any?, myIdentifier: Any?, sessionId: Any?): Boolean = try {
        val share = field(received, "share") as? ByteArray
        if (received == null || share == null) {
            false
        } else if (!dkgVerifyRound1(field(senderPackage, "identifier"), senderPackage, sessionId)) {
            false
        } else if (!verifyShareSigAgainstPackage(field(received, "sig"), sessionId as ByteArray, field(received, "from"), myIdentifier, share, senderPackage)) {
            false
        } else {
            vssCheck(canonicalScalar(share), field(senderPackage, "coefficientCommitments"), myIdentifier)
        }
    } catch (e: RuntimeException) {
        false
    }

    // ---- complaints and blame ----

    /**
     * Build a complaint, filed by `accuser` when the share it received from `accused` fails [dkgVerifyShare]: it REVEALS the received share AND the accused's
     * non-repudiable signature over it. The authoritative commitments at adjudication come from the broadcast round-1 packages, never from the complaint (so
     * `senderCommitments` is accepted for symmetry only), and the signature is re-checked against the accused's C0.
     */
    @JvmStatic
    fun dkgFileComplaint(accused: Any?, accuser: Any?, receivedShare: Any?, shareSig: Any?, senderCommitments: Any?, sessionId: Any?): Map<String, Any?> {
        if (!isInteger(accused) || IntentJs.num(accused)!! <= 0) throw IllegalArgumentException("dkgFileComplaint: accused must be a positive integer")
        if (!isInteger(accuser) || IntentJs.num(accuser)!! <= 0) throw IllegalArgumentException("dkgFileComplaint: accuser must be a positive integer")
        if (same(accused, accuser)) throw IllegalArgumentException("dkgFileComplaint: cannot file a complaint against yourself")
        if (shareSig !is String || shareSig.isEmpty()) throw IllegalArgumentException("dkgFileComplaint: shareSig (the accused-signed share) is required")
        if (sessionId !is ByteArray || sessionId.isEmpty()) throw IllegalArgumentException("dkgFileComplaint: sessionId must be a non-empty byte string")
        val rs = Frost.bytesToScalar(receivedShare as? ByteArray ?: throw IllegalArgumentException("dkgFileComplaint: receivedShare must be bytes"))
        return linkedMapOf("accused" to accused, "accuser" to accuser, "sessionId" to b64(sessionId), "revealedShare" to b64(Frost.scalarToBytes(rs)), "shareSig" to shareSig)
    }

    private fun findPackage(packages: Any?, id: Any?): Any? = (packages as List<Any?>).firstOrNull { same(field(it, "identifier"), id) }

    private fun verdict(justified: Boolean, reason: String, disqualify: Any? = null, atFault: Any? = null): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("justified" to justified)
        if (disqualify != null) m["disqualify"] = disqualify
        if (atFault != null) m["atFault"] = atFault
        m["reason"] = reason
        return m
    }

    /**
     * Adjudicate a complaint INDEPENDENTLY against the broadcast round-1 packages: scoped to the accused's session, the revealed share must be VALIDLY SIGNED BY
     * THE ACCUSED (inadmissible otherwise, so fabricated bytes cannot frame an honest party), then the VSS check decides: signed and failing VSS is JUSTIFIED
     * (disqualify the accused); signed and passing VSS is a false accusation (the accuser is at fault). Never throws. `{justified, disqualify?, atFault?, reason}`.
     */
    @JvmStatic
    fun dkgVerifyComplaint(complaint: Any?, round1Packages: Any?): Map<String, Any?> = try {
        if (complaint == null) throw IllegalArgumentException("Cannot read properties of null (reading 'accused')") // inside the reference's try: malformed
        val accused = field(complaint, "accused")
        val accuser = field(complaint, "accuser")
        val pkg = findPackage(round1Packages, accused)
        if (pkg == null) {
            verdict(false, "accused ${ZkJs.string(accused)} has no round-1 package to adjudicate against")
        } else if (field(pkg, "sessionId") != field(complaint, "sessionId")) {
            verdict(false, "complaint sessionId does not match the accused round-1 package session")
        } else {
            val sid = unb64u(field(complaint, "sessionId"))
            val share = unb64u(field(complaint, "revealedShare"))
            if (!verifyShareSigAgainstPackage(field(complaint, "shareSig"), sid, accused, accuser, share, pkg)) {
                verdict(false, "revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)", atFault = accuser)
            } else if (vssCheck(canonicalScalar(share), field(pkg, "coefficientCommitments"), accuser)) {
                verdict(false, "accused-signed share is VALID against the accused commitments — false accusation", atFault = accuser)
            } else {
                verdict(true, "accused non-repudiably signed a share that FAILS VSS against its broadcast commitments", disqualify = accused)
            }
        }
    } catch (e: RuntimeException) {
        verdict(false, "malformed complaint")
    }

    /**
     * The accused's REBUTTAL: re-present the share it actually signed and sent to the complaint's recipient (recomputed from its retained polynomial and re-signed
     * under C0, the same bytes [dkgRound2] produced). `{accused, accuser, sessionId, presentedShare, shareSig}`; throws when the state or the complaint do not
     * belong to `accused` or name another session.
     */
    @JvmStatic
    fun dkgRebut(accused: Any?, complaint: Any?, myRound2State: State): Map<String, Any?> {
        if (myRound2State.identifier != accused && !same(myRound2State.identifier, accused)) throw IllegalArgumentException("dkgRebut: myRound2State is not the accused")
        if (!same(field(complaint, "accused"), accused)) throw IllegalArgumentException("dkgRebut: complaint does not name this accused")
        if (b64(myRound2State.sessionId) != field(complaint, "sessionId")) throw IllegalArgumentException("dkgRebut: complaint is scoped to a different session than my state")
        val coeffs = myRound2State.coefficients.map { Frost.bytesToScalar(it) }
        val accuser = field(complaint, "accuser")
        val share = Frost.scalarToBytes(evalPoly(coeffs, bigOf(accuser)))
        val sig = dkgSignShare(myRound2State, accuser, share)
        return linkedMapOf("accused" to accused, "accuser" to accuser, "sessionId" to field(complaint, "sessionId"), "presentedShare" to b64(share), "shareSig" to sig)
    }

    private fun blame(guilty: Any?, reason: String): Map<String, Any?> = linkedMapOf("guilty" to guilty, "reason" to reason)

    /**
     * Adjudicate a complaint, optionally with the accused's rebuttal, to ONE guilty party from the signatures and VSS alone. An accused with no package is guilty;
     * a share validly signed by the accused is decisive (failing VSS: the accused is guilty, no rebuttal saves it; passing VSS: the accuser, a false accusation);
     * a share NOT validly signed by the accused is a non-receipt or fabrication claim, so the accuser is guilty unless a rebuttal that names the same pair and
     * session cannot present a validly signed, VSS-correct share (then the accused). Never throws for a complaint object. `{guilty, reason}`.
     */
    @JvmStatic
    fun dkgResolveBlame(complaint: Any?, rebuttal: Any?, round1Packages: Any?): Map<String, Any?> = try {
        val accused = field(complaint, "accused")
        val accuser = field(complaint, "accuser")
        val pkg = findPackage(round1Packages, accused)
        if (pkg == null) {
            blame(accused, "accused ${ZkJs.string(accused)} has no round-1 package to defend with")
        } else if (field(pkg, "sessionId") != field(complaint, "sessionId")) {
            blame(accuser, "complaint names a session the accused did not run — inadmissible")
        } else {
            val sid = unb64u(field(complaint, "sessionId"))
            val share = unb64u(field(complaint, "revealedShare"))
            val admissible = verifyShareSigAgainstPackage(field(complaint, "shareSig"), sid, accused, accuser, share, pkg)
            if (admissible) {
                if (!vssCheck(canonicalScalar(share), field(pkg, "coefficientCommitments"), accuser)) blame(accused, "accused non-repudiably signed a share that fails VSS")
                else blame(accuser, "accused-signed share is valid against its commitments — false accusation")
            } else if (rebuttal != null && ZkJs.truthy(rebuttal) && same(field(rebuttal, "accused"), accused) && same(field(rebuttal, "accuser"), accuser) &&
                field(rebuttal, "sessionId") == field(complaint, "sessionId")
            ) {
                val rShare = unb64u(field(rebuttal, "presentedShare"))
                val ok = verifyShareSigAgainstPackage(field(rebuttal, "shareSig"), sid, accused, accuser, rShare, pkg) &&
                    vssCheck(canonicalScalar(rShare), field(pkg, "coefficientCommitments"), accuser)
                if (ok) blame(accuser, "accused produced a validly-signed, VSS-correct share for the recipient — the non-receipt/fabrication complaint is refuted")
                else blame(accused, "accused could not present a validly-signed, VSS-correct share on rebuttal")
            } else {
                blame(accuser, "complaint carries no accused-signed share and the accused offered no rebuttal — inadmissible, cannot frame the accused")
            }
        }
    } catch (e: RuntimeException) {
        if (complaint !is Map<*, *>) throw e
        blame(field(complaint, "accuser"), "malformed complaint — inadmissible")
    }

    /**
     * The QUALIFIED set: the participants with a round-1 package on the run's session (the session the packages agree on, the first of equal counts) whose proof of
     * knowledge verifies, minus every participant a complaint resolves against AS THE ACCUSED (a guilty accuser removes nobody: a griefer can neither frame nor
     * remove an honest party). Order-independent; the surviving ids ascending.
     */
    @JvmStatic @JvmOverloads
    fun dkgQualifiedSet(participants: Any?, complaints: Any?, round1Packages: Any?, rebuttals: Any? = emptyList<Any?>()): List<Any?> {
        val pkgs = round1Packages as List<Any?>
        val pkgById = LinkedHashMap<Any?, Any?>()
        for (p in pkgs) pkgById[key(field(p, "identifier"))] = p
        val counts = LinkedHashMap<Any?, Int>()
        for (p in pkgs) counts.merge(field(p, "sessionId"), 1) { a, b -> a + b }
        var runSession: Any? = ""
        var best = -1
        for ((s, c) in counts) if (c > best) { best = c; runSession = s }
        val qualified = LinkedHashMap<Any?, Any?>()
        for (p in participants as List<Any?>) {
            val pkg = pkgById[key(p)] ?: continue
            if (field(pkg, "sessionId") != runSession) continue
            val sid = try { unb64u(field(pkg, "sessionId")) } catch (e: RuntimeException) { continue }
            if (dkgVerifyRound1(p, pkg, sid)) qualified[key(p)] = p
        }
        for (c in complaints as List<Any?>) {
            val reb = (rebuttals as List<Any?>).firstOrNull {
                same(field(it, "accused"), field(c, "accused")) && same(field(it, "accuser"), field(c, "accuser")) && field(it, "sessionId") == field(c, "sessionId")
            }
            val res = dkgResolveBlame(c, reb, pkgs)
            if (same(res["guilty"], field(c, "accused"))) qualified.remove(key(res["guilty"]))
        }
        return qualified.values.sortedBy { IntentJs.num(it) ?: Double.NaN }
    }

    // ---- echo agreement ----

    private fun hashOf(v: Any?): String = Pca.hashCanonical(IntentJs.normalize(v))

    private fun packageDigest(p: Any?): String {
        val pok = field(p, "proofOfKnowledge")
        return hashOf(
            linkedMapOf(
                "identifier" to field(p, "identifier"), "sessionId" to field(p, "sessionId"), "coefficientCommitments" to field(p, "coefficientCommitments"),
                "proofOfKnowledge" to linkedMapOf("R" to field(pok, "R"), "mu" to field(pok, "mu")),
            ),
        )
    }

    private fun complaintDigest(c: Any?): String = hashOf(
        linkedMapOf(
            "accused" to field(c, "accused"), "accuser" to field(c, "accuser"), "sessionId" to field(c, "sessionId"), "revealedShare" to field(c, "revealedShare"), "shareSig" to field(c, "shareSig"),
        ),
    )

    /**
     * The CANONICAL, order-independent transcript digest a party commits to in its echo: a hash over the sorted round-1 package digests, the sorted complaint
     * digests, the sorted qualified set and the session id, so two honest parties that saw the same transcript in any order agree and any divergence shows.
     */
    @JvmStatic
    fun dkgTranscriptDigest(round1Packages: Any?, complaints: Any?, qualified: Any?, sessionId: ByteArray): String {
        val r1 = (round1Packages as List<Any?>).map { packageDigest(it) }.sorted()
        val cs = (complaints as List<Any?>).map { complaintDigest(it) }.sorted()
        val q = (qualified as List<Any?>).sortedBy { IntentJs.num(it) ?: Double.NaN }
        return hashOf(linkedMapOf("sessionId" to b64(sessionId), "round1" to r1, "complaints" to cs, "qualified" to q))
    }

    /** This party's ECHO over its transcript view: `{identifier, sessionId, transcriptDigest}`, broadcast after the blame round and before finalize. */
    @JvmStatic
    fun dkgEcho(identifier: Any?, round1Packages: Any?, complaints: Any?, qualified: Any?, sessionId: ByteArray): Map<String, Any?> =
        linkedMapOf("identifier" to identifier, "sessionId" to b64(sessionId), "transcriptDigest" to dkgTranscriptDigest(round1Packages, complaints, qualified, sessionId))

    /**
     * Check the echo round: EVERY qualified party must have contributed exactly one echo, all bound to `sessionId`, all carrying the SAME digest; echoes of
     * non-qualified parties are ignored. `{agreed: true, digest}` or `{agreed: false, reason}` (a divergent digest signals equivocation). Never throws.
     */
    @JvmStatic
    fun dkgCheckEchoes(qualified: Any?, echoes: Any?, sessionId: Any?): Map<String, Any?> = try {
        val sid = b64(sessionId as? ByteArray ?: throw IllegalArgumentException("session"))
        val qSet = LinkedHashMap<Any?, Any?>()
        for (q in qualified as List<Any?>) qSet[key(q)] = q
        val byId = LinkedHashMap<Any?, Any?>()
        var failure: String? = null
        for (e in echoes as List<Any?>) {
            if (e == null) throw IllegalArgumentException("Cannot read properties of null (reading 'identifier')")
            val id = field(e, "identifier")
            if (!qSet.containsKey(key(id))) continue
            if (field(e, "sessionId") != sid) { failure = "echo from ${ZkJs.string(id)} is bound to a different session"; break }
            if (byId.containsKey(key(id))) { failure = "duplicate echo from qualified participant ${ZkJs.string(id)}"; break }
            byId[key(id)] = e
        }
        if (failure != null) {
            linkedMapOf("agreed" to false, "reason" to failure)
        } else {
            var agreed: Any? = null
            var have = false
            var out: Map<String, Any?>? = null
            for ((k, j) in qSet) {
                val e = byId[k]
                if (e == null) { out = linkedMapOf("agreed" to false, "reason" to "missing echo from qualified participant ${ZkJs.string(j)}"); break }
                if (!have) { agreed = field(e, "transcriptDigest"); have = true }
                else if (field(e, "transcriptDigest") != agreed) { out = linkedMapOf("agreed" to false, "reason" to "qualified participant ${ZkJs.string(j)} echoed a DIFFERENT transcript (equivocation detected)"); break }
            }
            out ?: if (!have) linkedMapOf("agreed" to false, "reason" to "no qualified echoes to agree on") else linkedMapOf("agreed" to true, "digest" to agreed)
        }
    } catch (e: RuntimeException) {
        linkedMapOf("agreed" to false, "reason" to "malformed echoes")
    }

    // ---- finalize ----

    private fun scalarSum(a: ByteArray, b: ByteArray): ByteArray = Frost.scalarToBytes(Frost.bytesToScalar(a).add(Frost.bytesToScalar(b)))

    /**
     * FINALIZE over the QUALIFIED set. `signingShare = f_i(i) + sum of the shares received from the other qualified participants`, `groupPublicKey = sum of the
     * qualified C_l0`, the group commitment `Phi_k = sum of the qualified C_lk` and every qualified participant's verifying share `Y_j = sum Phi_k*j^k`.
     * `receivedShares` are `{from, sessionId, share}`; `qualified` defaults to all participants of `allCommitments`; the finalizer must itself be qualified and at
     * least t strong; every package and share must name the state's session. `agreement` (`{echoes, complaints?}`) runs the echo round BEFORE any key is derived:
     * every qualified party's echo must carry the digest of THIS party's own transcript view, else it aborts. Throws on any violation; the key package is
     * `{identifier, signingShare, groupPublicKey, verifyingShare, publicKeyPackage: {groupPublicKey, groupCommitment, verifyingShares}}`.
     */
    @JvmStatic @JvmOverloads
    fun dkgFinalize(
        myIdentifier: Any?, myState: State, receivedShares: Any?, allCommitments: Any?, qualified: Any? = null, agreement: Any? = null, agreementPresent: Boolean = agreement != null,
    ): Map<String, Any?> {
        if (myState.identifier != myIdentifier && !same(myState.identifier, myIdentifier)) throw IllegalArgumentException("dkgFinalize: myState.identifier != myIdentifier")
        val pkgs = allCommitments as List<Any?>
        val ids = pkgs.map { field(it, "identifier") }
        if (ids.map { key(it) }.toSet().size != ids.size) throw IllegalArgumentException("dkgFinalize: duplicate identifiers in commitments")
        if (ids.none { same(it, myIdentifier) }) throw IllegalArgumentException("dkgFinalize: my own package is missing from allCommitments")
        val sid = b64(myState.sessionId)
        for (p in pkgs) if (field(p, "sessionId") != sid) throw IllegalArgumentException("dkgFinalize: participant ${ZkJs.string(field(p, "identifier"))} round-1 package is from a different session")
        val qset: List<Any?> = ((qualified as List<Any?>?) ?: ids).filter { q -> ids.any { same(it, q) } }
        val qSet = LinkedHashSet<Any?>(qset.map { key(it) })
        if (!qSet.contains(key(myIdentifier))) throw IllegalArgumentException("dkgFinalize: myIdentifier is not in the qualified set")
        if (qSet.size < myState.t) throw IllegalArgumentException("dkgFinalize: qualified set (${qSet.size}) is smaller than the threshold t=${myState.t}")
        val t = myState.t
        for (p in pkgs) {
            if (!qSet.contains(key(field(p, "identifier")))) continue // a disqualified participant may be malformed; ignore it
            val cc = field(p, "coefficientCommitments") as List<Any?>
            if (cc.size != t) throw IllegalArgumentException("dkgFinalize: participant ${ZkJs.string(field(p, "identifier"))} committed to ${cc.size} coefficients, expected t=$t")
        }
        if (agreementPresent && agreement is Map<*, *> && agreement.containsKey("echoes")) {
            val qsorted = qSet.sortedBy { IntentJs.num(it) ?: Double.NaN }
            val check = dkgCheckEchoes(qsorted, agreement["echoes"], myState.sessionId)
            if (check["agreed"] != true) throw IllegalArgumentException("dkgFinalize: echo-broadcast agreement failed — ${check["reason"]}")
            val mine = dkgTranscriptDigest(pkgs, (agreement["complaints"] as List<Any?>?) ?: emptyList<Any?>(), qsorted, myState.sessionId)
            if (check["digest"] != mine) throw IllegalArgumentException("dkgFinalize: echo-broadcast agreement failed — my transcript view diverges from the agreed echo digest (equivocation)")
        }
        val recvBy = LinkedHashMap<Any?, ByteArray>()
        for (r in receivedShares as List<Any?>) {
            val from = field(r, "from")
            if (same(from, myIdentifier)) continue
            if (!qSet.contains(key(from))) continue // drop shares from disqualified senders
            if (field(r, "sessionId") != sid) throw IllegalArgumentException("dkgFinalize: received share from ${ZkJs.string(from)} is from a different session")
            if (recvBy.containsKey(key(from))) throw IllegalArgumentException("dkgFinalize: duplicate received share from ${ZkJs.string(from)}")
            recvBy[key(from)] = field(r, "share") as? ByteArray ?: throw IllegalArgumentException("dkgFinalize: share must be bytes")
        }
        for (j in qset) {
            if (same(j, myIdentifier)) continue
            if (!recvBy.containsKey(key(j))) throw IllegalArgumentException("dkgFinalize: missing received share from qualified participant ${ZkJs.string(j)}")
        }
        val myCoeffs = myState.coefficients.map { Frost.bytesToScalar(it) }
        var sBytes = Frost.scalarToBytes(evalPoly(myCoeffs, bigOf(myIdentifier)))
        for ((_, share) in recvBy) {
            if (share.isEmpty() || share.size > 64) throw IllegalArgumentException("ct-scalar: reduce takes 1..64 bytes")
            sBytes = scalarSum(sBytes, share)
        }
        val groupCoeff = ArrayList<EdwardsPoint>()
        for (k in 0 until t) {
            var acc = EdwardsPoint.ZERO
            for (p in pkgs) {
                if (!qSet.contains(key(field(p, "identifier")))) continue
                acc = acc.add(Frost.decodeSafePoint(unb64u((field(p, "coefficientCommitments") as List<Any?>)[k])))
            }
            groupCoeff.add(acc)
        }
        val groupPublicKey = groupCoeff[0].toBytes()
        val groupCommitment = groupCoeff.map { it.toBytes() }
        val verifyingShares = qset.map { j ->
            var acc = EdwardsPoint.ZERO
            val x = bigOf(j)
            var xk = BigInteger.ONE
            for (phi in groupCoeff) {
                acc = acc.add(mulPoint(phi, xk))
                xk = xk.multiply(x).mod(L)
            }
            Pair(j, acc.toBytes())
        }
        val s = Frost.bytesToScalar(sBytes)
        val verifyingShare = mulBase(s).toBytes()
        val mine = verifyingShares.firstOrNull { same(it.first, myIdentifier) }
        if (mine == null || !mulBase(s).sameAs(Frost.decodeSafePoint(mine.second))) throw IllegalStateException("dkgFinalize: signing share is inconsistent with the group verifying share (bad dealer share)")
        return linkedMapOf(
            "identifier" to myIdentifier, "signingShare" to sBytes, "groupPublicKey" to groupPublicKey, "verifyingShare" to verifyingShare,
            "publicKeyPackage" to linkedMapOf(
                "groupPublicKey" to groupPublicKey, "groupCommitment" to groupCommitment,
                "verifyingShares" to verifyingShares.map { linkedMapOf("identifier" to it.first, "publicKey" to it.second) },
            ),
        )
    }

    // ---- in-process simulation ----

    /**
     * Run the whole ceremony in-process across `n` participants and return the shared group key and per-participant shares: `{groupPublicKey, participantShares:
     * [{identifier, share, publicKey}], groupCommitment, keyPackages, round1Packages, qualified, complaints, rebuttals, echoes, sessionId}`, shaped like a trusted
     * dealer's keygen so it is a literal drop-in for it but with no dealer. `opts`: `identifiers` (default 1..n), `coefficientsByParticipant` (fixed polynomials),
     * `sessionId` (default one draw of `rng`), `cheaters` (participants that send every recipient a share inconsistent with their commitments, which they SIGN;
     * the recipients complain and the cheaters are disqualified) and `equivocateEchoFor` (a participant whose echo covers a tampered qualified set, so
     * finalize aborts). It exercises every public step, checks that all qualified participants derive the same key and throws on any violation.
     */
    @JvmStatic @JvmOverloads
    fun frostDkgSimulate(t: Any?, n: Any?, opts: Map<String, Any?> = emptyMap(), rng: Random32 = FrostNet.SECURE_RANDOM32): Map<String, Any?> {
        if (!isInteger(t) || !isInteger(n) || IntentJs.num(t)!! < 1 || IntentJs.num(n)!! < IntentJs.num(t)!!) throw IllegalArgumentException("frostDkgSimulate: need 1 <= t <= n (got t=${ZkJs.string(t)}, n=${ZkJs.string(n)})")
        val nn = num(n).toInt()
        val ids: List<Any?> = (opts["identifiers"] as List<Any?>?) ?: List(nn) { IntentJs.ofLong((it + 1).toLong()) }
        if (ids.size != nn) throw IllegalArgumentException("frostDkgSimulate: identifiers.length must equal n")
        if (ids.map { key(it) }.toSet().size != nn) throw IllegalArgumentException("frostDkgSimulate: identifiers must be distinct")
        if (ids.any { !isInteger(it) || IntentJs.num(it)!! <= 0 }) throw IllegalArgumentException("frostDkgSimulate: identifiers must be positive integers")
        val sessionId = (opts["sessionId"] as ByteArray?) ?: rng.next()
        val cheaters = ((opts["cheaters"] as List<Any?>?) ?: emptyList<Any?>()).map { key(it) }.toSet()
        val perParticipant = opts["coefficientsByParticipant"] as List<Any?>?

        val states = ids.mapIndexed { idx, id -> dkgRound1(id, t, n, sessionId, perParticipant?.getOrNull(idx), null, rng).state }
        val round1Packages = states.map { it.pkg }
        for (p in round1Packages) if (!dkgVerifyRound1(p["identifier"], p, sessionId)) throw IllegalStateException("frostDkgSimulate: PoP verification failed for participant ${ZkJs.string(p["identifier"])}")

        val inbox = LinkedHashMap<Any?, ArrayList<Map<String, Any?>>>()
        for (id in ids) inbox[key(id)] = ArrayList()
        val complaints = ArrayList<Map<String, Any?>>()
        val stateById = LinkedHashMap<Any?, State>()
        for (st in states) stateById[key(st.identifier)] = st
        for (st in states) {
            for (outgoing in dkgRound2(st, round1Packages)) {
                var shareBytes = outgoing["share"] as ByteArray
                var shareSig = outgoing["sig"] as String
                if (cheaters.contains(key(outgoing["from"]))) {
                    val bad = shareBytes.clone()
                    bad[0] = (bad[0].toInt() xor 1).toByte() // inconsistent with the broadcast commitments
                    shareBytes = bad
                    shareSig = dkgSignShare(st, outgoing["to"], bad) // the cheater SIGNS what it actually sends
                }
                val senderPkg = round1Packages.first { same(it["identifier"], outgoing["from"]) }
                if (dkgVerifyShare(linkedMapOf("from" to outgoing["from"], "share" to shareBytes, "sig" to shareSig), senderPkg, outgoing["to"], sessionId)) {
                    inbox.getValue(key(outgoing["to"])).add(linkedMapOf("from" to outgoing["from"], "sessionId" to outgoing["sessionId"], "share" to shareBytes, "sig" to shareSig))
                } else {
                    complaints.add(dkgFileComplaint(outgoing["from"], outgoing["to"], shareBytes, shareSig, senderPkg["coefficientCommitments"], sessionId))
                }
            }
        }
        val rebuttals = complaints.map { dkgRebut(it["accused"], it, stateById.getValue(key(it["accused"]))) }
        val qualified = dkgQualifiedSet(ids, complaints, round1Packages, rebuttals)
        if (qualified.size < num(t)) throw IllegalStateException("frostDkgSimulate: only ${qualified.size} qualified participants (< t=${ZkJs.string(t)}) after the blame round")
        val equivocate = opts["equivocateEchoFor"]
        val echoes = qualified.map { id ->
            val view = if (opts.containsKey("equivocateEchoFor") && same(id, equivocate)) qualified.filter { q -> !same(q, qualified[qualified.size - 1]) } else qualified
            dkgEcho(id, round1Packages, complaints, view, sessionId)
        }
        val qualifiedStates = states.filter { st -> qualified.any { same(it, st.identifier) } }
        val keyPackages = qualifiedStates.map { st -> dkgFinalize(st.identifier, st, inbox.getValue(key(st.identifier)), round1Packages, qualified, linkedMapOf("echoes" to echoes, "complaints" to complaints), true) }
        val groupPublicKey = keyPackages[0]["groupPublicKey"] as ByteArray
        for (kp in keyPackages) if (!(kp["groupPublicKey"] as ByteArray).contentEquals(groupPublicKey)) throw IllegalStateException("frostDkgSimulate: participants disagree on the group public key")
        val participantShares = keyPackages.map { linkedMapOf("identifier" to it["identifier"], "share" to it["signingShare"], "publicKey" to it["verifyingShare"]) }
        return linkedMapOf(
            "groupPublicKey" to groupPublicKey, "participantShares" to participantShares, "groupCommitment" to (keyPackages[0]["publicKeyPackage"] as Map<String, Any?>)["groupCommitment"],
            "keyPackages" to keyPackages, "round1Packages" to round1Packages, "qualified" to qualified, "complaints" to complaints, "rebuttals" to rebuttals, "echoes" to echoes, "sessionId" to sessionId,
        )
    }
}
