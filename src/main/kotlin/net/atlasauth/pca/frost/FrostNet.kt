package net.atlasauth.pca.frost

import net.atlasauth.pca.compliance.ComplianceJs
import net.atlasauth.pca.ratchet.EdwardsPoint
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.ZkJs
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** The source of 32-byte random values every FROST operation draws from (nonces, proof-of-possession nonces, default session ids): a seam for reproducible transcripts. */
fun interface Random32 {
    fun next(): ByteArray
}

/** Thrown by [FrostNet.enrollVerificationShares] when a signer's key has no valid proof-of-possession. */
class PoPError(message: String, val identifier: Long? = null) : RuntimeException(message)

/** Thrown when a signer sends two DIFFERENT messages for the same (session, round). */
class EquivocationError(val sessionId: String, val round: Long, val identifier: Long, val previousDigest: String, val offendingDigest: String) :
    RuntimeException("equivocation: signer $identifier sent two different messages for session '$sessionId' round $round")

/** A refusal of a signing session, with the per-signer reasons. */
open class CoordinatorError(message: String, val refusals: List<Pair<Long, String>> = emptyList()) : RuntimeException(message)

/** A signing session that exceeded its bounded round deadline: it produced NO signature. */
class CoordinatorTimeoutError(message: String, val timeoutMs: Double, refusals: List<Pair<Long, String>> = emptyList()) : CoordinatorError(message, refusals)

/** One signer reached through a transport: the coordinator holds this handle, never the share. A throw is an unreachable signer. */
interface SignerTransport {
    val identifier: Long
    fun round1(req: Map<String, Any?>): Map<String, Any?>
    fun round2(req: Map<String, Any?>): Map<String, Any?>
}

/**
 * Multi-process network FROST for guardian custody: the PROTOCOL half of the guardian quorum. [FrostNet.GuardianSignerService] holds exactly ONE share and never
 * emits it; the [FrostNet.NetworkCoordinator] collects at least t round-1 commitments, forms the signing set, collects the round-2 shares and aggregates with the
 * ordinary FROST primitives; it holds no share and cannot sign alone. Each signer independently verifies a policy authorization token (an Ed25519-signed "allow
 * for action digest X under group key G") against the authority key it was CONFIGURED with before it releases its share, so a compromised coordinator cannot make a
 * signer release. Enforced here: a Schnorr proof-of-possession of every verification share (rogue-key defense), equivocation detection per (session, round,
 * signer), a bounded round deadline and a stale-session guard. Out of scope: separate hosts and HSMs, and authenticated, encrypted channels with a PKI.
 * The aggregate is an ordinary Ed25519 signature under the group key, so the verifier needs nothing new.
 *
 * Messages, tokens and wire objects are decoded JSON (maps and lists, base64url text); results are JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object FrostNet {
    const val ALLOW_TOKEN_TYP = "pca.frost.allow.v1"
    const val SIGNER_POP_DST = "pca.frost.signer-pop.v1"

    /** The largest signing set a signer or coordinator decodes: bounds the interpolation work a hostile peer can demand. */
    const val MAX_FROST_SIGNING_SET = 256
    private val SECURE = SecureRandom()
    private val L = Frost.L

    @JvmField val SECURE_RANDOM32: Random32 = Random32 { ByteArray(32).also { SECURE.nextBytes(it) } }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    private fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    private fun posSafe(x: Any?): Boolean = IntentJs.isSafeInteger(x) && IntentJs.num(x)!! > 0

    private fun key32(x: Any?): Boolean = x is ByteArray && x.size == 32

    private fun b64uOf(x: Any?): String = if (x is ByteArray) Keys.b64u(x) else throw IllegalArgumentException("The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.")

    private fun canon(v: Any?): ByteArray = Pca.canonBytes(IntentJs.normalize(v))

    // ---- allow token ----

    /** `base64url(sha256(message))`: the "action digest" an allow token authorizes. */
    @JvmStatic
    fun frostActionDigest(message: Any?): String {
        if (message !is ByteArray) throw IllegalArgumentException("frostActionDigest: message must be bytes")
        return Keys.b64u(sha256(message))
    }

    /**
     * Mint an allow token with the policy authority's Ed25519 SECRET key: `{body: {typ, action_digest, group_pk, nonce, not_before?, expires_at?}, authority, sig}`.
     * `opts` is `{message?, frostActionDigest?, groupPublicKey, nonce?, notBefore?, expiresAt?}`: the digest is `frostActionDigest` or the digest of `message`
     * (one is required); the default nonce is one 32-byte draw of `rng`.
     */
    @JvmStatic @JvmOverloads
    fun issueAllowToken(policySecretKey: Any?, opts: Map<String, Any?>, rng: Random32 = SECURE_RANDOM32): Map<String, Any?> {
        val given = opts["frostActionDigest"]
        val digest: Any? = given ?: (if (ZkJs.truthy(opts["message"])) frostActionDigest(opts["message"]) else null)
        if (!ZkJs.truthy(digest)) throw IllegalArgumentException("issueAllowToken: provide message or frostActionDigest")
        val body = linkedMapOf<String, Any?>("typ" to ALLOW_TOKEN_TYP, "action_digest" to digest, "group_pk" to b64uOf(opts["groupPublicKey"]))
        body["nonce"] = opts["nonce"] ?: Keys.b64u(rng.next())
        if (opts.containsKey("notBefore")) body["not_before"] = opts["notBefore"]
        if (opts.containsKey("expiresAt")) body["expires_at"] = opts["expiresAt"]
        val sk = policySecretKey as? ByteArray ?: throw IllegalArgumentException("The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.")
        val ed = Keys.edFromSeed(sk)
        return linkedMapOf("body" to body, "authority" to ed.id(), "sig" to Keys.b64u(ed.sign(canon(body))))
    }

    private fun verdict(ok: Boolean, reason: String? = null): Map<String, Any?> = if (ok) linkedMapOf("ok" to true) else linkedMapOf("ok" to false, "reason" to reason)

    /**
     * Independently verify an allow token against the signer's CONFIGURED authority key (never `token.authority`, which a coordinator could set to its own):
     * well formed, the right `typ`, signed by that key, naming this group key and this message's action digest, and inside its window. `expect` is
     * `{policyAuthorityPublicKey, groupPublicKey, message, now}`. `{ok}` or `{ok: false, reason}`; the tail after `(fail closed): ` of an error reason is open.
     */
    @JvmStatic
    fun verifyAllowToken(token: Any?, expect: Map<String, Any?>): Map<String, Any?> {
        try {
            if (token == null || (token !is Map<*, *> && token !is List<*>)) return verdict(false, "allow token missing or malformed")
            val body = get(token, "body")
            if (body == null || (body !is Map<*, *> && body !is List<*>)) return verdict(false, "allow token has no body")
            if (get(body, "typ") != ALLOW_TOKEN_TYP) return verdict(false, "allow token wrong typ (${ZkJs.string(if (has(body, "typ")) get(body, "typ") else ZkJs.UNDEF)})")
            val sig = get(token, "sig")
            if (sig !is String) return verdict(false, "allow token missing signature")
            val sigBytes = Pca.decodeB64uStrict(sig, 64) ?: return verdict(false, "allow token signature not canonical base64url")
            if (expect["policyAuthorityPublicKey"] == null) return verdict(false, "allow token not signed by the trusted policy authority") // a null key verifies nothing
            val pub = expect["policyAuthorityPublicKey"] as? ByteArray ?: throw IllegalArgumentException("The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.")
            if (!Pca.ed25519Strict(pub, canon(body), sigBytes)) return verdict(false, "allow token not signed by the trusted policy authority")
            if (get(body, "group_pk") != b64uOf(expect["groupPublicKey"])) return verdict(false, "allow token authorizes a different group key")
            if (get(body, "action_digest") != frostActionDigest(expect["message"])) return verdict(false, "allow token authorizes a different action digest")
            val now = expect["now"]
            if (!IntentJs.isFinite(now)) return verdict(false, "invalid verification time")
            val nowD = IntentJs.num(now)!!
            if (has(body, "not_before") && nowD < ComplianceJs.toNumber(get(body, "not_before"))) return verdict(false, "allow token not yet valid")
            if (has(body, "expires_at") && nowD >= ComplianceJs.toNumber(get(body, "expires_at"))) return verdict(false, "allow token expired")
            return verdict(true)
        } catch (e: RuntimeException) {
            return verdict(false, "allow token verification error (fail closed): ${e.message ?: "unknown"}")
        }
    }

    // ---- proof of possession ----

    private fun mulBase(s: BigInteger): EdwardsPoint {
        val v = s.mod(L)
        return if (v.signum() == 0) EdwardsPoint.ZERO else EdwardsPoint.BASE.multiply(v)
    }

    private fun mulPoint(p: EdwardsPoint, s: BigInteger): EdwardsPoint {
        val v = s.mod(L)
        return if (v.signum() == 0) EdwardsPoint.ZERO else p.multiply(v)
    }

    private fun popChallenge(groupPublicKey: ByteArray, identifier: Long, pk: ByteArray, r: ByteArray): BigInteger {
        val h = MessageDigest.getInstance("SHA-512")
        h.update(SIGNER_POP_DST.toByteArray(Charsets.UTF_8))
        h.update(groupPublicKey)
        h.update(Frost.scalarToBytes(BigInteger.valueOf(identifier)))
        h.update(pk)
        h.update(r)
        val e = Frost.bytesToScalar(h.digest())
        return if (e.signum() == 0) BigInteger.ONE else e
    }

    /**
     * A signer's Schnorr proof-of-possession of the verification share derived from `share`, bound to `groupPublicKey`: `{identifier, publicKey, R, s}` (base64url).
     * `nonce` fixes the proof nonce (test vectors only); otherwise it is drawn from `rng` until it reduces to a non-zero scalar. It reveals nothing about the secret.
     */
    @JvmStatic @JvmOverloads
    fun createSignerPoP(identifier: Any?, share: Any?, groupPublicKey: Any?, nonce: ByteArray? = null, rng: Random32 = SECURE_RANDOM32): Map<String, Any?> {
        if (!posSafe(identifier)) throw IllegalArgumentException("createSignerPoP: identifier must be a positive integer")
        if (!key32(share)) throw IllegalArgumentException("createSignerPoP: share must be 32 bytes")
        if (!key32(groupPublicKey)) throw IllegalArgumentException("createSignerPoP: groupPublicKey must be 32 bytes")
        val id = IntentJs.lng(identifier)
        val x = Frost.bytesToScalar(share as ByteArray)
        val pk = mulBase(x).toBytes()
        var k = if (nonce != null) Frost.bytesToScalar(nonce) else BigInteger.ZERO
        while (k.signum() == 0) k = Frost.bytesToScalar(rng.next())
        val r = mulBase(k).toBytes()
        val e = popChallenge(groupPublicKey as ByteArray, id, pk, r)
        val s = Frost.scalarToBytes(k.add(e.multiply(x)).mod(L))
        return linkedMapOf("identifier" to IntentJs.ofLong(id), "publicKey" to Keys.b64u(pk), "R" to Keys.b64u(r), "s" to Keys.b64u(s))
    }

    /** Verify a proof-of-possession: `s*B == R + e*PK` with `R` and `PK` through the strict point rules. Never throws: any malformed input or bad proof is false. */
    @JvmStatic
    fun verifySignerPoP(pop: Any?, groupPublicKey: Any?): Boolean = try {
        if (pop !is Map<*, *>) {
            false
        } else if (!posSafe(pop["identifier"]) || !key32(groupPublicKey)) {
            false
        } else {
            val pk = Pca.decodeB64uStrict(pop["publicKey"], 32)
            val rb = Pca.decodeB64uStrict(pop["R"], 32)
            val sb = Pca.decodeB64uStrict(pop["s"], 32)
            if (pk == null || rb == null || sb == null) {
                false
            } else {
                val pkPt = Frost.decodeSafePoint(pk)
                val rPt = Frost.decodeSafePoint(rb)
                if (!Frost.isCanonicalScalar(sb)) {
                    false // s and s + L must not both verify
                } else {
                    val e = popChallenge(groupPublicKey as ByteArray, IntentJs.lng(pop["identifier"]), pk, rb)
                    mulBase(Frost.bytesToScalar(sb)).sameAs(rPt.add(mulPoint(pkPt, e)))
                }
            }
        }
    } catch (e: RuntimeException) {
        false
    }

    /**
     * The enforced enrollment surface: accept each signer only with a valid proof-of-possession binding its verification share under `groupPublicKey`, and return
     * `[{identifier, publicKey}]` for a coordinator. A missing, mismatched or invalid proof (a rogue key), a duplicate id or a malformed record throws [PoPError].
     * Each enrollment is `{identifier, publicKey (32 bytes), pop}`.
     */
    @JvmStatic
    fun enrollVerificationShares(enrollments: Any?, groupPublicKey: Any?): List<Map<String, Any?>> {
        if (enrollments !is List<*> || enrollments.isEmpty()) throw PoPError("enrollVerificationShares: no signer enrollments")
        if (!key32(groupPublicKey)) throw PoPError("enrollVerificationShares: groupPublicKey must be 32 bytes")
        val out = ArrayList<Map<String, Any?>>()
        val seen = HashSet<Long>()
        for (e in enrollments) {
            val idRaw = get(e, "identifier")
            if (e == null || !posSafe(idRaw)) throw PoPError("enrollVerificationShares: enrollment with invalid identifier")
            val id = IntentJs.lng(idRaw)
            if (!seen.add(id)) throw PoPError("enrollVerificationShares: duplicate enrollment for signer $id", id)
            val pk = get(e, "publicKey")
            if (!key32(pk)) throw PoPError("enrollVerificationShares: signer $id verification share must be 32 bytes", id)
            val pop = get(e, "pop")
            if (pop == null || !ZkJs.truthy(pop) || get(pop, "identifier").let { !(IntentJs.num(it) != null && IntentJs.num(it) == id.toDouble()) } || get(pop, "publicKey") != Keys.b64u(pk as ByteArray)) {
                throw PoPError("enrollVerificationShares: signer $id missing or mismatched proof-of-possession (rogue key rejected)", id)
            }
            if (!verifySignerPoP(pop, groupPublicKey)) throw PoPError("enrollVerificationShares: signer $id invalid proof-of-possession (rogue key rejected)", id)
            out.add(linkedMapOf("identifier" to IntentJs.ofLong(id), "publicKey" to pk))
        }
        return out
    }

    // ---- equivocation ----

    /**
     * Records the FIRST message seen per (session id, round, signer id) and fails closed on any second, DIFFERING message from the same tuple (an identical repeat
     * is idempotent: honest retransmits do not trip it). A coordinator keeps one across sessions.
     */
    class EquivocationGuard {
        private val seen = HashMap<String, String>()

        /** Observe a round message; throws [EquivocationError] on a second, differing message for the tuple. */
        @Synchronized
        fun observe(sessionId: Any?, round: Any?, identifier: Any?, message: Any?) {
            if (sessionId !is String || sessionId.isEmpty()) throw IllegalArgumentException("EquivocationGuard: session_id must be a non-empty string")
            if (!IntentJs.isSafeInteger(round) || IntentJs.num(round)!! < 1) throw IllegalArgumentException("EquivocationGuard: round must be a positive integer")
            if (!posSafe(identifier)) throw IllegalArgumentException("EquivocationGuard: identifier must be a positive integer")
            val r = IntentJs.lng(round)
            val id = IntentJs.lng(identifier)
            val key = "$sessionId\u0000$r\u0000$id"
            val digest = Keys.b64u(sha256(canon(message)))
            val prev = seen[key]
            if (prev == null) {
                seen[key] = digest
                return
            }
            if (prev != digest) throw EquivocationError(sessionId, r, id, prev, digest)
        }

        /** Forget every binding of a session id (bounded-memory housekeeping). */
        @Synchronized
        fun forget(sessionId: String) {
            val prefix = "$sessionId\u0000"
            seen.keys.removeAll { it.startsWith(prefix) }
        }
    }

    // ---- wire decoding ----

    private fun encodeCommitment(c: Frost.FrostCommitment): Map<String, Any?> =
        linkedMapOf("identifier" to IntentJs.ofLong(c.identifier), "hiding" to Keys.b64u(c.hiding), "binding" to Keys.b64u(c.binding))

    /** Strict decode of one wire commitment `{identifier, hiding, binding}`: total, a typed error for anything malformed. */
    @JvmStatic
    fun decodeCommitment(w: Any?): Frost.FrostCommitment {
        if (w !is Map<*, *>) throw IllegalArgumentException("bad commitment")
        val hiding = Pca.decodeB64uStrict(w["hiding"], 32)
        val binding = Pca.decodeB64uStrict(w["binding"], 32)
        if (!posSafe(w["identifier"])) throw IllegalArgumentException("bad commitment identifier")
        if (hiding == null || binding == null) throw IllegalArgumentException("bad commitment point encoding")
        return Frost.FrostCommitment(IntentJs.lng(w["identifier"]), hiding, binding)
    }

    /** Strict decode of a list of wire commitments, bounded by [MAX_FROST_SIGNING_SET]. */
    @JvmStatic
    fun decodeCommitments(list: Any?): List<Frost.FrostCommitment> {
        if (list !is List<*>) throw IllegalArgumentException("commitments must be a list")
        if (list.size > MAX_FROST_SIGNING_SET) throw IllegalArgumentException("commitments list exceeds the maximum signing set")
        return list.map { decodeCommitment(it) }
    }

    /** Strict decode of the signing set's public verification shares `[{identifier, publicKey}]`, bounded by [MAX_FROST_SIGNING_SET]. */
    @JvmStatic
    fun decodeVerificationShares(list: Any?): List<Frost.VerificationShare> {
        if (list !is List<*>) throw IllegalArgumentException("verification_shares must be a list")
        if (list.size > MAX_FROST_SIGNING_SET) throw IllegalArgumentException("verification_shares list exceeds the maximum signing set")
        return list.map { v ->
            if (v !is Map<*, *>) throw IllegalArgumentException("bad verification share")
            val pk = Pca.decodeB64uStrict(v["publicKey"], 32)
            if (!posSafe(v["identifier"])) throw IllegalArgumentException("bad verification-share identifier")
            if (pk == null) throw IllegalArgumentException("bad verification-share key encoding")
            Frost.VerificationShare(IntentJs.lng(v["identifier"]), pk)
        }
    }

    // ---- the guardian signer service ----

    private class Session(val nonces: Frost.FrostNonces, val commitment: Frost.FrostCommitment, val createdAt: Double)

    /**
     * A single-share FROST signer: one instance is one trust domain. Per session it keeps ONLY its own secret nonces and releases a signature share in round 2 iff it
     * has live round-1 state for the session, the request names its group key and the allow token verifies independently against its configured authority key and
     * binds to the exact message. A refusal keeps the nonces (an honest retry with a valid token still works); a success consumes them one-shot. With a
     * [NonceStore] a restarted signer resumes live sessions, a session is marked spent BEFORE its share is computed (a refusal after that point burns the session)
     * and any store failure is a refusal.
     *
     * `sessionTtlMs` is the stale-session guard: a round-1 session completed later than that is dropped and refused. `now` is the clock (default: the wall clock).
     */
    class GuardianSignerService(
        identifier: Any?, share: Any?, groupPublicKey: Any?, threshold: Any?, policyAuthorityPublicKey: Any?, sessionTtlMs: Any? = null,
        private val now: () -> Double = { System.currentTimeMillis().toDouble() }, private val nonceStore: NonceStore? = null, private val rng: Random32 = SECURE_RANDOM32,
    ) {
        val identifier: Long
        val verificationShare: ByteArray
        private val share: ByteArray
        private val groupPublicKey: ByteArray
        private val threshold: Int
        private val policyAuthorityPublicKey: ByteArray
        private val sessionTtlMs: Double?
        private val sessions = HashMap<String, Session>()
        private val spent = HashSet<String>()
        private val pop: Map<String, Any?>

        init {
            if (!posSafe(identifier)) throw IllegalArgumentException("GuardianSignerService: identifier must be a positive integer")
            if (!key32(share)) throw IllegalArgumentException("GuardianSignerService: share must be 32 bytes")
            if (!key32(groupPublicKey)) throw IllegalArgumentException("GuardianSignerService: groupPublicKey must be 32 bytes")
            if (!IntentJs.isSafeInteger(threshold) || IntentJs.num(threshold)!! < 1) throw IllegalArgumentException("GuardianSignerService: threshold must be a positive integer")
            if (!key32(policyAuthorityPublicKey)) throw IllegalArgumentException("GuardianSignerService: policyAuthorityPublicKey must be 32 bytes")
            if (sessionTtlMs != null && (!IntentJs.isFinite(sessionTtlMs) || IntentJs.num(sessionTtlMs)!! <= 0)) throw IllegalArgumentException("GuardianSignerService: sessionTtlMs must be a positive finite number")
            this.identifier = IntentJs.lng(identifier)
            this.share = (share as ByteArray).clone()
            this.groupPublicKey = (groupPublicKey as ByteArray).clone()
            this.threshold = IntentJs.lng(threshold).toInt()
            this.policyAuthorityPublicKey = (policyAuthorityPublicKey as ByteArray).clone()
            this.sessionTtlMs = sessionTtlMs?.let { IntentJs.num(it) }
            this.verificationShare = Frost.verifyingShare(this.share)
            this.pop = createSignerPoP(IntentJs.ofLong(this.identifier), this.share, this.groupPublicKey, null, rng)
        }

        /** This signer's proof-of-possession of its verification share (safe to publish). */
        val proofOfPossession: Map<String, Any?> get() = pop

        /** A ready-to-enroll record `{identifier, publicKey, pop}` for [enrollVerificationShares]. */
        fun enrollment(): Map<String, Any?> = linkedMapOf("identifier" to IntentJs.ofLong(identifier), "publicKey" to verificationShare.clone(), "pop" to pop)

        private fun r1fail(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "identifier" to IntentJs.ofLong(identifier), "reason" to reason)

        /** Round 1: commit to a fresh nonce pair for `req.session_id` and keep the SECRET nonces locally. */
        @Synchronized
        fun round1(req: Any?): Map<String, Any?> {
            try {
                val sid = get(req, "session_id")
                if (req == null || get(req, "typ") != "pca.frost.round1.v1" || sid !is String || sid.isEmpty()) return r1fail("malformed round-1 request")
                if (spent.contains(sid) || nonceStore?.isSpent(sid) == true) return r1fail("session already signed")
                if (sessions.containsKey(sid) || nonceStore?.load(sid) != null) return r1fail("duplicate round-1 for session") // never overwrite live nonces
                val c = Frost.commit(Frost.FrostParticipantShare(identifier, share, verificationShare), rng.next(), rng.next())
                val createdAt = now()
                // durable BEFORE the commitment leaves this process: a crash then can only lose the session, never reuse a nonce
                nonceStore?.create(sid, NonceRecord(c.hidingNonce, c.bindingNonce, c.commitment.hiding, c.commitment.binding, createdAt))
                sessions[sid] = Session(Frost.FrostNonces(c.hidingNonce, c.bindingNonce), c.commitment, createdAt)
                return linkedMapOf("ok" to true, "identifier" to IntentJs.ofLong(identifier), "commitment" to encodeCommitment(c.commitment), "pop" to pop)
            } catch (e: RuntimeException) {
                return r1fail(e.message ?: "round-1 error")
            }
        }

        private fun refuse(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "identifier" to IntentJs.ofLong(identifier), "refused" to true, "reason" to reason)

        /** Round 2: release a signature share iff the allow token verifies and the session has live round-1 state. */
        @Synchronized
        fun round2(req: Any?): Map<String, Any?> {
            try {
                val sid = get(req, "session_id")
                if (req == null || get(req, "typ") != "pca.frost.round2.v1" || sid !is String) return refuse("malformed round-2 request")
                if (spent.contains(sid) || nonceStore?.isSpent(sid) == true) return refuse("session already signed (one-shot)")
                var state = sessions[sid]
                if (state == null && nonceStore != null) {
                    val rec = nonceStore.load(sid) // restart recovery: resume a live session from the durable store
                    if (rec != null) {
                        state = Session(Frost.FrostNonces(rec.hiding, rec.binding), Frost.FrostCommitment(identifier, rec.hidingCommitment, rec.bindingCommitment), rec.createdAt)
                        sessions[sid] = state
                    }
                }
                if (state == null) return refuse("no round-1 state for this session")
                // stale-session guard: a session not completed within its window is dropped, not signed
                val age = now() - state.createdAt
                if (sessionTtlMs != null && !(age.isFinite() && age <= sessionTtlMs)) {
                    sessions.remove(sid)
                    nonceStore?.drop(sid)
                    return refuse("session expired (stale-session guard: round-1 older than ${sessionTtlMs.toLong()}ms)")
                }
                val message = Pca.decodeB64uStrict(get(req, "message"), -1) ?: return refuse("message not canonical base64url")
                if (get(req, "group_pk") != Keys.b64u(groupPublicKey)) return refuse("request names a different group key")
                // independent policy authorization: the heart of coordinator-compromise resistance
                val allow = verifyAllowToken(
                    get(req, "allow"),
                    linkedMapOf("policyAuthorityPublicKey" to policyAuthorityPublicKey, "groupPublicKey" to groupPublicKey, "message" to message, "now" to now()),
                )
                if (allow["ok"] != true) return refuse("policy authorization failed: ${allow["reason"]}")
                val commitments = decodeCommitments(get(req, "commitments") ?: emptyList<Any?>())
                if (commitments.size < threshold) return refuse("signing set below threshold t=$threshold")
                val own = commitments.firstOrNull { it.identifier == identifier } ?: return refuse("our commitment is not in the signing set")
                // equivocation defense: the commitment put in the set for OUR id must byte-match the one emitted in round 1 for this session
                if (!own.hiding.contentEquals(state.commitment.hiding) || !own.binding.contentEquals(state.commitment.binding)) {
                    return refuse("equivocation detected: our commitment in the signing set differs from our round-1 commitment")
                }
                val verificationShares = decodeVerificationShares(get(req, "verification_shares"))
                // the spent marker first (durable), then sign: a crash or refusal after this line burns the session, never reuses it
                nonceStore?.spend(sid)
                val o = Frost.FrostSignOpts()
                o.threshold = threshold
                o.verificationShare = verificationShare
                o.verificationShares = verificationShares
                val sigShare = Frost.sign(identifier, share, groupPublicKey, state.nonces, message, commitments, o)
                sessions.remove(sid)
                spent.add(sid)
                return linkedMapOf("ok" to true, "identifier" to IntentJs.ofLong(identifier), "sig_share" to Keys.b64u(sigShare.sigShare))
            } catch (e: RuntimeException) {
                return refuse(e.message ?: "round-2 error") // a crypto-level failure is also a refusal
            }
        }
    }

    /** In-process transport: a separate service object with its own isolated session state, reached only through calls. The coordinator holds this handle, not the share. */
    @JvmStatic
    fun inProcessTransport(service: GuardianSignerService): SignerTransport = object : SignerTransport {
        override val identifier: Long = service.identifier
        override fun round1(req: Map<String, Any?>): Map<String, Any?> = service.round1(req)
        override fun round2(req: Map<String, Any?>): Map<String, Any?> = service.round2(req)
    }

    // ---- the coordinator ----

    /** The result of a signing session: the aggregate Ed25519 signature (it verifies under the group key), the session id and the signers that contributed a share. */
    class NetworkSignResult(val signature: ByteArray, val sessionId: String, val signers: List<Long>)

    /**
     * The network coordinator: it holds NO signing share, and cannot forge the allow token, so it cannot make honest signers release without a genuine
     * authorization. Given a message and an allow token it runs round 1 to collect at least t commitments (each with a valid proof-of-possession of the recorded
     * verification share), forms the signing set, runs round 2 and aggregates with the FROST primitives (which verify every share and the aggregate). `enroll`
     * (proof-bearing enrollments, verified at construction: a rogue key throws) or `verificationShares` supply the public verification shares.
     */
    class NetworkCoordinator(
        groupPublicKey: Any?, threshold: Any?, signers: List<SignerTransport>, verificationShares: List<Map<String, Any?>>? = null, enroll: Any? = null, enrollPresent: Boolean = false,
        private val newSessionId: () -> String = { Keys.b64u(SECURE_RANDOM32.next()) }, timeoutMs: Any? = null,
    ) {
        private val groupPublicKey: ByteArray
        private val threshold: Int
        private val signers: List<SignerTransport> = ArrayList(signers)
        private val verificationShares: List<Frost.VerificationShare>
        private val pkById: Map<Long, String>
        private val equivocation = EquivocationGuard()
        private val timeoutMs: Double?

        init {
            if (!key32(groupPublicKey)) throw IllegalArgumentException("NetworkCoordinator: groupPublicKey must be 32 bytes")
            if (!IntentJs.isSafeInteger(threshold) || IntentJs.num(threshold)!! < 1) throw IllegalArgumentException("NetworkCoordinator: threshold must be a positive integer")
            if (timeoutMs != null && (!IntentJs.isFinite(timeoutMs) || IntentJs.num(timeoutMs)!! <= 0)) throw IllegalArgumentException("NetworkCoordinator: timeoutMs must be a positive finite number")
            this.groupPublicKey = groupPublicKey as ByteArray
            this.threshold = IntentJs.lng(threshold).toInt()
            val vs = if (enrollPresent) enrollVerificationShares(enroll, groupPublicKey) else verificationShares ?: throw IllegalArgumentException("NetworkCoordinator: provide verificationShares or enroll")
            this.verificationShares = vs.map { Frost.VerificationShare(IntentJs.lng(it["identifier"]), it["publicKey"] as ByteArray) }
            this.pkById = this.verificationShares.associate { it.identifier to Keys.b64u(it.publicKey) }
            this.timeoutMs = timeoutMs?.let { IntentJs.num(it) }
        }

        /**
         * Drive one t-of-n signing session. `signerIds` picks the signers (default: the first t). Returns the aggregate signature or throws [CoordinatorError] with the
         * per-signer refusals, or [CoordinatorTimeoutError] when the bounded round deadline (`timeoutMs`, default the constructor's) elapses.
         */
        @JvmOverloads
        fun sign(message: Any?, allow: Any?, signerIds: List<Long>? = null, timeoutMs: Double? = null): NetworkSignResult {
            val windowMs = timeoutMs ?: this.timeoutMs
            if (windowMs == null || windowMs.isNaN() || windowMs.isInfinite() || windowMs <= 0) return drive(message, allow, signerIds)
            val run = CompletableFuture.supplyAsync { drive(message, allow, signerIds) }
            try {
                return run.get(windowMs.toLong(), TimeUnit.MILLISECONDS)
            } catch (e: TimeoutException) {
                run.cancel(true)
                throw CoordinatorTimeoutError("coordinator: signing session did not reach threshold within ${windowMs.toLong()}ms", windowMs)
            } catch (e: ExecutionException) {
                throw (e.cause as? RuntimeException) ?: IllegalStateException(e.cause?.message ?: "session error")
            }
        }

        private fun drive(messageAny: Any?, allow: Any?, signerIds: List<Long>?): NetworkSignResult {
            val message = messageAny as? ByteArray ?: throw IllegalArgumentException("coordinator.sign: message must be bytes")
            val chosen = if (signerIds != null) signers.filter { it.identifier in signerIds } else signers.take(threshold)
            if (chosen.size < threshold) throw CoordinatorError("coordinator: only ${chosen.size} signer(s) selected, need t=$threshold")
            val sessionId = newSessionId()

            // Round 1: collect commitments.
            val refusals = ArrayList<Pair<Long, String>>()
            val committed = ArrayList<Pair<SignerTransport, Map<String, Any?>>>()
            val r1 = chosen.map { s ->
                try {
                    Pair(s, s.round1(linkedMapOf("typ" to "pca.frost.round1.v1", "session_id" to sessionId)))
                } catch (e: RuntimeException) {
                    Pair(s, linkedMapOf<String, Any?>("ok" to false, "identifier" to IntentJs.ofLong(s.identifier), "reason" to (e.message ?: "unreachable")))
                }
            }
            for ((s, resp) in r1) {
                val rid = IntentJs.lng(resp["identifier"])
                if (resp["ok"] != true) {
                    refusals.add(Pair(rid, ZkJs.string(resp["reason"])))
                    continue
                }
                // rogue-key defense: the signer must prove possession of the verification share on record
                val expectedPk = pkById[rid]
                if (expectedPk == null) {
                    refusals.add(Pair(rid, "no verification share on record for this signer"))
                    continue
                }
                val pop = resp["pop"]
                if (pop == null || !numEq(get(pop, "identifier"), rid) || get(pop, "publicKey") != expectedPk || !verifySignerPoP(pop, groupPublicKey)) {
                    refusals.add(Pair(rid, "invalid or missing proof-of-possession (rogue-key defense)"))
                    continue
                }
                // equivocation defense: a signer cannot bind this (session, round 1) to two different commitments
                try {
                    // an absent commitment is undefined, which the observer's strict canonicalizer refuses
                    if (!resp.containsKey("commitment")) throw IllegalArgumentException("canonicalize: unsupported type undefined")
                    equivocation.observe(sessionId, IntentJs.ofLong(1), IntentJs.ofLong(rid), resp["commitment"])
                } catch (e: EquivocationError) {
                    refusals.add(Pair(rid, e.message!!))
                    continue
                } catch (e: RuntimeException) {
                    refusals.add(Pair(rid, "equivocation check failed"))
                    continue
                }
                committed.add(Pair(s, resp["commitment"] as Map<String, Any?>))
            }
            if (committed.size < threshold) throw CoordinatorError("coordinator: round 1 produced ${committed.size} commitment(s), need t=$threshold", refusals)
            // exactly t committed signers are the signing set (the verification shares must match this set)
            val set = committed.take(threshold)
            val commitments = set.map { it.second }
            val setIds = set.map { IntentJs.lng(it.second["identifier"]) }.toSet()
            val vsWire = verificationShares.filter { it.identifier in setIds }.map { linkedMapOf<String, Any?>("identifier" to IntentJs.ofLong(it.identifier), "publicKey" to Keys.b64u(it.publicKey)) }
            if (vsWire.size != set.size) throw CoordinatorError("coordinator: missing a verification share for a signer in the set")

            // Round 2: collect signature shares.
            val r2 = set.map { (transport, _) ->
                val req = linkedMapOf<String, Any?>(
                    "typ" to "pca.frost.round2.v1", "session_id" to sessionId, "message" to Keys.b64u(message), "group_pk" to Keys.b64u(groupPublicKey),
                    "commitments" to commitments, "verification_shares" to vsWire, "allow" to allow,
                )
                try {
                    transport.round2(req)
                } catch (e: RuntimeException) {
                    linkedMapOf<String, Any?>("ok" to false, "identifier" to IntentJs.ofLong(transport.identifier), "refused" to true, "reason" to (e.message ?: "unreachable"))
                }
            }
            val sigShares = ArrayList<Frost.FrostSignatureShare>()
            for (resp in r2) {
                val rid = IntentJs.lng(resp["identifier"])
                if (resp["ok"] != true) {
                    refusals.add(Pair(rid, ZkJs.string(resp["reason"])))
                    continue
                }
                try {
                    if (!resp.containsKey("sig_share")) throw IllegalArgumentException("canonicalize: unsupported type undefined") // {sig_share: undefined}
                    equivocation.observe(sessionId, IntentJs.ofLong(2), IntentJs.ofLong(rid), linkedMapOf("sig_share" to resp["sig_share"]))
                } catch (e: EquivocationError) {
                    refusals.add(Pair(rid, e.message!!))
                    continue
                } catch (e: RuntimeException) {
                    refusals.add(Pair(rid, "equivocation check failed"))
                    continue
                }
                val sb = Pca.decodeB64uStrict(resp["sig_share"], 32)
                if (sb == null) refusals.add(Pair(rid, "malformed signature share")) else sigShares.add(Frost.FrostSignatureShare(rid, sb))
            }
            if (sigShares.size < threshold) throw CoordinatorError("coordinator: round 2 produced ${sigShares.size} share(s), need t=$threshold", refusals)

            // aggregate with the FROST primitive (it re-verifies and refuses an invalid aggregate)
            val aggCommitments = commitments.map { decodeCommitment(it) }
            val signature = Frost.aggregate(message, aggCommitments, sigShares, groupPublicKey, threshold, verificationShares.filter { it.identifier in setIds })
            return NetworkSignResult(signature, sessionId, set.map { IntentJs.lng(it.second["identifier"]) })
        }

        private fun numEq(x: Any?, id: Long): Boolean = IntentJs.num(x) != null && IntentJs.num(x) == id.toDouble()
    }
}
