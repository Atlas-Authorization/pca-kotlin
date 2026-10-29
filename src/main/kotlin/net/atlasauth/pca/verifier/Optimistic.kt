package net.atlasauth.pca.verifier

/**
 * Optimistic-path verification (extension layer; packages/pca/src/optimistic.ts, bond-settlement.ts): bonded claims, the challenge
 * window, fraud proofs (wire level) and guardian-signed settlement records. Inputs are parsed JSON values; nothing here throws on
 * hostile input.
 *
 * A fraud proof is only convincing because the settlement layer RE-RUNS the Policy VM on its server-held open-time snapshot;
 * [fraudProofWireCheck] does not do that (no native SDK evaluates the Policy VM decision). It checks that the proof is well formed,
 * names this claim and bond, and carries the decision its kind requires.
 */
object Optimistic {
    const val CLAIM_DOMAIN = "atlas-pca/optimistic/v1\u0000"
    const val SETTLEMENT_DOMAIN = "atlas-pca/bond-settlement/v1\u0000"
    private const val IRREVERSIBLE = "irreversible"
    private const val DEFAULT_R_MARGIN = 1e-9

    /** Bounds a claim's `issued_at` skew and window length (milliseconds). */
    class ChallengeWindowPolicy(val minWindowMs: Double, val maxWindowMs: Double, val maxSkewMs: Double)

    /** The library default (1 s minimum, 24 h maximum, 5 s skew). */
    val DEFAULT_POLICY = ChallengeWindowPolicy(1000.0, 86_400_000.0, 5000.0)

    @Suppress("UNCHECKED_CAST")
    private fun map(v: Any?): Map<String, Any?>? = v as? Map<String, Any?>

    private fun finite(v: Any?): Double? = IntentJs.num(v)?.takeIf { !it.isNaN() && !it.isInfinite() }

    /** A JSON object (and, like JavaScript, an array) as an object; anything else is not. */
    private fun obj(v: Any?): Map<String, Any?>? = when (v) {
        is Map<*, *> -> map(v)
        is List<*> -> emptyMap()
        else -> null
    }

    /** `sig` over `domain || lenientCanonical(body)`: Pair(valid, canonicalizable). */
    private fun signedLenient(pub: String, domain: String, body: Map<String, Any?>, sig: Any?): Pair<Boolean, Boolean> {
        val c = try { Json.canonicalize(body) } catch (e: IllegalArgumentException) { return Pair(false, false) }
        val s = sig as? String
        return Pair(s != null && Pca.verifyB64u(pub, (domain + c).toByteArray(Charsets.UTF_8), s), true)
    }

    /**
     * The FIRST check a bonded claim fails, or `ok`: malformed, irreversible, digest, claimed_r, window, signature. The claim must
     * cover `expectedPcactnDigest`, be signed by `signerPublic`, and its window must sit within the policy of `serverNow`.
     */
    @JvmStatic
    fun claimCheck(claim: Any?, expectedPcactnDigest: String, signerPublic: String, serverNow: Double, p: ChallengeWindowPolicy = DEFAULT_POLICY): String {
        val c = obj(claim) ?: return "malformed"
        if (c["reversibility_class"] == IRREVERSIBLE) return "irreversible"
        val d = c["pcactn_digest"] as? String
        if (d == null || d != expectedPcactnDigest) return "digest"
        if (finite(c["claimed_r"]) == null) return "claimed_r"
        val issued = finite(c["issued_at"])
        val window = finite(c["challenge_window_ms"])
        if (issued == null || window == null || serverNow.isNaN() || serverNow.isInfinite() ||
            Math.abs(issued - serverNow) > p.maxSkewMs || window < p.minWindowMs || window > p.maxWindowMs
        ) return "window"
        val body = LinkedHashMap<String, Any?>()
        for ((k, v) in c) if (k != "sig") body[k] = v
        val (good, canon) = signedLenient(signerPublic, CLAIM_DOMAIN, body, c["sig"])
        if (!canon) return "malformed"
        if (!good) return "signature"
        return "ok"
    }

    /** The last instant (epoch ms) at which a challenge is accepted: `issued_at + window`. */
    @JvmStatic
    fun challengeWindowEnd(issuedAt: Double, windowMs: Double): Double = issuedAt + windowMs

    /** True while challenges are accepted: `now <= issued_at + window` (inclusive end). */
    @JvmStatic
    fun withinChallengeWindow(issuedAt: Double, windowMs: Double, now: Double): Boolean =
        !now.isNaN() && !now.isInfinite() && now <= challengeWindowEnd(issuedAt, windowMs)

    /** `open` while challenges are accepted, else `finalized`. */
    @JvmStatic
    fun claimStatus(issuedAt: Double, windowMs: Double, now: Double): String = if (withinChallengeWindow(issuedAt, windowMs, now)) "open" else "finalized"

    /** JavaScript `===` between two JSON members (numbers by value, otherwise by canonical form; both absent equal). */
    private fun memberEq(m1: Map<String, Any?>, m2: Map<String, Any?>, k: String): Boolean {
        val h1 = m1.containsKey(k)
        val h2 = m2.containsKey(k)
        if (h1 != h2) return false
        if (!h1) return true
        val a = m1[k]
        val b = m2[k]
        val x = IntentJs.num(a)
        if (x != null) {
            val y = IntentJs.num(b)
            return y != null && x == y
        }
        return Ledger.same(a, b)
    }

    /**
     * The first wire-level check a fraud proof fails against the claim it names, or `ok`: malformed, digest, bond, claimed_r, kind,
     * consistency.
     */
    @JvmStatic
    fun fraudProofWireCheck(claim: Any?, proof: Any?): String {
        val c = map(claim)
        val p = map(proof)
        if (c == null || p == null) return "malformed"
        val d = map(p["decision"]) ?: return "malformed"
        val rel = d["releaseGuardianShare"] as? Boolean
        val opt = d["optimisticAllowed"] as? Boolean
        val r = finite(d["r"])
        if (rel == null || opt == null || r == null || p["pcactn_digest"] !is String || p["bond_ref"] !is String || p["reason"] !is String) return "malformed"
        if (!memberEq(p, c, "pcactn_digest")) return "digest"
        if (!memberEq(p, c, "bond_ref")) return "bond"
        if (!memberEq(p, c, "claimed_r")) return "claimed_r"
        val kind = p["kind"] as? String ?: ""
        var margin = DEFAULT_R_MARGIN
        val m = finite(p["r_margin"])
        if (m != null) margin = Math.max(0.0, m)
        val holds: Boolean = when (kind) {
            "irreversible" -> {
                val ev = map(map(map(p["evidence"])?.get("action"))?.get("action"))?.get("reversibility_class") as? String ?: ""
                (c["reversibility_class"] as? String ?: "") == IRREVERSIBLE || ev == IRREVERSIBLE
            }
            "policy-denied" -> !rel
            "optimistic-not-allowed" -> rel && !opt
            "risk-understated" -> {
                val cr = finite(c["claimed_r"])
                cr != null && rel && opt && r > cr + margin
            }
            else -> return "kind"
        }
        return if (holds) "ok" else "consistency"
    }

    private fun nonEmpty(v: Any?): Boolean = v is String && v.isNotEmpty()

    private fun nonNeg(v: Any?): Double? = finite(v)?.takeIf { it >= 0 }

    /**
     * The first check a settlement record fails, or `ok`: malformed, suite, shape, split, signature. The record's guardian signature
     * is checked last, over the lenient canonical body without `sig` / `pq_sig`.
     */
    @JvmStatic
    fun settlementWireCheck(record: Any?, guardianPublic: String, pins: Map<String, Any?>? = null): String {
        val r = map(record) ?: return "malformed"
        if (Pq.resolveSigAlg(r["alg"], r.containsKey("alg")) == null) return "suite"
        val action = r["action"] as? String ?: ""
        val slash = action == "slash"
        val amount = finite(r["amount"])
        val hasSplit = r.containsKey("split")
        val ev = r["evidenceDigest"] as? String
        val atOk = finite(r["at"]) != null
        val sigOk = r["sig"] is String
        var epochOk = true
        if (r.containsKey("guardian_epoch")) {
            val e = r["guardian_epoch"]
            val f = IntentJs.num(e)
            epochOk = f != null && IntentJs.isSafeInteger(e) && f >= 0
        }
        if (!nonEmpty(r["claimId"]) || !(action == "open" || action == "release" || slash) ||
            amount == null || amount <= 0 || !nonEmpty(r["from"]) || !nonEmpty(r["to"]) || !atOk || ev == null ||
            (slash && ev == "") || (!slash && ev != "") ||
            (slash && map(r["split"]) == null) || (!slash && hasSplit) || !sigOk || !epochOk
        ) return "shape"
        if (slash) {
            val sp = map(r["split"])!!
            val sa = IntentJs.num(sp["amount"])
            val cr = nonNeg(sp["challengerReward"])
            val vc = nonNeg(sp["victimCompensation"])
            val tr = nonNeg(sp["treasuryRemainder"])
            val to = r["to"] as? String
            val ta = sp["treasuryAccount"] as? String
            var conserved = sa != null && sa == amount && cr != null && vc != null && tr != null && (cr + vc) + tr == amount &&
                nonEmpty(sp["victimAccount"]) && ta != null && ta == to
            if (conserved) {
                if (sp["challengerAccount"] == null) {
                    conserved = sp.containsKey("challengerAccount") && cr == 0.0 && vc == 0.0 && tr == amount
                } else {
                    conserved = nonEmpty(sp["challengerAccount"])
                }
            }
            if (!conserved) return "split"
        }
        val body = LinkedHashMap<String, Any?>()
        for ((k, v) in r) if (k != "sig" && k != "pq_sig") body[k] = v
        // The signed body keeps alg / pq_pk and drops both signatures; the message is the LENIENT canonical form (as signRecord).
        val algPresent = r.containsKey("alg")
        val msg = try {
            (SETTLEMENT_DOMAIN + Json.canonicalize(body)).toByteArray(Charsets.UTF_8)
        } catch (e: IllegalArgumentException) { return "malformed" }
        if (!IntentJs.verifyPinnedSuite(r["alg"], algPresent, guardianPublic, r["pq_pk"], msg, r["sig"], r["pq_sig"], pins)) return "signature"
        return "ok"
    }
}
