package net.atlasauth.pca.verifier

/**
 * Consistency tokens (`fresh_at`; packages/pca/src/fresh-at.ts): a signed high-water mark of verifier-side state. A verifier refuses to
 * DECIDE against state older than the token it was handed (`stale_state` is an escalate-class failure, never an allow). The token is a
 * PCActn MEMBER (`fresh_at`, signed by the leaf signature) read by the verifier's `fresh_at` check ([decide]); a token that travelled beside
 * the PCActn (a header) is still read for one release through [Policy.sideCarried]. Verification only: tokens are minted by the server.
 * Everything here is total: malformed input is the failure value, never an exception.
 */
object FreshAt {
    const val DOMAIN = "atlas-pca/fresh-at/v1\u0000"
    const val REF_DOMAIN = "atlas-pca/fresh-at-ref/v1"

    private val NUMERIC = listOf("revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision")

    /** Closed key set of the member (an unknown key is unsigned malleability inside a signed member). */
    private val KEYS = setOf(
        "v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer", "sig",
    )

    /** The verifier's own state counters. */
    class State(val revocationEpoch: Long, val ledgerTreeSize: Long, val budgetVersion: Long, val policyRevision: Long, val policyDigest: String) {
        internal fun counter(k: String): Long = when (k) {
            "revocation_epoch" -> revocationEpoch
            "ledger_tree_size" -> ledgerTreeSize
            "budget_version" -> budgetVersion
            else -> policyRevision
        }

        companion object {
            /** `{revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest}` or null when malformed. */
            @JvmStatic
            fun fromJson(o: Any?): State? {
                val m = K3Sig.map(o) ?: return null
                for (k in NUMERIC) if (!K3Sig.isSafeInt(m[k])) return null
                val d = m["policy_digest"] as? String ?: return null
                return State(IntentJs.lng(m["revocation_epoch"]), IntentJs.lng(m["ledger_tree_size"]), IntentJs.lng(m["budget_version"]), IntentJs.lng(m["policy_revision"]), d)
            }
        }
    }

    /** `decision` is `ok`, `escalate` (code `stale_state`, [behind] names the lagging counters) or `deny` (the other codes). */
    class Verdict(val decision: String, val code: String? = null, val behind: List<String> = emptyList()) {
        /** The vector form: `{decision}`, `{decision, code, behind}` (escalate) or `{decision, code}` (deny). */
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["decision"] = decision
            if (code != null) m["code"] = code
            if (decision == "escalate") m["behind"] = behind
            return m
        }
    }

    /** Verifier-side configuration of the `fresh_at` check. */
    class Policy(
        /** The pinned token signer (base64url Ed25519 public key). */
        val signer: String,
        /** The scope this verifier decides for; a token for another scope is refused. */
        val scope: String,
        /** The verifier's OWN current state counters. */
        val local: State,
        val maxTokenAgeMs: Long? = null,
        /** Every PCActn must carry (or have side-carried) a token; none is `escalate: a consistency token is required`. */
        val require: Boolean = false,
        /** True when a side-carried token was presented (even a null one, which is `bad_token`); read only when the PCActn has no member. */
        val hasSideCarried: Boolean = false,
        val sideCarried: Any? = null,
    ) {
        companion object {
            /** The conformance-vector form `{signer, scope, local, max_token_age_ms?, require?, side_carried?}` or null when malformed. */
            @JvmStatic
            fun fromJson(o: Any?): Policy? {
                val m = K3Sig.map(o) ?: return null
                val signer = m["signer"] as? String ?: return null
                val scope = m["scope"] as? String ?: return null
                val local = State.fromJson(m["local"]) ?: return null
                val age = if (m.containsKey("max_token_age_ms")) {
                    if (!IntentJs.isSafeInteger(m["max_token_age_ms"])) return null
                    IntentJs.lng(m["max_token_age_ms"])
                } else null
                return Policy(signer, scope, local, age, m["require"] == true, m.containsKey("side_carried"), m["side_carried"])
            }
        }
    }

    enum class Status { NONE, PASS, FAIL }

    /** `NONE`: nothing to report (no `fresh_at` entry in the checks). */
    class Check(val status: Status, val reason: String = "")

    /** Well formed and signed by `signer` over exactly its content. Never throws. */
    @JvmStatic
    fun verify(t: Any?, signer: String): Boolean {
        val m = K3Sig.map(t) ?: return false
        if (IntentJs.num(m["v"]) != 1.0 || m["signer"] != signer || !K3Sig.isStr(m["scope"], 256) || !K3Sig.isStr(m["policy_digest"], 128) || !K3Sig.isSafeInt(m["issued_at"])) return false
        for (k in NUMERIC) if (!K3Sig.isSafeInt(m[k])) return false
        val body = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer")) body[k] = m[k]
        return K3Sig.verifyBody(DOMAIN, body, signer, m["sig"])
    }

    /** The content address a PCActn or request signs to bind the token it carried; throws only for an out-of-profile value. */
    @JvmStatic
    fun digest(token: Any?): String = K3Sig.digestOf("d" to REF_DOMAIN, "t" to token)

    /**
     * May the verifier decide against `local` for `token`? Order (each fails closed): signature/shape -> scope -> issued in the future
     * (> 60 s skew) -> token age -> policy fork (same revision, different digest) -> any counter behind the token => escalate `stale_state`.
     */
    @JvmStatic
    fun check(token: Any?, local: State, signer: String, scope: String, now: Long, maxTokenAgeMs: Long? = null): Verdict {
        if (!verify(token, signer)) return Verdict("deny", "bad_token")
        val t = K3Sig.map(token)!!
        if (t["scope"] != scope) return Verdict("deny", "wrong_scope")
        val issued = IntentJs.lng(t["issued_at"])
        if (!(issued <= now + 60_000L)) return Verdict("deny", "token_from_the_future")
        if (maxTokenAgeMs != null && !(now - issued <= maxTokenAgeMs)) return Verdict("deny", "token_too_old")
        if (IntentJs.lng(t["policy_revision"]) == local.policyRevision && t["policy_digest"] != local.policyDigest) return Verdict("deny", "policy_fork")
        val behind = NUMERIC.filter { !(local.counter(it) >= IntentJs.lng(t[it])) }
        return if (behind.isEmpty()) Verdict("ok") else Verdict("escalate", "stale_state", behind)
    }

    /** Wire shape of the member. Returns the problem or null. Does NOT check the signature (that is the `fresh_at` check). */
    @JvmStatic
    fun validateWire(v: Any?): String? {
        val m = K3Sig.map(v) ?: return "'fresh_at' must be an object"
        for (k in m.keys) if (k !in KEYS) return "'fresh_at' has an unknown field '$k'"
        if (IntentJs.num(m["v"]) != 1.0) return "'fresh_at.v' must be 1"
        if (!K3Sig.isStr(m["scope"], 256) || !K3Sig.isStr(m["policy_digest"], 128)) return "'fresh_at' scope and policy_digest must be non-empty strings"
        for (k in NUMERIC + "issued_at") if (!K3Sig.isSafeInt(m[k])) return "'fresh_at.$k' must be a non-negative safe integer"
        if (Pca.decodeB64uStrict(m["signer"], 32) == null) return "'fresh_at.signer' is not canonical base64url (32 bytes)"
        if (Pca.decodeB64uStrict(m["sig"], 64) == null) return "'fresh_at.sig' is not canonical base64url (64 bytes)"
        return null
    }

    /**
     * The verifier's `fresh_at` check. Reported (PASS/FAIL) only when the PCActn carries the member (`hasMember`), a side-carried token is
     * read, or the policy requires one; otherwise NONE (byte-identical to before). A stale verifier is an ESCALATE-class failure
     * (`escalate: stale_state ...`); anything else is a hard failure.
     */
    @JvmStatic
    fun decide(member: Any?, hasMember: Boolean, policy: Policy?, now: Long): Check {
        if (policy == null) {
            return if (hasMember) Check(Status.FAIL, "the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)") else Check(Status.NONE)
        }
        val has = hasMember || policy.hasSideCarried
        if (!has) {
            return if (policy.require) Check(Status.FAIL, "escalate: a consistency token is required (refresh and retry with the token of your latest write)") else Check(Status.NONE)
        }
        val token = if (hasMember) member else policy.sideCarried
        val v = try {
            check(token, policy.local, policy.signer, policy.scope, now, policy.maxTokenAgeMs)
        } catch (e: RuntimeException) {
            Verdict("deny", "bad_token")
        }
        return when (v.decision) {
            "ok" -> Check(Status.PASS)
            "escalate" -> Check(Status.FAIL, "escalate: stale_state (verifier state is behind the token on ${v.behind.joinToString(", ")})")
            else -> Check(Status.FAIL, v.code ?: "bad_token")
        }
    }
}
