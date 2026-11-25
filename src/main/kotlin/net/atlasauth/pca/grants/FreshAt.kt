package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.K3Sig
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.FreshAt as FreshAtVerify

/**
 * Consistency tokens for the operational plane. Verification (verify, digest, check, decide, validateWire) is [FreshAtVerify]; signing is
 * [Issue.signFreshAt]. This object adds the validating signer, the state fold, the gate and the issuer.
 */
object FreshAt {
    private val NUMERIC = listOf("revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision")

    /** The JavaScript number value of a JSON number; a non-number is refused (the reference would compute NaN and sign nothing). */
    private fun dbl(s: Map<String, Any?>, k: String): Double {
        val v = s[k]
        if (v is Json.Num) return v.raw.toDoubleOrNull() ?: throw IllegalArgumentException("fresh_at state: $k is not a number")
        if (v is Number) return v.toDouble()
        throw IllegalArgumentException("fresh_at state: $k is not a number")
    }

    /** Whichever of the two values is larger (the first when equal), keeping the value's own representation. */
    private fun max(a: Map<String, Any?>, b: Map<String, Any?>, k: String): Any? = if (dbl(b, k) > dbl(a, k)) b[k] else a[k]

    /** Sign a token for [state]; throws on a malformed state (the reference's RangeError). */
    @JvmStatic
    fun signFreshAt(secret: Keys.EdKey, scope: String, state: Map<String, Any?>, issuedAt: Long): Map<String, Any?> {
        var ok = K3Sig.isStr(scope, 256) && K3Sig.isStr(state["policy_digest"], 128) && issuedAt >= 0
        for (k in NUMERIC) ok = ok && K3Sig.isSafeInt(state[k])
        require(ok) { "signFreshAt: a malformed state" }
        return Issue.signFreshAt(secret, scope, state, issuedAt)
    }

    /** Field-wise maximum of two states (the client-side fold); equal revisions with different digests keep a's digest. */
    @JvmStatic
    fun mergeFreshAt(a: Map<String, Any?>, b: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for (k in NUMERIC) m[k] = max(a, b, k)
        m["policy_digest"] = if (dbl(b, "policy_revision") > dbl(a, "policy_revision")) b["policy_digest"] else a["policy_digest"]
        return m
    }

    /** Compose a freshness verdict into a decision: it can only tighten (allow to escalate/deny), never loosen. */
    @JvmStatic
    fun gateDecision(decision: String, v: FreshAtVerify.Verdict): String = when {
        decision == "deny" || v.decision == "deny" -> "deny"
        v.decision == "escalate" -> "escalate"
        else -> decision
    }

    /** Verifier-side state holder: advance on every write, mint the token for the write, check incoming tokens. */
    class Issuer(private val secret: Keys.EdKey, val scope: String, initial: Map<String, Any?>) {
        private var state: Map<String, Any?> = LinkedHashMap(initial)

        @Synchronized
        fun current(): Map<String, Any?> = LinkedHashMap(state)

        /** Apply a write (any subset of counters; each only moves forward) and return its token. */
        @Synchronized
        fun advance(patch: Map<String, Any?>, now: Long): Map<String, Any?> {
            val next = LinkedHashMap<String, Any?>(state)
            next.putAll(patch)
            state = mergeFreshAt(state, next)
            return signFreshAt(secret, scope, state, now)
        }

        @Synchronized
        fun check(token: Any?, now: Long, maxTokenAgeMs: Long? = null): FreshAtVerify.Verdict {
            val signer = GrantSigning.signerOf(secret)
            // the token's own signature is judged first (as the reference), so a bad token reads bad_token whatever the held state is
            val local = FreshAtVerify.State.fromJson(state)
                ?: return FreshAtVerify.Verdict("deny", if (FreshAtVerify.verify(token, signer)) "bad_state" else "bad_token")
            return FreshAtVerify.check(token, local, signer, scope, now, maxTokenAgeMs)
        }
    }
}
