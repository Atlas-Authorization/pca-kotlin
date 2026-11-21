package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json

import java.security.MessageDigest
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaDecision

/** The decision-to-effect binding and the claimed-fidelity gate of goal-to-decision. */
object GoalBinding {
    /** Digest of exactly the action that was decided: verb, resource and every parameter. */
    @JvmStatic
    fun actionDigest(act: Map<String, Any?>): String = Pca.hashCanonical(G.map("d" to "atlas-pca/goal-action/v1", "act" to act))

    /** Bind a decision to the action it was made for: {decision, action_digest}. */
    @JvmStatic
    fun bindDecision(act: Map<String, Any?>, decision: String): Map<String, Any?> = G.map("decision" to decision, "action_digest" to actionDigest(act))

    private fun ctEq(x: String, y: String): Boolean = MessageDigest.isEqual(Json.utf8(x), Json.utf8(y))

    /** Run guard: true only for an `allow` bound to exactly this action. Total. */
    @JvmStatic
    fun guardExecute(bound: Map<String, Any?>?, executed: Map<String, Any?>): Boolean {
        try {
            if (bound == null) return false // reading a member of null throws inside the reference's try: false
            if ("allow" != bound["decision"]) return false
            val d = bound["action_digest"]
            return d is String && ctEq(d, actionDigest(executed))
        } catch (e: RuntimeException) {
            return false
        }
    }

    /**
     * An agent-claimed fidelity never moves the outcome; only a replayed fidelity below the minimum can, and only downward.
     * [replayedPpm] null = not replayed; a NaN replay is unconfirmed and tightens.
     */
    @JvmStatic
    fun claimGate(base: String, minPpm: Double, replayedPpm: Double?): String =
        if (replayedPpm != null && !(replayedPpm >= minPpm)) PcaDecision.tighten(base, "escalate") else base

    /** Hiding goal commitment (goal binding v3). */
    @JvmStatic
    fun goalCommit(goalDigest: String, policyDigest: String, salt: String): String {
        val h = MessageDigest.getInstance("SHA-256").digest(Json.utf8(("pca-goal:v3:commit:$goalDigest:$policyDigest:$salt")))
        return Keys.b64u(h)
    }

    /** Constant-time check that [commit] opens to (goal, policy, salt). */
    @JvmStatic
    fun openCommit(commit: String, goalDigest: String, policyDigest: String, salt: String): Boolean = ctEq(commit, goalCommit(goalDigest, policyDigest, salt))
}
