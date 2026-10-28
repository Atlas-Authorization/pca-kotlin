package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Goal binding v3 (`approved_goal`): replays `goal-commit-vectors.json` (`commit`, `invalid`, `binding`) and pins the exact
 * outcomes the vectors cannot (reason text of a misconfiguration, floors, v1/v2 retained).
 */
@Suppress("UNCHECKED_CAST")
class GoalCommitV3Test {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("goal-commit-vectors.json") }
    private val g = "B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw"
    private val p = "9U7dBfYHPTNYZ84mWFHOiddEAPc7IEQ1AMEVp13dqSo"

    private fun grant(commit: Any?): Map<String, Any?> =
        if (commit is String) linkedMapOf("caveats" to listOf(linkedMapOf<String, Any?>("type" to "envelope", "goal_commit" to commit)))
        else linkedMapOf("caveats" to emptyList<Any?>())

    private fun refOf(v: Map<String, Any?>) = Pca.ApprovedGoal(v["goal_digest"] as String, v["policy_digest"] as String)

    private fun decide(intent: Any?, grant: Map<String, Any?>, policy: Pca.IntentPolicy?, session: String? = null): String? =
        Pca.decideIntent(intent, intent != null, grant, policy, session)

    @Test
    fun corpusSizesArePinned() {
        assertEquals(7, (doc["commit"] as List<*>).size)
        assertEquals(4, (doc["invalid"] as List<*>).size)
        assertEquals(16, (doc["binding"] as List<*>).size)
    }

    @Test
    fun commitVectors() {
        for (v in doc["commit"] as List<Map<String, Any?>>) {
            assertEquals(v["name"].toString(), v["goal"], Pca.intentGoalV3(refOf(v)))
            assertEquals(v["name"].toString(), v["commit"], Pca.intentGoalCommitV3(refOf(v), v["salt"] as String))
        }
    }

    @Test
    fun invalidDigestsAreRefused() {
        for (v in doc["invalid"] as List<Map<String, Any?>>) {
            val name = v["name"].toString()
            assertFalse(name, refOf(v).isWellFormed)
            try { Pca.intentGoalV3(refOf(v)); fail("$name: intentGoalV3 must refuse") } catch (e: IllegalArgumentException) { assertNotNull(e.message) }
            try { Pca.intentGoalCommitV3(refOf(v), "s"); fail("$name: intentGoalCommitV3 must refuse") } catch (e: IllegalArgumentException) { assertNotNull(e.message) }
        }
    }

    @Test
    fun bindingVectors() {
        for (v in doc["binding"] as List<Map<String, Any?>>) {
            val r = decide(v["intent"], grant(v["grant_commit"]), Pca.IntentPolicy.fromJson(v["policy"]), v["session"] as String?)
            assertEquals("${v["name"]}: $r", v["expect"], if (r == "") "pass" else "fail")
        }
    }

    @Test
    fun exactOutcomes() {
        val ref = Pca.ApprovedGoal(g, p)
        val intent = ParityVectors.obj("""{"ref":"$g","map_digest":"$p","goal_salt":"s","fidelity_ppm":1,"residual_risk_ppm":0}""")
        val v3 = Pca.intentGoalCommitV3(ref, "s")
        val v1 = Pca.intentGoalCommit(g, p, "s")
        val pol = Pca.IntentPolicy(approvedGoal = ref)
        assertTrue(pol.isActive) // approved_goal alone activates the check
        assertEquals("", decide(intent, grant(v3), pol))
        assertNotEmpty(decide(intent, grant(v1), pol)) // a v1 grant under a v3 policy
        assertNotEmpty(decide(intent, grant(v3), Pca.IntentPolicy(require = true))) // a v3 grant under a v1 verifier
        assertEquals("this verifier requires an intent binding but the PCActn carries none", decide(null, grant(v3), pol))
        assertEquals("the root grant carries no envelope goal commitment to bind the intent to", decide(intent, grant(null), pol))
        assertEquals(
            "the root grant's goal commitment does not open to the approved goal and compiled policy (v3)",
            decide(intent, grant(v1), pol),
        )
        for (bad in listOf("""{"goal_digest":"$g"}""", """{"goal_digest":"$g","policy_digest":"$p","x":1}""", """{"goal_digest":"$g","policy_digest":""}""", "null")) {
            val policy = Pca.IntentPolicy.fromJson(ParityVectors.obj("""{"approved_goal":$bad}"""))
            assertEquals(
                bad, "intent policy misconfigured: approved_goal digests must be canonical base64url (32 bytes) (fail closed)",
                decide(intent, grant(v3), policy),
            )
        }
        // the floors still apply under a v3 policy
        assertNotEmpty(decide(intent, grant(v3), Pca.IntentPolicy(minFidelityPpm = 2.0, approvedGoal = ref)))
        assertEquals("", decide(intent, grant(v3), Pca.IntentPolicy(minFidelityPpm = 1.0, approvedGoal = ref)))
    }

    private fun assertNotEmpty(r: String?) {
        assertTrue("expected a refusal, got $r", r != null && r.isNotEmpty())
    }
}
