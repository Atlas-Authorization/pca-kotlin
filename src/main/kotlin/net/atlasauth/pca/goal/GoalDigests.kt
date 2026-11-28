package net.atlasauth.pca.goal

import java.util.TreeSet
import net.atlasauth.pca.verifier.Pca

/** The content digests of the goal-to-decision flow (strict canonical JSON: safe integers only; a float or cycle throws). */
object GoalDigests {
    /** Digest of the whole signed Goal. */
    @JvmStatic
    fun goalDigest(goal: Any?): String = Pca.hashCanonical(G.map("d" to "atlas-pca/goal-ir/v1", "goal" to goal))

    /** Digest of the instruction text a goal was interpreted from. */
    @JvmStatic
    fun nlDigest(instruction: String): String = Pca.hashCanonical(G.map("d" to "atlas-pca/goal-nl/v1", "text" to instruction))

    /** Digest of the model set: sorted (code-unit order), de-duplicated ids. */
    @JvmStatic
    fun modelSetDigest(models: List<String>): String =
        Pca.hashCanonical(G.map("d" to "atlas-pca/goal-model-set/v1", "models" to ArrayList<Any?>(TreeSet(models))))

    /** Digest of an approval's covered fields (the digests it pins plus its expiry). */
    @JvmStatic
    fun approvalDigest(body: Map<String, Any?>): String = Pca.hashCanonical(G.map("d" to "atlas-pca/goal-approval-body/v1", "body" to body))
}
