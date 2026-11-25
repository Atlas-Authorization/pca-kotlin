package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json

import java.security.MessageDigest
import net.atlasauth.pca.verifier.Keys

/**
 * The pure parts of the typed compiler front door. The compiler itself (typecheck, compile, the proved decision functions) is
 * [GoalKernel]; this object holds the policy canonical form and digest and the tape codec entry points.
 */
object GoalCompiler {
    /** Canonical bytes of a policy (sorted-key JSON, no floats): the input of the policy digest. */
    @JvmStatic
    fun canonicalPolicy(p: Map<String, Any?>): String = G.stable(p)

    @JvmStatic
    fun policyDigest(p: Map<String, Any?>): String = Keys.b64u(MessageDigest.getInstance("SHA-256").digest(Json.utf8(canonicalPolicy(p))))

    /** The goal as a token tape: the kernel's rendering ([GoalKernel.renderTape]); `decodeGoal(renderTape(g))` equals g. */
    @JvmStatic
    fun renderTape(goal: Map<String, Any?>): List<Any?> = GoalKernel.renderTape(goal)
}
