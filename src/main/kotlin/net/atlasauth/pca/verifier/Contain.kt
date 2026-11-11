package net.atlasauth.pca.verifier

/**
 * Host-callback containment: every callback a host supplies (revocation, grant resolution, context, store claim, hooks) that throws
 * anything but a fatal JVM error is a denial, never an escape. OutOfMemoryError, ThreadDeath and the like are never swallowed.
 */
internal object Contain {
    fun ok(t: Throwable): Boolean = t is Exception || t is LinkageError || t is AssertionError || t is StackOverflowError
}
