package net.atlasauth.pca.invariants

import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the invariant harness's deterministic building blocks. */
@Suppress("UNCHECKED_CAST")
class InvariantsDiffTest {
    private val m = "ref-invariants"

    private fun map(o: Any?) = o as Map<String, Any?>

    /** {"$bytes": b64u} members become ByteArray (the JSON args of a case carry bytes that way). */
    private fun rev(v: Any?): Any? = when {
        v is List<*> -> v.map { rev(it) }
        v is Map<*, *> && v.size == 1 && v["\$bytes"] is String -> Keys.unb64u(v["\$bytes"] as String)
        v is Map<*, *> -> LinkedHashMap<String, Any?>().also { o -> for ((k, x) in v) o[k as String] = rev(x) }
        else -> v
    }

    @Test fun keyPairFromSeed() = OracleCases.each(m, "keyPairFromSeed") { a -> Invariants.keyPairFromSeed(rev(a[0]) as ByteArray?).toMap() }
    @Test fun buildChain() = OracleCases.each(m, "buildChain") { a -> Invariants.buildChain(map(rev(a[0]))) }
    @Test fun worsen() = OracleCases.each(m, "worsen") { a -> Invariants.worsen(map(a[0]), map(a[1])) }

    @Test fun consts() = OracleCases.each(m, "consts") {
        linkedMapOf<String, Any?>("DEFAULT_SEED" to Invariants.DEFAULT_SEED, "DEFAULT_NUM_RUNS" to Invariants.DEFAULT_NUM_RUNS, "INVARIANT_NAMES" to Invariants.INVARIANT_NAMES)
    }
}
