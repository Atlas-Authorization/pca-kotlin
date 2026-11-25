package net.atlasauth.pca.rotate

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.revoke.RevocationRegistry
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.BaseOracle
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the key-rotation and subtree re-issue package. */
@Suppress("UNCHECKED_CAST")
class RotateDiffTest {
    private val m = "ref-rotate"

    private fun map(o: Any?) = o as Map<String, Any?>

    private fun key(seed: Any?): Keys.EdKey? = (seed as String?)?.let { Keys.edFromSeed(Keys.unb64u(it)) }

    /** The reference wrapper's `now`: absent is null; present but not a finite number is NaN (refused). */
    private fun now(o: Map<String, Any?>): Double? = if (!o.containsKey("now")) null else Js.num(o["now"]) ?: Double.NaN

    private fun reason(o: Map<String, Any?>) = o["reason"] as String?

    /** The frozen clock the corpus generator ran under (its header's clockMs). */
    private val REGEN_NOW = BaseOracle.clockMs("$m.json.gz")

    /** An entry whose revokedAt is within two minutes of the wall clock (live, or the regeneration's) prints as "<now>" (the reference does the same). */
    private fun norm(v: Any?): Any? = when (v) {
        is List<*> -> v.map { norm(it) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { o ->
            for ((k, x) in v) {
                val d = Js.num(x)
                o[k as String] = if (k == "revokedAt" && d != null && (Math.abs(d - System.currentTimeMillis()) < 120_000 || Math.abs(d - REGEN_NOW) < 120_000)) "<now>" else norm(x)
            }
        }
        else -> v
    }

    private fun result(r: Rotate.RotationResult) = norm(linkedMapOf("chain" to ArrayList<Any?>(r.chain), "revocation" to r.revocation.toMap()))

    @Test fun rotateAgentKey() = OracleCases.each(m, "rotateAgentKey") { a ->
        val op = map(a[1])
        result(Rotate.rotateAgentKey(a[0], key(op["oldSeed"]), key(op["newSeed"]), reason(op), now(op)))
    }

    @Test fun rotatePrincipalKey() = OracleCases.each(m, "rotatePrincipalKey") { a ->
        val o = map(a[0])
        val hs = (o["holderSeeds"] as List<*>?)?.map { key(it) }
        result(Rotate.rotatePrincipalKey(o["chain"], o["oldRoot"], key(o["oldSeed"]), key(o["newSeed"]), hs, reason(o), now(o)))
    }

    @Test fun revokeAndReissueSubtree() = OracleCases.each(m, "revokeAndReissueSubtree") { a ->
        val op = map(a[2])
        result(Rotate.revokeAndReissueSubtree(a[0], a[1] as? String, key(op["newSeed"]), key(op["ancestorSeed"]), reason(op), now(op)))
    }

    @Test fun compromisedKeyFlow() = OracleCases.each(m, "compromisedKeyFlow") { a ->
        val op = map(a[2])
        val f = Rotate.compromisedKeyFlow(a[0], a[1] as? String, key(op["newSeed"]), key(op["ancestorSeed"]), reason(op), now(op))
        norm(linkedMapOf("revocations" to f.revocations.map { it.toMap() }, "reissued" to ArrayList<Any?>(f.reissued)))
    }

    @Test fun applyRotation() = OracleCases.each(m, "applyRotationScenario") { a ->
        val spec = map(a[0])
        val reg = RevocationRegistry()
        (spec["pre"] as List<*>?)?.forEach { id ->
            reg.revoke(linkedMapOf("kind" to "cap", "value" to id, "reason" to "pre", "revokedAt" to Json.Num(BaseOracle.T0.toString())))
        }
        val failAt = Js.num(spec["failAt"])
        val failUnrevoke = spec["failUnrevoke"] == true
        var calls = 0
        val sink = object : RevocationSink {
            override fun revoke(input: Map<String, Any?>) {
                calls++
                if (failAt != null && failAt == calls.toDouble()) throw IllegalStateException("sink down")
                reg.revoke(input)
            }
            override fun unrevoke(key: Map<String, Any?>): Boolean {
                if (failUnrevoke) throw IllegalStateException("unrevoke down")
                return reg.unrevoke(key)
            }
            override fun lookup(kind: String, value: String): Any? = reg.lookup(kind, value)
        }
        val res: Any? = try {
            Rotate.applyRotation(sink, spec["records"], spec["reissued"])
        } catch (e: RuntimeException) {
            linkedMapOf("\$err" to true)
        }
        linkedMapOf("result" to res, "list" to norm(reg.list().map { it.toMap() }))
    }
}
