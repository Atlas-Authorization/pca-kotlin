package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pins reasons / rejection messages / canonical forms over the whole corpus (see [ReasonSnapshot]) and checks the adversarial set. */
class SnapshotTest {
    companion object {
        const val CHUNKS = 16
        val core: Map<String, Any?> by lazy { ReasonSnapshot.loadJson("vectors.json") }
        val adv: Map<String, Any?> by lazy { ReasonSnapshot.loadJson("vectors-adversarial.json.gz") }
        val skipSuites = setOf("ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s")
    }

    /** Runs the body on a thread with a large stack so deep-nesting inputs behave identically under any JVM stack setting. */
    private fun big(body: () -> Unit) {
        var err: Throwable? = null
        val t = Thread(null, { try { body() } catch (e: Throwable) { err = e } }, "big", 1L shl 29)
        t.start(); t.join()
        err?.let { throw it }
    }

    private fun check(computed: Map<String, String>) {
        val exp = ReasonSnapshot.load()
        for ((k, v) in computed) {
            val want = exp[ReasonSnapshot.esc(k)] ?: continue
            assertEquals(k, want, v)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun runAdv(k: Int) {
        val vs = adv["vectors"] as List<Any?>
        var i = k
        while (i < vs.size) {
            val v = vs[i] as Map<String, Any?>
            i += CHUNKS
            val pco = v["pcactn"] as? Map<String, Any?>
            val algs = ArrayList<String>()
            (pco?.get("alg") as? String)?.let { algs.add(it) }
            (pco?.get("cap_chain") as? List<Any?>)?.forEach { h -> ((h as? Map<String, Any?>)?.get("alg") as? String)?.let { algs.add(it) } }
            if (algs.any { it in skipSuites }) continue
            val g = ReasonSnapshot.verify(v)
            val exp = v["expect"] as Map<String, Any?>
            assertEquals(v["name"].toString(), exp["allow"], g.allow)
            val want = exp["checks"] as Map<String, Any?>
            assertEquals(v["name"].toString(), want.keys, g.checks.keys)
            for ((ck, wv) in want) assertEquals(v["name"].toString() + ":" + ck, wv, g.checks[ck])
        }
        check(ReasonSnapshot.compute(adv, "adv", k, CHUNKS))
    }

    @Test fun coreVectors() = big { check(ReasonSnapshot.compute(core, "core", 0, 1)) }

    @Test fun advPrimitives() = big {
        @Suppress("UNCHECKED_CAST") val prim = adv["primitives"] as Map<String, Any?>
        @Suppress("UNCHECKED_CAST") for (x in prim["b64u"] as List<Any?>) {
            val b = x as Map<String, Any?>
            val len = if (b.containsKey("len")) Json.asLong(b["len"]).toInt() else -1
            assertEquals(b["input"].toString(), b["valid"], Pca.decodeB64uStrict(b["input"], len) != null)
        }
        @Suppress("UNCHECKED_CAST") for (x in prim["json_parse"] as List<Any?>) {
            val j = x as Map<String, Any?>
            val inp = j["input"] as String
            var accepted = true
            var canon: String? = null
            try { canon = Json.canonicalizeStrict(Json.parse(inp)) } catch (e: RuntimeException) { accepted = false } catch (e: StackOverflowError) { accepted = false }
            assertEquals(inp, j["accept"], accepted)
            if (accepted && j.containsKey("canonical")) assertEquals(inp, j["canonical"], canon)
        }
        @Suppress("UNCHECKED_CAST") for (x in prim["canonical"] as List<Any?>) {
            val c = x as Map<String, Any?>
            assertEquals(c["expect"], Json.canonicalizeStrict(c["value"]))
            assertEquals(c["hash"], Pca.hashStrict(c["value"]))
        }
    }

    @Test fun conformanceRunner() = big { assertEquals(0, runConformance("conformance/", "../../tools/pca-diff-fuzz/counterexamples/")) }
    @Test fun a00() = big { runAdv(0) }
    @Test fun a01() = big { runAdv(1) }
    @Test fun a02() = big { runAdv(2) }
    @Test fun a03() = big { runAdv(3) }
    @Test fun a04() = big { runAdv(4) }
    @Test fun a05() = big { runAdv(5) }
    @Test fun a06() = big { runAdv(6) }
    @Test fun a07() = big { runAdv(7) }
    @Test fun a08() = big { runAdv(8) }
    @Test fun a09() = big { runAdv(9) }
    @Test fun a10() = big { runAdv(10) }
    @Test fun a11() = big { runAdv(11) }
    @Test fun a12() = big { runAdv(12) }
    @Test fun a13() = big { runAdv(13) }
    @Test fun a14() = big { runAdv(14) }
    @Test fun a15() = big { runAdv(15) }
    @Test fun i00() = big { check(ReasonSnapshot.computeInputs(0, CHUNKS)) }
    @Test fun i01() = big { check(ReasonSnapshot.computeInputs(1, CHUNKS)) }
    @Test fun i02() = big { check(ReasonSnapshot.computeInputs(2, CHUNKS)) }
    @Test fun i03() = big { check(ReasonSnapshot.computeInputs(3, CHUNKS)) }
    @Test fun i04() = big { check(ReasonSnapshot.computeInputs(4, CHUNKS)) }
    @Test fun i05() = big { check(ReasonSnapshot.computeInputs(5, CHUNKS)) }
    @Test fun i06() = big { check(ReasonSnapshot.computeInputs(6, CHUNKS)) }
    @Test fun i07() = big { check(ReasonSnapshot.computeInputs(7, CHUNKS)) }
    @Test fun i08() = big { check(ReasonSnapshot.computeInputs(8, CHUNKS)) }
    @Test fun i09() = big { check(ReasonSnapshot.computeInputs(9, CHUNKS)) }
    @Test fun i10() = big { check(ReasonSnapshot.computeInputs(10, CHUNKS)) }
    @Test fun i11() = big { check(ReasonSnapshot.computeInputs(11, CHUNKS)) }
    @Test fun i12() = big { check(ReasonSnapshot.computeInputs(12, CHUNKS)) }
    @Test fun i13() = big { check(ReasonSnapshot.computeInputs(13, CHUNKS)) }
    @Test fun i14() = big { check(ReasonSnapshot.computeInputs(14, CHUNKS)) }
    @Test fun i15() = big { check(ReasonSnapshot.computeInputs(15, CHUNKS)) }
}
