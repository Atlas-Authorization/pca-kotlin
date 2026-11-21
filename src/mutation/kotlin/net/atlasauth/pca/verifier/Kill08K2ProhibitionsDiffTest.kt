package net.atlasauth.pca.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for the prohibition engine (packages/pca/src/prohibitions.ts): test-data/k05-prohibitions.json.gz
 * from tools/pca-audit/k05-oracles/prohibitions-oracle.mts (constitution / state validation, the monitor grids around every boundary,
 * advance, evidence, signed evidence, check-and-advance). Results compare as lenient canonical JSON (the reference's `{ok, reason}`
 * verdicts are rebuilt from the native's `String?`); a reference throw ({$throws}) requires a throw. Cases named `x:` hold a value the
 * canonical hash refuses (-0, |n| > 2^53-1, lone surrogates) and replay in [exoticCases].
 */
@Suppress("UNCHECKED_CAST")
class Kill08K2ProhibitionsDiffTest {
    companion object {
        const val FILE = "k05-prohibitions.json.gz"

        private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
        private fun seed(s: Any?): ByteArray = Pca.decodeB64uStrict(s, -1) ?: throw IllegalArgumentException("bad seed")
        private fun verdict(why: String?): Any? = if (why == null) Prohibitions.map("ok", true) else Prohibitions.map("ok", false, "reason", why)

        val IMPL: Map<String, (List<Any?>) -> Any?> = mapOf(
            "validateInvariant" to { a -> Prohibitions.validateInvariant(a[0]) },
            "validateConstitution" to { a -> Prohibitions.validateConstitution(a[0]) },
            "stateProblem" to { a -> Prohibitions.stateProblem(a[0]) },
            "canonicalState" to { a -> Prohibitions.canonicalState(a[0]) },
            "stateDigest" to { a -> Prohibitions.stateDigest(a[0]) },
            "tickState" to { a -> Prohibitions.tickState(a[0], a[1]) },
            "emptyState" to { a -> Prohibitions.emptyState(a[0]) },
            "checkProhibitions" to { a -> Prohibitions.checkProhibitions(a[0], a[1], a[2]) },
            "advanceStateStrict" to { a -> if (a.size > 3) Prohibitions.advanceStateStrict(a[0], a[1], a[2], a[3]) else Prohibitions.advanceStateStrict(a[0], a[1], a[2]) },
            "proveSafety" to { a -> Prohibitions.proveSafety(a[0], a[1], a[2]) },
            "verifySafetyEvidence" to { a -> verdict(Prohibitions.verifySafetyEvidence(a[0], a[1], a[2], a[3])) },
            "safetyBindingId" to { a -> Prohibitions.safetyBindingId(m(a[0]), a[1] as String) },
            "signSafetyEvidence" to { a -> Prohibitions.signSafetyEvidence(a[0], seed(a[1]), a[2] as String?) },
            "verifySignedSafetyEvidence" to { a -> verdict(Prohibitions.verifySignedSafetyEvidence(a[0], a[1])) },
            "checkAndAdvance" to { a ->
                val o = a.getOrNull(4) as Map<String, Any?>?
                val dg = o?.get("expectedStateDigest") as String?
                if (o != null && o.containsKey("expectedSeq")) Prohibitions.checkAndAdvance(a[0] as Boolean, a[1], a[2], a[3], o["expectedSeq"], dg)
                else Prohibitions.checkAndAdvance(a[0] as Boolean, a[1], a[2], a[3], Prohibitions.ABSENT, dg)
            },
            "verifyConstitution" to { a -> verdict(Prohibitions.verifyConstitution(a[0], a.getOrNull(1) as String?)) },
            "constitutionId" to { a -> Prohibitions.constitutionId(m(a[0])) },
            "whenAffirmative" to { a -> Prohibitions.whenAffirmative(a[0], m(a[1])) },
        )

        private fun isThrow(o: Any?) = o is Map<*, *> && o.containsKey("\$throws")
        private fun show(o: Any?): String = if (isThrow(o)) "THROWS" else Json.canonicalize(o)

        fun cases(fn: String, exotic: Boolean): List<Map<String, Any?>> =
            K05Oracle.cases(FILE, fn).filter { (it["name"] as String).startsWith("$fn/x:") == exotic }

        /** Replays every case of [fn]; the divergences, one per case. */
        fun diverge(fn: String, exotic: Boolean): Pair<Int, List<String>> {
            val f = IMPL[fn] ?: throw IllegalStateException("no binding for $fn")
            val bad = ArrayList<String>()
            var ran = 0
            for (c in cases(fn, exotic)) {
                ran++
                val want = show(c["out"])
                val got = try { Json.canonicalize(f(c["args"] as List<Any?>)) } catch (t: Throwable) { "THROWS" }
                if (want != got) bad.add("${c["name"]}\n  want: ${want.take(400)}\n  got:  ${got.take(400)}")
            }
            return ran to bad
        }

        fun check(fn: String) {
            val (ran, bad) = diverge(fn, false)
            assertTrue("$fn: no cases", ran > 0)
            assertTrue("$fn: ${bad.size} of $ran divergent case(s):\n" + bad.take(25).joinToString("\n"), bad.isEmpty())
        }
    }

    @Test fun oracleCoversEveryBinding() {
        val fns = K05Oracle.fns(FILE)
        assertTrue("fns in the oracle without a binding: ${fns - IMPL.keys}", IMPL.keys.containsAll(fns))
        assertFalse("bindings without cases: ${IMPL.keys - fns}", fns.containsAll(IMPL.keys).not())
    }

    @Test fun validateInvariant() = check("validateInvariant")
    @Test fun validateConstitution() = check("validateConstitution")
    @Test fun stateProblem() = check("stateProblem")
    @Test fun canonicalState() = check("canonicalState")
    @Test fun stateDigest() = check("stateDigest")
    @Test fun tickState() = check("tickState")
    @Test fun emptyState() = check("emptyState")
    @Test fun checkProhibitions() = check("checkProhibitions")
    @Test fun advanceStateStrict() = check("advanceStateStrict")
    @Test fun proveSafety() = check("proveSafety")
    @Test fun verifySafetyEvidence() = check("verifySafetyEvidence")
    @Test fun safetyBindingId() = check("safetyBindingId")
    @Test fun signSafetyEvidence() = check("signSafetyEvidence")
    @Test fun verifySignedSafetyEvidence() = check("verifySignedSafetyEvidence")
    @Test fun checkAndAdvance() = check("checkAndAdvance")
    @Test fun verifyConstitution() = check("verifyConstitution")
    @Test fun constitutionId() = check("constitutionId")
    @Test fun whenAffirmative() = check("whenAffirmative")

    /** Inputs the canonical hash refuses (-0, huge integers, lone surrogates): every fn, replayed together. */
    @Test fun exoticCases() {
        val bad = ArrayList<String>()
        var ran = 0
        for (fn in IMPL.keys) {
            val (n, b) = diverge(fn, true)
            ran += n
            bad.addAll(b)
        }
        assertTrue("no exotic cases", ran > 0)
        assertTrue("${bad.size} of $ran divergent exotic case(s):\n" + bad.take(25).joinToString("\n"), bad.isEmpty())
    }
}
