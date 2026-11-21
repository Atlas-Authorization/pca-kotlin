package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.pub
import net.atlasauth.pca.verifier.IntentTestKit.sign
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mutation kills for [Optimistic] (packages/pca/src/optimistic.ts, bond-settlement.ts): every claim check in order with its
 * boundaries (skew, window bounds, non-finite clocks), every fraud-proof outcome by kind, and the settlement shape / split checks.
 */
class Kill05LeaseOptimisticTest {
    private val K = "k05-opt/signer"
    private val G = "k05-opt/guardian"
    private fun n(s: String) = Json.Num(s)

    private fun lenientSigned(domain: String, m: Map<String, Any?>, key: String): LinkedHashMap<String, Any?> {
        val body = LinkedHashMap<String, Any?>()
        for ((k, v) in m) if (k != "sig" && k != "pq_sig") body[k] = v
        return LinkedHashMap(m).also { it["sig"] = sign(key, (domain + Json.canonicalize(body)).toByteArray(Charsets.UTF_8)) }
    }

    private fun bare(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = jm("pcactn_digest", "D", "bond_ref", "B", "claimed_r", n("0.5"), "issued_at", 1000L, "challenge_window_ms", 5000L, "reversibility_class", "reversible")
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    private fun claim(vararg kv: Any?) = lenientSigned(Optimistic.CLAIM_DOMAIN, bare(*kv), K)

    private fun chk(c: Any?, now: Double = 1000.0, p: Optimistic.ChallengeWindowPolicy = Optimistic.DEFAULT_POLICY) = Optimistic.claimCheck(c, "D", pub(K), now, p)

    @Test fun claimChecksInOrder() {
        assertEquals("ok", chk(claim()))
        assertEquals("ok", Optimistic.claimCheck(claim(), "D", pub(K), 1000.0))
        assertEquals("malformed", chk(null))
        assertEquals("malformed", chk("claim"))
        assertEquals("digest", chk(jl())) // an array reads as an empty object
        assertEquals("irreversible", chk(claim("reversibility_class", "irreversible")))
        assertEquals("digest", chk(claim("pcactn_digest", "E")))
        assertEquals("digest", chk(claim("pcactn_digest", 5L)))
        assertEquals("digest", chk(claim("pcactn_digest", null)))
        assertEquals("claimed_r", chk(claim("claimed_r", "0.5")))
        assertEquals("claimed_r", chk(claim("claimed_r", null)))
        for (bad in listOf("NaN", "Infinity", "-Infinity")) {
            assertEquals(bad, "claimed_r", chk(bare("claimed_r", n(bad))))
            assertEquals(bad, "window", chk(bare("issued_at", n(bad))))
            assertEquals(bad, "window", chk(bare("challenge_window_ms", n(bad))))
        }
        assertEquals("ok", chk(claim("claimed_r", 0L)))
        assertEquals("window", chk(claim("issued_at", null)))
        assertEquals("window", chk(claim("issued_at", "1000")))
        assertEquals("window", chk(claim("challenge_window_ms", null)))
        // skew: 5000 either way is inside, one more is not
        assertEquals("ok", chk(claim(), 6000.0))
        assertEquals("window", chk(claim(), 6001.0))
        assertEquals("ok", chk(claim("issued_at", 6000L), 1000.0))
        assertEquals("window", chk(claim("issued_at", 6001L), 1000.0))
        // window bounds [1 s, 24 h]
        assertEquals("ok", chk(claim("challenge_window_ms", 1000L)))
        assertEquals("window", chk(claim("challenge_window_ms", 999L)))
        assertEquals("ok", chk(claim("challenge_window_ms", 86_400_000L)))
        assertEquals("window", chk(claim("challenge_window_ms", 86_400_001L)))
        // a non-finite server clock is refused even when the policy would let any skew through
        assertEquals("window", chk(claim(), Double.NaN))
        val open = Optimistic.ChallengeWindowPolicy(0.0, Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY)
        assertEquals("ok", chk(claim(), 1.0e15, open))
        assertEquals("window", chk(claim(), Double.NaN, open))
        assertEquals("window", chk(claim(), Double.POSITIVE_INFINITY, open))
        assertEquals("window", chk(claim(), Double.NEGATIVE_INFINITY, open))
        val tight = Optimistic.ChallengeWindowPolicy(2000.0, 3000.0, 10.0)
        assertEquals("window", chk(claim(), 1000.0, tight))
        assertEquals("ok", chk(claim("challenge_window_ms", 2000L), 1010.0, tight))
        assertEquals("window", chk(claim("challenge_window_ms", 2000L), 1011.0, tight))
        assertEquals("ok", chk(claim("challenge_window_ms", 3000L), 990.0, tight))
        assertEquals("window", chk(claim("challenge_window_ms", 3001L), 1000.0, tight))
        // a body the canonical form cannot hold is malformed, before the signature
        assertEquals("malformed", chk(LinkedHashMap(claim()).also { it["x"] = 1.5 }))
        // signature
        assertEquals("signature", chk(LinkedHashMap(claim()).also { it.remove("sig") }))
        assertEquals("signature", chk(LinkedHashMap(claim()).also { it["sig"] = 5L }))
        assertEquals("signature", chk(LinkedHashMap(claim()).also { it["sig"] = claim("bond_ref", "B2")["sig"] }))
        assertEquals("signature", chk(lenientSigned(Optimistic.CLAIM_DOMAIN, bare(), "k05-opt/other")))
        assertEquals("signature", chk(lenientSigned(Optimistic.SETTLEMENT_DOMAIN, bare(), K)))
        assertEquals("ok", chk(LinkedHashMap(claim()).also { it.remove("sig"); it["sig"] = claim()["sig"] }))
    }

    @Test fun challengeWindow() {
        assertEquals(150.0, Optimistic.challengeWindowEnd(100.0, 50.0), 0.0)
        assertTrue(Optimistic.withinChallengeWindow(100.0, 50.0, 150.0))
        assertTrue(Optimistic.withinChallengeWindow(100.0, 50.0, -5.0))
        assertFalse(Optimistic.withinChallengeWindow(100.0, 50.0, 150.5))
        assertFalse(Optimistic.withinChallengeWindow(100.0, 50.0, Double.NaN))
        assertFalse(Optimistic.withinChallengeWindow(100.0, 50.0, Double.NEGATIVE_INFINITY))
        assertFalse(Optimistic.withinChallengeWindow(100.0, 50.0, Double.POSITIVE_INFINITY))
        assertFalse(Optimistic.withinChallengeWindow(Double.POSITIVE_INFINITY, 50.0, Double.POSITIVE_INFINITY))
        assertFalse(Optimistic.withinChallengeWindow(Double.NaN, 50.0, 10.0))
        assertEquals("open", Optimistic.claimStatus(100.0, 50.0, 150.0))
        assertEquals("finalized", Optimistic.claimStatus(100.0, 50.0, 151.0))
        assertEquals("finalized", Optimistic.claimStatus(100.0, 50.0, Double.NEGATIVE_INFINITY))
    }

    private val fc = jm("pcactn_digest", "D", "bond_ref", "B", "claimed_r", n("0.5"), "reversibility_class", "reversible")

    private fun proof(kind: Any?, rel: Any?, opt: Any?, r: Any?, vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = jm("pcactn_digest", "D", "bond_ref", "B", "claimed_r", n("0.5"), "reason", "why", "kind", kind,
            "decision", jm("releaseGuardianShare", rel, "optimisticAllowed", opt, "r", r))
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    private fun fraud(c: Any?, p: Any?) = Optimistic.fraudProofWireCheck(c, p)

    @Test fun fraudProofWire() {
        val ok = proof("policy-denied", false, false, n("0.9"))
        assertEquals("ok", fraud(fc, ok))
        assertEquals("malformed", fraud(null, ok))
        assertEquals("malformed", fraud("c", ok))
        assertEquals("malformed", fraud(fc, null))
        assertEquals("malformed", fraud(fc, jl()))
        assertEquals("malformed", fraud(fc, LinkedHashMap(ok).also { it.remove("decision") }))
        assertEquals("malformed", fraud(fc, LinkedHashMap(ok).also { it["decision"] = jl() }))
        assertEquals("malformed", fraud(fc, proof("policy-denied", "false", false, n("0.9"))))
        assertEquals("malformed", fraud(fc, proof("policy-denied", false, null, n("0.9"))))
        assertEquals("malformed", fraud(fc, proof("policy-denied", false, false, "0.9")))
        assertEquals("malformed", fraud(fc, proof("policy-denied", false, false, null)))
        assertEquals("malformed", fraud(fc, proof("policy-denied", false, false, n("NaN"))))
        assertEquals("malformed", fraud(fc, proof("policy-denied", false, false, n("Infinity"))))
        assertEquals("malformed", fraud(fc, LinkedHashMap(ok).also { it["pcactn_digest"] = 5L }))
        assertEquals("malformed", fraud(fc, LinkedHashMap(ok).also { it.remove("bond_ref") }))
        assertEquals("malformed", fraud(fc, LinkedHashMap(ok).also { it["reason"] = null }))
        // the members the proof names must be the claim's
        assertEquals("digest", fraud(fc, LinkedHashMap(ok).also { it["pcactn_digest"] = "E" }))
        assertEquals("digest", fraud(LinkedHashMap(fc).also { it.remove("pcactn_digest") }, ok))
        assertEquals("bond", fraud(fc, LinkedHashMap(ok).also { it["bond_ref"] = "B2" }))
        assertEquals("bond", fraud(LinkedHashMap(fc).also { it["bond_ref"] = 7L }, ok))
        assertEquals("claimed_r", fraud(fc, LinkedHashMap(ok).also { it["claimed_r"] = n("0.6") }))
        assertEquals("claimed_r", fraud(fc, LinkedHashMap(ok).also { it.remove("claimed_r") }))
        assertEquals("claimed_r", fraud(fc, LinkedHashMap(ok).also { it["claimed_r"] = "0.5" }))
        assertEquals("claimed_r", fraud(LinkedHashMap(fc).also { it["claimed_r"] = "0.5" }, ok))
        assertEquals("ok", fraud(fc, LinkedHashMap(ok).also { it["claimed_r"] = n("0.50") })) // numbers by value
        assertEquals("ok", fraud(LinkedHashMap(fc).also { it.remove("claimed_r") }, LinkedHashMap(ok).also { it.remove("claimed_r") }))
        assertEquals("ok", fraud(LinkedHashMap(fc).also { it["claimed_r"] = "r" }, LinkedHashMap(ok).also { it["claimed_r"] = "r" }))
        // kind
        assertEquals("kind", fraud(fc, proof("bogus", false, false, n("0.9"))))
        assertEquals("kind", fraud(fc, proof(5L, false, false, n("0.9"))))
        assertEquals("kind", fraud(fc, proof(null, false, false, n("0.9"))))
        // policy-denied: the share was withheld
        assertEquals("consistency", fraud(fc, proof("policy-denied", true, false, n("0.9"))))
        // optimistic-not-allowed: released but not optimistically
        assertEquals("ok", fraud(fc, proof("optimistic-not-allowed", true, false, n("0.1"))))
        assertEquals("consistency", fraud(fc, proof("optimistic-not-allowed", true, true, n("0.1"))))
        assertEquals("consistency", fraud(fc, proof("optimistic-not-allowed", false, false, n("0.1"))))
        // risk-understated: r strictly above claimed_r + margin (margin floored at 0, default 1e-9)
        assertEquals("consistency", fraud(fc, proof("risk-understated", true, true, n("0.75"), "r_margin", n("0.25"))))
        assertEquals("ok", fraud(fc, proof("risk-understated", true, true, n("0.76"), "r_margin", n("0.25"))))
        assertEquals("consistency", fraud(fc, proof("risk-understated", true, true, n("0.6"), "r_margin", n("1"))))
        assertEquals("ok", fraud(fc, proof("risk-understated", true, true, n("0.6"), "r_margin", n("-1"))))
        assertEquals("ok", fraud(fc, proof("risk-understated", true, true, n("0.6"), "r_margin", "x")))
        assertEquals("ok", fraud(fc, proof("risk-understated", true, true, n("0.6"))))
        assertEquals("consistency", fraud(fc, proof("risk-understated", true, true, n("0.5"))))
        assertEquals("consistency", fraud(fc, proof("risk-understated", false, true, n("0.9"))))
        assertEquals("consistency", fraud(fc, proof("risk-understated", true, false, n("0.9"))))
        assertEquals("consistency", fraud(LinkedHashMap(fc).also { it.remove("claimed_r") }, LinkedHashMap(proof("risk-understated", true, true, n("0.9"))).also { it.remove("claimed_r") }))
        assertEquals("consistency", fraud(LinkedHashMap(fc).also { it["claimed_r"] = "r" }, proof("risk-understated", true, true, n("0.9"), "claimed_r", "r")))
        // irreversible: by the claim's own class or the evidence's action class
        val irr = proof("irreversible", true, true, n("0.1"))
        assertEquals("consistency", fraud(fc, irr))
        assertEquals("ok", fraud(LinkedHashMap(fc).also { it["reversibility_class"] = "irreversible" }, irr))
        assertEquals("consistency", fraud(LinkedHashMap(fc).also { it["reversibility_class"] = 5L }, irr))
        assertEquals("consistency", fraud(LinkedHashMap(fc).also { it.remove("reversibility_class") }, irr))
        val ev = { e: Any? -> LinkedHashMap(irr).also { it["evidence"] = e } }
        assertEquals("ok", fraud(fc, ev(jm("action", jm("action", jm("reversibility_class", "irreversible"))))))
        assertEquals("consistency", fraud(fc, ev(jm("action", jm("action", jm("reversibility_class", "reversible"))))))
        assertEquals("consistency", fraud(fc, ev(jm("action", jm("action", jm("reversibility_class", 5L))))))
        assertEquals("consistency", fraud(fc, ev(jm("action", jm("action", jm())))))
        assertEquals("consistency", fraud(fc, ev(jm("action", jm("action", "irreversible")))))
        assertEquals("consistency", fraud(fc, ev(jm("action", jm()))))
        assertEquals("consistency", fraud(fc, ev(jm("action", "irreversible"))))
        assertEquals("consistency", fraud(fc, ev(jm())))
        assertEquals("consistency", fraud(fc, ev("irreversible")))
        assertEquals("consistency", fraud(fc, ev(null)))
    }

    private fun settle(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = jm("claimId", "C1", "action", "open", "amount", n("10"), "from", "A", "to", "T", "at", 1000L, "evidenceDigest", "")
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return lenientSigned(Optimistic.SETTLEMENT_DOMAIN, m, G)
    }

    private fun split(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val m = jm("amount", n("10"), "challengerReward", n("2"), "victimCompensation", n("3"), "treasuryRemainder", n("5"),
            "victimAccount", "V", "treasuryAccount", "T", "challengerAccount", "CH")
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    private fun sw(r: Any?) = Optimistic.settlementWireCheck(r, pub(G))

    @Test fun settlementWire() {
        assertEquals("ok", sw(settle()))
        assertEquals("ok", Optimistic.settlementWireCheck(settle(), pub(G), null))
        assertEquals("ok", sw(settle("action", "release")))
        assertEquals("ok", sw(settle("amount", n("0.5"))))
        assertEquals("ok", sw(settle("guardian_epoch", 0L)))
        assertEquals("malformed", sw(null))
        assertEquals("malformed", sw(jl()))
        assertEquals("suite", sw(settle("alg", 5L)))
        assertEquals("suite", sw(settle("alg", "rot13")))
        for ((k, v) in listOf<Pair<String, Any?>>(
            "claimId" to "", "claimId" to 5L, "action" to "close", "action" to 5L, "amount" to n("0"), "amount" to n("-1"), "amount" to "10",
            "amount" to null, "from" to "", "to" to null, "at" to "1000", "evidenceDigest" to 5L, "evidenceDigest" to "E",
            "evidenceDigest" to null, "split" to split(), "split" to null, "guardian_epoch" to -1L, "guardian_epoch" to "1", "guardian_epoch" to null,
        )) assertEquals("$k=$v", "shape", sw(settle(k, v)))
        assertEquals("shape", sw(LinkedHashMap(settle()).also { it["sig"] = 5L }))
        assertEquals("shape", sw(LinkedHashMap(settle()).also { it.remove("sig") }))
        // slash: evidence required, a split that conserves the amount and pays the treasury account
        val slash = { s: Any? -> settle("action", "slash", "evidenceDigest", "E", "split", s) }
        assertEquals("ok", sw(slash(split())))
        assertEquals("shape", sw(settle("action", "slash", "evidenceDigest", "", "split", split())))
        assertEquals("shape", sw(settle("action", "slash", "evidenceDigest", "E")))
        assertEquals("shape", sw(slash("split")))
        assertEquals("split", sw(slash(split("amount", n("9")))))
        assertEquals("split", sw(slash(split("amount", "10"))))
        assertEquals("split", sw(slash(split("challengerReward", n("-1"), "treasuryRemainder", n("8")))))
        assertEquals("split", sw(slash(split("challengerReward", null))))
        assertEquals("split", sw(slash(split("victimCompensation", "3"))))
        assertEquals("split", sw(slash(split("treasuryRemainder", n("4")))))
        assertEquals("split", sw(slash(split("victimAccount", ""))))
        assertEquals("split", sw(slash(split("victimAccount", 5L))))
        assertEquals("split", sw(slash(split("treasuryAccount", "U"))))
        assertEquals("split", sw(slash(split("treasuryAccount", 5L))))
        assertEquals("split", sw(slash(split("treasuryAccount", null))))
        assertEquals("split", sw(slash(split("challengerAccount", ""))))
        assertEquals("split", sw(slash(split("challengerAccount", 5L))))
        // no challenger: everything to the treasury
        assertEquals("ok", sw(slash(split("challengerAccount", null, "challengerReward", n("0"), "victimCompensation", n("0"), "treasuryRemainder", n("10")))))
        assertEquals("split", sw(slash(split("challengerAccount", null))))
        assertEquals("split", sw(slash(split("challengerAccount", null, "challengerReward", n("0"), "victimCompensation", n("2"), "treasuryRemainder", n("8")))))
        assertEquals("split", sw(slash(split("challengerAccount", null, "challengerReward", n("2"), "victimCompensation", n("0"), "treasuryRemainder", n("8")))))
        assertEquals("split", sw(slash(LinkedHashMap(split("challengerReward", n("0"), "victimCompensation", n("0"), "treasuryRemainder", n("10"))).also { it.remove("challengerAccount") })))
        // canonical form and signature last
        assertEquals("malformed", sw(LinkedHashMap(settle()).also { it["x"] = 1.5 }))
        assertEquals("signature", sw(LinkedHashMap(settle()).also { it["to"] = "U" }))
        assertEquals("signature", sw(lenientSigned(Optimistic.SETTLEMENT_DOMAIN, LinkedHashMap(settle()).also { it.remove("sig") }, "k05-opt/other")))
        assertEquals("signature", sw(LinkedHashMap(settle()).also { it["sig"] = "abc" }))
        assertEquals("ok", sw(LinkedHashMap(settle()).also { it["pq_sig"] = "ignored" }))
    }
}
