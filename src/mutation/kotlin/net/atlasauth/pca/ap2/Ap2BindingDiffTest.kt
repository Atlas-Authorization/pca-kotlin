package net.atlasauth.pca.ap2

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.PcaCore
import org.junit.Test

/** Replays the reference vectors of the AP2 PCA binding verification through [Ap2.verifyPcaBinding]. */
@Suppress("UNCHECKED_CAST")
class Ap2BindingDiffTest {
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun num(o: Any?): Double = when (o) {
        is Json.Num -> o.raw.toDouble()
        is Number -> o.toDouble()
        else -> throw IllegalArgumentException("not a number")
    }

    private fun hook(d: Any?): PcaCore.Hook {
        val h = m(d)
        val r = if (true == h["enforced"]) {
            PcaCore.HookResult.enforced(true == h["ok"], h["reason"] as String?, if (h.containsKey("t")) num(h["t"]) else null)
        } else {
            PcaCore.HookResult.notEnforced()
        }
        return PcaCore.Hook { _ -> r }
    }

    private fun input(j: Map<String, Any?>): Ap2.VerifyPcaBindingInput {
        val i = Ap2.VerifyPcaBindingInput()
        i.open = m(j["open"])
        i.closed = m(j["closed"])
        i.openHash = j["openHash"] as String?
        i.expectedPrincipal = j["expectedPrincipal"] as String?
        if (j["pqPins"] is Map<*, *>) i.pqPins = m(j["pqPins"])
        i.audience = j["audience"] as String?
        // a call without a clock reads the wall clock, which the corpus froze at its case clock
        i.now = if (j["now"] != null) num(j["now"]).toLong() else net.atlasauth.pca.verifier.BaseOracle.clockMs("ref-ap2-java-extra.json.gz").toLong()
        if (j["mandate"] is Map<*, *>) i.mandate = m(j["mandate"])
        if (j["recentChargeTimes"] is List<*>) i.recentChargeTimes = j["recentChargeTimes"] as List<Any?>
        if (j.containsKey("hooks")) {
            val hooks = PcaCore.Hooks()
            val h = m(j["hooks"])
            if (h.containsKey("threshold")) hooks.threshold = hook(h["threshold"])
            if (h.containsKey("attestation")) hooks.attestation = hook(h["attestation"])
            if (h.containsKey("revocation")) hooks.revocation = hook(h["revocation"])
            if (h.containsKey("zk")) hooks.zk = hook(h["zk"])
            i.hooks = hooks
        }
        if (j.containsKey("enforce")) {
            val f = m(m(j["enforce"])["freshness"])
            i.enforce = PcaCore.Enforce(freshness = PcaCore.Freshness(num(f["maxAgeMs"])))
        }
        return i
    }

    @Test fun verifyPcaBinding() = OracleCases.each("ref-ap2-java-extra", "verifyPcaBinding") { a -> Ap2.verifyPcaBinding(input(m(a[0]))) }
}
