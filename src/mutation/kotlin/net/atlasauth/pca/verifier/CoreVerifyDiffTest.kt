package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** Replays the reference vectors of the core verify entry through [PcaCore.verify]: hooks, enforcement gates, assurance, pins, suites. */
@Suppress("UNCHECKED_CAST")
class CoreVerifyDiffTest {
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun hook(d: Any?): PcaCore.Hook {
        val h = m(d)
        val r = if (h["enforced"] == true) PcaCore.HookResult.enforced(h["ok"] == true, h["reason"] as String?, if (h.containsKey("t")) IntentJs.num(h["t"]) else null)
        else PcaCore.HookResult.notEnforced()
        return PcaCore.Hook { r }
    }

    internal fun options(j: Map<String, Any?>): PcaCore.Options {
        val o = PcaCore.Options(m(j["grant"]))
        o.grantFromArtifact = j["grantFromArtifact"] == true
        if (j.containsKey("nowEpoch")) o.nowEpoch = IntentJs.num(j["nowEpoch"])!!.toLong()
        if (j.containsKey("pqPins")) o.pqPins = m(j["pqPins"])
        if (j.containsKey("allowedSuites")) o.allowedSuites = (j["allowedSuites"] as List<*>).map { it as String }
        if (j.containsKey("audience")) o.audience = if (j["audience"] == null) Pca.Audience.Any else Pca.Audience.Of(j["audience"] as String)
        if (j.containsKey("authorizedPlanRoots")) o.authorizedPlanRoots = (j["authorizedPlanRoots"] as List<*>).map { it as String }
        o.insecureSkipPlanRootCheck = j["insecureSkipPlanRootCheck"] == true
        if (j.containsKey("hooks")) {
            val hm = m(j["hooks"])
            val h = PcaCore.Hooks()
            if (hm.containsKey("attestation")) h.attestation = hook(hm["attestation"])
            if (hm.containsKey("threshold")) h.threshold = hook(hm["threshold"])
            if (hm.containsKey("revocation")) h.revocation = hook(hm["revocation"])
            if (hm.containsKey("zk")) h.zk = hook(hm["zk"])
            o.hooks = h
        }
        if (j.containsKey("enforce")) {
            val em = m(j["enforce"])
            val e = PcaCore.Enforce()
            if (em.containsKey("freshness")) {
                val f = m(em["freshness"])
                e.freshness = PcaCore.Freshness(
                    IntentJs.num(f["maxAgeMs"])!!,
                    if (f.containsKey("epochMs")) IntentJs.num(f["epochMs"]) else null,
                    if (f.containsKey("clockSkewMs")) IntentJs.num(f["clockSkewMs"]) else null,
                    if (f.containsKey("now")) IntentJs.num(f["now"])!!.toLong() else null,
                )
            }
            if (em.containsKey("attestation")) {
                val a = m(em["attestation"])
                val g = PcaCore.AttestationGate(hook(a["verifier"]))
                if (a.containsKey("required")) g.required = a["required"] == true
                e.attestation = g
            }
            o.enforce = e
        }
        o.assurance = j["assurance"] == true
        if (j.containsKey("requireAssurance")) o.requireAssurance = m(j["requireAssurance"])
        if (j.containsKey("intent")) o.intentPolicy = Pca.IntentPolicy.fromJson(j["intent"])
        return o
    }

    private fun out(r: PcaCore.Result): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["allow"] = r.allow
        m["checks"] = LinkedHashMap(r.checks)
        if (r.reason != null) m["reason"] = r.reason
        if (r.assurance != null) m["assurance"] = r.assurance
        return m
    }

    @Test fun verifyCore() = OracleCases.each("ref-core-verify-java", "verifyCore") { a -> out(PcaCore.verify(a[0], options(m(a[1])))) }

    /** The reference reports checks in a fixed order; the JSON comparison ignores member order, so pin it here. */
    @Test fun checkOrderIsNormative() {
        for (c in OracleCases.of("ref-core-verify-java", "verifyCore")) {
            val want = m(m(c["out"])["checks"]).keys.toList()
            val a = c["args"] as List<Any?>
            assertEquals(c["name"].toString(), want, PcaCore.verify(a[0], options(m(a[1]))).checks.keys.toList())
        }
    }
}
