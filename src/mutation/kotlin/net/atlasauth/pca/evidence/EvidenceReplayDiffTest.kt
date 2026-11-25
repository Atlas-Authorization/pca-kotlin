package net.atlasauth.pca.evidence

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** verifyEvidenceBundle over the reference's walkthrough world and its mutations: the whole findings report is compared. */
@Suppress("UNCHECKED_CAST")
class EvidenceReplayDiffTest {
    private fun port(kind: String) = EvidenceReplay.Port { _, _ ->
        if (kind == "throws") throw IllegalStateException("boom")
        val v = LinkedHashMap<String, Any?>()
        v["ok"] = kind == "ok"
        if (kind != "ok") v["reason"] = "port refused"
        v
    }

    @Test fun verifyEvidenceBundle() = OracleCases.each("ref-evidence-java-extra2", "verifyEvidenceBundle") { a ->
        val trust = LinkedHashMap(a[1] as Map<String, Any?>)
        val ports = LinkedHashMap<String, EvidenceReplay.Port>()
        val vs = trust.remove("verifiers")
        if (vs is Map<*, *>) for ((k, v) in vs) ports[k as String] = port(v as String)
        EvidenceVerify.verifyEvidenceBundle(a[0], trust, ports)
    }
}
