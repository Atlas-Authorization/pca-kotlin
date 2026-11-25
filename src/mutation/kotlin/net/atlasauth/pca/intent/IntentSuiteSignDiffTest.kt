package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pq
import org.junit.Test

/** Suite signing of the intent artifacts: shape of the signed artifact plus the verdict under the matching pin. */
@Suppress("UNCHECKED_CAST")
class IntentSuiteSignDiffTest {
    private val m = "ref-intent-suite-sign-java"

    private fun key(a: List<Any?>): Keys.SuiteKey {
        val alg = a[2] as String
        val ed = Keys.edFromSeed(Keys.unb64u(a[1] as String))
        if ("ed25519" == alg) return Keys.ed25519(ed)
        val p = if (alg.endsWith("ml-dsa-87")) Pq.Prim.ML_DSA_87 else Pq.Prim.ML_DSA_65
        return Keys.suite(alg, ed, Keys.pqFromSeed(p, Keys.unb64u(a[3] as String)))
    }

    private fun len(v: Any?): Any? = if (v is String) Keys.unb64u(v).size else null

    private fun shape(a: Map<String, Any?>, ok: Boolean): Map<String, Any?> {
        val rest = LinkedHashMap(a)
        for (k in listOf("sig", "pq_sig", "alg", "pq_pk")) rest.remove(k)
        return linkedMapOf(
            "alg" to a["alg"], "pq_pk" to a["pq_pk"], "rest" to rest, "sig_len" to len(a["sig"]), "pq_sig_len" to len(a["pq_sig"]), "ok" to ok,
        )
    }

    private fun pins(a: Map<String, Any?>, who: String): Map<String, Any?> {
        val p = LinkedHashMap<String, Any?>()
        if (a["pq_pk"] != null) p[who] = a["pq_pk"]
        return p
    }

    private fun ok(v: Map<String, Any?>) = v["ok"] == true

    @Test fun signStatement() = OracleCases.each(m, "signStatement") { a ->
        val s = IntentStatement.signIntent(IntentOmega.obj(a[0]), key(a))
        shape(s, ok(IntentStatement.verifyIntent(s, null, pins(s, s["principal"] as String))))
    }

    @Test fun signObservation() = OracleCases.each(m, "signObservation") { a ->
        val s = IntentObservation.signIntentObservation(IntentOmega.obj(a[0]), key(a))
        shape(s, ok(IntentObservation.verifyIntentObservation(s, null, pins(s, s["signer"] as String))))
    }

    @Test fun signProfile() = OracleCases.each(m, "signProfile") { a ->
        val s = IntentProfile.signIntentProfile(IntentOmega.obj(a[0]), key(a))
        shape(s, ok(IntentProfile.verifyIntentProfile(s, pins(s, s["owner"] as String))))
    }
}
