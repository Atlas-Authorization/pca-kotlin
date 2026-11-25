package net.atlasauth.pca.fhe

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Differential tests of the pure parts of pca-fhe (quantization, gate policy, signed-claim and verdict-attestation layer). */
@Suppress("UNCHECKED_CAST")
class FheDiffTest {
    private val M = "ref-fhe"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun seed(o: Any?): ByteArray = Keys.unb64u(o as String)
    private fun strs(o: Any?): List<String> = (o as List<Any?>).map { it as String }

    @Test fun quantization() {
        OracleCases.each(M, "transformedInputs") { a -> FheRisk.transformedInputs(map(a[0])).toList() }
        OracleCases.each(M, "quantizeRiskInputs") { a -> (if (a.size == 1) FheRisk.quantizeRiskInputs(map(a[0])) else FheRisk.quantizeRiskInputs(map(a[0]), a[1])).toList() }
        OracleCases.each(M, "weightVector") { a -> FheRisk.weightVector(map(a[0])).toList() }
        OracleCases.each(M, "fheRiskPolicy") { a -> if (a.size == 2) FheRisk.fheRiskPolicy(map(a[0]), a[1]) else FheRisk.fheRiskPolicy(map(a[0]), a[1], a[2]) }
        OracleCases.each(M, "plaintextVerdict") { a -> FheRisk.plaintextVerdict(map(a[0]), map(a[1]), a[2]) }
        OracleCases.each(M, "fromActn") { a -> FheRisk.transformedInputs(FheRisk.riskInputsFromPCActn(map(a[0]))).toList() }
        OracleCases.each(M, "binding") { a -> FheRisk.bindingFromPCActn(map(a[0])) }
    }

    @Test fun signedClaims() {
        OracleCases.each(M, "sign") { a -> FheOrigin.signRiskClaim(map(a[0]), seed(a[1]), a[2] as String, Keys.unb64u(map(a[3])["\$bytes"] as String)) }
        OracleCases.each(M, "claimDigest") { a -> FheOrigin.signedClaimDigest(a[0]) }
        OracleCases.each(M, "verifyClaim") { a ->
            val e = map(a[1])
            val used = HashSet(strs(e["used"]))
            val max = Js.num(e["max"])!!.toInt()
            val exp = FheOrigin.ClaimExpectations(strs(e["trustedSigners"]), e["context"] as String, e["binding"], e["policy"]) { k ->
                if (k in used || used.size >= max) false else { used.add(k); true }
            }
            val r = FheOrigin.verifySignedRiskClaim(a[0], exp)
            if (r.ok) linkedMapOf("ok" to true, "claim" to r.claim, "digest" to r.digest) else linkedMapOf("ok" to false, "reason" to r.reason)
        }
        OracleCases.each(M, "nonceGuard") { a ->
            val g = FheOrigin.memoryNonceGuard(Js.num(a[0])!!.toInt())
            strs(a[1]).map { g.claim(it) }
        }
    }

    @Test fun verdictAttestations() {
        OracleCases.each(M, "attest") { a -> FheOrigin.attestVerdict(seed(a[0]), map(a[1]), map(a[2]), a[3] == true) }
        OracleCases.each(M, "verifyAttest") { a ->
            val e = map(a[1])
            val r = FheOrigin.verifyVerdictAttestation(a[0], strs(e["trustedHolders"]), e["claimDigest"] as String, e["gate"]?.let { map(it) })
            if (r.ok) linkedMapOf("ok" to true, "admit" to r.admit) else linkedMapOf("ok" to false, "reason" to r.reason)
        }
    }
}
