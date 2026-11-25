package net.atlasauth.pca.verifier

import net.atlasauth.pca.compliance.ComplianceJs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The agent passport against the reference (ref-passport, 516 cases): the fingerprint and issuing, the binding match (reason texts and order), the registry,
 * the trust score, the evidence binding, signing under Ed25519, ML-DSA-65 and the hybrid suite (signature bytes compare), verification with every refusal reason
 * and the assurance label. The revocation source and the hardware verifier are built from the case's spec. The one case the reference accepts only through its
 * legacy `allowUnboundPq` option is asserted refused (the option is not offered).
 */
@Suppress("UNCHECKED_CAST")
class RefPassportDiffTest {
    private val mod = "ref-passport"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict((o as? Map<*, *>)?.get("\$bytes"), 32) ?: throw IllegalArgumentException("not a signing key")

    private fun signer(secret: Any?, suite: Any?): Keys.SuiteKey {
        val s = suite as Map<String, Any?>?
        val alg = if (s != null && s.containsKey("alg")) s["alg"] as String else "ed25519"
        val pq = s?.get("pqSeed")?.let { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(it)) }
        return Keys.suite(alg, Keys.edFromSeed(seed(secret)), pq)
    }

    private fun registry(a: List<Any?>): Any? {
        val r = Passport.buildRegistry(a[0])
        return (a[1] as List<Any?>).map { op ->
            val o = op as List<Any?>
            when (o[0]) {
                "get" -> r.get(o[1])
                "has" -> r.has(o[1])
                "all" -> r.all()
                else -> throw AssertionError("op")
            }
        }
    }

    private fun sign(a: List<Any?>): Any? {
        val o = map(a[1])
        return Passport.signPassport(
            a[0], signer(o["issuerSecret"], o["suite"]), if (o.containsKey("subject")) o["subject"] else ComplianceJs.UNDEF, o["exp"], o["iat"], o["nbf"], o["evidence"],
        )
    }

    private fun verify(a: List<Any?>): Any? {
        val o = LinkedHashMap(map(a[1]))
        val rev = o.remove("revocation")
        val hw = o.remove("hardware")
        o.remove("allowUnboundPq")
        val revocation: ((Map<String, Any?>) -> Any?)? = when {
            rev is Map<*, *> && rev.containsKey("revoked") -> { _ -> rev["revoked"] }
            rev is Map<*, *> && rev.containsKey("revokedIds") -> { p -> (rev["revokedIds"] as List<Any?>).contains(p["id"]) }
            rev == "throws" -> { _ -> throw RuntimeException("revocation down") }
            else -> null
        }
        val hardware: Attestation.HardwareVerifier? = if (hw == null) null else Attestation.HardwareVerifier {
            val m = map(hw)
            if (m["throws"] != null) throw RuntimeException(m["throws"] as String)
            m["result"]
        }
        return Passport.verifyPassport(a[0], o, revocation, hardware)
    }

    private fun assurance(a: List<Any?>): Any? {
        val label = a[1]
        val verifier: Any? = when {
            label == "no-verifier" -> null
            label == null -> Any()
            else -> Assurance.setLabel(Any(), (label as Map<String, Any?>)["level"] as String, label["vendor"] as String?)
        }
        return Passport.passportAssurance(map(a[0]), verifier)
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf("PASSPORT_SIG_DOMAIN" to Passport.SIG_DOMAIN, "PASSPORT_VERSION" to Passport.VERSION, "DEFAULT_PASSPORT_EVIDENCE_AGE_MS" to Passport.DEFAULT_EVIDENCE_AGE_MS)
        "passportFingerprint" -> Passport.passportFingerprint(a[0])
        "issuePassport" -> Passport.issuePassport(a[0])
        "matchesBinding" -> Passport.matchesBinding(a[0], a.getOrNull(1))
        "registry" -> registry(a)
        "trustScore" -> Passport.trustScore(a[0], (a.getOrNull(1) as Map<String, Any?>?)?.get("knownOperators"))
        "passportEvidenceBinding" -> Passport.passportEvidenceBinding(a[0], a[1], a[2])
        "signPassport" -> sign(a)
        "verifyPassport" -> verify(a)
        "passportAssurance" -> assurance(a)
        else -> throw AssertionError("unhandled fn $fn")
    }

    private val unboundOnly = setOf("verifyPassport/pq-unbound#468")

    @Test fun everyFunction() {
        val fns = setOf("constants", "passportFingerprint", "issuePassport", "matchesBinding", "registry", "trustScore", "passportEvidenceBinding", "signPassport", "verifyPassport", "passportAssurance")
        var total = 0
        var refused = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val args = OracleCases.decNum(c["args"]) as List<Any?>
                if (c["name"] in unboundOnly) {
                    val r = map(call(fn, args))
                    assertEquals(c["name"].toString(), false, r["ok"])
                    assertEquals("bad_signature", r["reason"])
                    refused++
                    continue
                }
                val case = LinkedHashMap(c)
                case["args"] = args
                OracleCases.diff(case, c["out"]) { x -> call(fn, x) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(1, refused)
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(516, total)
    }
}
