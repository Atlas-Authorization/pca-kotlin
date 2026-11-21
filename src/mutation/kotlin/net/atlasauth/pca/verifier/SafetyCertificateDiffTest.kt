package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays the reference oracle of the signed safety certificate (262 cases, every fn dispatched; the two the reference accepts only
 * through its legacy `allowUnboundPq` opt-out are asserted refused): the bound and its statement, check
 * validation, the signed message, issuing under Ed25519, ML-DSA-65 and the hybrid suite (signature bytes compared), verification with
 * every refusal reason, the canonical encoding and the compliance row. A non-finite number is {"$num": text} on both sides; a secret is
 * a seed label; null in an optional position is an argument that was not given.
 */
@Suppress("UNCHECKED_CAST")
class SafetyCertificateDiffTest {
    private val mod = "ref-safety-certificate"

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null
    private fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("not an object")

    /** {"$num": text} is that double, carried as a JSON number with JavaScript's text. */
    private fun dec(v: Any?): Any? = when (v) {
        is Map<*, *> -> if (v.size == 1 && v["\$num"] is String) Json.Num(v["\$num"] as String) else (v as Map<String, Any?>).mapValuesTo(LinkedHashMap()) { dec(it.value) }
        is List<*> -> v.map { dec(it) }
        else -> v
    }

    /** A non-finite result is {"$num": text}. */
    private fun enc(v: Any?): Any? = when (v) {
        is Double -> if (v.isNaN() || v.isInfinite()) linkedMapOf<String, Any?>("\$num" to Json.jsNumberText(v)) else v
        is Json.Num -> if (v.raw == "NaN" || v.raw.endsWith("Infinity")) linkedMapOf<String, Any?>("\$num" to v.raw) else v
        is Map<*, *> -> (v as Map<String, Any?>).mapValuesTo(LinkedHashMap()) { enc(it.value) }
        is List<*> -> v.map { enc(it) }
        else -> v
    }

    /** {"$bytes": seed} with the loader's base64url seed in place of the label. */
    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict((o as? Map<*, *>)?.get("\$bytes"), 32) ?: throw IllegalArgumentException("not a signing key")

    private fun guardian(a: Map<String, Any?>): Keys.SuiteKey {
        val suite = a["suite"] as? Map<String, Any?>
        val alg = if (suite != null && suite.containsKey("alg")) suite["alg"] as String else "ed25519"
        val pq = suite?.get("pqSeed")?.let { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(it)) }
        return Keys.suite(alg, Keys.edFromSeed(seed(a["guardianSecret"])), pq)
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf(
            "MAX_SAFETY_CHECKS" to SafetyCertificate.MAX_SAFETY_CHECKS, "SAFETY_CERT_DOMAIN" to SafetyCertificate.SAFETY_CERT_DOMAIN,
            "SAFETY_CERT_SCOPE" to SafetyCertificate.SAFETY_CERT_SCOPE, "SAFETY_CERT_VERSION" to SafetyCertificate.SAFETY_CERT_VERSION,
        )
        "safetyCertificateBound" -> SafetyCertificate.safetyCertificateBound(arg(a, 0))
        "safetyCertificateStatement" -> SafetyCertificate.safetyCertificateStatement(IntentJs.num(arg(a, 0)) ?: throw IllegalArgumentException("not a number"))
        "validateSafetyChecks" -> SafetyCertificate.validateSafetyChecks(arg(a, 0))
        "safetyCertificateMessage" -> SafetyCertificate.safetyCertificateMessage(map(arg(a, 0)))
        "issueSafetyCertificate" -> {
            val x = map(arg(a, 0))
            SafetyCertificate.issueSafetyCertificate(x["policy"], guardian(x), x["issuedAt"], x["grantRef"] as String?, x["instance"] as String?, x["checks"])
        }
        "verifySafetyCertificate" -> SafetyCertificate.verifySafetyCertificate(arg(a, 0), arg(a, 1) as Map<String, Any?>?)
        "encodeSafetyCertificate" -> SafetyCertificate.encodeSafetyCertificate(map(arg(a, 0)))
        "decodeSafetyCertificate" -> SafetyCertificate.decodeSafetyCertificate(arg(a, 0))
        "safetyCertificateForCompliance" -> SafetyCertificate.safetyCertificateForCompliance(arg(a, 0), arg(a, 1) as Map<String, Any?>?)
        else -> throw AssertionError("unhandled fn $fn")
    }

    private val handled = setOf(
        "constants", "safetyCertificateBound", "safetyCertificateStatement", "validateSafetyChecks", "safetyCertificateMessage", "issueSafetyCertificate",
        "verifySafetyCertificate", "encodeSafetyCertificate", "decodeSafetyCertificate", "safetyCertificateForCompliance",
    )

    /**
     * The reference accepts these only through `allowUnboundPq`, a legacy insecure opt-out that no native verifier offers (they are
     * fail-closed: a post-quantum key the certificate carries is never trusted by itself). They are refused here.
     */
    private val unboundOnly = setOf("verifySafetyCertificate/pure-pq-unbound-allowed#140", "verifySafetyCertificate/hybrid-unbound-allowed#144")

    @Test fun replayAllCases() {
        assertEquals(handled, BaseOracle.fns("$mod.json.gz"))
        var total = 0
        var refused = 0
        val bad = ArrayList<String>()
        for (fn in handled) for (c in OracleCases.of(mod, fn)) {
            total++
            var want = c["out"]
            val name = c["name"] as String
            if (unboundOnly.contains(name)) {
                refused++
                val opts = (c["args"] as List<Any?>)[1] as Map<String, Any?>
                assertEquals(name, mapOf<String, Any?>("allowUnboundPq" to true), opts) // nothing else lets the case through
                val accepted = c["out"] as Map<String, Any?>
                assertEquals(name, true, accepted["ok"])
                want = linkedMapOf<String, Any?>("ok" to false, "reason" to "guardian signature does not verify", "recomputedBound" to accepted["recomputedBound"])
            }
            OracleCases.diff(c, want) { a -> enc(call(fn, dec(a) as List<Any?>)) }?.let { bad.add(it) }
        }
        assertEquals(262, total)
        assertEquals(2, refused)
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    private val policy = Json.parseLenient(
        """{"weights":{"alpha":0.25,"beta":0.2,"gamma":0.2,"delta":0.2,"epsilon":0.1,"zeta":0.05},"theta1":0.25,"theta2":0.6,"kappa":4,"lambda":0.0005,"rho":0.5,"bMax":2}""",
    )

    @Test fun anIssuedCertificateVerifiesAndATamperedBoundDoesNot() {
        val key = Keys.ed25519(Keys.edFromSeed(OracleCases.seed("sc/guardian")))
        val cert = SafetyCertificate.issueSafetyCertificate(policy, key, IntentJs.ofLong(1_800_000_000_000L))
        assertEquals(true, SafetyCertificate.verifySafetyCertificate(cert)["ok"])
        assertEquals(cert["sig"], SafetyCertificate.decodeSafetyCertificate(SafetyCertificate.encodeSafetyCertificate(cert))!!["sig"])
        val tampered = LinkedHashMap(cert).also { it["bound"] = IntentJs.ofLong(100) }
        assertEquals(false, SafetyCertificate.verifySafetyCertificate(tampered)["ok"])
    }

    /** A post-quantum certificate verifies under the verifier's pin, never under the key it carries: no option turns that off. */
    @Test fun theCarriedPostQuantumKeyIsNotTrustedByDefault() {
        val ed = Keys.edFromSeed(OracleCases.seed("sc/guardian"))
        val key = Keys.suite("hybrid-ed25519-ml-dsa-65", ed, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, OracleCases.seed("sc/pq")))
        val cert = SafetyCertificate.issueSafetyCertificate(policy, key, IntentJs.ofLong(1_800_000_000_000L))
        assertEquals(false, SafetyCertificate.verifySafetyCertificate(cert)["ok"])
        assertEquals(false, SafetyCertificate.verifySafetyCertificate(cert, linkedMapOf<String, Any?>("allowUnboundPq" to true))["ok"])
        assertEquals(true, SafetyCertificate.verifySafetyCertificate(cert, linkedMapOf<String, Any?>("pqPins" to Keys.pqPin(key)))["ok"])
        val otherPin = linkedMapOf<String, Any?>(ed.id() to Keys.pqFromSeed(Pq.Prim.ML_DSA_65, OracleCases.seed("sc/other")).pkB64u())
        assertEquals(false, SafetyCertificate.verifySafetyCertificate(cert, linkedMapOf<String, Any?>("pqPins" to otherPin, "allowUnboundPq" to true))["ok"])
    }

    /** `requireChecks` is iterated as the reference iterates it: a list by entry, text by code point, and a value that cannot be iterated is malformed. */
    @Test fun requiredChecksThatAreNotAListAreReadAsTheReferenceReadsThem() {
        val key = Keys.ed25519(Keys.edFromSeed(OracleCases.seed("sc/guardian")))
        val check = { id: String -> linkedMapOf<String, Any?>("id" to id, "status" to "passed", "evidence" to linkedMapOf<String, Any?>("kind" to "sha256", "ref" to "0".repeat(64)), "at" to IntentJs.ofLong(1)) }
        val cert = SafetyCertificate.issueSafetyCertificate(policy, key, IntentJs.ofLong(1_800_000_000_000L), null, null, listOf(check("a"), check("\uD83D\uDE00")))
        fun v(required: Any?): Map<String, Any?> = SafetyCertificate.verifySafetyCertificate(cert, linkedMapOf<String, Any?>("requireChecks" to required))
        assertEquals(true, v("")["ok"])
        assertEquals(true, v("a\uD83D\uDE00a")["ok"])
        assertEquals("required check 'b' is not present", v("ab")["reason"])
        val tail = " is not iterable (cannot read property Symbol(Symbol.iterator))"
        assertEquals(mapOf<String, Any?>("ok" to false, "reason" to "malformed certificate: number 5$tail"), v(IntentJs.ofLong(5)))
        assertEquals("malformed certificate: boolean true$tail", v(true)["reason"])
        assertEquals("malformed certificate: object$tail", v(linkedMapOf<String, Any?>())["reason"])
    }
}
