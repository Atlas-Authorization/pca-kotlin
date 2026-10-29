package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays `passport-vectors.json` (signed agent passport): every signature suite this verifier implements (a suite it does not
 * implement must answer `unsupported_suite`), the hardware branch through a stub verifier that answers what the vector says, and
 * the `passport_hardware_vectors` table through the REAL vendor verifiers built from their configuration. The table is produced by
 * the TypeScript generator: its absence is a failure, never a skip. Plus exact-outcome tests of the reason codes.
 */
@Suppress("UNCHECKED_CAST")
class PassportConformanceTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("passport-vectors.json") }

    private fun deepCopy(v: Any?): Any? = Json.parseLenient(Json.canonicalize(v))

    /** Replays the rows; returns how many exercised a supported non-default suite. */
    private fun replay(rows: List<Map<String, Any?>>, docs: MutableMap<String, Any?>): Int {
        val supported = Pq.supportedSuites().toSet()
        var seen = 0
        for (v in rows) {
            val name = v["name"] as String
            val signed = if (v["signed_ref"] is String) docs[v["signed_ref"] as String] else v["signed"]
            docs[name] = signed
            val issuers = (v["trustedIssuers"] as List<*>).map { it as String }
            val revoked = (v["revoked"] as List<*>).map { it as String }
            var gotBinding: Attest.Binding? = null
            var attest: HardwareAttester? = null
            val hw = v["hardware"] as? Map<String, Any?>
            if (hw != null) {
                attest = { _, b ->
                    gotBinding = b
                    if (hw["throws"] == true) throw IllegalStateException("verifier down")
                    Attest.Result(hw["ok"] == true, hw["bound"] == true, "", hw["measured"] as? Map<String, Any?>)
                }
            }
            var dh: Attest.DefaultHardware? = null
            val hv = v["hardware_verifier"] as? Map<String, Any?>
            if (hv != null) {
                val ver = Attest.verifierFromConfig(hv["vendor"] as String, hv["config"] as? Map<String, Any?>)
                val ev = hv["evidence"] as? Map<String, Any?>
                dh = Attest.DefaultHardware(ver) { _ -> ev }
            }
            val o = Passport.Options(
                trustedIssuers = issuers, nowMs = Json.asLong(v["now"]),
                clockSkewMs = if (v.containsKey("clockSkewMs")) Json.asLong(v["clockSkewMs"]) else null,
                maxEvidenceAgeMs = if (v.containsKey("maxEvidenceAgeMs")) Json.asLong(v["maxEvidenceAgeMs"]) else null,
                subject = v["subject"] as? String,
                pqPins = v["pqPins"] as? Map<String, Any?>,
                attest = attest, defaultHardware = dh,
                revoked = { id, _, _ -> revoked.contains(id) },
            )
            val got = Passport.verify(signed, o).reason ?: ""
            var want = if ((v["expect"] as Map<String, Any?>)["ok"] == true) "" else (v["expect"] as Map<String, Any?>)["reason"] as String
            val alg = (signed as? Map<String, Any?>)?.get("alg") as? String
            if (alg != null) {
                if (alg !in supported) want = "unsupported_suite" else seen++
            }
            assertEquals(name, want, got)
            val eb = v["expectBinding"] as? Map<String, Any?>
            if (eb != null) {
                val g = gotBinding
                assertNotNull("$name: the verifier was never handed a binding", g)
                assertEquals(name, eb["holderPub"], g!!.holderPub)
                assertEquals(name, eb["grantRef"], g.grantRef)
                assertEquals(name, Json.asLong(eb["epoch"]).toDouble(), g.epoch, 0.0)
                assertEquals(name, eb["nonce"], g.nonce)
            }
        }
        return seen
    }

    @Test
    fun passportVectors() {
        val rows = doc["passport_vectors"] as List<Map<String, Any?>>
        assertTrue("only ${rows.size} vectors", rows.size >= 74)
        val seen = replay(rows, HashMap())
        assertTrue("only $seen vectors exercised a supported post-quantum suite", seen >= 3)
    }

    @Test
    fun passportHardwareVectorsThroughTheRealVendorVerifiers() {
        val rows = doc["passport_hardware_vectors"] as? List<Map<String, Any?>>
        assertNotNull("passport-vectors.json has no passport_hardware_vectors table: regenerate it with the TypeScript reference", rows)
        assertTrue("only ${rows!!.size} passport_hardware_vectors", rows.size >= 40)
        val docs = HashMap<String, Any?>()
        for (v in doc["passport_vectors"] as List<Map<String, Any?>>) docs[v["name"] as String] = v["signed"]
        replay(rows, docs)
    }

    // ---- exact outcomes of the reason codes over the first (valid) vector ----

    private val base: Map<String, Any?> get() = (doc["passport_vectors"] as List<Map<String, Any?>>)[0]

    private fun options(v: Map<String, Any?>, now: Long? = null, revoked: ((String, String, String) -> Boolean)? = { _, _, _ -> false }) = Passport.Options(
        trustedIssuers = (v["trustedIssuers"] as List<*>).map { it as String }, nowMs = now ?: Json.asLong(v["now"]), revoked = revoked,
    )

    private fun signed(): MutableMap<String, Any?> = deepCopy(base["signed"]) as MutableMap<String, Any?>

    @Test
    fun theBaseVectorVerifiesAndEveryEditIsRefusedWithItsReason() {
        val v = base
        assertEquals(null, Passport.verify(signed(), options(v)).reason)
        assertEquals("malformed", Passport.verify("x", options(v)).reason)
        assertEquals("malformed", Passport.verify(null, options(v)).reason)
        val ver = signed().also { it["ver"] = IntentJs.ofLong(2) }
        assertEquals("unsupported_version", Passport.verify(ver, options(v)).reason)
        val alg = signed().also { it["alg"] = "bogus-suite" }
        assertEquals("unsupported_suite", Passport.verify(alg, options(v)).reason)
        val noIssuer = Passport.Options(trustedIssuers = emptyList(), nowMs = Json.asLong(v["now"]), revoked = { _, _, _ -> false })
        assertEquals("unknown_issuer", Passport.verify(signed(), noIssuer).reason)
        val tampered = signed().also { (it["passport"] as MutableMap<String, Any?>)["model_id"] = "other" }
        assertEquals("bad_signature", Passport.verify(tampered, options(v)).reason)
        assertEquals("not_yet_valid", Passport.verify(signed(), options(v, now = Json.asLong(signed()["nbf"]) - 1)).reason)
        assertEquals("expired", Passport.verify(signed(), options(v, now = Json.asLong(signed()["exp"]))).reason)
        assertEquals("revocation_unavailable", Passport.verify(signed(), options(v, revoked = null)).reason)
        assertEquals("revoked", Passport.verify(signed(), options(v, revoked = { _, _, _ -> true })).reason)
        assertEquals("revocation_unavailable", Passport.verify(signed(), options(v, revoked = { _, _, _ -> throw IllegalStateException("down") })).reason)
        val wrongSubject = Passport.Options(trustedIssuers = (v["trustedIssuers"] as List<*>).map { it as String }, nowMs = Json.asLong(v["now"]), subject = "someone-else", revoked = { _, _, _ -> false })
        assertEquals("subject_mismatch", Passport.verify(signed(), wrongSubject).reason)
        val noHw = signed()
        (noHw["passport"] as MutableMap<String, Any?>)["hardware_rooted"] = true
        assertTrue(Passport.verify(noHw, options(v)).reason!!.let { it == "bad_signature" })
    }
}
