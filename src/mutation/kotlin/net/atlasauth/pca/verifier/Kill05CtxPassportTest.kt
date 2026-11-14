package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for Passport.kt, pinned to packages/pca/src/passport.ts (verifyPassport): every reason code and boundary
 * with its detail text, the Verdict members, the fail-closed handlers, and the hardware branch (ported from the java-pca
 * PassportKillTest; every passport is signed at runtime, so only the check under test can refuse it).
 */
@Suppress("UNCHECKED_CAST")
class Kill05CtxPassportTest {
    private val nbf = 500_000L
    private val exp = 2_000_000L
    private val now = 1_000_000L
    private val label = "k05-passport-issuer"
    private val iss = IntentTestKit.pub(label)
    private val sub = IntentTestKit.pub("k05-passport-subject")

    private fun identity(hw: Boolean): LinkedHashMap<String, Any?> =
        linkedMapOf("model_id" to "m1", "operator" to "op", "hardware_rooted" to hw, "weights_digest" to "wd", "weights_measured" to true)

    private fun body(p: Map<String, Any?>, evidence: Any?, vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val pp = LinkedHashMap(p)
        pp["id"] = Passport.fingerprint(p)
        val b = linkedMapOf<String, Any?>("typ" to "atlas-pca/passport", "ver" to 1L, "passport" to pp, "iss" to iss, "sub" to sub,
            "iat" to nbf, "nbf" to nbf, "exp" to exp)
        if (evidence != null) b["evidence"] = evidence
        for ((k, v) in over) b[k] = v
        return b
    }

    private fun sign(b: Map<String, Any?>): LinkedHashMap<String, Any?> {
        val out = LinkedHashMap(b)
        out["sig"] = IntentTestKit.sign(label, IntentJs.message(Passport.SIG_DOMAIN, b))
        return out
    }

    private fun soft(vararg over: Pair<String, Any?>) = sign(body(identity(false), null, *over))
    private fun ev(at: Any?, nonce: Any?): Map<String, Any?> = mapOf("document" to mapOf("nonce" to nonce), "at" to at)
    private fun hardware(evidence: Any? = ev(now, "n1")) = sign(body(identity(true), evidence))

    private fun opts(
        issuers: List<String> = listOf(iss), nowMs: Long = now, skew: Long? = null, maxAge: Long? = null, subject: String? = null,
        attest: HardwareAttester? = null, dh: Attest.DefaultHardware? = null,
        revoked: ((String, String, String) -> Boolean)? = { _, _, _ -> false },
    ) = Passport.Options(issuers, nowMs, skew, maxAge, subject, null, attest, dh, revoked)

    private val good: HardwareAttester = { _, _ -> Attest.Result(true, true, "", identity(true)) }

    private fun check(want: String, detail: String?, signed: Any?, o: Passport.Options) {
        val v = Passport.verify(signed, o)
        assertEquals("$signed", want, v.reason ?: "")
        assertEquals("$want detail", detail, v.detail)
        assertEquals(want == "", v.ok)
    }

    private fun malformed(signed: Any?) = check("malformed", null, signed, opts())

    @Test
    fun verdictMembers() {
        val soft = soft()
        val v = Passport.verify(soft, opts())
        assertTrue(v.ok)
        assertNull(v.reason)
        assertNull(v.detail)
        assertEquals(soft["passport"], v.passport)
        assertFalse(v.hardwareVerified)
        val h = Passport.verify(hardware(), opts(attest = good))
        assertTrue(h.ok)
        assertTrue(h.hardwareVerified)
        val bad = Passport.verify("x", opts())
        assertFalse(bad.ok)
        assertNull(bad.passport)
        assertFalse(bad.hardwareVerified)
        assertEquals("Passport.Verdict(ok=false, reason=malformed, detail=null)", bad.toString())
        assertEquals("Passport.Verdict(ok=true, reason=null, detail=null)", v.toString())
    }

    @Test
    fun malformedShapes() {
        malformed(null)
        malformed("x")
        malformed(soft("typ" to "other"))
        malformed(soft().also { it.remove("passport") })
        malformed(sign(body(identity(false), null, "passport" to "x")))
        for (k in listOf("iss", "sub")) {
            malformed(soft(k to ""))
            malformed(sign(body(identity(false), null).also { it.remove(k) }))
        }
        malformed(soft().also { it["sig"] = "" })
        malformed(soft().also { it["sig"] = 5L })
        malformed(soft().also { it.remove("sig") })
        for (k in listOf("model_id", "operator")) {
            for (bad in listOf<Any?>("", null)) {
                val p = identity(false)
                if (bad == null) p.remove(k) else p[k] = bad
                malformed(sign(body(p, null)))
            }
        }
        for (bad in listOf<Any?>("", 5L, null)) {
            val b = body(identity(false), null)
            val pp = b["passport"] as MutableMap<String, Any?>
            if (bad == null) pp.remove("id") else pp["id"] = bad
            malformed(sign(b))
        }
        malformed(sign(body(identity(false).also { it["hardware_rooted"] = "yes" }, null)))
    }

    @Test
    fun times() {
        fun times(signed: Any?, o: Passport.Options = opts()) = check("malformed", "times", signed, o)
        times(soft("iat" to "x"))
        times(soft("nbf" to "x"))
        times(soft("exp" to "x"))
        times(sign(body(identity(false), null).also { it.remove("iat") }))
        times(soft("exp" to nbf))
        times(soft(), opts(nowMs = 9007199254740992L))
        times(soft(), opts(nowMs = -9007199254740992L))
        check("expired", null, soft(), opts(nowMs = 9007199254740991L))
        check("not_yet_valid", null, soft(), opts(nowMs = -9007199254740991L))
        check("", null, soft("exp" to nbf + 1), opts(nowMs = nbf))
    }

    @Test
    fun versionSuiteIssuerSignature() {
        check("unsupported_version", "2", soft("ver" to 2L), opts())
        check("unsupported_version", "undefined", sign(body(identity(false), null).also { it.remove("ver") }), opts())
        check("unsupported_suite", "not-a-suite", soft("alg" to "not-a-suite"), opts())
        // refused before the signature, so the (unsignable) non-canonical number is added after signing
        check("unsupported_suite", "1", soft().also { it["alg"] = Json.Num("1.0") }, opts())
        check("unknown_issuer", null, soft(), opts(issuers = listOf("other")))
        check("bad_signature", null, soft().also { it["sig"] = Pca.b64(ByteArray(64)) }, opts())
        val b = body(identity(false), null)
        (b["passport"] as MutableMap<String, Any?>)["id"] = "wrong"
        check("id_mismatch", null, sign(b), opts())
    }

    @Test
    fun failClosedHandlers() {
        val throwing = object : AbstractList<String>() {
            override val size: Int get() = 1
            override fun get(index: Int): String = throw IllegalStateException("boom")
        }
        check("malformed", "IllegalStateException", soft(), opts(issuers = throwing))
        // a revocation source that throws (anything non-fatal) is "no revocation answer", never a malformed passport
        check("revocation_unavailable", null, soft(), opts(revoked = { _, _, _ -> throw StackOverflowError() }))
    }

    @Test
    fun validityWindow() {
        check("not_yet_valid", null, soft(), opts(nowMs = nbf - 1))
        check("", null, soft(), opts(nowMs = nbf))
        check("expired", null, soft(), opts(nowMs = exp))
        check("", null, soft(), opts(nowMs = exp - 1))
        check("", null, soft(), opts(nowMs = nbf - 60_000, skew = 1_000_000_000L))
        check("not_yet_valid", null, soft(), opts(nowMs = nbf - 60_001, skew = 1_000_000_000L))
        check("", null, soft(), opts(nowMs = exp + 59_999, skew = 1_000_000_000L))
        check("expired", null, soft(), opts(nowMs = exp + 60_000, skew = 1_000_000_000L))
        check("not_yet_valid", null, soft(), opts(nowMs = nbf - 1, skew = -5L))
    }

    @Test
    fun subjectAndRevocation() {
        check("subject_mismatch", null, soft(), opts(subject = "someone-else"))
        check("", null, soft(), opts(subject = sub))
        check("revocation_unavailable", "no revocation source", soft(), opts(revoked = null))
        check("revocation_unavailable", null, soft(), opts(revoked = { _, _, _ -> throw IllegalStateException("down") }))
        check("revoked", null, soft(), opts(revoked = { _, _, _ -> true }))
        check("revoked", null, hardware(), opts(revoked = { _, _, _ -> true }))
    }

    @Test
    fun hardwareEvidence() {
        val o = opts(attest = good)
        check("hardware_verifier_missing", null, hardware(), opts())
        check("", null, hardware(), o)
        check("hardware_evidence_missing", null, hardware(null), o)
        check("hardware_evidence_missing", null, hardware("x"), o)
        check("hardware_evidence_missing", null, hardware(mapOf("document" to "x", "at" to now)), o)
        check("hardware_evidence_missing", null, hardware(mapOf("at" to now)), o)
        check("hardware_evidence_missing", null, hardware(mapOf("document" to emptyMap<String, Any?>(), "at" to now)), o)
        check("hardware_evidence_missing", null, hardware(ev(now, "")), o)
        check("hardware_evidence_missing", "evidence.at", hardware(mapOf("document" to mapOf("nonce" to "n"))), o)
        check("hardware_evidence_missing", "evidence.at", hardware(ev("x", "n")), o)
    }

    @Test
    fun hardwareEvidenceAge() {
        val o = opts(attest = good)
        check("", null, hardware(ev(now - Passport.DEFAULT_EVIDENCE_AGE_MS, "n")), o)
        check("hardware_evidence_stale", null, hardware(ev(now - Passport.DEFAULT_EVIDENCE_AGE_MS - 1, "n")), o)
        check("hardware_evidence_stale", null, hardware(ev(now + 1, "n")), o)
        val sk = opts(attest = good, skew = 10L)
        check("", null, hardware(ev(now + 10, "n")), sk)
        check("hardware_evidence_stale", null, hardware(ev(now + 11, "n")), sk)
        val five = opts(attest = good, skew = 10L, maxAge = 5L)
        check("", null, hardware(ev(now - 5, "n")), five)
        check("hardware_evidence_stale", null, hardware(ev(now - 6, "n")), five)
        check("", null, hardware(ev(now, "n")), opts(attest = good, maxAge = 0L))
        check("hardware_evidence_stale", null, hardware(ev(now - 1, "n")), opts(attest = good, maxAge = 0L))
        check("hardware_evidence_stale", null, hardware(), opts(attest = good, maxAge = -1L))
    }

    @Test
    fun hardwareOutcomeAndIdentity() {
        var got: Attest.Binding? = null
        val s = hardware()
        check("", null, s, opts(attest = { _, b -> got = b; Attest.Result(true, true, "", identity(true)) }))
        assertEquals(sub, got!!.holderPub)
        assertEquals("passport:" + (s["passport"] as Map<String, Any?>)["id"], got!!.grantRef)
        assertEquals(0.0, got!!.epoch, 0.0)
        assertEquals("n1", got!!.nonce)
        check("hardware_attestation_failed", "nope", hardware(), opts(attest = { _, _ -> Attest.Result(false, true, "nope", identity(true)) }))
        check("hardware_attestation_failed", "unbound", hardware(), opts(attest = { _, _ -> Attest.Result(true, false, "unbound", identity(true)) }))
        check("hardware_attestation_failed", "down", hardware(), opts(attest = { _, _ -> throw IllegalStateException("down") }))
        check("hardware_attestation_failed", "error", hardware(), opts(attest = { _, _ -> throw IllegalStateException() }))
        check("hardware_identity_mismatch", null, hardware(), opts(attest = { _, _ -> Attest.Result(true, true, "", null) }))
        for (k in listOf("model_id", "operator", "weights_digest")) {
            val m = identity(true).also { it[k] = "different" }
            check("hardware_identity_mismatch", null, hardware(), opts(attest = { _, _ -> Attest.Result(true, true, "", m) }))
            val m2 = identity(true).also { it.remove(k) }
            check("hardware_identity_mismatch", null, hardware(), opts(attest = { _, _ -> Attest.Result(true, true, "", m2) }))
        }
        val wm = identity(true).also { it["weights_measured"] = false }
        check("hardware_identity_mismatch", null, hardware(), opts(attest = { _, _ -> Attest.Result(true, true, "", wm) }))
        val p = linkedMapOf<String, Any?>("model_id" to "m1", "operator" to "op", "hardware_rooted" to true)
        check("", null, sign(body(p, ev(now, "n"))), opts(attest = { _, _ -> Attest.Result(true, true, "", mapOf("model_id" to "m1", "operator" to "op")) }))
    }

    @Test
    fun integratorAttestWinsOverDefault() {
        var usedDefault = false
        val impl = object : Attest.VendorImpl {
            override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result {
                usedDefault = true
                return Attest.Result(false, false, "default")
            }
        }
        val dh = Attest.DefaultHardware(Attest.VendorVerifier("test", impl, null))
        check("", null, hardware(), opts(attest = good, dh = dh))
        assertFalse(usedDefault)
        check("hardware_attestation_failed", "default", hardware(), opts(dh = dh))
        assertTrue(usedDefault)
    }
}
