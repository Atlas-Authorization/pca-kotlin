package net.atlasauth.pca.attesteat

import java.security.MessageDigest
import net.atlasauth.pca.scitt.Scitt
import net.atlasauth.pca.scitt.ScittPrivateKey
import net.atlasauth.pca.scitt.ScittPublicKey
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pq
import net.atlasauth.pca.verifier.Sigstore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the reference vectors of the attestation-token layer (EAT build / verify, freshness, channel binding, appraisal, AMD root, PQ co-signature, admission, provenance). */
class AttestEatDiffTest {
    private val m = "ref-attest-eat"

    @Suppress("UNCHECKED_CAST")
    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun isBytes(o: Any?): Boolean = o is Map<*, *> && o.size == 1 && o["\$bytes"] is String

    private fun bytes(o: Any?): ByteArray = Keys.unb64u(map(o)["\$bytes"] as String)

    /** {"$bytes"} members become byte arrays (the oracle's rev). */
    private fun rev(v: Any?): Any? = when {
        isBytes(v) -> bytes(v)
        v is List<*> -> v.map { rev(it) }
        v is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = rev(x) }
        else -> v
    }

    private fun priv(spec: Any?): ScittPrivateKey {
        val s = map(spec)
        return if (s["alg"] == "EdDSA") Scitt.ed25519PrivateKey(Keys.unb64u(s["seed"] as String)) else Scitt.es256PrivateKey(Keys.unb64u(s["d"] as String))
    }

    private fun pub(spec: Any?): ScittPublicKey {
        val s = map(spec)
        return if (s["alg"] == "EdDSA") Scitt.ed25519PublicKey(Keys.unb64u(s["pub"] as String))
        else Scitt.es256PublicKey(Keys.unb64u(s["x"] as String), Keys.unb64u(s["y"] as String))
    }

    /** Opts with {"$bytes"} turned into bytes and a verifyKey spec turned into a key. */
    private fun verifyOpts(o: Any?): Map<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        val r = rev(o) as MutableMap<String, Any?>
        if (r["verifyKey"] is Map<*, *>) r["verifyKey"] = pub(r["verifyKey"])
        return r
    }

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    @Test fun genCorpusIsPresent() = net.atlasauth.pca.verifier.BaseOracle.requireGen(m)

    @Test fun constants() = OracleCases.each(m, "constants") { _ ->
        linkedMapOf<String, Any?>(
            "EAT_TYP" to AttestEat.EAT_TYP,
            "DEFAULT_EAT_ALG" to AttestEat.DEFAULT_EAT_ALG,
            "DEFAULT_MAX_AGE_MS" to AttestEat.DEFAULT_MAX_AGE_MS,
            "CHANNEL_BINDING_DOMAIN" to AttestEat.CHANNEL_BINDING_DOMAIN,
            "AMD_SEV_SNP_SIGNED_REGION_END" to AttestEat.AMD_SEV_SNP_SIGNED_REGION_END,
            "AMD_SEV_SNP_HARDWARE_ROOT_LABEL" to AttestEat.AMD_SEV_SNP_HARDWARE_ROOT_LABEL,
            "KNOWN_REPORT_VERSIONS" to AttestEat.KNOWN_REPORT_VERSIONS,
            "KNOWN_AMD_ARK_SPKI_SHA384" to AttestEat.KNOWN_AMD_ARK_SPKI_SHA384,
            "AMD_MILAN_ARK_SPKI_SHA384" to AttestEat.AMD_MILAN_ARK_SPKI_SHA384,
            "PQCOSIGN_DOMAIN" to AttestEatPq.PQCOSIGN_DOMAIN,
            "DEFAULT_PQ_COSIGN_SUITE" to AttestEatPq.DEFAULT_PQ_COSIGN_SUITE,
            "PQ_COSIGN_SUITES" to AttestEatPq.PQ_COSIGN_SUITES,
        )
    }

    @Test fun deriveChannelCnf() = OracleCases.each(m, "deriveChannelCnf") { a -> AttestEat.deriveChannelCnf(a[0], arg(a, 1)) }

    @Test fun bindChannel() = OracleCases.each(m, "bindChannel") { a -> AttestEat.bindChannel(a[0], a[1], a[2]) }

    @Test fun buildEAT() = OracleCases.each(m, "buildEAT") { a ->
        val args = LinkedHashMap(map(a[0]))
        if (args["key"] is Map<*, *>) args["key"] = priv(args["key"])
        AttestEat.buildEAT(args)
    }

    @Test fun verifyEAT() = OracleCases.each(m, "verifyEAT") { a -> AttestEat.verifyEAT(a[0], pub(a[1]), if (a.size > 2) map(a[2]) else LinkedHashMap()) }

    /**
     * Cases where the port is stricter than these vectors (a present clock skew that is not a finite number; a minimum tier other than
     * affirming / affirming-hw-rooted): the current reference refuses them too, the vectors predate that fix. Each must refuse.
     */
    private val stricter = setOf(
        "verifyFreshness/skew junk string", "verifyFreshness/skew junk stale", "verifyFreshness/skew string number", "verifyFreshness/skew null",
        "verifyFreshness/skew true", "verifyFreshAttestedEAT/amd skew junk", "eatAdmissionEvidence/min tier unknown", "eatAdmissionEvidence/min tier null",
    )

    private fun eachStrict(fn: String, f: (List<Any?>) -> Any?) {
        val bad = ArrayList<String>()
        for (c in OracleCases.of(m, fn)) {
            @Suppress("UNCHECKED_CAST")
            val args = c["args"] as List<Any?>
            if (stricter.contains(c["name"])) {
                val got = f(args)
                if (got !is Map<*, *> || got["ok"] != false) bad.add("${c["name"]} was not refused: $got")
            } else {
                val d = OracleCases.diff(c, c["out"], f)
                if (d != null) bad.add(d)
            }
        }
        assertTrue(bad.joinToString("\n"), bad.isEmpty())
    }

    @Test fun verifyFreshness() = eachStrict("verifyFreshness") { a ->
        // a call without a usable `now` reads the wall clock, which the corpus froze at its case clock
        val opts = LinkedHashMap(map(a[1]))
        val n = net.atlasauth.pca.verifier.IntentJs.num(opts["now"])
        if (n == null || n.isNaN() || n.isInfinite()) opts["now"] = net.atlasauth.pca.verifier.Json.Num(java.math.BigDecimal(net.atlasauth.pca.verifier.BaseOracle.clockMs("$m.json.gz")).toPlainString())
        AttestEat.verifyFreshness(map(a[0]), opts)
    }

    @Test fun nonFiniteSkewAndUnknownMinTierRefused() {
        val eat = linkedMapOf<String, Any?>("eat_nonce" to "n1", "iat" to 1_000_000_000L) // decades stale: only an unbounded skew would admit it
        for (skew in listOf<Any?>(Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, Double.NaN, "5", null, true)) {
            val o = linkedMapOf<String, Any?>("expectedNonce" to "n1", "now" to 1_800_000_000_000L, "maxAgeMs" to 60_000L, "clockSkewMs" to skew)
            val r = AttestEat.verifyFreshness(eat, o)
            assertEquals(skew.toString(), false, r["ok"])
            assertEquals(skew.toString(), "invalid clockSkewMs (must be a finite number)", r["reason"])
        }
        for (tier in listOf<Any?>("warning", "rejected", "bogus", null, 2L)) {
            val o = linkedMapOf<String, Any?>("instanceKey" to "k", "minTier" to tier)
            val r = AttestEatAdmission.eatAdmissionEvidence("x", o)
            assertEquals(tier.toString(), false, r["ok"])
            assertEquals(tier.toString(), false, r["bound"])
            assertEquals(tier.toString(), "invalid minTier", r["reason"])
        }
    }

    @Test fun verifyChannelBinding() = OracleCases.each(m, "verifyChannelBinding") { a -> AttestEat.verifyChannelBinding(map(a[0]), map(a[1])) }

    @Test fun appraise() = OracleCases.each(m, "appraise") { a ->
        val ev = map(a[0])
        when (a.size) {
            1 -> AttestEat.appraise(ev)
            2 -> AttestEat.appraise(ev, map(a[1]))
            3 -> AttestEat.appraise(ev, map(a[1]), map(a[2]))
            else -> AttestEat.appraise(ev, map(a[1]), map(a[2]), map(a[3]))
        }
    }

    @Test fun parseReportTolerant() = OracleCases.each(m, "parseReportTolerant") { a ->
        val r = AttestEat.parseReportTolerant(bytes(a[0]))
        val out = LinkedHashMap<String, Any?>()
        for (k in listOf("ok", "version", "known", "degraded", "notes")) out[k] = r[k]
        out["hasReport"] = r.containsKey("report")
        if (r.containsKey("evidence")) out["evidence"] = r["evidence"]
        if (r.containsKey("report")) out["measured"] = AttestEat.measuredFromReport(map(r["report"]))
        out
    }

    // ---- AMD hardware root + composition ----

    @Test fun verifyAmdAttestation() = OracleCases.each(m, "verifyAmdAttestation") { a ->
        val r = AttestEat.verifyAmdAttestation(bytes(a[0]), map(rev(a[1])))
        val out = LinkedHashMap<String, Any?>()
        out["ok"] = r["ok"]
        out["hardwareRoot"] = r["hardwareRoot"]
        if (r.containsKey("reason")) out["reason"] = r["reason"]
        if (r.containsKey("evidence")) out["evidence"] = r["evidence"]
        if (r.containsKey("measured")) out["measured"] = r["measured"]
        out
    }

    @Test fun verifyFreshAttestedEAT() = eachStrict("verifyFreshAttestedEAT") { a -> AttestEat.verifyFreshAttestedEAT(a[0], verifyOpts(a[1])) }

    // ---- post-quantum co-signature ----

    private fun suiteKey(suite: String, spec: Any?): Keys.SuiteKey {
        val s = map(spec)
        val ed = if (s["ed"] != null) Keys.edFromSeed(Keys.unb64u(s["ed"] as String)) else null
        var pq: Keys.PqKey? = null
        if (s["pq"] != null) {
            val p = map(s["pq"])
            val prim = when (p["prim"] as String) {
                "ml-dsa-65" -> Pq.Prim.ML_DSA_65
                "ml-dsa-87" -> Pq.Prim.ML_DSA_87
                "slh-dsa-sha2-128f" -> Pq.Prim.SLH_DSA_SHA2_128F
                else -> Pq.Prim.SLH_DSA_SHA2_256S
            }
            pq = Keys.pqFromSeed(prim, Keys.unb64u(p["seed"] as String))
        }
        return Keys.suite(suite, ed, pq)
    }

    @Test fun canonicalVerdictBytes() = OracleCases.each(m, "canonicalVerdictBytes") { a -> AttestEatPq.canonicalVerdictBytes(map(a[0]), a[1]) }

    @Test fun verdictFromAppraisal() = OracleCases.each(m, "verdictFromAppraisal") { a -> AttestEatPq.verdictFromAppraisal(map(a[0]), map(a[1])) }

    @Test fun isPqCoSignSuite() = OracleCases.each(m, "isPqCoSignSuite") { a -> AttestEatPq.isPqCoSignSuite(arg(a, 0)) }

    @Test fun coSignAttestation() = OracleCases.each(m, "coSignAttestation") { a ->
        val op = map(a[1])
        val suite = if (op["suite"] is String) op["suite"] as String else AttestEatPq.DEFAULT_PQ_COSIGN_SUITE
        val o = AttestEatPq.CoSignOptions(suiteKey(suite, op["key"]))
        if (op["suite"] != null) o.suite = suite
        o.now = op["now"]
        AttestEatPq.coSignAttestation(map(a[0]), o)
    }

    /**
     * A call without a usable `now` ages the co-signature against the wall clock, which the corpus froze to a fixed instant; every other member is compared
     * as it is, and the age must be the live clock minus the co-signing time (any other value fails).
     */
    @Test fun verifyCoSignedAttestation() {
        val bad = ArrayList<String>()
        for (c in OracleCases.of(m, "verifyCoSignedAttestation")) {
            @Suppress("UNCHECKED_CAST")
            val a = c["args"] as List<Any?>
            val want = c["out"]
            val d = OracleCases.diff(c, want) { x ->
                val r = AttestEatPq.verifyCoSignedAttestation(x[0], if (x.size > 1) map(x[1]) else null)
                val usesClock = x.size < 2 || net.atlasauth.pca.verifier.IntentJs.num(map(x[1])["now"]) == null
                if (usesClock && r is Map<*, *> && r["ok"] == true && want is Map<*, *> && want["ageMs"] != null) {
                    val age = net.atlasauth.pca.verifier.IntentJs.num(r["ageMs"])!!
                    val cosigned = net.atlasauth.pca.verifier.IntentJs.num(r["cosignedAt"])!!
                    assertTrue("${c["name"]}: age is not the live clock minus the co-signing time", Math.abs(age + cosigned - System.currentTimeMillis()) < 60_000)
                    LinkedHashMap(r as Map<String, Any?>).also { it["ageMs"] = want["ageMs"] }
                } else r
            }
            if (d != null) bad.add(d)
        }
        assertTrue(bad.joinToString("\n"), bad.isEmpty())
    }

    // ---- admission + provenance ----

    @Test fun ed25519Jkt() = OracleCases.each(m, "ed25519Jkt") { a -> AttestEatAdmission.ed25519Jkt(a[0] as String) }

    @Test fun eatAdmissionEvidence() = eachStrict("eatAdmissionEvidence") { a -> AttestEatAdmission.eatAdmissionEvidence(a[0], verifyOpts(a[1])) }

    @Test fun runtimeDigestFromEat() = OracleCases.each(m, "runtimeDigestFromEat") { a ->
        AttestEatProvenance.runtimeDigestFromEat(a[0], if (a.size > 1) map(a[1]) else null)
    }

    @Test fun issueArtifactDischarge() = OracleCases.each(m, "issueArtifactDischarge") { a ->
        val i = LinkedHashMap(map(a[0]))
        i["roots"] = Sigstore.parseTrustedRoot(i["roots"])
        i["issuerKey"] = Keys.ed25519(Keys.edFromSeed(Keys.unb64u(map(i["issuerKey"])["seed"] as String)))
        var n = 0
        val nonce: () -> ByteArray = { MessageDigest.getInstance("SHA-256").digest("eat-oracle-nonce/${n++}".toByteArray(Charsets.UTF_8)).copyOf(16) }
        AttestEatProvenance.issueArtifactDischarge(i, nonce)
    }
}
