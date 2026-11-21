package net.atlasauth.pca.spiffe

import java.util.Base64
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle for the SPIFFE package (see the oracle header for the case shapes). */
@Suppress("UNCHECKED_CAST")
class SpiffeDiffTest {
    private val m = "ref-spiffe"
    private val sub = "spiffe://example.org/workload/db"
    private val nowMs = 1_800_000_060_000L

    /** A failure with the reference's code: the SpiffeError code, or "jose" for any other failure. */
    class Fail(val code: String, cause: Throwable) : RuntimeException(cause)

    private fun <T> w(c: () -> T): T = try {
        c()
    } catch (e: SpiffeError) {
        throw Fail(e.code, e)
    } catch (e: Throwable) {
        throw Fail("jose", e)
    }

    private fun mm(o: Any?) = o as Map<String, Any?>
    private fun l(o: Any?) = o as List<Any?>
    private fun n(o: Any?) = o.toString().toLong()
    private fun num(v: Long) = Json.Num(v.toString())

    /** {"$bytes": b64url} to bytes; anything else unchanged. */
    private fun bytes(o: Any?): Any? = if (o is Map<*, *> && o.size == 1 && o["\$bytes"] is String) Base64.getUrlDecoder().decode(o["\$bytes"] as String) else o

    private fun chainOf(c: Any?): Any? = if (c is List<*>) c.map { bytes(it) } else c

    @Test fun constants() = OracleCases.each(m, "constants") { linkedMapOf("JWT_SVID_ALGORITHMS" to ArrayList<Any?>(Spiffe.JWT_SVID_ALGORITHMS)) }
    @Test fun parseSpiffeId() = OracleCases.each(m, "parseSpiffeId") { a -> w { Spiffe.parseSpiffeId(a[0]).toJson() } }
    @Test fun holderBindingMessage() = OracleCases.each(m, "holderBindingMessage") { Spiffe.holderBindingMessage(it[0] as String, it[1] as String) }

    @Test fun holderToSpiffeId() = OracleCases.each(m, "holderToSpiffeId") { a ->
        val h = mm(a[0])
        w { Spiffe.holderToSpiffeId(Spiffe.SpiffeHolder(h["holder"] as String, h["spiffeId"] as String, h["trustDomain"] as String, h["path"] as String)) }
    }

    @Test fun readCertFacts() = OracleCases.each(m, "readCertFacts") { SpiffeDer.readCertFacts(Base64.getUrlDecoder().decode(it[0] as String)).toJson() }

    @Test fun parseX509Svid() = OracleCases.each(m, "parseX509Svid") { a ->
        w {
            val s = Spiffe.parseX509Svid(bytes(a[0]))
            linkedMapOf("spiffeId" to s.spiffeId.toJson(), "publicKeyDer" to s.publicKeyDer)
        }
    }

    // ---- verifyX509Svid

    private fun x509Rev(mode: String?, calls: MutableList<Any?>): Any? = when (mode) {
        null -> null
        "notfn" -> Spiffe.NOT_A_FUNCTION
        else -> Spiffe.X509RevocationCheck { s ->
            calls.add(s.toJson())
            when {
                mode == "false" -> false
                mode == "true" -> true
                mode == "throw" -> throw IllegalStateException("boom")
                mode == "one" -> 1L
                mode.startsWith("true@") -> s.position == mode.substring(5).toInt()
                else -> Any() // undef / promise: not a boolean
            }
        }
    }

    private fun x509Opts(o: Map<String, Any?>, calls: MutableList<Any?>) = Spiffe.VerifyX509SvidOptions().apply {
        trustDomain = o["trustDomain"] as String?
        roots = l(o["roots"]).map { bytes(it) }
        if (o["nowMs"] != null) nowMs = n(o["nowMs"])
        if (o["maxChainLength"] != null) maxChainLength = n(o["maxChainLength"]).toInt()
        revocation = x509Rev(o["revocation"] as String?, calls)
    }

    @Test fun verifyX509Svid() = OracleCases.each(m, "verifyX509Svid") { a ->
        w {
            val calls = ArrayList<Any?>()
            val r = Spiffe.verifyX509Svid(chainOf(a[0]), x509Opts(mm(a[1]), calls))
            linkedMapOf("spiffeId" to r.spiffeId.toJson(), "publicKeyDer" to r.publicKeyDer, "calls" to calls)
        }
    }

    // ---- JWT-SVID

    private fun jwtRev(mode: String?, calls: MutableList<Any?>): Any? = when (mode) {
        null -> null
        "notfn" -> Spiffe.NOT_A_FUNCTION
        else -> Spiffe.JwtRevocationCheck { s ->
            calls.add(s.toJson())
            when (mode) {
                "false", "async-false" -> false
                "true", "async-true" -> true
                "throw", "async-throw" -> throw IllegalStateException("boom")
                "one" -> 1L
                else -> Any()
            }
        }
    }

    private fun jwtOpts(s: Map<String, Any?>, key: Any?, calls: MutableList<Any?>) = Spiffe.VerifyJwtSvidOptions().apply {
        val aud = s["audience"]
        audience = if (aud is String) listOf(aud) else l(aud).map { it as String }
        trustDomain = s["trustDomain"] as String?
        if (s["currentDateMs"] != null) currentDateMs = n(s["currentDateMs"])
        if (s["algorithms"] != null) algorithms = l(s["algorithms"]).map { it as String }
        if (s["clockTolerance"] != null) clockTolerance = s["clockTolerance"]
        revocation = jwtRev(s["revocation"] as String?, calls)
        this.key = key
    }

    private fun jwtKeyOf(keySpec: Map<String, Any?>): Any? {
        if (keySpec["jwk"] != null) return mm(keySpec["jwk"])
        val jwks = mm(mm(keySpec["bundle"])["jwks"])
        return Spiffe.createTrustBundleSource({ linkedMapOf("jwks" to jwks) }, 1000.0, 5000.0, { nowMs }).jwtKey
    }

    @Test fun jwtSession() = OracleCases.each(m, "jwtSession") { a ->
        w {
            val s = mm(a[0])
            val calls = ArrayList<Any?>()
            val r = Spiffe.verifyJwtSvid(s["token"] as String, jwtOpts(s, jwtKeyOf(mm(s["key"])), calls))
            linkedMapOf("spiffeId" to r.spiffeId.toJson(), "claims" to r.claims, "audience" to r.audience, "expiresAt" to r.expiresAt, "calls" to calls)
        }
    }

    // ---- holder binding

    private fun bind(s: Map<String, Any?>) = Spiffe.SvidToHolderOptions().apply {
        if (s["proof"] != null) proof = s["proof"] as String
        acceptUnboundJwtHolder = s["acceptUnbound"] == true || s["acceptUnboundJwtHolder"] == true
    }

    @Test fun holderSession() = OracleCases.each(m, "holderSession") { a ->
        w {
            val s = mm(a[0])
            val svid: Any? = when (s["svid"]) {
                "x509" -> Spiffe.verifyX509Svid(s["chain"], Spiffe.VerifyX509SvidOptions().apply { trustDomain = "example.org"; roots = l(s["roots"]); nowMs = n(s["nowMs"]) })
                "x509-parsed" -> Spiffe.parseX509Svid(s["chain"])
                "jwt" -> mm(s["jwt"]).let { j -> Spiffe.verifyJwtSvid(j["token"] as String, jwtOpts(j, mm(j["jwk"]), ArrayList())) }
                "string" -> sub
                "parsed-id" -> Spiffe.parseSpiffeId(sub)
                "hand-built" -> linkedMapOf("claims" to linkedMapOf<String, Any?>())
                else -> null
            }
            val o = bind(s)
            val hk = s["holderKey"]
            when (s["op"]) {
                // an explicit JSON null is a value (refused as a key), unlike an absent member, which asks for the key to be derived from the SVID
                "holder" -> linkedMapOf("holder" to Spiffe.svidToHolder(svid, if (hk == null && s.containsKey("holderKey")) Any() else bytes(hk), o).toJson())
                "forHolder" -> {
                    if (hk == null || hk is String) linkedMapOf("spiffeId" to Spiffe.spiffeIdForHolder(svid, hk as String?, o))
                    else {
                        Spiffe.svidToHolder(svid, hk, o) // a non-string key is refused (a raw object is not a key)
                        throw IllegalStateException("unreachable: a non-string holder key was accepted")
                    }
                }
                else -> linkedMapOf("pin" to Spiffe.workloadDischargePin(s["label"] as String?, svid))
            }
        }
    }

    // ---- caches (manual clock)

    private fun cacheSession(revocation: Boolean, s: Map<String, Any?>): Map<String, Any?> {
        var t = n(s["start"])
        var fetchCalls = 0
        val fetches = l(s["fetches"])
        val fetch = Spiffe.Fetch {
            val f = mm(fetches[Math.min(fetchCalls, fetches.size - 1)])
            fetchCalls++
            if (f["throw"] == true) throw IllegalStateException("fetch failed")
            f["list"]
        }
        val refreshMs = s["refreshMs"].toString().toDouble()
        val maxStaleMs = s["maxStaleMs"].toString().toDouble()
        val rs = if (revocation) Spiffe.createRevocationSource(fetch, refreshMs, maxStaleMs) { t } else null
        val bs = if (revocation) null else Spiffe.createTrustBundleSource(fetch, refreshMs, maxStaleMs) { t }
        val out = ArrayList<Any?>()
        for (so in l(s["steps"])) {
            val st = mm(so)
            val op = st["op"] as String
            try {
                if (op == "adv") {
                    t += n(st["ms"])
                    out.add(linkedMapOf("v" to num(t)))
                    continue
                }
                val v: Any? = when (op) {
                    "x509" -> mm(st["subject"]).let { x ->
                        rs!!.x509.check(Spiffe.X509RevocationSubject(x["spiffeId"] as String, x["serialNumber"] as String, x["fingerprint256"] as String, n(x["position"]).toInt(), x["isLeaf"] == true))
                    }
                    "jwt" -> mm(st["subject"]).let { x ->
                        rs!!.jwt.check(Spiffe.JwtRevocationSubject(x["spiffeId"] as String, x["jti"] as String?, x["expiresAt"], x["tokenHash"] as String))
                    }
                    "refresh" -> { rs!!.refresh(); null }
                    "ensureFresh" -> { rs!!.ensureFresh(); null }
                    "x509Roots" -> bs!!.x509Roots()
                    else -> {
                        val k = bs!!.jwtKey.resolve(mm(st["header"]), null)
                        val proj = linkedMapOf<String, Any?>("kty" to k["kty"])
                        for (f in listOf("crv", "x", "n")) if (k[f] != null) proj[f] = k[f]
                        proj
                    }
                }
                out.add(linkedMapOf("v" to v))
            } catch (e: SpiffeError) {
                out.add(linkedMapOf("code" to e.code))
            } catch (e: Exception) {
                out.add(linkedMapOf("code" to "jose"))
            }
        }
        return linkedMapOf("steps" to out, "fetchCalls" to num(fetchCalls.toLong()))
    }

    @Test fun revocationSession() = OracleCases.each(m, "revocationSession") { a -> w { cacheSession(true, mm(a[0])) } }
    @Test fun bundleSession() = OracleCases.each(m, "bundleSession") { a -> w { cacheSession(false, mm(a[0])) } }

    // ---- admission

    private val known = setOf(
        "malformed_spiffe_id", "empty_trust_domain", "trust_domain_too_long", "invalid_trust_domain", "invalid_path", "id_too_long", "missing_audience", "missing_exp",
        "malformed_token", "invalid_subject", "trust_domain_mismatch", "no_uri_san", "multiple_uri_san", "invalid_holder_key", "unverified_svid", "missing_trust_domain",
        "holder_binding_failed", "malformed_certificate", "leaf_is_ca", "leaf_no_digital_signature", "leaf_cert_sign", "leaf_crl_sign", "leaf_root_path",
        "unsupported_critical_extension", "forbidden_algorithm", "invalid_typ", "chain_empty", "chain_trust_domain_mismatch", "chain_signature", "chain_not_ca",
        "chain_no_key_cert_sign", "chain_path_len", "chain_expired", "chain_untrusted_root", "chain_too_long", "trust_bundle_unavailable", "trust_bundle_invalid",
        "svid_revoked", "chain_revoked", "revocation_unavailable", "SVID is bound to a different key",
    )

    @Test fun admission() = OracleCases.each(m, "admission") { a ->
        val s = mm(a[0])
        val e = Spiffe.SpiffeEvidence()
        e.kind = s["kind"] as String?
        if (s["bind"] != null) e.bind = bind(mm(s["bind"]))
        if (e.kind == "x509") {
            e.chain = s["chain"]
            e.verifyX509 = Spiffe.VerifyX509SvidOptions().apply { trustDomain = "example.org"; roots = l(s["roots"]); nowMs = n(s["nowMs"]) }
        } else {
            e.token = s["token"] as String?
            e.verifyJwt = Spiffe.VerifyJwtSvidOptions().apply { audience = listOf("api"); trustDomain = "example.org"; currentDateMs = nowMs; key = mm(s["jwk"]) }
        }
        val r = LinkedHashMap(Spiffe.spiffeAdmissionEvidence(e, s["instanceKey"] as String?).toJson())
        if (r["reason"] != null && r["reason"] !in known) r["reason"] = "other"
        r
    }
}
