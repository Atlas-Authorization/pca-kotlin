package net.atlasauth.pca.attesteat

import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pq

/**
 * POST-QUANTUM co-signature of a verified attestation verdict. After the classical AMD hardware root has been verified, the verdict's
 * security-relevant fields are bound under a post-quantum signature (ML-DSA-65 by default, or a hybrid / nested / category-5 suite),
 * so PCA's propagation of the verdict no longer rests on classical crypto. This does NOT make AMD's root post-quantum; it makes the
 * recorded verdict forward-secure. A classical-only suite is refused (fail closed).
 *
 * A verdict is the JSON-shaped map {tier, trustworthy, measured?, measurement?, nonce?, iat?, issuer?}; a co-signed attestation is
 * {verdict, cosig: {cosignedAt, sig, pq_sig?}, suite, signer_pub: {pq, ed?}}.
 */
object AttestEatPq {
    const val PQCOSIGN_DOMAIN = "atlas-pca/attest-cosign/v1"
    const val DEFAULT_PQ_COSIGN_SUITE = "ml-dsa-65"
    val PQ_COSIGN_SUITES: List<String> = listOf(
        "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65",
        "hybrid-ed25519-ml-dsa-87", "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s",
    )

    /** Type guard: [x] is one of the accepted PQ co-sign suites (rejects ed25519, unknown names, non-strings). */
    fun isPqCoSignSuite(x: Any?): Boolean = x is String && PQ_COSIGN_SUITES.contains(x)

    private fun canonicalMeasured(verdict: Map<String, Any?>): Any? {
        if (!verdict.containsKey("measured")) return null
        val mo = verdict["measured"] ?: throw IllegalArgumentException("Cannot read properties of null (reading 'model_id')")
        val m = AttestEat.rec(mo)
        val out = LinkedHashMap<String, Any?>()
        for (k in listOf("model_id", "weights_digest")) if (m != null && m.containsKey(k)) out[k] = m[k]
        out["weights_measured"] = if (m != null && m["weights_measured"] is Boolean) m["weights_measured"] else null
        for (k in listOf("runtime_measurement", "operator")) if (m != null && m.containsKey(k)) out[k] = m[k]
        out["system_prompt_digest"] = if (m != null && m["system_prompt_digest"] is String) m["system_prompt_digest"] else null
        out["tool_manifest_digest"] = if (m != null && m["tool_manifest_digest"] is String) m["tool_manifest_digest"] else null
        return out
    }

    /**
     * The CANONICAL, DETERMINISTIC bytes the co-signature is computed over: `utf8(JSON.stringify(obj))` with `obj` in the fixed order
     * typ, tier, trustworthy, measurement, measured, nonce, iat, issuer, cosignedAt, every optional emitted as its value or null.
     */
    fun canonicalVerdictBytes(verdict: Map<String, Any?>, cosignedAt: Any?): ByteArray {
        val c = LinkedHashMap<String, Any?>()
        c["typ"] = PQCOSIGN_DOMAIN
        if (verdict.containsKey("tier")) c["tier"] = verdict["tier"]
        c["trustworthy"] = verdict["trustworthy"] == true
        c["measurement"] = if (verdict["measurement"] is String) verdict["measurement"] else null
        c["measured"] = canonicalMeasured(verdict)
        c["nonce"] = if (verdict["nonce"] is String) verdict["nonce"] else null
        val iat = Js.num(verdict["iat"])
        c["iat"] = if (iat != null && !iat.isNaN() && !iat.isInfinite()) verdict["iat"] else null
        c["issuer"] = if (verdict["issuer"] is String) verdict["issuer"] else null
        if (cosignedAt != null) c["cosignedAt"] = cosignedAt
        return Json.utf8(Jose.stringify(c))
    }

    /** Build a verdict from an [AttestEat.appraise] result plus the EAT claims (tier, trustworthy, measured, measurement, nonce, iat, issuer). */
    fun verdictFromAppraisal(result: Map<String, Any?>, claims: Map<String, Any?>): Map<String, Any?> {
        val v = LinkedHashMap<String, Any?>()
        v["tier"] = result["tier"]
        v["trustworthy"] = result["trustworthy"]
        if (claims.containsKey("measured")) v["measured"] = claims["measured"]
        val rm = (claims["measured"] as? Map<*, *>)?.get("runtime_measurement")
        val measurement: Any? = if (rm is String && rm.isNotEmpty()) rm else (claims["sevsnp"] as? Map<*, *>)?.get("measurement")
        if (measurement is String && measurement.isNotEmpty()) v["measurement"] = measurement
        if (claims["eat_nonce"] is String) v["nonce"] = claims["eat_nonce"]
        val iat = Js.num(claims["iat"])
        if (iat != null && !iat.isNaN() && !iat.isInfinite()) v["iat"] = claims["iat"]
        if (claims["iss"] is String) v["issuer"] = claims["iss"]
        return v
    }

    /** Options of [coSignAttestation]. */
    class CoSignOptions(
        /** The co-signer's key material for that suite ([Keys.suite]). */
        @JvmField var secretKey: Keys.SuiteKey?,
    ) {
        /** The suite name (default [DEFAULT_PQ_COSIGN_SUITE]); a classical-only or unknown suite is refused. */
        @JvmField var suite: String? = null

        /** Pin the co-sign timestamp (epoch ms, a JSON-shaped number) for a deterministic signature; null = now. */
        @JvmField var now: Any? = null
    }

    /**
     * Co-sign a verified attestation verdict under a post-quantum suite. Call AFTER the classical hardware verification has passed.
     * FAIL-CLOSED on misconfiguration: a classical-only or unknown suite, or key material for a different suite, THROWS.
     */
    fun coSignAttestation(verdict: Map<String, Any?>, opts: CoSignOptions): Map<String, Any?> {
        val suiteName = opts.suite ?: DEFAULT_PQ_COSIGN_SUITE
        if (!isPqCoSignSuite(suiteName)) throw IllegalArgumentException("coSignAttestation: '$suiteName' is not an accepted post-quantum co-sign suite")
        val key = opts.secretKey ?: throw IllegalArgumentException("coSignAttestation: secretKey material is required")
        if (suiteName != key.alg) throw IllegalArgumentException("coSignAttestation: suite '$suiteName' requires key material for that suite")
        val nowD = Js.num(opts.now)
        val cosignedAt: Any? = if (nowD != null && !nowD.isNaN() && !nowD.isInfinite()) opts.now else System.currentTimeMillis()
        val msg = canonicalVerdictBytes(verdict, cosignedAt)
        val signerPub = LinkedHashMap<String, Any?>()
        signerPub["pq"] = key.pq!!.pkB64u()
        if (key.ed != null) signerPub["ed"] = key.ed.id()
        val parts = key.sign(msg)
        val cosig = LinkedHashMap<String, Any?>()
        cosig["cosignedAt"] = cosignedAt
        cosig["sig"] = parts.first
        if (parts.second != null) cosig["pq_sig"] = parts.second
        val out = LinkedHashMap<String, Any?>()
        out["verdict"] = verdict
        out["cosig"] = cosig
        out["suite"] = suiteName
        out["signer_pub"] = signerPub
        return out
    }

    private fun parseSignerPub(v: Any?): Map<String, Any?>? {
        val r = AttestEat.rec(v)
        val pq = r?.get("pq")
        if (r == null || pq !is String || pq.isEmpty()) return null
        val out = LinkedHashMap<String, Any?>()
        out["pq"] = pq
        val ed = r["ed"]
        if (ed is String && ed.isNotEmpty()) out["ed"] = ed
        return out
    }

    private fun signerMatches(expected: Any?, got: Map<String, Any?>): Boolean {
        val expPq: Any? = when (expected) {
            is String -> expected
            null -> throw IllegalArgumentException("Cannot read properties of null (reading 'pq')")
            is Map<*, *> -> expected["pq"]
            else -> null
        }
        if (expPq !is String || !AttestEat.strEq(expPq, got["pq"] as String)) return false
        val e = AttestEat.rec(expected)
        val ee = e?.get("ed")
        if (ee is String) {
            val ge = got["ed"]
            if (ge !is String || !AttestEat.strEq(ee, ge)) return false
        }
        return true
    }

    private fun numOut(d: Double): Any = if (d == Math.rint(d) && Math.abs(d) < 9007199254740992.0) d.toLong() else d

    private fun jsString(v: Any?): String = when (v) {
        null -> "null"
        is String, is Boolean -> v.toString()
        is Json.Num -> Json.canonicalize(v)
        is List<*> -> ""
        else -> "[object Object]"
    }

    private fun fail(partial: Map<String, Any?>, reason: String): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>(partial)
        m["ok"] = false
        m["reason"] = reason
        return m
    }

    /**
     * Verify a co-signed attestation: recompute the canonical verdict bytes from the artifact's OWN verdict and co-sign time and check
     * the post-quantum signature under the embedded signer key. FAIL CLOSED on a malformed artifact, a classical-only or unknown suite,
     * a tampered verdict, a wrong key, an `expectedSigner` mismatch (a b64u PQ key string or {pq, ed?}), or a co-signature older than
     * `maxAgeMs`. [opts]: expectedSigner?, maxAgeMs?, now?. Never throws. Result {ok, reason?, suite?, verdict?, signer_pub?, cosignedAt?, ageMs?}.
     */
    fun verifyCoSignedAttestation(cosigned: Any?, opts: Map<String, Any?>? = null): Map<String, Any?> {
        val o = opts ?: LinkedHashMap()
        try {
            val c = AttestEat.rec(cosigned) ?: return fail(LinkedHashMap(), "co-signed attestation is not an object")
            val verdict = AttestEat.rec(c["verdict"])
            if (verdict == null || verdict["tier"] !is String || verdict["trustworthy"] !is Boolean) {
                return fail(LinkedHashMap(), "verdict is missing or has a non-string tier / non-boolean trustworthy")
            }
            val cosig = AttestEat.rec(c["cosig"])
            val cat = if (cosig == null) null else Js.num(cosig["cosignedAt"])
            if (cosig == null || cat == null || cat.isNaN() || cat.isInfinite() || cosig["sig"] !is String) {
                return fail(LinkedHashMap(), "cosig is missing or has a non-numeric cosignedAt / non-string sig")
            }
            if (!isPqCoSignSuite(c["suite"])) {
                return fail(LinkedHashMap(), "suite '" + (if (c.containsKey("suite")) jsString(c["suite"]) else "undefined") + "' is not an accepted post-quantum co-sign suite")
            }
            val suite = c["suite"] as String
            val signerPub = parseSignerPub(c["signer_pub"]) ?: return fail(LinkedHashMap(), "signer_pub is missing or has no post-quantum public key")

            val nowD = Js.num(o["now"])
            val now = if (nowD != null && !nowD.isNaN() && !nowD.isInfinite()) nowD else System.currentTimeMillis().toDouble()
            val ageMs = now - cat
            val partial = LinkedHashMap<String, Any?>()
            partial["ok"] = false
            partial["suite"] = suite
            partial["verdict"] = c["verdict"]
            partial["signer_pub"] = signerPub
            partial["cosignedAt"] = cosig["cosignedAt"]
            partial["ageMs"] = numOut(ageMs)

            if (o.containsKey("expectedSigner") && !signerMatches(o["expectedSigner"], signerPub)) return fail(partial, "co-signer public key does not match the expected signer")
            if (o.containsKey("maxAgeMs")) {
                val max = Js.num(o["maxAgeMs"])
                if (max == null || max.isNaN() || max.isInfinite() || max <= 0) return fail(partial, "invalid maxAgeMs")
                if (cat > now) return fail(partial, "co-sign timestamp is in the future")
                if (ageMs > max) return fail(partial, "co-signature is stale (older than maxAgeMs)")
            }
            val msg = canonicalVerdictBytes(verdict, cosig["cosignedAt"])
            val hybrid = suite.startsWith("hybrid-")
            val good = Pq.verifyArtifactSignature(suite, if (hybrid) signerPub["ed"] as String? else null, signerPub["pq"], msg, cosig["sig"], cosig["pq_sig"])
            if (!good) return fail(partial, "post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)")
            val ok = LinkedHashMap<String, Any?>(partial)
            ok["ok"] = true
            return ok
        } catch (e: RuntimeException) {
            return fail(LinkedHashMap(), "co-signature verification error (fail closed): " + (e.message ?: "unknown"))
        }
    }
}
