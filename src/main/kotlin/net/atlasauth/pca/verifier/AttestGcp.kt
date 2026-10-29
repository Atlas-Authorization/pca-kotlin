package net.atlasauth.pca.verifier

/**
 * Google Cloud Confidential Space: the attestation token (RS256, ES256 defensively) verified under a signing key anchored in the
 * configured trust anchors (a pinned JWKS, SPKI pins or an x5c chain to a configured root), with iss / time window, the
 * Confidential Space claims, the eat_nonce binding and the workload image-digest allowlist. Same checks, order and reason text as
 * the reference verifier. Classical; no network I/O.
 */
internal object AttestGcp {
    private class Verifier(
        val issuers: Set<String>,
        val trustedKeys: List<Map<String, Any?>?>,
        val spkiPins: Set<String>,
        val rootCertsPem: List<String>,
        val images: Set<String>,
        val teeTypes: Set<String>?,
        val swName: String,
        val swVersions: Set<String>?,
        val allowDebug: Boolean,
        val nonceHash: String,
        val skew: Double,
    ) : Attest.VendorImpl {

        /** A public key from a JWK (RSA n/e, EC x/y, or the leaf of an x5c chain): the key, or the reason on failure. */
        private fun jwkKey(jwk: Map<String, Any?>): Pair<AttestCert.CertKey?, String> {
            val n = jwk["n"] as? String
            val e = jwk["e"] as? String
            if (n != null && e != null) {
                return try {
                    Pair(AttestJws.jwkRsaKey(n, e), "")
                } catch (x: AttErr) {
                    Pair(null, "JWKS key is not a usable public key: " + AttestUtil.errMsg(x))
                }
            }
            val crv = jwk["crv"] as? String
            val x = jwk["x"] as? String
            val y = jwk["y"] as? String
            if (jwk["kty"] == "EC" && crv != null && x != null && y != null) {
                return try {
                    Pair(AttestJws.jwkEcKey(crv, x, y), "")
                } catch (ex: AttErr) {
                    Pair(null, "JWKS key is not a usable public key: " + AttestUtil.errMsg(ex))
                }
            }
            val x5c = jwk["x5c"] as? List<*>
            if (x5c != null && x5c.isNotEmpty()) {
                val s = x5c[0] as? String
                if (s != null) {
                    return try {
                        val c = AttestCert.parseCertDer(AttestUtil.nodeB64(s))
                        Pair(AttestCert.keyOfCert(c), "")
                    } catch (ex: AttErr) {
                        Pair(null, "JWKS key is not a usable public key: " + AttestUtil.errMsg(ex))
                    }
                }
            }
            return Pair(null, "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate")
        }

        /** Verifies a JWK x5c chain to a configured SPKI pin or root certificate; "" when it anchors. */
        private fun verifyJwkX5cChain(x5c: List<Any?>, nowMs: Long): String {
            if (x5c.isEmpty()) return "empty x5c certificate chain"
            val certs = ArrayList<AttestCert.Cert>(x5c.size)
            for ((i, e) in x5c.withIndex()) {
                val b64 = e as? String
                if (b64 == null || b64.isEmpty()) return "empty x5c entry at index $i"
                val c = try {
                    AttestCert.parseCertDer(AttestUtil.nodeB64(b64))
                } catch (x: AttErr) {
                    return "malformed x5c certificate at index $i: ${AttestUtil.errMsg(x)}"
                }
                if (!AttestDer.derValidAtF(c.raw, nowMs, skew)) return "x5c certificate at index $i is outside its validity window"
                certs.add(c)
            }
            for (i in 0 until certs.size - 1) {
                if (!AttestCert.certSigOkBy(certs[i], certs[i + 1])) return "x5c link $i is not signed by the certificate above it"
            }
            for (c in certs) {
                val k = try { AttestCert.keyOfCert(c) } catch (x: AttErr) { null }
                if (k != null && spkiPins.contains(k.spkiSha256())) return ""
            }
            val top = certs[certs.size - 1]
            for (pemText in rootCertsPem) {
                val rk = rootKeyFromPem(pemText)
                if (rk != null && AttestCert.certSigOk(top, rk)) return ""
            }
            return "x5c chain does not anchor in a configured GCP trust root"
        }

        /** A trust root given as a certificate or as a bare public key. */
        private fun rootKeyFromPem(pemText: String): AttestCert.CertKey? {
            try {
                val c = AttestCert.certFromPem(pemText)
                return AttestCert.keyOfCert(c)
            } catch (e: AttErr) {
                // not a certificate: try a bare SubjectPublicKeyInfo
            }
            val m = Regex("-----BEGIN PUBLIC KEY-----([\\s\\S]*?)-----END PUBLIC KEY-----").find(pemText) ?: return null
            val body = m.groupValues[1].filter { it != ' ' && it != '\t' && it != '\r' && it != '\n' }
            val der = AttestUtil.base64Std(body) ?: return null
            return try {
                AttestCert.keyOfSpki(der)
            } catch (e: AttErr) {
                null
            }
        }

        /** The key the token was signed under: by kid if present, else the sole key. */
        private fun pickJwk(tok: AttestJws.Parsed, keys: List<Map<String, Any?>?>): Map<String, Any?>? {
            if (tok.hasKid && tok.kid.isNotEmpty()) {
                for (k in keys) {
                    val kid = k?.get("kid") as? String
                    if (kid != null && kid == tok.kid) return k
                }
                return null
            }
            if (keys.size == 1) return keys[0]
            return null
        }

        private fun mapList(v: Any?): List<Map<String, Any?>?> = ((v as? List<*>) ?: emptyList<Any?>()).map { AttestUtil.rec(it) }

        /** Resolves the token's signing key and confirms it is anchored: the key, or the failure reason. */
        private fun signingKey(tok: AttestJws.Parsed, evidenceJwks: Any?, nowMs: Long): Pair<AttestCert.CertKey?, String> {
            val evKeys = mapList(AttestUtil.rec(evidenceJwks)?.get("keys"))
            var jwk = pickJwk(tok, evKeys)
            var fromTrusted = false
            if (jwk == null) {
                jwk = pickJwk(tok, trustedKeys)
                fromTrusted = jwk != null
            }
            val hasKid = tok.hasKid && tok.kid.isNotEmpty()
            if (jwk == null && tok.hasX5c && tok.x5c.isNotEmpty()) jwk = mapOf("x5c" to ArrayList<Any?>(tok.x5c))
            if (jwk == null) {
                if (hasKid) return Pair(null, "no JWKS key matches the token kid '${tok.kid}' (untrusted signer)")
                return Pair(null, "no kid on the token and no unambiguous single signing key available")
            }
            val (key, why) = jwkKey(jwk)
            if (why != "" || key == null) return Pair(null, why)
            val spki = key.spkiSha256()
            if (fromTrusted || spkiPins.contains(spki)) return Pair(key, "")
            for (tk in trustedKeys) {
                if (tk == null) continue
                val (tb, w) = jwkKey(tk)
                if (w == "" && tb != null && tb.spkiSha256() == spki) return Pair(key, "")
            }
            val x5c = jwk["x5c"] as? List<Any?>
            if (x5c != null && x5c.isNotEmpty() && (rootCertsPem.isNotEmpty() || spkiPins.isNotEmpty())) {
                val chainErr = verifyJwkX5cChain(x5c, nowMs)
                return if (chainErr == "") Pair(key, "") else Pair(null, "signing key not trusted: $chainErr")
            }
            return Pair(null, "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)")
        }

        private fun jwsSignature(tok: AttestJws.Parsed, k: AttestCert.CertKey): String {
            val (kty, crv) = AttestJws.jwkKtyCrv(k)
            when (tok.alg) {
                "RS256" -> {
                    if (kty != "RSA") return "RS256 token but signing key is $kty (not RSA)"
                    if (!AttestJws.rs256Ok(tok.signature, tok.signingInput, k)) return "JWS RS256 signature does not verify under the Confidential Space signing key"
                    return ""
                }
                "ES256" -> {
                    if (kty != "EC" || crv != "P-256") return "ES256 token but signing key is $kty/$crv (not EC P-256)"
                    if (tok.signature.size != 64) return "ES256 signature is ${tok.signature.size} bytes (expected 64: r‖s)"
                    if (!AttestJws.es256Ok(tok.signature, tok.signingInput, k)) return "JWS ES256 signature does not verify under the Confidential Space signing key"
                    return ""
                }
            }
            return "unsupported JWS alg '${tok.alg}' (Confidential Space uses RS256)"
        }

        /** Maps a Confidential Space hwmodel to its isolation family ("" when unrecognised). */
        private fun teeTypeOf(hwmodel: String): String {
            when (hwmodel) {
                "GCP_AMD_SEV", "GCP_AMD_SEV_SNP", "GCP_AMD_SEV_ES" -> return "sev-snp"
                "GCP_INTEL_TDX" -> return "tdx"
            }
            val up = hwmodel.uppercase()
            if (up.startsWith("GCP_AMD_SEV")) return "sev-snp"
            if (up.startsWith("GCP_INTEL_TDX")) return "tdx"
            return ""
        }

        private fun nonceCandidates(v: Any?): List<String> {
            if (v is String) return if (v.isNotEmpty()) listOf(v) else emptyList()
            val arr = AttestUtil.asStrList(v) ?: return emptyList()
            return arr.filter { it.isNotEmpty() }
        }

        override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result {
            val token = ev?.get("token") as? String
            if (ev == null || token == null || token.isEmpty()) return Attest.fail("no GCP Confidential Space token for this action")
            val tok = try {
                AttestJws.parseJwt(token, "parseGcpCsJwt")
            } catch (e: AttErr) {
                return Attest.fail("Confidential Space token parse failed: " + e.message)
            }
            if (tok.alg != "RS256" && tok.alg != "ES256") return Attest.fail("unsupported JWS alg '${tok.alg}' (Confidential Space uses RS256)")
            val (key, why) = signingKey(tok, ev["jwks"], nowMs)
            if (why != "" || key == null) return Attest.fail("Confidential Space signing key invalid: $why")
            val sigErr = jwsSignature(tok, key)
            if (sigErr != "") return Attest.fail(sigErr)

            val payload = tok.payload
            val issV = payload["iss"]
            val iss = issV as? String ?: ""
            if (iss.isEmpty() || !issuers.contains(iss)) {
                val shown = if (issV !is String) "undefined" else iss
                return Attest.fail("token iss '$shown' is not a configured trusted Google attestation issuer")
            }
            val nowSec = Math.floor(nowMs.toDouble() / 1000)
            val skewSec = Math.ceil(skew / 1000)
            val exp = AttestUtil.asFinite(payload["exp"])
            val iat = AttestUtil.asFinite(payload["iat"])
            val nbf = AttestUtil.asFinite(payload["nbf"])
            if (exp == null) return Attest.fail("token has no exp (cannot bound validity — fail closed)")
            if (nowSec - skewSec > exp) return Attest.fail("Confidential Space token expired")
            if (nbf != null && nowSec + skewSec < nbf) return Attest.fail("Confidential Space token not yet valid (nbf)")
            if (iat != null && nowSec + skewSec < iat) return Attest.fail("Confidential Space token issued in the future (iat)")

            val submods = AttestUtil.rec(payload["submods"])
            if (AttestUtil.rec(submods?.get("confidential_space")) == null) return Attest.fail("token carries no submods.confidential_space (not a Confidential Space token)")
            val swnameV = payload["swname"]
            val swname = swnameV as? String
            if (swname == null || swname != swName) return Attest.fail("unexpected swname '${swname ?: "undefined"}' (expected '$swName')")
            if (swVersions != null) {
                var versions: List<String> = AttestUtil.asStrList(payload["swversion"]) ?: emptyList()
                if (AttestUtil.asStrList(payload["swversion"]) == null) {
                    val s = payload["swversion"] as? String
                    if (s != null && s.isNotEmpty()) versions = listOf(s)
                }
                if (versions.none { swVersions.contains(it) }) return Attest.fail("swversion not in policy allowlist")
            }
            val hwmodel = payload["hwmodel"] as? String ?: ""
            if (hwmodel.isEmpty()) return Attest.fail("token carries no hwmodel claim")
            val teeType = teeTypeOf(hwmodel)
            if (teeType == "") return Attest.fail("unrecognized hwmodel '$hwmodel' (not a known AMD SEV-SNP / Intel TDX model)")
            if (teeTypes != null && !teeTypes.contains(teeType)) return Attest.fail("attestation type '$teeType' (hwmodel '$hwmodel') is not in the policy allowlist")
            val dbgstat = payload["dbgstat"] as? String
            if (!allowDebug && (dbgstat == null || dbgstat != "disabled-since-boot")) {
                return Attest.fail("token dbgstat '${dbgstat ?: "undefined"}' is not 'disabled-since-boot' (debug build — no confidentiality)")
            }
            if (expected == null) return Attest.fail("no expected attestation binding supplied")
            val raw = try {
                Attest.bindingBytes(expected)
            } catch (e: IllegalArgumentException) {
                return Attest.fail("binding not constructible: " + e.message)
            }
            val bindingBytes = AttestMaa.transformBinding(raw, nonceHash)
            val candidates = nonceCandidates(payload["eat_nonce"])
            if (candidates.isEmpty()) return Attest.fail("token carries no eat_nonce claim to bind the PCA challenge")
            var bound = false
            for (c in candidates) {
                val b = AttestUtil.decodeClaimBytes(c)
                if (b != null && AttestUtil.timingSafeEq(b, bindingBytes)) { bound = true; break }
            }
            if (!bound) return Attest.fail("eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)")
            val container = AttestUtil.rec(submods?.get("container"))
            val imageDigest = AttestMaa.firstString(container, listOf("image_digest")) ?: return Attest.fail("token carries no submods.container.image_digest to measure the workload")
            if (!images.contains(imageDigest.lowercase())) return Attest.fail("workload image_digest not in policy allowlist")
            val host = LinkedHashMap<String, String>()
            host["attestation_type"] = teeType
            host["hwmodel"] = hwmodel
            host["image_digest"] = imageDigest
            val ref = AttestMaa.firstString(container, listOf("image_reference"))
            if (ref != null) host["image_reference"] = ref
            return Attest.Result(true, true, "", AttestUtil.newMeasured(imageDigest, ""), host)
        }
    }

    fun create(cfg: Map<String, Any?>): Attest.VendorImpl {
        val p = "createGcpConfidentialSpaceVerifier: "
        val issArr = cfg["trustedIssuers"] as? List<*>
        if (issArr == null || issArr.isEmpty()) throw IllegalArgumentException(p + "trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs")
        val issuers = HashSet<String>()
        for (x in issArr) {
            val s = x as? String
            if (s == null || s.isEmpty()) throw IllegalArgumentException(p + "every trusted issuer must be a non-empty URL string")
            issuers.add(s)
        }
        val anch = AttestUtil.rec(cfg["trustAnchors"]) ?: emptyMap()
        val trustedKeys = ArrayList<Map<String, Any?>?>()
        val tj = AttestUtil.rec(anch["trustedJwks"])
        val tjKeys = tj?.get("keys") as? List<*>
        if (tjKeys != null) for (k in tjKeys) trustedKeys.add(AttestUtil.rec(k))
        val spki = AttestUtil.listLen(anch["trustedKeySpki"])
        val spkiPins = HashSet<String>()
        for (s in AttestUtil.anyStrings(anch["trustedKeySpki"])) spkiPins.add(s.lowercase())
        val rootCerts = AttestUtil.asStrList(anch["rootCertsPem"]) ?: emptyList()
        if (trustedKeys.size + spki + AttestUtil.listLen(anch["rootCertsPem"]) == 0)
            throw IllegalArgumentException(p + "trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted")
        val pol = AttestUtil.rec(cfg["policy"]) ?: emptyMap()
        val digests = AttestUtil.asStrList(pol["imageDigests"])
        if (digests == null || digests.isEmpty()) throw IllegalArgumentException(p + "policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)")
        var teeTypes: Set<String>? = null
        if (pol.containsKey("allowedTeeTypes")) {
            val arr = pol["allowedTeeTypes"] as? List<*>
            if (arr != null) {
                if (arr.isEmpty()) throw IllegalArgumentException(p + "policy.allowedTeeTypes, when present, must be non-empty")
                teeTypes = arr.filterIsInstance<String>().toSet()
            }
        }
        val skew = AttestUtil.skewOf(cfg)
        val images = digests.map { it.lowercase() }.toSet()
        val swName = pol["expectedSwName"] as? String ?: "CONFIDENTIAL_SPACE"
        var swVersions: Set<String>? = null
        val sv = pol["allowedSwVersions"] as? List<*>
        if (sv != null) swVersions = sv.filterIsInstance<String>().toSet()
        return Verifier(
            issuers, trustedKeys, spkiPins, rootCerts, images, teeTypes, swName, swVersions,
            pol["allowDebug"] == true, pol["nonceHash"] as? String ?: "", skew,
        )
    }
}
