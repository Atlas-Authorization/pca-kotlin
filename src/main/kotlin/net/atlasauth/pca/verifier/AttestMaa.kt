package net.atlasauth.pca.verifier

/**
 * Microsoft Azure Attestation (MAA): the signed MAA JWT of an Azure confidential VM (SEV-SNP "sevsnpvm" or TDX "tdxvm"), verified
 * under the token-signing x5c chain anchored in a configured MAA root, with the PCA challenge bound through the report-data or
 * runtime user-data claim. Same checks, order and reason text as the reference verifier. Classical (ES256 / RS256); no network
 * I/O: anchors are configured explicitly.
 */
internal object AttestMaa {
    private class Anchors(val rootCertsPem: List<String>, val rootSpki: List<String>)

    private class Policy(
        val sevSnp: List<String>, val tdx: List<String>, val sevHost: List<String>, val tdxRtmrs: List<String>,
        val minTcb: Map<String, Double>, val allowDebug: Boolean, val runtimeUserData: Boolean,
        val tdxStatuses: List<String>?, val reportDataHash: String, val hasSev: Boolean, val hasTdx: Boolean,
    )

    private val TCB_CLAIMS = listOf(
        Triple("bootloader", "x-ms-sevsnpvm-bootloader-svn", "bootloader_svn"),
        Triple("snp", "x-ms-sevsnpvm-snpfw-svn", "snpfw_svn"),
        Triple("microcode", "x-ms-sevsnpvm-microcode-svn", "microcode_svn"),
        Triple("tee", "x-ms-sevsnpvm-tee-svn", "tee_svn"),
    )

    // ---- x5c chain ----

    /** Verifies an x5c chain (base64 DER, leaf first) to a configured trust anchor: the leaf, or the failure reason. */
    private fun verifyX5cChain(a: Anchors, x5c: List<Any?>, nowMs: Long, skew: Double): Pair<AttestCert.Cert?, String> {
        fun thrown(e: AttErr) = Pair<AttestCert.Cert?, String>(null, "x5c chain verification error (fail closed): " + AttestUtil.errMsg(e))
        try {
            if (x5c.isEmpty()) return Pair(null, "empty x5c certificate chain")
            val certs = ArrayList<AttestCert.Cert>(x5c.size)
            for ((i, e) in x5c.withIndex()) {
                val b64 = e as? String
                if (b64 == null || b64.isEmpty()) return Pair(null, "empty x5c entry at index $i")
                val c = try {
                    AttestCert.parseCertDer(AttestUtil.nodeB64(b64))
                } catch (x: AttErr) {
                    return Pair(null, "malformed x5c certificate at index $i: ${AttestUtil.errMsg(x)}")
                }
                if (!AttestDer.derValidAtF(c.raw, nowMs, skew)) return Pair(null, "x5c certificate at index $i is outside its validity window")
                certs.add(c)
            }
            val fingerprints = HashSet<String>()
            for (fp in a.rootSpki) if (fp.isNotEmpty()) fingerprints.add(fp.lowercase())
            val roots = ArrayList<AttestCert.Cert>()
            for (pem in a.rootCertsPem) {
                val c = AttestCert.certFromPem(pem)
                val k = AttestCert.keyOfCert(c)
                roots.add(c)
                fingerprints.add(k.spkiSha256())
            }
            if (fingerprints.isEmpty() && roots.isEmpty()) return Pair(null, "no MAA trust anchor configured (fail closed)")
            var anchorIdx = -1
            for ((j, c) in certs.withIndex()) {
                val k = AttestCert.keyOfCert(c)
                if (fingerprints.contains(k.spkiSha256())) { anchorIdx = j; break }
            }
            if (anchorIdx >= 0) {
                for (i in 0 until anchorIdx) {
                    if (!AttestCert.certSigOkBy(certs[i], certs[i + 1])) return Pair(null, "x5c link $i is not signed by the certificate above it")
                }
                return Pair(certs[0], "")
            }
            for (i in 0 until certs.size - 1) {
                if (!AttestCert.certSigOkBy(certs[i], certs[i + 1])) return Pair(null, "x5c link $i is not signed by the certificate above it")
            }
            val top = certs[certs.size - 1]
            for (r in roots) if (AttestCert.certSigOkBy(top, r)) return Pair(certs[0], "")
            return Pair(null, "x5c chain does not anchor in a configured MAA trust root")
        } catch (e: AttErr) {
            return thrown(e)
        }
    }

    /** The JWKS entry matched by kid, else the header's own x5c: the chain, or the failure reason. */
    private fun resolveSigningX5c(tok: AttestJws.Parsed, jwks: Any?): Pair<List<Any?>?, String> {
        val keys = (AttestUtil.rec(jwks)?.get("keys") as? List<*>) ?: emptyList<Any?>()
        fun chainOf(k: Any?): List<Any?> = (AttestUtil.rec(k)?.get("x5c") as? List<Any?>) ?: emptyList()
        if (keys.isNotEmpty()) {
            if (!tok.hasKid || tok.kid.isEmpty()) {
                if (keys.size != 1) return Pair(null, "token has no kid and the JWKS publishes multiple keys (ambiguous)")
                val c = chainOf(keys[0])
                if (c.isNotEmpty()) return Pair(c, "")
                return Pair(null, "JWKS key carries no x5c chain")
            }
            for (k in keys) {
                val kid = AttestUtil.rec(k)?.get("kid") as? String
                if (kid != null && kid == tok.kid) {
                    val c = chainOf(k)
                    if (c.isNotEmpty()) return Pair(c, "")
                    return Pair(null, "JWKS key '${tok.kid}' carries no x5c chain")
                }
            }
            return Pair(null, "no JWKS key matches the token kid '${tok.kid}' (untrusted signer)")
        }
        if (tok.hasX5c && tok.x5c.isNotEmpty()) return Pair(ArrayList<Any?>(tok.x5c), "")
        return Pair(null, "no signing x5c available (no JWKS and no header x5c)")
    }

    private fun jwsSignature(tok: AttestJws.Parsed, leaf: AttestCert.Cert): String {
        val k = try {
            AttestCert.keyOfCert(leaf)
        } catch (e: AttErr) {
            return "x5c chain verification error (fail closed): " + AttestUtil.errMsg(e)
        }
        val (kty, crv) = AttestJws.jwkKtyCrv(k)
        when (tok.alg) {
            "ES256" -> {
                if (kty != "EC" || crv != "P-256") return "ES256 token but signing key is $kty/$crv (not EC P-256)"
                if (tok.signature.size != 64) return "ES256 signature is ${tok.signature.size} bytes (expected 64: r‖s)"
                if (!AttestJws.es256Ok(tok.signature, tok.signingInput, k)) return "JWS ES256 signature does not verify under the MAA signing key"
                return ""
            }
            "RS256" -> {
                if (kty != "RSA") return "RS256 token but signing key is $kty (not RSA)"
                if (!AttestJws.rs256Ok(tok.signature, tok.signingInput, k)) return "JWS RS256 signature does not verify under the MAA signing key"
                return ""
            }
        }
        return "unsupported JWS alg '${tok.alg}' (MAA uses ES256 / RS256)"
    }

    /** The first non-empty string member among `keys`, or null. */
    fun firstString(rec: Map<String, Any?>?, keys: List<String>): String? {
        if (rec == null) return null
        for (k in keys) {
            val s = rec[k] as? String
            if (s != null && s.isNotEmpty()) return s
        }
        return null
    }

    fun transformBinding(binding: ByteArray, mode: String): ByteArray = when (mode) {
        "sha256" -> AttestUtil.sha256(binding)
        "sha512" -> AttestUtil.sha512(binding)
        else -> binding
    }

    private class Verifier(val issuers: Set<String>, val anchors: Anchors, val policy: Policy, val skew: Double) : Attest.VendorImpl {
        override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result {
            val token = ev?.get("token") as? String
            if (ev == null || token == null || token.isEmpty()) return Attest.fail("no Azure MAA token for this action")
            val tok = try {
                AttestJws.parseJwt(token, "parseMaaJwt")
            } catch (e: AttErr) {
                return Attest.fail("MAA token parse failed: " + e.message)
            }
            if (tok.alg != "ES256" && tok.alg != "RS256") return Attest.fail("unsupported JWS alg '${tok.alg}' (MAA uses ES256 / RS256)")
            val (x5c, why) = resolveSigningX5c(tok, ev["jwks"])
            if (x5c == null) return Attest.fail(why)
            val (leaf, why2) = verifyX5cChain(anchors, x5c, nowMs, skew)
            if (leaf == null) return Attest.fail("MAA signing chain invalid: $why2")
            val sigErr = jwsSignature(tok, leaf)
            if (sigErr != "") return Attest.fail(sigErr)

            val payload = tok.payload
            val issV = payload["iss"]
            val iss = issV as? String ?: ""
            if (iss.isEmpty() || !issuers.contains(iss)) {
                val shown = if (issV !is String) "undefined" else iss
                return Attest.fail("token iss '$shown' is not a configured trusted MAA instance")
            }
            val nowSec = Math.floor(nowMs.toDouble() / 1000)
            val skewSec = Math.ceil(skew / 1000)
            val exp = AttestUtil.asFinite(payload["exp"])
            val iat = AttestUtil.asFinite(payload["iat"])
            val nbf = AttestUtil.asFinite(payload["nbf"])
            if (exp == null) return Attest.fail("token has no exp (cannot bound validity — fail closed)")
            if (nowSec - skewSec > exp) return Attest.fail("MAA token expired")
            if (nbf != null && nowSec + skewSec < nbf) return Attest.fail("MAA token not yet valid (nbf)")
            if (iat != null && nowSec + skewSec < iat) return Attest.fail("MAA token issued in the future (iat)")

            val teeClaims: Map<String, Any?> = AttestUtil.rec(payload["x-ms-isolation-tee"]) ?: payload
            var isolation = teeClaims["x-ms-attestation-type"] as? String
            if (isolation == null) isolation = payload["x-ms-attestation-type"] as? String
            if (isolation == null || (isolation != "sevsnpvm" && isolation != "tdxvm")) {
                return Attest.fail("unexpected x-ms-attestation-type '${isolation ?: "undefined"}' (expected sevsnpvm | tdxvm)")
            }

            if (expected == null) return Attest.fail("no expected attestation binding supplied")
            val raw = try {
                Attest.bindingBytes(expected)
            } catch (e: IllegalArgumentException) {
                return Attest.fail("binding not constructible: " + e.message)
            }
            if (policy.runtimeUserData) {
                val runtime = AttestUtil.rec(payload["x-ms-runtime"])
                    ?: return Attest.fail("token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)")
                val ud = runtime["user-data"] as? String ?: ""
                if (ud.isEmpty()) return Attest.fail("x-ms-runtime carries no user-data to bind the PCA challenge")
                val got = AttestUtil.decodeClaimBytes(ud)
                if (got == null || !AttestUtil.timingSafeEq(got, raw)) return Attest.fail("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)")
            } else {
                val bindingBytes = transformBinding(raw, policy.reportDataHash)
                val keys = if (isolation == "sevsnpvm") listOf("x-ms-sevsnpvm-reportdata") else listOf("tdx_report_data", "x-ms-tdx-report-data", "x-ms-tdx-reportdata")
                val claim = firstString(teeClaims, keys) ?: return Attest.fail("token carries no report-data claim to bind the PCA challenge")
                val got = AttestUtil.decodeClaimBytes(claim) ?: return Attest.fail("report-data claim is not decodable (hex/base64)")
                if (!AttestUtil.timingSafeEq(got, bindingBytes)) return Attest.fail("report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)")
            }
            return if (isolation == "sevsnpvm") sevSnpResult(teeClaims) else tdxResult(teeClaims)
        }

        private fun sevSnpResult(tee: Map<String, Any?>): Attest.Result {
            if (!policy.hasSev) return Attest.fail("sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)")
            val measurement = firstString(tee, listOf("x-ms-sevsnpvm-launchmeasurement")) ?: return Attest.fail("sevsnpvm token carries no launch-measurement claim")
            val mHex = measurement.lowercase()
            if (!policy.sevSnp.contains(mHex)) return Attest.fail("SEV-SNP launch measurement not in policy allowlist")
            val dbg = tee["x-ms-sevsnpvm-is-debuggable"] as? Boolean
            if (dbg != null && dbg && !policy.allowDebug) return Attest.fail("SEV-SNP guest is debuggable (no confidentiality)")
            val hostData = firstString(tee, listOf("x-ms-sevsnpvm-hostdata"))
            if (policy.sevHost.isNotEmpty()) {
                if (hostData == null || !policy.sevHost.contains(hostData.lowercase())) return Attest.fail("SEV-SNP host-data not in policy allowlist")
            }
            val reported = LinkedHashMap<String, String>()
            for ((name, claim, hostKey) in TCB_CLAIMS) {
                val f = AttestUtil.asFinite(tee[claim])
                val isSvn = f != null && f == Math.floor(f) && f >= 0
                if (isSvn) reported[hostKey] = AttestUtil.jsNumString(f!!)
                val floor = policy.minTcb[name] ?: continue
                if (!isSvn) return Attest.fail("SEV-SNP $name SVN claim '$claim' is missing or not a non-negative integer (policy requires a minimum)")
                if (f!! < floor) return Attest.fail("SEV-SNP $name SVN ${AttestUtil.jsNumString(f)} is below the policy minimum ${AttestUtil.jsNumString(floor)}")
            }
            val host = LinkedHashMap<String, String>()
            host["attestation_type"] = "sevsnpvm"
            host.putAll(reported)
            if (hostData != null) host["host_data"] = hostData.lowercase()
            return Attest.Result(true, true, "", AttestUtil.newMeasured(mHex, ""), host)
        }

        private fun tdxResult(tee: Map<String, Any?>): Attest.Result {
            if (!policy.hasTdx) return Attest.fail("tdxvm token but policy configures no TDX MRTD allowlist (fail closed)")
            val mrtd = firstString(tee, listOf("tdx_mrtd", "x-ms-tdx-mrtd")) ?: return Attest.fail("tdxvm token carries no MRTD claim")
            val mrtdHex = mrtd.lowercase()
            if (!policy.tdx.contains(mrtdHex)) return Attest.fail("TDX MRTD not in policy allowlist")
            val tdDebug = (tee["tdx_td_attributes_debug"] as? Boolean) ?: false
            val dbgstat = tee["dbgstat"] as? String
            if (!policy.allowDebug && (tdDebug || (dbgstat != null && dbgstat != "disabled"))) return Attest.fail("TDX guest is debuggable (no confidentiality)")
            val tcbStatus = tee["attester_tcb_status"] as? String
            if (tcbStatus != null) {
                val accepted = policy.tdxStatuses ?: AttestIntel.DEFAULT_ACCEPTED_STATUSES
                if (!accepted.contains(tcbStatus)) return Attest.fail("TDX platform TCB status '$tcbStatus' is not accepted by policy")
            }
            val rtmr0 = firstString(tee, listOf("tdx_rtmr0", "x-ms-tdx-rtmr0"))
            if (policy.tdxRtmrs.isNotEmpty()) {
                if (rtmr0 == null || !policy.tdxRtmrs.contains(rtmr0.lowercase())) return Attest.fail("TDX RTMR0 not in policy allowlist")
            }
            val host = LinkedHashMap<String, String>()
            host["attestation_type"] = "tdxvm"
            if (tcbStatus != null && tcbStatus.isNotEmpty()) host["tcb_status"] = tcbStatus
            if (rtmr0 != null) host["rtmr0"] = rtmr0.lowercase()
            return Attest.Result(true, true, "", AttestUtil.newMeasured(mrtdHex, ""), host)
        }
    }

    fun create(cfg: Map<String, Any?>): Attest.VendorImpl {
        val p = "createAzureMaaVerifier: "
        val issArr = cfg["trustedIssuers"] as? List<*>
        if (issArr == null || issArr.isEmpty()) throw IllegalArgumentException(p + "trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs")
        val issuers = HashSet<String>()
        for (x in issArr) {
            val s = x as? String
            if (s == null || s.isEmpty()) throw IllegalArgumentException(p + "every trusted issuer must be a non-empty URL string")
            issuers.add(s)
        }
        val anch = AttestUtil.rec(cfg["trustAnchors"]) ?: emptyMap()
        if (AttestUtil.listLen(anch["rootCertsPem"]) + AttestUtil.listLen(anch["rootSpkiSha256"]) == 0)
            throw IllegalArgumentException(p + "trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted")
        val anchors = Anchors(AttestUtil.asStrList(anch["rootCertsPem"]) ?: emptyList(), AttestUtil.asStrList(anch["rootSpkiSha256"]) ?: emptyList())
        val pol = AttestUtil.rec(cfg["policy"])
        val sev = if (pol != null) AttestUtil.asStrList(pol["sevSnpMeasurements"]) ?: emptyList() else emptyList()
        val tdx = if (pol != null) AttestUtil.asStrList(pol["tdxMrtds"]) ?: emptyList() else emptyList()
        val hasSev = sev.isNotEmpty()
        val hasTdx = tdx.isNotEmpty()
        if (pol == null || (!hasSev && !hasTdx)) throw IllegalArgumentException(p + "policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)")
        val minTcb = LinkedHashMap<String, Double>()
        if (pol.containsKey("sevSnpMinTcb")) {
            val m = AttestUtil.rec(pol["sevSnpMinTcb"]) ?: throw IllegalArgumentException(p + "policy.sevSnpMinTcb must be an object")
            for (k in m.keys.sorted()) {
                if (TCB_CLAIMS.none { it.first == k }) throw IllegalArgumentException("${p}policy.sevSnpMinTcb.$k is not a known field (bootloader | snp | microcode | tee)")
                val f = AttestUtil.asFinite(m[k])
                if (f == null || f != Math.floor(f) || f < 0) throw IllegalArgumentException("${p}policy.sevSnpMinTcb.$k must be a non-negative integer")
                minTcb[k] = f
            }
        }
        val policy = Policy(
            sevSnp = AttestUtil.lowerAll(sev),
            tdx = AttestUtil.lowerAll(tdx),
            sevHost = AttestUtil.lowerAll(AttestUtil.asStrList(pol["sevSnpHostData"]) ?: emptyList()),
            tdxRtmrs = AttestUtil.lowerAll(AttestUtil.asStrList(pol["tdxRtmrs"]) ?: emptyList()),
            minTcb = minTcb,
            allowDebug = pol["allowDebug"] == true,
            runtimeUserData = pol["runtimeUserDataBinding"] == true,
            tdxStatuses = AttestUtil.asStrList(pol["tdxAllowedTcbStatuses"]),
            reportDataHash = pol["reportDataHash"] as? String ?: "",
            hasSev = hasSev,
            hasTdx = hasTdx,
        )
        return Verifier(issuers, anchors, policy, AttestUtil.skewOf(cfg))
    }
}
