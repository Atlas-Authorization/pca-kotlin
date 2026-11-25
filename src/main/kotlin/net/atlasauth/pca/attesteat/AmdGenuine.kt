package net.atlasauth.pca.attesteat

import java.security.interfaces.ECPublicKey
import net.atlasauth.pca.verifier.AttErr
import net.atlasauth.pca.verifier.AttestAmd
import net.atlasauth.pca.verifier.AttestCert
import net.atlasauth.pca.verifier.AttestDer
import net.atlasauth.pca.verifier.AttestUtil

/**
 * The AMD SEV-SNP genuine-report verifier without a report_data binding, for the attestation-token layer: the pinned VCEK, ASK, ARK
 * chain, the report signature, the VCEK to report binding and a policy of ECDSA-P384, VMPL 0, debug refused unless allowed and the
 * launch measurement. It runs the same checks, in the same order and with the same reason text, as the core verifier.
 */
internal object AmdGenuine {
    private const val REPORT_LEN = 0x4a0
    private const val OFF_SIG_R = 0x2a0
    private const val OFF_SIG_S = 0x2e8
    private const val POLICY_DEBUG_BIT = 1L shl 19

    /** The parsed fields the token layer projects (version, guest_svn, debug, measurement, chip_id, reported_tcb). */
    fun shape(raw: ByteArray, r: AttestAmd.Report): Map<String, Any?> {
        val version = (raw[0].toLong() and 0xff) or ((raw[1].toLong() and 0xff) shl 8) or ((raw[2].toLong() and 0xff) shl 16) or ((raw[3].toLong() and 0xff) shl 24)
        val m = LinkedHashMap<String, Any?>()
        m["version"] = version
        m["guest_svn"] = r.guestSvn
        m["debug"] = (r.policy and POLICY_DEBUG_BIT) != 0L
        m["measurement"] = AttestUtil.hex(r.measurement)
        m["chip_id"] = AttestUtil.hex(r.chipId)
        m["reported_tcb"] = java.lang.Long.toUnsignedString(r.reportedTcb)
        return m
    }

    /** parseSevSnpReport projected to the token layer's fields; throws on a short buffer. */
    fun parseReport(raw: ByteArray): Map<String, Any?> = shape(raw, AttestAmd.parseReport(raw))

    private class Chain(val reason: String, val key: ECPublicKey?, val tbs: ByteArray?)

    private fun verifyChain(vcekDer: ByteArray, askArkPem: String, pin: String, nowMs: Long, clockSkew: Any?): Chain {
        fun fail(r: String) = Chain(r, null, null)
        return try {
            var skew = 0.0
            if (clockSkew != null) {
                val f = AttestUtil.asFinite(clockSkew)
                if (f == null || f < 0) return fail("clockSkewMs must be a non-negative number")
                skew = f
            }
            val vcek = AttestCert.parseCertDer(vcekDer)
            val pems = AttestCert.pemCertBlocks(askArkPem)
            if (pems.size != 2) return fail("ASK+ARK chain must contain exactly two certificates (ASK then ARK)")
            val ask = AttestCert.certFromPem(pems[0])
            val ark = AttestCert.certFromPem(pems[1])
            if (!ark.selfIssued() || !AttestCert.certSigOkBy(ark, ark)) return fail("second certificate of the chain is not a self-signed ARK (chain out of order?)")
            if (ask.selfIssued()) return fail("first certificate of the chain is self-signed, not an ASK (chain out of order?)")
            if (!ask.rawSubject.contentEquals(vcek.rawIssuer)) return fail("ASK subject does not match the VCEK issuer")
            val arkKey = AttestCert.keyOfCert(ark)
            if (arkKey.spkiSha384() != pin.lowercase()) return fail("ARK does not match the pinned AMD trust anchor")
            if (!ask.rawIssuer.contentEquals(ark.rawSubject) || !AttestCert.certSigOkBy(ask, ark)) return fail("ASK is not signed by ARK")
            if (!AttestCert.certSigOkBy(vcek, ask)) return fail("VCEK is not signed by ASK")

            val labels = listOf("VCEK", "ASK", "ARK")
            val ders = listOf(vcekDer, ask.raw, ark.raw)
            val roleErr = AttestDer.checkChainRoles(ders)
            if (roleErr != "") return fail("AMD chain role check failed: $roleErr")
            for ((i, der) in ders.withIndex()) {
                val label = labels[i]
                val exts = AttestDer.parseCertExtensions(der)
                for (oid in exts.oids) {
                    if (exts.m.getValue(oid).critical && oid !in AttestDer.RECOGNISED_CRITICAL) return fail("$label certificate has an unrecognised critical extension $oid")
                }
                if (label != "VCEK") {
                    val bc = exts.m["2.5.29.19"]
                    if (bc == null || !bc.critical) return fail("$label certificate BasicConstraints is not marked critical")
                }
                val (from, to) = AttestDer.derValidity(der)
                if (!from.ok || !to.ok) return fail("$label certificate validity is unparseable")
                if (nowMs.toDouble() + skew < from.ms.toDouble()) return fail("$label certificate is not yet valid")
                if (nowMs.toDouble() - skew > to.ms.toDouble()) return fail("$label certificate has expired")
            }

            val vk = AttestCert.keyOfCert(vcek)
            if (vk.typ != "ec" || vk.curve != "secp384r1") {
                val curve = if (vk.curve == "") "undefined" else vk.curve
                throw AttErr("VCEK is not EC secp384r1 (got ${vk.typ}/$curve)")
            }
            AttestCert.ecPointOfKey(vk, "P-384")
            val tbs = AttestDer.tbsOfCertificate(vcekDer)
            Chain("", vk.pub as ECPublicKey, tbs)
        } catch (e: AttErr) {
            fail("AMD chain verification error: " + AttestUtil.errMsg(e))
        }
    }

    private fun verifySignature(r: AttestAmd.Report, pub: ECPublicKey): Boolean {
        val n = pub.params.order
        val rr = AttestUtil.leToBig(r.sigR)
        val ss = AttestUtil.leToBig(r.sigS)
        if (rr.signum() <= 0 || rr >= n || ss.signum() <= 0 || ss >= n) return false
        return AttestUtil.ecdsaVerify(pub, AttestUtil.sha384(r.signed), rr, ss)
    }

    /**
     * Verify a report against the pinned chain with the token layer's policy. Result: the failure reason ("" on success) and, on
     * success, the parsed report fields. [expectedMeasurement] null pins the report's own launch measurement (no measurement pin).
     */
    fun verify(
        raw: ByteArray, vcekDer: ByteArray, askArkPem: String, arkPin: String, nowMs: Long, clockSkewMs: Any?,
        expectedMeasurement: String?, allowDebug: Boolean,
    ): Pair<String, Map<String, Any?>?> {
        val rep = try {
            AttestAmd.parseReport(raw)
        } catch (e: AttErr) {
            return Pair("report parse failed: " + AttestUtil.errMsg(e), null)
        }
        if (raw.size != REPORT_LEN) return Pair("report length ${raw.size} is not the canonical $REPORT_LEN", null)
        fun nonZero(from: Int, to: Int): Boolean {
            for (i in from until to) if (raw[i].toInt() != 0) return true
            return false
        }
        if (nonZero(OFF_SIG_S + 72, raw.size) || nonZero(OFF_SIG_R + 48, OFF_SIG_R + 72) || nonZero(OFF_SIG_S + 48, OFF_SIG_S + 72))
            return Pair("report signature block has non-zero reserved bytes", null)
        val chain = verifyChain(vcekDer, askArkPem, arkPin, nowMs, clockSkewMs)
        if (chain.reason != "" || chain.key == null || chain.tbs == null) return Pair("cert chain invalid: " + chain.reason, null)
        if (!verifySignature(rep, chain.key)) return Pair("report signature does not verify under VCEK", null)
        val bindErr = AttestAmd.checkVcekReportBinding(chain.tbs, rep)
        if (bindErr != "") return Pair(bindErr, null)
        // policy: ECDSA-P384, debug refused unless allowed, VMPL 0, then the launch measurement
        if (rep.sigAlgo != 1L) return Pair("unexpected signature_algo ${rep.sigAlgo}", null)
        if (!allowDebug && (rep.policy and POLICY_DEBUG_BIT) != 0L) return Pair("guest policy has the DEBUG bit set (host can inspect the guest)", null)
        if (rep.vmpl != 0L) return Pair("vmpl ${rep.vmpl} is not the required 0", null)
        val own = AttestUtil.hex(rep.measurement)
        val want = (expectedMeasurement ?: own).lowercase()
        if (own != want) return Pair("measurement not in policy allowlist", null)
        return Pair("", shape(raw, rep))
    }
}
