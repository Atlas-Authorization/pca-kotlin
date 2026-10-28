package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.interfaces.ECPublicKey

/**
 * AMD SEV-SNP: genuine ATTESTATION_REPORT verification (ECDSA-P384 report signature under the VCEK, VCEK -> ASK -> ARK chain to
 * the pinned ARK of the configured family, VCEK <-> report binding, policy) with the same checks, order and reason text as the
 * reference verifier. Classical (ECDSA-P384 / RSA-PSS); no network I/O.
 */
internal object AttestAmd {
    /** The SPKI SHA-384 (lowercase hex) of each family's ARK, as published by AMD's key distribution service. */
    private val ARK_SPKI_SHA384 = mapOf(
        "milan" to "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        "genoa" to "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        "turin" to "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
    )

    // ATTESTATION_REPORT layout (AMD SEV-SNP ABI): offsets, all integers little-endian.
    private const val OFF_GUEST_SVN = 0x004
    private const val OFF_POLICY = 0x008
    private const val OFF_VMPL = 0x030
    private const val OFF_SIG_ALGO = 0x034
    private const val OFF_REPORT_DATA = 0x050
    private const val OFF_MEASUREMENT = 0x090
    private const val OFF_HOST_DATA = 0x0c0
    private const val OFF_REPORTED_TCB = 0x180
    private const val OFF_CHIP_ID = 0x1a0
    private const val OFF_COMMITTED_TCB = 0x1e0
    private const val OFF_LAUNCH_TCB = 0x1f0
    private const val OFF_SIGNED_END = 0x2a0
    private const val OFF_SIG_R = 0x2a0
    private const val OFF_SIG_S = 0x2e8
    private const val REPORT_LEN = 0x4a0
    private const val POLICY_DEBUG_BIT = 1L shl 19
    private const val SIG_ALGO_ECDSA_P384 = 1L

    private class Report(
        val guestSvn: Long, val policy: Long, val vmpl: Long, val sigAlgo: Long,
        val reportedTcb: Long, val committedTcb: Long, val launchTcb: Long,
        val reportData: ByteArray, val measurement: ByteArray, val hostData: ByteArray, val chipId: ByteArray,
        val signed: ByteArray, val sigR: ByteArray, val sigS: ByteArray,
    )

    private fun parseReport(b: ByteArray): Report {
        val minLen = OFF_SIG_S + 72
        if (b.size < minLen) throw AttErr("parseSevSnpReport: report too short (${b.size} < $minLen)")
        val bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
        return Report(
            bb.getInt(OFF_GUEST_SVN).toLong() and 0xffffffffL,
            bb.getLong(OFF_POLICY),
            bb.getInt(OFF_VMPL).toLong() and 0xffffffffL,
            bb.getInt(OFF_SIG_ALGO).toLong() and 0xffffffffL,
            bb.getLong(OFF_REPORTED_TCB),
            bb.getLong(OFF_COMMITTED_TCB),
            bb.getLong(OFF_LAUNCH_TCB),
            b.copyOfRange(OFF_REPORT_DATA, OFF_REPORT_DATA + 64),
            b.copyOfRange(OFF_MEASUREMENT, OFF_MEASUREMENT + 48),
            b.copyOfRange(OFF_HOST_DATA, OFF_HOST_DATA + 32),
            b.copyOfRange(OFF_CHIP_ID, OFF_CHIP_ID + 64),
            b.copyOfRange(0, OFF_SIGNED_END),
            b.copyOfRange(OFF_SIG_R, OFF_SIG_R + 72),
            b.copyOfRange(OFF_SIG_S, OFF_SIG_S + 72),
        )
    }

    private fun u64(v: Long): BigInteger = BigInteger(java.lang.Long.toUnsignedString(v))

    /** ECDSA-P384 / SHA-384 over the signed region under the VCEK; AMD stores r and s little-endian. */
    private fun verifySignature(r: Report, pub: ECPublicKey): Boolean {
        val n = pub.params.order
        val rr = AttestUtil.leToBig(r.sigR)
        val ss = AttestUtil.leToBig(r.sigS)
        if (rr.signum() <= 0 || rr >= n || ss.signum() <= 0 || ss >= n) return false
        return AttestUtil.ecdsaVerify(pub, AttestUtil.sha384(r.signed), rr, ss)
    }

    private const val OID_HWID = "1.3.6.1.4.1.3704.1.4"
    private const val OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1"
    private const val OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2"
    private const val OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3"
    private const val OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8"
    private const val HWID_LEN = 64

    /** Decodes an SPL extension value: one minimal DER INTEGER 0..255. Pair(value, failure text or ""). */
    private fun decodeSpl(v: ByteArray): Pair<Int, String> {
        if (v.size < 3 || v[0].toInt() != 0x02) return Pair(0, "is not a DER INTEGER")
        val l = v[1].toInt() and 0xff
        if (l < 1 || l > 2 || v.size != 2 + l) return Pair(0, "has a wrong-length INTEGER")
        val c0 = v[2].toInt() and 0xff
        if ((c0 and 0x80) != 0) return Pair(0, "is negative")
        if (l == 2) {
            if (c0 != 0x00) return Pair(0, "is out of range (> 255)")
            if ((v[3].toInt() and 0x80) == 0) return Pair(0, "is a non-minimal INTEGER")
            return Pair(v[3].toInt() and 0xff, "")
        }
        return Pair(c0, "")
    }

    /** Binds the VCEK body to the report: hwID == chip_id and the four SPLs == the REPORTED_TCB bytes. */
    private fun checkVcekReportBinding(vcekTbs: ByteArray, r: Report): String {
        val exts = try {
            AttestDer.parseTbsExtensions(vcekTbs)
        } catch (e: AttErr) {
            return "VCEK extensions malformed: " + AttestUtil.errMsg(e)
        }
        val hw = exts.get(OID_HWID) ?: return "VCEK certificate has no CHIP_ID (hwID) extension"
        if (hw.critical) return "VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)"
        if (hw.value.size != HWID_LEN) return "VCEK CHIP_ID (hwID) extension is ${hw.value.size} bytes, expected $HWID_LEN"
        if (!AttestUtil.timingSafeEq(hw.value, r.chipId)) return "VCEK CHIP_ID does not match report chip_id"
        fun byteAt(i: Int): Int = ((r.reportedTcb ushr (8 * i)) and 0xff).toInt()
        val pairs = listOf(
            Triple(OID_BL_SPL, "bootloader", byteAt(0)),
            Triple(OID_TEE_SPL, "tee", byteAt(1)),
            Triple(OID_SNP_SPL, "snp", byteAt(6)),
            Triple(OID_UCODE_SPL, "microcode", byteAt(7)),
        )
        for ((oid, name, want) in pairs) {
            val ext = exts.get(oid) ?: return "VCEK certificate has no $name SPL extension"
            if (ext.critical) return "VCEK $name SPL extension is marked critical (the AMD profile is non-critical)"
            val (got, why) = decodeSpl(ext.value)
            if (why != "") return "VCEK $name SPL extension $why"
            if (got != want) return "VCEK $name SPL $got does not match report reported_tcb ($want) — TCB downgrade?"
        }
        return ""
    }

    private class Chain(val reason: String, val key: ECPublicKey?, val tbs: ByteArray?)

    /** Verifies VCEK -> ASK -> ARK with the ARK pinned: the failure reason, or the VCEK key and tbs. */
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
                    val bc = exts.get("2.5.29.19")
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

    // ---- policy ----

    private class Policy(
        val measurements: List<String>,
        val hostData: List<String>,
        val chipIds: List<String>,
        val allowDebug: Boolean,
        val requireEcdsaP384: Boolean,
        val minGuestSvn: Double?,
        val minReportedTcb: BigInteger?,
        val minCommittedTcb: BigInteger?,
        val minLaunchTcb: BigInteger?,
        val requireVmpl: Any?,
        val requireVmplPresent: Boolean,
    ) {
        fun check(r: Report): String {
            if (requireEcdsaP384 && r.sigAlgo != SIG_ALGO_ECDSA_P384) return "unexpected signature_algo ${r.sigAlgo}"
            if (!allowDebug && (r.policy and POLICY_DEBUG_BIT) != 0L) return "guest policy has the DEBUG bit set (host can inspect the guest)"
            if (minGuestSvn != null && r.guestSvn.toDouble() < minGuestSvn) return "guest_svn ${r.guestSvn} below minimum ${AttestUtil.jsNumString(minGuestSvn)}"
            if (minReportedTcb != null && u64(r.reportedTcb) < minReportedTcb) return "reported_tcb below minimum (rollback?)"
            if (minCommittedTcb != null && u64(r.committedTcb) < minCommittedTcb) return "committed_tcb below minimum (rollback?)"
            if (minLaunchTcb != null && u64(r.launchTcb) < minLaunchTcb) return "launch_tcb below minimum"
            val want = requireVmpl
            if (want == null) {
                if (r.vmpl != 0L) return "vmpl ${r.vmpl} is not the required 0"
            } else if (want is String) {
                if (want != "any") return "vmpl ${r.vmpl} is not the required $want"
            } else {
                val f = AttestUtil.asFinite(want)
                if (f == null || r.vmpl.toDouble() != f) return "vmpl ${r.vmpl} is not the required ${AttestUtil.jsAnyString(want)}"
            }
            if (measurements.isNotEmpty() && AttestUtil.hex(r.measurement) !in measurements) return "measurement not in policy allowlist"
            if (hostData.isNotEmpty() && AttestUtil.hex(r.hostData) !in hostData) return "host_data not in policy allowlist"
            if (chipIds.isNotEmpty() && AttestUtil.hex(r.chipId) !in chipIds) return "chip_id not in policy allowlist"
            return ""
        }
    }

    /** `BigInt(v)` for a JSON value; the message is the reference's. */
    fun parseJsBigInt(v: Any?): BigInteger {
        when (v) {
            null -> throw IllegalArgumentException("Cannot convert null to a BigInt")
            is Boolean -> return if (v) BigInteger.ONE else BigInteger.ZERO
            is String -> {
                val s = AttestUtil.jsTrim(v)
                if (s.isEmpty()) return BigInteger.ZERO
                var base = 10
                var body = s
                if (s.length > 2 && s[0] == '0') {
                    when (s[1]) {
                        'x', 'X' -> { base = 16; body = s.substring(2) }
                        'o', 'O' -> { base = 8; body = s.substring(2) }
                        'b', 'B' -> { base = 2; body = s.substring(2) }
                    }
                }
                if (base == 10 || (body.isNotEmpty() && body[0] != '+' && body[0] != '-')) {
                    val n = try { BigInteger(body, base) } catch (e: NumberFormatException) { null }
                    if (n != null && (base != 10 || body.isNotEmpty())) return n
                }
                throw IllegalArgumentException("Cannot convert $v to a BigInt")
            }
            is Json.Num -> {
                val f = AttestUtil.asFinite(v)
                if (f == null || f != Math.floor(f)) throw IllegalArgumentException("The number ${v.raw} cannot be converted to a BigInt because it is not an integer")
                val n = try { BigInteger(v.raw) } catch (e: NumberFormatException) { null }
                if (n != null) return n
                return java.math.BigDecimal(f).toBigInteger()
            }
            else -> throw IllegalArgumentException("Cannot convert value to a BigInt")
        }
    }

    private class Verifier(val family: String, val pin: String, val binding: String, val policy: Policy, val skew: Any?) : Attest.VendorImpl {
        /** The failure reason, or the parsed report. */
        private fun verifyReport(raw: ByteArray, vcekDer: ByteArray, askArkPem: String, nowMs: Long, expected: Attest.Binding?): Pair<String, Report?> {
            val rep = try {
                parseReport(raw)
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
            val chain = verifyChain(vcekDer, askArkPem, pin, nowMs, skew)
            if (chain.reason != "" || chain.key == null || chain.tbs == null) return Pair("cert chain invalid: " + chain.reason, null)
            if (!verifySignature(rep, chain.key)) return Pair("report signature does not verify under VCEK", null)
            val bindErr = checkVcekReportBinding(chain.tbs, rep)
            if (bindErr != "") return Pair(bindErr, null)
            if (expected != null) {
                val want = try {
                    Attest.bindingBytes(expected)
                } catch (e: IllegalArgumentException) {
                    return Pair("genuine verification error (fail closed): " + e.message, null)
                }
                if (!AttestUtil.timingSafeEq(want, rep.reportData)) return Pair("report_data does not bind holder/grant/epoch/nonce", null)
            }
            val pol = policy.check(rep)
            if (pol != "") return Pair(pol, null)
            return Pair("", rep)
        }

        override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result {
            val report = AttestUtil.evBytes(ev, "report")
            val vcek = AttestUtil.evBytes(ev, "vcekDer")
            val askArk = AttestUtil.evString(ev, "askArkPem")
            if (ev == null || report == null || vcek == null || askArk == null) return Attest.fail("no AMD SEV-SNP evidence for this action")
            if (expected == null) return Attest.fail("no expected attestation binding supplied")
            val direct = binding == "report-data"
            val (reason, rep) = verifyReport(report, vcek, askArk, nowMs, if (direct) expected else null)
            if (rep == null) return Attest.fail("SEV-SNP report invalid: $reason")
            if (!direct) {
                val rd = AttestUtil.evBytes(ev, "runtimeData") ?: return Attest.fail("azure-runtime-data binding needs the runtime-data JSON bytes")
                val why = AttestUtil.checkAzureRuntimeDataBinding(rep.reportData, rd, expected)
                if (why != "") return Attest.fail(why)
            }
            val m = AttestUtil.hex(rep.measurement)
            return Attest.Result(
                true, true, "", AttestUtil.newMeasured(m, AttestUtil.hex(rep.chipId)),
                linkedMapOf("attestation_type" to "amd-sev-snp", "family" to family, "measurement" to m),
            )
        }
    }

    fun create(cfg: Map<String, Any?>): Attest.VendorImpl {
        val pol = AttestUtil.rec(cfg["policy"]) ?: emptyMap()
        // the wire config carries the u64 floors as decimal strings: converted before the constructor runs
        val floors = HashMap<String, BigInteger>()
        for (k in listOf("minReportedTcb", "minCommittedTcb", "minLaunchTcb")) {
            if (pol.containsKey(k)) floors[k] = parseJsBigInt(pol[k])
        }
        val family = cfg["family"] as? String ?: ""
        var pin = ARK_SPKI_SHA384[family] ?: throw IllegalArgumentException("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'")
        val pinOverride = cfg["trustAnchorArkSpkiSha384"] as? String
        if (pinOverride != null) pin = pinOverride // conformance harness only: replaces the built-in pin
        val binding = cfg["binding"] as? String ?: ""
        if (binding != "report-data" && binding != "azure-runtime-data") throw IllegalArgumentException("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'")
        val ms = AttestUtil.asStrList(pol["measurements"])
        if (ms == null || ms.isEmpty()) throw IllegalArgumentException("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
        val p = Policy(
            measurements = AttestUtil.lowerAll(ms),
            hostData = AttestUtil.lowerAll(AttestUtil.asStrList(pol["hostData"]) ?: emptyList()),
            chipIds = AttestUtil.lowerAll(AttestUtil.asStrList(pol["chipIds"]) ?: emptyList()),
            allowDebug = pol["allowDebug"] == true,
            requireEcdsaP384 = pol["requireEcdsaP384"] != false,
            minGuestSvn = AttestUtil.asFinite(pol["minGuestSvn"]),
            minReportedTcb = floors["minReportedTcb"],
            minCommittedTcb = floors["minCommittedTcb"],
            minLaunchTcb = floors["minLaunchTcb"],
            requireVmpl = pol["requireVmpl"],
            requireVmplPresent = pol.containsKey("requireVmpl"),
        )
        return Verifier(family, pin, binding, p, cfg["clockSkewMs"])
    }
}
