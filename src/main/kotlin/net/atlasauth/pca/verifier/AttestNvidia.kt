package net.atlasauth.pca.verifier

import java.security.interfaces.ECPublicKey

/**
 * NVIDIA GPU confidential-computing attestation (Hopper / Blackwell): the SPDM 1.1 GET_MEASUREMENTS transcript signed by the GPU's
 * device-identity key, the device certificate chain pinned to the NVIDIA Device Identity CA, the PCA challenge bound through the
 * SPDM request nonce, pinned measurement blocks, and the optional collateral hook (signed RIMs, CRLs, OCSP and a firmware policy:
 * [AttestNvidiaCollateral]). Same checks, order and reason text as the reference verifier. Classical (ECDSA-P384 / SHA-384).
 */
internal object AttestNvidia {
    private const val REQ_LEN = 37
    private const val NONCE_LEN = 32
    private const val SIG_LEN = 96
    private const val MAX_CHAIN = 5

    const val OPAQUE_DRIVER_VERSION = 3
    const val OPAQUE_VBIOS_VERSION = 6
    const val OPAQUE_CHIP_INFO = 35

    class Measurement(val index: Int, val digest: ByteArray)

    class Report(
        val requestVersion: Int, val responseVersion: Int,
        val requestNonce: ByteArray, val measurements: List<Measurement>, val opaque: Map<Int, ByteArray>,
        val signature: ByteArray, val signedBytes: ByteArray,
    )

    private fun le16(b: ByteArray, o: Int): Int = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)

    /** SPDM 1.1+ is the first version with the signed GET_MEASUREMENTS layout parsed here; request and response must agree. Returns the failure reason or null. */
    fun versionProblem(rep: Report): String? =
        if (rep.requestVersion < 0x11 || rep.responseVersion != rep.requestVersion) {
            "SPDM version 0x${Integer.toHexString(rep.requestVersion)}/0x${Integer.toHexString(rep.responseVersion)} is not an accepted GET_MEASUREMENTS version"
        } else null

    /** Parses a request||response transcript; it fails on any structural problem. */
    fun parseSpdmEvidence(b: ByteArray): Report {
        if (b.size < REQ_LEN + 8 + NONCE_LEN + 2 + SIG_LEN) throw AttErr("parseNvidiaSpdmEvidence: transcript too short (${b.size})")
        if ((b[1].toInt() and 0xff) != 0xe0) throw AttErr("parseNvidiaSpdmEvidence: request code 0x${Integer.toHexString(b[1].toInt() and 0xff)} is not GET_MEASUREMENTS")
        val requestNonce = b.copyOfRange(4, 4 + NONCE_LEN)
        val opaque = LinkedHashMap<Int, ByteArray>()
        val r = b.copyOfRange(REQ_LEN, b.size)
        if ((r[1].toInt() and 0xff) != 0x60) throw AttErr("parseNvidiaSpdmEvidence: response code is not MEASUREMENTS")
        val numBlocks = r[4].toInt() and 0xff
        val recLen = (r[5].toInt() and 0xff) or ((r[6].toInt() and 0xff) shl 8) or ((r[7].toInt() and 0xff) shl 16)
        var o = 8
        if (o + recLen + NONCE_LEN + 2 + SIG_LEN > r.size) throw AttErr("parseNvidiaSpdmEvidence: measurement record length overruns transcript")
        val recEnd = o + recLen
        val measurements = ArrayList<Measurement>()
        while (o < recEnd) {
            if (o + 4 > recEnd) throw AttErr("parseNvidiaSpdmEvidence: truncated measurement block header")
            val index = r[o].toInt() and 0xff
            val size = le16(r, o + 2)
            val bodyStart = o + 4
            if (bodyStart + size > recEnd || size < 3) throw AttErr("parseNvidiaSpdmEvidence: measurement block overruns record")
            val vsize = le16(r, bodyStart + 1)
            if (3 + vsize > size) throw AttErr("parseNvidiaSpdmEvidence: DMTF value overruns measurement block")
            measurements.add(Measurement(index, r.copyOfRange(bodyStart + 3, bodyStart + 3 + vsize)))
            o = bodyStart + size
        }
        if (measurements.size != numBlocks) throw AttErr("parseNvidiaSpdmEvidence: header says $numBlocks blocks, parsed ${measurements.size}")
        o += NONCE_LEN
        val opaqueLen = le16(r, o)
        o += 2
        if (o + opaqueLen + SIG_LEN != r.size) throw AttErr("parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript")
        val opaqueEnd = o + opaqueLen
        while (o < opaqueEnd) {
            if (o + 4 > opaqueEnd) throw AttErr("parseNvidiaSpdmEvidence: truncated opaque TLV header")
            val t = le16(r, o)
            val l = le16(r, o + 2)
            o += 4
            if (o + l > opaqueEnd) throw AttErr("parseNvidiaSpdmEvidence: opaque TLV overruns opaque data")
            opaque[t] = r.copyOfRange(o, o + l)
            o += l
        }
        return Report(b[0].toInt() and 0xff, r[0].toInt() and 0xff, requestNonce, measurements, opaque, r.copyOfRange(r.size - SIG_LEN, r.size), b.copyOfRange(0, b.size - SIG_LEN))
    }

    /** `String.prototype.slice` for a (byte) string; negative indices count from the end. */
    private fun jsSlice(s: String, from: Int, to: Int): String {
        val n = s.length
        fun norm(i0: Int): Int {
            var i = i0
            if (i < 0) {
                i += n
                if (i < 0) i = 0
            }
            if (i > n) i = n
            return i
        }
        val a = norm(from)
        val b = norm(to)
        return if (a >= b) "" else s.substring(a, b)
    }

    /** NVIDIA's VBIOS version rendering: byte-reverse, re-pair as dotted hex (`96.00.9f.00.04`). */
    fun formatVbiosVersion(raw: ByteArray): String {
        val rev = ByteArray(raw.size)
        for (i in raw.indices) rev[raw.size - 1 - i] = raw[i]
        val hx = AttestUtil.hex(rev)
        val half = hx.length / 2
        val temp = jsSlice(hx, half, hx.length) + jsSlice(hx, half - 2, half)
        val parts = ArrayList<String>()
        var i = 0
        while (i < temp.length) {
            parts.add(temp.substring(i, Math.min(i + 2, temp.length)))
            i += 2
        }
        return parts.joinToString(".")
    }

    /** Node's `X509Certificate.ca`: BasicConstraints CA:TRUE, and keyCertSign when keyUsage is present. */
    fun certIsCa(c: AttestCert.Cert): Boolean {
        val info = try {
            AttestDer.readCertRoleInfo(c.raw)
        } catch (e: AttErr) {
            return false
        }
        return info.hasBasicConstraints && info.ca && (!info.hasKeyUsage || info.keyCertSign)
    }

    fun subjectLine(c: AttestCert.Cert): String = AttestCert.nameText(c.rawSubject).replace("\n", ", ")

    /**
     * Verifies the device chain (leaf first): every link signed, every issuer a CA, every certificate valid at `nowMs`, an ECDSA
     * P-384 key throughout, the root self-signed and pinned by SPKI SHA-256. The chain, or the failure reason.
     */
    fun verifyDeviceChain(pemText: String, pins: List<String>, nowMs: Long): Pair<List<AttestCert.Cert>?, String> {
        val blocks = AttestCert.pemCertBlocks(pemText)
        if (blocks.isEmpty()) return Pair(null, "device chain unparseable: parsePemChain: no certificates found")
        if (blocks.size > MAX_CHAIN) return Pair(null, "device chain unparseable: parsePemChain: chain longer than $MAX_CHAIN")
        val chain = ArrayList<AttestCert.Cert>(blocks.size)
        for (b in blocks) {
            try {
                chain.add(AttestCert.certFromPem(b))
            } catch (e: AttErr) {
                return Pair(null, "device chain unparseable: " + AttestUtil.errMsg(e))
            }
        }
        for ((i, c) in chain.withIndex()) {
            if (!AttestDer.derValidAt(c.raw, nowMs, 0)) return Pair(null, "device chain cert #$i is outside its validity window")
            val k = try { AttestCert.keyOfCert(c) } catch (e: AttErr) { null }
            if (k == null || k.typ != "ec" || k.curve != "secp384r1") return Pair(null, "device chain cert #$i is not an ECDSA P-384 key")
        }
        for (i in 0 until chain.size - 1) {
            val issuer = chain[i + 1]
            if (!certIsCa(issuer)) return Pair(null, "device chain cert #${i + 1} issues a certificate but is not a CA")
            if (!AttestCert.certSigOkBy(chain[i], issuer)) return Pair(null, "device chain link #$i signature does not verify under its issuer")
        }
        val root = chain[chain.size - 1]
        if (!certIsCa(root) || !AttestCert.certSigOkBy(root, root)) return Pair(null, "device chain root is not a self-signed CA")
        val rk = try { AttestCert.keyOfCert(root) } catch (e: AttErr) { return Pair(null, "device chain root is not a self-signed CA") }
        val pinned = pins.any { it.lowercase() == rk.spkiSha256() }
        if (!pinned) return Pair(null, "chain root is not a pinned NVIDIA root")
        return Pair(chain, "")
    }

    // ---- the verifier ----

    private class Want(val index: Int, val digest: String)

    /** `Number(s)` for a measurement-block key (decimal forms only): the value, or null when it is not a number. */
    fun jsNumberFromString(s: String): Double? {
        val t = AttestUtil.jsTrim(s)
        if (t.isEmpty()) return 0.0
        if (!NUMBER_RE.matches(t)) return null
        return t.toDoubleOrNull()
    }

    private val NUMBER_RE = Regex("[+-]?([0-9]+\\.?[0-9]*|\\.[0-9]+)([eE][+-]?[0-9]+)?")

    private class Verifier(val pins: List<String>, val want: List<Want>, val leafSub: String, val hook: AttestNvidiaCollateral.Hook?) : Attest.VendorImpl {
        override fun verify(ev: Map<String, Any?>?, expected: Attest.Binding?, nowMs: Long): Attest.Result {
            val evidence = AttestUtil.evBytes(ev, "evidence")
            val chainPem = AttestUtil.evString(ev, "certChainPem")
            if (ev == null || evidence == null || chainPem == null) return Attest.fail("no NVIDIA GPU evidence for this action")
            val (chain, why) = verifyDeviceChain(chainPem, pins, nowMs)
            if (chain == null) return Attest.fail(why)
            val leaf = chain[0]
            if (leafSub != "" && !AttestCert.nameText(leaf.rawSubject).contains(leafSub)) return Attest.fail("device leaf subject does not contain '$leafSub'")
            val rep = try {
                parseSpdmEvidence(evidence)
            } catch (e: AttErr) {
                return Attest.fail("GPU attestation report parse failed: " + AttestUtil.errMsg(e))
            }
            val lk = try { AttestCert.keyOfCert(leaf) } catch (e: AttErr) { null }
            val pub = lk?.pub as? ECPublicKey
            if (pub == null || !AttestUtil.verifyRawEcdsa(pub, AttestUtil.sha384(rep.signedBytes), rep.signature)) return Attest.fail("GPU attestation report signature does not verify under the device identity key")
            if (expected == null) return Attest.fail("no expected attestation binding supplied")
            val raw = try {
                Attest.bindingBytes(expected)
            } catch (e: IllegalArgumentException) {
                return Attest.fail("binding not constructible: " + e.message)
            }
            if (!rep.requestNonce.contentEquals(AttestUtil.sha256(raw))) return Attest.fail("SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)")
            val byIndex = HashMap<Int, Measurement>()
            for (m in rep.measurements) byIndex[m.index] = m
            for (w in want) {
                val m = byIndex[w.index] ?: return Attest.fail("measurement block ${w.index} missing from report")
                if (AttestUtil.hex(m.digest) != w.digest) return Attest.fail("measurement block ${w.index} does not match the pinned digest")
            }
            if (hook != null) {
                val col = AttestUtil.rec(ev["collateral"])
                val hwhy = hook.withBundle(col).run(rep, chain, nowMs)
                if (hwhy != "") return Attest.fail(hwhy)
            }
            val sorted = rep.measurements.sortedBy { it.index } // stable
            val h = java.security.MessageDigest.getInstance("SHA-384")
            for (m in sorted) h.update(m.digest)
            val host = LinkedHashMap<String, String>()
            host["attestation_type"] = "nvidia-gpu-cc"
            host["gpu_measurements_sha384"] = AttestUtil.hex(h.digest())
            host["leaf_subject"] = AttestCert.nameText(leaf.rawSubject).replace("\n", ", ")
            val drv = rep.opaque[OPAQUE_DRIVER_VERSION]
            if (drv != null) host["driver_version"] = String(drv, Charsets.ISO_8859_1).trimEnd('\u0000')
            val vb = rep.opaque[OPAQUE_VBIOS_VERSION]
            if (vb != null) host["vbios_version"] = formatVbiosVersion(vb)
            return Attest.Result(true, true, "", AttestUtil.newMeasured("", ""), host)
        }
    }

    fun create(cfg: Map<String, Any?>): Attest.VendorImpl {
        var hook: AttestNvidiaCollateral.Hook? = null
        val col = AttestUtil.rec(cfg["collateral"])
        if (col != null) hook = AttestNvidiaCollateral.newHook(col)
        val pins = AttestUtil.asStrList(cfg["rootSpkiSha256"])
        if (pins == null || pins.isEmpty()) throw IllegalArgumentException("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)")
        val pol = AttestUtil.rec(cfg["policy"]) ?: emptyMap()
        val meas = AttestUtil.rec(pol["measurements"]) ?: emptyMap()
        if (meas.isEmpty() && hook == null) throw IllegalArgumentException("createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)")
        class Entry(val key: String, val idx: Double?, val dig: String)
        val entries = ArrayList<Entry>()
        for ((k, d) in meas) entries.add(Entry(k, jsNumberFromString(k), AttestUtil.jsAnyString(d).lowercase()))
        entries.sortWith { a, b ->
            val x = a.idx ?: 0.0
            val y = b.idx ?: 0.0
            if (x != y) x.compareTo(y) else a.key.compareTo(b.key)
        }
        val want = ArrayList<Want>()
        for (e in entries) {
            val idx = e.idx
            if (idx == null || idx != Math.floor(idx) || idx < 0 || idx > 255) throw IllegalArgumentException("createNvidiaSpdmVerifier: measurement index out of range")
            want.add(Want(idx.toInt(), e.dig))
        }
        return Verifier(pins, want, pol["leafSubjectIncludes"] as? String ?: "", hook)
    }
}
