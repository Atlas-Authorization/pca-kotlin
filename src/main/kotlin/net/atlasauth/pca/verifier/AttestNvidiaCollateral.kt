package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.time.LocalDateTime
import java.time.ZoneOffset

/**
 * NVIDIA GPU-CC collateral: Reference Integrity Manifests (SWID/CoRIM XML, enveloped XMLDSig, strict profile), the golden
 * measurement comparison with NVIDIA's merge / alternatives / NVDEC0 rules, the driver / VBIOS version binding, certificate
 * revocation through CRLs and OCSP (RFC 6960), and a firmware policy. Fetching is never automatic: the RIMs, CRLs and OCSP
 * responses arrive with the evidence. Same checks, order and reason text as the reference.
 */
internal object AttestNvidiaCollateral {
    private const val NS_DSIG = "http://www.w3.org/2000/09/xmldsig#"
    private const val ALG_C14N11 = "http://www.w3.org/2006/12/xml-c14n11"
    private const val ALG_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    private const val ALG_ECDSA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    private const val ALG_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    private const val NVDEC0_OFF = 0x55
    private const val NVDEC_BLOCK = 35

    class Golden(val index: Int, val active: Boolean, val alternatives: Int, val size: Int, val hashes: List<String>)

    class Rim(val product: String, val version: String, val golden: Map<Int, Golden>)

    private fun pemOfDerB64(b64: String): String {
        val body = AttestUtil.stripJsSpace(b64)
        val lines = ArrayList<String>()
        var i = 0
        while (i < body.length) {
            lines.add(body.substring(i, Math.min(i + 64, body.length)))
            i += 64
        }
        return "-----BEGIN CERTIFICATE-----\n" + lines.joinToString("\n") + "\n-----END CERTIFICATE-----"
    }

    private val HASH_ATTR = Regex("Hash[0-9]+")
    private val LOWER_HEX = Regex("[0-9a-f]+")

    /** Verifies a RIM document and returns its golden measurements: the manifest, or the failure reason. */
    fun verifyRim(xml: String, rimPins: List<String>, nowMs: Long): Pair<Rim?, String> {
        fun fail(r: String) = Pair<Rim?, String>(null, r)
        if (xml.isEmpty() || xml.codePointCount(0, xml.length) > 4_000_000) return fail("RIM: empty or oversized document")
        if (rimPins.isEmpty()) return fail("RIM: no pinned RIM root configured")
        val doc = try {
            AttestXml.parse(xml)
        } catch (e: AttErr) {
            return fail("RIM: verification error (fail closed): " + AttestUtil.errMsg(e))
        }
        if (doc.violation != "") return fail("RIM: " + doc.violation)
        val root = doc.root
        if (root.local != "SoftwareIdentity") return fail("RIM: root element is not SoftwareIdentity")
        if (root.descendantsNs(NS_DSIG, "Signature") != 1) return fail("RIM: expected exactly one Signature element")
        val sigs = root.elementChildrenNs(NS_DSIG, "Signature")
        if (sigs.size != 1) return fail("RIM: the Signature must be a direct child of the root")
        val sig = sigs[0]
        val signedInfo = sig.elementChildrenNs(NS_DSIG, "SignedInfo")
        if (signedInfo.size != 1) return fail("RIM: expected exactly one SignedInfo")
        val si = signedInfo[0]
        fun algOf(els: List<AttestXml.Node>): String = if (els.isEmpty()) "" else els[0].attr("Algorithm")
        if (algOf(si.elementChildrenNs(NS_DSIG, "CanonicalizationMethod")) != ALG_C14N11) return fail("RIM: CanonicalizationMethod must be C14N 1.1")
        if (algOf(si.elementChildrenNs(NS_DSIG, "SignatureMethod")) != ALG_ECDSA384) return fail("RIM: SignatureMethod must be ECDSA-SHA384")
        val refs = si.elementChildrenNs(NS_DSIG, "Reference")
        if (refs.size != 1) return fail("RIM: expected exactly one Reference")
        val ref = refs[0]
        if (ref.attr("URI") != "") return fail("RIM: Reference URI must be \"\" (the whole document)")
        var holder = ref
        val ts = ref.elementChildrenNs(NS_DSIG, "Transforms")
        if (ts.isNotEmpty()) holder = ts[0]
        val transforms = holder.elementChildrenNs(NS_DSIG, "Transform").map { it.attr("Algorithm") }
        if (transforms.size != 2 || transforms[0] != ALG_ENVELOPED || transforms[1] != ALG_C14N11) return fail("RIM: transforms must be exactly [enveloped-signature, C14N 1.1]")
        if (algOf(ref.elementChildrenNs(NS_DSIG, "DigestMethod")) != ALG_SHA384) return fail("RIM: DigestMethod must be SHA-384")
        var digestValue = ""
        var sigValueB64 = ""
        val dv = ref.elementChildrenNs(NS_DSIG, "DigestValue")
        if (dv.isNotEmpty()) digestValue = AttestUtil.stripJsSpace(dv[0].textContent())
        val sv = sig.elementChildrenNs(NS_DSIG, "SignatureValue")
        if (sv.isNotEmpty()) sigValueB64 = AttestUtil.stripJsSpace(sv[0].textContent())
        if (digestValue == "" || sigValueB64 == "") return fail("RIM: missing DigestValue / SignatureValue")

        val certB64 = ArrayList<String>()
        val ki = sig.elementChildrenNs(NS_DSIG, "KeyInfo")
        if (ki.isNotEmpty()) {
            val xd = ki[0].elementChildrenNs(NS_DSIG, "X509Data")
            if (xd.isNotEmpty()) for (c in xd[0].elementChildrenNs(NS_DSIG, "X509Certificate")) certB64.add(c.textContent())
        }
        if (certB64.isEmpty()) return fail("RIM: no signer certificates in KeyInfo")
        val (chain, why) = AttestNvidia.verifyDeviceChain(certB64.joinToString("\n") { pemOfDerB64(it) }, rimPins, nowMs)
        if (chain == null) return fail("RIM signer chain: $why")

        val siCanon = AttestXml.canonicalize(si, si.parent!!.scope(), null)
        val sigRaw = AttestUtil.nodeB64(sigValueB64)
        if (sigRaw.size != 96) return fail("RIM: SignatureValue is not a 96-byte P-384 signature")
        val lk = try { AttestCert.keyOfCert(chain[0]) } catch (e: AttErr) { null }
        val pub = lk?.pub as? ECPublicKey
        if (pub == null || !AttestUtil.verifyRawEcdsa(pub, AttestUtil.sha384(siCanon.toByteArray(Charsets.UTF_8)), sigRaw)) return fail("RIM: SignedInfo signature does not verify under the signer certificate")

        val canon = AttestXml.canonicalize(root, emptyMap(), sig)
        val h = AttestUtil.sha384(canon.toByteArray(Charsets.UTF_8))
        if (java.util.Base64.getEncoder().encodeToString(h) != digestValue) return fail("RIM: document digest does not match the signed DigestValue")

        var meta: AttestXml.Node? = null
        var payload: AttestXml.Node? = null
        for (c in root.elementChildren()) {
            if (meta == null && c.local == "Meta") meta = c
            if (payload == null && c.local == "Payload") payload = c
        }
        if (meta == null || payload == null) return fail("RIM: missing Meta / Payload")
        val golden = LinkedHashMap<Int, Golden>()
        for (r in payload.elementChildren()) {
            if (r.local != "Resource" || r.attr("type") != "Measurement") continue
            val index = AttestNvidia.jsNumberFromString(r.attr("index"))
            val alts = AttestNvidia.jsNumberFromString(r.attr("alternatives"))
            val size = AttestNvidia.jsNumberFromString(r.attr("size"))
            val hs = ArrayList<Pair<Int, String>>()
            for (a in r.attrs) {
                if (HASH_ATTR.matches(a.local)) hs.add(Pair(a.local.substring(4).toIntOrNull() ?: 0, a.value.lowercase()))
            }
            val sorted = hs.sortedBy { it.first } // stable
            fun isInt(f: Double?, min: Double): Boolean = f != null && f == Math.floor(f) && f >= min && Math.abs(f) < 9.2e18
            if (index == null || alts == null || size == null || !isInt(index, 0.0) || !isInt(alts, 1.0) || !isInt(size, 1.0)) return fail("RIM: malformed Measurement resource")
            val hashes = sorted.map { it.second }
            var bad = hashes.size != alts.toInt()
            for (hh in hashes) if (!LOWER_HEX.matches(hh) || hh.length != size.toInt() * 2) bad = true
            if (bad) return fail("RIM: Measurement ${index.toInt()} hash list is inconsistent with alternatives/size")
            if (golden.containsKey(index.toInt())) return fail("RIM: duplicate Measurement index ${index.toInt()}")
            golden[index.toInt()] = Golden(index.toInt(), r.attr("active").lowercase() == "true", alts.toInt(), size.toInt(), hashes)
        }
        if (golden.isEmpty()) return fail("RIM: no measurements")
        return Pair(Rim(meta.attr("product"), meta.attr("colloquialVersion"), golden), "")
    }

    // ---- RIM ids named by the (signed) GPU report ----

    class RimIds(val chip: String, val driver: String, val vbios: String, val driverVersion: String, val vbiosVersion: String)

    private fun opaqueAscii(b: ByteArray?): String {
        if (b == null) return ""
        val s = String(b, Charsets.ISO_8859_1).trimEnd('\u0000')
        return AttestUtil.jsTrim(s)
    }

    private val CHIP_NAME = Regex("[A-Z][A-Z0-9]{2,11}")

    fun rimIdsForReport(rep: AttestNvidia.Report): RimIds? {
        val o = rep.opaque
        val driverVersion = opaqueAscii(o[AttestNvidia.OPAQUE_DRIVER_VERSION])
        val vb = o[AttestNvidia.OPAQUE_VBIOS_VERSION]
        val project = opaqueAscii(o[17]).uppercase()
        val projectSku = opaqueAscii(o[18]).uppercase()
        val chipSku = opaqueAscii(o[15]).uppercase()
        if (driverVersion == "" || vb == null || project == "" || projectSku == "" || chipSku == "") return null
        var chip = "GH100"
        val raw = o[AttestNvidia.OPAQUE_CHIP_INFO]
        if (raw != null) {
            chip = opaqueAscii(raw)
            if (!CHIP_NAME.matches(chip)) return null
        }
        val vbiosVersion = AttestNvidia.formatVbiosVersion(vb)
        val driver = if (chip == "GH100") "NV_GPU_DRIVER_GH100_$driverVersion" else "NV_GPU_CC_DRIVER_${chip}_$driverVersion"
        val vbios = "NV_GPU_VBIOS_${project}_${projectSku}_${chipSku}_" + vbiosVersion.replace(".", "").uppercase()
        return RimIds(chip, driver, vbios, driverVersion, vbiosVersion)
    }

    /** Compares a report with the driver and VBIOS RIMs (NVIDIA's merge / alternatives / NVDEC0 rules); "" when it matches. */
    fun compareReportToRims(rep: AttestNvidia.Report, driver: Rim, vbios: Rim): String {
        val merged = HashMap<Int, Golden>()
        for (g in driver.golden.values) if (g.active) merged[g.index] = g
        for (i in vbios.golden.keys.sorted()) {
            val g = vbios.golden.getValue(i)
            if (!g.active) continue
            if (merged.containsKey(g.index)) return "driver and VBIOS RIMs both have an active measurement at index ${g.index}"
            merged[g.index] = g
        }
        if (merged.isEmpty()) return "RIMs carry no active golden measurements"
        val runtime = HashMap<Int, ByteArray>()
        for (m in rep.measurements) runtime[m.index - 1] = m.digest
        if (merged.size > runtime.size) return "RIMs list more active measurements than the report carries"
        val nvdec = rep.opaque[11]
        val nvdecDisabled = nvdec != null && nvdec.isNotEmpty() && (nvdec[0].toInt() and 0xff) == NVDEC0_OFF
        var mismatches = 0
        for (index in merged.keys.sorted()) {
            val g = merged.getValue(index)
            if (index + 1 == NVDEC_BLOCK && nvdecDisabled) continue
            val digest = runtime[index]
            val hex = if (digest != null) AttestUtil.hex(digest) else ""
            if (digest == null || digest.size != g.size || !g.hashes.contains(hex)) mismatches++
        }
        if (mismatches > 0) return "runtime measurements differ from the golden RIM values at $mismatches index(es)"
        return ""
    }

    /**
     * Checks the device chain against CRLs: every CRL must verify under one chain certificate and be fresh, no chain certificate
     * may be listed by its issuer's CRL, and each required issuer must have a verified CRL. "" when it holds.
     */
    fun checkChainRevocation(chain: List<AttestCert.Cert>, crls: List<ByteArray>, nowMs: Long, requireIssuers: List<String>): String {
        if (crls.isEmpty()) return "no CRLs supplied"
        val covered = HashSet<Int>()
        for ((ci, crl) in crls.withIndex()) {
            var issuerIdx = -1
            var revoked: Set<String>? = null
            var lastReason = "no chain certificate verifies it"
            for ((i, cert) in chain.withIndex()) {
                val k = try { AttestCert.keyOfCert(cert) } catch (e: AttErr) { continue }
                val (rv, why) = AttestIntel.verifyCrl(crl, k, nowMs)
                if (why == "") {
                    issuerIdx = i
                    revoked = rv
                    break
                }
                if (lastReason == "no chain certificate verifies it" || lastReason.contains("signature does not verify")) lastReason = why
            }
            if (issuerIdx < 0 || revoked == null) return "CRL #$ci rejected: $lastReason"
            covered.add(issuerIdx)
            for (i in 0 until chain.size - 1) {
                if (i + 1 == issuerIdx && revoked.contains(chain[i].serialHex())) return "chain certificate '${AttestNvidia.subjectLine(chain[i])}' is revoked"
            }
        }
        for (need in requireIssuers) {
            var found = false
            for (i in covered) if (AttestCert.nameText(chain[i].rawSubject).contains(need)) found = true
            if (!found) return "no verified CRL issued by a certificate matching '$need'"
        }
        return ""
    }

    // ---- firmware policy ----

    private val DEC10_VERSION = Regex("[0-9]+(\\.[0-9]+)*")
    private val HEX16_VERSION = Regex("[0-9a-fA-F]{1,4}(\\.[0-9a-fA-F]{1,4})*")

    private fun parseVersion(v: String, radix: Int): List<Double>? {
        val re = if (radix == 16) HEX16_VERSION else DEC10_VERSION
        if (!re.matches(v)) return null
        val out = ArrayList<Double>()
        for (p in v.split(".")) {
            val n = try { BigInteger(p, radix) } catch (e: NumberFormatException) { return null }
            out.add(n.toDouble())
        }
        return out
    }

    private fun cmpVersion(a: List<Double>, b: List<Double>): Int {
        val n = Math.max(a.size, b.size)
        for (i in 0 until n) {
            val x = if (i < a.size) a[i] else 0.0
            val y = if (i < b.size) b[i] else 0.0
            val d = x - y
            if (d != 0.0) return if (d < 0) -1 else 1
        }
        return 0
    }

    class FirmwarePolicy(
        val minD: List<Double>?, val minV: List<Double>?, val denyD: List<List<Double>>, val denyV: List<List<Double>>,
        val minDText: String, val minVText: String,
    ) {
        fun check(ids: RimIds): String {
            val d = parseVersion(ids.driverVersion, 10) ?: return "driver version '${ids.driverVersion}' in the GPU report is not parseable"
            val v = parseVersion(ids.vbiosVersion, 16) ?: return "VBIOS version '${ids.vbiosVersion}' in the GPU report is not parseable"
            if (minD != null && cmpVersion(d, minD) < 0) return "driver ${ids.driverVersion} is below the minimum $minDText"
            if (minV != null && cmpVersion(v, minV) < 0) return "VBIOS ${ids.vbiosVersion} is below the minimum $minVText"
            for (x in denyD) if (cmpVersion(d, x) == 0) return "driver ${ids.driverVersion} is on the deny list"
            for (x in denyV) if (cmpVersion(v, x) == 0) return "VBIOS ${ids.vbiosVersion} is on the deny list"
            return ""
        }
    }

    private fun compileFirmwarePolicy(fw: Map<String, Any?>): FirmwarePolicy {
        fun need(v: String, radix: Int, what: String): List<Double> =
            parseVersion(v, radix) ?: throw IllegalArgumentException("nvidiaCollateralHook: malformed $what '$v'")
        var minD: List<Double>? = null
        var minV: List<Double>? = null
        var minDText = ""
        var minVText = ""
        val sd = fw["minDriverVersion"] as? String ?: ""
        if (sd != "") { minD = need(sd, 10, "minDriverVersion"); minDText = sd }
        val sv = fw["minVbiosVersion"] as? String ?: ""
        if (sv != "") { minV = need(sv, 16, "minVbiosVersion"); minVText = sv }
        val denyD = AttestUtil.anyStrings(fw["denyDriverVersions"]).map { need(it, 10, "denyDriverVersions entry") }
        val denyV = AttestUtil.anyStrings(fw["denyVbiosVersions"]).map { need(it, 16, "denyVbiosVersions entry") }
        return FirmwarePolicy(minD, minV, denyD, denyV, minDText, minVText)
    }

    // ---- the collateral hook ----

    class Bundle(val driverRim: String, val vbiosRim: String, val crls: List<ByteArray>, val ocsp: List<ByteArray>)

    /** The post-verification collateral check of the NVIDIA verifier. Its bundle is the collateral the evidence carries. */
    class Hook internal constructor(
        private val rimPins: List<String>,
        private val revocation: String?,
        private val requireCrls: Boolean,
        private val requireIssuers: List<String>,
        private val firmware: FirmwarePolicy?,
        private val bundle: Bundle?,
    ) {
        /** The hook bound to the collateral of one evidence object (null: none supplied). */
        fun withBundle(c: Map<String, Any?>?): Hook {
            if (c == null) return Hook(rimPins, revocation, requireCrls, requireIssuers, firmware, null)
            val b = Bundle(
                c["driverRimXml"] as? String ?: "",
                c["vbiosRimXml"] as? String ?: "",
                AttestUtil.anyStrings(c["crls"]).map { AttestUtil.nodeB64(it) },
                AttestUtil.anyStrings(c["ocsp"]).map { AttestUtil.nodeB64(it) },
            )
            return Hook(rimPins, revocation, requireCrls, requireIssuers, firmware, b)
        }

        /** The hook proper: the failure reason, or "" when the collateral holds. */
        fun run(rep: AttestNvidia.Report, chain: List<AttestCert.Cert>, nowMs: Long): String {
            val ids = rimIdsForReport(rep) ?: return "GPU report does not carry the opaque fields needed to name its RIMs"
            val leaf = chain[0]
            val subject = AttestCert.nameText(leaf.rawSubject)
            val chipRe = Regex("(^|[^A-Za-z0-9])" + Regex.escape(ids.chip) + "([^A-Za-z0-9]|$)")
            if (!chipRe.containsMatchIn(subject)) return "device leaf subject '${subject.replace("\n", ", ")}' is not a ${ids.chip} device certificate (chip family mismatch)"
            if (firmware != null) {
                val why = firmware.check(ids)
                if (why != "") return "firmware policy: $why"
            }
            if (bundle == null) return "no RIM collateral supplied for this report"
            val (d, dwhy) = verifyRim(bundle.driverRim, rimPins, nowMs)
            val (v, vwhy) = verifyRim(bundle.vbiosRim, rimPins, nowMs)
            if (d == null) return "driver RIM: $dwhy"
            if (v == null) return "VBIOS RIM: $vwhy"
            if (d.product != ids.chip) return "driver RIM product '${d.product}' does not match the GPU chip '${ids.chip}' (wrong-family manifest)"
            if (v.product != ids.chip) return "VBIOS RIM product '${v.product}' does not match the GPU chip '${ids.chip}' (wrong-family manifest)"
            if (d.version != ids.driverVersion) return "driver RIM version '${d.version}' does not match the report's driver '${ids.driverVersion}'"
            if (v.version.replace(".", "").uppercase() != ids.vbiosVersion.replace(".", "").uppercase()) return "VBIOS RIM version '${v.version}' does not match the report's VBIOS '${ids.vbiosVersion}'"
            val cmp = compareReportToRims(rep, d, v)
            if (cmp != "") return cmp
            var mode = "crl"
            if (revocation != null) mode = revocation else if (!requireCrls) mode = ""
            if (bundle.crls.isNotEmpty() || mode == "crl" || mode == "both") {
                val why = checkChainRevocation(chain, bundle.crls, nowMs, requireIssuers)
                if (why != "") return "revocation: $why"
            }
            if (bundle.ocsp.isNotEmpty() || mode == "ocsp" || mode == "both") {
                val why = checkChainOcsp(chain, bundle.ocsp, nowMs)
                if (why != "") return "revocation (OCSP): $why"
            }
            return ""
        }
    }

    fun newHook(col: Map<String, Any?>): Hook {
        val pins = AttestUtil.asStrList(col["rimRootSpkiSha256"])
        if (pins == null || pins.isEmpty()) throw IllegalArgumentException("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root")
        val fw = AttestUtil.rec(col["firmware"])
        val policy = if (fw != null) compileFirmwarePolicy(fw) else null
        return Hook(pins, col["revocation"] as? String, col["requireCrls"] != false, AttestUtil.anyStrings(col["requireCrlIssuers"]), policy, null)
    }

    // ---- OCSP (RFC 6960) ----

    private const val OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1"
    private const val OCSP_DEFAULT_MAX_MS = 7L * 24 * 3600 * 1000

    private val OCSP_SIG_ALGS = mapOf(
        "1.2.840.10045.4.3.2" to Pair("SHA-256", true),
        "1.2.840.10045.4.3.3" to Pair("SHA-384", true),
        "1.2.840.10045.4.3.4" to Pair("SHA-512", true),
        "1.2.840.113549.1.1.11" to Pair("SHA-256", false),
        "1.2.840.113549.1.1.12" to Pair("SHA-384", false),
        "1.2.840.113549.1.1.13" to Pair("SHA-512", false),
    )

    private val OCSP_CERTID_HASHES = mapOf(
        "1.3.14.3.2.26" to "SHA-1",
        "2.16.840.1.101.3.4.2.1" to "SHA-256",
        "2.16.840.1.101.3.4.2.2" to "SHA-384",
        "2.16.840.1.101.3.4.2.3" to "SHA-512",
    )

    private class ONode(val tag: Int, val hdr: Int, val start: Int, val end: Int) {
        fun constructed(): Boolean = (tag and 0x20) != 0
    }

    private fun readNode(b: ByteArray, off: Int, limit: Int): ONode {
        val t = try {
            AttestDer.tlvAt(b, off, limit)
        } catch (e: AttErr) {
            throw AttErr("not valid DER")
        }
        if ((t.tag and 0x1f) == 0x1f) throw AttErr("multi-byte tags are not supported")
        return ONode(t.tag, off, t.start, t.end)
    }

    private fun kids(b: ByteArray, n: ONode): List<ONode> {
        val out = ArrayList<ONode>()
        var p = n.start
        while (p < n.end) {
            val k = readNode(b, p, n.end)
            out.add(k)
            p = k.end
        }
        return out
    }

    private fun oidOf(b: ByteArray, n: ONode): String {
        if (n.tag != 0x06) throw AttErr("expected an OBJECT IDENTIFIER")
        return AttestDer.oidToDotted(b, AttestDer.Tlv(n.tag, n.start, n.end))
    }

    private val REV_TIME = Regex("[0-9]{14}Z")
    private val OCSP_GEN_TIME = Regex("([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\\.([0-9]*[1-9]))?Z")
    private val OCSP_UTC_TIME = Regex("([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")

    /** A DER time in range (no roll-over): epoch ms, or null. */
    private fun ocspTimeMs(text: String, utc: Boolean): Long? {
        val m = (if (utc) OCSP_UTC_TIME else OCSP_GEN_TIME).matchEntire(text) ?: return null
        val g = m.groupValues
        var y = g[1].toInt()
        if (utc) y = if (y < 50) y + 2000 else y + 1900
        val mo = g[2].toInt()
        val d = g[3].toInt()
        val h = g[4].toInt()
        val mi = g[5].toInt()
        val s = g[6].toInt()
        if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59) return null
        var ms = try {
            LocalDateTime.of(y, mo, d, h, mi, s).toInstant(ZoneOffset.UTC).toEpochMilli()
        } catch (e: java.time.DateTimeException) {
            return null
        }
        if (!utc && g.size > 7 && g[7] != "") ms += (g[7] + "000").substring(0, 3).toInt()
        return ms
    }

    /** Walks the structure: every UTCTime / GeneralizedTime must be a well-formed DER time. */
    private fun timesWellFormed(b: ByteArray, n: ONode): Boolean {
        if (n.constructed()) {
            val ks = try { kids(b, n) } catch (e: AttErr) { return false }
            for (k in ks) if (!timesWellFormed(b, k)) return false
            return true
        }
        if (n.tag == 0x17 || n.tag == 0x18) return ocspTimeMs(String(b, n.start, n.end - n.start, Charsets.ISO_8859_1), n.tag == 0x17) != null
        return true
    }

    private fun stripLeading0(b: ByteArray): ByteArray {
        var i = 0
        while (i < b.size - 1 && b[i].toInt() == 0) i++
        return b.copyOfRange(i, b.size)
    }

    private fun hashBytes(alg: String, b: ByteArray): ByteArray = java.security.MessageDigest.getInstance(alg).digest(b)

    private fun ocspSigOk(alg: String, tbs: ByteArray, sig: ByteArray, k: AttestCert.CertKey): Boolean {
        val a = OCSP_SIG_ALGS[alg] ?: return false
        val pub = k.pub
        return try {
            when (pub) {
                is ECPublicKey -> a.second && AttestUtil.verifyDerEcdsa(pub, hashBytes(a.first, tbs), sig)
                is RSAPublicKey -> {
                    if (a.second) false
                    else {
                        val s = java.security.Signature.getInstance(a.first.replace("-", "") + "withRSA")
                        s.initVerify(pub)
                        s.update(tbs)
                        s.verify(sig)
                    }
                }
                else -> false
            }
        } catch (e: java.security.GeneralSecurityException) {
            false
        }
    }

    class OcspResult(val ok: Boolean, val reason: String, val status: String)

    private fun ofail(reason: String) = OcspResult(false, reason, "")

    /** Verifies one DER OCSPResponse for `cert` (issued by `issuer`); malformation is a failure, never an exception. */
    fun verifyOcspResponse(der: ByteArray, cert: AttestCert.Cert, issuer: AttestCert.Cert, chain: List<AttestCert.Cert>, nowMs: Long): OcspResult = try {
        verifyOcspInner(der, cert, issuer, chain, nowMs)
    } catch (e: AttErr) {
        ofail("OCSP response rejected: " + e.message)
    } catch (e: RuntimeException) {
        ofail("OCSP response rejected: " + (e.message ?: e.javaClass.simpleName))
    }

    private class Single(val status: ONode, val thisUpdate: Long, val nextUpdate: Long, val hasNext: Boolean)

    private fun verifyOcspInner(der: ByteArray, cert: AttestCert.Cert, issuer: AttestCert.Cert, chain: List<AttestCert.Cert>, nowMs: Long): OcspResult {
        val top = try { readNode(der, 0, der.size) } catch (e: AttErr) { return ofail("response is not valid DER") }
        if (top.end != der.size) return ofail("trailing bytes after OCSPResponse")
        if (top.tag != 0x30) throw AttErr("OCSPResponse is not a SEQUENCE")
        val tk = try { kids(der, top) } catch (e: AttErr) { throw AttErr("malformed OCSPResponse") }
        if (tk.isEmpty() || tk[0].tag != 0x0a || tk[0].end - tk[0].start != 1) throw AttErr("malformed OCSPResponse")
        val status = der[tk[0].start].toInt() and 0xff
        if (status != 0) return ofail("OCSP responseStatus is $status (not successful)")
        if (tk.size < 2 || tk[1].tag != 0xa0) return ofail("successful response carries no responseBytes")
        val rbWrap = try { kids(der, tk[1]) } catch (e: AttErr) { throw AttErr("malformed responseBytes") }
        if (rbWrap.size != 1 || rbWrap[0].tag != 0x30) throw AttErr("malformed responseBytes")
        val rb = try { kids(der, rbWrap[0]) } catch (e: AttErr) { throw AttErr("malformed responseBytes") }
        if (rb.size != 2 || rb[1].tag != 0x04) throw AttErr("malformed responseBytes")
        val rtype = oidOf(der, rb[0])
        if (rtype != OID_OCSP_BASIC) return ofail("responseType is not id-pkix-ocsp-basic")
        val basic = der.copyOfRange(rb[1].start, rb[1].end)
        val bn = try { readNode(basic, 0, basic.size) } catch (e: AttErr) { return ofail("BasicOCSPResponse is not valid DER") }
        if (bn.tag != 0x30) throw AttErr("BasicOCSPResponse is not a SEQUENCE")
        val bk = try { kids(basic, bn) } catch (e: AttErr) { throw AttErr("malformed BasicOCSPResponse") }
        if (bk.size < 3 || bk[0].tag != 0x30 || bk[1].tag != 0x30 || bk[2].tag != 0x03) throw AttErr("malformed BasicOCSPResponse")
        if (!timesWellFormed(basic, bn)) return ofail("response carries a malformed (out-of-range) ASN.1 time")
        val tbsNode = bk[0]
        val tbsBytes = basic.copyOfRange(tbsNode.hdr, tbsNode.end)
        val algKids = try { kids(basic, bk[1]) } catch (e: AttErr) { throw AttErr("malformed signatureAlgorithm") }
        if (algKids.isEmpty()) throw AttErr("malformed signatureAlgorithm")
        val sigAlg = oidOf(basic, algKids[0])
        if (!OCSP_SIG_ALGS.containsKey(sigAlg)) return ofail("unsupported OCSP signature algorithm $sigAlg")
        if (bk[2].end - bk[2].start < 1) throw AttErr("malformed signature")
        val sig = basic.copyOfRange(bk[2].start + 1, bk[2].end)

        // ResponseData: [0] version?, responderID, producedAt, responses, [1] extensions?
        val rd = kids(basic, tbsNode)
        var ri = 0
        if (ri < rd.size && rd[ri].tag == 0xa0) ri++
        if (ri + 3 > rd.size) throw AttErr("malformed ResponseData")
        val rid = rd[ri]
        val produced = rd[ri + 1]
        val responses = rd[ri + 2]
        if (produced.tag != 0x18 || responses.tag != 0x30 || (rid.tag != 0xa1 && rid.tag != 0xa2)) throw AttErr("malformed ResponseData")
        val producedAt = ocspTimeMs(String(basic, produced.start, produced.end - produced.start, Charsets.ISO_8859_1), false) ?: 0L

        val subjectSerial = stripLeading0(cert.serial)
        val issuerKeyBits = AttestCert.spkiKeyBits(issuer)
        val singles = kids(basic, responses)
        val matches = ArrayList<Single>()
        for (s in singles) {
            val sk = try { kids(basic, s) } catch (e: AttErr) { throw AttErr("malformed SingleResponse") }
            if (sk.size < 3 || sk[0].tag != 0x30 || sk[2].tag != 0x18) throw AttErr("malformed SingleResponse")
            val cid = try { kids(basic, sk[0]) } catch (e: AttErr) { throw AttErr("malformed CertID") }
            if (cid.size != 4 || cid[0].tag != 0x30 || cid[1].tag != 0x04 || cid[2].tag != 0x04 || cid[3].tag != 0x02) throw AttErr("malformed CertID")
            val hk = try { kids(basic, cid[0]) } catch (e: AttErr) { throw AttErr("malformed CertID hash algorithm") }
            if (hk.isEmpty()) throw AttErr("malformed CertID hash algorithm")
            val hoid = oidOf(basic, hk[0])
            val h = OCSP_CERTID_HASHES[hoid] ?: continue
            val wantName = hashBytes(h, issuer.rawSubject)
            val wantKey = hashBytes(h, issuerKeyBits)
            if (!stripLeading0(basic.copyOfRange(cid[3].start, cid[3].end)).contentEquals(subjectSerial) ||
                !basic.copyOfRange(cid[1].start, cid[1].end).contentEquals(wantName) ||
                !basic.copyOfRange(cid[2].start, cid[2].end).contentEquals(wantKey)
            ) continue
            val tu = ocspTimeMs(String(basic, sk[2].start, sk[2].end - sk[2].start, Charsets.ISO_8859_1), false) ?: 0L
            var nextUpdate = 0L
            var hasNext = false
            if (sk.size > 3 && sk[3].tag == 0xa0) {
                val nk = try { kids(basic, sk[3]) } catch (e: AttErr) { null }
                if (nk != null && nk.size == 1 && nk[0].tag == 0x18) {
                    nextUpdate = ocspTimeMs(String(basic, nk[0].start, nk[0].end - nk[0].start, Charsets.ISO_8859_1), false) ?: 0L
                    hasNext = true
                }
            }
            matches.add(Single(sk[1], tu, nextUpdate, hasNext))
        }
        if (matches.isEmpty()) return ofail("no SingleResponse matches the certificate (serial / issuer hashes differ)")
        if (matches.size > 1) return ofail("ambiguous: multiple SingleResponses match the certificate")
        val one = matches[0]

        // responder authentication
        val issuerKey = AttestCert.keyOfCert(issuer)
        val ridInner = try { kids(basic, rid) } catch (e: AttErr) { throw AttErr("malformed responderID") }
        if (ridInner.size != 1) throw AttErr("malformed responderID")
        val rIn = ridInner[0]
        fun matchesResponder(c: AttestCert.Cert): Boolean {
            if (rid.tag == 0xa1) return rIn.tag == 0x30 && basic.copyOfRange(rIn.hdr, rIn.end).contentEquals(c.rawSubject)
            val bits = try { AttestCert.spkiKeyBits(c) } catch (e: AttErr) { return false }
            if (rIn.tag != 0x04) return false
            return basic.copyOfRange(rIn.start, rIn.end).contentEquals(AttestUtil.sha1(bits))
        }
        val isIssuerId = matchesResponder(issuer)
        if (!(isIssuerId && ocspSigOk(sigAlg, tbsBytes, sig, issuerKey))) {
            val embedded = ArrayList<AttestCert.Cert>()
            if (bk.size > 3 && bk[3].tag == 0xa0) {
                try {
                    val wrap = kids(basic, bk[3])
                    if (wrap.size == 1) {
                        for (c in kids(basic, wrap[0])) {
                            try {
                                embedded.add(AttestCert.parseCertDer(basic.copyOfRange(c.hdr, c.end)))
                            } catch (e: AttErr) {
                                // an unparseable embedded certificate is ignored
                            }
                        }
                    }
                } catch (e: AttErr) {
                    // no usable embedded certificates
                }
            }
            var why = "no embedded responder certificate verifies the response"
            var found: AttestCert.Cert? = null
            for (cand in embedded) {
                if (!matchesResponder(cand)) {
                    why = "embedded certificates do not match the responderID"
                    continue
                }
                if (!cand.hasOcspSigningEku()) {
                    why = "delegated responder certificate lacks the id-kp-OCSPSigning EKU"
                    continue
                }
                val (from, to) = AttestDer.derValidity(cand.raw)
                if (!from.ok || !to.ok || !(from.ms <= nowMs && nowMs <= to.ms)) {
                    why = "delegated responder certificate is outside its validity window"
                    continue
                }
                var signers: List<AttestCert.Cert> = listOf(issuer)
                for ((i, c) in chain.withIndex()) {
                    if (c.raw.contentEquals(issuer.raw)) {
                        signers = chain.subList(i, chain.size)
                        break
                    }
                }
                var okSigner = false
                for (s in signers) if (cand.rawIssuer.contentEquals(s.rawSubject) && AttestCert.certSigOkBy(cand, s)) okSigner = true
                if (!okSigner) {
                    why = "delegated responder certificate is not signed by the supplied NVIDIA chain"
                    continue
                }
                val ck = try { AttestCert.keyOfCert(cand) } catch (e: AttErr) { null }
                if (ck == null || !ocspSigOk(sigAlg, tbsBytes, sig, ck)) {
                    why = "OCSP response signature does not verify under the delegated responder key"
                    continue
                }
                found = cand
                break
            }
            if (found == null) {
                if (isIssuerId) return ofail("OCSP response signature does not verify under the issuer key")
                return ofail(why)
            }
        }

        // freshness
        if (one.thisUpdate > nowMs) return ofail("response thisUpdate is in the future")
        if (producedAt > nowMs) return ofail("response producedAt is in the future")
        if (one.hasNext) {
            if (one.nextUpdate < one.thisUpdate) return ofail("response nextUpdate is invalid")
            if (nowMs > one.nextUpdate) return ofail("response is stale (past nextUpdate)")
        }
        if (nowMs - one.thisUpdate > OCSP_DEFAULT_MAX_MS) return ofail("response is older than the maximum accepted age")

        // certStatus: CHOICE [0] good, [1] revoked, [2] unknown
        val st = one.status
        if ((st.tag and 0xc0) != 0x80) return ofail("malformed certStatus")
        when (st.tag and 0x1f) {
            0 -> return OcspResult(true, "", "good")
            2 -> return OcspResult(true, "", "unknown")
            1 -> {
                val items = try { kids(basic, st) } catch (e: AttErr) { null }
                if (items == null || items.isEmpty() || !REV_TIME.matches(String(basic, items[0].start, items[0].end - items[0].start, Charsets.ISO_8859_1))) return ofail("malformed revoked certStatus")
                return OcspResult(true, "", "revoked")
            }
        }
        return ofail("unrecognised certStatus")
    }

    /**
     * Checks the device chain with OCSP responses: every response must verify for exactly one chain certificate, any REVOKED fails,
     * and every certificate that advertises an OCSP responder must have a GOOD response.
     */
    fun checkChainOcsp(chain: List<AttestCert.Cert>, responses: List<ByteArray>, nowMs: Long): String {
        if (chain.size < 2) return "chain too short for OCSP"
        if (responses.isEmpty()) return "no OCSP responses supplied"
        val last = chain.size - 1
        val required = HashSet<Int>()
        for (i in 0 until last) if (chain[i].ocspServers().isNotEmpty()) required.add(i)
        val statuses = HashMap<Int, String>()
        for (i in 0 until last) statuses[i] = "absent"
        for ((ri, der) in responses.withIndex()) {
            var matched = false
            var lastReason = "matches no chain certificate"
            for (i in 0 until last) {
                val r = verifyOcspResponse(der, chain[i], chain[i + 1], chain, nowMs)
                if (!r.ok) {
                    if (!r.reason.startsWith("no SingleResponse matches")) return "OCSP response #$ri for '${AttestNvidia.subjectLine(chain[i])}' rejected: ${r.reason}"
                    lastReason = r.reason
                    continue
                }
                if (matched) return "OCSP response #$ri matches more than one chain certificate"
                matched = true
                if (statuses[i] != "absent") return "duplicate OCSP responses for chain certificate #$i"
                statuses[i] = r.status
                if (r.status == "revoked") return "chain certificate '${AttestNvidia.subjectLine(chain[i])}' is revoked (OCSP)"
            }
            if (!matched) return "OCSP response #$ri rejected: $lastReason"
        }
        for (i in 0 until last) {
            if (required.contains(i) && statuses[i] != "good") return "no GOOD OCSP response for required certificate '${AttestNvidia.subjectLine(chain[i])}' (status: ${statuses[i]})"
        }
        return ""
    }
}
