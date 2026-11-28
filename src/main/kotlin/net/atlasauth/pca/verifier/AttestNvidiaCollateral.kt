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

    class Rim(val product: String, val version: String, val golden: Map<Int, Golden>, val tagId: String = "", val signerSubject: String = "")

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
            AttestXml.parse(if (xml.startsWith("\uFEFF")) xml.substring(1) else xml) // a leading byte-order mark is not content
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
        if (pub == null || !AttestUtil.verifyRawEcdsa(pub, AttestUtil.sha384(Json.utf8(siCanon)), sigRaw)) return fail("RIM: SignedInfo signature does not verify under the signer certificate")

        val canon = AttestXml.canonicalize(root, emptyMap(), sig)
        val h = AttestUtil.sha384(Json.utf8(canon))
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
            val hs = ArrayList<Pair<Double, String>>()
            for (a in r.attrs) {
                if (HASH_ATTR.matches(a.local)) hs.add(Pair(a.local.substring(4).toDouble(), a.value.lowercase())) // HASH_ATTR: ASCII digits only, read as the reference's Number(), never capped to Int
            }
            val sorted = hs.sortedBy { it.first } // stable
            fun isInt(f: Double, min: Double): Boolean = f == Math.floor(f) && f >= min && f < 9.2e18
            // a Measurement index is a one-byte block index: anything larger is refused here instead of saturating in toInt() below (2^40 and 2^40 + 1 would collide)
            if (index == null || alts == null || size == null || !isInt(index, 0.0) || index > 255.0 || !isInt(alts, 1.0) || !isInt(size, 1.0)) return fail("RIM: malformed Measurement resource")
            val hashes = sorted.map { it.second }
            var bad = hashes.size != alts.toInt()
            for (hh in hashes) if (!LOWER_HEX.matches(hh) || hh.length != size.toInt() * 2) bad = true
            if (bad) return fail("RIM: Measurement ${index.toInt()} hash list is inconsistent with alternatives/size")
            if (golden.containsKey(index.toInt())) return fail("RIM: duplicate Measurement index ${index.toInt()}")
            golden[index.toInt()] = Golden(index.toInt(), r.attr("active").lowercase() == "true", alts.toInt(), size.toInt(), hashes)
        }
        if (golden.isEmpty()) return fail("RIM: no measurements")
        return Pair(Rim(meta.attr("product"), meta.attr("colloquialVersion"), golden, root.attr("tagId"), AttestNvidia.subjectLine(chain[0])), "")
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

    /** One index whose runtime digest differs from the golden values, and the RIM (`driver` or `vbios`) that listed it. */
    class Mismatch(val index: Int, val source: String)

    /** The comparison of a report with the RIMs: `ok` with the number of indices checked, or the reason (and the mismatching indices when that is the reason). */
    class Compared(val ok: Boolean, val checked: Int, val reason: String, val mismatches: List<Mismatch>?)

    private fun cmpFail(reason: String, mismatches: List<Mismatch>? = null) = Compared(false, 0, reason, mismatches)

    /** NVIDIA's merge / alternatives / NVDEC0 rules, with the detail the reference reports. */
    fun compareReport(rep: AttestNvidia.Report, driver: Rim, vbios: Rim): Compared {
        val merged = LinkedHashMap<Int, Pair<Golden, String>>()
        for (g in driver.golden.values) if (g.active) merged[g.index] = Pair(g, "driver")
        for (g in vbios.golden.values) {
            if (!g.active) continue
            if (merged.containsKey(g.index)) return cmpFail("driver and VBIOS RIMs both have an active measurement at index ${g.index}")
            merged[g.index] = Pair(g, "vbios")
        }
        if (merged.isEmpty()) return cmpFail("RIMs carry no active golden measurements")
        val runtime = HashMap<Int, ByteArray>()
        for (m in rep.measurements) runtime[m.index - 1] = m.digest
        if (merged.size > runtime.size) return cmpFail("RIMs list more active measurements than the report carries")
        val nvdec = rep.opaque[11]
        val nvdecDisabled = nvdec != null && nvdec.isNotEmpty() && (nvdec[0].toInt() and 0xff) == NVDEC0_OFF
        val mismatches = ArrayList<Mismatch>()
        var checked = 0
        for (index in merged.keys.sorted()) {
            val (g, source) = merged.getValue(index)
            if (index + 1 == NVDEC_BLOCK && nvdecDisabled) continue
            val digest = runtime[index]
            val hex = if (digest != null) AttestUtil.hex(digest) else ""
            checked++
            if (digest == null || digest.size != g.size || !g.hashes.contains(hex)) mismatches.add(Mismatch(index, source))
        }
        if (mismatches.isNotEmpty()) return cmpFail("runtime measurements differ from the golden RIM values at ${mismatches.size} index(es)", mismatches)
        return Compared(true, checked, "", null)
    }

    /** Compares a report with the driver and VBIOS RIMs (NVIDIA's merge / alternatives / NVDEC0 rules); "" when it matches. */
    fun compareReportToRims(rep: AttestNvidia.Report, driver: Rim, vbios: Rim): String = compareReport(rep, driver, vbios).reason

    /** The CRL distribution points extension (RFC 5280 4.2.1.13). */
    private const val OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31"

    /**
     * Checks the device chain against CRLs: every CRL must verify under one chain certificate and be fresh, no chain certificate
     * may be listed by its issuer's CRL, each required issuer must have a verified CRL, and every chain certificate that
     * `requireFor` demands (`"cdp"`: each non-root certificate that names a CRL distribution point, `"all"`: each non-root
     * certificate, a `List<Long>`: exactly those chain indices, `"none"`: nobody) must be covered by a verified CRL from its issuer
     * (chain[i + 1]). "" when it holds.
     */
    fun checkChainRevocation(chain: List<AttestCert.Cert>, crls: List<ByteArray>, nowMs: Long, requireIssuers: List<String>, requireFor: Any?): String {
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
        val last = chain.size - 1
        val required: List<Int> = when (requireFor) {
            "none" -> emptyList()
            "all" -> (0 until last).toList()
            "cdp" -> (0 until last).filter { chain[it].extValue(OID_CRL_DISTRIBUTION_POINTS) != null }
            is List<*> -> {
                for (x in requireFor) {
                    val d = IntentJs.num(x)
                    if (d == null || d != Math.floor(d) || d < 0 || d >= last) return "requireCrlFor index ${if (d == null) ZkJs.string(x) else if (d == Math.floor(d)) d.toLong().toString() else Json.esNumber(d)} is not a non-root chain certificate"
                }
                requireFor.map { IntentJs.num(it)!!.toInt() }
            }
            else -> throw IllegalArgumentException("nvidiaCollateralHook: requireCrlFor must be 'cdp', 'all' or an array of chain indices")
        }
        for (i in required) {
            if (!covered.contains(i + 1)) return "no verified CRL from the issuer of chain certificate '${AttestNvidia.subjectLine(chain[i])}'"
        }
        return ""
    }

    /** The `requireCrlFor` option of a hook: absent = `"cdp"`; else `"cdp"`, `"all"` or an array of integer chain indices (a `List<Long>`). */
    private fun parseRequireCrlFor(v: Any?): Any {
        // the reference's `String(value)`: an array joins its members' strings (null as empty), an object is "[object Object]"
        fun js(x: Any?): String = when (x) {
            null -> ""
            is List<*> -> x.joinToString(",") { js(it) }
            is Map<*, *> -> "[object Object]"
            else -> AttestUtil.jsAnyString(x)
        }
        val bad = IllegalArgumentException("nvidiaCollateralHook: malformed requireCrlFor '${js(v)}'")
        if (v == null) return "cdp"
        if (v == "cdp" || v == "all") return v
        if (v !is List<*>) throw bad
        val out = ArrayList<Long>()
        for (x in v) {
            if (!IntentJs.isInt(x)) throw bad
            out.add(IntentJs.num(x)!!.toLong())
        }
        return out
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
            if (d < 0) return -1
            if (d != 0.0) return 1 // d > 0, or NaN (two infinite components), which the reference also ranks above
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

    /**
     * Like the reference, every present setting must be well formed: a truthy minimum that is not a version string, a deny list
     * that is not an array, or a deny entry that is not a version string throws (reading them as absent would drop that part of
     * the policy: fail open).
     */
    private fun compileFirmwarePolicy(fw: Map<String, Any?>): FirmwarePolicy {
        fun need(v: Any?, radix: Int, what: String): List<Double> {
            val p = if (v is String) parseVersion(v, radix) else null
            return p ?: throw IllegalArgumentException("nvidiaCollateralHook: malformed $what '${AttestUtil.jsAnyString(v)}'")
        }
        fun denyList(v: Any?, radix: Int, what: String): List<List<Double>> {
            val out = ArrayList<List<Double>>()
            if (v == null) return out
            if (v !is List<*>) throw IllegalArgumentException("nvidiaCollateralHook: $what must be an array")
            for (x in v) out.add(need(x, radix, "$what entry"))
            return out
        }
        val sd = fw["minDriverVersion"]
        val sv = fw["minVbiosVersion"]
        val minD = if (IntentRevocation.truthy(sd)) need(sd, 10, "minDriverVersion") else null
        val minV = if (IntentRevocation.truthy(sv)) need(sv, 16, "minVbiosVersion") else null
        val denyD = denyList(fw["denyDriverVersions"], 10, "denyDriverVersions")
        val denyV = denyList(fw["denyVbiosVersions"], 16, "denyVbiosVersions")
        return FirmwarePolicy(minD, minV, denyD, denyV, if (minD != null) sd as String else "", if (minV != null) sv as String else "")
    }

    // ---- the collateral hook ----

    class Bundle(val driverRim: String, val vbiosRim: String, val crls: List<ByteArray>, val ocsp: List<ByteArray>)

    /** The post-verification collateral check of the NVIDIA verifier. Its bundle is the collateral the evidence carries. */
    class Hook internal constructor(
        private val rimPins: List<String>,
        private val revocation: String?,
        private val requireCrls: Boolean,
        private val requireIssuers: List<String>,
        private val requireCrlFor: Any,
        private val firmware: FirmwarePolicy?,
        private val bundle: Bundle?,
    ) {
        /** The hook bound to the collateral of one evidence object (null: none supplied). */
        fun withBundle(c: Map<String, Any?>?): Hook {
            if (c == null) return Hook(rimPins, revocation, requireCrls, requireIssuers, requireCrlFor, firmware, null)
            val b = Bundle(c["driverRimXml"] as? String ?: "", c["vbiosRimXml"] as? String ?: "", b64All(c["crls"]), b64All(c["ocsp"]))
            return Hook(rimPins, revocation, requireCrls, requireIssuers, requireCrlFor, firmware, b)
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
                // coverage is demanded only where CRLs are required (mode crl / both); supplied-but-not-required CRLs keep the plain check
                val why = checkChainRevocation(chain, bundle.crls, nowMs, requireIssuers, if (mode == "crl" || mode == "both") requireCrlFor else "none")
                if (why != "") return "revocation: $why"
            }
            if (bundle.ocsp.isNotEmpty() || mode == "ocsp" || mode == "both") {
                val why = checkChainOcsp(chain, bundle.ocsp, nowMs)
                if (why != "") return "revocation (OCSP): $why"
            }
            return ""
        }
    }

    private fun b64All(v: Any?): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        for (s in AttestUtil.anyStrings(v)) out.add(AttestUtil.nodeB64(s))
        return out
    }

    fun newHook(col: Map<String, Any?>): Hook {
        val pins = AttestUtil.asStrList(col["rimRootSpkiSha256"])
        if (pins == null || pins.isEmpty()) throw IllegalArgumentException("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root")
        val fw = AttestUtil.rec(col["firmware"])
        if (IntentRevocation.truthy(col["firmware"]) && fw == null) throw IllegalArgumentException("nvidiaCollateralHook: firmware must be an object")
        val policy = if (fw != null) compileFirmwarePolicy(fw) else null
        val needIssuers = col["requireCrlIssuers"]
        val issuers = if (needIssuers == null) emptyList() else AttestUtil.asStrList(needIssuers) ?: throw IllegalArgumentException("nvidiaCollateralHook: requireCrlIssuers must list only strings")
        return Hook(pins, col["revocation"] as? String, col["requireCrls"] != false, issuers, parseRequireCrlFor(col["requireCrlFor"]), policy, null)
    }

    // ---- OCSP (RFC 6960) ----

    private const val OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1"
    const val OCSP_DEFAULT_MAX_MS = 7L * 24 * 3600 * 1000

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

    /** BER parse of the whole tree like the reference's asn1 reader: every constructed node's children must exactly fill it, at any depth (AttErr otherwise). */
    /** Every nested length must fit; the embedded certificates `[0]` (a direct child of the root) are left to the strict certificate parser, which refuses a malformed one only when it is used. */
    private fun derTreeOk(b: ByteArray, n: ONode, root: Boolean = true) {
        if (!n.constructed()) return
        for (k in kids(b, n)) if (!(root && k.tag == 0xa0)) derTreeOk(b, k, false)
    }

    /** Walks the structure: every UTCTime / GeneralizedTime must be a well-formed DER time. */
    private fun timesWellFormed(b: ByteArray, n: ONode): Boolean {
        if (n.constructed()) {
            // an unreadable subtree here is only the embedded certificates (derTreeOk vetted the rest); their strict parse refuses them when used
            val ks = try { kids(b, n) } catch (e: AttErr) { return true }
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
                    if (a.second || k.typ != "rsa") false // an rsa-pss key never verifies a PKCS#1 signature
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

    /** The verdict of one OCSP response: `status` is good, revoked or unknown; the instants are epoch ms; `responder` is `issuer` or `delegated`. */
    class OcspResult(
        val ok: Boolean, val reason: String, val status: String,
        val thisUpdate: Long = 0, val nextUpdate: Long? = null, val producedAt: Long = 0, val revokedAt: Long? = null, val revocationReason: Int? = null, val responder: String = "",
    )

    /** Verification options: the maximum age of `thisUpdate` (default 7 days), the tolerated clock skew (default 0) and a nonce the response must echo. */
    class OcspOptions(val maxAgeMs: Double = OCSP_DEFAULT_MAX_MS.toDouble(), val clockSkewMs: Double = 0.0, val expectedNonce: ByteArray? = null)

    private fun ofail(reason: String) = OcspResult(false, reason, "")

    private const val OID_OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2"

    /** Verifies one DER OCSPResponse for `cert` (issued by `issuer`); malformation is a failure, never an exception. */
    fun verifyOcspResponse(der: ByteArray, cert: AttestCert.Cert, issuer: AttestCert.Cert, chain: List<AttestCert.Cert>, nowMs: Long, opts: OcspOptions = OcspOptions()): OcspResult = try {
        verifyOcspInner(der, cert, issuer, chain, nowMs, opts)
    } catch (e: AttErr) {
        ofail("OCSP response rejected: " + e.message)
    } catch (e: RuntimeException) {
        ofail("OCSP response rejected: " + (e.message ?: e.javaClass.simpleName))
    }

    private class Single(val status: ONode, val thisUpdate: Long, val nextUpdate: Long, val hasNext: Boolean)

    private fun verifyOcspInner(der: ByteArray, cert: AttestCert.Cert, issuer: AttestCert.Cert, chain: List<AttestCert.Cert>, nowMs: Long, opts: OcspOptions): OcspResult {
        val skew = opts.clockSkewMs
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
        val bn = try { readNode(basic, 0, basic.size).also { derTreeOk(basic, it) } } catch (e: AttErr) { return ofail("BasicOCSPResponse is not valid DER") }
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
        // timesWellFormed walked tbsResponseData (a SEQUENCE) and refused any malformed GeneralizedTime in it, producedAt included
        val producedAt = ocspTimeMs(String(basic, produced.start, produced.end - produced.start, Charsets.ISO_8859_1), false) ?: throw AttErr("producedAt is malformed")

        val subjectSerial = stripLeading0(cert.serial)
        val issuerKeyBits = AttestCert.spkiKeyBits(issuer)
        val singles = kids(basic, responses)
        val matches = ArrayList<Single>()
        for (s in singles) {
            if (s.tag != 0x30) throw AttErr("malformed SingleResponse")
            val sk = try { kids(basic, s) } catch (e: AttErr) { throw AttErr("malformed SingleResponse") }
            if (sk.size < 3 || sk[0].tag != 0x30 || sk[2].tag != 0x18) throw AttErr("malformed SingleResponse")
            // timesWellFormed walked this SEQUENCE: its [0] parses and every GeneralizedTime in it is well formed
            var nextUpdate = 0L
            var hasNext = false
            var si = 3
            if (si < sk.size && sk[si].tag == 0xa0) {
                val nk = try { kids(basic, sk[si]) } catch (e: AttErr) { throw AttErr("nextUpdate is malformed") }
                if (nk.size != 1 || nk[0].tag != 0x18) throw AttErr("nextUpdate is malformed")
                nextUpdate = ocspTimeMs(String(basic, nk[0].start, nk[0].end - nk[0].start, Charsets.ISO_8859_1), false) ?: throw AttErr("nextUpdate is malformed")
                hasNext = true
                si++
            }
            if (si < sk.size && sk[si].tag == 0xa1) si++ // singleExtensions
            // on every SingleResponse: an unknown element must not hide a stale nextUpdate
            if (si != sk.size) throw AttErr("malformed SingleResponse")
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
            val tu = ocspTimeMs(String(basic, sk[2].start, sk[2].end - sk[2].start, Charsets.ISO_8859_1), false) ?: throw AttErr("thisUpdate is malformed")
            matches.add(Single(sk[1], tu, nextUpdate, hasNext))
        }
        if (matches.isEmpty()) return ofail("no SingleResponse matches the certificate (serial / issuer hashes differ)")
        if (matches.size > 1) return ofail("ambiguous: multiple SingleResponses match the certificate")
        val one = matches[0]

        // responder authentication
        var responder = "issuer"
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
                // an unparseable embedded certificate rejects the response
                for (st in kids(basic, bk[3])) for (c in kids(basic, st)) embedded.add(AttestCert.parseCertDer(basic.copyOfRange(c.hdr, c.end)))
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
                if (!from.ok || !to.ok || !(from.ms.toDouble() - skew <= nowMs.toDouble() && nowMs <= to.ms)) {
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
                for (s in signers) if (AttestCert.checkIssued(cand, s) && AttestCert.certSigOkBy(cand, s)) okSigner = true
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
            responder = "delegated"
        }

        // nonce
        if (opts.expectedNonce != null) {
            val exts = rd.getOrNull(ri + 3)
            var echoed: ByteArray? = null
            if (exts != null && exts.tag == 0xa1) {
                val list = kids(basic, exts)
                val seq = if (list.size == 1 && list[0].tag == 0x30) kids(basic, list[0]) else emptyList()
                for (e in seq) {
                    val parts = kids(basic, e)
                    if (parts.size < 2 || oidOf(basic, parts[0]) != OID_OCSP_NONCE) continue
                    val v = parts[parts.size - 1]
                    val raw = basic.copyOfRange(v.start, v.end)
                    var got = raw
                    try {
                        val inner = readNode(raw, 0, raw.size)
                        if (inner.end == raw.size && inner.tag == 0x04) got = raw.copyOfRange(inner.start, inner.end)
                    } catch (x: AttErr) {
                        // not a nested OCTET STRING: the value itself is the echoed nonce
                    }
                    echoed = got
                    break
                }
            }
            if (echoed == null) return ofail("response does not echo the nonce")
            if (!echoed.contentEquals(opts.expectedNonce)) return ofail("response nonce does not match the request nonce")
        }

        // freshness
        if (!(one.thisUpdate.toDouble() <= nowMs.toDouble() + skew)) return ofail("response thisUpdate is in the future")
        if (!(producedAt.toDouble() <= nowMs.toDouble() + skew)) return ofail("response producedAt is in the future")
        if (one.hasNext) {
            if (one.nextUpdate < one.thisUpdate) return ofail("response nextUpdate is invalid")
            if (!(nowMs <= one.nextUpdate)) return ofail("response is stale (past nextUpdate)")
        }
        if (!((nowMs - one.thisUpdate).toDouble() <= opts.maxAgeMs)) return ofail("response is older than the maximum accepted age")

        // certStatus: CHOICE [0] good, [1] revoked, [2] unknown
        val st = one.status
        if ((st.tag and 0xc0) != 0x80) return ofail("malformed certStatus")
        // exact tags: good and unknown are primitive NULLs, revoked a constructed RevokedInfo
        when (st.tag) {
            0x80 -> return OcspResult(true, "", "good", one.thisUpdate, if (one.hasNext) one.nextUpdate else null, producedAt, responder = responder)
            0x82 -> return OcspResult(true, "", "unknown", one.thisUpdate, if (one.hasNext) one.nextUpdate else null, producedAt, responder = responder)
            0xa0, 0xa2, 0x81 -> return ofail("malformed certStatus")
            0xa1 -> {
                val items = try { kids(basic, st) } catch (e: AttErr) { emptyList() }
                val rt = if (items.isEmpty()) null else String(basic, items[0].start, items[0].end - items[0].start, Charsets.ISO_8859_1)
                if (rt == null || !REV_TIME.matches(rt)) return ofail("malformed revoked certStatus")
                val at = LocalDateTime.of(rt.substring(0, 4).toInt(), rt.substring(4, 6).toInt(), rt.substring(6, 8).toInt(), rt.substring(8, 10).toInt(), rt.substring(10, 12).toInt(), rt.substring(12, 14).toInt())
                    .toInstant(ZoneOffset.UTC).toEpochMilli()
                var reasonCode: Int? = null
                if (items.size > 1 && items[1].constructed()) {
                    val inner = try { kids(basic, items[1]) } catch (e: AttErr) { emptyList() }
                    if (inner.isNotEmpty() && inner[0].tag == 0x0a && inner[0].end > inner[0].start) reasonCode = BigInteger(basic.copyOfRange(inner[0].start, inner[0].end)).toInt()
                }
                return OcspResult(true, "", "revoked", one.thisUpdate, if (one.hasNext) one.nextUpdate else null, producedAt, at, reasonCode, responder)
            }
        }
        return ofail("unrecognised certStatus")
    }

    /** The chain-level OCSP verdict: `verified` responses, the status of every non-root chain certificate (good, revoked, unknown or absent) and the reason on failure. */
    class ChainOcsp(val ok: Boolean, val reason: String, val verified: Int, val statuses: Map<Int, String>?)

    /** The chain-level options: which certificates must have a GOOD response (`"aia"`, `"all"` or chain indices), the age and skew bounds, and a nonce per chain index. */
    class ChainOcspOptions(val requireGood: Any? = null, val maxAgeMs: Double? = null, val clockSkewMs: Double? = null, val expectedNonces: List<ByteArray?>? = null)

    /**
     * Checks the device chain with OCSP responses: every response must verify for exactly one chain certificate, any REVOKED fails, and every certificate
     * `requireGood` names (default: each non-root certificate that advertises an OCSP responder) must have a GOOD response.
     */
    fun checkChainOcspFull(chain: List<AttestCert.Cert>, responses: List<ByteArray>, nowMs: Long, co: ChainOcspOptions = ChainOcspOptions()): ChainOcsp {
        if (chain.size < 2) return ChainOcsp(false, "chain too short for OCSP", 0, null)
        if (responses.isEmpty()) return ChainOcsp(false, "no OCSP responses supplied", 0, null)
        val last = chain.size - 1
        val required = LinkedHashSet<Int>()
        val policy = co.requireGood ?: "aia"
        if (policy is List<*>) {
            for (x in policy) {
                val d = IntentJs.num(x)
                if (d == null || d != Math.floor(d) || d < 0 || d >= last) {
                    return ChainOcsp(false, "requireGood index ${if (d == null) ZkJs.string(x) else if (d == Math.floor(d)) d.toLong().toString() else Json.esNumber(d)} is not a non-root chain certificate", 0, null)
                }
                required.add(d.toInt())
            }
        } else {
            for (i in 0 until last) if (policy == "all" || chain[i].ocspServers().isNotEmpty()) required.add(i)
        }
        val statuses = LinkedHashMap<Int, String>()
        for (i in 0 until last) statuses[i] = "absent"
        var verified = 0
        fun failed(reason: String) = ChainOcsp(false, reason, verified, LinkedHashMap(statuses))
        for ((ri, der) in responses.withIndex()) {
            var matched = false
            var lastReason = "matches no chain certificate"
            for (i in 0 until last) {
                val o = OcspOptions(co.maxAgeMs ?: OCSP_DEFAULT_MAX_MS.toDouble(), co.clockSkewMs ?: 0.0, co.expectedNonces?.getOrNull(i))
                val r = verifyOcspResponse(der, chain[i], chain[i + 1], chain, nowMs, o)
                if (!r.ok) {
                    if (!r.reason.startsWith("no SingleResponse matches")) return failed("OCSP response #$ri for '${AttestNvidia.subjectLine(chain[i])}' rejected: ${r.reason}")
                    lastReason = r.reason
                    continue
                }
                if (matched) return failed("OCSP response #$ri matches more than one chain certificate")
                matched = true
                if (statuses[i] != "absent") return failed("duplicate OCSP responses for chain certificate #$i")
                statuses[i] = r.status
                verified++
                if (r.status == "revoked") return failed("chain certificate '${AttestNvidia.subjectLine(chain[i])}' is revoked (OCSP)")
            }
            if (!matched) return failed("OCSP response #$ri rejected: $lastReason")
        }
        for (i in required) {
            if (statuses[i] != "good") return failed("no GOOD OCSP response for required certificate '${AttestNvidia.subjectLine(chain[i])}' (status: ${statuses[i]})")
        }
        return ChainOcsp(true, "", verified, statuses)
    }

    /** [checkChainOcspFull] with the default options: "" when it holds, else the failure reason. */
    fun checkChainOcsp(chain: List<AttestCert.Cert>, responses: List<ByteArray>, nowMs: Long): String = checkChainOcspFull(chain, responses, nowMs).reason

    /** `allAsn1TimesWellFormed` over a DER value: every UTCTime / GeneralizedTime inside is a well-formed DER time with in-range fields (no roll-over); the contents of OCTET STRING and BIT STRING are opaque. A value the reader cannot parse is false. */
    fun asn1TimesWellFormed(der: ByteArray): Boolean = try {
        timesWellFormed(der, readNode(der, 0, der.size))
    } catch (e: AttErr) {
        false
    }
}
