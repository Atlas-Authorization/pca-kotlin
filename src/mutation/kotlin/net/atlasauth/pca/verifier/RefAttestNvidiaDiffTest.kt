package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The NVIDIA GPU-CC attestation modules against the reference (ref-attest-nvidia, 467 cases, and ref-attest-nvidia-rim, 163): the SPDM transcript parse, the
 * device chain over real H100 / GB100 captures and forged PKIs, the report signature and challenge, RIM verification (XMLDSig, C14N 1.1), RIM ids, the golden
 * comparison, CRL revocation, the collateral hook with its firmware policy, the fetch helpers, the OCSP request, response and chain checks, and the ASN.1 time
 * walk. A reason that carries the text of the reference's X.509 / XML / ASN.1 library compares by presence; every other reason compares exactly.
 */
@Suppress("UNCHECKED_CAST")
class RefAttestNvidiaDiffTest {
    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun bytes(o: Any?): ByteArray = Pca.decodeB64uStrict((o as Map<*, *>)["\$bytes"], -1) ?: throw IllegalArgumentException("not bytes")

    private fun byteList(o: Any?): List<ByteArray> = (o as List<Any?>).map { bytes(it) }

    private fun num(o: Any?): Double = IntentJs.num(o)!!

    private val LIB_ERR = Regex("error:[0-9A-F]{8}:")
    private val LIB_CHAIN = Regex("unparseable: (?!parsePemChain:)")

    private fun libText(r: String): Boolean =
        r.contains("verification error (fail closed)") || r.contains("OCSP response rejected:") || LIB_ERR.containsMatchIn(r) || LIB_CHAIN.containsMatchIn(r) || r.startsWith("The first argument")

    /** A reason that reports the text of a library compares by presence. */
    private fun norm(v: Any?): Any? = when (v) {
        is Map<*, *> -> {
            val m = LinkedHashMap<String, Any?>()
            for ((k, x) in v) m[k as String] = norm(x)
            val r = m["reason"]
            if (r is String && libText(r)) m["reason"] = "<library>"
            val e = m["value"]
            if (m.containsKey("value") && e is String && libText(e)) m["value"] = "<library>"
            m
        }
        is List<*> -> v.map { norm(it) }
        else -> v
    }

    // ---- scripted transport ----

    private class Script(val response: Map<String, Any?>) {
        val log = ArrayList<Any?>()
        val withBody: Boolean get() = false

        fun fetch(ocsp: Boolean): NvidiaFetch = NvidiaFetch { url, method, contentType, body ->
            val entry = linkedMapOf<String, Any?>("url" to url, "method" to method, "contentType" to contentType)
            if (ocsp) entry["bodyBytes"] = IntentJs.ofLong((body?.size ?: 0).toLong())
            log.add(entry)
            if (response.containsKey("\$throws")) throw IllegalStateException(response["\$throws"] as String)
            val b = response["bodyBytes"]
            val data = if (b != null) Pca.decodeB64uStrict((b as Map<*, *>)["\$bytes"], -1)!! else Json.canonicalize(response["body"]).toByteArray(Charsets.UTF_8)
            NvidiaHttpResponse(if (response["status"] != null) IntentJs.num(response["status"])!!.toInt() else 200, data)
        }
    }

    private fun fetched(sc: Map<String, Any?>, ocsp: Boolean, call: (NvidiaFetch) -> Map<String, Any?>): Any? {
        val s = Script(map(sc["response"]))
        val out = LinkedHashMap<String, Any?>()
        try {
            out["ok"] = true
            out.putAll(call(s.fetch(ocsp)))
        } catch (e: RuntimeException) {
            out.clear()
            out["ok"] = false
            out["error"] = e.message
        }
        out["requests"] = s.log
        return out
    }

    // ---- functions ----

    private fun constants(): Any? = linkedMapOf(
        "NVIDIA_SPDM_SUITE" to AttestNvidiaSpdm.NVIDIA_SPDM_SUITE, "NVIDIA_OPAQUE" to AttestNvidiaSpdm.NVIDIA_OPAQUE, "NVIDIA_RIM_BASE_URL" to AttestNvidiaRim.NVIDIA_RIM_BASE_URL,
        "NVIDIA_GH100_CRL_URLS" to AttestNvidiaRim.NVIDIA_GH100_CRL_URLS, "NVIDIA_GB100_CRL_URLS" to AttestNvidiaRim.NVIDIA_GB100_CRL_URLS,
        "NVIDIA_OCSP_URL" to AttestNvidiaOcsp.NVIDIA_OCSP_URL, "NVIDIA_OCSP_DEFAULT_MAX_AGE_MS" to AttestNvidiaOcsp.NVIDIA_OCSP_DEFAULT_MAX_AGE_MS,
    )

    private fun hook(a: List<Any?>): Any? {
        val sc = map(a[0])
        val h = AttestNvidiaRim.createNvidiaCollateralHook(map(sc["opts"]))
        val b = sc["bundle"] as Map<String, Any?>?
        val bundle: Map<String, Any?>? = b?.let {
            val m = linkedMapOf<String, Any?>("driverRimXml" to it["driverRimXml"], "vbiosRimXml" to it["vbiosRimXml"])
            if (it["crls"] != null) m["crls"] = byteList(it["crls"])
            if (it["ocsp"] != null) m["ocsp"] = byteList(it["ocsp"])
            m
        }
        return linkedMapOf("value" to h.check(bundle, bytes(sc["evidence"]), sc["chainPem"] as String, num(sc["nowMs"])))
    }

    private fun ocspRequest(a: List<Any?>): Any? {
        val o = map(a[2])
        val nonceMap = o["nonce"] as Map<*, *>?
        val nonce = if (nonceMap != null) bytes(nonceMap) else null // an empty nonce is refused ("nonce must be 1..32 bytes")
        return AttestNvidiaOcsp.buildNvidiaOcspRequest(a[0] as String, a[1] as String, nonce, o["hash"] as String?)
    }

    private fun ocspVerify(a: List<Any?>): Any? {
        val o = map(a[1])
        val opts = LinkedHashMap<String, Any?>()
        for (k in listOf("maxAgeMs", "clockSkewMs")) if (o[k] != null) opts[k] = o[k]
        if (o["expectedNonce"] != null) opts["expectedNonce"] = bytes(o["expectedNonce"])
        return AttestNvidiaOcsp.verifyNvidiaOcspResponse(
            bytes(a[0]), o["chainPem"] as String, IntentJs.num(o["certIndex"])!!.toInt(), num(o["nowMs"]), o["issuerIndex"]?.let { IntentJs.num(it)!!.toInt() }, opts,
        )
    }

    private fun ocspChain(a: List<Any?>): Any? {
        val o = map(a[3])
        val opts = LinkedHashMap<String, Any?>(o)
        if (o["expectedNonces"] != null) opts["expectedNonces"] = (o["expectedNonces"] as List<Any?>).map { if (it == null) null else bytes(it) }
        return AttestNvidiaOcsp.checkNvidiaChainOcsp(a[0] as String, byteList(a[1]), num(a[2]), opts)
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> constants()
        "parseReport" -> AttestNvidiaSpdm.parseNvidiaSpdmEvidence(bytes(a[0]))
        "formatVbiosVersion" -> AttestNvidiaSpdm.formatVbiosVersion(bytes(a[0]))
        "spkiSha256Hex" -> AttestNvidiaSpdm.spkiSha256Hex(a[0] as String)
        "parsePemChain" -> AttestNvidiaSpdm.parsePemChain(a[0] as String)
        "verifyDeviceChain" -> AttestNvidiaSpdm.verifyNvidiaDeviceChain(a[0] as String, (a[1] as List<Any?>).map { it as String }, num(a[2]))
        "verifySpdmSignature" -> AttestNvidiaSpdm.verifyNvidiaSpdmSignature(bytes(a[0]), a[1] as String)
        "spdmChallenge" -> AttestNvidiaSpdm.nvidiaSpdmChallenge(a[0])
        "verifyRim" -> AttestNvidiaRim.verifyNvidiaRim(a[0], (map(a[1])["rimRootSpkiSha256"] as List<Any?>).map { it as String }, num(map(a[1])["nowMs"]))
        "rimIds" -> AttestNvidiaRim.nvidiaRimIdsForReport(bytes(a[0]))
        "compareReport" -> AttestNvidiaRim.compareReportToRims(bytes(a[0]), map(a[1]), map(a[2]))
        "checkRevocation" -> AttestNvidiaRim.checkNvidiaChainRevocation(a[0] as String, byteList(a[1]), num(a[2]), (a[3] as List<Any?>).map { it as String }, a[4])
        "collateralHook" -> hook(a)
        "fetchRim" -> {
            val sc = map(a[0])
            fetched(sc, false) { f -> linkedMapOf("value" to AttestNvidiaRim.fetchNvidiaRim(sc["id"] as String, f, sc["baseUrl"] as String?)) }
        }
        "fetchCrl" -> {
            val sc = map(a[0])
            fetched(sc, false) { f -> linkedMapOf("value" to AttestNvidiaRim.fetchNvidiaCrl(sc["url"] as String, f)) }
        }
        "fetchOcsp" -> {
            val sc = map(a[0])
            val o = map(sc["opts"] ?: emptyMap<String, Any?>())
            fetched(sc, true) { f -> AttestNvidiaOcsp.fetchNvidiaOcsp(sc["certPem"] as String, sc["issuerPem"] as String, f, o["url"] as String?, o["nonce"]?.let { bytes(it) }) }
        }
        "ocspRequest" -> ocspRequest(a)
        "ocspUrls" -> AttestNvidiaOcsp.nvidiaCertOcspUrls(a[0] as String)
        "ocspVerify" -> ocspVerify(a)
        "ocspChain" -> ocspChain(a)
        "asn1TimesWellFormed" -> AttestNvidiaOcsp.allAsn1TimesWellFormed(bytes(a[0]))
        else -> throw AssertionError("unhandled fn $fn")
    }

    private fun replay(mod: String, fns: Set<String>, total: Int) {
        val blobs = OracleBlobs.load("$mod.json.gz")
        var n = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                n++
                val case = LinkedHashMap(c)
                case["args"] = OracleBlobs.hydrate(OracleCases.decNum(c["args"]), blobs)
                OracleCases.diff(case, norm(OracleBlobs.hydrate(c["out"], blobs))) { x -> norm(OracleCases.toJson(call(fn, x))) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(total, n)
    }

    @Test fun nvidiaSurface() = replay(
        "ref-attest-nvidia",
        setOf(
            "constants", "parseReport", "formatVbiosVersion", "spkiSha256Hex", "parsePemChain", "verifyDeviceChain", "verifySpdmSignature", "spdmChallenge", "rimIds", "compareReport",
            "checkRevocation", "fetchRim", "fetchCrl", "ocspRequest", "ocspUrls", "ocspVerify", "ocspChain", "fetchOcsp", "asn1TimesWellFormed",
        ),
        467,
    )

    @Test fun rimAndCollateralHook() = replay("ref-attest-nvidia-rim", setOf("verifyRim", "collateralHook"), 163)
}
