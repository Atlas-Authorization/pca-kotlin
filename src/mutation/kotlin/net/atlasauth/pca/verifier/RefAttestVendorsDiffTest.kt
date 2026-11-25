package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * The public vendor-attestation facades against the reference (ref-attest-vendors, 758 cases, 22 functions): the constants, the byte / PEM / key helpers, the
 * DCAP quote and TD report parsers, the Intel PCK chain, the genuine-quote verifier, CRL, signed-JSON and PCS collateral verification, the Azure runtime-data
 * binding, the Azure MAA and Confidential Space JWT parsers, both x5c chain checks, and the two JWKS fetchers over a scripted transport.
 *
 * A text that comes from a library (OpenSSL, `JSON.parse`, the P-256 library, `decodeURIComponent`) compares by its fixed prefix and by presence; every other
 * text is exact. A case whose certificate bytes are not DER at all only requires a refusal, whatever stack parses it (counted below).
 */
@Suppress("UNCHECKED_CAST")
class RefAttestVendorsDiffTest {
    private val mod = "ref-attest-vendors"
    private val blobs: Map<String, Any?> by lazy { OracleBlobs.load("$mod.json.gz") }

    private val LIB = Regex(
        "error:[0-9A-Fa-f]{8}:|Unexpected (token|end|number|string|non-whitespace)|bad point: |invalid Point, expected length|URI malformed|Expected [^ ]+ |Unterminated string|Bad control character|Bad escaped character",
    )

    /** The cases whose certificate bytes are not valid DER: only a refusal is required. */
    private val REFUSAL_ONLY = Regex("/(malformed-certificate|malformed-base64-certificate|malformed-second-certificate|anchor-malformed-pem|pem-malformed-block)$")

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun list(o: Any?): List<Any?> = o as List<Any?>

    /** {"$bytes": b64url} -> ByteArray, recursively (blobs are hydrated first). */
    private fun dec(v: Any?): Any? = when (v) {
        is List<*> -> v.map { dec(it) }
        is Map<*, *> ->
            if (v.size == 1 && v.containsKey("\$bytes")) Base64.getUrlDecoder().decode(v["\$bytes"] as String)
            else LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k as String] = dec(x) }
        else -> v
    }

    private fun bytes(o: Any?): ByteArray = o as ByteArray
    private fun long(o: Any?): Long = IntentJs.lng(o)

    /** The typed P-256 key as the reference's plain shape. */
    private fun plain(v: Any?): Any? = when (v) {
        is AttestVendors.EcdsaP256PublicKey -> linkedMapOf<String, Any?>("point" to v.point)
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k.toString()] = plain(x) }
        is List<*> -> v.map { plain(it) }
        else -> v
    }

    private class Script(val steps: List<Any?>) {
        val log = ArrayList<String>()
        private var i = 0

        fun fetch(): AttestMaaKeys.MaaFetch = AttestMaaKeys.MaaFetch { url ->
            log.add(url)
            val r = steps[Math.min(i++, steps.size - 1)] as Map<String, Any?>
            if (r.containsKey("\$throws")) throw IllegalStateException(r["\$throws"] as String)
            val b = r["body"]
            val raw = if (b is Map<*, *> && b.containsKey("\$text")) b["\$text"] as String else Json.canonicalize(b)
            AttestMaaKeys.MaaHttpResponse(if (r["status"] != null) IntentJs.num(r["status"])!!.toInt() else 200, raw.toByteArray(Charsets.UTF_8))
        }
    }

    private fun fetchCall(a: List<Any?>, f: (String, AttestMaaKeys.MaaFetch, Map<String, Any?>) -> Any?): Any? {
        val sc = map(a[0])
        val s = Script(list(sc["script"]))
        val out = LinkedHashMap<String, Any?>()
        try {
            out["jwks"] = f(sc["issuer"] as String, s.fetch(), map(sc["opts"] ?: emptyMap<String, Any?>()))
            out["ok"] = true
        } catch (e: RuntimeException) {
            out.remove("jwks")
            out["ok"] = false
            out["error"] = e.message ?: ""
        }
        out["requests"] = s.log
        return out
    }

    private fun constants(): Any? = linkedMapOf(
        "INTEL_DCAP_SUITE" to AttestVendors.INTEL_DCAP_SUITE, "AZURE_MAA_SUITE" to AttestVendors.AZURE_MAA_SUITE, "AZURE_MAA_SUITES" to AttestVendors.AZURE_MAA_SUITES,
        "GCP_CS_SUITE" to AttestVendors.GCP_CS_SUITE, "GCP_CS_SUITES" to AttestVendors.GCP_CS_SUITES, "GCP_CS_DEFAULT_ISSUER" to AttestVendors.GCP_CS_DEFAULT_ISSUER,
        "INTEL_SGX_ROOT_CA_SPKI_SHA256" to AttestVendors.INTEL_SGX_ROOT_CA_SPKI_SHA256, "AMD_SNP_SUITE" to AttestVendors.AMD_SNP_SUITE,
        "AMD_ARK_SPKI_SHA384" to AttestVendors.AMD_ARK_SPKI_SHA384, "DEFAULT_ACCEPTED_STATUSES" to AttestVendors.DEFAULT_ACCEPTED_STATUSES,
    )

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> constants()
        "toHex" -> AttestVendors.toHex(bytes(a[0]))
        "pemToDer" -> AttestVendors.pemToDer(a[0] as String)
        "ecdsaP256PublicKey" -> AttestVendors.ecdsaP256PublicKey(bytes(a[0]))
        "parseDcapTdReport" -> AttestVendors.parseDcapTdReport(bytes(a[0]))
        "parseDcapQuote" -> AttestVendors.parseDcapQuote(bytes(a[0]))
        "extractPckFmspcAndTcb" -> AttestVendors.extractPckFmspcAndTcb(bytes(a[0]))
        "verifyIntelPckChainX509" -> {
            val m = map(a[0])
            AttestVendors.verifyIntelPckChainX509(m["pckChainPem"] as String, m["trustAnchorRootCaSpkiSha256"] as String?, long(m["nowMs"]))
        }
        "verifyGenuineTdxQuote" -> {
            val m = map(a[0])
            AttestVendors.verifyGenuineTdxQuote(bytes(m["quote"]), long(m["nowMs"]), m["trustAnchorRootCaSpkiSha256"] as String?, m["expected"] as Map<String, Any?>?, m["policy"] as Map<String, Any?>?)
        }
        "verifyCrl" -> AttestVendors.verifyCrl(bytes(a[0]), bytes(map(a[1])["spkiDer"]), long(a[2]))
        "serialIsRevoked" -> AttestVendors.serialIsRevoked(list(a[0]).map { it as String }, a[1] as String)
        "verifySignedJson" -> AttestVendors.verifySignedJson(a[0] as String, a[1] as String, bytes(map(a[2])["spkiDer"]))
        "decodeIssuerChainHeader" -> AttestVendors.decodeIssuerChainHeader(a[0] as String)
        "verifyIntelTdxCollateral" -> {
            val m = map(a[0])
            AttestVendors.verifyIntelTdxCollateral(
                bytes(m["quote"]), m["collateral"] as Map<String, Any?>?, long(m["nowMs"]), m["policy"] as Map<String, Any?>?, m["trustAnchorRootCaSpkiSha256"] as String?, m["allowDebug"] == true,
            )
        }
        "checkAzureRuntimeDataBinding" -> AttestVendors.checkAzureRuntimeDataBinding(bytes(a[0]), bytes(a[1]), map(a[2]))
        "parseMaaJwt" -> AttestVendors.parseMaaJwt(a[0] as String)
        "parseGcpCsJwt" -> AttestVendors.parseGcpCsJwt(a[0] as String)
        "verifyX5cChain" -> {
            val o = map(a[2])
            AttestVendors.verifyX5cChain(a[0] as? List<Any?>, a[1] as? Map<String, Any?>, long(o["nowMs"]), o["clockSkewMs"]?.let { IntentJs.num(it) })
        }
        "verifyJwkX5cChain" -> {
            val o = map(a[2])
            AttestVendors.verifyJwkX5cChain(a[0] as? List<Any?>, a[1] as? Map<String, Any?>, long(o["nowMs"]), IntentJs.num(o["skewMs"])!!)
        }
        "teeTypeOfHwModel" -> AttestVendors.teeTypeOfHwModel(a[0] as String)
        "fetchMaaJwks" -> fetchCall(a) { issuer, f, o -> if (o["certsPath"] != null) AttestVendors.fetchMaaJwks(issuer, f, o["certsPath"] as String) else AttestVendors.fetchMaaJwks(issuer, f) }
        "fetchGcpConfidentialSpaceJwks" -> fetchCall(a) { issuer, f, o -> AttestVendors.fetchGcpConfidentialSpaceJwks(issuer, f, o["jwksUri"] as String?) }
        else -> throw AssertionError("unhandled fn $fn")
    }

    /** Does [got] equal [want], with a library text compared by its fixed prefix and by presence? */
    private fun same(want: Any?, got: Any?): Boolean = when {
        want is Map<*, *> && got is Map<*, *> -> want.keys == got.keys && want.keys.all { same(want[it], got[it]) }
        want is List<*> && got is List<*> -> want.size == got.size && want.indices.all { same(want[it], got[it]) }
        want is String && got is String -> {
            val m = LIB.find(want)
            if (m == null) want == got else got.startsWith(want.substring(0, m.range.first)) && (m.range.first > 0 || got.isNotEmpty())
        }
        else -> IntentJs.jsonEquals(want, got)
    }

    private fun refused(r: Any?): Boolean = when (r) {
        is Map<*, *> -> r["ok"] == false
        is String -> true
        else -> false
    }

    @Test fun everyFunction() {
        val fns = setOf(
            "constants", "toHex", "pemToDer", "ecdsaP256PublicKey", "parseDcapTdReport", "parseDcapQuote", "extractPckFmspcAndTcb", "verifyIntelPckChainX509", "verifyGenuineTdxQuote",
            "verifyCrl", "serialIsRevoked", "verifySignedJson", "decodeIssuerChainHeader", "verifyIntelTdxCollateral", "checkAzureRuntimeDataBinding", "parseMaaJwt", "parseGcpCsJwt",
            "verifyX5cChain", "verifyJwkX5cChain", "teeTypeOfHwModel", "fetchMaaJwks", "fetchGcpConfidentialSpaceJwks",
        )
        var total = 0
        var refusalOnly = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val name = c["name"] as String
                val args = dec(OracleBlobs.hydrate(OracleCases.decNum(c["args"]), blobs)) as List<Any?>
                val want = OracleBlobs.hydrate(c["out"], blobs)
                var got: Any? = null
                var err: Throwable? = null
                try { got = OracleCases.toJson(plain(call(fn, args))) } catch (t: Throwable) { err = t }
                val wantThrow = want is Map<*, *> && want.containsKey("\$throws")
                val problem: String? = when {
                    REFUSAL_ONLY.containsMatchIn(name) -> {
                        refusalOnly++
                        if (err != null || refused(got)) null else "$name\n  want a refusal\n  got: $got"
                    }
                    wantThrow -> when {
                        err == null -> "$name\n  want: throw $want\n  got:  $got"
                        else -> if (OracleCases.engineCrash(want) || same(linkedMapOf("\$throws" to (want as Map<*, *>)["\$throws"]), linkedMapOf("\$throws" to (err.message ?: "")))) null else "$name\n  want: $want\n  got:  THROWS ${err.message}"
                    }
                    err != null -> "$name\n  want: $want\n  got:  THROWS $err"
                    else -> {
                        val norm = IntentJs.normalize(got)
                        if (same(IntentJs.normalize(want), norm)) null else "$name\n  want: $want\n  got:  $norm"
                    }
                }
                if (problem != null) bad.add(problem)
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(758, total)
        assertEquals(6, refusalOnly)
    }

    @Test fun theConstantsAreTheReferenceValues() {
        assertEquals(listOf("UpToDate", "SWHardeningNeeded"), AttestVendors.DEFAULT_ACCEPTED_STATUSES)
        assertEquals(setOf("milan", "genoa", "turin"), AttestVendors.AMD_ARK_SPKI_SHA384.keys)
    }
}
