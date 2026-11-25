package net.atlasauth.pca.verifier

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The SEV-SNP helpers against the reference (ref-sevsnp-helpers, 248 cases): the hex form, PEM splitting, the report parser (every field, u64 as
 * {"$bigint"}), the P-384 key and signature helpers, the report signature (high-S accepted), the policy gate with its gate order, the default identity
 * derivation, the KDS VCEK fetch over an injected transport, the certificate helpers and the VCEK / report binding (the reason after "VCEK extensions
 * malformed:" compares by prefix).
 */
@Suppress("UNCHECKED_CAST")
class RefSevSnpHelpersDiffTest {
    private val mod = "ref-sevsnp-helpers"
    private val malformed = "VCEK extensions malformed:"

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    private fun dec(v: Any?): Any? = when (v) {
        is Map<*, *> -> when {
            v.size == 1 && v["\$bytes"] is String -> java.util.Base64.getUrlDecoder().decode(v["\$bytes"] as String)
            v.size == 1 && v["\$bigint"] is String -> BigInteger(v["\$bigint"] as String)
            v.size == 1 && v["\$num"] is String -> Json.Num(v["\$num"] as String)
            else -> (v as Map<String, Any?>).mapValuesTo(LinkedHashMap()) { dec(it.value) }
        }
        is List<*> -> v.map { dec(it) }
        else -> v
    }

    private fun enc(v: Any?): Any? = when (v) {
        is BigInteger -> linkedMapOf<String, Any?>("\$bigint" to v.toString())
        is Map<*, *> -> (v as Map<String, Any?>).mapValuesTo(LinkedHashMap()) { enc(it.value) }
        is List<*> -> v.map { enc(it) }
        else -> v
    }

    private fun report(a: List<Any?>, i: Int): SevSnp.Report = SevSnp.parseSevSnpReport(a[i] as ByteArray)

    private fun parsed(r: SevSnp.Report): Map<String, Any?> {
        fun ver(f: SevSnp.FirmwareVersion) = linkedMapOf<String, Any?>("major" to f.major, "minor" to f.minor, "build" to f.build)
        return linkedMapOf(
            "version" to r.version, "guest_svn" to r.guestSvn, "policy" to r.policy, "family_id" to r.familyId, "image_id" to r.imageId, "vmpl" to r.vmpl,
            "signature_algo" to r.signatureAlgo, "current_tcb" to r.currentTcb, "platform_info" to r.platformInfo, "report_data" to r.reportData,
            "measurement" to r.measurement, "host_data" to r.hostData, "id_key_digest" to r.idKeyDigest, "author_key_digest" to r.authorKeyDigest,
            "report_id" to r.reportId, "report_id_ma" to r.reportIdMa, "reported_tcb" to r.reportedTcb, "cpuid_fam_id" to r.cpuidFamId,
            "cpuid_mod_id" to r.cpuidModId, "cpuid_step" to r.cpuidStep, "chip_id" to r.chipId, "committed_tcb" to r.committedTcb,
            "current_version" to ver(r.currentVersion), "committed_version" to ver(r.committedVersion), "launch_tcb" to r.launchTcb,
            "launch_mit_vector" to r.launchMitVector, "current_mit_vector" to r.currentMitVector,
            "signature" to linkedMapOf("r" to r.signatureR, "s" to r.signatureS),
            "signed_len" to r.signed.size, "signed_sha256" to AttestUtil.hex(AttestUtil.sha256(r.signed)), "raw_len" to r.raw.size,
        )
    }

    private fun fetchVcek(a: List<Any?>): Any? {
        val o = a[2] as Map<String, Any?>
        var url: String? = null
        val transport: ((String) -> SevSnp.KdsResponse)? = if (o["noFetch"] == true) null else { u ->
            url = u
            SevSnp.KdsResponse(IntentJs.num(o["status"])!!.toInt(), o["body"] as ByteArray)
        }
        val bytes = SevSnp.fetchVcekFromKds(a[0] as ByteArray, a[1] as BigInteger, o["product"] as String?, o["baseUrl"] as String?, transport)
        return linkedMapOf("url" to url, "bytes" to bytes)
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "toHex" -> SevSnp.toHex(a[0] as ByteArray)
        "splitPemCertificates" -> SevSnp.splitPemCertificates(a[0] as String)
        "parseReport" -> parsed(report(a, 0))
        "ecdsaP384PublicKey" -> linkedMapOf("point" to SevSnp.ecdsaP384PublicKey(a[0] as ByteArray).point)
        "signatureToCompact" -> (a[0] as Map<String, Any?>).let { SevSnp.sevSnpSignatureToCompact(it["r"] as ByteArray, it["s"] as ByteArray) }
        "verifyReportSignature" -> if (arg(a, 1) == null) false else SevSnp.verifySevSnpReportSignature(report(a, 0), SevSnp.ecdsaP384PublicKey(a[1] as ByteArray))
        "checkPolicy" -> SevSnp.checkSevSnpPolicy(report(a, 0), arg(a, 1) as Map<String, Any?>?)
        "deriveIdentity" -> SevSnp.makeDefaultDeriveIdentity(a[1] == true)(report(a, 0))
        "fetchVcek" -> fetchVcek(a)
        "extractTbsCertificate" -> SevSnp.extractTbsCertificate(a[0] as ByteArray)
        "extractVcekPublicKey" -> SevSnp.extractVcekPublicKey(a[0] as ByteArray).let { linkedMapOf("point" to it.key.point, "tbs" to it.tbs) }
        "checkVcekReportBinding" -> SevSnp.checkVcekReportBinding(a[0] as ByteArray, report(a, 1)).let { if (it != null && it.startsWith(malformed)) malformed else it }
        "constants" -> linkedMapOf(
            "SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384" to SevSnp.SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384, "SEV_SNP_POLICY_DEBUG_BIT" to SevSnp.SEV_SNP_POLICY_DEBUG_BIT,
            "AMD_MILAN_ARK_SPKI_SHA384" to SevSnp.AMD_MILAN_ARK_SPKI_SHA384,
        )
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun everyFunction() {
        val fns = setOf(
            "toHex", "splitPemCertificates", "parseReport", "ecdsaP384PublicKey", "signatureToCompact", "verifyReportSignature", "checkPolicy", "deriveIdentity",
            "fetchVcek", "extractTbsCertificate", "extractVcekPublicKey", "checkVcekReportBinding", "constants",
        )
        var total = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val want = if (fn == "checkVcekReportBinding" && c["out"] is String && (c["out"] as String).startsWith(malformed)) malformed else c["out"]
                val case = LinkedHashMap(c)
                case["args"] = dec(c["args"])
                OracleCases.diff(case, want) { x -> enc(call(fn, x)) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(248, total)
    }
}
