package net.atlasauth.pca.verifier

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays `attestation-evidence-vectors.json`: every vendor verifier answers exactly what the reference verifiers answered when
 * the file was generated (reason text included; an OpenSSL / node:crypto message is compared by its stable prefix), and the
 * strict X.509 readers answer every unit row. The file is produced by the TypeScript generator; a missing file FAILS the test
 * (it is never skipped).
 */
@Suppress("UNCHECKED_CAST")
class AttestationVectorsTest {
    private val doc: Map<String, Any?> by lazy { ParityVectors.load("attestation-evidence-vectors.json") }
    private val blobs: Map<String, Any?> get() = doc["blobs"] as Map<String, Any?>

    /** Replaces every `{"$blob": id}` with the string stored under `blobs[id]`. */
    private fun hydrate(x: Any?): Any? = when (x) {
        is List<*> -> x.map { hydrate(it) }
        is Map<*, *> -> {
            val id = if (x.size == 1) x["\$blob"] as? String else null
            if (id != null) blobs[id] ?: throw IllegalStateException("unknown blob $id")
            else LinkedHashMap<String, Any?>().also { m -> for ((k, v) in x) m[k as String] = hydrate(v) }
        }
        else -> x
    }

    private fun bindingOf(v: Any?): Attest.Binding? {
        val m = v as? Map<String, Any?> ?: return null
        return Attest.Binding(
            m["holderPub"] as? String ?: "", m["grantRef"] as? String ?: "",
            AttestUtil.asFinite(m["epoch"]) ?: 0.0, m["nonce"] as? String ?: "",
        )
    }

    /** verifier_from_config + verify for one row: the wire result, or `{"construct_error": text}`. */
    private fun runRow(row: Map<String, Any?>): Map<String, Any?> {
        val vendor = row["vendor"] as? String ?: ""
        val ver = try {
            Attest.verifierFromConfig(vendor, row["config"] as? Map<String, Any?>)
        } catch (e: IllegalArgumentException) {
            return linkedMapOf("construct_error" to e.message)
        }
        val res = ver.verify(row["evidence"] as? Map<String, Any?>, bindingOf(row["expected_binding"]), AttestUtil.asFinite(row["now"])!!.toLong())
        return res.wire()
    }

    private fun canon(m: Map<String, Any?>): String = Json.canonicalize(m)

    @Test
    fun everyVendorRowAnswersExactlyTheReference() {
        val schema = doc["verifier_config_schema"] as Map<String, Any?>
        assertEquals(Attest.VENDORS.sorted(), schema.keys.sorted())
        val rows = doc["attestation_vectors"] as List<Map<String, Any?>>
        assertTrue("only ${rows.size} attestation vectors", rows.size >= 750)
        val seen = HashSet<String>()
        val perVendor = HashMap<String, Int>()
        for (r in rows) {
            assertTrue("duplicate vector id ${r["id"]}", seen.add(r["id"] as String))
            perVendor.merge(r["vendor"] as String, 1) { a, b -> a + b }
        }
        for (v in Attest.VENDORS) assertTrue("no vectors for $v", (perVendor[v] ?: 0) > 0)
        var failures = 0
        val sb = StringBuilder()
        for (r in rows) {
            val row = hydrate(r) as Map<String, Any?>
            val got = LinkedHashMap(runRow(row))
            val exp = LinkedHashMap(row["expect"] as Map<String, Any?>)
            if (exp["reason_match"] == "prefix") {
                val prefix = exp["reason_prefix"] as? String ?: ""
                val reason = got["reason"] as? String ?: ""
                if (!reason.startsWith(prefix)) { failures++; sb.append("${row["id"]}: reason '$reason' does not start with '$prefix'\n"); continue }
                got.remove("reason")
                exp.remove("reason")
            }
            exp.remove("reason_match")
            exp.remove("reason_prefix")
            if (canon(got) != canon(exp)) {
                failures++
                if (failures <= 25) sb.append("${row["id"]} (${row["intent"]})\n  got  ${canon(got)}\n  want ${canon(exp)}\n")
            }
        }
        assertEquals("$failures of ${rows.size} rows differ:\n$sb", 0, failures)
    }

    // ---- the strict X.509 readers ----

    private fun b64(v: Any?): ByteArray = AttestUtil.nodeB64(v as String)

    private fun runX509(fn: String, input: Map<String, Any?>): Map<String, Any?> {
        fun ok(v: Any?): Map<String, Any?> = linkedMapOf("ok" to true, "value" to v)
        fun bad(e: Throwable): Map<String, Any?> = linkedMapOf("ok" to false, "error" to e.message)
        fun extList(t: AttestDer.ExtTable): Any? = t.oids.map {
            val e = t.m.getValue(it)
            linkedMapOf<String, Any?>("oid" to it, "critical" to e.critical, "value" to AttestUtil.hex(e.value))
        }
        fun instant(i: AttestDer.Instant): Any? = if (!i.ok) null else IntentJs.ofLong(i.ms)
        try {
            when (fn) {
                "read_cert_role_info" -> {
                    val info = AttestDer.readCertRoleInfo(b64(input["cert"]))
                    val m = linkedMapOf<String, Any?>("hasBasicConstraints" to info.hasBasicConstraints, "ca" to info.ca, "hasKeyUsage" to info.hasKeyUsage, "keyCertSign" to info.keyCertSign)
                    if (info.pathLen >= 0) m["pathLen"] = IntentJs.ofLong(info.pathLen.toLong())
                    return ok(m)
                }
                "parse_cert_extensions" -> return ok(extList(AttestDer.parseCertExtensions(b64(input["cert"]))))
                "parse_tbs_extensions" -> return ok(extList(AttestDer.parseTbsExtensions(b64(input["tbs"]))))
                "tbs_of_certificate" -> return ok(Base64.getEncoder().encodeToString(AttestDer.tbsOfCertificate(b64(input["cert"]))))
                "unrecognised_critical_extension" -> {
                    val rec = (input["recognised"] as? List<*>)?.map { it as String }?.toSet()
                    val oid = if (rec != null) AttestDer.unrecognisedCriticalExtension(b64(input["cert"]), rec) else AttestDer.unrecognisedCriticalExtension(b64(input["cert"]))
                    return ok(oid)
                }
                "check_chain_roles" -> {
                    val why = AttestDer.checkChainRoles((input["chain"] as List<*>).map { b64(it) })
                    return ok(if (why != "") why else null)
                }
                "der_validity_ms" -> {
                    val (from, to) = AttestDer.derValidity(b64(input["cert"]))
                    return ok(linkedMapOf("from" to instant(from), "to" to instant(to)))
                }
                "parse_der_time" -> return ok(instant(AttestDer.parseDerTime(AttestUtil.asFinite(input["tag"])!!.toInt(), input["text"] as? String ?: "")))
            }
        } catch (e: AttErr) {
            return bad(e)
        }
        throw IllegalStateException("unknown x509 function $fn")
    }

    @Test
    fun strictX509Rows() {
        val rows = doc["x509_vectors"] as List<Map<String, Any?>>
        assertTrue("only ${rows.size} x509 vectors", rows.size >= 90)
        var failures = 0
        val sb = StringBuilder()
        for (r in rows) {
            val row = hydrate(r) as Map<String, Any?>
            val got = runX509(row["fn"] as String, row["input"] as? Map<String, Any?> ?: emptyMap())
            val want = row["expect"]
            if (Json.canonicalize(got) != Json.canonicalize(want)) {
                failures++
                if (failures <= 25) sb.append("${row["id"]}\n  got  ${Json.canonicalize(got)}\n  want ${Json.canonicalize(want)}\n")
            }
        }
        assertEquals("$failures of ${rows.size} rows differ:\n$sb", 0, failures)
    }
}
