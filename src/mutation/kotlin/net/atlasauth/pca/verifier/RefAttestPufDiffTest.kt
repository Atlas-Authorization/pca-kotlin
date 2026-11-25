package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The PUF attestation root against the reference (ref-attest-puf, 278 cases): the constants, the correction bound, the simulated PUF, the fuzzy extractor
 * (every parameter pair, refusal and noise level), the TPM endorsement-key provider over an injected runner (the calls it makes compare), enrollment, the
 * device attestor (signature bytes compare under Ed25519 and ML-DSA), the enrollment registry and the verifier.
 */
@Suppress("UNCHECKED_CAST")
class RefAttestPufDiffTest {
    private val mod = "ref-attest-puf"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun bytes(o: Any?): ByteArray = Pca.decodeB64uStrict(if (o is Map<*, *>) o["\$bytes"] else o, -1) ?: throw IllegalArgumentException("not bytes")

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    private fun sha256Hex(b: ByteArray): String = hex(java.security.MessageDigest.getInstance("SHA-256").digest(b))

    private fun ok(v: Any?): Any? = linkedMapOf("ok" to true, "value" to v)

    private fun puf(spec: Any?): AttestPuf.PufProvider {
        val s = map(spec)
        val flip = (s["flip"] as List<Any?>?)?.map { IntentJs.num(it)!! } ?: emptyList()
        return AttestPuf.createSimulatedPuf(s["id"] as String, bytes(s["seed"]), IntentJs.num(s["length"])!!.toInt(), flip)
    }

    private fun rand(r: Any?): (Int) -> ByteArray {
        val l = r as List<Any?>
        var i = 0
        return { n -> val b = bytes(l[if (i++ == 0) 0 else 1]); b.copyOfRange(0, Math.min(n, b.size)) }
    }

    private fun fuzzyEnroll(a: List<Any?>): Any? {
        val p = map(a[1])
        val e = AttestPuf.fuzzyEnroll(bytes(a[0]), p["rep"], p["messageBits"], rand(a[2]))
        return linkedMapOf("keySha256" to sha256Hex(e.key), "helper" to e.helper) // the reference returns the result itself (no ok wrapper)
    }

    private fun tpm(a: List<Any?>): Any? {
        val sc = map(a[0])
        val opts = sc["opts"] as Map<String, Any?>?
        val spec = sc["run"]
        val calls = ArrayList<Any?>()
        val runner = AttestPuf.TpmCommandRunner { cmd, args ->
            calls.add(listOf(cmd, args))
            when {
                spec == "undefined" -> null
                spec is Map<*, *> && spec.containsKey("\$throws") -> throw RuntimeException(spec["\$throws"] as String)
                else -> {
                    val r = map(spec)
                    AttestPuf.TpmCommandResult(IntentJs.num(r["status"])?.toInt(), (r["stdout"] as? Map<*, *>)?.let { bytes(it) }, r["stderr"] as String?, r["error"] as String?)
                }
            }
        }
        val out = LinkedHashMap<String, Any?>()
        try {
            val p = AttestPuf.TpmEkPufProvider(
                opts?.get("id"), opts?.get("length"), runner, opts?.get("tool"), opts?.get("ekHandle"), (opts?.get("args") as List<String>?), opts?.get("minEkBytes"),
            )
            val v = if (sc["op"] == "readEkPublic") p.readEkPublic() else p.response(if (sc.containsKey("challenge")) bytes(sc["challenge"]) else challenge)
            out["ok"] = true
            out["value"] = v
        } catch (e: RuntimeException) {
            out["ok"] = false
            out["error"] = e.message
        }
        out["calls"] = calls
        return out
    }

    // the oracle's default challenge: sha256("attest-puf-oracle-randomness/challenge")
    private val challenge: ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest("attest-puf-oracle-randomness/challenge".toByteArray(Charsets.UTF_8))

    private fun enroll(a: List<Any?>): Any? {
        val o = map(a[2])
        return ok(AttestPuf.enrollPuf(puf(a[0]), bytes(a[1]), o["rep"], o["messageBits"], o["alg"], rand(a[3])))
    }

    private fun registry(a: List<Any?>): Any? {
        val sc = map(a[0])
        val r = AttestPuf.createPufEnrollmentRegistry(sc["enrollments"])
        return ok((sc["ops"] as List<Any?>).map { opo ->
            val op = map(opo)
            when (val k = op.keys.first()) {
                "register" -> { r.register(op[k]); null }
                "lookup" -> r.lookup(op[k] as String)
                "revoke" -> { r.revoke(op[k] as String); null }
                else -> r.isRevoked(op[k] as String)
            }
        })
    }

    private fun verify(a: List<Any?>): Any? {
        val sc = map(a[0])
        val cfg = map(sc["config"])
        val pol = map(cfg["policy"])
        val policy = LinkedHashMap<String, Any?>()
        policy["measurements"] = pol["measurements"]
        if (pol["weightsMeasurements"] != null) policy["weightsMeasurements"] = pol["weightsMeasurements"]
        val opts = linkedMapOf<String, Any?>("policy" to policy)
        if (cfg.containsKey("requirePq")) opts["requirePq"] = cfg["requirePq"]
        val byId = HashMap<String, Map<String, Any?>>()
        for (e in (sc["enrollments"] as List<Any?>? ?: emptyList())) byId[map(e)["providerId"] as String] = map(e)
        val resolveEnrollment = if (cfg["noResolveEnrollment"] == true) null else AttestPuf.EnrollmentResolver { id, _, _ -> byId[id] }
        val evidence = sc["evidence"]
        val resolveEvidence = if (cfg["noEvidenceSeam"] == true) null else AttestPuf.EvidenceResolver { _, _ -> evidence }
        val revoked = sc["revoked"] as List<Any?>?
        val derive: ((Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>)? = if (pol["identity"] == "custom") { st, enr ->
            linkedMapOf(
                "model_id" to "m-custom", "weights_digest" to (st["weights_digest"] ?: ""), "weights_measured" to true, "runtime_measurement" to st["measurement"], "operator" to enr["providerId"],
            )
        } else null
        val v = AttestPuf.createPufVerifier(opts, resolveEnrollment, resolveEvidence, if (revoked == null) null else { id -> revoked.contains(id) }, derive)
        val inp = map(sc["input"])
        return v.verify(linkedMapOf("document" to linkedMapOf<String, Any?>(), "ctx" to linkedMapOf<String, Any?>(), "nowMs" to inp["nowMs"], "expected" to inp["expected"]).also { if (!inp.containsKey("expected")) it.remove("expected") })
    }

    private fun build(a: List<Any?>): Any? {
        val cfg = map(a[0])
        val live = LinkedHashMap<String, Any?>()
        if (cfg["policy"] != null) live["policy"] = cfg["policy"]
        AttestPuf.createPufVerifier(live, if (cfg["noResolveEnrollment"] == true) null else AttestPuf.EnrollmentResolver { _, _, _ -> null })
        return ok(linkedMapOf("built" to true))
    }

    private fun call(fn: String, a: List<Any?>): Any? = when (fn) {
        "constants" -> linkedMapOf(
            "PUF_EXTRACT_INFO" to AttestPuf.PUF_EXTRACT_INFO, "PUF_ATTEST_DOMAIN" to AttestPuf.PUF_ATTEST_DOMAIN, "PUF_KEY_BYTES" to AttestPuf.PUF_KEY_BYTES, "TPM_EK_PUF_DOMAIN" to AttestPuf.TPM_EK_PUF_DOMAIN,
        )
        "repetitionCorrectionBound" -> AttestPuf.repetitionCorrectionBound(IntentJs.num(a[0])!!)
        "simulatedPufResponse" -> puf(a[0]).response(bytes(a[1]))
        "fuzzyEnroll" -> fuzzyEnroll(a)
        "fuzzyReproduce" -> ok(linkedMapOf("keySha256" to sha256Hex(AttestPuf.fuzzyReproduce(bytes(a[0]), a[1]))))
        "tpmEk" -> tpm(a)
        "enrollPuf" -> enroll(a)
        "pufAttest" -> ok(AttestPuf.createPufAttestor(puf(a[0]), map(a[1])).attest(map(a[2])))
        "registry" -> registry(a)
        "verifyPuf" -> verify(a)
        "buildVerifier" -> build(a)
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun everyFunction() {
        val fns = setOf("constants", "repetitionCorrectionBound", "simulatedPufResponse", "fuzzyEnroll", "fuzzyReproduce", "tpmEk", "enrollPuf", "pufAttest", "registry", "verifyPuf", "buildVerifier")
        var total = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                total++
                val case = LinkedHashMap(c)
                case["args"] = OracleCases.decNum(c["args"])
                // the masked-message enrolment cases carry the reference result in an {ok, value} wrapper; the others carry it bare
                OracleCases.diff(case, c["out"]) { x -> call(fn, x).let { r -> if (fn == "fuzzyEnroll" && (c["out"] as? Map<*, *>)?.containsKey("value") == true) ok(r) else r } }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(278, total)
    }
}
