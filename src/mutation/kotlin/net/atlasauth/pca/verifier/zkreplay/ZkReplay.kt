package net.atlasauth.pca.verifier.zkreplay

import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import net.atlasauth.pca.verifier.Assurance
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.PcaCore
import net.atlasauth.pca.verifier.Zk
import net.atlasauth.pca.verifier.ZkCeremony

/**
 * Replays the reference oracle of the zk module (commitments, binding tags, struct hashes, quantization, context pins, the canonical
 * envelope gate, Policy-VM proof verification, the SNARK backends, the attested-VM statements and the ceremony checks). Self-contained
 * so that the core test (no pairing engine) and the native module's test (the real engine) run the same dispatch. The core test
 * registers [Recorded], which answers the pairing question with the reference's own verdict of the case being replayed, so every
 * case's final outcome is asserted without the native library; the real pairing is the native module's test.
 */
@Suppress("UNCHECKED_CAST")
object ZkReplay {
    /** An argument a typed API cannot receive (the reference's type confusion): counts as the reference's refusal. */
    private class Unrepresentable(m: String) : RuntimeException(m)

    @Volatile private var currentName: String? = null
    @Volatile private var currentWant: Any? = null

    // verifyPolicyVmProof cases the reference decides before the pairing check (shape, tags, signal count, allow, risk pin, canonical
    // encoding, context pins): the name after the fn and the curve starts with one of these. Reaching the engine there is a gate bug.
    private val GATE_ONLY = listOf(
        "expect-now-wrong", "expect-thunk-throws", "expectRiskHash", "circuit-", "system-", "extra-key", "proof-extra-key", "allow-0", "signal-count-",
        "signal-noncanonical", "signal-plus-order", "pi_a.x-hex", "pi_a.x+p", "pi_a.x-leading-zero", "pi_a.z-0", "pi_a-infinity", "pi_a-affine-2", "pi_b-short",
        "proof-null", "proof-missing", "proof-string", "protocol-plonk", "proof-curve-wrong", "shape-", "risk-hash-mismatch", "risk-hash-half", "bls-not-allowed",
        "15-signals", "now-out-of-range", "context-pin",
    )

    private fun gateOnly(name: String): Boolean {
        if (!name.startsWith("verifyPolicyVmProof/")) return false
        var stem = name.substring("verifyPolicyVmProof/".length)
        for (p in listOf("bn/", "bls/", "v2/")) if (stem.startsWith(p)) stem = stem.substring(p.length)
        return GATE_ONLY.any { stem.startsWith(it) }
    }

    /**
     * The engine of the core test: the pairing verdict is the reference's recorded outcome of the case being replayed (its boolean,
     * its `verified`, or its hook result's `ok`). It fails the run when a case the reference refuses before the pairing reaches it.
     */
    object Recorded : Zk.Groth16Engine {
        /** The cases that asked the pairing question, in order. */
        val reached: MutableList<String> = java.util.Collections.synchronizedList(ArrayList<String>())

        override fun verify(vkey: Any?, publicSignals: List<Any?>, proof: Any?): Boolean {
            val name = currentName ?: throw AssertionError("the engine was called outside a case")
            if (gateOnly(name)) throw AssertionError("$name must be refused before the pairing check")
            reached.add(name)
            val w = currentWant
            if (w is Boolean) return w
            if (w is Map<*, *> && w["verified"] is Boolean) return w["verified"] == true
            val r = (w as? Map<*, *>)?.get("result")
            if (r is Map<*, *> && r["ok"] is Boolean) return r["ok"] == true
            throw AssertionError("$name: the reference gave no verdict (it refused before the pairing check)")
        }

        override fun prove(curve: String, wasm: ByteArray, zkey: ByteArray, input: Map<String, String>): Map<String, Any?> = throw NeedsArtifacts()
    }

    class Outcome(val total: Int, val fns: Set<String>, val artifacts: List<String>, val divergent: List<String>)

    val FNS: Set<String> = setOf(
        "constants", "commitmentField", "policyCommitment", "pinnedPolicyCommitment", "actionCommitment", "proverKeyBinding", "policyVmStructHash", "policyVmRiskHash",
        "quantizeActionStruct", "policyVmCommitmentFromAction", "quantizePlanStruct", "quantizePolicyStruct", "quantizePolicyVmInputs", "decodePolicyVmPublic",
        "decodePolicyVmBoundPublic", "policyVmContextMatches", "isCanonicalGroth16Envelope", "verifyPolicyVmProof", "createPolicyVmSnarkBackend",
        "createPolicyVmSnarkBackendBls12381", "createGroth16SnarkBackend", "createPolicyVmBoundSnarkBackend", "createAttestedComplianceProver", "createZkVerifier",
        "circuitVersion", "vkId", "circuitProvenance", "checkCircuitProvenance", "transcriptSha256", "checkTranscript", "ceremonyOf", "provePolicyVmCompliance",
    )

    /** An argument that was not given: the library's own "absent" value, so an omitted argument behaves as in the reference. */
    private val UNDEF: Any = Zk.NO_EXPECT

    private fun seed(label: String): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/$label".toByteArray(Charsets.UTF_8))

    /** The corpus argument conventions: {"$bigint"}, {"$num"}, {"$bytes": {"$seed"}}. */
    private fun revive(v: Any?): Any? {
        if (v is List<*>) return v.map { revive(it) }
        if (v !is Map<*, *>) return v
        if (v.size == 1 && v.containsKey("\$bigint")) return BigInteger(v["\$bigint"] as String)
        if (v.size == 1 && v.containsKey("\$num")) {
            val s = v["\$num"]
            return if (s == "NaN") Double.NaN else if (s == "Infinity") Double.POSITIVE_INFINITY else Double.NEGATIVE_INFINITY
        }
        val b = v["\$bytes"]
        if (v.size == 1 && b is Map<*, *>) return seed(b["\$seed"] as String)
        val out = LinkedHashMap<String, Any?>()
        for ((k, x) in v) out[k as String] = revive(x)
        return out
    }

    private fun toJson(v: Any?): Any? {
        if (v is BigInteger) return linkedMapOf<String, Any?>("\$bigint" to v.toString())
        if (v is Zk.DigestHalves) return v.toMap()
        if (v is Int || v is Long) return Json.Num(v.toString())
        if (v is Double) return Json.Num(Json.jsNumberText(v))
        if (v is List<*>) return v.map { toJson(it) }
        if (v is Map<*, *>) {
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in v) out[k as String] = toJson(x)
            return out
        }
        return v
    }

    private fun at(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else UNDEF
    private fun present(v: Any?): Boolean = v != null && v !== UNDEF
    private fun map(v: Any?): Map<String, Any?> = v as? Map<String, Any?> ?: throw Unrepresentable("not an object")
    private fun list(v: Any?): List<Any?> = v as? List<Any?> ?: throw Unrepresentable("not an array")
    private fun str(v: Any?): String = v as? String ?: throw Unrepresentable("not a string")
    private fun optStr(m: Map<String, Any?>, k: String): String? = if (m[k] == null && !m.containsKey(k)) null else str(m[k])
    private fun dbl(v: Any?): Double = IntentJs.num(v) ?: throw Unrepresentable("not a number")
    private fun halves(v: Any?): Zk.DigestHalves? = if (!present(v)) null else Zk.DigestHalves(str(map(v)["hi"]), str(map(v)["lo"]))

    private fun quantizeOpts(a: List<Any?>, i: Int): Zk.QuantizeOpts? {
        val o = at(a, i)
        if (o === UNDEF) return Zk.QuantizeOpts()
        if (o == null) return null // explicit null options: the quantizer refuses them as the reference does
        val m = map(o)
        return Zk.QuantizeOpts(
            if (m.containsKey("verbCodes")) map(m["verbCodes"]) else null,
            if (m.containsKey("resourceCodes")) map(m["resourceCodes"]) else null,
            m["strictCatalog"] == true,
            optStr(m, "paramScalarField"),
        )
    }

    /** A PolicyVmExpectSource: "$absent" = not given, {"$expectThunk": X} = a function returning X ("throw" = one that throws). */
    private fun expectOf(e: Any?): Any? {
        if (e === UNDEF || e == "\$absent") return UNDEF
        if (e is Map<*, *> && e.containsKey("\$expectThunk")) {
            val x = e["\$expectThunk"]
            val thunk: () -> Any? = if (x == "throw") ({ throw IllegalStateException("thunk") }) else ({ x })
            return thunk
        }
        return e
    }

    private fun <T : Zk.VerifyOpts> verifyOpts(into: T, o: Any?): T {
        if (!present(o)) return into
        val m = map(o)
        into.verificationKey = m["verificationKey"]
        if (m.containsKey("expect")) into.expect = expectOf(m["expect"])
        into.expectRiskHash = halves(m["expectRiskHash"])
        return into
    }

    private fun backendOpts(o: Any?): Zk.BackendOpts {
        val b = verifyOpts(Zk.BackendOpts(), o)
        if (!present(o)) return b
        val m = map(o)
        if (present(m["ceremony"])) b.ceremony = map(m["ceremony"])
        b.expectActionHash = halves(m["expectActionHash"])
        b.expectPolicyHash = halves(m["expectPolicyHash"])
        b.expectPlanHash = halves(m["expectPlanHash"])
        return b
    }

    private fun backend(kind: String, opts: Any?): Zk.SnarkBackend = when (kind) {
        "createGroth16SnarkBackend", "groth16" -> Zk.createGroth16SnarkBackend(backendOpts(opts))
        "createPolicyVmSnarkBackend", "policyvm" -> Zk.createPolicyVmSnarkBackend(backendOpts(opts))
        "createPolicyVmSnarkBackendBls12381", "policyvm-bls" -> Zk.createPolicyVmSnarkBackendBls12381(backendOpts(opts))
        "createPolicyVmBoundSnarkBackend", "policyvm-bound" -> Zk.createPolicyVmBoundSnarkBackend(backendOpts(opts))
        else -> throw AssertionError("unknown backend $kind")
    }

    private fun label(target: Any?): Any? {
        val l = Assurance.labelOf(target) ?: return null
        val out = LinkedHashMap<String, Any?>()
        out["level"] = l.level
        if (l.vendor != null) out["vendor"] = l.vendor
        if (l.awaitingAudit != null) out["awaitingAudit"] = l.awaitingAudit
        if (l.ceremony != null) out["ceremony"] = l.ceremony
        return out
    }

    private fun constants(): Any? = linkedMapOf(
        "ZK_PROVER_BINDING_REF" to Zk.ZK_PROVER_BINDING_REF,
        "POLICYVM_PUBLIC_SIGNAL" to Zk.POLICYVM_PUBLIC_SIGNAL,
        "POLICYVM_PUBLIC_SIGNAL_COUNT" to Zk.POLICYVM_PUBLIC_SIGNAL_COUNT,
        "POLICYVM_BOUND_PUBLIC_SIGNAL" to Zk.POLICYVM_BOUND_PUBLIC_SIGNAL,
        "POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT" to Zk.POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT,
        "POLICYVM_BOUND_RISK_FIELDS" to Zk.POLICYVM_BOUND_RISK_FIELDS,
        "POLICYVM_REVERSIBILITY_ORDER" to Zk.POLICYVM_REVERSIBILITY_ORDER,
        "paths" to linkedMapOf(
            "DEFAULT_VKEY_PATH" to Zk.DEFAULT_VKEY_PATH, "DEFAULT_WASM_PATH" to Zk.DEFAULT_WASM_PATH, "DEFAULT_ZKEY_PATH" to Zk.DEFAULT_ZKEY_PATH,
            "POLICYVM_VKEY_PATH" to Zk.POLICYVM_VKEY_PATH, "POLICYVM_SAMPLE_PROOF_PATH" to Zk.POLICYVM_SAMPLE_PROOF_PATH, "POLICYVM_WASM_PATH" to Zk.POLICYVM_WASM_PATH,
            "POLICYVM_ZKEY_PATH" to Zk.POLICYVM_ZKEY_PATH, "POLICYVM_BLS12381_VKEY_PATH" to Zk.POLICYVM_BLS12381_VKEY_PATH,
            "POLICYVM_BLS12381_SAMPLE_PROOF_PATH" to Zk.POLICYVM_BLS12381_SAMPLE_PROOF_PATH, "POLICYVM_BOUND_VKEY_PATH" to Zk.POLICYVM_BOUND_VKEY_PATH,
            "POLICYVM_BOUND_SAMPLE_PROOF_PATH" to Zk.POLICYVM_BOUND_SAMPLE_PROOF_PATH, "POLICYVM_BOUND_WASM_PATH" to Zk.POLICYVM_BOUND_WASM_PATH,
            "POLICYVM_BOUND_ZKEY_PATH" to Zk.POLICYVM_BOUND_ZKEY_PATH,
        ),
    )

    private val ERROR_TAIL = Regex("(zk verification error \\(fail closed\\)): .*$", RegexOption.DOT_MATCHES_ALL)

    private fun zkVerifier(spec: Map<String, Any?>, ctx: Map<String, Any?>): Any? {
        val o = Zk.VerifierOpts()
        o.trustedProverKeys = (spec["trustedProverKeys"] as? List<*>)?.filterIsInstance<String>() ?: emptyList()
        if (spec.containsKey("policyCommitments")) o.policyCommitments = list(spec["policyCommitments"]).map { str(it) }
        if (spec.containsKey("revokedProverKeys")) o.revokedProverKeys = list(spec["revokedProverKeys"]).map { str(it) }
        if (spec.containsKey("clockSkewMs")) o.clockSkewMs = dbl(spec["clockSkewMs"])
        val nowMs = dbl(spec["nowMs"])
        o.now = { nowMs }
        val snark = spec["snark"]
        if (present(snark)) o.snarkBackend = backend(str(map(snark)["kind"]), map(snark)["opts"])
        val hook = Zk.createZkVerifier(o)
        val r: PcaCore.HookResult = hook.check(if (ctx.containsKey("pcactn")) ctx["pcactn"] else UNDEF, ctx["grant"])
        val result = LinkedHashMap<String, Any?>()
        result["enforced"] = r.enforced
        result["ok"] = r.ok
        val reason = r.reason
        if (reason != null) result["reason"] = ERROR_TAIL.replace(reason, "\$1")
        return linkedMapOf("result" to result, "label" to label(hook))
    }

    private fun prover(secret: Any?, po: Map<String, Any?>): Any? {
        val p = Zk.createAttestedComplianceProver(secret as? ByteArray ?: throw Unrepresentable("not a key"))
        val statement = p.prove(po["pcactn"], map(po["decideInput"]), IntentJs.lng(po["issued_at"]), IntentJs.lng(po["expires_at"]))
        return linkedMapOf("publicKey" to p.publicKey, "statement" to statement)
    }

    /** The one prove case is a contract, not a recorded proof: with the gitignored artifacts given it is run, otherwise it is listed. */
    private class NeedsArtifacts : Error("prover artifacts were not given")

    private fun proveRoundTrip(witness: Map<String, Any?>): Any? {
        val wasm = System.getenv("PCA_ZK_POLICYVM_WASM")
        val zkey = System.getenv("PCA_ZK_POLICYVM_ZKEY")
        if (wasm.isNullOrEmpty() || zkey.isNullOrEmpty()) throw NeedsArtifacts()
        val env = Zk.provePolicyVmCompliance(witness, Files.readAllBytes(java.nio.file.Paths.get(wasm)), Files.readAllBytes(java.nio.file.Paths.get(zkey)))
        val v = Zk.VerifyOpts()
        v.verificationKey = Zk.policyVmVerificationKey()
        if (!Zk.verifyPolicyVmProof(env, v)) throw AssertionError("the fresh proof does not verify under the bundled key")
        return linkedMapOf("publicSignals" to env["publicSignals"], "verifiesUnder" to "VK_BN", "sampleProofCircuit" to env["circuit"])
    }

    private fun call(fn: String, a: List<Any?>): Any? {
        val a0 = at(a, 0)
        val a1 = at(a, 1)
        return when (fn) {
            "constants" -> constants()
            "commitmentField" -> Zk.commitmentField(str(a0))
            "policyCommitment" -> Zk.policyCommitment(a0)
            "pinnedPolicyCommitment" -> Zk.pinnedPolicyCommitment(a0)
            "actionCommitment" -> Zk.actionCommitment(a0)
            "proverKeyBinding" -> Zk.proverKeyBinding(str(a0), dbl(a1), str(at(a, 2)))
            "policyVmStructHash" -> Zk.policyVmStructHash(list(a0))
            "policyVmRiskHash" -> Zk.policyVmRiskHash(a0)
            "quantizeActionStruct" -> Zk.quantizeActionStruct(a0, quantizeOpts(a, 1))
            "policyVmCommitmentFromAction" -> Zk.policyVmCommitmentFromAction(a0, quantizeOpts(a, 1))
            "quantizePlanStruct" -> Zk.quantizePlanStruct(map(a0), quantizeOpts(a, 1))
            "quantizePolicyStruct" -> Zk.quantizePolicyStruct(map(a0), quantizeOpts(a, 1))
            "quantizePolicyVmInputs" -> Zk.quantizePolicyVmInputs(map(a0), quantizeOpts(a, 1))
            "decodePolicyVmPublic" -> Zk.decodePolicyVmPublic(list(a0))
            "decodePolicyVmBoundPublic" -> Zk.decodePolicyVmBoundPublic(list(a0))
            "policyVmContextMatches" -> Zk.policyVmContextMatches(list(a0), expectOf(a1), at(a, 2) == "bound")
            "isCanonicalGroth16Envelope" -> Zk.isCanonicalGroth16Envelope(a0, if (a1 == null) null else str(a1))
            "verifyPolicyVmProof" -> Zk.verifyPolicyVmProof(a0, verifyOpts(Zk.VerifyOpts(), a1))
            "createPolicyVmSnarkBackend", "createPolicyVmSnarkBackendBls12381", "createGroth16SnarkBackend", "createPolicyVmBoundSnarkBackend" -> {
                val b = backend(fn, a0)
                val inp = map(a1)
                linkedMapOf("verified" to b.verify(inp["proof"], map(inp["publicInputs"]), inp["ctx"]), "label" to label(b))
            }
            "createZkVerifier" -> zkVerifier(map(a0), map(a1))
            "createAttestedComplianceProver" -> prover(a0, map(a1))
            "circuitVersion" -> Zk.circuitVersion(str(a0))
            "vkId" -> ZkCeremony.vkId(a0)
            "circuitProvenance" -> ZkCeremony.circuitProvenance(map(a0))
            "checkCircuitProvenance" -> ZkCeremony.checkCircuitProvenance(a0, map(a1))
            "transcriptSha256" -> ZkCeremony.transcriptSha256(a0)
            "checkTranscript" -> {
                val o: Map<String, Any?> = if (present(a1)) map(a1) else emptyMap()
                ZkCeremony.checkTranscript(a0, if (o.containsKey("minContributions")) dbl(o["minContributions"]) else null, optStr(o, "r1csSha256"), optStr(o, "circuit"))
            }
            "ceremonyOf" -> ZkCeremony.ceremonyOf(a0, if (a1 === UNDEF) null else a1)
            "provePolicyVmCompliance" -> proveRoundTrip(map(a0))
            else -> throw AssertionError("unhandled fn $fn")
        }
    }

    private fun text(o: Any?): String = try {
        Json.canonicalize(o).let { if (it.length > 600) it.substring(0, 600) + "..." else it }
    } catch (e: RuntimeException) {
        o.toString()
    }

    /** The revived arguments of the case called [name]. */
    fun args(corpus: Path, name: String): List<Any?> {
        GZIPInputStream(Files.newInputStream(corpus)).bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (line in lines) {
                if (!line.startsWith("{\"fn\":")) continue
                val c = IntentJs.normalize(Json.parseLenient(line.removeSuffix(","))) as Map<String, Any?>
                if (c["name"] == name) return revive(c["args"]) as List<Any?>
            }
        }
        throw AssertionError("no case $name")
    }

    /** Replays every case of the corpus at [corpus] (ref-zk.json.gz) through the registered engine. */
    fun run(corpus: Path): Outcome {
        val fns = LinkedHashSet<String>()
        val artifacts = ArrayList<String>()
        val divergent = ArrayList<String>()
        var total = 0
        GZIPInputStream(Files.newInputStream(corpus)).bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (line in lines) {
                if (!line.startsWith("{\"fn\":")) continue
                val c = IntentJs.normalize(Json.parseLenient(line.removeSuffix(","))) as Map<String, Any?>
                val fn = c["fn"] as String
                val name = c["name"] as String
                total++
                fns.add(fn)
                val want = c["out"]
                val throws = want is Map<*, *> && want.containsKey("\$throws")
                var got: Any? = null
                var err: Throwable? = null
                currentName = name
                currentWant = want
                try {
                    // policyVmContextMatches cases carry their pins as written (an unrevived {"\$bigint"} object is not a pin value)
                    val raw = c["args"] as List<Any?>
                    val callArgs = if (fn == "policyVmContextMatches") raw else revive(raw) as List<Any?>
                    got = IntentJs.normalize(toJson(call(fn, callArgs)))
                } catch (t: NeedsArtifacts) {
                    artifacts.add(name)
                    continue
                } catch (t: AssertionError) {
                    throw t
                } catch (t: Exception) {
                    err = t
                } finally {
                    currentName = null
                    currentWant = null
                }
                if (throws) {
                    if (err == null) divergent.add("$name\n  want: a refusal\n  got:  ${text(got)}")
                } else if (err != null) {
                    divergent.add("$name\n  want: ${text(want)}\n  got:  THROWS $err")
                } else if (!IntentJs.jsonEquals(want, got)) {
                    divergent.add("$name\n  want: ${text(want)}\n  got:  ${text(got)}")
                }
            }
        }
        return Outcome(total, fns, artifacts, divergent)
    }
}
