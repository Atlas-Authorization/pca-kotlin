package net.atlasauth.pca.verifier

/**
 * The post-quantum software / HSM attestation root. A statement over the measured workload, bound to a holder, grant, epoch and nonce, signed by an
 * HSM-held key under a post-quantum or hybrid suite (ML-DSA, SLH-DSA, with Ed25519 for a hybrid). The verifier holds only public keys and trusts a fixed set.
 *
 * Honest scope: the signature is post-quantum, but the measurements are software-measured and then vouched for by the HSM root, so the identity it yields
 * has `weights_measured: false`. It satisfies a plain weights allowlist and never a grant's measured-weights requirement by itself; compose it with a
 * hardware root in a multi-root policy to get both properties. `alg` and the attestor public keys are inside the signed body, so a suite downgrade or a key
 * swap invalidates the statement; a hybrid needs both component signatures.
 */
@Suppress("UNCHECKED_CAST")
object AttestPqSoftware {
    /** Domain separator of the signed statement body. */
    const val PQ_ATTEST_DOMAIN = "atlas-pca/attest-pq/v1\u0000"

    private val PQ_PRIMS = setOf(Pq.Prim.ML_DSA_65, Pq.Prim.ML_DSA_87, Pq.Prim.SLH_DSA_SHA2_128F, Pq.Prim.SLH_DSA_SHA2_256S)
    private val OPTIONAL_CLAIMS = listOf("weights_digest", "system_prompt_digest", "tool_manifest_digest", "model_id", "operator")

    private fun hasPq(s: Pq.Suite): Boolean = s.pq in PQ_PRIMS

    /** A statement signer built from an HSM-held key (provided, never generated here). */
    class Attestor internal constructor(private val key: Keys.SuiteKey, val pqPublicKey: String, val ed25519PublicKey: String?) {
        /**
         * Mint a statement over `claims`: `measurement`, `holder_pub`, `grant_ref`, `epoch`, `nonce` and the optional `weights_digest`, `system_prompt_digest`,
         * `tool_manifest_digest`, `model_id`, `operator`. Throws on a claim the binding refuses.
         */
        fun attest(claims: Map<String, Any?>): Map<String, Any?> {
            val bind = LinkedHashMap<String, Any?>()
            for ((k, c) in listOf("holderPub" to "holder_pub", "grantRef" to "grant_ref", "epoch" to "epoch", "nonce" to "nonce")) if (claims.containsKey(c)) bind[k] = claims[c]
            val body = LinkedHashMap<String, Any?>()
            if (!claims.containsKey("measurement")) throw IllegalArgumentException("canonicalize: unsupported type undefined")
            body["measurement"] = claims["measurement"]
            body["binding"] = Attestation.attestationBindingB64u(bind)
            body["alg"] = key.alg
            key.pqPk()?.let { body["pq_pk"] = it }
            ed25519PublicKey?.let { body["attestor_ed25519"] = it }
            for (k in OPTIONAL_CLAIMS) if (claims.containsKey(k)) body[k] = claims[k]
            val sg = key.sign(IntentJs.message(PQ_ATTEST_DOMAIN, IntentJs.normalize(body)))
            val out = LinkedHashMap(body)
            out["sig"] = sg.first
            if (sg.second != null) out["pq_sig"] = sg.second
            return out
        }
    }

    /**
     * Build an attestor under `alg`. The suite must carry a post-quantum component (a classical suite is refused: this is the post-quantum root), the PQ key
     * must be of the suite's family, and a hybrid also needs the Ed25519 key.
     */
    @JvmStatic fun createPqSoftwareAttestor(alg: Any?, ed: Keys.EdKey?, pq: Keys.PqKey?): Attestor {
        val suite = Pq.resolveSigAlg(alg, true)
        if (suite == null) {
            if (alg is String && alg in Pq.REGISTERED_SUITES) throw IllegalArgumentException("createPqSoftwareAttestor: '$alg' is classical; the PQ root requires a post-quantum suite")
            throw IllegalArgumentException("createPqSoftwareAttestor: unknown signature alg '${ZkJs.string(alg)}'")
        }
        if (!hasPq(suite)) throw IllegalArgumentException("createPqSoftwareAttestor: '${suite.alg}' is classical; the PQ root requires a post-quantum suite")
        if (pq == null || pq.prim != suite.pq) throw IllegalArgumentException("createPqSoftwareAttestor: '${suite.alg}' requires the matching PQ key material")
        if (suite.hasEd25519 && ed == null) throw IllegalArgumentException("createPqSoftwareAttestor: hybrid suite '${suite.alg}' requires edSecret")
        val key = Keys.suite(suite.alg, if (suite.hasEd25519) ed else null, pq)
        return Attestor(key, pq.pkB64u(), ed?.id())
    }

    /** Resolves the signed statement for an action from the attestation document and the context; null when there is none. A throw is a refusal. */
    fun interface EvidenceResolver {
        fun resolve(document: Any?, ctx: Any?): Any?
    }

    /** The verifier [createPqSoftwareVerifier] builds: the hardware seam, labelled `software` / `pq-software`. */
    class Verifier internal constructor(
        private val measurements: List<Any?>,
        private val weights: List<Any?>?,
        private val trustedPq: Set<Any?>,
        private val trustedEd: Set<Any?>,
        private val requirePq: Boolean,
        private val requireHybrid: Boolean,
        private val allowed: Set<Any?>?,
        private val resolver: EvidenceResolver?,
        private val derive: ((Map<String, Any?>) -> Map<String, Any?>)?,
    ) : Attestation.HardwareVerifier, Assurance.Labeled {
        override val assuranceLabel: Assurance.Label = Assurance.Label("software", "pq-software", null, null)

        private fun fail(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

        /**
         * `input` is `{document, ctx, nowMs, expected}`. In order: the suite and the post-quantum / hybrid / allowed-suite requirements; the attestor keys are
         * trusted; the signature over the canonical statement body; the binding equals the expected holder, grant, epoch and nonce; the measurement
         * allowlist and the optional weights allowlist. The first failure is the result; it never throws.
         */
        override fun verify(input: Map<String, Any?>): Any? {
            try {
                val res = resolver ?: return fail("no PQ-software evidence resolver configured (fail closed)")
                val st = res.resolve(input["document"], input["ctx"])
                if (st !is Map<*, *> || st["alg"] !is String) return fail("no PQ-software attestation statement for this action")
                st as Map<String, Any?>
                val suite = Pq.resolveSigAlg(st["alg"], true) ?: return fail("PQ statement declares an unknown signature alg '${ZkJs.string(st["alg"])}'")
                if (requirePq && !hasPq(suite)) return fail("PQ required: a classical-only suite '${suite.alg}' is not accepted by the post-quantum root")
                if (requireHybrid && !(suite.hasEd25519 && hasPq(suite))) return fail("hybrid required: suite '${suite.alg}' is not a classical+PQ hybrid")
                if (allowed != null && suite.alg !in allowed) return fail("suite '${suite.alg}' is not in the allowed-suites list")

                val pqPk = st["pq_pk"]
                if (suite.needsPqPk && (pqPk !is String || pqPk !in trustedPq)) return fail("PQ attestor key is not trusted")
                val edPk = st["attestor_ed25519"]
                if (suite.hasEd25519 && (edPk !is String || edPk !in trustedEd)) return fail("hybrid Ed25519 attestor key is not trusted")

                val body = LinkedHashMap(st)
                val sig = body.remove("sig")
                val pqSig = body.remove("pq_sig")
                val message = IntentJs.message(PQ_ATTEST_DOMAIN, IntentJs.normalize(body))
                val pin = if (suite.needsPqPk) PinnedPq.resolve(null, null, trustedPk = pqPk as? String) else null
                if (!Pq.verifySuite(suite.alg, true, edPk as? String, pin, message, sig, pqSig)) return fail("PQ attestation signature does not verify")

                if (!ZkJs.truthy(input["expected"])) return fail("no expected attestation binding supplied")
                val expected = try {
                    Keys.b64u(Attestation.attestationBinding(input["expected"]))
                } catch (e: RuntimeException) {
                    return fail("binding not constructible: ${e.message ?: "invalid"}")
                }
                val binding = st["binding"]
                if (binding !is String || binding.isEmpty()) return fail("PQ statement is not bound (binding absent)")
                if (binding != expected) return fail("PQ statement binding mismatch (holder/grant/epoch/nonce)")

                if (measurements.none { it == st["measurement"] }) return fail("measurement not in policy allowlist")
                if (weights != null && weights.isNotEmpty()) {
                    val w = st["weights_digest"]
                    if (w !is String || weights.none { it == w }) return fail("measured weights digest not in policy allowlist")
                }
                val measured = derive?.invoke(st) ?: defaultIdentity(st)
                return linkedMapOf("ok" to true, "bound" to true, "measured" to measured, "hostAsserted" to linkedMapOf("suite" to suite.alg))
            } catch (e: RuntimeException) {
                return fail("pq-software verification error (fail closed): ${e.message ?: "unknown"}")
            }
        }
    }

    private fun defaultIdentity(st: Map<String, Any?>): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>(
            "model_id" to ((st["model_id"] as? String) ?: ""),
            "weights_digest" to ((st["weights_digest"] as? String) ?: ""),
            "weights_measured" to false, // software-measured, vouched for by the HSM root: never silicon-rooted
            "runtime_measurement" to st["measurement"],
            "operator" to ((st["operator"] as? String) ?: ""),
        )
        (st["system_prompt_digest"] as? String)?.let { m["system_prompt_digest"] = it }
        (st["tool_manifest_digest"] as? String)?.let { m["tool_manifest_digest"] = it }
        return m
    }

    private fun listOrNull(v: Any?): List<Any?>? = (v as? List<Any?>)?.toList()

    /**
     * Build the verifier from `opts`: `trustedPqPublicKeys` (at least one), `trustedEd25519PublicKeys` (for a hybrid), `requirePq` (default true),
     * `requireHybrid` (default false), `allowedSuites` (absent: any suite meeting the requirements; an empty or non-list value refuses every suite) and
     * `policy: {measurements (non-empty), weightsMeasurements?}`. The lists are copied: later edits by the caller change nothing.
     * [derive] maps a verified statement to the identity `agent_binding` is checked against (default: the statement's own claims, weights unmeasured).
     */
    @JvmStatic @JvmOverloads
    fun createPqSoftwareVerifier(opts: Map<String, Any?>?, resolver: EvidenceResolver? = null, derive: ((Map<String, Any?>) -> Map<String, Any?>)? = null): Verifier {
        val policy = opts?.get("policy") as? Map<String, Any?>
        val ms = listOrNull(policy?.get("measurements"))
        if (ms == null || ms.isEmpty()) throw IllegalArgumentException("createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
        val trustedPq = listOrNull(opts?.get("trustedPqPublicKeys"))?.toSet() ?: emptySet()
        if (trustedPq.isEmpty()) throw IllegalArgumentException("createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)")
        val allowed: Set<Any?>? = if (opts!!.containsKey("allowedSuites")) (listOrNull(opts["allowedSuites"]) ?: emptyList()).toSet() else null
        return Verifier(
            ms, listOrNull(policy!!["weightsMeasurements"]), trustedPq, listOrNull(opts["trustedEd25519PublicKeys"])?.toSet() ?: emptySet(),
            opts["requirePq"] != false, opts["requireHybrid"] == true, allowed, resolver, derive,
        )
    }
}
