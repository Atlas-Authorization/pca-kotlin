package net.atlasauth.pca.verifier

/**
 * Binding of the objective-risk functional to the live decision path, without touching the signed PCActn (the reference's `objective-binding`).
 *
 * The facts live in the already-signed grant envelope, as an optional `objective_risk` member (covered by the root signature). A grant that commits
 * nothing is unaffected (the caller falls back to the heuristic). The actual registry, resource graph and calibration set are INSTANCE-held config
 * (`auth_config.pca.objectiveRisk`, a parsed object); their digests must equal the committed ones, or the result is a mismatch (fail closed per
 * `on_mismatch`; a grant cannot downgrade to the heuristic on its own say-so: the instance must set `allow_heuristic_fallback`).
 */
@Suppress("UNCHECKED_CAST")
object ObjectiveBinding {
    private fun isObj(v: Any?): Boolean = v is Map<*, *>
    private fun isStr(v: Any?): Boolean = v is String && v.isNotEmpty()
    private fun isOne(v: Any?): Boolean = v !is Boolean && v !is String && IntentJs.num(v) == 1.0
    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = Issue.obj(*kv)

    /**
     * Read the committed `objective_risk` off a grant's envelope: `{}` = not committed, `{commitment}` = well formed, `{malformed}` = refused. Pure.
     */
    @JvmStatic
    fun readObjectiveCommitment(grant: Any?): Map<String, Any?> {
        val env = Authorize.readEnvelope(grant)
        if (env == null || !env.containsKey("objective_risk")) return LinkedHashMap()
        val raw = env["objective_risk"] as? Map<String, Any?>
        fun bad(m: String) = obj("malformed" to m)
        if (raw == null || !isOne(raw["v"])) return bad("objective_risk: unsupported shape/version")
        val emb = raw["embedder"] as? Map<String, Any?>
        if (emb == null || emb["scheme"] != "native" || !isStr(emb["model_id"]) || !isObj(emb["config"]))
            return bad("objective_risk.embedder must be { scheme: \"native\", model_id, config }")
        val goal = raw["goal"] as? Map<String, Any?>
        if (goal == null || !isStr(goal["commit"])) return bad("objective_risk.goal must be a goal commitment")
        if (!isStr(raw["registry_digest"]) || !isStr(raw["graph_digest"])) return bad("objective_risk needs registry_digest and graph_digest")
        if (raw.containsKey("calibration_digest") && !isStr(raw["calibration_digest"])) return bad("objective_risk.calibration_digest must be a string")
        val kinds = raw["authorized_kinds"]
        if (kinds !is List<*> || !kinds.all { it is String }) return bad("objective_risk.authorized_kinds must be string[]")
        if (raw.containsKey("denominations") && raw["denominations"] !is List<*>) return bad("objective_risk.denominations must be an array")
        if (raw.containsKey("on_mismatch") && raw["on_mismatch"] != "deny" && raw["on_mismatch"] != "heuristic") return bad("objective_risk.on_mismatch must be \"deny\" or \"heuristic\"")
        return obj("commitment" to raw)
    }

    private fun buildRegistry(cfg: Any?): ObjectiveRisk.InMemoryInverseRegistry {
        val c = cfg as? Map<String, Any?>
        val reg = ObjectiveRisk.InMemoryInverseRegistry(((c?.get("trusted_verifiers") as? List<Any?>) ?: emptyList()).map { it as String })
        for (eo in (c?.get("entries") as? List<Any?>) ?: emptyList()) {
            val e = eo as Map<String, Any?>
            val row = obj("inverseKind" to e["inverse_kind"], "fidelity" to e["fidelity"])
            val v = e["verification"]
            if (ZkJs.truthy(v)) row["verification"] = obj("verifierId" to (v as Map<String, Any?>)["verifier_id"], "evidenceDigest" to v["evidence_digest"])
            reg.register(e["verb"] as String, row)
        }
        return reg
    }

    private fun buildGraph(cfg: Any?): ObjectiveRisk.ResourceGraph {
        val c = cfg as? Map<String, Any?>
        val g = ObjectiveRisk.ResourceGraph()
        for (n in (c?.get("nodes") as? List<Any?>) ?: emptyList()) g.addNode(n as Map<String, Any?>)
        for (e in (c?.get("edges") as? List<Any?>) ?: emptyList()) g.addEdge(e as Map<String, Any?>)
        return g
    }

    /**
     * Resolve the objective risk inputs for `action` under `grant`. Total (never throws). `instance` is the parsed instance config
     * (`{registry?, graph?, calibration?, allow_heuristic_fallback?}`) or null.
     *  - nothing committed: `{mode: "none"}` (the heuristic, unchanged);
     *  - committed and reproduced: `{mode: "objective", inputs: {reversibility, blastRadius, semanticDistance}, r, evidenceDigest}`;
     *  - committed but not reproducible or invalid: `{mode: "mismatch", reasons, onMismatch}` (default `deny`).
     * `taint` and `age` are verifier-supplied (they only feed `r`); both default to 1.
     */
    @JvmStatic @JvmOverloads
    fun resolveObjectiveRisk(grant: Any?, action: Any?, instance: Map<String, Any?>?, taint: Double? = null, age: Double? = null): Map<String, Any?> {
        val read = readObjectiveCommitment(grant)
        val malformed = read["malformed"]
        if (ZkJs.truthy(malformed)) return obj("mode" to "mismatch", "reasons" to arrayListOf<Any?>(malformed), "onMismatch" to "deny")
        val commitment = read["commitment"] as Map<String, Any?>? ?: return obj("mode" to "none")
        val requested = commitment["on_mismatch"] ?: "deny"
        // a GRANT cannot downgrade the verifier's objective risk to the heuristic on its own say-so
        val onMismatch = if (requested == "heuristic" && instance?.get("allow_heuristic_fallback") == true) "heuristic" else "deny"
        fun miss(vararg reasons: Any?): Map<String, Any?> = obj("mode" to "mismatch", "reasons" to ArrayList<Any?>(reasons.toList()), "onMismatch" to onMismatch)
        return try {
            val env = Authorize.readEnvelope(grant) ?: return miss("grant carries no valid envelope")
            if (instance == null) return miss("the grant commits objective-risk facts but the instance holds no objective-risk config")
            val registry = buildRegistry(instance["registry"])
            val graph = buildGraph(instance["graph"])
            val emb = commitment["embedder"] as Map<String, Any?>
            val embedder = ObjectiveRisk.nativeHashEmbedder(emb["config"] as Map<String, Any?>)
            if (embedder.modelId != emb["model_id"]) return miss("embedder model_id does not match the committed one")
            val calibration = instance["calibration"] as? List<Any?>
            val hasCalDigest = commitment.containsKey("calibration_digest")
            if (hasCalDigest && (calibration == null || ObjectiveRisk.calibrationDigest(calibration) != commitment["calibration_digest"]))
                return miss("calibration set does not match the committed digest")
            val commitments = obj("registryDigest" to commitment["registry_digest"], "graphDigest" to commitment["graph_digest"])
            if (hasCalDigest) commitments["calibrationDigest"] = commitment["calibration_digest"]
            val weights = (env["risk_policy"] as Map<String, Any?>)["weights"] as Map<String, Any?>
            val res = ObjectiveRisk.objectiveRisk(
                action,
                ObjectiveRisk.ObjectiveRiskContext(
                    registry, (commitment["authorized_kinds"] as List<Any?>).map { it as String }.toSet(), graph, commitment["scope"] as? Map<String, Any?>, embedder,
                    commitment["goal"] as Map<String, Any?>, commitments, (commitment["denominations"] as? List<Any?>) ?: emptyList(), weights, taint ?: 1.0, age ?: 1.0,
                    null, if (hasCalDigest && calibration != null) calibration else null,
                ),
            )
            if (res["valid"] != true) return miss(*(res["reasons"] as List<Any?>).toTypedArray())
            val inp = res["inputs"] as Map<String, Any?>
            obj(
                "mode" to "objective",
                "inputs" to obj("reversibility" to inp["reversibility"], "blastRadius" to inp["blastRadius"], "semanticDistance" to inp["semanticDistance"]),
                "r" to res["r"], "evidenceDigest" to res["evidenceDigest"],
            )
        } catch (e: RuntimeException) {
            miss("objective risk evaluation error (fail closed): ${e.message ?: "unknown"}")
        }
    }
}
