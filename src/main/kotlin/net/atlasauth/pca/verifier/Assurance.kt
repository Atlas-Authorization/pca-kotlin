package net.atlasauth.pca.verifier

import java.util.Collections
import java.util.WeakHashMap

/**
 * Assurance labels (T8 / B7).
 *
 * A check's status (`pass` / `fail` / `not-enforced` / `unsupported`) says WHETHER it held; the assurance report says WHAT a pass
 * rests on: software or hardware attestation, a SNARK proof or an attested-VM statement, a post-quantum or an Ed25519 signature,
 * independent multisig shares or a FROST (preview) aggregate. It also names features the verifier does not implement
 * (`unsupported`), which are reported and never count as a pass.
 *
 * Labels come from the VERIFIER'S configuration, never from the presented evidence: a software attestation verifier is `software`
 * whatever the document claims. A hook or backend without a label is `unknown`, which satisfies no requirement.
 *
 * A `requireAssurance` policy ([Authorize.Input.requireAssurance]) turns the report into a gate: when the evidence is weaker,
 * missing, failed, unlabelled, preview, degraded or unsupported, the `assurance` check fails and the request is denied before any
 * replay state is written. A report entry is `{outcome, level?, vendor?, preview?, ceremony?, suites?, t?, reason?, degraded?}`.
 */
object Assurance {
    /** What a hook, hardware verifier or SNARK-like backend declares about itself. */
    class Label(val level: String, val vendor: String? = null, val preview: Boolean? = null, val ceremony: String? = null)

    /** A verifier that declares its own label (no registry needed). */
    interface Labeled {
        val assuranceLabel: Label?
    }

    // identity of the labelled object is what counts: give each labelled hook its own instance (an object or a lambda)
    private val labels: MutableMap<Any, Label> = Collections.synchronizedMap(WeakHashMap())

    /**
     * Attach an assurance label to a verifier hook, a hardware verifier or a SNARK-like backend. `level`: attestation `software`
     * | `hardware` | `multi_root`; zk `groth16` | `policyvm_snark` | `stark` | `zkvm` | `attested_vm` | `attested_vm_hw`; threshold
     * `multisig` | `frost` | `frost_dkg` | `mpc`. The target is looked up by `equals`/`hashCode`, so a value-equal pair of targets
     * would share a label: label distinct instances. Returns `target`.
     */
    @JvmOverloads
    fun <T : Any> setLabel(target: T, level: String, vendor: String? = null, preview: Boolean? = null, ceremony: String? = null): T {
        labels[target] = Label(level, vendor, preview, ceremony)
        return target
    }

    /** The label of `target` ([Labeled] first, then [setLabel]), if any. */
    fun labelOf(target: Any?): Label? {
        if (target == null) return null
        if (target is Labeled) return target.assuranceLabel
        return labels[target]
    }

    private val ATT_RANK = mapOf("unknown" to 0, "software" to 1, "hardware" to 2, "multi_root" to 3)
    private val ZK_RANK = mapOf("unknown" to 0, "attested_vm" to 1, "attested_vm_hw" to 1, "stark" to 2, "zkvm" to 2, "groth16" to 3, "policyvm_snark" to 3)
    private val ZK_NEED = mapOf("attested_vm" to 1, "attested_vm_hardware" to 1, "proof" to 2, "snark" to 3)
    private val PREVIEW_SCHEMES = listOf("frost", "frost_dkg", "mpc")
    private val CHAIN_NAMES = listOf("cap_chain", "chain") // the reference names the chain check `cap_chain`, this SDK's verdict `chain`
    private val REQUIREMENT_KEYS = listOf("attestation", "zk", "signature", "threshold", "allow_preview", "allowPreview")

    /** The `degraded["tighten"]` text of a verdict that passed rule 21 under `model_polarity: "legacy"`. */
    const val LEGACY_POLARITY_DEGRADED = Authorize.LEGACY_POLARITY_DEGRADED

    /** True for the preview threshold schemes (FROST, DKG, MPC). */
    fun isPreviewScheme(scheme: Any?): Boolean = scheme is String && scheme in PREVIEW_SCHEMES

    /** One root of a multi-root attestation policy: its labelled verifier and whether the root is `required`. */
    class Root(val verifier: Any?, val required: Boolean = false)

    /**
     * The attestation level a multi-root N-of-M policy guarantees: the fewest hardware roots any accepted subset can contain (all
     * required roots, filled up to `threshold` with the weakest optional ones). Two or more => `multi_root`, one => `hardware`, none
     * => the weakest level among the roots that could make up the quorum.
     */
    fun multiRootLevel(roots: List<Root>, threshold: Double): String {
        fun rank(r: Root): Int = ATT_RANK[labelOf(r.verifier)?.level ?: "unknown"] ?: 0
        val req = roots.filter { it.required }
        val opt = roots.filter { !it.required }.sortedBy { rank(it) } // stable, like the reference's sort
        val fill = maxOf(0.0, threshold - req.size).let { if (it > opt.size) opt.size else it.toInt() }
        val chosen = req + opt.take(fill)
        val hw = chosen.count { rank(it) >= ATT_RANK.getValue("hardware") }
        if (hw >= 2) return "multi_root"
        if (hw == 1) return "hardware"
        val min = chosen.minOfOrNull { rank(it) } ?: ATT_RANK.getValue("software")
        return if (min >= ATT_RANK.getValue("software")) "software" else "unknown"
    }

    /**
     * Classify one signature suite (absent = Ed25519): `ed25519`, `hybrid` (Ed25519 + a PQ suite), `pq` (PQ only), or `unknown` for an
     * unregistered suite.
     */
    fun signatureLevel(alg: Any?): String {
        val a: Any = alg ?: "ed25519"
        if (a == "ed25519") return "ed25519"
        if (a !is String || a !in Pq.REGISTERED_SUITES) return "unknown"
        return if (a.startsWith("hybrid-")) "hybrid" else "pq"
    }

    private fun weakest(levels: List<String>): String {
        for (l in listOf("unknown", "ed25519", "hybrid")) if (l in levels) return l
        return if (levels.isNotEmpty()) "pq" else "unknown"
    }

    private fun suiteMissingHere(alg: Any?): Boolean {
        val a: Any = alg ?: "ed25519"
        return a is String && a in Pq.REGISTERED_SUITES && a !in Pq.supportedSuites()
    }

    private fun text(v: Any?): String = IntentRevocation.jsText(IntentJs.normalize(v), true)

    private fun isNumber(v: Any?): Boolean = v !is Boolean && IntentJs.num(v) != null

    /**
     * What each check rests on (the TypeScript `assuranceReport`). `checks` maps each check to its status; `degraded` maps a check name
     * to why a PASSING check rests on a compatibility mode (it is then reported `degraded`). Signature checks carry their suites and
     * level; a carried `bond_ref` is `unsupported` (never a pass).
     *
     * `hooks` are the verifier's labelled hooks (`attestation`, `zk`, `threshold`, `revocation`): a passing check reports the hook's level,
     * vendor, preview flag and (zk) ceremony; an unlabelled hook reports `unknown`. `attestationHook` (the verifier actually used) wins
     * over `hooks["attestation"]`; `thresholdT` is the `t` the threshold hook enforced; `allowUnboundPq` reports a PQ suite that was
     * not pinned as `unbound_pq`.
     *
     * With `hooks == null` (the [Authorize.authorize] path: this SDK verifies no zk proof, attestation or threshold co-signature there) a
     * failed attestation, a carried `zk_compliance` / `threshold` and a registered suite whose backend is missing here are also
     * reported `unsupported`.
     */
    @JvmOverloads
    fun report(
        p: Map<String, Any?>?, checks: Map<String, String>, degraded: Map<String, String>? = null,
        hooks: Map<String, Any?>? = null, attestationHook: Any? = null, thresholdT: Any? = null, allowUnboundPq: Boolean = false,
    ): Map<String, Map<String, Any?>> {
        val out = LinkedHashMap<String, Map<String, Any?>>()
        val pp: Map<String, Any?> = p ?: emptyMap()
        val havePcactn = p != null
        val hk: Map<String, Any?> = hooks ?: emptyMap()
        val chainRaw = pp["cap_chain"]
        val chain: List<Any?> = if (chainRaw is List<*>) chainRaw else emptyList()
        val hopAlgs: List<Any?> = chain.map { (it as? Map<*, *>)?.get("alg") }
        for ((name, st) in checks) {
            val e = LinkedHashMap<String, Any?>()
            e["outcome"] = st
            if (st == "unsupported") e["reason"] = "$name is not implemented by this verifier"
            if (st == "pass") {
                val hook: Any? = when (name) {
                    "attestation" -> attestationHook ?: hk["attestation"]
                    "zk_compliance" -> hk["zk"]
                    "threshold" -> hk["threshold"]
                    "revocation" -> hk["revocation"]
                    else -> null
                }
                val label = labelOf(hook)
                if (name == "attestation" || name == "zk_compliance" || (name == "threshold" && hook != null)) {
                    val level = label?.level ?: "unknown"
                    e["level"] = level
                    if (label?.vendor != null) e["vendor"] = label.vendor
                    if (name == "zk_compliance" && label?.ceremony != null) e["ceremony"] = label.ceremony
                    if (label?.preview == true || (name == "threshold" && isPreviewScheme(level))) e["preview"] = true
                    if (name == "threshold" && isNumber(thresholdT)) e["t"] = thresholdT
                } else if (label != null) {
                    e["level"] = label.level
                    if (label.vendor != null) e["vendor"] = label.vendor
                    if (label.preview == true) e["preview"] = true
                }
                if (name == "leaf_signature" && havePcactn) {
                    val alg: Any = pp["alg"] ?: "ed25519"
                    e["suites"] = listOf(text(alg))
                    e["level"] = if (allowUnboundPq && alg != "ed25519") "unbound_pq" else signatureLevel(alg)
                }
                if (name in CHAIN_NAMES && havePcactn && chainRaw is List<*>) {
                    val algs: List<Any> = hopAlgs.map { it ?: "ed25519" }
                    e["suites"] = algs.map { text(it) }
                    e["level"] = if (allowUnboundPq && algs.any { it != "ed25519" }) "unbound_pq" else weakest(algs.map { signatureLevel(it) })
                }
            }
            out[name] = e
        }

        fun unsupported(name: String, why: String) {
            out[name] = linkedMapOf("outcome" to "unsupported", "reason" to why)
        }

        if (hooks == null) {
            if (out["leaf_signature"]?.get("outcome") == "fail" && suiteMissingHere(pp["alg"]))
                unsupported("leaf_signature", "signature suite '${text(pp["alg"])}' has no backend in this runtime")
            if (out["chain"]?.get("outcome") == "fail" && hopAlgs.any { suiteMissingHere(it) })
                unsupported("chain", "a capability suite has no backend in this runtime")
            if (pp.containsKey("zk_compliance")) unsupported("zk_compliance", "zk compliance verification is not implemented by this SDK")
            if (out["attestation"]?.get("outcome") == "fail") unsupported("attestation", "attestation verification is not implemented by this SDK")
            if (pp.containsKey("threshold")) unsupported("threshold", "threshold co-signatures are not verified by this SDK")
        }
        if (pp.containsKey("bond_ref")) unsupported("bond", "bond verification is not implemented by this verifier") // never verified here
        for ((name, why) in degraded.orEmpty()) {
            val cur = out[name]
            if (cur != null && cur["outcome"] == "pass") {
                val m = LinkedHashMap(cur)
                m["degraded"] = true
                m["reason"] = why
                out[name] = m
            }
        }
        return out
    }

    /**
     * The TypeScript `unmetAssurance`: the reason (prefixed `assurance: `) of the first unmet dimension of `require`, or null.
     * Keys: `attestation` (`software` < `hardware` < `multi_root`), `zk` (`attested_vm` | `attested_vm_hardware` | `proof` |
     * `snark`), `signature` (`"pq"`), `threshold` (a list of accepted schemes), `allowPreview`. Missing, failed, not-enforced,
     * unlabelled, weaker, preview, degraded and unsupported evidence never meets a requirement. An unknown requirement key or value
     * is refused (fail closed).
     */
    fun unmetAssurance(report: Map<String, Map<String, Any?>>, require: Map<String, Any?>): String? {
        for ((name, e) in report) {
            if (e["outcome"] == "unsupported")
                return "assurance: unsupported: $name (${(e["reason"] as? String)?.takeIf { it.isNotEmpty() } ?: "not implemented"}); a high-assurance policy never accepts it"
        }
        for ((name, e) in report) {
            if (e["outcome"] == "pass" && e["degraded"] == true)
                return "assurance: $name rests on a degraded compatibility mode (${(e["reason"] as? String)?.takeIf { it.isNotEmpty() } ?: "degraded"}); a high-assurance policy never accepts it"
        }
        val unknown = require.keys.filter { it !in REQUIREMENT_KEYS }
        if (unknown.isNotEmpty()) return "assurance: unknown assurance requirement(s): ${unknown.sorted().joinToString(", ")} (fail closed)"
        val att = require["attestation"]
        val zk = require["zk"]
        val sig = require["signature"]
        val thr = require["threshold"]
        val allowPreview = (if (require.containsKey("allowPreview")) require["allowPreview"] else require["allow_preview"]) == true
        if (att != null && att !in listOf("software", "hardware", "multi_root")) return "assurance: unknown attestation requirement ${repr(att)} (fail closed)"
        if (zk != null && (zk !is String || !ZK_NEED.containsKey(zk))) return "assurance: unknown zk requirement ${repr(zk)} (fail closed)"
        if (sig != null && sig != "pq") return "assurance: unknown signature requirement ${repr(sig)} (fail closed)"
        if (thr != null && !(thr is List<*> && thr.all { it is String })) return "assurance: unknown threshold requirement ${repr(thr)} (fail closed)"
        val thresholds: List<String>? = (thr as List<*>?)?.map { it as String }

        fun need(name: String, what: String): Pair<Map<String, Any?>?, String?> {
            val e = report[name] ?: return Pair(null, "assurance: $what required but there is no $name evidence")
            if (e["outcome"] != "pass") return Pair(null, "assurance: $what required but the $name check is ${e["outcome"]}")
            return Pair(e, null)
        }

        fun level(e: Map<String, Any?>): String = (e["level"] as? String) ?: "unknown"

        if (att != null) {
            val (e, why) = need("attestation", "$att attestation")
            if (why != null) return why
            if ((ATT_RANK[level(e!!)] ?: 0) < ATT_RANK.getValue(att as String))
                return "assurance: $att attestation required but the evidence is ${level(e)}"
        }
        if (zk != null) {
            val (e, why) = need("zk_compliance", "zk compliance ($zk)")
            if (why != null) return why
            val lv = e!!["level"]
            if (zk == "attested_vm_hardware" && (lv == "attested_vm" || lv == "unknown" || lv == null))
                return "assurance: zk compliance ($zk) required but the prover key is not bound to hardware evidence"
            if ((ZK_RANK[level(e)] ?: 0) < ZK_NEED.getValue(zk as String)) return "assurance: zk compliance ($zk) required but the evidence is ${level(e)}"
        }
        if (sig == "pq") {
            for (name in listOf("leaf_signature", CHAIN_NAMES.firstOrNull { it in report } ?: "cap_chain")) {
                val (e, why) = need(name, "post-quantum signatures")
                if (why != null) return why
                val lv = e!!["level"]
                if (lv != "pq" && lv != "hybrid") return "assurance: post-quantum signatures required but $name is ${level(e)}"
            }
        }
        if (thresholds != null) {
            val names = thresholds.joinToString(" | ")
            val (e, why) = need("threshold", "threshold ($names)")
            if (why != null) return why
            val lv = e!!["level"] as? String ?: return "assurance: threshold ($names) required but no threshold verifier enforced it"
            if (lv !in thresholds) return "assurance: threshold ($names) required but the scheme is $lv"
        }
        if (!allowPreview) {
            for ((name, e) in report) {
                if (e["outcome"] != "pass" || e["preview"] != true) continue
                if (name == "threshold" && thresholds != null && (e["level"] as? String ?: "") in thresholds) continue
                return "assurance: $name rests on preview crypto (${level(e)}); set allowPreview or list the scheme to accept it"
            }
        }
        return null
    }

    /** Python-style rendering of a refused requirement value (the message text only). */
    private fun repr(v: Any?): String = if (v is String) "'$v'" else text(v)
}
