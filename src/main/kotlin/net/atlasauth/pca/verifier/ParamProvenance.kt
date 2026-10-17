package net.atlasauth.pca.verifier

import java.util.TreeSet

/**
 * Rule 17: per-parameter provenance, label receipts and flow rules (packages/pca/src/param-provenance.ts
 * `decideParamProvenance`, label-receipts.ts, the taint lattice of taint.ts: trusted 0 < first_party 1 < tool 2 < web 3
 * < agent 4; the join is the highest rank; tainted = rank >= 2). Outcome `pass`, `question` or `deny`; first failure
 * wins; never throws.
 */
object ParamProvenance {
    const val LABELS_DOMAIN = "atlas-pca/labels/v1\u0000"
    const val LABELS_REF_DOMAIN = "atlas-pca/labels-ref/v1"
    const val LABEL_REF_PREFIX = "pca-labels:"
    const val PUBLIC_CLASS = "public"
    const val MAX_LABEL_FIELDS = 64
    const val MAX_PROV_PATHS = 32
    const val MAX_PROV_REFS = 8
    const val MAX_COMMITTED_LABELS = 16
    internal val PROV_PATH_RE = Regex("action\\.params\\.[A-Za-z0-9_]{1,64}")
    private val PROTO_NAMES = setOf("__proto__", "constructor", "prototype")
    internal val TAINT_LEVELS = listOf("trusted", "first_party", "tool", "web", "agent")
    private val MODES = listOf("allow", "question", "question_typed", "deny")
    private const val TAINTED_RANK = 2

    /** The rule-17 verdict. `labels`: classified path -> level; `classes`: path -> sorted class list; `env`: nested labels. */
    class ProvResult internal constructor(
        val outcome: String,
        val reason: String?,
        val friction: String?,
        val labels: Map<String, Any?>,
        val classes: Map<String, Any?>,
        val env: Map<String, Any?>,
    )

    internal fun isTaintLevel(k: Any?): Boolean = k is String && k in TAINT_LEVELS
    internal fun rank(level: Any?): Int = if (isTaintLevel(level)) TAINT_LEVELS.indexOf(level) else 4
    internal fun isProvPath(k: String): Boolean = PROV_PATH_RE.matches(k) && k.substring("action.params.".length) !in PROTO_NAMES

    // ---- label receipts ----
    internal fun validateLabelsWire(lo: Any?): String? {
        if (lo !is Map<*, *>) return "label receipt must be an object"
        val l = IntentJs.obj(lo)
        val m = IntentArtifacts.closedMembers(l, listOf("v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig"), IntentArtifacts.SUITE_MEMBERS, "labels")
        if (m != null) return m
        if (!OracleFacts.isOne(l["v"]) || "pca-labels" != l["kind"]) return "label receipt must be {v: 1, kind: \"pca-labels\"}"
        if (!IntentArtifacts.isBoundedString(l["site"], 256)) return "'labels.site' must be a non-empty string (<= 256 bytes)"
        if (!IntentArtifacts.isDigest(l["session"])) return "'labels.session' must be canonical base64url (32 bytes)"
        if (!IntentArtifacts.isDigest(l["response_digest"])) return "'labels.response_digest' must be canonical base64url (32 bytes)"
        if (l["fields"] !is Map<*, *>) return "'labels.fields' must be an object"
        val fields = IntentJs.obj(l["fields"])
        if (fields.isEmpty() || fields.size > MAX_LABEL_FIELDS) return "'labels.fields' must hold 1..$MAX_LABEL_FIELDS fields"
        for ((k, f) in fields) {
            if (!IntentArtifacts.isBoundedString(k, 256)) return "label field paths must be non-empty strings (<= 256 bytes)"
            if (f !is Map<*, *> || IntentArtifacts.closedMembers(IntentJs.obj(f), listOf("class", "value_digest"), listOf(), "object") != null)
                return "label field '$k' must be exactly {class, value_digest}"
            val cls = IntentJs.get(f, "class")
            if (cls !is String || cls.length > 128 || !IntentArtifacts.DATA_CLASS_RE.matches(cls)) return "label field '$k': invalid data class"
            if (!IntentArtifacts.isDigest(IntentJs.get(f, "value_digest"))) return "label field '$k': value_digest must be canonical base64url (32 bytes)"
        }
        if (!IntentJs.isInt(l["issued_at"]) || IntentJs.num(l["issued_at"])!! < 0) return "'labels.issued_at' must be a non-negative safe integer"
        if (!IntentArtifacts.isBoundedString(l["kid"], 64)) return "'labels.kid' must be a non-empty string (<= 64 bytes)"
        if (l["sig"] !is String) return "'labels.sig' must be a string"
        return null
    }

    fun labelsRef(l: Map<String, Any?>): String = IntentArtifacts.artifactRef(LABELS_REF_DOMAIN, "l", l)

    internal fun verifyLabels(l: Any?, keys: List<*>): String? {
        val w = validateLabelsWire(l)
        if (w != null) return w
        val r = IntentJs.obj(l)
        val se = IntentArtifacts.artifactSuiteError(r)
        if (se != null) return "signature suite: $se"
        val key = keys.firstOrNull { r["site"] == IntentJs.get(it, "site") && r["kid"] == IntentJs.get(it, "kid") } as Map<*, *>?
            ?: return "no pinned label key for site '${r["site"]}' kid '${r["kid"]}'"
        return if (IntentArtifacts.verifyArtifactSig(LABELS_DOMAIN, r, key["pk"], key["pq_pk"])) null else "bad label receipt signature"
    }

    /** The most specific flow pattern for `cls`: itself, else the longest `p.*` prefix, else `*`. */
    internal fun flowRuleFor(rules: Map<String, Any?>, cls: String): String? {
        if (rules.containsKey(cls)) return cls
        var best: String? = null
        for (p in rules.keys) {
            if (!p.endsWith(".*")) continue
            val prefix = p.substring(0, p.length - 1)
            if (cls.startsWith(prefix) && (best == null || p.length > best.length)) best = p
        }
        if (best != null) return best
        return if (rules.containsKey("*")) "*" else null
    }

    internal fun flowAllowed(rules: Map<String, Any?>, cls: String, origin: String, aud: String): Boolean {
        if (aud == origin || cls == PUBLIC_CLASS) return true
        val p = flowRuleFor(rules, cls) ?: return false
        val sinks = rules[p]
        return sinks is List<*> && sinks.contains(aud)
    }

    internal fun validateFlowRules(rules: Any?): String? {
        if (rules !is Map<*, *>) return "flows must be an object"
        for ((p, v) in IntentJs.obj(rules)) {
            val base = if (p == "*") "x" else if (p.endsWith(".*")) p.substring(0, p.length - 2) else p
            if (!IntentArtifacts.DATA_CLASS_RE.matches(base)) return "flow pattern '$p' is not a class, a 'prefix.*' or '*'"
            if (v !is List<*>) return "flow pattern '$p' needs a list of audiences"
            for (s in v) if (!IntentArtifacts.isBoundedString(s, 256)) return "flow pattern '$p' needs a list of audiences"
        }
        return null
    }

    // ---- policy and wire ----
    internal fun validateProvenancePolicy(po: Any?): String? {
        if (po !is Map<*, *> || IntentJs.get(po, "params") !is Map<*, *>) return "provenance policy needs a params map"
        val p = IntentJs.obj(po)
        val cm = IntentArtifacts.closedMembers(p, listOf("params"), listOf("registry", "label_keys", "critical_max", "material_tainted", "critical_tainted", "flows"), "policy")
        if (cm != null) return cm
        for ((k, v) in IntentJs.obj(p["params"])) {
            if (!IntentArtifacts.isParamPath(k)) return "policy param '$k' is not an action.params path"
            if ("material" != v && "critical" != v) return "policy param '$k': sensitivity must be material or critical"
        }
        if (p.containsKey("registry")) {
            if (p["registry"] !is Map<*, *>) return "registry must be an object"
            for ((k, v) in IntentJs.obj(p["registry"]))
                if (!IntentArtifacts.isBoundedString(k, 256) || !isTaintLevel(v)) return "registry entry '$k' must map to a taint level"
        }
        if (p.containsKey("label_keys")) {
            val lk = p["label_keys"] as? List<*> ?: return "label_keys must be a list"
            for (k in lk)
                if (k !is Map<*, *> || IntentArtifacts.closedMembers(IntentJs.obj(k), listOf("site", "kid", "pk"), listOf("pq_pk"), "label_key") != null ||
                    !IntentArtifacts.isBoundedString(IntentJs.get(k, "site"), 256) || !IntentArtifacts.isBoundedString(IntentJs.get(k, "kid"), 64) ||
                    !IntentArtifacts.isDigest(IntentJs.get(k, "pk")) || !IntentArtifacts.pinPqOk(k)
                ) return "every label key needs site, kid, a 32-byte pk and an optional string pq_pk"
        }
        if (p.containsKey("critical_max") && !isTaintLevel(p["critical_max"])) return "critical_max must be a taint level"
        if (p.containsKey("material_tainted") && p["material_tainted"] !in MODES) return "material_tainted must be allow | question | question_typed | deny"
        if (p.containsKey("critical_tainted") && ("allow" == p["critical_tainted"] || p["critical_tainted"] !in MODES))
            return "critical_tainted must be question | question_typed | deny"
        if (p.containsKey("flows")) {
            val e = validateFlowRules(p["flows"])
            if (e != null) return e
        }
        return null
    }

    internal fun validateProvWire(prov: Any?): String? {
        if (prov !is Map<*, *>) return "'prov' must be an object"
        val m = IntentJs.obj(prov)
        if (m.size > MAX_PROV_PATHS) return "'prov' holds more than $MAX_PROV_PATHS paths"
        for ((k, refs) in m) {
            if (!isProvPath(k)) return "'prov' key '$k' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)"
            if (refs !is List<*> || refs.isEmpty() || refs.size > MAX_PROV_REFS) return "'prov.$k' must hold 1..$MAX_PROV_REFS refs"
            for (r in refs) if (!IntentArtifacts.isBoundedString(r, 256)) return "'prov.$k' refs must be non-empty strings (<= 256 bytes)"
        }
        return null
    }

    /** `pca-labels:<digest>#<field>` split at the FIRST `#`: (receipt, field), or null. */
    internal fun parseLabelRef(ref: String): Pair<String, String>? {
        if (!ref.startsWith(LABEL_REF_PREFIX)) return null
        val rest = ref.substring(LABEL_REF_PREFIX.length)
        val i = rest.indexOf('#')
        if (i < 0) return null
        val receipt = rest.substring(0, i)
        val field = rest.substring(i + 1)
        return if (IntentArtifacts.isDigest(receipt) && field.isNotEmpty()) receipt to field else null
    }

    private fun sorted(keys: Collection<String>): List<String> = IntentJs.sortedUtf8(keys)

    /** The `primitives.intent_provenance` entry point: normalizes `input`, then rule 17. */
    fun decide(input: Any?): ProvResult = try {
        decideNormalized(IntentJs.obj(IntentJs.normalize(input)))
    } catch (e: RuntimeException) {
        ProvResult("deny", "provenance: evaluation error (fail closed): " + e.javaClass.simpleName, null, LinkedHashMap(), LinkedHashMap(), LinkedHashMap())
    }

    /** Rule 17 over an already normalized input `{aud, session, action, prov?, committed_labels?, labels?, policy}`. */
    internal fun decideNormalized(input: Map<String, Any?>): ProvResult {
        val labels = LinkedHashMap<String, Any?>()
        val classes = LinkedHashMap<String, Any?>()
        try {
            val policyO = input["policy"]
            val pe = validateProvenancePolicy(policyO)
            if (pe != null) return deny(labels, classes, "policy misconfigured (fail closed): $pe")
            val policy = IntentJs.obj(policyO)
            val prov = IntentJs.opt(input, "prov", LinkedHashMap<String, Any?>())
            val we = validateProvWire(prov)
            if (we != null) return deny(labels, classes, we)
            val committed = IntentJs.opt(input, "committed_labels", listOf<Any?>())
            if (committed !is List<*> || committed.size > MAX_COMMITTED_LABELS)
                return deny(labels, classes, "committed labels must be a list of at most $MAX_COMMITTED_LABELS digests")
            val committedSet = LinkedHashSet<String>()
            for (d in committed) {
                if (!IntentArtifacts.isDigest(d) || !committedSet.add(d as String)) return deny(labels, classes, "committed labels must be distinct canonical 32-byte digests")
            }
            val action = input["action"]
            if (action !is Map<*, *>) return deny(labels, classes, "action must be an object")
            if (IntentJs.opt(action, "params", emptyMap<String, Any?>()) !is Map<*, *>) return deny(labels, classes, "action.params must be an object")
            val params = IntentArtifacts.actionParams(action)
            if (IntentJs.opt(input, "labels", listOf<Any?>()) !is List<*>) return deny(labels, classes, "labels must be an array")
            val provMap = IntentJs.obj(prov)
            val paths = sorted(provMap.keys)
            for (p in paths) if (!IntentArtifacts.resolveParamPath(params, p).found) return deny(labels, classes, "prov names '$p', a parameter the action does not carry")
            for (a in paths) for (b in paths) if (a != b && b.startsWith("$a.")) return deny(labels, classes, "prov paths '$a' and '$b' overlap")

            val receipts = HashMap<String, Map<String, Any?>>()
            for (r in IntentArtifacts.iterable(IntentJs.opt(input, "labels", listOf<Any?>()))) {
                try {
                    if (validateLabelsWire(r) == null) receipts[labelsRef(IntentJs.obj(r))] = IntentJs.obj(r)
                } catch (e: RuntimeException) { /* no reference */ }
            }
            val reg = IntentJs.opt(policy, "registry", emptyMap<String, Any?>()) as Map<*, *>
            val keys = IntentJs.opt(policy, "label_keys", listOf<Any?>()) as List<*>
            // `aud` is whatever the input carries (TS never casts it): a non-string never equals a site and no flow
            // rule lists it, so only a labelled parameter can be refused over it
            val aud = input["aud"]
            val audText = if (input.containsKey("aud")) jsString(aud) else "undefined"
            val origins = LinkedHashMap<String, MutableList<Pair<String, String>>>()

            for (p in paths) {
                val value = IntentArtifacts.resolveParamPath(params, p).value
                var join = -1
                for (refO in provMap[p] as List<*>) {
                    val ref = refO as String
                    if (!ref.startsWith(LABEL_REF_PREFIX)) {
                        val r = if (reg.containsKey(ref) && isTaintLevel(reg[ref])) rank(reg[ref]) else 4
                        join = maxOf(join, r)
                        continue
                    }
                    val lr = parseLabelRef(ref) ?: return deny(labels, classes, "malformed label ref on '$p'")
                    if (lr.first !in committedSet) return deny(labels, classes, "label ref on '$p' names a receipt the PCActn does not commit")
                    val rc = receipts[lr.first] ?: return deny(labels, classes, "label receipt for '$p' was not supplied")
                    val ve = verifyLabels(rc, keys)
                    if (ve != null) return deny(labels, classes, "label receipt for '$p': $ve")
                    if (rc["session"] != input["session"]) return deny(labels, classes, "label receipt for '$p' is bound to another session")
                    val fields = IntentJs.obj(rc["fields"])
                    if (!fields.containsKey(lr.second)) return deny(labels, classes, "label receipt for '$p' has no field '${lr.second}'")
                    val field = IntentJs.obj(fields[lr.second])
                    val match = try { IntentJs.hashCanonical(value) == field["value_digest"] } catch (e: RuntimeException) { false }
                    val r = if (match) (if (rc["site"] == aud) 1 else 2) else 4
                    join = maxOf(join, r)
                    origins.getOrPut(p) { ArrayList() }.add(field["class"] as String to rc["site"] as String)
                }
                labels[p] = TAINT_LEVELS[if (join < 0) 4 else join]
            }
            val sens = IntentJs.obj(policy["params"])
            for (p in sorted(sens.keys)) {
                if (labels.containsKey(p)) continue
                if (IntentArtifacts.resolveParamPath(params, p).found) labels[p] = "agent"
            }
            val flows = IntentJs.obj(IntentJs.opt(policy, "flows", emptyMap<String, Any?>()))
            for (p in sorted(origins.keys)) {
                val cs = TreeSet<String> { a, b -> Json.compareUtf8(a, b) }
                for (o in origins[p]!!) cs.add(o.first)
                classes[p] = ArrayList<Any?>(cs)
                for (o in origins[p]!!)
                    if (aud !is String || !flowAllowed(flows, o.first, o.second, aud)) return deny(labels, classes, "flow: class '${o.first}' from '${o.second}' may not reach '$audText' (parameter '$p')")
            }
            val capRank = rank(IntentJs.opt(policy, "critical_max", "agent"))
            val labelled = sorted(labels.keys)
            for (p in labelled) {
                if ("critical" == sens[p] && rank(labels[p]) > capRank)
                    return deny(labels, classes, "critical parameter '$p' has provenance '${labels[p]}', above the policy maximum '${policy["critical_max"]}'")
            }
            var question = false
            var typed = false
            for (p in labelled) {
                val s = sens[p]
                if (s == null || rank(labels[p]) < TAINTED_RANK) continue
                val mode = if ("critical" == s) IntentJs.opt(policy, "critical_tainted", "question_typed")
                else IntentJs.opt(policy, "material_tainted", "question")
                if ("deny" == mode) return deny(labels, classes, "tainted $s parameter '$p' (provenance '${labels[p]}') is denied by policy")
                if ("question" == mode || "question_typed" == mode) question = true
                if ("question_typed" == mode) typed = true
            }
            val env = LinkedHashMap<String, Any?>()
            for (p in labelled) if (!IntentArtifacts.setNested(env, p, labels[p])) return deny(labels, classes, "provenance paths overlap at '$p'")
            return if (question) ProvResult("question", "provenance: a tainted value needs the principal (lazy question)", if (typed) "typed" else "tap", labels, classes, env)
            else ProvResult("pass", null, null, labels, classes, env)
        } catch (e: RuntimeException) {
            return deny(labels, classes, "evaluation error (fail closed): " + e.javaClass.simpleName)
        }
    }

    /** The read-cell verdict (V14): `outcome` allow / question / deny, the optional fields to minimise, the uncovered ones. */
    class ReadPurposeResult internal constructor(val outcome: String, val minimise: List<String>, val uncovered: List<String>)

    private fun classCovered(patterns: List<*>, cls: String): Boolean =
        cls == PUBLIC_CLASS || patterns.any { p -> p is String && (p == "*" || p == cls || (p.endsWith(".*") && cls.startsWith(p.substring(0, p.length - 1)))) }

    /**
     * Read cell decision (V14; `primitives.intent_read_purpose`, label-receipts.ts `decideReadPurpose`) over
     * `{fields: [{path, class, optional?}], purpose, coverage: {purpose: [pattern]}, on_uncovered?}`: a field is covered when
     * its class is `public` or matches a pattern of the OWN member `coverage[purpose]` (a class, `p.*`, `*`); an uncovered
     * optional field is minimised, any other uncovered field makes the read `on_uncovered` (default `question`). Both lists
     * de-duplicated and sorted in UTF-8 byte order. Malformed input (JSON null anywhere included) is deny with empty lists.
     */
    fun decideReadPurpose(input: Any?): ReadPurposeResult {
        val malformed = ReadPurposeResult("deny", listOf(), listOf())
        try {
            val inp = IntentJs.normalize(input) as? Map<*, *> ?: return malformed
            val fields = inp["fields"]
            val purpose = inp["purpose"]
            val coverage = inp["coverage"]
            val onUncovered = if (inp.containsKey("on_uncovered")) inp["on_uncovered"] else "question"
            if (fields !is List<*> || purpose !is String || coverage !is Map<*, *> || (onUncovered != "question" && onUncovered != "deny")) return malformed
            for (pats in coverage.values) if (pats !is List<*> || pats.any { it !is String }) return malformed
            for (f in fields) {
                if (f !is Map<*, *> || f["path"] !is String || f["class"] !is String || (f.containsKey("optional") && f["optional"] !is Boolean)) return malformed
            }
            val patterns = if (coverage.containsKey(purpose)) coverage[purpose] as List<*> else listOf<Any?>()
            val minimise = HashSet<String>()
            val uncovered = HashSet<String>()
            for (f in fields) {
                val m = f as Map<*, *>
                if (classCovered(patterns, m["class"] as String)) continue
                (if (m["optional"] == true) minimise else uncovered).add(m["path"] as String)
            }
            return ReadPurposeResult(if (uncovered.isEmpty()) "allow" else onUncovered as String, IntentJs.sortedUtf8(minimise), IntentJs.sortedUtf8(uncovered))
        } catch (e: RuntimeException) {
            return malformed
        }
    }

    /** JavaScript `String(v)` of a JSON value (the TS reason's template interpolation). */
    private fun jsString(v: Any?): String = when (v) {
        null -> "null"
        is Map<*, *> -> "[object Object]"
        is List<*> -> v.joinToString(",") { if (it == null) "" else jsString(it) }
        else -> v.toString()
    }

    private fun deny(labels: Map<String, Any?>, classes: Map<String, Any?>, reason: String): ProvResult =
        ProvResult("deny", "provenance: $reason", null, labels, classes, LinkedHashMap())
}
