package net.atlasauth.pca.verifier

/**
 * Rule 18: classifier verdicts (packages/pca/src/intent-classifier.ts `decideClassifierDimensions`). A verdict
 * `pca-intent-classification` is signed by its `judge` key, which must be on the classifier's allowlist; per classifier
 * exactly one label must reach the k-of-n quorum of distinct judges. First failure wins; never throws.
 */
object IntentClassifier {
    const val INTENT_CLASSIFIER_DOMAIN = "atlas-pca/intent-classifier/v1\u0000"
    const val INTENT_CLASSIFIER_REF_DOMAIN = "atlas-pca/intent-classifier-ref/v1"
    const val MAX_COMMITTED_CLASSES = 8
    const val MAX_CLASSIFIER_LABELS = 32

    /** The rule-18 verdict: `classes` maps each classifier id to its quorum label. */
    class ClassResult internal constructor(val ok: Boolean, val reason: String?, val classes: Map<String, Any?>?) {
        internal companion object {
            fun fail(reason: String) = ClassResult(false, "classes: $reason", null)
        }
    }

    internal fun validateVerdictWire(vo: Any?): String? {
        if (vo !is Map<*, *>) return "verdict must be an object"
        val v = IntentJs.obj(vo)
        val m = IntentArtifacts.closedMembers(v, listOf("v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig"), IntentArtifacts.SUITE_MEMBERS, "verdict")
        if (m != null) return m
        if (!OracleFacts.isOne(v["v"]) || "pca-intent-classification" != v["kind"]) return "verdict must be {v: 1, kind: \"pca-intent-classification\"}"
        if (!IntentArtifacts.isName(v["classifier"])) return "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$"
        if (!IntentArtifacts.isDigest(v["session"])) return "'verdict.session' must be canonical base64url (32 bytes)"
        if (!IntentArtifacts.isDigest(v["content_digest"])) return "'verdict.content_digest' must be canonical base64url (32 bytes)"
        if (!IntentArtifacts.isBoundedString(v["label"], 64)) return "'verdict.label' must be a non-empty string (<= 64 bytes)"
        if (!IntentArtifacts.isBoundedString(v["measurement"], 256)) return "'verdict.measurement' must be a non-empty string (<= 256 bytes)"
        if (!IntentArtifacts.isDigest(v["judge"])) return "'verdict.judge' must be canonical base64url (32 bytes)"
        if (v["sig"] !is String) return "'verdict.sig' must be a string"
        return null
    }

    fun verdictRef(v: Map<String, Any?>): String = IntentArtifacts.artifactRef(INTENT_CLASSIFIER_REF_DOMAIN, "c", v)

    internal fun validatePolicy(po: Any?): String? {
        if (po !is Map<*, *> || IntentJs.get(po, "classifiers") !is List<*>) return "classifier policy needs a classifiers list"
        val cm = IntentArtifacts.closedMembers(IntentJs.obj(po), listOf("classifiers"), listOf(), "policy")
        if (cm != null) return cm
        val ids = HashSet<String>()
        for (co in IntentJs.get(po, "classifiers") as List<*>) {
            if (co !is Map<*, *> || IntentArtifacts.closedMembers(IntentJs.obj(co), listOf("id", "param", "labels", "keys", "k"), listOf("measurements", "pq_keys"), "classifier") != null)
                return "every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}"
            if (!IntentArtifacts.isName(co["id"]) || (co["id"] as String) in ids)
                return "every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$"
            val c = IntentJs.obj(co)
            val id = c["id"] as String
            ids.add(id)
            if (!IntentArtifacts.isParamPath(c["param"])) return "classifier '$id': param must be an action.params path"
            val labels = c["labels"]
            if (labels !is List<*> || labels.isEmpty() || labels.size > MAX_CLASSIFIER_LABELS)
                return "classifier '$id': labels must hold 1..$MAX_CLASSIFIER_LABELS strings"
            for (l in labels) if (!IntentArtifacts.isBoundedString(l, 64)) return "classifier '$id': labels must be distinct non-empty strings"
            if (HashSet<Any?>(labels).size != labels.size) return "classifier '$id': labels must be distinct non-empty strings"
            val keys = c["keys"]
            if (keys !is List<*> || keys.isEmpty()) return "classifier '$id': keys must be distinct 32-byte keys"
            for (k in keys) if (!IntentArtifacts.isDigest(k)) return "classifier '$id': keys must be distinct 32-byte keys"
            if (HashSet<Any?>(keys).size != keys.size) return "classifier '$id': keys must be distinct 32-byte keys"
            if (!IntentJs.isInt(c["k"]) || IntentJs.num(c["k"])!! < 1 || IntentJs.num(c["k"])!! > keys.size)
                return "classifier '$id': k must be an integer in [1, ${keys.size}]"
            if (c.containsKey("measurements")) {
                val ms = c["measurements"] as? List<*> ?: return "classifier '$id': measurements must be a list of strings"
                for (m in ms) if (m !is String) return "classifier '$id': measurements must be a list of strings"
            }
            if (c.containsKey("pq_keys")) {
                var ok = c["pq_keys"] is Map<*, *>
                if (ok) for ((k, v) in IntentJs.obj(c["pq_keys"]))
                    if (!keys.contains(k) || v !is String || v.isEmpty()) ok = false
                if (!ok) return "classifier '$id': pq_keys must map allowlisted keys to PQ keys"
            }
        }
        return null
    }

    /** True iff rule 18 is active: the committed verdicts or the classifier policy is a non-empty array. */
    fun classifierCheckActive(committed: Any?, policy: Any?): Boolean =
        OracleFacts.nonEmpty(committed) || OracleFacts.nonEmpty(IntentJs.get(policy, "classifiers"))

    /** The `primitives.intent_classifier` entry point: normalizes `input`, then rule 18. */
    fun decide(input: Any?): ClassResult = try {
        decideNormalized(IntentJs.obj(IntentJs.normalize(input)))
    } catch (e: RuntimeException) {
        ClassResult.fail("evaluation error (fail closed): " + e.javaClass.simpleName)
    }

    /** Rule 18 over an already normalized input `{session, action, committed?, verdicts?, policy}`. */
    internal fun decideNormalized(input: Map<String, Any?>): ClassResult {
        try {
            val pe = validatePolicy(input["policy"])
            if (pe != null) return ClassResult.fail("policy misconfigured (fail closed): $pe")
            val committed = IntentJs.opt(input, "committed", listOf<Any?>())
            if (committed !is List<*> || committed.size > MAX_COMMITTED_CLASSES)
                return ClassResult.fail("committed verdicts must be a list of at most $MAX_COMMITTED_CLASSES digests")
            val seen = HashSet<String>()
            for (d in committed) if (!IntentArtifacts.isDigest(d) || !seen.add(d as String)) return ClassResult.fail("committed verdicts must be distinct canonical 32-byte digests")
            val supplied = IntentJs.opt(input, "verdicts", listOf<Any?>())
            if (supplied !is List<*>) return ClassResult.fail("verdicts must be an array")
            if (input["action"] !is Map<*, *>) return ClassResult.fail("action must be an object")
            if (IntentJs.opt(input["action"], "params", emptyMap<String, Any?>()) !is Map<*, *>) return ClassResult.fail("action.params must be an object")
            val byRef = HashMap<String, Map<String, Any?>>()
            for (v in IntentArtifacts.iterable(supplied)) {
                if (validateVerdictWire(v) != null) continue
                try { byRef[verdictRef(IntentJs.obj(v))] = IntentJs.obj(v) } catch (e: RuntimeException) { /* no reference */ }
            }
            val params = IntentArtifacts.actionParams(input["action"])
            val classifiers = IntentJs.get(input["policy"], "classifiers") as List<*>
            val votes = HashMap<String, MutableMap<String, Int>>()
            val pairs = HashSet<String>()
            for (d in committed) {
                val v = byRef[d] ?: return ClassResult.fail("a committed verdict was not supplied (or is malformed)")
                val se = IntentArtifacts.artifactSuiteError(v)
                if (se != null) return ClassResult.fail("verdict signature suite: $se")
                val c = classifiers.firstOrNull { v["classifier"] == IntentJs.get(it, "id") }?.let { IntentJs.obj(it) }
                    ?: return ClassResult.fail("verdict for undeclared classifier '${v["classifier"]}'")
                val id = c["id"] as String
                if (!(c["keys"] as List<*>).contains(v["judge"])) return ClassResult.fail("classifier '$id': judge key is not on the allowlist")
                val pq = if (IntentJs.own(c, "pq_keys")) IntentJs.get(c["pq_keys"], v["judge"] as String) else null
                if (!IntentArtifacts.verifyArtifactSig(INTENT_CLASSIFIER_DOMAIN, v, v["judge"], pq)) return ClassResult.fail("classifier '$id': bad verdict signature")
                if (v["session"] != input["session"]) return ClassResult.fail("classifier '$id': verdict bound to another session")
                val content = IntentArtifacts.resolveParamPath(params, c["param"])
                if (!content.found) return ClassResult.fail("classifier '$id': the action carries no '${c["param"]}'")
                if (IntentJs.hashCanonical(content.value) != v["content_digest"]) return ClassResult.fail("classifier '$id': verdict is about other content")
                if (!(c["labels"] as List<*>).contains(v["label"])) return ClassResult.fail("classifier '$id': label '${v["label"]}' is not in its label set")
                if (c.containsKey("measurements") && !(c["measurements"] as List<*>).contains(v["measurement"]))
                    return ClassResult.fail("classifier '$id': measurement is not pinned")
                if (!pairs.add("$id\u0000${v["judge"]}")) return ClassResult.fail("classifier '$id': two verdicts from one judge")
                val t = votes.getOrPut(id) { HashMap() }
                t[v["label"] as String] = (t[v["label"] as String] ?: 0) + 1
            }
            val classes = LinkedHashMap<String, Any?>()
            for (co in classifiers) {
                val c = IntentJs.obj(co)
                val id = c["id"] as String
                val t: Map<String, Int> = votes[id] ?: emptyMap()
                val k = IntentJs.num(c["k"])!!
                val winners = ArrayList<String>()
                for (l in c["labels"] as List<*>) if ((t[l] ?: 0) >= k) winners.add(l as String)
                if (winners.isEmpty()) return ClassResult.fail("classifier '$id': no label reaches the quorum ${IntentJs.lng(c["k"])}")
                if (winners.size > 1) return ClassResult.fail("classifier '$id': ambiguous, ${winners.size} labels reach the quorum")
                classes[id] = winners[0]
            }
            return ClassResult(true, null, classes)
        } catch (e: RuntimeException) {
            return ClassResult.fail("evaluation error (fail closed): " + e.javaClass.simpleName)
        }
    }
}
