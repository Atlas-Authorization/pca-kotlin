package net.atlasauth.pca.verifier

/**
 * Shared conventions of the Intent Layer v2 W-B artifacts (rules 16-18; packages/pca/src/intent-artifacts.ts): closed
 * member sets, signatures under a VERIFIER-pinned key over `utf8(domain) || strictCanonical(artifact without sig and
 * pq_sig)`, content-addressed references, and own-member parameter paths.
 */
internal object IntentArtifacts {
    val INTENT_NAME_RE = Regex("[a-z][a-z0-9_]{0,63}")
    val DATA_CLASS_RE = Regex("[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*")
    val PARAM_SEGMENT_RE = Regex("[A-Za-z0-9_-]{1,64}")
    private val FORBIDDEN_SEGMENTS = setOf("__proto__", "constructor", "prototype")

    fun isPathSegment(s: String): Boolean = PARAM_SEGMENT_RE.matches(s) && s !in FORBIDDEN_SEGMENTS
    fun isName(v: Any?): Boolean = v is String && INTENT_NAME_RE.matches(v)
    fun isBoundedString(v: Any?, max: Int): Boolean = v is String && v.isNotEmpty() && IntentJs.u8len(v) <= max
    fun isDigest(v: Any?): Boolean = IntentJs.b32(v)

    /** A wire scalar: string, boolean or safe integer (not -0). */
    fun isScalar(v: Any?): Boolean = v is String || v is Boolean || IntentJs.isInt(v)

    /** Same JSON type and value (`2 != "2"`, `true != 1`). */
    fun scalarEq(a: Any?, b: Any?): Boolean {
        if (a is String || b is String) return a is String && a == b
        if (a is Boolean || b is Boolean) return a is Boolean && a == b
        val x = IntentJs.num(a)
        val y = IntentJs.num(b)
        if (x != null && y != null) return x == y
        return a == null && b == null // typeof null === 'object' and null === null
    }

    /** Null when every key is listed and every required key is present, else the reason. */
    fun closedMembers(o: Map<String, Any?>, required: List<String>, optional: List<String>, where: String): String? {
        for (k in o.keys) if (k !in required && k !in optional) return "unknown member '$where.$k'"
        for (k in required) if (!o.containsKey(k)) return "missing member '$where.$k'"
        return null
    }

    /** The optional suite members every W-B artifact may carry (`alg` and `pq_pk` are signed, `pq_sig` is not). */
    val SUITE_MEMBERS: List<String> = listOf("alg", "pq_pk", "pq_sig")

    /** A pin entry's optional `pq_pk`: absent, or a non-empty string. */
    fun pinPqOk(pin: Any?): Boolean {
        if (!IntentJs.own(pin, "pq_pk")) return true
        val v = IntentJs.get(pin, "pq_pk")
        return v is String && v.isNotEmpty()
    }

    /**
     * The artifact's suite capability: a non-string `alg` is malformed, an `alg` this verifier does not implement is
     * `unsupported_suite`, `pq_pk` / `pq_sig` must be strings, and an ed25519 artifact carries neither.
     */
    fun artifactSuiteError(a: Map<String, Any?>): String? {
        val e = IntentJs.suiteError(a["alg"], a.containsKey("alg"))
        if (e != null) return e
        for (k in listOf("pq_pk", "pq_sig")) if (a.containsKey(k) && a[k] !is String) return "$k must be a string"
        if (IntentJs.suiteOf(a) == "ed25519" && (a.containsKey("pq_pk") || a.containsKey("pq_sig"))) return "an ed25519 artifact must not carry pq_pk / pq_sig"
        return null
    }

    /** `utf8(domain) || strictCanonical(artifact without sig and pq_sig)`. */
    fun artifactMessage(domain: String, artifact: Map<String, Any?>): ByteArray {
        val body = LinkedHashMap(artifact)
        body.remove("sig")
        body.remove("pq_sig")
        return IntentJs.message(domain, body)
    }

    /**
     * The artifact's signature under the PINNED signer (`pk`, and for a PQ / hybrid suite the pin's `pq_pk`: the artifact's
     * own `pq_pk` alone never authorises it); malformed input is a failed signature. Never throws.
     */
    fun verifyArtifactSig(domain: String, artifact: Map<String, Any?>, pinnedPk: Any?, pinnedPqPk: Any?): Boolean = try {
        if (artifact["sig"] !is String || pinnedPk !is String) false
        else IntentJs.verifyPinnedSuite(
            artifact["alg"], artifact.containsKey("alg"), pinnedPk, artifact["pq_pk"],
            artifactMessage(domain, artifact), artifact["sig"], artifact["pq_sig"], IntentJs.pin(pinnedPk, pinnedPqPk),
        )
    } catch (e: RuntimeException) {
        false
    }

    fun artifactRef(refDomain: String, slot: String, artifact: Any?): String = IntentJs.ref(refDomain, slot, artifact)

    /** Resolve `action.params.a.b` through OWN members of plain objects (segments [A-Za-z0-9_-]{1,64}, no prototype names). */
    fun resolveParamPath(params: Any?, path: Any?): Predicates.Resolved {
        if (path !is String || !path.startsWith("action.params.")) return Predicates.Resolved(false, null)
        val segs = path.substring("action.params.".length).split(".")
        var cur = params
        for (s in segs) {
            if (!isPathSegment(s) || cur !is Map<*, *> || !cur.containsKey(s)) return Predicates.Resolved(false, null)
            cur = cur[s]
        }
        return Predicates.Resolved(true, cur)
    }

    fun isParamPath(path: Any?): Boolean {
        if (path !is String || !path.startsWith("action.params.")) return false
        val segs = path.substring("action.params.".length).split(".")
        if (segs.isEmpty() || segs.size > 8) return false
        return segs.all { isPathSegment(it) }
    }

    /** Set `root.<path>` creating plain objects; false when the path collides with an existing member. */
    @Suppress("UNCHECKED_CAST")
    fun setNested(root: MutableMap<String, Any?>, path: String, value: Any?): Boolean {
        val segs = path.split(".")
        var cur = root
        for (i in 0 until segs.size - 1) {
            val k = segs[i]
            if (!cur.containsKey(k)) cur[k] = LinkedHashMap<String, Any?>()
            val next = cur[k] as? MutableMap<String, Any?> ?: return false
            cur = next
        }
        val last = segs[segs.size - 1]
        if (cur.containsKey(last)) return false
        cur[last] = value
        return true
    }

    /** A list member (read with [IntentJs.opt]); anything else, null included, is malformed and fails closed. */
    fun iterable(o: Any?): List<Any?> = o as? List<Any?> ?: throw IllegalArgumentException("not a list")

    /** `action.params` (absent = {}); a present non-object is malformed and fails closed. */
    fun actionParams(action: Any?): Any? {
        val p = IntentJs.opt(action, "params", LinkedHashMap<String, Any?>())
        if (p !is Map<*, *>) throw IllegalArgumentException("action.params is not an object")
        return p
    }
}
