package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import org.bouncycastle.math.ec.rfc8032.Ed25519

/**
 * Native Kotlin reference verifier for the CORE PCActn checks, wire format v2. Byte-matches `@atlasauth/pca`
 * (the TypeScript source of truth) and the sibling language verifiers (java-pca, go-pca, python-pca, ...).
 *
 * Normative check order: `wire, version, audience, validity, chain, plan_inclusion, leaf_signature, counter_format`, then
 * `intent` when evaluated (Intent Layer M2, see [IntentPolicy]) (a wire failure is terminal). Requires BouncyCastle (`org.bouncycastle.math.ec.rfc8032.Ed25519`), which the
 * module already depends on for the step-up client.
 *
 * This is a faithful Kotlin port of `sdks/java-pca/.../Pca.java` + the audience fail-closed semantics in
 * `packages/pca/src/pcactn.ts` (`verifyPCActnCore`).
 */
object Pca {
    const val WIRE_VERSION = 2L
    const val MAX_CHAIN_HOPS = 16
    /** Shared hard caveat caps (all PCA verifiers): per-hop cumulative list, and the sum over every hop of a chain. */
    const val MAX_CAVEATS_PER_HOP = 256
    const val MAX_CAVEATS_PER_CHAIN = 1024
    const val CAVEAT_LIMIT_REASON = "chain exceeds caveat limit (max $MAX_CAVEATS_PER_HOP per hop, $MAX_CAVEATS_PER_CHAIN per chain)"

    /** True when the chain breaks the caveat caps; reads raw list sizes only, so it runs before any hashing/signature work. */
    internal fun caveatLimitExceeded(chain: List<Any?>): Boolean {
        var total = 0L
        for (c in chain) {
            val n = ((c as? Map<*, *>)?.get("caveats") as? List<*>)?.size ?: 0
            if (n > MAX_CAVEATS_PER_HOP) return true
            total += n
            if (total > MAX_CAVEATS_PER_CHAIN) return true
        }
        return false
    }
    /** Shared raw wire-size cap of a PCActn JSON document (UTF-8 bytes), checked before any parsing. */
    const val MAX_ARTIFACT_BYTES = 524288
    const val ARTIFACT_SIZE_REASON = "artifact exceeds size limit (max $MAX_ARTIFACT_BYTES bytes)"

    /** True when the raw document exceeds [MAX_ARTIFACT_BYTES] UTF-8 bytes (O(1) for clearly small/large strings). */
    fun artifactTooLarge(text: String): Boolean {
        if (text.length > MAX_ARTIFACT_BYTES) return true
        if (text.length.toLong() * 3 <= MAX_ARTIFACT_BYTES) return false
        return Json.utf8(text).size > MAX_ARTIFACT_BYTES
    }
    const val MAX_LIFETIME_MS = 3_600_000L
    const val MAX_SKEW_MS = 60_000L
    const val MAX_AUD_LEN = 256
    const val MAX_NONCE_LEN = 128

    val SIG_DOMAIN: ByteArray = "atlas-pca/actn/v2\u0000".toByteArray(Charsets.UTF_8)
    val CAP_DOMAIN: ByteArray = "atlas-pca/cap/v1\u0000".toByteArray(Charsets.UTF_8)
    const val DEFAULT_REV = "reversible"

    /**
     * The verifier's own audience, compared to the PCActn's signed `aud` (mirrors `verifyPCActnCore`'s
     * tri-state `audience` option):
     *  - [Of]    => must equal `aud`, else the `audience` check fails;
     *  - [Any]   => deliberate opt-out ("I accept any audience"): the binding is not enforced (never fails);
     *  - [Unset] => FAIL-CLOSED when the PCActn carries a signed `aud` (a verifier that forgets its audience
     *               must not silently lose cross-instance binding); passes only when there is no `aud` at all.
     */
    sealed class Audience {
        data class Of(val id: String) : Audience()
        object Any : Audience()
        object Unset : Audience()
    }

    // ---- Intent Layer M2: envelope.intent ----
    const val INTENT_GOAL_PREFIX = "pca-intent:v1:"
    /** Goal binding v3: `pca-intent:v3:<goal_digest>:<policy_digest>` (the signed Goal IR and the policy compiled from it). */
    const val INTENT_GOAL_V3_PREFIX = "pca-intent:v3:"
    /** Domain of the root grant's salted goal commitment (envelope goal_commit). */
    const val INTENT_GOAL_COMMIT_DOMAIN = "atlas-pca/goal/v1\u0000"
    const val PPM_ONE = 1_000_000L
    const val MAX_INTENT_GOAL_SALT_LEN = 128
    /** Closed member set of `envelope.intent` (all required). */
    internal val ENVELOPE_INTENT_FIELDS = listOf("ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm")
    private const val MAX_SAFE_DOUBLE = 9007199254740991.0

    /**
     * Verifier-side intent policy (Intent Layer M2). ACTIVE iff [require] is true or either threshold is set (a threshold
     * implies require); an active policy fails closed on a PCActn without `intent`. Thresholds are nullable doubles so a
     * set-but-invalid value (negative, fractional, NaN) is representable: it is a misconfiguration and fails closed.
     */
    data class IntentPolicy(
        /** Require every PCActn to carry a bound `intent`. */
        val require: Boolean = false,
        /** Deny when the claimed `fidelity_ppm` is below this (null = unset). Setting it implies require. */
        val minFidelityPpm: Double? = null,
        /** Deny when the claimed `residual_risk_ppm` is above this (null = unset). Setting it implies require. */
        val maxResidualRiskPpm: Double? = null,
        /** Goal binding v3: the root grant must open against exactly this Goal IR + compiled policy. Setting it implies require. */
        val approvedGoal: ApprovedGoal? = null,
    ) {
        /** True iff the policy is active (the intent check runs even for a PCActn without the field). */
        val isActive: Boolean get() = require || minFidelityPpm != null || maxResidualRiskPpm != null || approvedGoal != null

        companion object {
            /**
             * From a parsed JSON object `{require?, min_fidelity_ppm?, max_residual_risk_ppm?}` ([Json] tree or plain
             * values). A non-object is null (no policy). A present threshold that is not a number (including JSON null)
             * maps to NaN: set, and invalid, so it fails closed.
             */
            fun fromJson(o: Any?): IntentPolicy? {
                if (o !is Map<*, *>) return null
                return IntentPolicy(
                    o["require"] == true, threshold(o, "min_fidelity_ppm"), threshold(o, "max_residual_risk_ppm"),
                    if (o.containsKey("approved_goal")) ApprovedGoal.fromJson(o["approved_goal"]) else null,
                )
            }

            /**
             * From raw JSON text (a policy configuration file, or a conformance vector's `intent_policy_json`), parsed
             * with the lenient RFC 8259 parser so any number spelling is kept (`950000.0` and `1e6` are the valid
             * thresholds 950000 and 1000000: validity is judged on the NUMERIC value). Non-object JSON is null; malformed
             * JSON throws (a configuration error).
             */
            fun fromJsonText(text: String): IntentPolicy? = fromJson(Json.parseLenient(text))

            private fun threshold(m: Map<*, *>, k: String): Double? {
                if (!m.containsKey(k)) return null
                return when (val v = m[k]) {
                    is Json.Num -> v.raw.toDoubleOrNull() ?: Double.NaN
                    is Number -> v.toDouble()
                    else -> Double.NaN
                }
            }
        }
    }

    /**
     * The digests a v3 goal commitment binds: canonical base64url (32 bytes) of the signed Goal IR and of the compiled policy.
     * [closed] is false when the configured object had a member other than exactly `goal_digest` and `policy_digest` (or was
     * not an object): such a policy is a misconfiguration and fails closed, as does a short, padded or empty digest.
     */
    class ApprovedGoal(val goalDigest: String?, val policyDigest: String?, val closed: Boolean = true) {
        val isWellFormed: Boolean get() = closed && decodeB64uStrict(goalDigest, 32) != null && decodeB64uStrict(policyDigest, 32) != null

        companion object {
            /** From a parsed JSON value; anything but an object of exactly the two members yields a malformed (fail-closed) ref. */
            fun fromJson(o: Any?): ApprovedGoal =
                if (o is Map<*, *>) ApprovedGoal(o["goal_digest"] as? String, o["policy_digest"] as? String, o.size == 2)
                else ApprovedGoal(null, null, false)
        }
    }

    /** The v3 goal string. Throws [IllegalArgumentException] on a malformed digest: never commit to garbage. */
    fun intentGoalV3(ref: ApprovedGoal): String {
        require(ref.isWellFormed) { "intentGoalV3: goal_digest and policy_digest must be canonical base64url (32 bytes)" }
        return INTENT_GOAL_V3_PREFIX + ref.goalDigest + ":" + ref.policyDigest
    }

    /** The v3 goal commitment for a salt (same domain and hash as [intentGoalCommit]). */
    fun intentGoalCommitV3(ref: ApprovedGoal, goalSalt: String): String =
        hashCanonical(linkedMapOf<String, Any?>("d" to INTENT_GOAL_COMMIT_DOMAIN, "goal" to intentGoalV3(ref), "salt" to goalSalt))

    /** A set policy threshold must be a safe integer >= 0 (finite, integral, not -0, <= 2^53-1). */
    internal fun okThreshold(x: Double?): Boolean {
        if (x == null) return true
        if (x.isNaN() || x.isInfinite() || x != Math.rint(x)) return false
        if (x == 0.0 && java.lang.Double.doubleToRawLongBits(x) != 0L) return false // -0
        return x >= 0 && x <= MAX_SAFE_DOUBLE
    }

    /** The goal string that binds a grant to an intent statement and Intent Map. */
    fun intentGoal(ref: String, mapDigest: String? = null): String =
        INTENT_GOAL_PREFIX + ref + (if (!mapDigest.isNullOrEmpty()) ":$mapDigest" else "")

    /** The goal commitment an `envelope.intent` claims the root grant carries. */
    fun intentGoalCommit(ref: String, mapDigest: String, goalSalt: String): String =
        hashCanonical(linkedMapOf<String, Any?>("d" to INTENT_GOAL_COMMIT_DOMAIN, "goal" to intentGoal(ref, mapDigest), "salt" to goalSalt))

    /**
     * Intent Layer v2 (rule 13 amends rule 12 step 2): the goal commitment when the PCActn carries a wire-valid
     * `intent_session`: the goal is `"pca-intent:v2:" + session + ":" + map_digest`.
     */
    fun intentGoalCommitV2(session: String, mapDigest: String, goalSalt: String): String =
        hashCanonical(linkedMapOf<String, Any?>("d" to INTENT_GOAL_COMMIT_DOMAIN, "goal" to IntentSession.intentGoalV2(session, mapDigest), "salt" to goalSalt))

    /**
     * Intent Layer v2 committed map (rule 19 amends rule 12 step 2): the goal commitment when the PCActn's
     * `intent_session.map_form` is `"commit"`: the goal is `"pca-intent:v2c:" + session + ":" + map_commit`.
     */
    fun intentGoalCommitV2c(session: String, mapCommit: String, goalSalt: String): String =
        hashCanonical(linkedMapOf<String, Any?>("d" to INTENT_GOAL_COMMIT_DOMAIN, "goal" to IntentSession.intentGoalV2c(session, mapCommit), "salt" to goalSalt))

    /** Wire validation of the `intent` slot (called when the slot is present, even as null). Null = well-formed. */
    @Suppress("UNCHECKED_CAST")
    internal fun validateIntentWire(o: Any?): String? {
        if (o !is Map<*, *>) return "'intent' must be an object"
        val v = o as Map<String, Any?>
        for (k in v.keys) if (!ENVELOPE_INTENT_FIELDS.contains(k)) return "unknown field 'intent.$k'"
        for (k in ENVELOPE_INTENT_FIELDS) if (!v.containsKey(k)) return "missing field 'intent.$k'"
        if (decodeB64uStrict(v["ref"], 32) == null) return "'intent.ref' is not canonical base64url (32 bytes)"
        if (decodeB64uStrict(v["map_digest"], 32) == null) return "'intent.map_digest' is not canonical base64url (32 bytes)"
        val salt = v["goal_salt"]
        if (salt !is String || salt.isEmpty() || utf8Len(salt) > MAX_INTENT_GOAL_SALT_LEN)
            return "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)"
        val f = v["fidelity_ppm"]
        if (!Json.isSafeInt(f) || Json.asLong(f) < 0 || Json.asLong(f) > PPM_ONE) return "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]"
        val r = v["residual_risk_ppm"]
        if (!Json.isSafeInt(r) || Json.asLong(r) < 0) return "'intent.residual_risk_ppm' must be a non-negative safe integer"
        return null
    }

    /** The root grant's goal commitment: the FIRST `envelope` caveat's string `goal_commit`, else null. */
    internal fun rootGoalCommit(grant: Map<String, Any?>?): String? {
        val cav = grant?.get("caveats") as? List<*> ?: return null
        val env = cav.firstOrNull { it is Map<*, *> && it["type"] == "envelope" } as? Map<*, *> ?: return null
        return env["goal_commit"] as? String
    }

    /**
     * The `intent` check (Intent Layer M2). [intent] is the PCActn's slot after wire validation and [present] whether the
     * PCActn carries it; [grant] the verifier's own root grant. Returns null when the check is not evaluated (no intent,
     * no active policy), "" on pass, else the failure reason. Never throws. [session] is the PCActn's wire-valid
     * `intent_session.session` (null when it carries none), which selects the v2 goal
     * `"pca-intent:v2:" + session + ":" + map_digest` (rule 13 amends rule 12 step 2), or with [mapForm] `"commit"` the v2c
     * goal `"pca-intent:v2c:" + session + ":" + map_digest` (rule 19).
     */
    internal fun decideIntent(
        intent: Any?, present: Boolean, grant: Map<String, Any?>?, policy: IntentPolicy?, session: String? = null, mapForm: Any? = null,
    ): String? {
        val active = policy != null && policy.isActive
        if (!present && !active) return null
        return try {
            if (active && (!okThreshold(policy!!.minFidelityPpm) || !okThreshold(policy.maxResidualRiskPpm)))
                return "intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)"
            val v3 = policy?.approvedGoal
            if (v3 != null && !v3.isWellFormed) // a non-null approvedGoal makes the policy active
                return "intent policy misconfigured: approved_goal digests must be canonical base64url (32 bytes) (fail closed)"
            if (!present) return "this verifier requires an intent binding but the PCActn carries none"
            val commit = rootGoalCommit(grant) ?: return "the root grant carries no envelope goal commitment to bind the intent to"
            val i = intent as Map<*, *>
            if (v3 != null) {
                if (intentGoalCommitV3(v3, i["goal_salt"] as String) != commit)
                    return "the root grant's goal commitment does not open to the approved goal and compiled policy (v3)"
            }
            val opened = if (v3 != null) commit else if (session != null) {
                if (mapForm == IntentMap.MAP_FORM_COMMIT) intentGoalCommitV2c(session, i["map_digest"] as String, i["goal_salt"] as String)
                else intentGoalCommitV2(session, i["map_digest"] as String, i["goal_salt"] as String)
            }
            else intentGoalCommit(i["ref"] as String, i["map_digest"] as String, i["goal_salt"] as String)
            if (opened != commit)
                return "intent ref / map_digest / goal_salt do not open the root grant's goal commitment"
            val fid = Json.asLong(i["fidelity_ppm"])
            val risk = Json.asLong(i["residual_risk_ppm"])
            val min = policy?.minFidelityPpm
            if (min != null && !(fid.toDouble() >= min)) return "intent fidelity $fid ppm is below the policy minimum ${min.toLong()}"
            val max = policy?.maxResidualRiskPpm
            if (max != null && !(risk.toDouble() <= max)) return "intent residual risk $risk ppm exceeds the policy maximum ${max.toLong()}"
            ""
        } catch (e: RuntimeException) {
            "intent binding error (fail closed): ${e.javaClass.simpleName}"
        }
    }

    /** `checks` holds, in normative order, wire alone (wire failure) or all eight checks (plus intent when evaluated). */
    class Verdict {
        var allow = false
        val checks = LinkedHashMap<String, Boolean>()

        /** Checks the verifier was told not to enforce (an explicit opt-out): they have no pass / fail entry in [checks]. */
        val notEnforced: MutableSet<String> = LinkedHashSet()
        var reason = ""

        /** EVERY failing check's reason (`<check>: <why>`), in check order: the ternary decision reads the full set, not the first. */
        val reasons: MutableList<String> = ArrayList()

        /** Rule 21 `legacy` model polarity was in effect: the verdict is degraded (a strict verifier must not rely on it). */
        var legacyModelPolarity = false
        internal fun fail(name: String, why: String) {
            checks[name] = false
            reasons.add("$name: $why")
            if (reason.isEmpty()) reason = "$name: $why"
        }
    }

    // ---- helpers ----
    private val B64U_ENC = Base64.getUrlEncoder().withoutPadding()
    private val B64U_DEC = Base64.getUrlDecoder()

    fun b64(b: ByteArray): String = B64U_ENC.encodeToString(b)

    /**
     * Strict base64url (RFC 4648 s5): alphabet A-Za-z0-9-_ only, no padding / whitespace, len % 4 != 1, zero
     * trailing bits (re-encode must reproduce the input). `len` >= 0 additionally pins the decoded byte length.
     * Returns null when invalid.
     */
    fun decodeB64uStrict(o: Any?, len: Int): ByteArray? {
        if (o !is String) return null
        // the alphabet, refused here though B64U_DEC would also throw on it (defence in depth)
        for (c in o) {
            val ok = (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '-' || c == '_'
            if (!ok) return null
        }
        if (o.length % 4 == 1) return null
        if (len >= 0 && o.length != (len * 4 + 2) / 3) return null
        val b: ByteArray = try {
            B64U_DEC.decode(o)
        } catch (e: IllegalArgumentException) {
            return null
        }
        if (b64(b) != o) return null // non-canonical trailing bits
        if (len >= 0 && b.size != len) return null
        return b
    }

    fun sha(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        var n = 0
        for (p in parts) n += p.size
        val out = ByteArray(n)
        var o = 0
        for (p in parts) { System.arraycopy(p, 0, out, o, p.size); o += p.size }
        return out
    }

    @Suppress("UNCHECKED_CAST")
    fun asMap(o: Any?): Map<String, Any?> = if (o is Map<*, *>) o as Map<String, Any?> else LinkedHashMap()

    @Suppress("UNCHECKED_CAST")
    fun asList(o: Any?): List<Any?> = if (o is List<*>) o as List<Any?> else ArrayList()

    fun asStr(o: Any?): String = if (o is String) o else ""

    /**
     * Canonical bytes of every protocol digest (capHash / hop body digest, Merkle leaves, params/conditions digests, the
     * signer-set hash): the STRICT form, exactly as hash.ts canonicalBytes. An out-of-profile value (nesting deeper than
     * [Json.MAX_DEPTH], a non-canonical number, a lone surrogate) throws here (fail closed) instead of hashing under the
     * lenient form that the reference never produces.
     */
    fun canonBytes(v: Any?): ByteArray = Json.canonicalizeStrict(v).toByteArray(Charsets.UTF_8)

    fun hashCanonical(v: Any?): String = b64(sha(canonBytes(v)))

    /** base64url(sha256(strictCanonical(v))). */
    fun hashStrict(v: Any?): String = b64(sha(Json.canonicalizeStrict(v).toByteArray(Charsets.UTF_8)))

    // ---- hash-suite agility (margin, not a fix: SHA-256 stays the default, an absent hash_suite reads as it) ----
    const val DEFAULT_HASH_SUITE = "sha256"

    /** Digest byte length per suite. */
    val HASH_LEN: Map<String, Int> = linkedMapOf("sha256" to 32, "sha384" to 48)

    /** True iff [s] is a known hash suite; anything else must fail closed at the caller. */
    fun isHashSuite(s: Any?): Boolean = s == "sha256" || s == "sha384"

    /** Raw-byte hash over the selected suite (the default is byte-identical to a bare SHA-256). */
    @JvmOverloads
    fun hashWithSuite(bytes: ByteArray, suite: String = DEFAULT_HASH_SUITE): ByteArray =
        MessageDigest.getInstance(if (suite == "sha384") "SHA-384" else "SHA-256").digest(bytes)

    /** base64url(H(strictCanonical(v))) under [suite]. */
    fun hashCanonical(v: Any?, suite: String): String = b64(hashWithSuite(canonBytes(v), suite))

    /** Encoded (unpadded) length of [n] bytes. */
    fun b64uLen(n: Int): Int = (n * 4 + 2) / 3

    /** True iff [s] is canonical base64url (optionally of an exact decoded byte length; negative = any). */
    @JvmOverloads
    fun isCanonicalB64u(s: Any?, len: Int = -1): Boolean = decodeB64uStrict(s, len) != null

    /** Alias of [canonBytes]: both are strict. */
    fun canonicalBytesStrict(v: Any?): ByteArray = canonBytes(v)

    /** LENIENT canonical bytes for SERVER-ONLY digests that no verifier recomputes; never for a protocol hash. */
    fun canonicalBytesLenient(v: Any?): ByteArray = Json.utf8(Json.canonicalize(v))

    /** base64url(sha256(lenient canonical)); SERVER-ONLY digests only. */
    fun hashCanonicalLenient(v: Any?): String = b64(sha(canonicalBytesLenient(v)))

    /** Strict-profile check of one number: an error text or null. */
    fun strictNumberError(v: Double): String? {
        if (v.isNaN() || v.isInfinite()) return "non-finite number"
        if (v == 0.0 && 1.0 / v < 0.0) return "negative zero"
        if (v == Math.floor(v)) return if (Math.abs(v) <= 9007199254740991.0) null else "integer outside the safe range (|n| > 2^53-1)"
        if (Math.abs(v) < 1e-6) return "non-integer magnitude below 1e-6 (needs an exponent form; not representable in the canonical decimal form)"
        val s = Json.esNumber(Math.abs(v))
        if (s.contains('e') || s.contains('E')) return "non-integer number needs an exponent form (not representable in the canonical decimal form)"
        val digits = s.replace(".", "").trimStart('0')
        if (digits.length > Json.MAX_DECIMAL_DIGITS) return "non-integer number has more than ${Json.MAX_DECIMAL_DIGITS} significant digits"
        return null
    }

    /** Every plan node commits an omitted reversibility_class as this default (same on node and action). */
    const val DEFAULT_REVERSIBILITY_CLASS = DEFAULT_REV

    /** The params digest of a call with no params: what an omitted params_digest commits as. */
    val EMPTY_PARAMS_DIGEST: String by lazy { paramsDigest(null) }

    /** The Merkle leaf (before hashing) of one plan node `{id, verb, resource, params_digest?, reversibility_class?, pre?, post?}`. */
    fun planNodeLeaf(n: Map<String, Any?>): Map<String, Any?> = planLeaf(n["id"], n, conditionsDigest(n["pre"], n["post"]))

    // ---- Merkle ----
    internal fun leafHash(leaf: Any?): ByteArray = sha(byteArrayOf(0x00), canonBytes(leaf))

    internal fun nodeHash(l: ByteArray, r: ByteArray): ByteArray = sha(byteArrayOf(0x01), l, r)

    fun merkleRoot(leaves: List<Any?>): String {
        if (leaves.isEmpty()) throw IllegalArgumentException("empty leaf set")
        val hs = ArrayList<ByteArray>()
        for (l in leaves) hs.add(leafHash(l))
        return b64(build(hs))
    }

    private fun build(hs: List<ByteArray>): ByteArray {
        if (hs.size == 1) return hs[0]
        var k = 1
        while (k * 2 < hs.size) k *= 2
        return nodeHash(build(hs.subList(0, k)), build(hs.subList(k, hs.size)))
    }

    /** Sibling sides (leaf to root) for leaf `index` of `size` leaves (RFC 6962 split). Requires 0 <= index < size. */
    internal fun pathShape(index: Long, size: Long): List<String> {
        val out = ArrayList<String>()
        var idx = index
        var n = size
        while (n > 1) {
            var k = 1L
            while (k * 2 < n) k *= 2
            if (idx < k) { out.add("R"); n = k }
            else { out.add("L"); idx -= k; n -= k }
        }
        out.reverse()
        return out
    }

    /** Never throws; malformed proofs return false. index/size are bound to the path shape. */
    fun verifyInclusion(root: String, proof: Map<String, Any?>?, leaf: Any?): Boolean {
        return try {
            if (proof == null || proof["path"] !is List<*>) return false
            if (!Json.isSafeInt(proof["index"]) || !Json.isSafeInt(proof["size"])) return false
            val index = Json.asLong(proof["index"])
            val size = Json.asLong(proof["size"])
            if (size < 1 || index < 0 || index >= size) return false
            val shape = pathShape(index, size)
            val path = asList(proof["path"])
            if (shape.size != path.size) return false
            var h = leafHash(leaf)
            for (i in path.indices) {
                if (path[i] !is Map<*, *>) return false
                val step = asMap(path[i])
                if (shape[i] != step["side"]) return false
                val sib = decodeB64uStrict(step["hash"], 32) ?: return false
                h = if (shape[i] == "L") nodeHash(sib, h) else nodeHash(h, sib)
            }
            b64(h) == root
        } catch (e: RuntimeException) {
            false
        }
    }

    fun paramsDigest(params: Any?): String =
        hashCanonical(params ?: LinkedHashMap<String, Any?>())

    @JvmName("conditionsDigest") internal fun conditionsDigest(pre: Any?, post: Any?): String {
        val m = LinkedHashMap<String, Any?>()
        m["pre"] = pre
        m["post"] = post
        return hashCanonical(m)
    }

    @JvmName("planLeaf") internal fun planLeaf(nodeId: Any?, action: Map<String, Any?>, cond: String): Map<String, Any?> {
        if (nodeId == null) throw IllegalArgumentException("missing node_id")
        val pd = action["params_digest"] ?: paramsDigest(null)
        val rc = action["reversibility_class"] ?: DEFAULT_REV
        val m = LinkedHashMap<String, Any?>()
        m["node_id"] = nodeId
        m["verb"] = action["verb"]
        m["resource"] = action["resource"]
        m["params_digest"] = pd
        m["reversibility_class"] = rc
        m["conditions"] = cond
        return m
    }

    // ---- Ed25519 (strict RFC 8032) ----
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val L: BigInteger =
        BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))

    /** y-coordinates of every small-order point: identity (1), order 2 (p-1), order 4 (0), order 8 (two values). */
    private val SMALL_ORDER_Y = arrayOf(
        BigInteger.ONE,
        P.subtract(BigInteger.ONE),
        BigInteger.ZERO,
        BigInteger("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16),
        BigInteger("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826", 16),
    )

    private fun leInt(b: ByteArray, off: Int, len: Int): BigInteger {
        val be = ByteArray(len)
        for (i in 0 until len) be[len - 1 - i] = b[off + i]
        return BigInteger(1, be)
    }

    /** True iff the 32-byte point encoding has a non-canonical y (>= p) or is one of the small-order points. */
    private fun badPointEncoding(b: ByteArray): Boolean {
        val y = leInt(b, 0, 32).clearBit(255) // sign bit ignored: both x signs share the same y
        if (y.compareTo(P) >= 0) return true
        for (s in SMALL_ORDER_Y) if (y == s) return true
        return false
    }

    /**
     * Strict Ed25519 verify: rejects non-canonical S (>= L), non-canonical y, small-order and mixed-order
     * public keys AND R (explicit small-order table + BouncyCastle full subgroup validation), then verifies.
     */
    fun ed25519Strict(pk: ByteArray?, msg: ByteArray, sig: ByteArray?): Boolean {
        return try {
            if (pk == null || sig == null || pk.size != 32 || sig.size != 64) return false
            if (badPointEncoding(pk) || badPointEncoding(sig)) return false
            if (leInt(sig, 32, 32).compareTo(L) >= 0) return false
            if (!Ed25519.validatePublicKeyFull(pk, 0)) return false
            if (!Ed25519.validatePublicKeyFull(sig, 0)) return false
            Ed25519.verify(sig, 0, pk, 0, msg, 0, msg.size)
        } catch (e: RuntimeException) {
            false
        }
    }

    fun verifyB64u(pub: String?, msg: ByteArray, sig: String?): Boolean {
        return ed25519Strict(decodeB64uStrict(pub, 32), msg, decodeB64uStrict(sig, 64))
    }

    // ---- capability chain ----
    fun capHash(c: Map<String, Any?>): String = hashCanonical(c)

    private fun bodyOf(c: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["issuer"] = c["issuer"]
        m["holder"] = c["holder"]
        m["caveats"] = c["caveats"]
        m["parent"] = c["parent"]
        if (c.containsKey("holder_pq")) m["holder_pq"] = c["holder_pq"]
        return m
    }

    /**
     * [bodyOf] + the suite fields (`alg`, `pq_pk`) bound in for a non-default suite (so a downgrade or ML-DSA
     * key-swap breaks the hop digest), byte-identical to [bodyOf] for ed25519. Mirrors `signableBody` in
     * capability.ts. Returns null for an unknown alg (FAIL-CLOSED).
     */
    private fun signableHopBody(c: Map<String, Any?>): Map<String, Any?>? {
        val suite = Pq.resolveSigAlg(c["alg"], c.containsKey("alg")) ?: return null
        val body = LinkedHashMap(bodyOf(c))
        if (suite.alg != "ed25519") {
            body["alg"] = suite.alg
            if (suite.needsPqPk && c["pq_pk"] is String) body["pq_pk"] = c["pq_pk"]
        }
        return body
    }

    private val HOLDER_PQ_DOMAIN = "atlas-pca/holder-pq/v1\u0000".toByteArray(Charsets.UTF_8)

    /** holder_pq commitment: b64u(sha256(domain || utf8(pq_pk string))). Mirrors holderPqCommitment in capability.ts. */
    fun holderPqCommitment(pqPk: String): String = b64(sha(HOLDER_PQ_DOMAIN, Json.utf8(pqPk)))

    /** F-2: a PQ-key suite (ml-dsa-65 / hybrid) is accepted only under the pq_pk the signer's holder committed to. Null when fine. */
    internal fun pqBindingError(alg: Any?, algPresent: Boolean, pqPk: Any?, committed: Any?, label: String): String? {
        val suite = Pq.resolveSigAlg(alg, algPresent)
        if (suite == null || !suite.needsPqPk) return null
        if (committed !is String)
            return "$label: suite '${suite.alg}' needs a PQ key bound to the signer, but the signer's holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)"
        if (pqPk !is String || holderPqCommitment(pqPk) != committed)
            return "$label: pq_pk does not match the signer's committed holder_pq (F-2)"
        return null
    }

    /** allowedSuites policy (absent alg == ed25519); a null list means no policy, an empty list refuses everything. */
    internal fun suitePolicyError(alg: Any?, algPresent: Boolean, label: String, allowed: List<String>?): String? {
        if (allowed == null) return null
        val a: String? = if (!algPresent) "ed25519" else alg as? String
        return if (a != null && allowed.contains(a)) null else "$label: signature suite '${if (algPresent) IntentRevocation.jsText(IntentJs.normalize(alg), true) else "ed25519"}' is not allowed by this verifier's suite policy"
    }

    /** Returns "" when OK, else an error label. Suite-agile: an unknown hop alg fails closed before any hashing. */
    private fun checkSig(c: Map<String, Any?>, signer: String, label: String, pq: PinnedPq?): String {
        val body = signableHopBody(c) ?: return "$label: ${Pq.refusal(c["alg"])}"
        val digest = try {
            hashCanonical(body)
        } catch (e: RuntimeException) {
            return "$label: malformed body"
        }
        val bd = asStr(c["body_digest"])
        val id = asStr(c["id"])
        if (digest != bd || id != bd) return "$label: body digest mismatch"
        val raw = decodeB64uStrict(bd, 32) ?: return "$label: bad signature (not signed by expected key)"
        // Suite-agile hop verification (mirrors verifyLeafSuite): ed25519 == verifyB64u(signer, msg, sig);
        // hybrid requires BOTH the Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under `pq_pk`);
        // pure ml-dsa-65 verifies `sig` under the resolved `pq` key (never the hop's own pq_pk). The signer is the expected Ed25519 key.
        val ok = Pq.verifySuite(c["alg"], c.containsKey("alg"), signer, pq, concat(CAP_DOMAIN, raw), c["sig"], c["pq_sig"])
        if (!ok) return "$label: bad signature (not signed by expected key)"
        return ""
    }

    const val PQ_PIN_CLASSICAL_REASON = "the grant issuer is pinned to a post-quantum key; a classical grant is refused"

    const val ROOT_PQ_PIN_REASON_PREFIX = "hop 0: root suite '"

    private fun rootPqPinReason(alg: String): String =
        "hop 0: root suite '$alg' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant " +
            "(policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)"

    private fun rootPqPinMismatchReason(alg: String): String =
        "hop 0: root suite '$alg': the server-side PQ pin for the root issuer (policy.pqPins) does not match the stored grant's pq_pk (fail closed)"

    /**
     * The root hop has no parent holding a holder_pq commitment, so a non-ed25519 root's PQ key must come from a verifier-side
     * authority: the verifier's stored copy of this very grant ([trustedRoot], same content hash) or a pin for root.issuer.
     * Mirrors rootPq in capability.ts. Returns the key (or null for an Ed25519 root) and, when refused, the reason.
     */
    private fun resolveRootPq(root: Map<String, Any?>, pqPins: Map<String, Any?>?, trustedRoot: Map<String, Any?>?): Pair<PinnedPq?, String?> {
        val suite = Pq.resolveSigAlg(root["alg"], root.containsKey("alg"))
        if (suite == null || !suite.needsPqPk) return Pair(null, null)
        val pk = root["pq_pk"]
        val trusted: String? = if (trustedRoot != null && pk is String) {
            try { if (capHash(trustedRoot) == capHash(root)) pk else null } catch (ex: RuntimeException) { null }
        } else null
        val issuer = root["issuer"] as? String
        // 0.4.2 fail closed: with the stored grant AND a pin for the issuer, both must agree (the grant never overrides a pin).
        if (trusted != null && pqPins != null && issuer != null && pqPins.containsKey(issuer) && pqPins[issuer] != trusted) {
            return Pair(null, rootPqPinMismatchReason(suite.alg))
        }
        val key = PinnedPq.resolve(issuer, pk, pqPins = pqPins, trustedPk = trusted)
        return if (key == null) Pair(null, rootPqPinReason(suite.alg)) else Pair(key, null)
    }

    /**
     * Returns "" when valid, else the failure reason. The 16-hop cap is enforced BEFORE any signature work. A non-ed25519
     * (pure-PQ or hybrid) ROOT is accepted only if [pqPins] maps `root.issuer` to the root's own `pq_pk`, or [trustedRoot]
     * is the root itself (the verifier's own stored grant); otherwise it is refused (R4-01).
     */
    fun verifyChain(
        chain: List<Any?>,
        expectedRootIssuer: String,
        haveIssuer: Boolean,
        allowedSuites: List<String>? = null,
        pqPins: Map<String, Any?>? = null,
        trustedRoot: Map<String, Any?>? = null,
    ): String =
        // TOTAL (R6-05): a hostile chain is a refusal, never an exception.
        try {
            verifyChainUnchecked(chain, expectedRootIssuer, haveIssuer, allowedSuites, pqPins, trustedRoot)
        } catch (ex: RuntimeException) {
            "malformed capability chain: ${ex.javaClass.simpleName}"
        }

    /** Which full-verifier check a [pcactnCheapClaims] refusal corresponds to (`audience` or `validity`) and why. */
    class CheapClaimFailure internal constructor(val check: String, val reason: String)

    /**
     * The PCActn's `aud`, `iat` and `exp`, checked BEFORE any signature verification or metering. These fields are unauthenticated here, so
     * a pass proves nothing; but a FAIL is final: the full verifier makes exactly the same `audience` and `validity` decisions on the same
     * fields, so a document refused here could never be admitted. O(1). Null when both checks pass. [audience] is this verifier's audience
     * id; [now] is epoch ms.
     */
    fun pcactnCheapClaims(p: Map<String, Any?>, audience: String, now: Double): CheapClaimFailure? {
        val aud = p["aud"]
        if (aud !is String || aud.isEmpty() || aud != audience) return CheapClaimFailure("audience", "aud does not match this resource server / instance")
        if (!Json.isSafeInt(p["iat"]) || !Json.isSafeInt(p["exp"])) return CheapClaimFailure("validity", "iat and exp must be safe-integer epoch ms")
        if (now.isNaN() || now != Math.rint(now) || Math.abs(now) > 9007199254740991.0) return CheapClaimFailure("validity", "the verifier clock is not a safe integer epoch-ms")
        val iat = Json.asLong(p["iat"])
        val exp = Json.asLong(p["exp"])
        val nowL = now.toLong()
        return when {
            !(exp > iat) -> CheapClaimFailure("validity", "exp must be greater than iat")
            exp - iat > MAX_LIFETIME_MS -> CheapClaimFailure("validity", "lifetime exceeds $MAX_LIFETIME_MS ms")
            iat > nowL + MAX_SKEW_MS -> CheapClaimFailure("validity", "iat is in the future (clock skew)")
            nowL > exp -> CheapClaimFailure("validity", "the PCActn has expired")
            else -> null
        }
    }

    /** The outcome of [verifyChainCheap]: `ok` with the number of hops that still need post-quantum verification, else why not. */
    class CheapChain internal constructor(val ok: Boolean, val pqHops: Int = 0, val reason: String? = null)

    /**
     * A necessary-condition pre-authentication chain check: shape, caps, depth, suite allowlist, body digest, parent links, issuer chaining
     * and the Ed25519 half of each hop, in at most [MAX_CHAIN_HOPS] Ed25519 verifications whatever suites the chain names. A pure
     * post-quantum hop passes on structure alone and is only decided by the full [verifyChain]. `ok` is NEVER an authentication: the
     * caller must still run the full verifier (after matching the root to a stored grant) before treating the chain as authentic.
     */
    @JvmOverloads
    fun verifyChainCheap(chain: List<Any?>?, expectedRootIssuer: String? = null, allowedSuites: List<String>? = null): CheapChain = try {
        cheapChain(chain, expectedRootIssuer, allowedSuites)
    } catch (ex: RuntimeException) {
        CheapChain(false, 0, "malformed capability chain: ${ex.message ?: "unverifiable"}")
    }

    private fun cheapChain(chain: List<Any?>?, expectedRootIssuer: String?, allowedSuites: List<String>?): CheapChain {
        fun no(r: String) = CheapChain(false, 0, r)
        val arr: List<Any?> = chain ?: emptyList()
        if (arr.isEmpty()) return no("empty chain")
        if (arr.size > MAX_CHAIN_HOPS) return no("chain too long (max $MAX_CHAIN_HOPS hops)")
        if (caveatLimitExceeded(arr)) return no(CAVEAT_LIMIT_REASON)
        var pqHops = 0
        for (i in arr.indices) {
            val label = "hop $i"
            val raw = arr[i]
            if (!wellTyped(raw)) return no("$label: malformed capability")
            val c = asMap(raw)
            val suite = Pq.resolveSigAlg(c["alg"], c.containsKey("alg")) ?: return no("$label: ${Pq.refusal(c["alg"])}")
            suitePolicyError(c["alg"], c.containsKey("alg"), label, allowedSuites)?.let { return no(it) }
            if (i == 0) {
                if (c.containsKey("parent")) return no("hop 0: root must not have a parent")
                if (expectedRootIssuer != null && c["issuer"] != expectedRootIssuer) return no("hop 0: root issuer is not the expected principal")
            } else {
                val parent = asMap(arr[i - 1])
                if (c["parent"] != capHash(parent)) return no("$label: broken parent link")
                if (c["issuer"] != parent["holder"]) return no("$label: issuer is not the parent's bound holder")
            }
            val digest = try {
                hashCanonical(signableHopBody(c) ?: return no("$label: ${Pq.refusal(c["alg"])}"))
            } catch (ex: RuntimeException) {
                return no("$label: malformed body")
            }
            if (digest != c["body_digest"] || c["id"] != c["body_digest"]) return no("$label: body digest mismatch")
            if (suite.hasEd25519) {
                val signer = if (i == 0) asStr(c["issuer"]) else asStr(asMap(arr[i - 1])["holder"])
                val raw32 = decodeB64uStrict(digest, 32) ?: return no("$label: bad signature (not signed by expected key)")
                if (!verifyB64u(signer, concat(CAP_DOMAIN, raw32), c["sig"] as? String)) return no("$label: bad signature (not signed by expected key)")
            }
            if (suite.needsPqPk) pqHops++
        }
        return CheapChain(true, pqHops, null)
    }

    /**
     * The post-quantum verification key for a signature by [holder] (a chain leaf or threshold share) under suite [alg], minted by the
     * single choke point from the holder's `holder_pq` commitment. Null for ed25519, and also null (so the signature check fails
     * closed) when the artifact's `pq_pk` is not the committed key.
     */
    fun holderPqKey(alg: Any?, holder: String, artifactPqPk: Any?, holderPq: String?): String? {
        val suite = Pq.resolveSigAlg(alg, alg != null) ?: return null
        if (!suite.needsPqPk) return null
        return PinnedPq.resolve(holder, artifactPqPk, holderPq = holderPq)?.key
    }

    /**
     * Mirrors `wellTyped` in capability.ts: id/issuer/holder/body_digest/sig are strings; alg/pq_pk/pq_sig/holder_pq/parent are
     * absent or strings (JSON null is NOT absent); caveats is a list of objects each with a string `type`.
     */
    internal fun wellTyped(o: Any?): Boolean {
        if (o !is Map<*, *>) return false
        for (k in listOf("id", "issuer", "holder", "body_digest", "sig")) if (o[k] !is String) return false
        for (k in listOf("alg", "pq_pk", "pq_sig", "holder_pq", "parent")) if (o.containsKey(k) && o[k] !is String) return false
        val cv = o["caveats"] as? List<*> ?: return false
        return cv.all { it is Map<*, *> && it["type"] is String }
    }

    private fun verifyChainUnchecked(
        chain: List<Any?>,
        expectedRootIssuer: String,
        haveIssuer: Boolean,
        allowedSuites: List<String>?,
        pqPins: Map<String, Any?>?,
        trustedRoot: Map<String, Any?>?,
    ): String {
        if (chain.isEmpty()) return "empty chain"
        if (chain.size > MAX_CHAIN_HOPS) return "chain too long (max $MAX_CHAIN_HOPS hops)"
        if (caveatLimitExceeded(chain)) return CAVEAT_LIMIT_REASON
        for (i in chain.indices)
            if (!wellTyped(chain[i])) return "hop $i: malformed capability"
        val root = asMap(chain[0])
        if (root.containsKey("parent")) return "hop 0: root must not have a parent"
        if (haveIssuer && root["issuer"] != expectedRootIssuer)
            return "hop 0: root issuer is not the expected principal"
        suitePolicyError(root["alg"], root.containsKey("alg"), "hop 0", allowedSuites)?.let { return it }
        val (rootPq, rootErr) = resolveRootPq(root, pqPins, trustedRoot)
        if (rootErr != null) return rootErr
        var e = checkSig(root, asStr(root["issuer"]), "hop 0", rootPq)
        if (e.isNotEmpty()) return e
        for (i in 1 until chain.size) {
            val label = "hop $i"
            val parent = asMap(chain[i - 1])
            val c = asMap(chain[i])
            val ph = try {
                capHash(parent)
            } catch (ex: RuntimeException) {
                return "$label: broken parent link"
            }
            if (c["parent"] != ph) return "$label: broken parent link"
            if (c["issuer"] != parent["holder"]) return "$label: issuer is not the parent's bound holder"
            suitePolicyError(c["alg"], c.containsKey("alg"), label, allowedSuites)?.let { return it }
            pqBindingError(c["alg"], c.containsKey("alg"), c["pq_pk"], parent["holder_pq"], label)?.let { return it }
            e = checkSig(c, asStr(parent["holder"]), label, PinnedPq.resolve(parent["holder"] as? String, c["pq_pk"], holderPq = parent["holder_pq"]))
            if (e.isNotEmpty()) return e
            val pc = asList(parent["caveats"])
            val cc = asList(c["caveats"])
            if (cc.size < pc.size) return "$label: drops parent caveat(s)"
            for (j in pc.indices) {
                val same = try {
                    hashCanonical(cc[j]) == hashCanonical(pc[j])
                } catch (ex: RuntimeException) {
                    false
                }
                if (!same) return "$label: caveat $j altered or reordered"
            }
        }
        // the leaf holds the full append-only list
        return allocationsMonotone(asMap(chain[chain.size - 1])["caveats"])
    }

    /** capability.ts allocationsMonotone: every `budget_alloc.limit` finite, >= 0 and never above the previous one. The failure reason, or "". */
    internal fun allocationsMonotone(list: Any?): String {
        if (list !is List<*>) return "malformed caveats"
        val caveats: List<Any?> = list
        var prev = Double.POSITIVE_INFINITY
        for ((i, cv) in caveats.withIndex()) {
            val c = asMap(cv)
            if (c["type"] != "budget_alloc") continue
            val lim = IntentJs.num(c["limit"]) ?: Double.NaN
            if (lim.isNaN() || lim.isInfinite() || lim < 0) return "budget_alloc caveat $i: limit must be a finite number >= 0"
            if (lim > prev) return "budget_alloc caveat $i: allocation ${AttestUtil.jsNumString(lim)} widens the parent's carried allocation ${AttestUtil.jsNumString(prev)} (monotone: a child can only allocate <= its parent)"
            prev = lim
        }
        return ""
    }

    // ---- wire format v2 ----
    private val REQUIRED = listOf(
        "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness",
        "counter", "risk_claim", "aud", "iat", "exp", "sig",
    )
    private val OPTIONAL = listOf(
        "nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding",
        "threshold", "zk_compliance", "bond_ref",
        // Intent Layer M2 (additive, SIGNED): the `envelope.intent` binding (see validateIntentWire / decideIntent).
        "intent",
        // Intent Layer v2 (additive, SIGNED): the session member (rule 13; see IntentSession.validateWire / IntentV2).
        "intent_session",
        // Consistency token (additive, SIGNED): the `fresh_at` member (see FreshAt.validateWire / FreshAt.decide).
        "fresh_at",
        // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
        "alg", "pq_pk", "pq_sig",
    )

    /** The closed set of required top-level PCActn v2 members. */
    val REQUIRED_FIELDS: List<String> get() = REQUIRED

    /** The optional top-level PCActn v2 members (most signed; `threshold` and `pq_sig` are the unsigned containers). */
    val OPTIONAL_FIELDS: List<String> get() = OPTIONAL

    /** The `type` of a carried budget-allocation caveat. */
    const val BUDGET_ALLOC_CAVEAT = "budget_alloc"

    /** A signed carried-allocation caveat `{type: "budget_alloc", limit}` for a delegation hop (a finite `limit` >= 0 verifies). */
    fun budgetAllocCaveat(limit: Double): MutableMap<String, Any?> =
        linkedMapOf("type" to BUDGET_ALLOC_CAVEAT, "limit" to StoreJs.num(limit))

    /** A well-formed `budget_alloc` caveat: a finite `limit` >= 0. */
    fun isBudgetAllocCaveat(cv: Any?): Boolean {
        if (cv !is Map<*, *> || cv["type"] != "budget_alloc") return false
        val lim = IntentJs.num(cv["limit"]) ?: return false
        return !lim.isNaN() && !lim.isInfinite() && lim >= 0
    }

    /** Milliseconds per freshness epoch when a gate names none. */
    const val DEFAULT_FRESHNESS_EPOCH_MS = 60_000L

    /** How long a replay store must remember a consumed PCActn key: the longest lifetime plus skew on both sides. */
    const val REPLAY_MIN_RETENTION_MS = MAX_LIFETIME_MS + 2 * MAX_SKEW_MS

    /** Length unit for aud / nonce limits is UTF-8 BYTES. */
    private fun utf8Len(s: String): Int = Json.utf8(s).size

    /**
     * Closed capability-hop key set (parent optional). The B4 crypto-agility fields (alg/pq_pk/pq_sig) are
     * additive on a hop exactly as at the top level: absent alg == ed25519 (pq_pk/pq_sig forbidden, byte-identical).
     */
    private val CAP_KEYS = listOf("id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig", "holder_pq")

    private fun isObj(o: Any?): Boolean = o is Map<*, *>
    private fun isStr(o: Any?): Boolean = o is String

    private fun closedKeys(m: Map<String, Any?>, where: String, vararg allowed: String): String? {
        val ok = allowed.toList()
        for (k in m.keys) if (!ok.contains(k)) return "unknown field '$where.$k'"
        return null
    }

    /** Wire v2 structural + lexical validation. Returns null when well-formed, else a short reason. Never throws. */
    @Suppress("UNCHECKED_CAST")
    fun validateWireV2(po: Any?): String? {
        return try {
            if (!isObj(po)) return "PCActn is not an object"
            val p = po as Map<String, Any?>
            for (k in p.keys) if (!REQUIRED.contains(k) && !OPTIONAL.contains(k)) return "unknown field '$k'"
            for (k in REQUIRED) if (!p.containsKey(k)) return "missing field '$k'"
            // every signed byte must admit the strict canonical encoding (sig/threshold/pq_sig are unsigned)
            val body = LinkedHashMap(p)
            body.remove("sig")
            body.remove("threshold")
            body.remove("pq_sig")
            try {
                Json.canonicalizeStrict(body)
            } catch (e: RuntimeException) {
                return e.message
            }

            if (!Json.isSafeInt(p["ver"])) return "'ver' must be a safe integer"
            if (!Json.isSafeInt(p["counter"])) return "'counter' must be a safe integer"
            if (!Json.isSafeInt(p["iat"])) return "'iat' must be a safe integer"
            if (!Json.isSafeInt(p["exp"])) return "'exp' must be a safe integer"
            val aud = p["aud"]
            if (!isStr(aud) || (aud as String).isEmpty() || utf8Len(aud) > MAX_AUD_LEN) return "'aud' must be a non-empty string (<= 256 UTF-8 bytes)"
            if (p.containsKey("nonce")) {
                val n = p["nonce"]
                if (!isStr(n) || (n as String).isEmpty() || utf8Len(n) > MAX_NONCE_LEN) return "'nonce' must be a non-empty string"
            }
            // B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. With no `alg` this asserts exactly
            // the classical 64-byte `sig` and that `pq_pk`/`pq_sig` are absent. Unknown `alg` fails closed.
            val sigWire = Pq.validateSignatureWire(p)
            if (sigWire != null) return sigWire
            if (decodeB64uStrict(p["grant_ref"], 32) == null) return "'grant_ref' is not canonical base64url (32 bytes)"

            if (!isObj(p["action"])) return "'action' must be an object"
            val a = p["action"] as Map<String, Any?>
            var e = closedKeys(a, "action", "verb", "resource", "params_digest", "reversibility_class")
            if (e != null) return e
            if (!isStr(a["verb"]) || !isStr(a["resource"]) || !isStr(a["reversibility_class"]))
                return "action.verb/resource/reversibility_class must be strings"
            if (decodeB64uStrict(a["params_digest"], 32) == null) return "'action.params_digest' is not canonical base64url (32 bytes)"

            if (!isObj(p["plan"])) return "'plan' must be an object"
            val pl = p["plan"] as Map<String, Any?>
            e = closedKeys(pl, "plan", "root", "inclusion_proof", "node_id", "conditions_digest")
            if (e != null) return e
            if (decodeB64uStrict(pl["root"], 32) == null) return "'plan.root' is not canonical base64url (32 bytes)"
            if (!isStr(pl["node_id"])) return "'plan.node_id' must be a string"
            if (pl.containsKey("conditions_digest") && decodeB64uStrict(pl["conditions_digest"], 32) == null)
                return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)"
            if (!isObj(pl["inclusion_proof"])) return "'plan.inclusion_proof' must be an object"
            val ip = pl["inclusion_proof"] as Map<String, Any?>
            e = closedKeys(ip, "plan.inclusion_proof", "index", "size", "path")
            if (e != null) return e
            if (!Json.isSafeInt(ip["index"])) return "'plan.inclusion_proof.index' must be a safe integer"
            if (!Json.isSafeInt(ip["size"])) return "'plan.inclusion_proof.size' must be a safe integer"
            if (ip["path"] !is List<*>) return "'plan.inclusion_proof.path' must be an array"
            val path = ip["path"] as List<Any?>
            for (i in path.indices) {
                if (!isObj(path[i])) return "proof step $i must be an object"
                val st = path[i] as Map<String, Any?>
                for (k in st.keys) if (k != "side" && k != "hash") return "unknown field 'path[$i].$k'"
                if ("L" != st["side"] && "R" != st["side"]) return "proof step $i: side must be 'L' or 'R'"
                if (decodeB64uStrict(st["hash"], 32) == null) return "proof step $i: hash is not canonical base64url (32 bytes)"
            }

            if (p["cap_chain"] !is List<*>) return "'cap_chain' must be an array"
            val chain = p["cap_chain"] as List<Any?>
            for (i in chain.indices) {
                if (!isObj(chain[i])) return "cap_chain[$i] must be an object"
                val c = chain[i] as Map<String, Any?>
                for (k in c.keys)
                    if (!CAP_KEYS.contains(k)) return "unknown field 'cap_chain[$i].$k'"
                for (k in arrayOf("id", "issuer", "holder", "body_digest"))
                    if (decodeB64uStrict(c[k], 32) == null) return "cap_chain[$i].$k is not canonical base64url (32 bytes)"
                // B4 crypto-agility: validate the hop's alg/sig/pq_pk/pq_sig per suite, exactly as the leaf.
                // Absent alg asserts a 64-byte sig and that pq_pk/pq_sig are absent (byte-identical pre-B4 hop).
                val hopSigWire = Pq.validateSignatureWire(c)
                if (hopSigWire != null) return "cap_chain[$i]: $hopSigWire"
                if (c.containsKey("parent") && decodeB64uStrict(c["parent"], 32) == null)
                    return "cap_chain[$i].parent is not canonical base64url (32 bytes)"
                if (c.containsKey("holder_pq") && decodeB64uStrict(c["holder_pq"], 32) == null)
                    return "cap_chain[$i].holder_pq is not canonical base64url (32 bytes)"
                if (c["caveats"] !is List<*>) return "cap_chain[$i].caveats must be an array of {type,...} objects"
                for (cv in c["caveats"] as List<Any?>)
                    if (!isObj(cv) || !isStr((cv as Map<String, Any?>)["type"]))
                        return "cap_chain[$i].caveats must be an array of {type,...} objects"
            }

            if (!isObj(p["attestation"])) return "'attestation' must be an object with an integer 'epoch'"
            val at = p["attestation"] as Map<String, Any?>
            if (!Json.isSafeInt(at["epoch"])) return "'attestation' must be an object with an integer 'epoch'"
            if (!isStr(at["quote_digest"]) || !isStr(at["model_id"]) || !isStr(at["measurement"]) || !isStr(at["operator"]))
                return "attestation string fields must be strings"
            if (!isObj(p["provenance"])) return "'provenance' is malformed"
            val pv = p["provenance"] as Map<String, Any?>
            if (!isStr(pv["causal_hash"]) || !Json.isStrictNumber(pv["taint_level"]) || pv["trusted_refs"] !is List<*>)
                return "'provenance' is malformed"
            for (r in pv["trusted_refs"] as List<Any?>) if (!isStr(r)) return "'provenance' is malformed"
            if (!isObj(p["freshness"])) return "'freshness' is malformed"
            val fr = p["freshness"] as Map<String, Any?>
            if (!Json.isSafeInt(fr["epoch"]) || !isStr(fr["beacon_ref"]) || !isStr(fr["accumulator_witness"])) return "'freshness' is malformed"
            if (!isObj(p["risk_claim"])) return "'risk_claim' is malformed"
            val rc = p["risk_claim"] as Map<String, Any?>
            if (!Json.isStrictNumber(rc["r"]) || !isObj(rc["inputs"])) return "'risk_claim' is malformed"

            if (p.containsKey("caution")) {
                val c = p["caution"]
                if (!Json.isStrictNumber(c)) return "'caution' must be a number in [0,1]"
                val d = Json.asDecimal(c)
                if (d.signum() < 0 || d.compareTo(java.math.BigDecimal.ONE) > 0) return "'caution' must be a number in [0,1]"
            }
            if (p.containsKey("rationale_commitment") && decodeB64uStrict(p["rationale_commitment"], 32) == null)
                return "'rationale_commitment' is not canonical base64url (32 bytes)"
            if (p.containsKey("tool_binding") && decodeB64uStrict(p["tool_binding"], 32) == null)
                return "'tool_binding' is not canonical base64url (32 bytes)"
            if (p.containsKey("progress_step") && !isObj(p["progress_step"])) return "'progress_step' must be an object"
            if (p.containsKey("intent")) validateIntentWire(p["intent"])?.let { return it }
            if (p.containsKey("intent_session")) IntentSession.validateWire(p["intent_session"])?.let { return it }
            if (p.containsKey("fresh_at")) FreshAt.validateWire(p["fresh_at"])?.let { return it }
            if (p.containsKey("prohibition_evidence") && !isObj(p["prohibition_evidence"]) && p["prohibition_evidence"] !is List<*>)
                return "'prohibition_evidence' must be an object or array"
            if (p.containsKey("threshold")) {
                if (!isObj(p["threshold"]) || (p["threshold"] as Map<String, Any?>)["shares"] !is List<*>)
                    return "'threshold' must be {shares:[...]}"
                val shares = (p["threshold"] as Map<String, Any?>)["shares"] as List<Any?>
                for (i in shares.indices) {
                    if (!isObj(shares[i]) || !isStr((shares[i] as Map<String, Any?>)["role"])) return "threshold.shares[$i] is malformed"
                    val sh = shares[i] as Map<String, Any?>
                    if (decodeB64uStrict(sh["publicKey"], 32) == null) return "threshold.shares[$i].publicKey is not canonical base64url (32 bytes)"
                    // 0.4.1: the share signature is validated PER SUITE (alg absent == ed25519: 64-byte sig, no pq_sig).
                    val shareErr = Pq.validateShareSignatureWire(sh)
                    if (shareErr != null) return "threshold.shares[$i]: $shareErr"
                }
            }
            null
        } catch (e: RuntimeException) {
            "malformed: $e"
        }
    }

    // ---- PCActn ----
    /** Signed message: "atlas-pca/actn/v2\0" || sha256(strictCanonical(body without sig/threshold/pq_sig)). */
    fun thresholdMessage(p: Map<String, Any?>): ByteArray {
        val body = LinkedHashMap<String, Any?>()
        // `sig`, `threshold` and the B4 `pq_sig` are unsigned (stripped); `alg`/`pq_pk` ARE signed.
        for ((k, v) in p) if (k != "sig" && k != "threshold" && k != "pq_sig") body[k] = v
        return concat(SIG_DOMAIN, sha(Json.canonicalizeStrict(body).toByteArray(Charsets.UTF_8)))
    }

    /** Verify raw PCActn JSON text: strict-profile parse first (any failure, or a non-object, is a wire failure). */
    fun verifyPcactnJson(
        text: String, grant: Map<String, Any?>, now: Long, audience: Audience, allowedSuites: List<String>? = null,
        intentPolicy: IntentPolicy? = null, intentV2: IntentV2.Context? = null, freshAt: FreshAt.Policy? = null,
        authorizedPlanRoots: List<String>? = null, insecureSkipPlanRootCheck: Boolean = false, pqPins: Map<String, Any?>? = null,
        attestationHook: PcaCore.Hook? = null, zkHook: PcaCore.Hook? = null,
    ): Verdict {
        if (artifactTooLarge(text)) { // FIRST: before any parsing
            val big = Verdict()
            big.fail("wire", ARTIFACT_SIZE_REASON)
            return big
        }
        val parsed: Any?
        try {
            parsed = Json.parse(text)
        } catch (e: RuntimeException) {
            val v = Verdict()
            v.fail("wire", "strict JSON: ${e.message}")
            return v
        }
        return verifyPcactn(parsed, grant, now, audience, allowedSuites, intentPolicy, intentV2, freshAt, authorizedPlanRoots, insecureSkipPlanRootCheck, pqPins, attestationHook, zkHook)
    }

    /**
     * Verify a parsed PCActn (Json.parse / parseLenient tree). Check order: wire (terminal), version, audience,
     * validity, chain, grant_ref_bound, plan_inclusion, leaf_signature, counter_format, then `intent` iff the PCActn carries
     * `intent` or [intentPolicy] is active (Intent Layer M2; absent both, the verdict is the pre-M2 one), then the Intent
     * Layer v2 checks `schema`, `intent_session`, `layers`, `accumulators`, `facts`, `provenance`, `classes` exactly when
     * [IntentV2] reports them under [intentV2] (null = none: a PCActn without `intent_session` verifies exactly as before), then
     * `fresh_at` (the consistency token; see [FreshAt.decide]) iff the PCActn carries the member, [freshAt] reads a side-carried token or
     * requires one. allow = every check true.
     *
     * [attestationHook] and [zkHook] are the reference's `hooks.attestation` and `hooks.zk`: an enforced attestation result passes or fails the
     * `attestation` check (not enforced leaves it unreported); [zkHook] runs only for a PCActn that CARRIES `zk_compliance`, whose proof no hook
     * enforced (none given, or one reporting not enforced) is refused: an unverified proof is never accepted. A hook that throws is a `malformed` failure.
     */
    fun verifyPcactn(
        pcactn: Any?, grant: Map<String, Any?>, now: Long, audience: Audience, allowedSuites: List<String>? = null,
        intentPolicy: IntentPolicy? = null, intentV2: IntentV2.Context? = null, freshAt: FreshAt.Policy? = null,
        authorizedPlanRoots: List<String>? = null, insecureSkipPlanRootCheck: Boolean = false, pqPins: Map<String, Any?>? = null,
        attestationHook: PcaCore.Hook? = null, zkHook: PcaCore.Hook? = null,
    ): Verdict =
        // TOTAL (R6-05): any residual fault on hostile input is a terminal wire refusal, never an exception.
        try {
            verifyPcactnUnchecked(pcactn, grant, now, audience, allowedSuites, intentPolicy, intentV2, freshAt, authorizedPlanRoots, insecureSkipPlanRootCheck, pqPins, attestationHook, zkHook)
        } catch (ex: RuntimeException) {
            Verdict().also { it.fail("wire", "malformed input (${ex.javaClass.simpleName})") }
        }

    private fun verifyPcactnUnchecked(
        pcactn: Any?, grant: Map<String, Any?>, now: Long, audience: Audience, allowedSuites: List<String>?,
        intentPolicy: IntentPolicy?, intentV2: IntentV2.Context?, freshAt: FreshAt.Policy?,
        authorizedPlanRoots: List<String>?, insecureSkipPlanRootCheck: Boolean, pqPins: Map<String, Any?>?,
        attestationHook: PcaCore.Hook?, zkHook: PcaCore.Hook?,
    ): Verdict {
        val v = Verdict()
        val wire = validateWireV2(pcactn)
        if (wire != null) {
            v.fail("wire", wire)
            return v
        }
        val p = asMap(pcactn)
        v.checks["wire"] = true
        val intentPresent = p.containsKey("intent")
        val intentReported = intentPresent || (intentPolicy != null && intentPolicy.isActive)
        var faulted = false
        try {
            // version
            if (Json.asLong(p["ver"]) == WIRE_VERSION) v.checks["version"] = true
            else v.fail("version", "unsupported ver (this verifier requires $WIRE_VERSION)")

            // audience (fail-closed: a signed aud with no supplied audience is a failure, not a pass)
            val hasAud = p["aud"] is String && (p["aud"] as String).isNotEmpty()
            when (audience) {
                is Audience.Any -> v.checks["audience"] = true // opt-out: binding not enforced
                is Audience.Unset -> if (hasAud) v.fail("audience", "PCActn carries a signed aud but this verifier supplied no audience") else v.checks["audience"] = true
                is Audience.Of -> if (audience.id == p["aud"]) v.checks["audience"] = true else v.fail("audience", "aud does not match this resource server / instance")
            }

            // validity
            val iat = Json.asLong(p["iat"])
            val exp = Json.asLong(p["exp"])
            if (!(exp > iat)) v.fail("validity", "exp must be greater than iat")
            else if (exp - iat > MAX_LIFETIME_MS) v.fail("validity", "lifetime exceeds $MAX_LIFETIME_MS ms")
            else if (iat > now + MAX_SKEW_MS) v.fail("validity", "iat is in the future (clock skew)")
            else if (now > exp) v.fail("validity", "the PCActn has expired")
            else v.checks["validity"] = true

            // chain (<= 16 hops, checked before any signature work; root == grant)
            val chain = asList(p["cap_chain"])
            val why: String = when {
                chain.isEmpty() -> "empty chain"
                chain.size > MAX_CHAIN_HOPS -> "chain too long (max $MAX_CHAIN_HOPS hops)"
                caveatLimitExceeded(chain) -> CAVEAT_LIMIT_REASON
                capHash(asMap(chain[0])) != capHash(grant) -> "chain root is not the grant"
                else -> verifyChain(chain, asStr(grant["issuer"]), grant["issuer"] is String, allowedSuites, pqPins, grant) // chain[0] == grant was checked above
            }
            if (why.isEmpty()) v.checks["chain"] = true else v.fail("chain", why)
            // a PIN for the root issuer says its grants are post-quantum protected: a classical root naming it is refused (checked here, not in the chain kernel)
            val rootCap = chain.firstOrNull() as? Map<*, *>
            val rootIssuer = rootCap?.get("issuer")
            if (pqPins != null && rootCap != null && rootIssuer is String && pqPins.containsKey(rootIssuer) && (!rootCap.containsKey("alg") || rootCap["alg"] == "ed25519"))
                v.fail("pq_pin", PQ_PIN_CLASSICAL_REASON)

            // grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the
            // ROOT capability of the presented chain (cap_chain[0].id). Independent of the chain verdict; fail-closed
            // on an empty / malformed chain. Replay state is keyed on grant_ref, so it must not be attacker-chosen.
            val gref = p["grant_ref"]
            val rootId = (chain.firstOrNull() as? Map<*, *>)?.get("id")
            if (gref is String && gref.isNotEmpty() && rootId is String && gref == rootId) v.checks["grant_ref_bound"] = true
            else v.fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain")

            // plan inclusion (leaf recomputed from the action itself)
            val plan = asMap(p["plan"])
            val action = asMap(p["action"])
            val cond = if (plan["conditions_digest"] is String) plan["conditions_digest"] as String else conditionsDigest(null, null)
            val incl = try {
                verifyInclusion(asStr(plan["root"]), asMap(plan["inclusion_proof"]), planLeaf(plan["node_id"], action, cond))
            } catch (e: RuntimeException) {
                false
            }
            if (incl) v.checks["plan_inclusion"] = true
            else v.fail("plan_inclusion", "action is not a node of the committed plan")

            // plan_root_authorized: the root must be one the principal authorized. A list given (even empty) is enforced and wins over the
            // opt-out; none and no explicit insecureSkipPlanRootCheck fails; the opt-out reports not-enforced.
            if (authorizedPlanRoots == null) {
                if (insecureSkipPlanRootCheck) v.notEnforced.add("plan_root_authorized")
                else v.fail("plan_root_authorized", "no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)")
            } else if (plan["root"] is String && authorizedPlanRoots.contains(plan["root"] as String)) v.checks["plan_root_authorized"] = true
            else v.fail("plan_root_authorized", "the plan root has not been authorized by the principal")

            // leaf signature — routed through the B4 suite seam (ed25519 / ml-dsa-65 / hybrid). For the default
            // (no `alg`) this is byte-identical to the classical strict-Ed25519 path under the leaf holder.
            var sigOk = false
            if (chain.isNotEmpty()) {
                val leafCap = asMap(chain[chain.size - 1])
                val holder = asStr(leafCap["holder"])
                val lerr = suitePolicyError(p["alg"], p.containsKey("alg"), "leaf", allowedSuites)
                    ?: pqBindingError(p["alg"], p.containsKey("alg"), p["pq_pk"], leafCap["holder_pq"], "leaf")
                if (lerr == null) sigOk = Pq.verifySuite(
                    p["alg"], p.containsKey("alg"), holder,
                    PinnedPq.resolve(leafCap["holder"] as? String, p["pq_pk"], holderPq = leafCap["holder_pq"]),
                    thresholdMessage(p), p["sig"], p["pq_sig"],
                )
            }
            if (sigOk) v.checks["leaf_signature"] = true
            else v.fail("leaf_signature", "signature does not verify under the leaf holder key")

            // counter
            if (Json.isSafeInt(p["counter"]) && Json.asLong(p["counter"]) >= 0) v.checks["counter_format"] = true
            else v.fail("counter_format", "missing or not a non-negative safe integer")

            // Intent Layer M2: `intent` (reported iff the PCActn carries intent or the policy is active)
            val session = if (p.containsKey("intent_session")) asMap(p["intent_session"])["session"] else null
            val mapForm = if (p.containsKey("intent_session")) asMap(p["intent_session"])["map_form"] else null
            val intentWhy = decideIntent(p["intent"], intentPresent, grant, intentPolicy, session as? String, mapForm)
            if (intentWhy != null) {
                if (intentWhy.isEmpty()) v.checks["intent"] = true else v.fail("intent", intentWhy)
            }
        } catch (e: RuntimeException) {
            faulted = true
            if (v.reason.isEmpty()) { v.reason = "malformed PCActn: $e"; v.reasons.add(v.reason) }
        }
        // any check not reached (internal error) is a failure; keep normative key order
        val ordered = LinkedHashMap<String, Boolean>()
        for (k in arrayOf("wire", "version", "audience", "validity", "chain", "pq_pin", "grant_ref_bound", "plan_inclusion", "plan_root_authorized", "leaf_signature", "counter_format")) {
            if (k == "pq_pin" && k !in v.checks) continue // reported only when it fails
            if (k == "plan_root_authorized" && k in v.notEnforced) continue // the explicit opt-out reports not-enforced and is no check row
            ordered[k] = v.checks[k] == true
        }
        if (intentReported) ordered["intent"] = v.checks["intent"] == true
        // a fault after every core check passed still denies (TS CoreMalformed: checks.malformed = fail)
        if (faulted) ordered["malformed"] = false
        // Intent Layer v2 (rules 13-18): reported in pipeline order exactly when IntentV2 reports them (total: never throws)
        val v2 = IntentV2.decide(p, grant, intentV2, now)
        for (c in v2.checks) {
            ordered[c.name] = c.ok
            if (!c.ok) {
                val r = "${c.name}: ${c.reason}"
                v.reasons.add(r) // never a duplicate: v2 check names are distinct and none is a core check name
                if (v.reason.isEmpty()) v.reason = r
            }
        }
        // Consistency token: `fresh_at`, right after the intent checks; reported only when the PCActn carries the member, a side-carried token
        // is read, or the policy requires one (otherwise no entry: byte-identical to before). A stale verifier is an `escalate:` failure.
        val fa = FreshAt.decide(p["fresh_at"], p.containsKey("fresh_at"), freshAt, now)
        if (fa.status != FreshAt.Status.NONE) {
            ordered["fresh_at"] = fa.status == FreshAt.Status.PASS
            if (fa.status == FreshAt.Status.FAIL) {
                val r = "fresh_at: ${fa.reason}"
                v.reasons.add(r)
                if (v.reason.isEmpty()) v.reason = r
            }
        }
        // the verifier hooks (hooks.attestation, hooks.zk): an enforced verdict decides its check, a hook that throws is a malformed PCActn
        var zkDecided = false
        try {
            val hookCtx = PcaCore.Ctx(p, grant, now)
            if (attestationHook != null) {
                val r = attestationHook.run(hookCtx)
                if (r.enforced) {
                    ordered["attestation"] = r.ok
                    if (!r.ok) {
                        val why = "attestation: ${r.reason ?: "rejected"}"
                        v.reasons.add(why)
                        if (v.reason.isEmpty()) v.reason = why
                    }
                }
            }
            if (p.containsKey("zk_compliance") && zkHook != null) {
                val r = zkHook.run(hookCtx)
                if (r.enforced) {
                    zkDecided = true
                    ordered["zk_compliance"] = r.ok
                    if (!r.ok) {
                        val why = "zk_compliance: ${r.reason ?: "rejected"}"
                        v.reasons.add(why)
                        if (v.reason.isEmpty()) v.reason = why
                    }
                }
            }
        } catch (e: RuntimeException) {
            ordered["malformed"] = false
            val why = "malformed PCActn: ${e.message}"
            v.reasons.add(why)
            if (v.reason.isEmpty()) v.reason = why
        }
        // a carried zk proof asserts a compliance guarantee: with no zk verifier that enforced it, fail closed at the core (pcactn.ts:835-841)
        if (p.containsKey("zk_compliance") && !zkDecided && ordered["malformed"] != false) {
            ordered["zk_compliance"] = false
            val r = "zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof"
            v.reasons.add(r)
            if (v.reason.isEmpty()) v.reason = r
        }
        v.legacyModelPolarity = v2.legacyModelPolarity
        v.checks.clear()
        v.checks.putAll(ordered)
        v.allow = !v.checks.containsValue(false)
        return v
    }
}
