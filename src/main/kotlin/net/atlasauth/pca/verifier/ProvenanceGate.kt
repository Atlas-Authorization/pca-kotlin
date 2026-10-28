package net.atlasauth.pca.verifier

/**
 * Build provenance as a K1 discharge (track K9; packages/pca/src/provenance-gate.ts). The RFC 9162 inclusion check, the
 * policy gates over the facts the cryptographic Sigstore check established (refusal codes, check order and reason strings
 * are normative, shared through `conformance/provenance-vectors.json`), and the `needs_discharge` caveat a grant uses to
 * ask an `artifact` verifier for the claims. Provenance can only remove authority.
 *
 * Values are the [Json] tree (maps, lists, strings, booleans, [Json.Num]). Total: malformed input is `false` or a refusal
 * code, never an exception.
 */
@Suppress("UNCHECKED_CAST")
object ProvenanceGate {
    const val SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
    const val INTOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"

    private const val MAX_SAFE = 9007199254740991L

    // ---- RFC 9162 inclusion ----

    /** RFC 9162 section 2.1.1: the hash of a leaf, SHA-256(0x00 || data). */
    fun rfc9162LeafHash(data: ByteArray): ByteArray = Pca.sha(byteArrayOf(0), data)

    private fun nodeHash(l: ByteArray, r: ByteArray): ByteArray = Pca.sha(byteArrayOf(1), l, r)

    /**
     * RFC 9162 section 2.1.3.2: verify an inclusion proof of [leafHash] at [index] in a tree of [size] leaves with root [root].
     * [proof] runs from the leaf level up, without the leaf and the root. Index and size are non-negative safe integers
     * (64-bit arithmetic). False on any malformed input.
     */
    fun verifyRfc9162Inclusion(leafHash: ByteArray, index: Long, size: Long, proof: List<ByteArray>, root: ByteArray): Boolean {
        try {
            if (!(index >= 0 && size >= 1 && size <= MAX_SAFE && index < size)) return false
            if (leafHash.size != 32 || root.size != 32 || proof.size > 64 || proof.any { it.size != 32 }) return false
            var fn = index
            var sn = size - 1
            var r = leafHash
            for (p in proof) {
                if (sn == 0L) return false
                if (fn and 1L == 1L || fn == sn) {
                    r = nodeHash(p, r)
                    if (fn and 1L == 0L) {
                        while (fn and 1L == 0L && fn != 0L) {
                            fn = fn shr 1
                            sn = sn shr 1
                        }
                    }
                } else {
                    r = nodeHash(r, p)
                }
                fn = fn shr 1
                sn = sn shr 1
            }
            return sn == 0L && r.contentEquals(root)
        } catch (e: RuntimeException) {
            return false
        }
    }

    // ---- facts and policy ----

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    /** A non-empty string of at most 2048 UTF-8 bytes. */
    private fun str(v: Any?): Boolean = IntentArtifacts.isBoundedString(v, 2048)

    private fun closed(o: Any?, required: List<String>, optional: List<String>, where: String = "object"): String? =
        IntentArtifacts.closedMembers(m(o), required, optional, where)

    private fun lowerHex(v: Any?, n: Int): Boolean = v is String && v.length == n && v.all { it in '0'..'9' || it in 'a'..'f' }

    private fun subjectError(s: Any?): Boolean {
        if (s !is Map<*, *> || closed(s, listOf("alg", "digest"), emptyList()) != null) return true
        val n = when (s["alg"]) { "sha256" -> 64; "sha512" -> 128; else -> return true }
        return !lowerHex(s["digest"], n)
    }

    private fun isLevel(v: Any?): Boolean = IntentJs.isInt(v) && IntentJs.lng(v) in 1L..3L

    /** Null when well-formed (closed members, bounded strings), else the reference's reason. */
    fun provenanceFactsError(fo: Any?): String? {
        if (fo !is Map<*, *>) return "facts must be an object"
        val f = m(fo)
        closed(
            f,
            listOf("v", "predicate_type", "build_type", "builder_id", "subjects", "identity", "oidc_issuer", "integrated_time", "rekor_log_index"),
            listOf("source_repo", "source_ref", "source_digest", "provenance_source"),
            "facts",
        )?.let { return it }
        if (!(IntentJs.isInt(f["v"]) && IntentJs.lng(f["v"]) == 1L)) return "facts.v must be 1"
        for (k in listOf("predicate_type", "build_type", "builder_id", "identity", "oidc_issuer")) if (!str(f[k])) return "facts.$k must be a non-empty string"
        for (k in listOf("source_repo", "source_ref", "source_digest")) if (f.containsKey(k) && !str(f[k])) return "facts.$k must be a non-empty string"
        val subs = f["subjects"]
        if (!(subs is List<*> && subs.size in 1..64 && subs.none { subjectError(it) })) return "facts.subjects must be 1..64 {alg, digest}"
        if (!IntentJs.isNonNeg(f["integrated_time"])) return "facts.integrated_time must be a non-negative integer"
        if (!IntentJs.isNonNeg(f["rekor_log_index"])) return "facts.rekor_log_index must be a non-negative integer"
        if (f.containsKey("provenance_source")) {
            val p = f["provenance_source"]
            if (p !is Map<*, *> || closed(p, listOf("uri"), listOf("git_commit")) != null || !str(p["uri"]) || (p.containsKey("git_commit") && !str(p["git_commit"]))) {
                return "facts.provenance_source is malformed"
            }
        }
        return null
    }

    /** Null when well-formed, else the reference's reason. */
    fun provenancePolicyError(po: Any?): String? {
        if (po !is Map<*, *>) return "policy must be an object"
        val p = m(po)
        closed(p, listOf("roots", "min_level"), listOf("source_repo", "source_ref", "source_ref_prefix", "build_types", "max_age_s", "require_runtime"), "policy")?.let { return it }
        val roots = p["roots"]
        if (!(roots is List<*> && roots.size in 1..32)) return "policy.roots must hold 1..32 pairs"
        for (ro in roots) {
            if (ro !is Map<*, *> || closed(ro, listOf("oidc_issuer", "builder_id", "level"), listOf("identity", "identity_prefix")) != null) return "policy root is malformed"
            if (!str(ro["oidc_issuer"]) || !str(ro["builder_id"])) return "policy root needs oidc_issuer and builder_id"
            if (ro.containsKey("identity") == ro.containsKey("identity_prefix")) return "policy root needs exactly one of identity and identity_prefix"
            if (ro.containsKey("identity") && !str(ro["identity"])) return "policy root identity is malformed"
            // a prefix must at least name a scheme and a host (length in UTF-16 units, as the reference counts it)
            val pre = ro["identity_prefix"]
            if (ro.containsKey("identity_prefix") && !(str(pre) && (pre as String).length >= 10)) return "policy root identity_prefix must be at least 10 characters"
            if (!isLevel(ro["level"])) return "policy root level must be 1, 2 or 3"
        }
        if (!isLevel(p["min_level"])) return "policy.min_level must be 1, 2 or 3"
        if (p.containsKey("source_repo") && !str(p["source_repo"])) return "policy.source_repo is malformed"
        if (p.containsKey("source_ref") && p.containsKey("source_ref_prefix")) return "policy takes source_ref or source_ref_prefix, not both"
        if (p.containsKey("source_ref") && !str(p["source_ref"])) return "policy.source_ref is malformed"
        if (p.containsKey("source_ref_prefix") && !str(p["source_ref_prefix"])) return "policy.source_ref_prefix is malformed"
        if (p.containsKey("build_types")) {
            val b = p["build_types"]
            if (!(b is List<*> && b.size in 1..16 && b.all { str(it) })) return "policy.build_types must hold 1..16 strings"
        }
        if (p.containsKey("max_age_s") && !(IntentJs.isInt(p["max_age_s"]) && IntentJs.lng(p["max_age_s"]) >= 1)) return "policy.max_age_s must be a positive integer"
        if (p.containsKey("require_runtime") && p["require_runtime"] !is Boolean) return "policy.require_runtime must be a boolean"
        return null
    }

    // ---- the gate ----

    /** `{ok: true, level, claims}` (claims in the reference's order) or `{ok: false, code}`. */
    class GateResult(val ok: Boolean, val level: Long, val claims: Map<String, Any?>?, val code: String?)

    private fun no(code: String) = GateResult(false, 0, null, code)

    /**
     * The provenance gates in the reference order over `{facts, policy, runtime?, now}`: policy, facts, clock, runtime digest,
     * predicate type, time, a pinned signer-builder pair (the highest matching level), the level floor, the provenance's own
     * source against the certificate's, the source repository and ref pins, the build type, then the subject. An absent member
     * is absent; a JSON `null` is present (and malformed). Total.
     */
    fun provenanceGate(input: Any?): GateResult {
        try {
            if (input !is Map<*, *>) return no("malformed_facts")
            val inp = m(input)
            if (provenancePolicyError(inp["policy"]) != null) return no("malformed_policy")
            if (provenanceFactsError(inp["facts"]) != null) return no("malformed_facts")
            if (!IntentJs.isNonNeg(inp["now"])) return no("malformed_facts")
            val now = IntentJs.lng(inp["now"])
            val f = m(inp["facts"])
            val p = m(inp["policy"])
            val hasRuntime = inp.containsKey("runtime")
            val rt = inp["runtime"]
            if (hasRuntime && subjectError(rt)) return no("malformed_runtime")
            if (f["predicate_type"] != SLSA_PROVENANCE_V1) return no("predicate_type")
            val itime = IntentJs.lng(f["integrated_time"])
            if (itime > now) return no("future")
            if (p.containsKey("max_age_s") && now - itime > IntentJs.lng(p["max_age_s"])) return no("stale")
            val identity = f["identity"] as String
            var level = 0L
            for (ro in p["roots"] as List<*>) {
                val r = m(ro)
                if (r["oidc_issuer"] != f["oidc_issuer"] || r["builder_id"] != f["builder_id"]) continue
                if (if (r.containsKey("identity")) r["identity"] != identity else !identity.startsWith(r["identity_prefix"] as String)) continue
                level = maxOf(level, IntentJs.lng(r["level"]))
            }
            if (level == 0L) return no("no_root")
            if (level < IntentJs.lng(p["min_level"])) return no("level")
            if (f.containsKey("provenance_source")) {
                val ps = m(f["provenance_source"])
                if (ps.containsKey("git_commit") && f.containsKey("source_digest") && ps["git_commit"] != f["source_digest"]) return no("source_mismatch")
                if (f.containsKey("source_repo")) {
                    val uri = ps["uri"] as String
                    val base = "git+" + f["source_repo"]
                    if (!(uri == base || uri.startsWith("$base@"))) return no("source_mismatch")
                }
            }
            if (p.containsKey("source_repo") && p["source_repo"] != f["source_repo"]) return no("source_repo")
            if (p.containsKey("source_ref") && p["source_ref"] != f["source_ref"]) return no("source_ref")
            if (p.containsKey("source_ref_prefix")) {
                val ref = f["source_ref"]
                if (!(ref is String && ref.startsWith(p["source_ref_prefix"] as String))) return no("source_ref")
            }
            if (p.containsKey("build_types") && f["build_type"] !in (p["build_types"] as List<Any?>)) return no("build_type")
            val subjects = f["subjects"] as List<*>
            val subject: Map<String, Any?>
            var bound = false
            if (hasRuntime) {
                val r = m(rt)
                subject = subjects.map { m(it) }.firstOrNull { it["alg"] == r["alg"] && it["digest"] == r["digest"] } ?: return no("runtime_mismatch")
                bound = true
            } else {
                if (p["require_runtime"] == true) return no("runtime_required")
                if (subjects.size != 1) return no("subject_ambiguous")
                subject = m(subjects[0])
            }
            val claims = LinkedHashMap<String, Any?>()
            claims["subject_alg"] = subject["alg"]
            claims["subject_digest"] = subject["digest"]
            claims["slsa_level"] = level
            for (k in listOf("builder_id", "build_type", "oidc_issuer", "identity", "source_repo", "source_ref", "source_digest")) if (f.containsKey(k)) claims[k] = f[k]
            claims["rekor_log_index"] = IntentJs.lng(f["rekor_log_index"])
            claims["runtime_bound"] = bound
            if (claims.values.any { it is String && IntentJs.u8len(it) > 256 }) return no("claim_too_long")
            return GateResult(true, level, claims, null)
        } catch (e: RuntimeException) {
            return no("malformed_facts")
        }
    }

    // ---- caveat ----

    /** Options of [provenanceCaveat]; null members take the reference default. */
    class CaveatOptions(
        /** Label of the verifier's `artifact` pin. */
        val issuer: String,
        /** 1, 2 or 3. */
        val minLevel: Long,
        /** Caveat id (K1 id syntax). Default `provenance`. */
        val id: String? = null,
        val sourceRepo: String? = null,
        /** Allowed builder ids (1..16), when given. */
        val builderIds: List<String>? = null,
        val oidcIssuer: String? = null,
        /** Require `runtime_bound: true`. Default true. */
        val requireRuntime: Boolean? = null,
        /** `chain_hop` or `action`. Default `action`. */
        val bind: String? = null,
        /** Default 300 000 (5 minutes). */
        val ttlMs: Long? = null,
    )

    private fun req(claim: String, op: String, value: Any?): Map<String, Any?> = linkedMapOf("claim" to claim, "op" to op, "value" to value)

    /** A `needs_discharge` caveat that asks the pinned `artifact` verifier for provenance claims. */
    fun provenanceCaveat(o: CaveatOptions): Map<String, Any?> {
        val require = mutableListOf<Any?>(req("slsa_level", "gte", o.minLevel))
        if (o.sourceRepo != null) require.add(req("source_repo", "eq", o.sourceRepo))
        if (o.builderIds != null) require.add(req("builder_id", "in", o.builderIds.toList()))
        if (o.oidcIssuer != null) require.add(req("oidc_issuer", "eq", o.oidcIssuer))
        if (o.requireRuntime != false) require.add(req("runtime_bound", "eq", true))
        return linkedMapOf(
            "type" to CaveatLang.NEEDS_DISCHARGE,
            "id" to (o.id ?: "provenance"),
            "issuer" to o.issuer,
            "issuer_class" to "artifact",
            "bind" to (o.bind ?: "action"),
            "ttl_ms" to (o.ttlMs ?: 300_000L),
            "require" to require,
        )
    }
}
