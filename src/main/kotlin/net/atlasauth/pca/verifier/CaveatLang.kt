package net.atlasauth.pca.verifier

/**
 * Caveat language v2 (track K1; security contract C-220..C-229; packages/pca/src/caveat-lang.ts). Six verifier-side features,
 * every one a RESTRICTION (a caveat only removes authority, and a verifier that does not know a type refuses the chain):
 *
 *  - `needs_discharge`  a third-party caveat, valid only with a signed discharge from a key THE VERIFIER pinned
 *  - `sealed`           no hop may be appended below the hop that carries it
 *  - `narrow` (artifact) a holder-signed per-action or short-lived self-attenuation that rides beside the PCActn
 *  - `max_uses`         a lifetime use count backed by the verifier's atomic replay store ([Authorize.StateStore])
 *  - `derive`           a bounded, stratified, non-recursive derived-fact check in Kleene three-valued logic
 *  - `spiffe_bound`     the presenting workload's verified SPIFFE ID must match
 *
 * Everything is total: a malformed caveat, discharge, narrow block or context is a refusal, never an exception and never an
 * allow. Values are the [Json] tree (maps, lists, strings, booleans, [Json.Num]); reason strings are part of the contract.
 */
object CaveatLang {
    const val NEEDS_DISCHARGE = "needs_discharge"
    const val SEALED = "sealed"
    const val MAX_USES = "max_uses"
    const val DERIVE = "derive"
    const val SPIFFE_BOUND = "spiffe_bound"

    /** Caveat types this module evaluates (the stock evaluator refuses them). */
    val K1_CAVEAT_TYPES: List<String> = listOf(NEEDS_DISCHARGE, SEALED, MAX_USES, DERIVE, SPIFFE_BOUND)

    const val DISCHARGE_DOMAIN = "atlas-pca/discharge/v1\u0000"
    const val DISCHARGE_REF_DOMAIN = "atlas-pca/discharge-ref/v1"
    const val DISCHARGE_ACTION_DOMAIN = "atlas-pca/discharge-action/v1"
    const val NARROW_DOMAIN = "atlas-pca/narrow/v1\u0000"
    const val MAX_USES_DOMAIN = "atlas-pca/max-uses/v1\u0000"

    /** A discharge or narrow block lives at most 24 hours. */
    const val MAX_LIFETIME_MS = 86_400_000L
    const val MAX_USES_LIMIT = 256
    const val NARROW_MAX_CAVEATS = 16
    const val DERIVE_MAX_DEFS = 8
    const val DERIVE_MAX_NODES = 32
    const val DERIVE_MAX_DEPTH = 4
    const val DERIVE_MAX_WINDOW_MS = 30L * 86_400_000L
    const val DERIVE_MAX_HISTORY = 10_000
    const val SPIFFE_MAX_ID_BYTES = 2048

    private const val MAX_SAFE = 9007199254740991L
    private val NAME_RE = Regex("[a-z][a-z0-9_]{0,63}")
    private val ID_RE = Regex("[a-z0-9][a-z0-9_.-]{0,63}")
    private val TRUST_DOMAIN_RE = Regex("[a-z0-9._-]+")
    private val SEGMENT_RE = Regex("[A-Za-z0-9._-]+")
    private val ISSUER_CLASSES = listOf("human", "org", "workload", "model", "artifact")
    private val OPS = listOf("eq", "neq", "gte", "lte", "in")
    private val CMP_OPS = listOf("eq", "neq", "lt", "lte", "gt", "gte")

    // ---- small helpers (JavaScript value semantics over the Json tree) ----
    private fun isObj(x: Any?): Boolean = x is Map<*, *>
    private fun isSafeInt(v: Any?): Boolean = IntentJs.isInt(v)
    private fun isStr256(v: Any?): Boolean = IntentArtifacts.isBoundedString(v, 256)
    private fun isScalarClaim(v: Any?): Boolean = IntentArtifacts.isScalar(v) && (v !is String || isStr256(v))
    private fun isName(v: Any?): Boolean = v is String && NAME_RE.matches(v)
    private fun isId(v: Any?): Boolean = v is String && ID_RE.matches(v)
    private fun safeClock(now: Long): Boolean = now >= -MAX_SAFE && now <= MAX_SAFE
    private fun has(m: Map<String, Any?>, k: String): Boolean = m.containsKey(k)
    private fun isK1Type(t: Any?): Boolean = t is String && K1_CAVEAT_TYPES.contains(t)
    private fun typeOf(c: Any?): Any? = (c as? Map<*, *>)?.get("type")

    /** True for a caveat object of a K1 type. */
    fun isK1Caveat(c: Any?): Boolean = isObj(c) && isK1Type(typeOf(c))

    private fun hopsOf(grant: Any?, chain: Any?): List<Any?> = if (chain is List<*> && chain.isNotEmpty()) chain else listOf(grant)

    private fun msg(e: Throwable): String = e.message ?: "unknown"

    // ======================================================================================
    // SPIFFE ID syntax
    // ======================================================================================

    /**
     * Null when `s` is a valid SPIFFE ID: `spiffe://` + a trust domain of lowercase letters, digits, `.`, `-`, `_` + an optional
     * path of non-empty segments over `[A-Za-z0-9._-]` that are not `.` or `..`, no trailing slash, at most 2048 bytes.
     */
    fun spiffeIdError(s: Any?): String? {
        if (s !is String || s.isEmpty()) return "SPIFFE ID must be a non-empty string"
        if (IntentJs.u8len(s) > SPIFFE_MAX_ID_BYTES) return "SPIFFE ID is too long"
        if (!s.startsWith("spiffe://")) return "SPIFFE ID must begin with spiffe://"
        val rest = s.substring(9)
        val slash = rest.indexOf('/')
        val td = if (slash == -1) rest else rest.substring(0, slash)
        val path = if (slash == -1) "" else rest.substring(slash)
        if (td.isEmpty() || td.length > 255 || !TRUST_DOMAIN_RE.matches(td)) return "invalid trust domain"
        if (path.isEmpty()) return null
        if (path.endsWith("/")) return "path must not end with a slash"
        for (seg in path.split("/").drop(1)) {
            if (seg.isEmpty() || seg == "." || seg == ".." || !SEGMENT_RE.matches(seg)) return "invalid path segment"
        }
        return null
    }

    // ======================================================================================
    // Hop analysis: which hop introduced a caveat
    // ======================================================================================

    /** A caveat with the hop that introduced it (`hop` 0 = the root grant) and that hop's capability hash. */
    class BoundCaveat(val caveat: Any?, val hop: Int, val capHash: String)

    /**
     * Every caveat of the leaf hop with the hop that introduced it. Caveat lists are cumulative and append-only, so the caveat at
     * position `p` was introduced by the first hop whose list is longer than `p`. Null for a malformed chain.
     */
    fun boundCaveats(grant: Any?, chain: Any? = null): List<BoundCaveat>? = try {
        val hops = hopsOf(grant, chain)
        val leafCaveats = (hops[hops.size - 1] as? Map<*, *>)?.get("caveats") as? List<*>
        if (leafCaveats == null) null
        else {
            val out = ArrayList<BoundCaveat>()
            val hashes = HashMap<Int, String>()
            for (p in leafCaveats.indices) {
                var h = hops.indexOfFirst { x -> ((x as? Map<*, *>)?.get("caveats") as? List<*>)?.let { it.size > p } == true }
                if (h < 0) h = hops.size - 1
                val hash = hashes.getOrPut(h) { Pca.capHash(IntentJs.obj(hops[h])) }
                out.add(BoundCaveat(leafCaveats[p], h, hash))
            }
            out
        }
    } catch (e: RuntimeException) {
        null
    } catch (e: StackOverflowError) {
        null
    }

    // ======================================================================================
    // needs_discharge
    // ======================================================================================

    private fun requireError(r: Any?): String? {
        if (!isObj(r)) return "requirement must be an object"
        val m = IntentJs.obj(r)
        val e = IntentArtifacts.closedMembers(m, listOf("claim", "op", "value"), emptyList(), "require")
        if (e != null) return e
        if (!isName(m["claim"])) return "claim name is malformed"
        val op = m["op"]
        if (!(op is String && op in OPS)) return "op must be eq, neq, gte, lte or in"
        val v = m["value"]
        if (op == "in") {
            if (v !is List<*> || v.isEmpty() || v.size > 16 || !v.all { isScalarClaim(it) }) return "'in' needs 1..16 scalar values"
        } else if (op == "gte" || op == "lte") {
            if (!isSafeInt(v)) return "'$op' needs a safe integer"
        } else if (!isScalarClaim(v)) return "value must be a scalar"
        return null
    }

    /** Null when the caveat is well-formed: closed members, canonical names, bounded sizes. */
    fun needsDischargeError(c: Any?): String? {
        if (!isObj(c)) return "caveat must be an object"
        val m = IntentJs.obj(c)
        val e = IntentArtifacts.closedMembers(m, listOf("type", "id", "issuer", "issuer_class", "bind", "ttl_ms", "require"), listOf("issuer_spiffe"), "needs_discharge")
        if (e != null) return e
        if (m["type"] != NEEDS_DISCHARGE) return "not a needs_discharge caveat"
        if (!isId(m["id"])) return "id is malformed"
        if (!isId(m["issuer"])) return "issuer label is malformed"
        val cls = m["issuer_class"]
        if (!(cls is String && cls in ISSUER_CLASSES)) return "issuer_class must be human, org, workload, model or artifact"
        if (m["bind"] != "chain_hop" && m["bind"] != "action") return "bind must be 'chain_hop' or 'action'"
        val ttl = m["ttl_ms"]
        if (!(isSafeInt(ttl) && IntentJs.lng(ttl) >= 1 && IntentJs.lng(ttl) <= MAX_LIFETIME_MS)) return "ttl_ms must be 1..86400000"
        val req = m["require"]
        if (req !is List<*> || req.size > 16) return "require must be an array of at most 16 requirements"
        for (r in req) {
            val re = requireError(r)
            if (re != null) return re
        }
        if (has(m, "issuer_spiffe")) {
            val se = spiffeIdError(m["issuer_spiffe"])
            if (se != null) return "issuer_spiffe: $se"
        }
        return null
    }

    /** A verifier-side pin for a discharge issuer. `label` is what caveats name; the keys never appear in a token. */
    class DischargePin(val label: String, val cls: String, val pk: String, val pqPk: String? = null, val spiffeId: String? = null) {
        companion object {
            /** Total: a member of the wrong type becomes a value no caveat can match (empty label / key). */
            fun fromJson(o: Any?): DischargePin {
                val m = o as? Map<*, *>
                return DischargePin(
                    (m?.get("label") as? String) ?: "", (m?.get("class") as? String) ?: "", (m?.get("pk") as? String) ?: "",
                    m?.get("pq_pk") as? String, m?.get("spiffe_id") as? String,
                )
            }
        }
    }

    /** The digest of the exact PCActn (counter and signature included): a bind-`action` discharge authorises that one action. */
    fun dischargeActionDigest(pcactn: Any?): String = Pca.hashCanonical(linkedMapOf("d" to DISCHARGE_ACTION_DOMAIN, "pcactn" to pcactn))

    /** Content address of a discharge (signature included); what a revocation list names. */
    fun dischargeDigest(d: Any?): String = Pca.hashCanonical(linkedMapOf("d" to DISCHARGE_REF_DOMAIN, "discharge" to d))

    private val D_REQUIRED = listOf("v", "kind", "caveat_id", "issuer", "cap_hash", "bind", "claims", "iat", "not_after", "nonce", "sig")
    private val D_OPTIONAL = listOf("action_digest", "alg", "pq_pk", "pq_sig")

    private fun nonceError(m: Map<String, Any?>): Boolean {
        val nb = if (m["nonce"] is String) Pca.decodeB64uStrict(m["nonce"], -1) else null
        return nb == null || nb.size < 16
    }

    /** Null = well-formed. */
    fun dischargeShapeError(a: Any?): String? {
        if (!isObj(a)) return "not an object"
        val m = IntentJs.obj(a)
        val e = IntentArtifacts.closedMembers(m, D_REQUIRED, D_OPTIONAL, "discharge")
        if (e != null) return e
        if (IntentJs.num(m["v"]) != 1.0 || m["kind"] != "pca-discharge") return "not a pca-discharge v1"
        if (!isId(m["caveat_id"])) return "caveat_id is malformed"
        if (!isId(m["issuer"])) return "issuer label is malformed"
        if (!IntentArtifacts.isDigest(m["cap_hash"])) return "cap_hash must be canonical base64url (32 bytes)"
        val bind = m["bind"]
        if (bind != "chain_hop" && bind != "action") return "bind must be 'chain_hop' or 'action'"
        if (if (bind == "action") !IntentArtifacts.isDigest(m["action_digest"]) else has(m, "action_digest")) return "action_digest is required for bind action and forbidden for chain_hop"
        val claims = m["claims"]
        if (!isObj(claims) || (claims as Map<*, *>).size > 16) return "claims must be an object of at most 16 members"
        for ((k, v) in claims as Map<*, *>) if (!(k is String && NAME_RE.matches(k)) || !isScalarClaim(v)) return "claim '$k' is malformed"
        if (!(IntentJs.isNonNeg(m["iat"])) || !(IntentJs.isNonNeg(m["not_after"]))) return "iat and not_after must be non-negative safe integers"
        val iat = IntentJs.lng(m["iat"])
        val notAfter = IntentJs.lng(m["not_after"])
        if (!(notAfter > iat)) return "not_after must be greater than iat"
        if (notAfter - iat > MAX_LIFETIME_MS) return "a discharge lives at most $MAX_LIFETIME_MS ms"
        if (nonceError(m)) return "nonce must be canonical base64url of at least 16 bytes"
        if (m["sig"] !is String) return "sig must be a string"
        return IntentArtifacts.artifactSuiteError(m)
    }

    private fun claimHolds(r: Map<String, Any?>, claims: Map<String, Any?>): Boolean {
        val name = r["claim"] as String
        if (!claims.containsKey(name)) return false
        val v = claims[name]
        val want = r["value"]
        return when (r["op"]) {
            "eq" -> IntentArtifacts.scalarEq(v, want)
            "neq" -> !IntentArtifacts.scalarEq(v, want)
            "gte" -> IntentJs.isInt(v) && IntentJs.lng(v) >= IntentJs.lng(want)
            "lte" -> IntentJs.isInt(v) && IntentJs.lng(v) <= IntentJs.lng(want)
            "in" -> (want as List<*>).any { IntentArtifacts.scalarEq(v, it) }
            else -> false
        }
    }

    /** What a discharge must be bound to. `revoked` lists [dischargeDigest] values the verifier has revoked. */
    class DischargeBinding(
        val capHash: String,
        val actionDigest: String? = null,
        val pins: List<DischargePin> = emptyList(),
        val now: Long,
        val revoked: List<String>? = null,
    )

    /** The result of [verifyDischarge]: `ok` with the discharge's [digest] and [claims], else the [reason]. */
    class DischargeVerdict(val ok: Boolean, val digest: String?, val claims: Map<String, Any?>?, val reason: String?) {
        override fun toString(): String = "CaveatLang.DischargeVerdict(ok=$ok, reason=$reason)"
    }

    private fun dno(r: String) = DischargeVerdict(false, null, null, r)

    /**
     * Verify one discharge against one caveat. The verifier's own pins decide the key; the discharge is bound to the hop carrying
     * the caveat (and for `action` to the PCActn); it must be inside its window and within the caveat's `ttl_ms`; and its claims
     * must satisfy every requirement. Total.
     */
    fun verifyDischarge(discharge: Any?, caveat: Any?, bind: DischargeBinding): DischargeVerdict = try {
        verifyDischargeUnchecked(discharge, caveat, bind)
    } catch (e: RuntimeException) {
        dno("discharge error (fail closed): ${msg(e)}")
    } catch (e: StackOverflowError) {
        dno("discharge error (fail closed): unknown")
    }

    private fun verifyDischargeUnchecked(discharge: Any?, caveat: Any?, bind: DischargeBinding): DischargeVerdict {
        if (!safeClock(bind.now)) return dno("the verifier clock is not a safe integer (fail closed)")
        val ce = needsDischargeError(caveat)
        if (ce != null) return dno("malformed needs_discharge caveat: $ce")
        val c = IntentJs.obj(caveat)
        val de = dischargeShapeError(discharge)
        if (de != null) return dno("malformed discharge: $de")
        val d = IntentJs.obj(discharge)
        if (d["caveat_id"] != c["id"]) return dno("the discharge is for another caveat")
        if (d["issuer"] != c["issuer"]) return dno("the discharge names another issuer")
        val pins = bind.pins.filter { it.label == c["issuer"] }
        if (pins.isEmpty()) return dno("the issuer is not pinned by this verifier")
        if (pins.size > 1) return dno("the issuer label is pinned more than once (ambiguous)")
        val pin = pins[0]
        if (pin.cls != c["issuer_class"]) return dno("the pinned issuer is not of the class the caveat requires")
        if (has(c, "issuer_spiffe") && pin.spiffeId != c["issuer_spiffe"]) return dno("the pinned issuer does not carry the SPIFFE ID the caveat requires")
        if (!IntentArtifacts.verifyArtifactSig(DISCHARGE_DOMAIN, d, pin.pk, pin.pqPk)) return dno("discharge signature invalid")
        if (d["bind"] != c["bind"]) return dno("the discharge binds differently than the caveat requires")
        if (d["cap_hash"] != bind.capHash) return dno("the discharge is bound to another hop")
        if (c["bind"] == "action" && d["action_digest"] != bind.actionDigest) return dno("the discharge is bound to another action")
        val iat = IntentJs.lng(d["iat"])
        val notAfter = IntentJs.lng(d["not_after"])
        if (bind.now < iat) return dno("the discharge is from the future")
        if (bind.now > notAfter) return dno("the discharge has expired")
        if (notAfter - iat > IntentJs.lng(c["ttl_ms"])) return dno("the discharge lives longer than the caveat allows")
        val digest = dischargeDigest(d)
        if (bind.revoked != null && bind.revoked.contains(digest)) return dno("the discharge is revoked")
        val claims = IntentJs.obj(d["claims"])
        for (r in c["require"] as List<*>) {
            val rm = IntentJs.obj(r)
            if (!claimHolds(rm, claims)) return dno("claim '${rm["claim"]}' does not satisfy the caveat")
        }
        return DischargeVerdict(true, digest, claims, null)
    }

    // ======================================================================================
    // narrow: holder-signed per-action self-attenuation (no new hop)
    // ======================================================================================

    /** Types a narrow block must not carry: structure that only a real hop can introduce, and nested narrowing. */
    private val NARROW_FORBIDDEN = listOf("envelope", SEALED, "budget_alloc", "intent_session")
    private val N_REQUIRED = listOf("v", "kind", "cap_hash", "holder", "caveats", "iat", "not_after", "nonce", "sig")
    private val N_OPTIONAL = listOf("action_digest", "alg", "pq_pk", "pq_sig")

    /** Null = well-formed. */
    fun narrowShapeError(a: Any?): String? {
        if (!isObj(a)) return "not an object"
        val m = IntentJs.obj(a)
        val e = IntentArtifacts.closedMembers(m, N_REQUIRED, N_OPTIONAL, "narrow")
        if (e != null) return e
        if (IntentJs.num(m["v"]) != 1.0 || m["kind"] != "pca-narrow") return "not a pca-narrow v1"
        if (!IntentArtifacts.isDigest(m["cap_hash"])) return "cap_hash must be canonical base64url (32 bytes)"
        if (!IntentArtifacts.isBoundedString(m["holder"], 64) || Pca.decodeB64uStrict(m["holder"], 32) == null) return "holder must be canonical base64url (32 bytes)"
        val cs = m["caveats"]
        if (cs !is List<*> || cs.size < 1 || cs.size > NARROW_MAX_CAVEATS) return "caveats must be 1..$NARROW_MAX_CAVEATS caveats"
        for (c in cs) {
            val t = typeOf(c)
            if (!isObj(c) || t !is String) return "every caveat must be an object with a string type"
            if (t in NARROW_FORBIDDEN) return "a narrow block cannot carry a '$t' caveat"
        }
        if (has(m, "action_digest") && !IntentArtifacts.isDigest(m["action_digest"])) return "action_digest must be canonical base64url (32 bytes)"
        if (!IntentJs.isNonNeg(m["iat"]) || !IntentJs.isNonNeg(m["not_after"])) return "iat and not_after must be non-negative safe integers"
        val iat = IntentJs.lng(m["iat"])
        val notAfter = IntentJs.lng(m["not_after"])
        if (!(notAfter > iat)) return "not_after must be greater than iat"
        if (notAfter - iat > MAX_LIFETIME_MS) return "a narrow block lives at most $MAX_LIFETIME_MS ms"
        if (nonceError(m)) return "nonce must be canonical base64url of at least 16 bytes"
        if (m["sig"] !is String) return "sig must be a string"
        return IntentArtifacts.artifactSuiteError(m)
    }

    /** The result of [verifyNarrow]: `ok` with the block's caveats, else the [reason]. */
    class NarrowVerdict(val ok: Boolean, val caveats: List<Any?>?, val reason: String?) {
        override fun toString(): String = "CaveatLang.NarrowVerdict(ok=$ok, reason=$reason)"
    }

    private fun nno(r: String) = NarrowVerdict(false, null, r)

    /**
     * Verify a narrow block against the chain's leaf: signed by the leaf holder (a non-Ed25519 suite only under the PQ key the
     * leaf's `holder_pq` commits to), bound to the leaf hop and, when it names one, to this PCActn, inside its window. The caveats
     * it carries then join the chain's. Total.
     */
    fun verifyNarrow(narrow: Any?, grant: Any?, chain: Any?, now: Long, actionDigest: String? = null): NarrowVerdict = try {
        verifyNarrowUnchecked(narrow, grant, chain, now, actionDigest)
    } catch (e: RuntimeException) {
        nno("narrow error (fail closed): ${msg(e)}")
    } catch (e: StackOverflowError) {
        nno("narrow error (fail closed): unknown")
    }

    private fun verifyNarrowUnchecked(narrow: Any?, grant: Any?, chain: Any?, now: Long, actionDigest: String?): NarrowVerdict {
        if (!safeClock(now)) return nno("the verifier clock is not a safe integer (fail closed)")
        val e = narrowShapeError(narrow)
        if (e != null) return nno("malformed narrow block: $e")
        val n = IntentJs.obj(narrow)
        val hops = hopsOf(grant, chain)
        val leaf = IntentJs.obj(hops[hops.size - 1])
        if (n["holder"] != leaf["holder"]) return nno("the narrow block is not signed by the leaf holder")
        if (n["cap_hash"] != Pca.capHash(leaf)) return nno("the narrow block is bound to another hop")
        val npq = n["pq_pk"]
        val holderPq = leaf["holder_pq"]
        val pinnedPq: String? = if (npq is String && holderPq is String && Pca.holderPqCommitment(npq) == holderPq) npq else null
        if (!IntentArtifacts.verifyArtifactSig(NARROW_DOMAIN, n, n["holder"], pinnedPq)) return nno("narrow signature invalid")
        if (has(n, "action_digest") && n["action_digest"] != actionDigest) return nno("the narrow block is bound to another action")
        if (now < IntentJs.lng(n["iat"])) return nno("the narrow block is from the future")
        if (now > IntentJs.lng(n["not_after"])) return nno("the narrow block has expired")
        return NarrowVerdict(true, n["caveats"] as List<*>, null)
    }

    // ======================================================================================
    // max_uses: n atomic first-use slots in the verifier's replay store
    // ======================================================================================

    /** Null when the caveat is well-formed. */
    fun maxUsesError(c: Any?): String? {
        if (!isObj(c)) return "caveat must be an object"
        val m = IntentJs.obj(c)
        val e = IntentArtifacts.closedMembers(m, listOf("type", "id", "n", "until"), emptyList(), "max_uses")
        if (e != null) return e
        if (m["type"] != MAX_USES) return "not a max_uses caveat"
        if (!isId(m["id"])) return "id is malformed"
        val n = m["n"]
        if (!(isSafeInt(n) && IntentJs.lng(n) >= 1 && IntentJs.lng(n) <= MAX_USES_LIMIT)) return "n must be 1..$MAX_USES_LIMIT"
        if (!IntentJs.isNonNeg(m["until"])) return "until must be a non-negative safe integer"
        return null
    }

    /** The store key of use slot `i` of caveat `id` carried by hop `capHashOfHop`: b64u(sha256(domain NUL cap NUL id NUL i)). */
    fun maxUsesSlotKey(capHashOfHop: String, id: String, i: Int): String =
        Pca.b64(Pca.sha(IntentJs.utf8("${MAX_USES_DOMAIN}${capHashOfHop}\u0000${id}\u0000${i}")))

    /** The result of [reserveMaxUses]: `ok` with the number of caveats spent, else the [reason]. */
    class UsesVerdict(val ok: Boolean, val spent: Int, val reason: String?) {
        override fun toString(): String = "CaveatLang.UsesVerdict(ok=$ok, spent=$spent, reason=$reason)"
    }

    private fun uno(r: String) = UsesVerdict(false, 0, r)

    /**
     * Spend one use of every `max_uses` caveat in `bound`, in order, after the rest of the decision allows. Each caveat takes
     * the first free slot of its `n`: an atomic TTL'd consume-once of `maxUsesSlotKey` in the replay store
     * ([Authorize.StateStore.consumeOnce], retained until the caveat's `until`), so concurrent actions never share a slot
     * (across processes when the store is durable and shared). The first exhausted, expired or malformed caveat refuses; slots
     * already taken stay spent (fail closed). A slot past `until` may be forgotten: the caveat is expired by then.
     */
    fun reserveMaxUses(store: Authorize.StateStore, bound: List<BoundCaveat>, now: Long): UsesVerdict = try {
        if (!safeClock(now)) uno("the verifier clock is not a safe integer (fail closed)")
        else reserveUnchecked(store, bound, now)
    } catch (e: RuntimeException) {
        uno("max_uses error (fail closed): ${msg(e)}")
    } catch (e: StackOverflowError) {
        uno("max_uses error (fail closed): unknown")
    }

    private fun reserveUnchecked(store: Authorize.StateStore, bound: List<BoundCaveat>, now: Long): UsesVerdict {
        var spent = 0
        val ids = HashSet<String>()
        for (b in bound) {
            if (typeOf(b.caveat) != MAX_USES) continue
            val err = maxUsesError(b.caveat)
            if (err != null) return uno("malformed max_uses caveat: $err")
            val c = IntentJs.obj(b.caveat)
            val id = c["id"] as String
            if (!ids.add("${b.capHash}\u0000$id")) return uno("duplicate max_uses id '$id'")
            if (now >= IntentJs.lng(c["until"])) return uno("max_uses '$id' has expired")
            val n = IntentJs.lng(c["n"]).toInt()
            var took = false
            var i = 0
            while (i < n && !took) {
                took = store.consumeOnce(maxUsesSlotKey(b.capHash, id, i), IntentJs.lng(c["until"]), now)
                i++
            }
            if (!took) return uno("max_uses '$id' is exhausted")
            spent += 1
        }
        return UsesVerdict(true, spent, null)
    }

    // ======================================================================================
    // derive: bounded derived facts in Kleene three-valued logic
    // ======================================================================================

    private fun exprError(x: Any?, names: Set<String>, depth: Int, count: IntArray): String? {
        if (depth > DERIVE_MAX_DEPTH) return "expression nests deeper than $DERIVE_MAX_DEPTH"
        count[0] += 1
        if (count[0] > DERIVE_MAX_NODES) return "more than $DERIVE_MAX_NODES expression nodes"
        if (!isObj(x)) return "expression must be an object"
        val m = IntentJs.obj(x)
        if (has(m, "ref")) {
            val e = IntentArtifacts.closedMembers(m, listOf("ref"), emptyList(), "ref")
            if (e != null) return e
            val r = m["ref"]
            return if (r is String && r in names) null else "ref names no earlier def"
        }
        if (has(m, "const")) {
            val e = IntentArtifacts.closedMembers(m, listOf("const"), emptyList(), "const")
            if (e != null) return e
            return if (isScalarClaim(m["const"])) null else "const must be a scalar"
        }
        val op = m["op"]
        if (op == "and" || op == "or") {
            val e = IntentArtifacts.closedMembers(m, listOf("op", "args"), emptyList(), op as String)
            if (e != null) return e
            val args = m["args"]
            if (args !is List<*> || args.size < 1 || args.size > 8) return "$op needs 1..8 arguments"
            for (a in args) {
                val r = exprError(a, names, depth + 1, count)
                if (r != null) return r
            }
            return null
        }
        if (op == "not") {
            val e = IntentArtifacts.closedMembers(m, listOf("op", "arg"), emptyList(), "not")
            return e ?: exprError(m["arg"], names, depth + 1, count)
        }
        if (op is String && op in CMP_OPS) {
            val e = IntentArtifacts.closedMembers(m, listOf("op", "a", "b"), emptyList(), op)
            return e ?: exprError(m["a"], names, depth + 1, count) ?: exprError(m["b"], names, depth + 1, count)
        }
        return "unknown expression"
    }

    /** Null when the caveat is well-formed: bounded, closed, and non-recursive (a def refers only to defs before it). */
    fun deriveError(c: Any?): String? {
        if (!isObj(c)) return "caveat must be an object"
        val m = IntentJs.obj(c)
        val e = IntentArtifacts.closedMembers(m, listOf("type", "id", "defs", "check"), emptyList(), "derive")
        if (e != null) return e
        if (m["type"] != DERIVE) return "not a derive caveat"
        if (!isId(m["id"])) return "id is malformed"
        val defs = m["defs"]
        if (defs !is List<*> || defs.size > DERIVE_MAX_DEFS) return "defs must be an array of at most $DERIVE_MAX_DEFS"
        val names = HashSet<String>()
        val count = IntArray(1)
        for (dv in defs) {
            if (!isObj(dv) || !isName(IntentJs.obj(dv)["name"])) return "def name is malformed"
            val d = IntentJs.obj(dv)
            val name = d["name"] as String
            if (name in names) return "def '$name' is defined twice"
            var de: String?
            when (d["kind"]) {
                "count" -> {
                    de = IntentArtifacts.closedMembers(d, listOf("name", "kind", "window_ms"), listOf("verb", "resource_prefix"), "count")
                    val w = d["window_ms"]
                    if (de == null && !(isSafeInt(w) && IntentJs.lng(w) >= 1 && IntentJs.lng(w) <= DERIVE_MAX_WINDOW_MS)) de = "window_ms out of range"
                    if (de == null && has(d, "verb") && !isStr256(d["verb"])) de = "verb must be a non-empty string"
                    if (de == null && has(d, "resource_prefix") && !isStr256(d["resource_prefix"])) de = "resource_prefix must be a non-empty string"
                }
                "param" -> {
                    de = IntentArtifacts.closedMembers(d, listOf("name", "kind", "path"), emptyList(), "param")
                    val p = d["path"]
                    if (de == null && !(p is String && p.split(".").size <= 4 && p.split(".").all { IntentArtifacts.isPathSegment(it) })) de = "param path is malformed"
                }
                "action" -> {
                    de = IntentArtifacts.closedMembers(d, listOf("name", "kind", "field"), emptyList(), "action")
                    if (de == null && d["field"] != "verb" && d["field"] != "resource") de = "field must be 'verb' or 'resource'"
                }
                "claim" -> {
                    de = IntentArtifacts.closedMembers(d, listOf("name", "kind", "caveat_id", "claim"), emptyList(), "claim")
                    if (de == null && !(isId(d["caveat_id"]) && isName(d["claim"]))) de = "claim reference is malformed"
                }
                "expr" -> de = IntentArtifacts.closedMembers(d, listOf("name", "kind", "expr"), emptyList(), "expr") ?: exprError(d["expr"], names, 1, count)
                else -> de = "unknown def kind"
            }
            if (de != null) return "def '$name': $de"
            names.add(name)
        }
        return exprError(m["check"], names, 1, count)
    }

    private fun evalExpr(x: Map<String, Any?>, env: Map<String, Any?>): Any? {
        if (has(x, "ref")) return env[x["ref"] as String]
        if (has(x, "const")) return x["const"]
        val op = x["op"]
        if (op == "not") {
            val v = evalExpr(IntentJs.obj(x["arg"]), env)
            return if (v is Boolean) !v else null
        }
        if (op == "and" || op == "or") {
            val stop = op == "or"
            var unknown = false
            for (a in x["args"] as List<*>) {
                val v = evalExpr(IntentJs.obj(a), env)
                if (v !is Boolean) unknown = true else if (v == stop) return stop
            }
            return if (unknown) null else !stop
        }
        val a = evalExpr(IntentJs.obj(x["a"]), env)
        val b = evalExpr(IntentJs.obj(x["b"]), env)
        if (a == null || b == null) return null
        if (op == "eq") return IntentArtifacts.scalarEq(a, b)
        if (op == "neq") return !IntentArtifacts.scalarEq(a, b)
        if (!isSafeInt(a) || !isSafeInt(b)) return null
        val p = IntentJs.lng(a)
        val q = IntentJs.lng(b)
        return when (op) {
            "lt" -> p < q
            "lte" -> p <= q
            "gt" -> p > q
            else -> p >= q
        }
    }

    /**
     * Evaluate a well-formed derive caveat: true only when `check` is exactly true (false and unknown both refuse; null =
     * unknown). `history` is the verifier's own record (`{t, verb, resource}` events); `claims` maps a caveat id to the claims
     * of the discharge that VERIFIED in this evaluation, the only claim source a `derive` may read.
     */
    fun evaluateDerive(c: Map<String, Any?>, now: Long, action: Any?, history: List<Any?>?, claims: Map<String, Map<String, Any?>>): Boolean? {
        val env = HashMap<String, Any?>()
        val act = action as? Map<*, *>
        for (dv in c["defs"] as List<*>) {
            val d = IntentJs.obj(dv)
            var v: Any? = null
            when (d["kind"]) {
                "count" -> {
                    if (history != null && history.size <= DERIVE_MAX_HISTORY) {
                        val window = IntentJs.lng(d["window_ms"])
                        var n = 0L
                        var bad = false
                        for (ev in history) {
                            val e = ev as? Map<*, *>
                            if (e == null || !isSafeInt(e["t"]) || e["verb"] !is String || e["resource"] !is String) {
                                bad = true
                                break
                            }
                            val t = IntentJs.lng(e["t"])
                            if (t > now - window && t <= now &&
                                (!has(d, "verb") || e["verb"] == d["verb"]) &&
                                (!has(d, "resource_prefix") || (e["resource"] as String).startsWith(d["resource_prefix"] as String))
                            ) n += 1
                        }
                        v = if (bad) null else n
                    }
                }
                "param" -> {
                    val r = IntentArtifacts.resolveParamPath(act?.get("params"), "action.params.${d["path"]}")
                    v = if (r.found && isScalarClaim(r.value)) r.value else null
                }
                "action" -> {
                    val f = act?.get(d["field"] as String)
                    v = if (isStr256(f)) f else null
                }
                "claim" -> {
                    val cl = claims[d["caveat_id"] as String]
                    v = if (cl == null) null else cl[d["claim"] as String]
                }
                "expr" -> v = evalExpr(IntentJs.obj(d["expr"]), env)
            }
            env[d["name"] as String] = v
        }
        val r = evalExpr(IntentJs.obj(c["check"]), env)
        return if (r is Boolean) r else null
    }

    // ======================================================================================
    // spiffe_bound
    // ======================================================================================

    /** Null when the caveat is well-formed: exactly one of `spiffe_id` and `spiffe_prefix`, a valid SPIFFE ID. */
    fun spiffeBoundError(c: Any?): String? {
        if (!isObj(c)) return "caveat must be an object"
        val m = IntentJs.obj(c)
        val e = IntentArtifacts.closedMembers(m, listOf("type"), listOf("spiffe_id", "spiffe_prefix"), "spiffe_bound")
        if (e != null) return e
        if (m["type"] != SPIFFE_BOUND) return "not a spiffe_bound caveat"
        if (has(m, "spiffe_id") == has(m, "spiffe_prefix")) return "exactly one of spiffe_id and spiffe_prefix"
        return spiffeIdError(m["spiffe_id"] ?: m["spiffe_prefix"])
    }

    /** `spiffe_id`: the peer must equal it. `spiffe_prefix`: the peer must equal it or lie below it (`prefix + "/"`). */
    private fun spiffeSatisfied(c: Map<String, Any?>, peer: Any?): Boolean {
        if (spiffeBoundError(c) != null || spiffeIdError(peer) != null) return false
        val p = peer as String
        if (has(c, "spiffe_id")) return p == c["spiffe_id"]
        val pre = c["spiffe_prefix"] as String
        return p == pre || p.startsWith("$pre/")
    }

    // ======================================================================================
    // The K1 evaluator
    // ======================================================================================

    /** What the verifier supplies besides the chain. Pins, revocations, history and the SPIFFE ID never come from the request. */
    class K1Input(
        val pins: List<DischargePin> = emptyList(),
        val discharges: List<Any?>? = null,
        /** A narrow block presented with the action; [ABSENT] = none (a JSON null is a presented, malformed block). */
        val narrow: Any? = ABSENT,
        val actionDigest: String? = null,
        val revokedDischarges: List<String>? = null,
        val spiffeId: String? = null,
        val history: List<Any?>? = null,
    ) {
        /** The same input with the verifier's own action digest (a caller-supplied one is never trusted). */
        fun withActionDigest(digest: String): K1Input = K1Input(pins, discharges, narrow, digest, revokedDischarges, spiffeId, history)

        companion object {
            val ABSENT = Any()

            @Suppress("UNCHECKED_CAST")
            /** The shape the conformance vectors use (null for anything but an object: no K1 input): `pins`, `discharges`, `narrow`, `action_digest`, `revoked_discharges`, `spiffe_id`, `history`. */
            fun fromJson(o: Any?): K1Input? {
                val m = o as? Map<*, *> ?: return null // not an object = no K1 input configured
                return K1Input(
                    pins = (m["pins"] as? List<*>)?.map { DischargePin.fromJson(it) } ?: emptyList(),
                    discharges = m["discharges"] as? List<Any?>,
                    narrow = if (m.containsKey("narrow")) m["narrow"] else ABSENT,
                    actionDigest = m["action_digest"] as? String,
                    revokedDischarges = (m["revoked_discharges"] as? List<*>)?.map { it?.toString() ?: "" },
                    spiffeId = m["spiffe_id"] as? String,
                    history = m["history"] as? List<Any?>,
                )
            }
        }
    }

    /**
     * The verdict of [evaluateK1]. `failed` are the types of the unsatisfied caveats in order (`<malformed>` for one without a
     * string type), `reasons` one reason per failure, `plain` the verified narrow block's NON-K1 caveats (the caller evaluates
     * them with its stock evaluator), `bound` the K1 caveats evaluated with their hops (hand the `max_uses` ones to
     * [reserveMaxUses] once everything allowed).
     */
    class K1Result(val ok: Boolean, val failed: List<String>, val reasons: List<String>, val plain: List<Any?>, val bound: List<BoundCaveat>) {
        override fun toString(): String = "CaveatLang.K1Result(ok=$ok, failed=$failed)"
    }

    /**
     * Evaluate the K1 caveat types of the leaf hop (and of a verified narrow block). Non-K1 caveats are left to the stock
     * evaluator. `needs_discharge`, `sealed`, `max_uses` and `derive` ids must be unique over the chain and narrow block: a
     * duplicate fails every caveat that shares it. `max_uses` is only checked for well-formedness and expiry here. An absent `k1`
     * (null) fails EVERY K1 caveat: no input is not an empty input. Total.
     */
    fun evaluateK1(grant: Any?, chain: Any?, k1: K1Input?, now: Long, action: Any? = null): K1Result {
        val failed = ArrayList<String>()
        val reasons = ArrayList<String>()
        fun fail(c: Any?, why: String) {
            val t = typeOf(c)
            failed.add(if (t is String) t else "<malformed>")
            reasons.add(why)
        }
        fun result(plain: List<Any?>, bound: List<BoundCaveat>) = K1Result(failed.isEmpty(), failed, reasons, plain, bound)
        return try {
            val base = boundCaveats(grant, chain)
            if (base == null || !safeClock(now)) {
                fail(linkedMapOf<String, Any?>("type" to "<malformed>"), if (base == null) "malformed capability chain" else "the verifier clock is not a safe integer (fail closed)")
                result(emptyList(), emptyList())
            } else if (k1 == null) {
                val k1Bound = base.filter { isK1Caveat(it.caveat) }
                for (b in k1Bound) fail(b.caveat, "the caveat language is not configured (no k1 input)")
                result(emptyList(), k1Bound)
            } else evaluateBound(grant, chain, base, k1, now, action, { c, w -> fail(c, w) }, { p, b -> result(p, b) })
        } catch (e: RuntimeException) {
            fail(linkedMapOf<String, Any?>("type" to "<malformed>"), "caveat language error (fail closed): ${msg(e)}")
            result(emptyList(), emptyList())
        } catch (e: StackOverflowError) {
            fail(linkedMapOf<String, Any?>("type" to "<malformed>"), "caveat language error (fail closed): unknown")
            result(emptyList(), emptyList())
        }
    }

    private fun evaluateBound(
        grant: Any?, chain: Any?, base: List<BoundCaveat>, k1: K1Input, now: Long, action: Any?,
        fail: (Any?, String) -> Unit, result: (List<Any?>, List<BoundCaveat>) -> K1Result,
    ): K1Result {
        val hops = hopsOf(grant, chain)
        val leafIndex = hops.size - 1
        var bound: List<BoundCaveat> = base
        val plain = ArrayList<Any?>()
        if (k1.narrow !== K1Input.ABSENT) {
            val nv = verifyNarrow(k1.narrow, grant, chain, now, k1.actionDigest)
            if (!nv.ok) {
                fail(linkedMapOf<String, Any?>("type" to "narrow"), nv.reason ?: "narrow refused")
                return result(emptyList(), bound.filter { isK1Caveat(it.caveat) })
            }
            val leafHash = Pca.capHash(IntentJs.obj(hops[leafIndex]))
            val ncs: List<Any?> = nv.caveats ?: emptyList()
            bound = bound + ncs.map { BoundCaveat(it, leafIndex, leafHash) }
            for (c in ncs) if (!isK1Caveat(c)) plain.add(c)
        }
        val k1Bound = bound.filter { isK1Caveat(it.caveat) }
        // ids are unique per type across the chain and narrow block
        val seen = HashMap<String, Int>()
        for (b in k1Bound) {
            val c = IntentJs.obj(b.caveat)
            val id = c["id"]
            if (id is String) seen["${c["type"]}\u0000$id"] = (seen["${c["type"]}\u0000$id"] ?: 0) + 1
        }
        val claims = LinkedHashMap<String, Map<String, Any?>>()
        // pass 1: discharges (derive reads their claims)
        for (b in k1Bound) {
            val c = IntentJs.obj(b.caveat)
            if (c["type"] != NEEDS_DISCHARGE) continue
            val bad = needsDischargeError(c)
            if (bad != null) {
                fail(c, bad)
                continue
            }
            val id = c["id"] as String
            if ((seen["$NEEDS_DISCHARGE\u0000$id"] ?: 0) > 1) {
                fail(c, "duplicate needs_discharge id '$id'")
                continue
            }
            var why = "no discharge presented"
            var okd: DischargeVerdict? = null
            for (d in k1.discharges ?: emptyList()) {
                if (!isObj(d) || IntentJs.obj(d)["caveat_id"] != id) continue
                val v = verifyDischarge(d, c, DischargeBinding(b.capHash, k1.actionDigest, k1.pins, now, k1.revokedDischarges))
                if (v.ok) {
                    okd = v
                    break
                }
                why = v.reason ?: why
            }
            if (okd != null) claims[id] = okd.claims!! else fail(c, why)
        }
        // pass 2: everything else, in order
        for (b in k1Bound) {
            val c = IntentJs.obj(b.caveat)
            when (c["type"]) {
                SEALED -> {
                    val e = IntentArtifacts.closedMembers(c, listOf("type"), emptyList(), "sealed")
                    if (e != null) fail(c, e)
                    else if (b.hop != leafIndex) fail(c, "a hop was appended below a sealed hop")
                }
                MAX_USES -> {
                    val e = maxUsesError(c)
                    val id = c["id"]
                    if (e != null) fail(c, e)
                    else if ((seen["$MAX_USES\u0000$id"] ?: 0) > 1) fail(c, "duplicate max_uses id '$id'")
                    else if (now >= IntentJs.lng(c["until"])) fail(c, "max_uses '$id' has expired")
                }
                DERIVE -> {
                    val e = deriveError(c)
                    val id = c["id"]
                    if (e != null) fail(c, e)
                    else if ((seen["$DERIVE\u0000$id"] ?: 0) > 1) fail(c, "duplicate derive id '$id'")
                    else {
                        val r = evaluateDerive(c, now, action, k1.history, claims)
                        if (r != true) fail(c, if (r == null) "derive check is unknown (a fact is missing)" else "derive check is false")
                    }
                }
                SPIFFE_BOUND -> if (!spiffeSatisfied(c, k1.spiffeId)) fail(c, "the presenting workload does not carry the required SPIFFE ID")
            }
        }
        return result(plain, k1Bound)
    }

    /**
     * The decision over a grant's policy caveats: K1 types by [evaluateK1], every other caveat of
     * `Caveats.policyCaveats(grant, chain)` PLUS the verified narrow block's plain caveats by the stock [Caveats] evaluator.
     * `context` has the stock keys (`now`, `delegation_depth`, `recent_action_times`, `action {verb, resource, params}`).
     * `failed` = stock failures + K1 failures, sorted.
     */
    fun evaluateCaveatsK1(grant: Any?, chain: Any?, k1: K1Input?, context: Any?): Caveats.Result {
        val ctx = context as? Map<*, *>
        val nowV = ctx?.get("now")
        val now = if (IntentJs.isInt(nowV)) IntentJs.lng(nowV) else Long.MAX_VALUE // not a safe integer: evaluateK1 refuses
        val k = evaluateK1(grant, chain, k1, now, ctx?.get("action"))
        val policy = Caveats.policyCaveats(grant, chain)
        val stockList: Any? = if (policy is List<*>) policy.filter { !isK1Caveat(it) } + k.plain else policy
        val stock = Caveats.evaluateCaveats(stockList, context)
        val failed = (stock.failed + k.failed).sorted()
        return Caveats.Result(failed.isEmpty(), failed)
    }

    // ======================================================================================
    // The discharge / narrow request headers
    // ======================================================================================

    /** What [presentedK1] read: `ok` with the presented `discharges` (null = none) and `narrow` ([K1Input.ABSENT] = none), else the [error]. */
    class Presented(val ok: Boolean, val discharges: List<Any?>?, val narrow: Any?, val error: String?) {
        override fun toString(): String = "CaveatLang.Presented(ok=$ok, error=$error)"
    }

    private fun headerValue(headers: Map<String, String?>, name: String): String? {
        val vals = headers.entries.filter { it.key.equals(name, ignoreCase = true) }.map { it.value }.distinct()
        return if (vals.size == 1) vals[0] else null // several differing spellings of one name: ambiguous = absent
    }

    private fun decodeHeaderJson(v: String): Any? {
        val raw = Pca.decodeB64uStrict(v, -1) ?: throw IllegalArgumentException("header is not strict base64url")
        val text = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            .decode(java.nio.ByteBuffer.wrap(raw)).toString()
        return Json.parse(text)
    }

    /**
     * Read `PCA-Discharges` (a base64url JSON ARRAY) and `PCA-Narrow` (any base64url JSON value; the verifier refuses a
     * non-object) from request headers, names case-insensitive, an empty value = absent. Strict base64url of UTF-8 and the strict
     * JSON parser; anything unreadable is an error (the caller then presents no discharges). Total.
     */
    fun presentedK1(headers: Map<String, String?>?): Presented = try {
        var discharges: List<Any?>? = null
        var narrow: Any? = K1Input.ABSENT
        val d = headers?.let { headerValue(it, "pca-discharges") }
        if (!d.isNullOrEmpty()) {
            val arr = decodeHeaderJson(d)
            if (arr !is List<*>) throw IllegalArgumentException("PCA-Discharges must be a JSON array")
            discharges = arr.toList()
        }
        val n = headers?.let { headerValue(it, "pca-narrow") }
        if (!n.isNullOrEmpty()) narrow = decodeHeaderJson(n)
        Presented(true, discharges, narrow, null)
    } catch (e: RuntimeException) {
        Presented(false, null, K1Input.ABSENT, msg(e))
    } catch (e: java.nio.charset.CharacterCodingException) {
        Presented(false, null, K1Input.ABSENT, "header is not UTF-8")
    } catch (e: StackOverflowError) {
        Presented(false, null, K1Input.ABSENT, "unknown")
    }

    /**
     * The K1 input a guard passes on: the verifier's own `own` input wins, the request's presented discharges / narrow fill what
     * it leaves unset. Null when `own` is null (K1 not configured: headers alone never switch it on). Unreadable headers are no
     * discharges. Total.
     */
    fun k1Of(headers: Map<String, String?>?, own: K1Input?): K1Input? {
        if (own == null) return null
        val p = presentedK1(headers)
        if (!p.ok) return own
        return K1Input(own.pins, own.discharges ?: p.discharges, if (own.narrow !== K1Input.ABSENT) own.narrow else p.narrow, own.actionDigest, own.revokedDischarges, own.spiffeId, own.history)
    }
}
