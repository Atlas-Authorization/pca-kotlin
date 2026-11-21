package net.atlasauth.pca.verifier

/**
 * Attestation-derived workload identity for an agent: the quote it presents measures the model, the weights, the runtime and the operator,
 * so a swapped model or a tampered runtime changes the measurement and the identity evaporates. Two modes:
 *  - SOFTWARE: a signed [DevAttestor] document. A real, checkable attestation for development, CI and attested-VM equivalents, but the
 *    measurements are asserted by the signer, not rooted in silicon.
 *  - HARDWARE: a [HardwareVerifier] (a vendor verifier through [fromVendor]) that verifies the vendor evidence; the identity it measures,
 *    never the document's own fields, then feeds the same freshness, nonce-binding and agent-binding checks.
 *
 * [createMultiRootVerifier] requires several independent roots to agree, and [anchorAttestationEvidence] appends each verified attestation to a
 * transparency log under a signed tree head, so an attestation admitted by mistake stays attributable.
 *
 * Documents, contexts and expected bindings are decoded JSON (maps and lists); results are JSON trees. Verification never throws: every failure
 * is `ok: false` with the reason. A post-quantum or hybrid document verifies only under a PQ key the VERIFIER pins for the attestor (`pqPins`);
 * the reference's legacy option that trusts the document's own PQ key is not offered, as everywhere in this SDK.
 */
@Suppress("UNCHECKED_CAST")
object Attestation {
    const val ATTEST_BIND_DOMAIN = AttestUtil.BIND_DOMAIN
    const val ATTEST_ANCHOR_DOMAIN = "atlas-pca/attest-anchor/v1\u0000"
    private const val DOMAIN = "atlas-pca/attest/v1\u0000"

    /** Hard ceiling on the age of a server-issued attestation nonce at verification time (5 minutes). A caller may only tighten it. */
    const val MAX_ATTESTATION_AGE_MS = 5 * 60_000L

    /** Default retention of a consumed nonce in [memoryNonceStore] (1 hour, 12 times the quote-age ceiling). */
    const val DEFAULT_NONCE_RETENTION_MS = 60 * 60 * 1000L

    /** Minimum entropy of a server-issued attestation nonce, in bytes (128 bits). Not configurable below this. */
    const val MIN_ATTESTATION_NONCE_BYTES = 16
    private const val DEFAULT_NONCE_STORE_MAX = 100_000L
    private const val MAX_SAFE = 9007199254740991.0

    // ---- small JavaScript-shaped helpers ----

    private fun get(o: Any?, k: String): Any? = ZkJs.get(o, k)

    /** `o?.a?.b`: the member chain; undefined as soon as a step is null, undefined or not an object. */
    private fun path(o: Any?, vararg keys: String): Any? {
        var cur: Any? = o
        for (k in keys) cur = if (cur == null || cur === ZkJs.UNDEF) ZkJs.UNDEF else ZkJs.get(cur, k)
        return cur
    }

    /** A value for a result tree: an undefined member is left out. */
    private fun defined(v: Any?): Any? = if (v === ZkJs.UNDEF) null else v

    private fun msg(e: Throwable): String = e.message ?: "invalid"

    private fun text(x: Any?): String = ZkJs.string(x)

    private fun finite(o: Any?): Boolean = IntentJs.isFinite(o)

    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = LinkedHashMap<String, Any?>().also { for ((k, v) in kv) it[k] = v }

    /** A set from an iterable: a list by element, a string by character, null or undefined empty; anything else is not iterable. */
    private fun stringSet(iterable: Any?): Set<String> {
        val out = HashSet<String>()
        when {
            iterable == null || iterable === ZkJs.UNDEF -> {}
            iterable is List<*> -> for (x in iterable) if (x is String) out.add(x)
            iterable is String -> iterable.codePoints().forEach { out.add(String(Character.toChars(it))) }
            else -> throw IllegalArgumentException("object is not iterable")
        }
        return out
    }

    // ---- binding ----

    internal fun bindingOf(exp: Any?): Attest.Binding {
        val h = get(exp, "holderPub")
        val g = get(exp, "grantRef")
        val n = get(exp, "nonce")
        val e = get(exp, "epoch")
        if (h !is String || h.isEmpty()) throw IllegalArgumentException("binding: holderPub required")
        if (g !is String || g.isEmpty()) throw IllegalArgumentException("binding: grantRef required")
        if (n !is String || n.isEmpty()) throw IllegalArgumentException("binding: nonce required")
        if (!IntentJs.isSafeInteger(e) || IntentJs.num(e)!! < 0) throw IllegalArgumentException("binding: epoch must be a non-negative safe integer")
        return Attest.Binding(h, g, IntentJs.num(e)!!, n)
    }

    /**
     * The value a quote's report data must carry: `SHA-512(ATTEST_BIND_DOMAIN || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce))` with
     * `lp(x) = u32be(len) || utf8(x)`. 64 bytes, the SEV-SNP report-data width; a quote captured for one holder, grant, epoch or nonce cannot be
     * relayed for another. Throws on a malformed expected binding `{holderPub, grantRef, epoch, nonce}`.
     */
    @JvmStatic fun attestationBinding(expected: Any?): ByteArray = Attest.bindingBytes(bindingOf(expected))

    /** [attestationBinding] as base64url (what a software document carries in `binding`). */
    @JvmStatic fun attestationBindingB64u(expected: Any?): String = Keys.b64u(attestationBinding(expected))

    // ---- software documents ----

    /** base64url(sha256(canonical(document))): a content address for the full signed quote. */
    @JvmStatic fun attestationDigest(document: Any?): String = Pca.hashCanonical(IntentJs.normalize(document))

    /** A software-mode attestor: signs [attest] documents with its key. Build it with [createDevAttestor]. */
    class DevAttestor internal constructor(private val signer: Keys.SuiteKey) {
        /** The b64u Ed25519 public key a verifier lists in `trustedAttestorKeys`. */
        val publicKey: String = (signer.ed ?: throw IllegalArgumentException("createDevAttestor: the attestor needs an Ed25519 identity")).id()

        /**
         * Sign a software-mode document over the claims `{model_id, weights_digest, runtime_measurement, operator, nonce, issued_at, expires_at}`
         * (all required), with optional `system_prompt_digest`, `tool_manifest_digest` and, when all three are present, `holder_pub`, `grant_ref`,
         * `epoch`, which bind the document to that holder, grant, epoch and nonce. Members the claims do not name are not carried. Throws on a
         * missing claim or a value with no canonical form.
         */
        fun attest(claims: Map<String, Any?>): Map<String, Any?> {
            val binds = claims.containsKey("holder_pub") && claims.containsKey("grant_ref") && claims.containsKey("epoch")
            val binding = if (binds) attestationBindingB64u(obj("holderPub" to claims["holder_pub"], "grantRef" to claims["grant_ref"], "epoch" to claims["epoch"], "nonce" to claims["nonce"])) else null
            val body = LinkedHashMap<String, Any?>()
            for (k in listOf("model_id", "weights_digest", "runtime_measurement", "operator", "nonce", "issued_at", "expires_at")) {
                if (!claims.containsKey(k)) throw IllegalArgumentException("canonicalize: unsupported type undefined")
                body[k] = claims[k]
            }
            body["attestor"] = publicKey
            body["mode"] = "software"
            // additive: the instruction and tool digests are carried only when supplied
            if (claims.containsKey("system_prompt_digest")) body["system_prompt_digest"] = claims["system_prompt_digest"]
            if (claims.containsKey("tool_manifest_digest")) body["tool_manifest_digest"] = claims["tool_manifest_digest"]
            if (binding != null) body["binding"] = binding
            return Issue.signArtifact(DOMAIN, body, signer)
        }
    }

    /** A software-mode attestor for development and CI over `signer` (an Ed25519 identity, optionally under a PQ or hybrid suite). */
    @JvmStatic fun createDevAttestor(signer: Keys.SuiteKey): DevAttestor = DevAttestor(signer)

    /**
     * The resolver over a set of known documents: it returns the one whose `nonce` equals the PCActn's `attestation.quote_digest` (null when none
     * does); a later document for a nonce replaces an earlier one. Entries that are not documents with a string nonce are ignored.
     */
    @JvmStatic fun attestationRegistry(docs: Any?): (Any?) -> Map<String, Any?>? {
        val byNonce = LinkedHashMap<String, Map<String, Any?>>()
        if (docs is List<*>) for (d in docs) if (d is Map<*, *> && d["nonce"] is String) byNonce[d["nonce"] as String] = d as Map<String, Any?>
        return { ctx ->
            val key = path(ctx, "pcactn", "attestation", "quote_digest")
            if (key is String) byNonce[key] else null
        }
    }

    // ---- single-use nonce store ----

    /** Single-use store for server-issued attestation nonces: `consume` is atomic and true only for the first call per nonce. */
    fun interface NonceStore {
        fun consume(nonce: Any?): Boolean
    }

    /**
     * An in-memory single-process nonce store. A consumed nonce is never re-accepted inside the retention window; the store is bounded by `max`
     * entries (null: 100000) and, when full of retained nonces, REFUSES new ones (false) rather than evicting a live one, because evicting reopens
     * replay for exactly the nonce dropped. `max` and `retentionMs` (null: 1 hour) must be positive integers. A clock reading (`now`, null: the
     * system clock) that is not a safe integer refuses the nonce (fail closed).
     */
    @JvmStatic @JvmOverloads
    fun memoryNonceStore(max: Any? = null, retentionMs: Any? = null, now: (() -> Double)? = null): NonceStore {
        val m = if (max == null) DEFAULT_NONCE_STORE_MAX.toDouble() else IntentJs.num(max)
        if (m == null || !IntentJs.isSafeInteger(m) || m < 1) {
            throw IllegalArgumentException("memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)")
        }
        val r = if (retentionMs == null) DEFAULT_NONCE_RETENTION_MS.toDouble() else IntentJs.num(retentionMs)
        if (r == null || !IntentJs.isSafeInteger(r) || r <= 0) throw IllegalArgumentException("memoryNonceStore: retentionMs must be a positive integer (ms)")
        return MemoryNonceStore(m.toLong(), r.toLong(), now ?: { System.currentTimeMillis().toDouble() })
    }

    private class MemoryNonceStore(private val max: Long, private val retention: Long, private val clock: () -> Double) : NonceStore {
        private val seen = LinkedHashMap<String, Long>() // nonce -> time consumed (insertion order is time order)

        @Synchronized override fun consume(nonce: Any?): Boolean {
            if (nonce !is String) return false
            val reading = clock()
            if (reading.isNaN() || reading.isInfinite() || reading != Math.rint(reading) || Math.abs(reading) > MAX_SAFE) return false
            val t = reading.toLong()
            val at = seen[nonce]
            if (at != null) {
                if (t - at < retention) return false // retained: a replay
                seen.remove(nonce) // aged out: treated as new (the freshness check refuses such a quote anyway)
            }
            if (seen.size >= max) {
                val it = seen.entries.iterator() // make room ONLY from aged-out entries
                while (it.hasNext()) {
                    if (t - it.next().value < retention) break
                    it.remove()
                }
                if (seen.size >= max) return false // full of live nonces: fail closed
            }
            seen[nonce] = t
            return true
        }
    }

    private val HEX = Regex("[0-9a-fA-F]+")
    private val B64U = Regex("[A-Za-z0-9_-]+")

    /**
     * Whether `nonce` plausibly carries at least `minBytes` bytes (null: 16; never below 16) of entropy: hex (at least twice that many digits) or
     * base64url (at least ceil(bytes*4/3) characters), with at least 8 distinct characters (refusing `aaaa...`, counters and words). A syntactic
     * floor only: the server must still draw nonces from a CSPRNG.
     */
    @JvmStatic @JvmOverloads
    fun nonceEntropyOk(nonce: Any?, minBytes: Any? = null): Boolean {
        if (nonce !is String) return false
        val need = Math.max(if (minBytes == null) MIN_ATTESTATION_NONCE_BYTES.toDouble() else net.atlasauth.pca.compliance.ComplianceJs.toNumber(minBytes), MIN_ATTESTATION_NONCE_BYTES.toDouble())
        val hex = HEX.matches(nonce)
        val b64 = B64U.matches(nonce)
        if (!hex && !b64) return false
        val bytes = if (hex) nonce.length / 2.0 else Math.floor(nonce.length * 3.0 / 4.0)
        if (bytes < need) return false
        return nonce.codePoints().distinct().count() >= 8
    }

    // ---- agent binding ----

    /** True iff the grant's `agent_binding` constrains anything: then a bound attestation is REQUIRED. */
    @JvmStatic fun requiresAttestation(binding: Any?): Boolean = Authorize.requiresAttestation(binding)

    /** True iff `doc.nonce` is the nonce the PCActn declares in `attestation.quote_digest`. */
    @JvmStatic fun nonceBinds(doc: Any?, ctx: Any?): Boolean {
        val n = get(doc, "nonce")
        return n is String && ZkJs.strictEq(n, path(ctx, "pcactn", "attestation", "quote_digest"))
    }

    private val SVN_TEXT = Regex("0|[1-9][0-9]*")

    /** `list.includes(v)`: SameValueZero over the list (an object equals nothing). */
    private fun includes(list: Any?, v: Any?): Boolean {
        if (list !is List<*> || v === ZkJs.UNDEF) return false
        for (e in list) {
            if (e == null || v == null) { if (e == null && v == null) return true; continue }
            if (e is Map<*, *> || e is List<*> || v is Map<*, *> || v is List<*>) continue
            val a = IntentJs.num(e)
            val b = IntentJs.num(v)
            if (a != null || b != null) {
                if (a != null && b != null && (a == b || (a.isNaN() && b.isNaN()))) return true
                continue
            }
            if (e == v) return true
        }
        return false
    }

    private fun nonEmptyList(x: Any?): Boolean = x is List<*> && x.isNotEmpty()

    private fun measuredSvn(runtime: Any?): Double? {
        if (runtime !is String || !SVN_TEXT.matches(runtime)) return null
        val n = runtime.toDouble()
        return if (n <= MAX_SAFE) n else null
    }

    /**
     * Match a measured identity `{model_id, weights_digest, weights_measured?, runtime_measurement, operator, system_prompt_digest?,
     * tool_manifest_digest?}` against the grant's `agent_binding`; the reason it fails, else null. In order: model allowlist, `min_measurement`
     * (absent or "" constrains nothing; a string is an equality pin; `{svn: n}` is a floor over a canonical decimal runtime measurement; anything
     * else fails closed), operator, `require_measured_weights`, weights, system prompt and tool manifest allowlists. A pinned digest the identity
     * does not carry fails closed.
     */
    @JvmStatic fun matchAgentBinding(identity: Any?, binding: Any?): String? {
        if (identity == null) throw IllegalArgumentException("Cannot read properties of null (reading 'runtime_measurement')")
        val id: Map<String, Any?> = identity as? Map<String, Any?> ?: emptyMap()
        val b: Map<String, Any?> = binding as? Map<String, Any?> ?: emptyMap()
        val runtime = get(id, "runtime_measurement")
        if (nonEmptyList(b["model_allowlist"]) && !includes(b["model_allowlist"], get(id, "model_id"))) {
            return "model_id ${text(get(id, "model_id"))} not in model_allowlist"
        }
        val mm = get(b, "min_measurement")
        if (mm !== ZkJs.UNDEF && mm != "") {
            if (mm is String) {
                if (mm != runtime) return "runtime_measurement does not match required min_measurement"
            } else if (mm is Map<*, *> && mm.size == 1 && mm.containsKey("svn") && IntentJs.isNonNeg(mm["svn"])) {
                val floor = IntentJs.num(mm["svn"])!!
                val got = measuredSvn(runtime)
                val floorText = AttestUtil.jsNumString(floor)
                if (got == null) return "runtime_measurement ${text(runtime)} is not an integer SVN (required min svn $floorText)"
                if (got < floor) return "runtime_measurement svn ${AttestUtil.jsNumString(got)} is below required min svn $floorText"
            } else {
                return "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)"
            }
        }
        val op = b["operator"]
        if (op is String && op.isNotEmpty() && op != id["operator"]) return "operator ${text(get(id, "operator"))} is not the bound operator"
        if (b["require_measured_weights"] == true && id["weights_measured"] != true) {
            return "weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)"
        }
        if (nonEmptyList(b["weights_allowlist"]) && !includes(b["weights_allowlist"], get(id, "weights_digest"))) {
            return "weights_digest not in weights_allowlist (model swap / fine-tune?)"
        }
        if (nonEmptyList(b["system_prompt_allowlist"]) && (id["system_prompt_digest"] !is String || !includes(b["system_prompt_allowlist"], id["system_prompt_digest"]))) {
            return "system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)"
        }
        if (nonEmptyList(b["tool_manifest_allowlist"]) && (id["tool_manifest_digest"] !is String || !includes(b["tool_manifest_allowlist"], id["tool_manifest_digest"]))) {
            return "tool_manifest_digest not in tool_manifest_allowlist (tools changed?)"
        }
        return null
    }

    // ---- hardware seam ----

    /**
     * The seam every TEE verifier implements. `input` is `{document, ctx, nowMs, expected}`; the answer is the JSON form of the reference's
     * `HardwareAttestationResult`: `{ok, reason?, measured?, bound?, hostAsserted?}`. It may throw: a throw is a refusal.
     */
    fun interface HardwareVerifier {
        fun verify(input: Map<String, Any?>): Any?
    }

    /**
     * A vendor verifier as the seam: [evidenceOf] picks the vendor evidence for the action from the verification input (null: none supplied), and
     * the vendor verifier checks it against the expected binding at the input's clock.
     */
    @JvmStatic fun fromVendor(vendor: Attest.VendorVerifier, evidenceOf: (Map<String, Any?>) -> Map<String, Any?>?): HardwareVerifier = HardwareVerifier { input ->
        val b = bindingOf(input["expected"])
        val now = IntentJs.num(input["nowMs"]) ?: throw IllegalArgumentException("nowMs is not a number")
        vendor.verify(evidenceOf(input), b, now.toLong()).wire()
    }

    // ---- verification ----

    private fun verdict(ok: Boolean, present: Boolean, bound: Boolean, reason: String?, identity: Any?): Map<String, Any?> {
        val m = obj("ok" to ok, "present" to present, "bound" to bound)
        if (reason != null) m["reason"] = reason
        if (identity != null) m["identity"] = identity
        return m
    }

    private fun failed(present: Boolean, reason: String): Map<String, Any?> = verdict(false, present, false, reason, null)

    private fun nonceAgeReason(issued: Any?, nowMs: Double, skew: Double, maxAge: Double): String? {
        val v = IntentJs.num(issued)
        if (v == null || v.isNaN() || v.isInfinite()) return "server nonce issue time unknown (cannot establish freshness)"
        if (nowMs + skew < v) return "nonce issued in the future"
        if (nowMs - v > maxAge + skew) return "attestation nonce expired (stale quote)"
        return null
    }

    /**
     * Verify an attestation. `input` is `{document, ctx, expected, nowMs, trustedAttestorKeys, pqPins?, maxNonceAgeMs?, clockSkewMs?}`: the optional
     * document, the PCActn context `{pcactn, grant}`, the binding the SERVER expects (`{holderPub, grantRef, epoch, nonce, nonceIssuedAt?}`), the
     * verifier's clock and the trusted software attestor keys. In order it requires a document; cross-checks the PCActn against `expected`; requires
     * the document's nonce to be the expected one; establishes the identity and the binding (hardware: the verifier must confirm the report data,
     * and the document's own fields and dates are ignored; software: the mode, the attestor, the signature and `binding` equal to
     * [attestationBinding]); checks freshness (hardware: the server's nonce age, which is required; software: the signed validity window, plus the
     * nonce age when `nonceIssuedAt` is given); and matches the identity against `agent_binding`. The first failure is the result: `{ok, present,
     * bound, reason?, identity?}`; `bound` is true only for a verified, bound attestation. Never throws.
     */
    @JvmStatic @JvmOverloads
    fun verifyAttestation(input: Map<String, Any?>, hardware: HardwareVerifier? = null): Map<String, Any?> {
        val doc = input["document"]
        val present = doc is Map<*, *> || doc is List<*>
        try {
            val ctx = input["ctx"]
            val expected = input["expected"]
            val nowO = input["nowMs"]
            // an unreadable clock would make every window and age comparison false, i.e. pass: refuse
            if (!finite(nowO)) return failed(present, "verifier clock is not a finite time (fail closed)")
            val nowMs = IntentJs.num(nowO)!!
            val trusted = stringSet(input["trustedAttestorKeys"])
            val skew = if (finite(input["clockSkewMs"])) Math.max(0.0, IntentJs.num(input["clockSkewMs"])!!) else 0.0
            val maxAge = Math.min(if (finite(input["maxNonceAgeMs"]) && IntentJs.num(input["maxNonceAgeMs"])!! > 0) IntentJs.num(input["maxNonceAgeMs"])!! else MAX_ATTESTATION_AGE_MS.toDouble(), MAX_ATTESTATION_AGE_MS.toDouble())
            val hasHw = hardware != null

            if (!present) return failed(false, "no attestation document for this action")
            val expectedB64 = try {
                attestationBindingB64u(expected)
            } catch (e: RuntimeException) {
                return failed(true, "attestation binding not constructible: ${msg(e)}")
            }
            if (!ZkJs.strictEq(path(ctx, "pcactn", "grant_ref"), get(expected, "grantRef"))) return failed(true, "attestation binding: PCActn grant_ref differs from expected grant")
            if (!ZkJs.strictEq(path(ctx, "pcactn", "attestation", "epoch"), get(expected, "epoch"))) return failed(true, "attestation binding: PCActn attestation epoch differs from expected epoch")
            if (!ZkJs.strictEq(path(ctx, "pcactn", "attestation", "quote_digest"), get(expected, "nonce"))) return failed(true, "attestation nonce does not bind to this PCActn")
            if (!ZkJs.strictEq(get(doc, "nonce"), get(expected, "nonce"))) return failed(true, "attestation nonce does not match the server-issued nonce")
            val d = doc as Map<String, Any?> // the nonce check passed, so the document is an object

            if (ctx == null) throw IllegalArgumentException("Cannot read properties of null (reading 'grant')")
            val env = Authorize.readEnvelope(get(ctx, "grant"))
            val agentBinding = env?.get("agent_binding")
            val requireHw = get(agentBinding, "require_hardware") == true
            if (requireHw && !hasHw) return failed(true, "agent_binding.require_hardware: no hardware verifier is configured (fail closed)")
            if (requireHw && d["mode"] != "hardware") return failed(true, "agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)")

            val identity: Any?
            if (hasHw) {
                val age = nonceAgeReason(get(expected, "nonceIssuedAt"), nowMs, skew, maxAge)
                if (age != null) return failed(true, age)
                val res = hardware!!.verify(obj("document" to doc, "ctx" to ctx, "nowMs" to nowO, "expected" to expected))
                    ?: throw IllegalArgumentException("Cannot read properties of null (reading 'ok')")
                val hw: Map<String, Any?> = res as? Map<String, Any?> ?: emptyMap()
                if (!ZkJs.truthy(get(hw, "ok"))) {
                    val why = get(hw, "reason")
                    return failed(true, "hardware attestation rejected: " + (if (why == null || why === ZkJs.UNDEF) "invalid" else text(why)))
                }
                if (hw["bound"] != true) return failed(true, "hardware verifier did not confirm report_data binding")
                if (!ZkJs.truthy(get(hw, "measured"))) return failed(true, "hardware verifier returned no measured identity")
                identity = hw["measured"]
            } else {
                if (d["mode"] != "software") return failed(true, "document mode ${text(get(d, "mode"))} needs a hardwareVerifier")
                val attestor = d["attestor"]
                if (attestor !is String || attestor !in trusted) return failed(true, "attestor key is not trusted")
                if (Pq.resolveSigAlg(d["alg"], d.containsKey("alg")) == null) return failed(true, "attestation declares an unknown signature alg")
                var sigOk = false
                if (d["sig"] is String) {
                    val body = LinkedHashMap(d)
                    body.remove("sig")
                    body.remove("pq_sig")
                    sigOk = IntentJs.verifyPinnedSuite(d["alg"], d.containsKey("alg"), attestor, d["pq_pk"], IntentJs.message(DOMAIN, body), d["sig"], d["pq_sig"], input["pqPins"] as? Map<String, Any?>)
                }
                if (!sigOk) return failed(true, "attestation signature does not verify")
                val binding = d["binding"]
                if (binding !is String || binding.isEmpty()) return failed(true, "attestation is not bound (binding absent)")
                if (expectedB64 != binding) return failed(true, "attestation binding mismatch (holder/grant/epoch/nonce)")
                if (!finite(d["issued_at"]) || !finite(d["expires_at"]) || IntentJs.num(d["expires_at"])!! < IntentJs.num(d["issued_at"])!!) {
                    return failed(true, "malformed attestation validity window")
                }
                if (nowMs + skew < IntentJs.num(d["issued_at"])!!) return failed(true, "attestation not yet valid")
                if (nowMs - skew > IntentJs.num(d["expires_at"])!!) return failed(true, "attestation expired")
                if (IntentJs.num(get(expected, "nonceIssuedAt")) != null) {
                    val age = nonceAgeReason(get(expected, "nonceIssuedAt"), nowMs, skew, maxAge)
                    if (age != null) return failed(true, age)
                }
                val soft = LinkedHashMap<String, Any?>()
                for (k in listOf("model_id", "weights_digest", "runtime_measurement", "operator")) if (d.containsKey(k)) soft[k] = d[k]
                if (d["system_prompt_digest"] is String) soft["system_prompt_digest"] = d["system_prompt_digest"]
                if (d["tool_manifest_digest"] is String) soft["tool_manifest_digest"] = d["tool_manifest_digest"]
                identity = soft
            }
            val why = matchAgentBinding(identity, agentBinding)
            if (why != null) return failed(true, why)
            return verdict(true, true, true, null, identity)
        } catch (e: RuntimeException) {
            return failed(present, "attestation verification error (fail closed): ${e.message ?: "unknown"}")
        } catch (e: StackOverflowError) {
            return failed(present, "attestation verification error (fail closed): unknown")
        }
    }

    // ---- the verifier hook ----

    /** The options of [createAttestationVerifier]. */
    class VerifierOptions {
        /** Single-use nonce store: the nonce is consumed ONCE, only after the attestation verified and is bound. Without it the nonce is only checked for age. */
        var nonceStore: NonceStore? = null

        /** Minimum nonce entropy in bytes (null: 16, the floor). Not applied in the self-declared-nonce mode. */
        var minNonceBytes: Any? = null

        /** The b64u public keys trusted to sign software documents (a list; anything else trusts none). */
        var trustedAttestorKeys: Any? = null

        /** Present: HARDWARE mode, which delegates authenticity to this verifier instead of the signature. */
        var hardwareVerifier: HardwareVerifier? = null

        /** How to find the document for an action (null: resolves nothing). */
        var resolveDocument: ((Any?) -> Map<String, Any?>?)? = null

        /** The SERVER-SUPPLIED expected binding of an action (null: none; then the hook fails closed unless the self-declared opt-out is on). */
        var expectedBinding: ((Any?) -> Any?)? = null

        /** LOUD OPT-OUT (legacy, development only): derive the expected binding from the PCActn itself, its `quote_digest` as the nonce. Replay protection is void. */
        var insecureSelfDeclaredNonce: Boolean = false
        var maxNonceAgeMs: Any? = null
        var clockSkewMs: Any? = null

        /** Verifier-pinned PQ keys of the software attestors (Ed25519 identity to ML-DSA public key). */
        var pqPins: Map<String, Any?>? = null

        /** The clock, epoch milliseconds (null: the system clock). */
        var now: (() -> Double)? = null
    }

    /** An attestation hook: `invoke(ctx)` is `{enforced: true, ok, reason?, present, bound}`. Never throws; carries its assurance label. */
    class Hook internal constructor(o: VerifierOptions) : (Any?) -> Map<String, Any?>, Assurance.Labeled {
        private val store = o.nonceStore
        private val minNonceBytes = o.minNonceBytes
        private val maxNonceAgeMs = o.maxNonceAgeMs
        private val clockSkewMs = o.clockSkewMs
        private val trusted: List<Any?> = (o.trustedAttestorKeys as? List<Any?>)?.let { ArrayList(it) } ?: ArrayList()
        private val hardware = o.hardwareVerifier
        private val resolve = o.resolveDocument
        private val expectedBinding = o.expectedBinding
        private val insecure = o.insecureSelfDeclaredNonce
        private val pqPins: Map<String, Any?>? = o.pqPins?.let { LinkedHashMap(it) }
        private val clock: () -> Double = o.now ?: { System.currentTimeMillis().toDouble() }

        // the label comes from the configuration, never from a document
        override val assuranceLabel: Assurance.Label = run {
            val hw = hardware?.let { Assurance.labelOf(it) }
            if (insecure) Assurance.Label("unknown", "insecure-self-declared-nonce", false, null)
            else if (hardware != null) (hw ?: Assurance.Label("unknown"))
            else Assurance.Label("software")
        }

        private fun fin(ok: Boolean, reason: String?, present: Boolean, bound: Boolean): Map<String, Any?> {
            val m = obj("enforced" to true, "ok" to ok)
            if (!reason.isNullOrEmpty()) m["reason"] = reason
            m["present"] = present
            m["bound"] = bound
            return m
        }

        override fun invoke(ctx: Any?): Map<String, Any?> {
            try {
                val document = resolve?.invoke(ctx)
                var expected: Any? = null
                if (expectedBinding != null) {
                    expected = expectedBinding.invoke(ctx)
                } else if (insecure) {
                    val chain = path(ctx, "pcactn", "cap_chain")
                    val leaf = if (chain is List<*> && chain.isNotEmpty()) chain[chain.size - 1] else get(ctx, "grant")
                    val e = LinkedHashMap<String, Any?>()
                    val holder = get(leaf, "holder")
                    e["holderPub"] = if (holder is String) holder else ""
                    for ((k, v) in listOf("grantRef" to path(ctx, "pcactn", "grant_ref"), "epoch" to path(ctx, "pcactn", "attestation", "epoch"), "nonce" to path(ctx, "pcactn", "attestation", "quote_digest"))) if (v !== ZkJs.UNDEF) e[k] = v
                    expected = e
                }
                if (expected == null) return fin(false, "no server-issued attestation nonce/binding available (fail closed)", document != null, false)
                val nonce = defined(get(expected, "nonce"))
                if (!insecure && !nonceEntropyOk(nonce, minNonceBytes)) {
                    return fin(false, "attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)", document != null, false)
                }
                val input = LinkedHashMap<String, Any?>()
                input["document"] = document
                input["ctx"] = ctx
                input["expected"] = expected
                input["nowMs"] = clock()
                input["trustedAttestorKeys"] = trusted
                input["pqPins"] = pqPins
                input["maxNonceAgeMs"] = maxNonceAgeMs
                input["clockSkewMs"] = clockSkewMs
                val v = verifyAttestation(input, hardware)
                val ok = v["ok"] == true
                val bound = v["bound"] == true
                val pres = v["present"] == true
                if (ok && bound && store != null && !store.consume(nonce)) return fin(false, "attestation nonce already consumed (replay)", pres, false)
                return fin(ok, v["reason"] as String?, pres, bound)
            } catch (e: RuntimeException) {
                return fin(false, "attestation verification error (fail closed): ${e.message ?: "unknown"}", false, false)
            } catch (e: StackOverflowError) {
                return fin(false, "attestation verification error (fail closed): unknown", false, false)
            }
        }
    }

    /**
     * The hook over [verifyAttestation]. The expected binding comes from `expectedBinding` (the server-issued nonce); with neither it nor the loud
     * self-declared opt-out the hook fails closed. The nonce must carry 128 bits of entropy and, with a store, is consumed once after a verified,
     * bound attestation.
     */
    @JvmStatic fun createAttestationVerifier(opts: VerifierOptions): Hook = Hook(opts)

    // ---- multi-root ----

    /** One independent attestation root: a distinct hardware or software trust anchor. `suite` is an audit label only. */
    class Root(val id: String, val verifier: HardwareVerifier, val required: Boolean = false, val suite: String? = null)

    private val IDENT_FIELDS = listOf("model_id", "weights_digest", "runtime_measurement", "operator", "system_prompt_digest", "tool_manifest_digest")

    /** The verifier [createMultiRootVerifier] builds: the seam, with an assurance label. */
    class MultiRoot internal constructor(roots: List<Root>, private val threshold: Double) : HardwareVerifier, Assurance.Labeled {
        private val roots: List<Root> = ArrayList(roots)
        override val assuranceLabel: Assurance.Label = Assurance.Label(
            Assurance.multiRootLevel(this.roots.map { Assurance.Root(it.verifier, it.required) }, threshold), "multi-root:" + this.roots.joinToString("+") { it.id }, false, null,
        )

        private fun identOf(measured: Any?): Array<String?> {
            val out = arrayOfNulls<String>(IDENT_FIELDS.size)
            if (measured is Map<*, *>) for (i in out.indices) {
                val v = measured[IDENT_FIELDS[i]]
                out[i] = if (v is String && v.isNotEmpty()) v else null
            }
            return out
        }

        /**
         * Runs EVERY root against the same input; denies when a REQUIRED root did not verify (ok, bound and measured), naming it; denies below the
         * threshold; reconciles the corroborating roots' identities and denies on a contradiction; else returns the reconciled identity with `bound: true`.
         */
        override fun verify(input: Map<String, Any?>): Any? {
            try {
                val passed = ArrayList<Int>()
                val idents = ArrayList<Array<String?>>()
                val measuredFlags = ArrayList<Boolean>()
                val host = LinkedHashMap<String, Any?>()
                for (i in roots.indices) {
                    val root = roots[i]
                    val res: Any? = try {
                        root.verifier.verify(input)
                    } catch (e: RuntimeException) {
                        obj("ok" to false, "reason" to "root '${root.id}' threw (fail closed): ${e.message ?: "unknown"}")
                    } catch (e: StackOverflowError) {
                        obj("ok" to false, "reason" to "root '${root.id}' threw (fail closed): unknown")
                    }
                    val m: Map<String, Any?>? = if (res is Map<*, *>) res as Map<String, Any?> else if (res is List<*>) emptyMap() else null
                    val passes = m != null && m["ok"] == true && m["bound"] == true && ZkJs.truthy(get(m, "measured"))
                    if (passes) {
                        passed.add(i)
                        idents.add(identOf(m!!["measured"]))
                        measuredFlags.add(get(m["measured"], "weights_measured") == true)
                        val ha = m["hostAsserted"]
                        if (ha is Map<*, *>) for ((k, v) in ha) host[root.id + "." + k] = v
                    } else if (root.required) {
                        val why = if (m == null) "root '${root.id}' returned a malformed result (fail closed)" else if (m["reason"] == null) "invalid" else text(m["reason"])
                        return obj("ok" to false, "reason" to "required attestation root '${root.id}' failed: $why")
                    }
                }
                if (passed.size < threshold) {
                    return obj("ok" to false, "reason" to "multi-root attestation below threshold (${passed.size}/${AttestUtil.jsNumString(threshold)} independent roots corroborated)")
                }
                val chosen = arrayOfNulls<String>(IDENT_FIELDS.size)
                for (f in IDENT_FIELDS.indices) {
                    var who = -1
                    for (k in passed.indices) {
                        val v = idents[k][f] ?: continue
                        if (chosen[f] == null) { chosen[f] = v; who = passed[k] }
                        else if (chosen[f] != v) {
                            return obj("ok" to false, "reason" to "multi-root attestation identity conflict: roots '${roots[who].id}' and '${roots[passed[k]].id}' disagree on ${IDENT_FIELDS[f]}")
                        }
                    }
                }
                var weightsMeasured = false
                if (chosen[1] != null) for (k in passed.indices) weightsMeasured = weightsMeasured or (measuredFlags[k] && chosen[1] == idents[k][1])
                val measured = obj(
                    "model_id" to (chosen[0] ?: ""), "weights_digest" to (chosen[1] ?: ""), "weights_measured" to weightsMeasured,
                    "runtime_measurement" to (chosen[2] ?: ""), "operator" to (chosen[3] ?: ""),
                )
                if (chosen[4] != null) measured["system_prompt_digest"] = chosen[4]
                if (chosen[5] != null) measured["tool_manifest_digest"] = chosen[5]
                val out = obj("ok" to true, "bound" to true, "measured" to measured)
                if (host.isNotEmpty()) out["hostAsserted"] = host
                return out
            } catch (e: RuntimeException) {
                return obj("ok" to false, "reason" to "multi-root attestation error (fail closed): ${e.message ?: "unknown"}")
            }
        }
    }

    /**
     * A verifier requiring corroboration from at least `threshold` of the independent `roots`. It plugs into [VerifierOptions.hardwareVerifier] like
     * a single-root verifier. Throws on no roots, a threshold that is not an integer in [1, roots], an empty id or duplicate ids.
     */
    @JvmStatic fun createMultiRootVerifier(roots: List<Root>?, threshold: Double): MultiRoot {
        if (roots == null || roots.isEmpty()) throw IllegalArgumentException("createMultiRootVerifier: at least one attestation root is required")
        if (threshold.isNaN() || threshold.isInfinite() || threshold != Math.rint(threshold) || threshold < 1 || threshold > roots.size) {
            throw IllegalArgumentException("createMultiRootVerifier: threshold must be an integer in [1, roots.length]")
        }
        val ids = HashSet<String>()
        for (r in roots) {
            if (r.id.isEmpty()) throw IllegalArgumentException("createMultiRootVerifier: each root needs a non-empty id")
            if (!ids.add(r.id)) throw IllegalArgumentException("createMultiRootVerifier: duplicate root id '${r.id}'")
        }
        return MultiRoot(roots, threshold)
    }

    // ---- anchoring ----

    /**
     * The canonical, domain-separated digest of a verified attestation `{identity, binding, rootIds?, suite?, verifiedAt}`: the leaf appended to the
     * transparency log. It binds the measured identity AND the holder, grant, epoch and nonce, so two verifications that measured different identities,
     * or bound to different actions, anchor to different leaves. Throws on a member that is missing or has no canonical form.
     */
    @JvmStatic fun attestationEvidenceDigest(ev: Any?): String {
        val identity = get(ev, "identity")
        val binding = get(ev, "binding")
        if (ev !is Map<*, *>) throw IllegalArgumentException("Cannot read properties of undefined (reading 'binding')")
        if (identity !is Map<*, *> || binding !is Map<*, *>) throw IllegalArgumentException("Cannot read properties of undefined")
        val e = ev as Map<String, Any?>
        val id = identity as Map<String, Any?>
        val bind = binding as Map<String, Any?>
        val roots = ArrayList<Any?>()
        val rid = e["rootIds"]
        when {
            rid is List<*> -> roots.addAll(rid)
            rid is String -> rid.codePoints().forEach { roots.add(String(Character.toChars(it))) }
            rid != null -> throw IllegalArgumentException("object is not iterable")
        }
        // Array.prototype.sort() with no comparator orders by the UTF-16 text of each element
        roots.sortWith { a, b -> text(a).compareTo(text(b)) }
        val m = LinkedHashMap<String, Any?>()
        m["domain"] = ATTEST_ANCHOR_DOMAIN
        for ((to, from) in listOf("holder" to "holderPub", "grant" to "grantRef", "epoch" to "epoch", "nonce" to "nonce")) {
            if (!bind.containsKey(from)) throw IllegalArgumentException("canonicalize: unsupported type undefined")
            m[to] = bind[from]
        }
        for (k in listOf("model_id", "weights_digest")) {
            if (!id.containsKey(k)) throw IllegalArgumentException("canonicalize: unsupported type undefined")
            m[k] = id[k]
        }
        m["weights_measured"] = id["weights_measured"] == true
        for (k in listOf("runtime_measurement", "operator")) {
            if (!id.containsKey(k)) throw IllegalArgumentException("canonicalize: unsupported type undefined")
            m[k] = id[k]
        }
        m["system_prompt_digest"] = id["system_prompt_digest"] ?: ""
        m["tool_manifest_digest"] = id["tool_manifest_digest"] ?: ""
        m["roots"] = roots
        m["suite"] = e["suite"] ?: ""
        if (!e.containsKey("verifiedAt")) throw IllegalArgumentException("canonicalize: unsupported type undefined")
        m["verified_at"] = e["verifiedAt"]
        return Pca.hashCanonical(IntentJs.normalize(m))
    }

    /** The options of [anchorAttestationEvidence]. */
    class AnchorOptions {
        /** The transparency log to anchor into (null: no log available, which fails closed). */
        var ledger: MerkleLog? = null

        /** The log's principal, recorded in the tree head. */
        var principal: String = ""

        /** The guardian that signs the tree head; omitted: the commitment is appended but no head is produced (only when not [required]). */
        var guardian: Keys.SuiteKey? = null

        /** The instance id recorded in the head. */
        var instanceId: String? = null

        /** The clock for the head's timestamp, epoch milliseconds (null: the system clock). */
        var now: (() -> Double)? = null

        /** When true, anchoring MUST fully succeed (log present, commitment appended, head signed) or throw. */
        var required: Boolean = false
    }

    private fun anchorFail(why: String) = IllegalStateException("attestation anchoring (fail closed): $why")

    /**
     * Anchor a VERIFIED attestation into the transparency log for post-quantum accountability: compute the evidence digest, append it as a commitment
     * and, with a guardian, sign the resulting tree head (an ml-dsa-65 or hybrid guardian makes the record post-quantum). It does not prevent a forged
     * attestation in real time; it makes one permanently recorded, consistency-checkable and attributable. With `required`, a missing log, a missing
     * guardian or a failed head signature throws instead of skipping. Returns `{index, commit, sth?}`.
     */
    @JvmStatic fun anchorAttestationEvidence(evidence: Any?, opts: AnchorOptions?): Map<String, Any?> {
        val required = opts != null && opts.required
        val ledger = opts?.ledger ?: throw anchorFail("no transparency ledger available")
        if (required && opts.guardian == null) throw anchorFail("required anchoring needs a guardian secret to sign the tree head")
        val commit = attestationEvidenceDigest(evidence)
        val prevRoot = ledger.root()
        val index = ledger.appendCommitment(commit)
        val head = ledger.head()
        var sth: Map<String, Any?>? = null
        val guardian = opts.guardian
        if (guardian != null) {
            val now = (opts.now ?: { System.currentTimeMillis().toDouble() })()
            try {
                sth = Ledger.signTreeHead(guardian, obj(
                    "instance_id" to (opts.instanceId ?: ""), "principal" to opts.principal, "size" to head["size"], "root" to head["root"], "prev_root" to prevRoot,
                    "timestamp" to (if (now == Math.rint(now) && Math.abs(now) < 9e15) StoreJs.num(now.toLong()) else StoreJs.num(now)),
                ))
            } catch (e: RuntimeException) {
                if (required) throw anchorFail("tree-head signing failed: ${e.message ?: "unknown"}")
            }
        }
        val out = obj("index" to IntentJs.ofLong(index.toLong()), "commit" to commit)
        if (sth != null) out["sth"] = sth
        return out
    }
}
