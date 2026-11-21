package net.atlasauth.pca.verifier

/**
 * Signed agent passport verification (packages/pca/src/passport.ts `verifyPassport`): the same reason codes in the same check
 * order (shape, version, suite, issuer, signature, id, validity window, subject, revocation, hardware evidence). Every
 * signature suite this SDK verifies is accepted; a post-quantum / hybrid suite only under a PQ key pinned for the issuer
 * ([Options.pqPins]); a suite it does not implement is `unsupported_suite`. Fail closed, never throws.
 *
 * Hardware: `hardware_rooted` is accepted only with evidence that a hardware verifier validates, bound to the subject key and
 * this passport's id, and whose measured identity equals the claims. The verifier is [Options.attest] (the integrator's, always
 * wins) or the built-in vendor verifier of [Options.defaultHardware] (AMD SEV-SNP, Intel TDX, Azure MAA, Google Confidential
 * Space, NVIDIA GPU: see [Attest.verifierFromConfig]); with neither the passport is refused with `hardware_verifier_missing`.
 */
/**
 * What a hardware verifier is asked for a passport: verify `document` (the carried evidence); the quote's bound value must
 * equal `expected` (holder = the subject key, grant = `passport:<id>`, epoch 0, the evidence nonce).
 */
typealias HardwareAttester = (document: Map<String, Any?>, expected: Attest.Binding) -> Attest.Result

@Suppress("UNCHECKED_CAST")
object Passport {
    const val SIG_DOMAIN = "atlas-pca/passport-sig/v1\u0000"
    const val VERSION = 1L
    const val DEFAULT_EVIDENCE_AGE_MS = 24L * 3_600_000L
    private const val MAX_SKEW_MS = 60_000L

    class Options(
        /** Issuer keys (b64u Ed25519) you trust. Empty trusts nobody. */
        val trustedIssuers: List<String>,
        val nowMs: Long,
        val clockSkewMs: Long? = null,
        val maxEvidenceAgeMs: Long? = null,
        /** When given, the passport's `sub` must equal it. */
        val subject: String? = null,
        /** The PQ public key pinned for each issuer key (required for every non-Ed25519 suite). */
        val pqPins: Map<String, Any?>? = null,
        val attest: HardwareAttester? = null,
        val defaultHardware: Attest.DefaultHardware? = null,
        /** True iff this passport (id, issuer, subject) is revoked; null = no revocation source (`revocation_unavailable`); a throw also denies. */
        val revoked: ((id: String, iss: String, sub: String) -> Boolean)? = null,
    )

    /** The verdict: `reason` is null when the passport verifies, else the reason code; `detail` is optional text. */
    class Verdict(val ok: Boolean, val reason: String?, val detail: String? = null, val passport: Map<String, Any?>? = null, val hardwareVerified: Boolean = false) {
        override fun toString(): String = "Passport.Verdict(ok=$ok, reason=$reason, detail=$detail)"
    }

    private fun bad(reason: String, detail: String? = null) = Verdict(false, reason, detail)

    private fun isStr(x: Any?): Boolean = x is String && x.isNotEmpty()

    /** Content fingerprint over the identity fields (the passport `id`). */
    fun fingerprint(p: Map<String, Any?>): String {
        val fp = LinkedHashMap<String, Any?>()
        fp["d"] = "atlas-pca/passport/v1"
        for (k in listOf("model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement", "operator", "hardware_rooted")) {
            // the three required members have no canonical form when absent (the reference's undefined); the optional digests default to null
            if (!p.containsKey(k) && (k == "model_id" || k == "operator" || k == "hardware_rooted")) throw IllegalArgumentException("canonicalize: unsupported type undefined")
            fp[k] = if (p.containsKey(k)) p[k] else null
        }
        return Pca.hashCanonical(fp)
    }

    private fun strictEq(a: Any?, b: Any?): Boolean = a !is Map<*, *> && a !is List<*> && b !is Map<*, *> && b !is List<*> && IntentJs.jsonEquals(a, b)

    fun verify(sp: Any?, o: Options): Verdict = try {
        verifyUnchecked(sp, o)
    } catch (e: RuntimeException) {
        bad("malformed", e.javaClass.simpleName)
    } catch (e: StackOverflowError) {
        bad("malformed", "StackOverflowError")
    }

    @Suppress("UNCHECKED_CAST")
    private fun verifyUnchecked(sp: Any?, o: Options): Verdict {
        if (sp !is Map<*, *>) return bad("malformed")
        val s = sp as Map<String, Any?>
        val pRaw = s["passport"]
        if (s["typ"] != "atlas-pca/passport" || pRaw == null) return bad("malformed")
        if (!IntentJs.isSafeInteger(s["ver"]) || IntentJs.num(s["ver"]) != VERSION.toDouble()) return bad("unsupported_version", IntentRevocation.jsText(IntentJs.normalize(s["ver"]), s.containsKey("ver")))
        val algPresent = s.containsKey("alg")
        if (algPresent && Pq.resolveSigAlg(s["alg"], true) == null) return bad("unsupported_suite", IntentRevocation.jsText(IntentJs.normalize(s["alg"]), true))
        val p = pRaw as? Map<String, Any?> ?: return bad("malformed")
        if (!isStr(s["iss"]) || !isStr(s["sub"]) || !isStr(s["sig"]) || !isStr(p["id"]) || !isStr(p["model_id"]) || !isStr(p["operator"]) || p["hardware_rooted"] !is Boolean) return bad("malformed")
        val iss = s["iss"] as String
        val sub = s["sub"] as String
        val id = p["id"] as String
        if (!listOf(s["iat"], s["nbf"], s["exp"]).all { IntentJs.isSafeInteger(it) } || Math.abs(o.nowMs) > 9007199254740991L || IntentJs.lng(s["exp"]) <= IntentJs.lng(s["nbf"])) return bad("malformed", "times")
        if (iss !in o.trustedIssuers) return bad("unknown_issuer")
        val body = LinkedHashMap(s)
        body.remove("sig")
        body.remove("pq_sig")
        if (!IntentJs.verifyPinnedSuite(s["alg"], algPresent, iss, s["pq_pk"], IntentJs.message(SIG_DOMAIN, body), s["sig"], s["pq_sig"], o.pqPins)) return bad("bad_signature")
        if (id != fingerprint(p)) return bad("id_mismatch")
        val skew = Math.min(Math.max(o.clockSkewMs ?: 0L, 0L), MAX_SKEW_MS)
        val nbf = IntentJs.lng(s["nbf"])
        val exp = IntentJs.lng(s["exp"])
        if (o.nowMs + skew < nbf) return bad("not_yet_valid")
        if (o.nowMs - skew >= exp) return bad("expired")
        if (o.subject != null && o.subject != sub) return bad("subject_mismatch")
        val rev = o.revoked ?: return bad("revocation_unavailable", "no revocation source")
        val isRevoked = try { rev(id, iss, sub) } catch (e: Throwable) { if (!Contain.ok(e)) throw e; return bad("revocation_unavailable") }
        if (isRevoked) return bad("revoked")
        val hw = p["hardware_rooted"] == true
        if (hw) {
            val ev = s["evidence"] as? Map<String, Any?> ?: emptyMap()
            val doc = ev["document"] as? Map<String, Any?>
            if (doc == null || !isStr(doc["nonce"])) return bad("hardware_evidence_missing")
            if (!IntentJs.isSafeInteger(ev["at"])) return bad("hardware_evidence_missing", "evidence.at")
            val at = IntentJs.lng(ev["at"])
            val maxAge = o.maxEvidenceAgeMs ?: DEFAULT_EVIDENCE_AGE_MS
            if (maxAge < 0 || o.nowMs - at > maxAge || at - o.nowMs > skew) return bad("hardware_evidence_stale")
            var attester: HardwareAttester? = o.attest
            val dh = o.defaultHardware
            if (attester == null && dh != null) attester = dh.attester(o.nowMs)
            if (attester == null) return bad("hardware_verifier_missing")
            val nonce = doc["nonce"] as String
            val r = try {
                attester(doc, Attest.Binding(sub, "passport:$id", 0.0, nonce))
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return bad("hardware_attestation_failed", e.message ?: "error")
            }
            if (!r.ok || !r.bound) return bad("hardware_attestation_failed", r.reason)
            if (!identityMatches(p, r.measured)) return bad("hardware_identity_mismatch")
        }
        return Verdict(true, null, null, p, hw)
    }

    /** The hardware-measured identity equals the claims: model and operator always; the optional digests / runtime measurement when stated; measured weights when claimed. */
    private fun identityMatches(p: Map<String, Any?>, m: Map<String, Any?>?): Boolean {
        if (m == null) return false
        if (!strictEq(m["model_id"], p["model_id"]) || !strictEq(m["operator"], p["operator"])) return false
        for (k in listOf("weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"))
            if (p.containsKey(k) && !strictEq(m[k], p[k])) return false
        if (p["weights_measured"] == true && m["weights_measured"] != true) return false
        return true
    }

    // ---- the reference's own surface: issuing, the binding match, the registry, the trust score, signing and raw verification ----

    private val J = net.atlasauth.pca.compliance.ComplianceJs

    /** `fingerprint` of a decoded identity; throws on null (the reference reads `p.model_id`). */
    @JvmStatic fun passportFingerprint(identity: Any?): String =
        fingerprint(identity as? Map<String, Any?> ?: throw IllegalArgumentException("Cannot read properties of ${if (identity == null) "null" else "undefined"} (reading 'model_id')"))

    /** Issue a passport: the identity with `id` set to its fingerprint. */
    @JvmStatic fun issuePassport(identity: Any?): Map<String, Any?> {
        val id = passportFingerprint(identity)
        val out = LinkedHashMap(identity as Map<String, Any?>)
        out["id"] = id
        return out
    }

    private fun pget(o: Any?, k: String): Any? = ZkJs.get(o, k)

    /** JavaScript `list.includes(v)` over a list (SameValueZero) or a string (substring); anything else cannot be searched. */
    private fun jsIncludes(list: Any?, v: Any?): Boolean = when (list) {
        is List<*> -> v !== ZkJs.UNDEF && list.any { ZkJs.strictEq(it, v) }
        is String -> list.contains(J.tpl(if (v === ZkJs.UNDEF) J.UNDEF else v))
        else -> throw IllegalArgumentException("list.includes is not a function")
    }

    private val SVN_TEXT = Regex("0|[1-9][0-9]*")

    /**
     * Does this passport satisfy a grant's `agent_binding`? Same allowlist semantics as the attestation verifier: an allowlist requires its digest to be present AND listed,
     * the operator when pinned must equal, `require_hardware` demands `hardware_rooted`, `require_measured_weights` demands `weights_measured`, and `min_measurement` is an equality
     * pin (string) or a monotone floor `{svn: n}` over the canonical decimal runtime measurement (anything else fails closed). `{ok, reasons}`; throws for a null passport or binding.
     */
    @JvmStatic fun matchesBinding(p: Any?, b: Any?): Map<String, Any?> {
        if (b == null) throw IllegalArgumentException("Cannot read properties of null (reading 'model_allowlist')")
        if (p == null) throw IllegalArgumentException("Cannot read properties of null (reading 'weights_digest')")
        val reasons = ArrayList<String>()
        fun need(list: Any?, value: Any?, label: String) {
            if (!ZkJs.truthy(list) || (list is List<*> && list.isEmpty())) return
            if (value === ZkJs.UNDEF) reasons.add("$label required by binding but absent from passport")
            else if (!jsIncludes(list, value)) reasons.add("$label '${J.tpl(value)}' not in allowlist")
        }
        val models = pget(b, "model_allowlist")
        if ((models is List<*> && models.isNotEmpty() || models is String && models.isNotEmpty()) && !jsIncludes(models, pget(p, "model_id"))) {
            reasons.add("model_id '${J.tpl(pget(p, "model_id").let { if (it === ZkJs.UNDEF) J.UNDEF else it })}' not in allowlist")
        }
        need(pget(b, "weights_allowlist"), pget(p, "weights_digest"), "weights_digest")
        need(pget(b, "system_prompt_allowlist"), pget(p, "system_prompt_digest"), "system_prompt_digest")
        need(pget(b, "tool_manifest_allowlist"), pget(p, "tool_manifest_digest"), "tool_manifest_digest")
        val op = pget(b, "operator")
        if (op !== ZkJs.UNDEF && !ZkJs.strictEq(pget(p, "operator"), op)) reasons.add("operator '${ZkJs.string(pget(p, "operator"))}' != required '${ZkJs.string(op)}'")
        if (ZkJs.truthy(pget(b, "require_hardware")) && !ZkJs.truthy(pget(p, "hardware_rooted"))) reasons.add("binding requires a hardware-rooted attestation")
        if (ZkJs.truthy(pget(b, "require_measured_weights")) && !ZkJs.truthy(pget(p, "weights_measured"))) reasons.add("binding requires hardware-measured weights")
        val mm = pget(b, "min_measurement")
        if (mm !== ZkJs.UNDEF) {
            val rm = pget(p, "runtime_measurement")
            if (mm is String) {
                if (!ZkJs.strictEq(rm, mm)) reasons.add("runtime_measurement does not equal the pinned measurement")
            } else {
                val bound: Any? = if (mm is Map<*, *> && mm.size == 1) pget(mm, "svn") else ZkJs.UNDEF
                if (!IntentJs.isNonNeg(bound)) {
                    reasons.add("min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)")
                } else {
                    val svn = if (rm is String && SVN_TEXT.matches(rm)) rm.toDouble() else Double.NaN
                    val floor = IntentJs.num(bound)!!
                    if (svn.isNaN() || svn > 9007199254740991.0 || svn < floor) reasons.add("runtime SVN ${ZkJs.string(rm)} < required ${J.numStr(floor)}")
                }
            }
        }
        return linkedMapOf("ok" to reasons.isEmpty(), "reasons" to reasons)
    }

    /** An id-keyed registry of passports: later duplicates replace the earlier in place (first-appearance order); ids are not validated. */
    class PassportRegistry internal constructor(private val byId: LinkedHashMap<String, Map<String, Any?>>) {
        fun get(id: Any?): Map<String, Any?>? = byId[keyOf(id)]
        fun has(id: Any?): Boolean = byId.containsKey(keyOf(id))
        fun all(): List<Map<String, Any?>> = ArrayList(byId.values)
    }

    private fun keyOf(id: Any?): String = when {
        id is String -> "s:$id"
        id == null -> "null"
        id === ZkJs.UNDEF || id === J.UNDEF -> "undefined"
        id is Boolean -> "b:$id"
        IntentJs.num(id) != null -> "n:" + J.numStr(IntentJs.num(id)!!)
        else -> "o:" + System.identityHashCode(id)
    }

    @JvmStatic fun buildRegistry(passports: Any?): PassportRegistry {
        if (passports !is List<*>) throw IllegalArgumentException("passports is not iterable")
        val m = LinkedHashMap<String, Map<String, Any?>>()
        for (p in passports) {
            if (p == null) throw IllegalArgumentException("Cannot read properties of null (reading 'id')")
            m[keyOf(if (p is Map<*, *> && p.containsKey("id")) p["id"] else ZkJs.UNDEF)] = p as? Map<String, Any?> ?: LinkedHashMap()
        }
        return PassportRegistry(m)
    }

    /**
     * A coarse identity-assurance score in [0, 1] from the passport's own completeness (not behavioural reputation): hardware root dominates (0.4); a weights digest adds 0.2
     * when measured, else 0.1; a system prompt and a tool manifest digest add 0.1 each; a known operator adds 0.2. `knownOperators` is the opts member.
     */
    @JvmStatic @JvmOverloads fun trustScore(p: Any?, knownOperators: Any? = null): Double {
        if (p == null) throw IllegalArgumentException("Cannot read properties of null (reading 'hardware_rooted')")
        var s = 0.0
        if (ZkJs.truthy(pget(p, "hardware_rooted"))) s += 0.4
        if (ZkJs.truthy(pget(p, "weights_digest"))) s += if (ZkJs.truthy(pget(p, "weights_measured"))) 0.2 else 0.1
        if (ZkJs.truthy(pget(p, "system_prompt_digest"))) s += 0.1
        if (ZkJs.truthy(pget(p, "tool_manifest_digest"))) s += 0.1
        if (knownOperators != null && jsIncludes(knownOperators, pget(p, "operator"))) s += 0.2
        return Math.max(0.0, Math.min(1.0, s))
    }

    /** The binding a hardware quote must carry for this passport: holder = the subject key, grant = `passport:<id>`, epoch 0, nonce = the evidence nonce. */
    @JvmStatic fun passportEvidenceBinding(passportId: Any?, subject: Any?, nonce: Any?): Map<String, Any?> =
        linkedMapOf("holderPub" to subject, "grantRef" to "passport:" + J.tpl(passportId), "epoch" to Json.Num("0"), "nonce" to nonce)

    private fun passportDomainMessage(body: Map<String, Any?>): ByteArray = IntentJs.message(SIG_DOMAIN, body)

    /**
     * Sign a passport as `issuer` (Ed25519, ML-DSA-65 or hybrid): the passport id must be its fingerprint, `hardware_rooted` needs `evidence`, `iat` defaults to the passport's
     * `issued_at` and `nbf` to `iat`, all three times must be safe integers with `exp > nbf`, and `evidence.at` defaults to `iat`. Throws: a signer never emits a weaker or
     * inconsistent artifact.
     */
    @JvmStatic @JvmOverloads
    fun signPassport(passport: Any?, issuer: Keys.SuiteKey, subject: Any?, exp: Any?, iat: Any? = null, nbf: Any? = null, evidence: Any? = null): Map<String, Any?> {
        val p = passport as? Map<String, Any?> ?: throw IllegalArgumentException("Cannot read properties of ${if (passport == null) "null" else "undefined"} (reading 'id')")
        if (!ZkJs.strictEq(ZkJs.get(p, "id"), passportFingerprint(p))) throw IllegalArgumentException("signPassport: passport.id is not the fingerprint of its identity (use issuePassport)")
        if (ZkJs.truthy(ZkJs.get(p, "hardware_rooted")) && !ZkJs.truthy(evidence)) throw IllegalArgumentException("signPassport: hardware_rooted requires attestation evidence (fail closed)")
        val evAt = if (evidence is Map<*, *> && evidence.containsKey("at")) evidence["at"] else ZkJs.UNDEF
        if (evAt !== ZkJs.UNDEF && !IntentJs.isSafeInteger(evAt)) throw IllegalArgumentException("signPassport: evidence.at must be a safe integer")
        val iatV = iat ?: ZkJs.get(p, "issued_at")
        val nbfV = nbf ?: iatV
        val ev: Any? = if (ZkJs.truthy(evidence)) LinkedHashMap((evidence as? Map<String, Any?>) ?: emptyMap()).also { if (evAt === ZkJs.UNDEF || evAt == null) it["at"] = iatV } else null
        if (!listOf(iatV, nbfV, exp).all { IntentJs.isSafeInteger(it) } || IntentJs.num(exp)!! <= IntentJs.num(nbfV)!!) throw IllegalArgumentException("signPassport: iat/nbf/exp must be safe integers with exp > nbf")
        val body = LinkedHashMap<String, Any?>()
        body["typ"] = "atlas-pca/passport"
        body["ver"] = Json.Num("1")
        body["passport"] = p
        body["iss"] = (issuer.ed ?: throw IllegalArgumentException("signPassport: the issuer needs an Ed25519 identity")).id()
        if (subject !== J.UNDEF) body["sub"] = subject
        body["iat"] = iatV
        body["nbf"] = nbfV
        body["exp"] = exp
        if (ev != null) body["evidence"] = ev
        return Issue.signArtifact(SIG_DOMAIN, body, issuer)
    }

    private fun badV(reason: String, detail: String? = null): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("ok" to false, "reason" to reason)
        if (!detail.isNullOrEmpty()) m["detail"] = detail
        return m
    }

    private fun jsStrOrNull(v: Any?): String? = if (v == null) null else if (v is String) v else J.tpl(v)

    /**
     * The reference's verdict over `o = {trustedIssuers, now, clockSkewMs?, subject?, maxEvidenceAgeMs?, pqPins?}` (decoded JSON, JavaScript comparison semantics), with the
     * revocation source and the hardware verifier of a `hardware_rooted` passport passed as functions: `{ok: true, passport, iss, sub, exp, hardware_verified}` or
     * `{ok: false, reason, detail?}`. A missing revocation source is `revocation_unavailable` and a `hardware_rooted` passport without a verifier is
     * `hardware_verifier_missing`: never downgraded. Never throws. The legacy `allowUnboundPq` option is not offered.
     */
    @JvmStatic @JvmOverloads
    fun verifyPassport(sp: Any?, o: Map<String, Any?>?, revocation: ((Map<String, Any?>) -> Any?)? = null, hardware: Attestation.HardwareVerifier? = null): Map<String, Any?> = try {
        verifyPassportUnchecked(sp, o, revocation, hardware)
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        badV("malformed", e.message ?: "error")
    }

    private fun verifyPassportUnchecked(sp: Any?, o: Map<String, Any?>?, revocation: ((Map<String, Any?>) -> Any?)?, hardware: Attestation.HardwareVerifier?): Map<String, Any?> {
        val s = sp as? Map<String, Any?>
        if (s == null || s["typ"] != "atlas-pca/passport" || !s.containsKey("passport") || s["passport"] == null) return badV("malformed")
        if (IntentJs.num(s["ver"]) != 1.0) return badV("unsupported_version", ZkJs.string(ZkJs.get(s, "ver")))
        val algPresent = s.containsKey("alg")
        if (algPresent && Pq.resolveSigAlg(s["alg"], true) == null) return badV("unsupported_suite", ZkJs.string(s["alg"]))
        val p = s["passport"]
        fun isS(x: Any?) = x is String && x.isNotEmpty()
        if (!isS(s["iss"]) || !isS(s["sub"]) || !isS(s["sig"]) || !isS(pget(p, "id")) || !isS(pget(p, "model_id")) || !isS(pget(p, "operator")) || pget(p, "hardware_rooted") !is Boolean) return badV("malformed")
        if (o == null) throw IllegalArgumentException("Cannot read properties of null (reading 'now')")
        val nowV = ZkJs.get(o, "now")
        if (!listOf(s["iat"], s["nbf"], s["exp"], nowV).all { IntentJs.isSafeInteger(it) } || IntentJs.num(s["exp"])!! <= IntentJs.num(s["nbf"])!!) return badV("malformed", "times")
        val iss = s["iss"] as String
        val sub = s["sub"] as String
        val pm = p as Map<String, Any?>
        val id = pm["id"] as String
        val trusted = ZkJs.get(o, "trustedIssuers")
        if (trusted !is List<*> || trusted.none { ZkJs.strictEq(it, iss) }) return badV("unknown_issuer")
        val body = LinkedHashMap(s)
        body.remove("sig")
        body.remove("pq_sig")
        if (!IntentJs.verifyPinnedSuite(s["alg"], algPresent, iss, s["pq_pk"], passportDomainMessage(body), s["sig"], s["pq_sig"], ZkJs.get(o, "pqPins") as? Map<String, Any?>)) return badV("bad_signature")
        if (id != fingerprint(pm)) return badV("id_mismatch")
        val now = IntentJs.num(nowV)!!
        val skewRaw = ZkJs.get(o, "clockSkewMs")
        val skew = Math.min(Math.max(if (skewRaw === ZkJs.UNDEF || skewRaw == null) 0.0 else J.toNumber(skewRaw), 0.0), MAX_SKEW_MS.toDouble()).let { if (it.isNaN()) 0.0 else it } // NaN skew falls back to none
        if (now + skew < IntentJs.num(s["nbf"])!!) return badV("not_yet_valid")
        if (now - skew >= IntentJs.num(s["exp"])!!) return badV("expired")
        val want = ZkJs.get(o, "subject")
        if (want !== ZkJs.UNDEF && !ZkJs.strictEq(want, sub)) return badV("subject_mismatch")
        if (revocation == null) return badV("revocation_unavailable", "no revocation source")
        val revoked = try {
            revocation(linkedMapOf("id" to id, "iss" to iss, "sub" to sub)) == true
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return badV("revocation_unavailable")
        }
        if (revoked) return badV("revoked")
        val hw = pm["hardware_rooted"] == true
        if (hw) {
            val ev: Any? = if (s["evidence"] == null) emptyMap<String, Any?>() else s["evidence"]
            val doc = ZkJs.get(ev, "document")
            if (!isS(ZkJs.get(doc, "nonce"))) return badV("hardware_evidence_missing")
            val at = ZkJs.get(ev, "at")
            if (!IntentJs.isSafeInteger(at)) return badV("hardware_evidence_missing", "evidence.at")
            val maxRaw = ZkJs.get(o, "maxEvidenceAgeMs")
            val maxAge: Any? = if (maxRaw === ZkJs.UNDEF || maxRaw == null) Json.Num(DEFAULT_EVIDENCE_AGE_MS.toString()) else maxRaw
            val atN = IntentJs.num(at)!!
            if (!IntentJs.isFinite(maxAge) || IntentJs.num(maxAge)!! < 0 || now - atN > IntentJs.num(maxAge)!! || atN - now > skew) return badV("hardware_evidence_stale")
            if (hardware == null) return badV("hardware_verifier_missing")
            val nonce = ZkJs.get(doc, "nonce") as String
            val expected = LinkedHashMap(passportEvidenceBinding(id, sub, nonce))
            expected["nonceIssuedAt"] = nowV
            val r = try {
                hardware.verify(linkedMapOf("document" to doc, "ctx" to LinkedHashMap<String, Any?>(), "nowMs" to nowV, "expected" to expected))
            } catch (e: Throwable) {
                if (!Contain.ok(e)) throw e
                return badV("hardware_attestation_failed", e.message ?: "error")
            }
            val rm = r as? Map<String, Any?>
            if (rm == null || rm["ok"] != true || rm["bound"] != true) return badV("hardware_attestation_failed", jsStrOrNull((r as? Map<*, *>)?.get("reason")))
            val m = rm["measured"]
            fun differs(k: String): Boolean = pm.containsKey(k) && !ZkJs.strictEq(ZkJs.get(m, k), pm[k])
            if (!ZkJs.truthy(m) || !ZkJs.strictEq(ZkJs.get(m, "model_id"), pm["model_id"]) || !ZkJs.strictEq(ZkJs.get(m, "operator"), pm["operator"]) ||
                differs("weights_digest") || differs("runtime_measurement") || differs("system_prompt_digest") || differs("tool_manifest_digest") ||
                (pm["weights_measured"] == true && ZkJs.get(m, "weights_measured") != true)
            ) return badV("hardware_identity_mismatch")
        }
        return linkedMapOf("ok" to true, "passport" to pm, "iss" to iss, "sub" to sub, "exp" to s["exp"], "hardware_verified" to hw)
    }

    /** The assurance label of a verified passport: `software` unless the evidence verified through a hardware verifier, then that verifier's label (`unknown` when it carries none). */
    @JvmStatic @JvmOverloads fun passportAssurance(verdict: Map<String, Any?>, verifier: Any? = null): Map<String, Any?> {
        if (verdict["hardware_verified"] != true) return linkedMapOf("level" to "software")
        val l = Assurance.labelOf(verifier)
        val out = linkedMapOf<String, Any?>("level" to (l?.level ?: "unknown"))
        if (!l?.vendor.isNullOrEmpty()) out["vendor"] = l!!.vendor
        return out
    }
}
