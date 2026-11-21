package net.atlasauth.pca.verifier

/**
 * Signed, versioned, expiring measurement-allowlist manifests for the hardware-attestation verifiers (Azure MAA, Intel DCAP, SEV-SNP, GCP Confidential
 * Space, NVIDIA GPU-CC): an operator publishes one signed manifest and a relying party verifies it and projects it into the policy fields each verifier takes.
 *
 * Given a trustworthy issuer-key registry and clock, an `ok` verification means: the body was signed, over a domain-separated canonical encoding, by a
 * REGISTERED issuer key under the algorithm registered FOR THAT ISSUER (no downgrade; a hybrid needs both halves); the manifest is inside its validity window
 * and its version is not older than the floor or the last accepted one (the same version with a different body is a conflict); values are well formed and unique
 * per kind (unknown kinds and members are refused); revoked and expired entries are never projected. It does not decide who the issuer is, and an allowlist
 * says "acceptable", not "secure". Rollback protection has three layers: the `lastSeen*` options (you persist), [verifyAllowlistDurable] (a hash-chained
 * high-water mark in a durable store) and the transparency anchor ([AttestAllowlistAnchor]).
 *
 * Manifests, options and results are decoded JSON (maps, lists, strings, numbers).
 */
@Suppress("UNCHECKED_CAST")
object AttestAllowlist {
    @JvmField val ALLOWLIST_KINDS: List<String> = listOf(
        "tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "gcp-image-digest", "nvidia-measurement", "nvidia-driver-version",
        "maa-signing-spki", "maa-chain-root-spki", "maa-chain-intermediate-spki", "attest-corroboration",
    )
    const val DOMAIN = "pca-attest-allowlist/v1\n"
    private val HEX96 = Regex("[0-9a-f]{96}")
    private val HEX64 = Regex("[0-9a-f]{64}")
    private val IMAGE_DIGEST = Regex("sha256:[0-9a-f]{64}")
    private val DRIVER_VERSION = Regex("[0-9]{1,6}(\\.[0-9]{1,6}){1,3}")
    private val CORROBORATION_LABEL = Regex("vantages=[1-9][0-9]{0,2};method=[\\x20-\\x7e]{1,150}")
    private val ISSUER_URL = Regex("https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?")
    private val B64U_DIGEST = Regex("[A-Za-z0-9_-]{43}")
    private val BODY_KEYS = setOf("version", "issuedAt", "notBefore", "expiresAt", "entries")
    private val ENTRY_KEYS = setOf("kind", "value", "label", "notAfter", "revoked")
    private val MANIFEST_KEYS = setOf("body", "issuer", "alg", "sig", "pq_sig")
    private const val MAX_ENTRIES = 10_000

    private fun isRecord(x: Any?): Boolean = x is Map<*, *>
    private fun onlyKeys(r: Map<*, *>, allowed: Set<String>): Boolean = r.keys.all { it in allowed }
    private fun hasControlChar(s: String): Boolean = s.any { it.code <= 0x1f || it.code == 0x7f }
    private fun isEpoch(x: Any?): Boolean = IntentJs.isInt(x) && IntentJs.num(x)!! >= 0
    private fun isNumberType(x: Any?): Boolean = IntentJs.num(x) != null
    private fun typeError(msg: String): Nothing = throw IllegalArgumentException(msg)

    private fun valueError(kind: String, value: String, label: String): String? = when (kind) {
        "tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "nvidia-measurement" -> if (HEX96.matches(value)) null else "$kind must be 96 lowercase hex chars"
        "gcp-image-digest" -> if (IMAGE_DIGEST.matches(value)) null else "gcp-image-digest must be sha256:<64 lowercase hex>"
        "nvidia-driver-version" -> if (DRIVER_VERSION.matches(value) && value.length <= 16) null else "nvidia-driver-version must be a dotted version of at most 16 chars"
        "maa-signing-spki" ->
            if (!HEX64.matches(value)) "maa-signing-spki must be 64 lowercase hex chars"
            else if (ISSUER_URL.matches(label)) null else "maa-signing-spki label must be the https issuer URL (no path, no trailing slash)"
        "maa-chain-root-spki", "maa-chain-intermediate-spki" -> if (HEX64.matches(value)) null else "$kind must be 64 lowercase hex chars"
        else ->
            if (!HEX64.matches(value)) "attest-corroboration must be a 64 lowercase hex evidence digest"
            else if (CORROBORATION_LABEL.matches(label)) null else "attest-corroboration label must be vantages=<n>;method=<text>"
    }

    /** Strictly validate and copy an untrusted body; throws on the first violation. */
    private fun parseBody(x: Any?): LinkedHashMap<String, Any?> {
        if (x !is Map<*, *> || !onlyKeys(x, BODY_KEYS)) typeError("body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries")
        val version = x["version"]
        val issuedAt = x["issuedAt"]
        val notBefore = x["notBefore"]
        val expiresAt = x["expiresAt"]
        val entries = x["entries"]
        if (!IntentJs.isSafeInteger(version) || IntentJs.num(version)!! < 1) typeError("version must be a positive integer")
        if (!isEpoch(issuedAt) || !isEpoch(notBefore) || !isEpoch(expiresAt)) typeError("issuedAt/notBefore/expiresAt must be integer epoch ms")
        if (!(IntentJs.num(notBefore)!! < IntentJs.num(expiresAt)!!)) typeError("notBefore must be before expiresAt")
        if (!(IntentJs.num(issuedAt)!! <= IntentJs.num(expiresAt)!!)) typeError("issuedAt must not be after expiresAt")
        if (entries !is List<*> || entries.size > MAX_ENTRIES) typeError("entries must be an array (bounded)")
        val seen = HashSet<String>()
        val out = ArrayList<Any?>()
        for ((i, e) in entries.withIndex()) {
            if (e !is Map<*, *> || !onlyKeys(e, ENTRY_KEYS)) typeError("entry $i: unexpected shape")
            val kind = e["kind"]
            val value = e["value"]
            val label = e["label"]
            if (kind !is String || kind !in ALLOWLIST_KINDS) typeError("entry $i: unknown kind")
            if (value !is String || label !is String) typeError("entry $i: value and label must be strings")
            if (label.isEmpty() || label.length > 200 || hasControlChar(label)) typeError("entry $i: label must be 1..200 printable chars")
            valueError(kind, value, label)?.let { typeError("entry $i: $it") }
            if (e.containsKey("notAfter") && !isEpoch(e["notAfter"])) typeError("entry $i: notAfter must be integer epoch ms")
            if (e.containsKey("revoked") && e["revoked"] != true) typeError("entry $i: revoked, when present, must be true")
            val dup = "$kind\u0000" + (if (kind == "maa-signing-spki") "$label\u0000" else "") + value
            if (!seen.add(dup)) typeError("entry $i: duplicate $kind value")
            val clean = linkedMapOf<String, Any?>("kind" to kind, "value" to value, "label" to label)
            if (e.containsKey("notAfter")) clean["notAfter"] = IntentJs.ofLong(IntentJs.lng(e["notAfter"]))
            if (e["revoked"] == true) clean["revoked"] = true
            out.add(clean)
        }
        return linkedMapOf(
            "version" to IntentJs.ofLong(IntentJs.lng(version)), "issuedAt" to IntentJs.ofLong(IntentJs.lng(issuedAt)), "notBefore" to IntentJs.ofLong(IntentJs.lng(notBefore)),
            "expiresAt" to IntentJs.ofLong(IntentJs.lng(expiresAt)), "entries" to out,
        )
    }

    private fun signedBytes(body: Map<String, Any?>): ByteArray = IntentJs.message(DOMAIN, IntentJs.normalize(body))

    private fun jsNum(x: Any?): String = IntentJs.lng(x).toString()

    private fun fail(code: String, reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "code" to code, "reason" to reason)

    private fun pqPinFor(prim: Pq.Prim?, k: Map<String, Any?>): PinnedPq? {
        val slot = when (prim) {
            Pq.Prim.ML_DSA_65 -> "mlDsaPub"
            Pq.Prim.SLH_DSA_SHA2_128F -> "slhDsaPub"
            Pq.Prim.ML_DSA_87 -> "mlDsa87Pub"
            Pq.Prim.SLH_DSA_SHA2_256S -> "slhDsa256sPub"
            Pq.Prim.FN_DSA_512 -> "fnDsa512Pub"
            Pq.Prim.FN_DSA_1024 -> "fnDsa1024Pub"
            else -> "lessCat1Pub"
        }
        return PinnedPq.resolve(null, null, trustedPk = k[slot] as? String)
    }

    /**
     * Verify a signed manifest `{body, issuer, alg, sig, pq_sig?}` with `opts` `{issuerKeys, nowMs, minVersion?, lastSeenVersion?, lastSeenDigest?, clockSkewMs?,
     * maxLifetimeMs?}`; `issuerKeys` maps an issuer id to `{alg, keys: {edPub?, mlDsaPub?, slhDsaPub?, mlDsa87Pub?, slhDsa256sPub?}, notAfter?}` (public keys,
     * base64url, configured by the VERIFIER). Never throws: the result is `{ok: true, body, issuer, alg, version, digest}` or `{ok: false, code, reason}` with
     * `code` one of malformed, unknown-issuer, issuer-expired, alg-mismatch, bad-signature, not-yet-valid, expired, rollback, below-min-version, conflict,
     * lifetime-too-long.
     */
    @JvmStatic
    fun verifyAllowlistManifest(manifest: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        try {
            if (manifest !is Map<*, *> || !onlyKeys(manifest, MANIFEST_KEYS)) return fail("malformed", "manifest has an unexpected shape")
            val nowRaw = opts?.get("nowMs")
            if (!IntentJs.isSafeInteger(nowRaw)) return fail("malformed", "nowMs must be an integer")
            val nowMs = IntentJs.num(nowRaw)!!
            val issuer = manifest["issuer"]
            val alg = manifest["alg"]
            val sig = manifest["sig"]
            val hasPq = manifest.containsKey("pq_sig")
            val pqSig = manifest["pq_sig"]
            if (issuer !is String || issuer.isEmpty() || issuer.length > 200) return fail("malformed", "issuer must be a string")
            if (alg !is String || alg !in Pq.REGISTERED_SUITES) return fail("malformed", "unknown signature alg")
            if (sig !is String) return fail("malformed", "sig must be a string")
            if (hasPq && pqSig !is String) return fail("malformed", "pq_sig must be a string")
            val suite = Pq.resolveSigAlg(alg, true)
            val needsPqSig = suite?.needsPqSig ?: alg.startsWith("hybrid")
            if (needsPqSig != hasPq) return fail("malformed", "pq_sig presence does not match the suite")
            val body = try {
                parseBody(manifest["body"])
            } catch (e: IllegalArgumentException) {
                return fail("malformed", e.message ?: "invalid body")
            }
            val o = opts!! // present: a missing nowMs was refused above
            val issuerKeys = o["issuerKeys"] as Map<String, Any?>
            if (!issuerKeys.containsKey(issuer)) return fail("unknown-issuer", "issuer '$issuer' is not registered")
            val reg = issuerKeys[issuer] as Map<String, Any?>
            if (reg["alg"] != alg) return fail("alg-mismatch", "issuer is registered for '${ZkJs.string(reg["alg"])}', manifest claims '$alg'")
            if (reg.containsKey("notAfter") && !(nowMs <= net.atlasauth.pca.compliance.ComplianceJs.toNumber(reg["notAfter"]))) return fail("issuer-expired", "issuer key is past its notAfter")
            val keys = reg["keys"] as Map<String, Any?>
            val pin = if (suite != null && suite.needsPqPk) pqPinFor(suite.pq, keys) else null
            if (suite == null || !Pq.verifySuite(alg, true, keys["edPub"] as? String, pin, signedBytes(body), sig, if (hasPq) pqSig else null)) {
                return fail("bad-signature", "signature does not verify under the registered issuer key")
            }
            // The signature is good: the rest is policy over authentic content. Numeric options are validated, never coerced: a NaN skew would make both
            // window comparisons false, and a NaN limit would silently disable its own check.
            fun has(k: String) = o.containsKey(k)
            if (has("clockSkewMs") && !IntentJs.isFinite(o["clockSkewMs"])) return fail("malformed", "clockSkewMs must be a finite number")
            if (has("maxLifetimeMs") && !IntentJs.isFinite(o["maxLifetimeMs"])) return fail("malformed", "maxLifetimeMs must be a finite number")
            if (has("minVersion") && !IntentJs.isSafeInteger(o["minVersion"])) return fail("malformed", "minVersion must be an integer")
            if (has("lastSeenVersion") && !IntentJs.isSafeInteger(o["lastSeenVersion"])) return fail("malformed", "lastSeenVersion must be an integer")
            val skew = Math.max(0.0, if (has("clockSkewMs")) IntentJs.num(o["clockSkewMs"])!! else 0.0)
            val notBefore = IntentJs.num(body["notBefore"])!!
            val expiresAt = IntentJs.num(body["expiresAt"])!!
            val version = IntentJs.num(body["version"])!!
            if (!(nowMs + skew >= notBefore)) return fail("not-yet-valid", "manifest is not yet valid")
            if (!(nowMs - skew <= expiresAt)) return fail("expired", "manifest has expired")
            if (has("maxLifetimeMs") && expiresAt - notBefore > IntentJs.num(o["maxLifetimeMs"])!!) return fail("lifetime-too-long", "manifest lifetime exceeds maxLifetimeMs")
            if (has("minVersion") && version < IntentJs.num(o["minVersion"])!!) return fail("below-min-version", "version ${IntentJs.lng(body["version"])} < minVersion ${jsNum(o["minVersion"])}")
            val digest = Pca.hashCanonical(IntentJs.normalize(body))
            if (has("lastSeenVersion")) {
                val last = IntentJs.num(o["lastSeenVersion"])!!
                if (version < last) return fail("rollback", "version ${IntentJs.lng(body["version"])} is older than last seen ${jsNum(o["lastSeenVersion"])}")
                if (version == last && has("lastSeenDigest") && o["lastSeenDigest"] != digest) return fail("conflict", "same version as last seen but a different body")
            }
            return linkedMapOf("ok" to true, "body" to body, "issuer" to issuer, "alg" to alg, "version" to body["version"], "digest" to digest)
        } catch (e: RuntimeException) {
            return fail("malformed", e.message ?: "verification error")
        }
    }

    // ---- durable high-water mark ----

    /** The stored high-water mark `{version, digest}` of an issuer, or null when the record is absent or not exactly that shape. */
    private fun parseHighWater(x: Any?): Pair<Double, String>? {
        if (x !is Map<*, *>) return null
        val v = x["version"]
        val d = x["digest"]
        if (!IntentJs.isSafeInteger(v) || IntentJs.isNegZero(IntentJs.num(v)!!) || d !is String || !B64U_DIGEST.matches(d)) return null
        return Pair(IntentJs.num(v)!!, d)
    }

    private sealed class Kv {
        object Missing : Kv()
        object Corrupt : Kv()
        data class Val(val v: Double, val d: String) : Kv()
    }

    private fun kvOf(raw: Any?, present: Boolean): Kv = if (!present) Kv.Missing else parseHighWater(raw)?.let { Kv.Val(it.first, it.second) } ?: Kv.Corrupt

    // Versions are append-only: a record whose version is already >= ours is kept as stored (an equal version with another digest is reported as a conflict).
    private fun updateFn(cur: Kv, v: Double, d: String): Kv = if (cur is Kv.Corrupt) cur else if (cur is Kv.Val && cur.v >= v) cur else Kv.Val(v, d)

    /**
     * [verifyAllowlistManifest] with the rollback high-water mark in durable state: the stored `{version, digest}` per issuer (key `allowlist/<issuer>`) is fed in
     * as `lastSeen*`, and an accepted manifest advances it atomically (it only ever moves up; a newer acceptance by another process turns this one into a
     * `rollback`). A corrupt record fails closed with `malformed`. Deleting the whole store resets it; the transparency anchor covers that.
     */
    @JvmStatic
    fun verifyAllowlistDurable(manifest: Any?, opts: Map<String, Any?>?, kv: AtomicKv): Map<String, Any?> {
        try {
            val issuer = if (manifest is Map<*, *> && manifest["issuer"] is String && (manifest["issuer"] as String).length <= 200) manifest["issuer"] as String else null
            if (issuer == null) return fail("malformed", "issuer must be a string")
            val key = "allowlist/$issuer"
            val raw = kv.get(key)
            val present = raw != null || key in kv.keys()
            val prior = if (present) parseHighWater(raw) else null
            val read = kvOf(raw, present)
            if (read is Kv.Corrupt) return fail("malformed", "persisted allowlist high-water mark is corrupt")
            val merged = LinkedHashMap(opts ?: emptyMap())
            if (prior != null) {
                merged["lastSeenVersion"] = IntentJs.ofLong(prior.first.toLong())
                merged["lastSeenDigest"] = prior.second
            }
            val v = verifyAllowlistManifest(manifest, merged)
            if (v["ok"] != true) return v
            val ver = IntentJs.num(v["version"])!!
            val dig = v["digest"] as String
            var now: Kv? = null
            val stored = kv.update(key) { cur ->
                val c = kvOf(cur, cur != null)
                now = c
                val next = updateFn(c, ver, dig)
                if (next is Kv.Val && next != c) linkedMapOf("version" to IntentJs.ofLong(ver.toLong()), "digest" to dig) else null
            }
            var nowKv = now
            if (nowKv == null) {
                // The store answered without running the updater: its record IS the record at update time. Nothing parseable stored means our
                // acceptance was never recorded: fail closed as a rollback, never accept unpersisted.
                val s = (if (stored == null) null else parseHighWater(stored)) ?: return fail("rollback", "a newer manifest was accepted concurrently")
                nowKv = Kv.Val(s.first, s.second)
            }
            val after = updateFn(nowKv, ver, dig)
            return when {
                after !is Kv.Val -> fail("rollback", "a newer manifest was accepted concurrently")
                after.v > ver -> fail("rollback", "a newer manifest was accepted concurrently")
                after.v == ver && after.d != dig -> fail("conflict", "same version as the stored high-water mark but a different body")
                else -> v
            }
        } catch (e: RuntimeException) {
            return fail("malformed", e.message ?: "durable verification error")
        }
    }

    // ---- operator tools ----

    /** Validate operator input and return the canonical body; throws on any violation. */
    @JvmStatic fun createAllowlistManifest(input: Any?): Map<String, Any?> = parseBody(input)

    /** Sign `body` with an issuer key under `alg`; throws when the body is invalid or the key material for the suite is missing. */
    @JvmStatic
    fun signAllowlistManifest(body: Any?, issuer: String, alg: Any?, ed: Keys.EdKey?, pq: Keys.PqKey?): Map<String, Any?> {
        val clean = parseBody(body)
        val suite = Pq.resolveSigAlg(alg, true) ?: throw IllegalArgumentException(Pq.refusal(alg))
        val key = Keys.suite(suite.alg, if (suite.hasEd25519) ed else null, if (suite.pq != null) pq else null)
        val sg = key.sign(signedBytes(clean))
        val out = linkedMapOf<String, Any?>("body" to clean, "issuer" to issuer, "alg" to suite.alg, "sig" to sg.first)
        if (sg.second != null) out["pq_sig"] = sg.second
        return out
    }

    /**
     * The next body that revokes `kind`/`value` (adds or flips a tombstone) with `version + 1`; it must be re-signed. `rev` is `{kind, value, label?}`, `times`
     * `{issuedAt, notBefore, expiresAt}`. For a `maa-signing-spki` the label must match too. Throws when the result is not a valid body.
     */
    @JvmStatic
    fun revokeAllowlistEntry(prev: Map<String, Any?>, rev: Map<String, Any?>, times: Map<String, Any?>): Map<String, Any?> {
        val entries = (prev["entries"] as List<Any?>).map { LinkedHashMap(it as Map<String, Any?>) }.toMutableList()
        val hit = entries.firstOrNull { it["kind"] == rev["kind"] && it["value"] == rev["value"] && (rev["kind"] != "maa-signing-spki" || it["label"] == rev["label"]) }
        if (hit != null) hit["revoked"] = true
        else entries.add(linkedMapOf("kind" to rev["kind"], "value" to rev["value"], "label" to (rev["label"] ?: "revoked"), "revoked" to true))
        val next = linkedMapOf<String, Any?>("version" to IntentJs.ofLong(IntentJs.lng(prev["version"]) + 1))
        next.putAll(times)
        next["entries"] = entries
        return parseBody(next)
    }

    /** Zero-padded 16-byte-slot hex of a dotted driver version (the form `NvidiaCcPolicy.driverVersions` takes). */
    @JvmStatic
    fun driverVersionSlotHex(version: String): String {
        if (!DRIVER_VERSION.matches(version) || version.length > 16) throw IllegalArgumentException("invalid driver version")
        return version.toByteArray(Charsets.US_ASCII).joinToString("") { "%02x".format(it) }.padEnd(32, '0')
    }

    // ---- projection ----

    /**
     * Project a VERIFIED manifest (the `ok` result of [verifyAllowlistManifest]) into policy arrays at `nowMs`. Revoked entries and entries past their own
     * `notAfter` are excluded, and a value revoked anywhere is excluded wherever else it appears.
     */
    @JvmStatic
    fun projectAllowlist(verified: Map<String, Any?>, nowMs: Double): Map<String, Any?> {
        val body = verified["body"] as Map<String, Any?>
        val tdxMrtds = ArrayList<Any?>()
        val tdxRtmrs = ArrayList<Any?>()
        val sev = ArrayList<Any?>()
        val images = ArrayList<Any?>()
        val nvM = ArrayList<Any?>()
        val nvV = ArrayList<Any?>()
        val nvCc = ArrayList<Any?>()
        val maa = LinkedHashMap<String, Any?>()
        val roots = ArrayList<Any?>()
        val inters = ArrayList<Any?>()
        val corr = ArrayList<Any?>()
        val revoked = ArrayList<Any?>()
        val expired = ArrayList<Any?>()
        val entries = (body["entries"] as List<Any?>).map { it as Map<String, Any?> }
        val denied = HashSet<String>()
        fun ref(e: Map<String, Any?>) = linkedMapOf("kind" to e["kind"], "value" to e["value"], "label" to e["label"])
        for (e in entries) if (e["revoked"] == true) {
            denied.add("${e["kind"]}\u0000${e["value"]}")
            revoked.add(ref(e))
        }
        for (e in entries) {
            if (e["revoked"] == true) continue
            if ("${e["kind"]}\u0000${e["value"]}" in denied) continue
            if (e.containsKey("notAfter") && !(nowMs <= IntentJs.num(e["notAfter"])!!)) {
                expired.add(ref(e))
                continue
            }
            val value = e["value"] as String
            when (e["kind"]) {
                "tdx-mrtd" -> tdxMrtds.add(value)
                "tdx-rtmr" -> tdxRtmrs.add(value)
                "sev-snp-measurement" -> sev.add(value)
                "gcp-image-digest" -> images.add(value)
                "nvidia-measurement" -> nvM.add(value)
                "nvidia-driver-version" -> { nvV.add(value); nvCc.add(driverVersionSlotHex(value)) }
                "maa-signing-spki" -> (maa.getOrPut(e["label"] as String) { ArrayList<Any?>() } as MutableList<Any?>).add(value)
                "maa-chain-root-spki" -> roots.add(value)
                "maa-chain-intermediate-spki" -> inters.add(value)
                "attest-corroboration" -> corr.add(linkedMapOf("value" to value, "label" to e["label"]))
            }
        }
        return linkedMapOf(
            "tdxMrtds" to tdxMrtds, "tdxRtmrs" to tdxRtmrs, "sevSnpMeasurements" to sev, "imageDigests" to images, "nvidiaMeasurements" to nvM, "nvidiaDriverVersions" to nvV,
            "nvidiaCcDriverVersions" to nvCc, "maaSigningSpkis" to maa, "maaChainRootSpkis" to roots, "maaChainIntermediateSpkis" to inters, "corroboration" to corr,
            "revoked" to revoked, "expired" to expired, "version" to body["version"], "manifestExpiresAt" to body["expiresAt"],
        )
    }

    private fun list(p: Map<String, Any?>, k: String): List<Any?> = ArrayList(p[k] as List<Any?>)

    /** Fields for the Azure MAA verifier's policy; empty lists are omitted. */
    @JvmStatic
    fun azureMaaPolicyFields(p: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        if (list(p, "tdxMrtds").isNotEmpty()) m["tdxMrtds"] = list(p, "tdxMrtds")
        if (list(p, "sevSnpMeasurements").isNotEmpty()) m["sevSnpMeasurements"] = list(p, "sevSnpMeasurements")
        if (list(p, "tdxRtmrs").isNotEmpty()) m["tdxRtmrs"] = list(p, "tdxRtmrs")
        return m
    }

    /** Fields for the Intel DCAP verifier's policy: `mrtds` is always present (an empty list makes the verifier refuse to build). */
    @JvmStatic
    fun intelDcapPolicyFields(p: Map<String, Any?>): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("mrtds" to list(p, "tdxMrtds"))
        if (list(p, "tdxRtmrs").isNotEmpty()) m["rtmrs"] = list(p, "tdxRtmrs")
        return m
    }

    @JvmStatic fun sevSnpPolicyFields(p: Map<String, Any?>): Map<String, Any?> = linkedMapOf("measurements" to list(p, "sevSnpMeasurements"))

    @JvmStatic fun gcpCsPolicyFields(p: Map<String, Any?>): Map<String, Any?> = linkedMapOf("imageDigests" to list(p, "imageDigests"))

    /** Fields for the NVIDIA policy; the driver gate is omitted when the manifest has no driver entries. */
    @JvmStatic
    fun nvidiaCcPolicyFields(p: Map<String, Any?>): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>("measurements" to list(p, "nvidiaMeasurements"))
        if (list(p, "nvidiaCcDriverVersions").isNotEmpty()) m["driverVersions"] = list(p, "nvidiaCcDriverVersions")
        return m
    }
}
