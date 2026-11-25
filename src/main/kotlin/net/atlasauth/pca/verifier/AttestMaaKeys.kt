package net.atlasauth.pca.verifier

import net.atlasauth.pca.compliance.ComplianceJs
import java.math.BigInteger
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Rotation-safe key trust for Azure MAA token-signing keys. The Azure MAA verifier needs `trustAnchors` (SPKI pins), but MAA instance signing certificates
 * ROTATE, so a hard-coded pin silently breaks (or, worse, gets "fixed" by pinning whatever the service returns). This derives `{rootSpkiSha256}` from a freshly
 * fetched `<issuer>/certs` JWKS under an explicit rotation policy, persists the accepted set and fails closed when the policy is violated.
 *
 * Guaranteed: network I/O happens only when [MaaKeyTrust.getTrustAnchors] or [fetchMaaCerts] is called, only for https issuers pinned in `trustedIssuers`, through
 * an injected transport that must not follow redirects, with a response-URL check, a timeout and a body-size limit. Every certificate that contributes an
 * anchor is validated: a self-signed instance certificate has a subject that is EXACTLY `CN=<issuer URL>` (no wildcard, no further RDNs), is genuinely
 * self-signed, inside its validity window (plus skew), no older than `maxKeyAgeMs`, and RSA of 2048..8192 bits or EC P-256, P-384 or P-521; a Microsoft-chained
 * key is used only through a pinned chain root (and, when pinned, a pinned intermediate, which then becomes the anchor). The accepted set changes only by
 * ROTATION (at most `maxNewKeysPerFetch` unseen keys per fetch and, by default, one key in common with the previous unexpired set); a total replacement needs an
 * operator-signed re-pin manifest (`maa-signing-spki` entries labelled with the issuer URL), whose tombstones strip a key even though the JWKS still serves it.
 * Results are cached for `ttlMs`; when a refresh fails at the TRANSPORT level the last accepted set is served for at most `maxStaleMs` after its fetch, then the
 * call fails closed. A policy violation never falls back to stale data. Persisted state is validated on load; `fetchedAtMs` is monotone and a clock behind the
 * stored fetch time fails closed.
 *
 * Not guaranteed: the first accepted set is anchored on the release-signed pins ([AttestMaaPins]) by default, which rests on the release key and the recorded
 * multi-vantage corroboration, not on a Microsoft root for the self-signed instance keys; an issuer the release did not pin needs `initialPins`, a signed
 * re-pin, persisted state or the explicit `allowTrustOnFirstUse` opt-in (use [corroborateMaaKeySets] to make that first use k-vantage-corroborated). A
 * self-signed instance certificate proves "served from this TLS origin", not identity beyond it. A slow, in-policy rotation chain is accepted by design. Rollback
 * of the persisted state is prevented only by a durable store ([durableMaaKeyStateStore]).
 */
@Suppress("UNCHECKED_CAST")
object AttestMaaKeys {
    private const val HOUR = 3_600_000.0
    private const val DAY = 24 * HOUR
    private val ISSUER_URL = Regex("https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?")
    private val HEX64 = Regex("[0-9a-f]{64}")
    private const val MAX_JWKS_KEYS = 32
    private const val MAX_X5C = 8
    private const val MAX_X5C_B64 = 131_072
    private val EC_CURVES = setOf("prime256v1", "secp384r1", "secp521r1")
    private val KINDS = setOf("self-signed", "chained-root", "chained-intermediate")

    // ---- state stores ----

    /** Caller-supplied persistence: the state of an issuer is a JSON tree `{v: 1, issuer, fetchedAtMs, anchors: [...]}`, or null when none is stored. */
    interface MaaKeyStateStore {
        fun get(issuer: String): Any?
        fun set(issuer: String, state: Any?)
    }

    /** In-memory store (tests, one process). Production callers should persist durably. */
    class MemoryMaaKeyStateStore : MaaKeyStateStore {
        private val m = LinkedHashMap<String, Any?>()
        override fun get(issuer: String): Any? = MemoryAtomicKv.copyTree(m[issuer])
        override fun set(issuer: String, state: Any?) { m[issuer] = MemoryAtomicKv.copyTree(state) }

        fun snapshot(): Map<String, Any?> = LinkedHashMap(m)
    }

    /**
     * Persist the accepted key sets in an [AtomicKv] (key `maa-keys/<issuer>`). Writes are atomic read-modify-write and MONOTONE in `fetchedAtMs`: a stale writer
     * never moves the stored state backwards. A corrupt stored record is returned as it is so [MaaKeyTrust.getTrustAnchors] fails closed (`corrupt-state`).
     */
    @JvmStatic
    fun durableMaaKeyStateStore(kv: AtomicKv): MaaKeyStateStore = object : MaaKeyStateStore {
        private fun k(issuer: String) = "maa-keys/$issuer"
        override fun get(issuer: String): Any? = kv.get(k(issuer))
        override fun set(issuer: String, state: Any?) {
            kv.update(k(issuer)) { prev ->
                val p = if (prev == null) null else parseState(prev, issuer)
                // `p.fetchedAtMs > state.fetchedAtMs`: an incomparable (absent / NaN) value is never smaller, so the write goes through
                val incoming = (state as? Map<*, *>)?.get("fetchedAtMs")?.let { IntentJs.num(it) }
                if (p != null && incoming != null && p.fetchedAtMs > incoming) null else state
            }
        }
    }

    // ---- guarded fetch ----

    /** What the injected transport returns for one GET: the HTTP status, the body bytes, the final URL (null when unknown) and the `content-length` header text. */
    class MaaHttpResponse @JvmOverloads constructor(val status: Int, val body: ByteArray, val url: String? = null, val contentLength: String? = null) {
        val ok: Boolean get() = status in 200..299
    }

    /** The injected transport: GET `url` accepting JSON, WITHOUT following redirects (a redirect is an error). A throw is a transport failure. */
    fun interface MaaFetch {
        fun fetch(url: String): MaaHttpResponse
    }

    private fun typeError(msg: String): Nothing = throw IllegalArgumentException(msg)

    /**
     * Fetch `<issuer>/certs` with https only, a timeout (`timeoutMs`, default 10 s) and a size limit (`maxBytes`, default 1 MiB), and return the JWKS
     * `{keys: [{kid?, kty?, alg?, x5c: [base64 DER]}]}` (at most 32 keys, each with 1..8 non-empty x5c entries). THROWS on any problem.
     */
    @JvmStatic @JvmOverloads
    fun fetchMaaCerts(issuer: String, fetch: MaaFetch?, timeoutMs: Any? = null, maxBytes: Any? = null): Map<String, Any?> {
        if (fetch == null) typeError("fetchMaaCerts: a fetch implementation must be injected")
        if (!ISSUER_URL.matches(issuer)) typeError("fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)")
        val timeout = if (timeoutMs != null) IntentJs.num(timeoutMs) ?: Double.NaN else 10_000.0
        val limit = if (maxBytes != null) IntentJs.num(maxBytes) ?: Double.NaN else 1_048_576.0
        val url = "$issuer/certs"
        val work = CompletableFuture.supplyAsync { fetch.fetch(url) }
        val res: MaaHttpResponse = try {
            work.get(timeout.toLong(), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            work.cancel(true)
            throw IllegalStateException("MAA certs fetch timed out after ${timeout.toLong()} ms")
        } catch (e: ExecutionException) {
            throw (e.cause as? RuntimeException) ?: IllegalStateException(e.cause?.message ?: "fetch error")
        }
        if (!res.ok) throw IllegalStateException("MAA certs fetch failed: HTTP ${res.status}")
        if (!res.url.isNullOrEmpty() && res.url != url) throw IllegalStateException("MAA certs fetch: response URL differs from the request (redirect)")
        val declared = ComplianceJs.toNumber(res.contentLength ?: "0")
        if (!declared.isNaN() && !declared.isInfinite() && declared > limit) throw IllegalStateException("MAA certs response exceeds the size limit")
        if (res.body.size > limit) throw IllegalStateException("MAA certs response exceeds the size limit")
        val parsed: Any? = try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(res.body)).toString()
            Json.parseNoDuplicates(if (text.startsWith("﻿")) text.substring(1) else text) // a UTF-8 decoder drops one leading BOM
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw IllegalStateException("MAA certs response is not valid UTF-8 JSON")
        } catch (e: IllegalArgumentException) {
            throw IllegalStateException("MAA certs response is not valid UTF-8 JSON")
        }
        return parseJwks(parsed)
    }

    private fun parseJwks(x: Any?): Map<String, Any?> {
        val raw = (x as? Map<*, *>)?.get("keys") as? List<*> ?: throw IllegalStateException("MAA certs: response has no keys array")
        if (raw.size > MAX_JWKS_KEYS) throw IllegalStateException("MAA certs: too many keys")
        val keys = ArrayList<Any?>()
        for (k in raw) {
            if (k !is Map<*, *> && k !is List<*>) throw IllegalStateException("MAA certs: malformed key entry")
            val r: Map<*, *> = (k as? Map<*, *>) ?: emptyMap<Any?, Any?>()
            val x5c = r["x5c"]
            if (x5c !is List<*> || x5c.isEmpty() || x5c.size > MAX_X5C || x5c.any { it !is String || it.isEmpty() || it.length > MAX_X5C_B64 }) {
                throw IllegalStateException("MAA certs: key without a well-formed x5c")
            }
            val out = LinkedHashMap<String, Any?>()
            for (f in listOf("kid", "kty", "alg")) if (r[f] is String) out[f] = r[f]
            out["x5c"] = ArrayList(x5c)
            keys.add(out)
        }
        return linkedMapOf("keys" to keys)
    }

    // ---- JWKS evaluation ----

    private fun nameCn(subject: String): String? {
        val lines = subject.split("\n").filter { it.isNotEmpty() }
        if (lines.size != 1) return null
        return if (lines[0].startsWith("CN=")) lines[0].substring(3) else null
    }

    private fun leafCn(subject: String): String? {
        for (l in subject.split("\n")) if (l.startsWith("CN=")) return l.substring(3)
        return null
    }

    private fun rsaKeyOk(k: AttestCert.CertKey): Boolean {
        if (k.typ != "rsa" && k.typ != "rsa-pss") return true
        val pk = k.pub as? java.security.interfaces.RSAPublicKey ?: return false
        val bits = pk.modulus.bitLength()
        val e = pk.publicExponent
        if (bits < 512 || bits > 16384) return false
        return e.testBit(0) && e >= BigInteger.valueOf(3) && e.bitLength() <= 32
    }

    private fun keyStrengthError(k: AttestCert.CertKey): String? {
        if (k.typ == "rsa") {
            val bits = (k.pub as java.security.interfaces.RSAPublicKey).modulus.bitLength()
            if (!(bits in 2048..8192)) return "RSA key size $bits outside 2048..8192"
            return if (rsaKeyOk(k)) null else "RSA public exponent must be odd, at least 3 and at most 32 bits"
        }
        if (k.typ == "ec") return if (k.curve in EC_CURVES) null else "EC curve '${k.curve}' not allowed"
        return "key type '${k.typ}' not allowed"
    }

    private fun safeVerify(c: AttestCert.Cert, signer: AttestCert.Cert): Boolean = try {
        val k = AttestCert.keyOfCert(signer)
        rsaKeyOk(k) && AttestCert.certSigOk(c, k)
    } catch (e: RuntimeException) {
        false
    }

    private fun parseCert(x: Any?): AttestCert.Cert {
        if (x !is String) {
            throw IllegalArgumentException("The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received ${if (x == null) "null" else "type ${if (x is Map<*, *> || x is List<*>) "object" else if (x is Boolean) "boolean" else "number"} (${ZkJs.string(x)})"}")
        }
        return AttestCert.parseCertDer(AttestUtil.nodeB64(x))
    }

    private class Window(val from: Double, val to: Double)

    private fun validity(c: AttestCert.Cert): Window {
        val (f, t) = AttestDer.derValidity(c.raw)
        return Window(if (f.ok) f.ms.toDouble() else Double.NaN, if (t.ok) t.ms.toDouble() else Double.NaN)
    }

    private class Accepted(val spki: String, val kind: String, val from: Double, val to: Double)

    private fun policyNum(p: Map<String, Any?>, k: String, default: Double): Double = if (p[k] != null) IntentJs.num(p[k]) ?: Double.NaN else default

    private fun lowerSet(v: Any?): Set<String> = (v as? List<*>)?.map { (it as String).lowercase() }?.toSet() ?: emptySet()

    private fun evaluate(jwks: Any?, issuer: String, policy: Map<String, Any?>, nowMs: Double): Pair<List<Accepted>, List<Pair<Any?, String>>> {
        val skew = policyNum(policy, "clockSkewMs", 60_000.0)
        val maxAge = policyNum(policy, "maxKeyAgeMs", 400 * DAY)
        val roots = lowerSet(policy["chainRootSpkiSha256"])
        val inters = lowerSet(policy["chainIntermediateSpkiSha256"])
        val leafCns = policy["chainLeafCn"] as? List<Any?>
        val accepted = LinkedHashMap<String, Accepted>()
        val rejected = ArrayList<Pair<Any?, String>>()
        val keys = (jwks as? Map<*, *>)?.get("keys") as? List<*> ?: emptyList<Any?>()
        for ((i, keyAny) in keys.withIndex()) {
            val key = keyAny as Map<String, Any?>
            val kid: Any? = key["kid"] ?: "#$i"
            try {
                val x5c = key["x5c"]
                if (x5c !is List<*> || x5c.isEmpty()) {
                    rejected.add(Pair(kid, "no x5c"))
                    continue
                }
                val certs = x5c.map { parseCert(it) }
                val leaf = certs[0]
                for ((j, c) in certs.withIndex()) {
                    val v = validity(c)
                    if (v.from.isNaN() || v.to.isNaN()) throw IllegalStateException("cert $j: unparsable validity")
                    if (!(nowMs + skew >= v.from)) throw IllegalStateException("cert $j: not yet valid")
                    if (!(nowMs - skew <= v.to)) throw IllegalStateException("cert $j: expired")
                }
                val lv = validity(leaf)
                val leafKey = AttestCert.keyOfCert(leaf)
                keyStrengthError(leafKey)?.let { throw IllegalStateException(it) }
                val leafSubject = AttestCert.nameText(leaf.rawSubject)
                if (certs.size == 1) {
                    if (!(nowMs - lv.from <= maxAge)) throw IllegalStateException("key older than maxKeyAgeMs")
                    val cn = nameCn(leafSubject) ?: throw IllegalStateException("subject is not a single CN")
                    if (cn.contains('*')) throw IllegalStateException("wildcard CN rejected")
                    if (cn != issuer) throw IllegalStateException("subject CN does not equal the issuer URL")
                    if (AttestCert.nameText(leaf.rawIssuer) != leafSubject || !safeVerify(leaf, leaf)) throw IllegalStateException("not a genuine self-signed cert")
                    val spki = leafKey.spkiSha256()
                    accepted[spki] = Accepted(spki, "self-signed", lv.from, lv.to)
                    continue
                }
                // Chained key: only under an explicitly pinned root (and, when configured, a pinned intermediate).
                if (roots.isEmpty()) throw IllegalStateException("chained key ignored (no chainRootSpkiSha256 configured)")
                for (j in 0 until certs.size - 1) if (!safeVerify(certs[j], certs[j + 1])) throw IllegalStateException("chain link $j is not signed by the next cert")
                val profile = AttestCert.strictChainError(certs)
                if (profile != "") throw IllegalStateException("chain profile: $profile")
                val top = certs[certs.size - 1]
                if (AttestCert.nameText(top.rawIssuer) != AttestCert.nameText(top.rawSubject) || !safeVerify(top, top)) throw IllegalStateException("chain does not end in a self-signed root")
                val rootSpki = AttestCert.keyOfCert(top).spkiSha256()
                if (rootSpki !in roots) throw IllegalStateException("chain root is not pinned")
                if (leafCns != null && (leafCn(leafSubject) ?: "\u0000") !in leafCns) throw IllegalStateException("chained leaf CN not allowed")
                val top2 = validity(top)
                var anchorSpki = rootSpki
                var anchorKind = "chained-root"
                var anchorFrom = top2.from
                var anchorTo = top2.to
                if (inters.isNotEmpty()) {
                    // The pinned intermediate must sit strictly between leaf and root; it (not the shared root) becomes the anchor.
                    val mid = certs.subList(1, certs.size - 1).firstOrNull { AttestCert.keyOfCert(it).spkiSha256() in inters }
                        ?: throw IllegalStateException("chain does not pass through a pinned intermediate")
                    val mv = validity(mid)
                    anchorSpki = AttestCert.keyOfCert(mid).spkiSha256()
                    anchorKind = "chained-intermediate"
                    anchorFrom = mv.from
                    anchorTo = mv.to
                }
                val prev = accepted[anchorSpki]
                accepted[anchorSpki] = Accepted(
                    anchorSpki, anchorKind, if (prev != null) Math.min(prev.from, anchorFrom) else anchorFrom, Math.min(anchorTo, Math.max(prev?.to ?: 0.0, lv.to)),
                )
            } catch (e: RuntimeException) {
                rejected.add(Pair(kid, e.message ?: "invalid key"))
            }
        }
        return Pair(accepted.values.toList(), rejected)
    }

    private fun rec(a: Accepted): LinkedHashMap<String, Any?> =
        linkedMapOf("spki" to a.spki, "kind" to a.kind, "notBeforeMs" to IntentJs.ofLong(a.from.toLong()), "notAfterMs" to IntentJs.ofLong(a.to.toLong()))

    /**
     * Validate every key of a JWKS against `policy` at `nowMs`. Never throws: `{accepted: [{spki, kind, notBeforeMs, notAfterMs}], rejected: [{kid, reason}]}`.
     * `policy` fields used here: `clockSkewMs` (60 s), `maxKeyAgeMs` (400 days), `chainRootSpkiSha256`, `chainIntermediateSpkiSha256`, `chainLeafCn`.
     */
    @JvmStatic
    fun evaluateMaaJwks(jwks: Any?, issuer: String, policy: Map<String, Any?>, nowMs: Double): Map<String, Any?> {
        val (acc, rej) = evaluate(jwks, issuer, policy, nowMs)
        return linkedMapOf("accepted" to acc.map { rec(it) }, "rejected" to rej.map { linkedMapOf("kid" to it.first, "reason" to it.second) })
    }

    // ---- trust store ----

    private class Anchor(val spki: String, val kind: String, val from: Long, val to: Long, val firstSeen: Long) {
        fun toMap(): LinkedHashMap<String, Any?> = linkedMapOf(
            "spki" to spki, "kind" to kind, "notBeforeMs" to IntentJs.ofLong(from), "notAfterMs" to IntentJs.ofLong(to), "firstSeenMs" to IntentJs.ofLong(firstSeen),
        )
    }

    private class State(val fetchedAtMs: Long, val anchors: List<Anchor>)

    private fun safeNonNegZero(x: Any?): Boolean = IntentJs.isSafeInteger(x) && !IntentJs.isNegZero(IntentJs.num(x)!!)

    private fun parseState(x: Any?, issuer: String): State? {
        if (x !is Map<*, *>) return null
        if (x["v"] == null || IntentJs.num(x["v"]) != 1.0 || x["issuer"] != issuer || !safeNonNegZero(x["fetchedAtMs"]) || x["anchors"] !is List<*>) return null
        val anchors = ArrayList<Anchor>()
        for (a in x["anchors"] as List<*>) {
            if (a !is Map<*, *>) return null
            val spki = a["spki"]
            if (spki !is String || !HEX64.matches(spki)) return null
            val kind = a["kind"]
            if (kind !is String || kind !in KINDS) return null
            if (!listOf("notBeforeMs", "notAfterMs", "firstSeenMs").all { safeNonNegZero(a[it]) }) return null
            anchors.add(Anchor(spki, kind, IntentJs.lng(a["notBeforeMs"]), IntentJs.lng(a["notAfterMs"]), IntentJs.lng(a["firstSeenMs"])))
        }
        return State(IntentJs.lng(x["fetchedAtMs"]), anchors)
    }

    /** The trust object [createMaaKeyTrust] builds. */
    class MaaKeyTrust internal constructor(private val policy: Map<String, Any?>, private val store: MaaKeyStateStore, private val fetch: MaaFetch) {
        private val trusted = (policy["trustedIssuers"] as List<*>).toSet()
        private val ttl = policyNum(policy, "ttlMs", HOUR)
        private val maxStale = policyNum(policy, "maxStaleMs", DAY)
        private val maxNew = policyNum(policy, "maxNewKeysPerFetch", 2.0)
        private val maxInitial = policyNum(policy, "maxInitialKeys", 8.0)
        private val skew = policyNum(policy, "clockSkewMs", 60_000.0)
        private val requireOverlap = if (policy["requireOverlap"] != null) ZkJs.truthy(policy["requireOverlap"]) else true

        private fun fail(code: String, reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "code" to code, "reason" to reason)

        private fun live(a: List<Anchor>, nowMs: Double): List<Anchor> = a.filter { nowMs - skew <= it.to.toDouble() && nowMs + skew >= it.from.toDouble() }

        private fun build(source: String, anchors: List<Anchor>, newKeys: List<String>, removed: List<String>, rejected: List<Map<String, Any?>>): Map<String, Any?> {
            val spkis = anchors.map { it.spki }.toSortedSet().toList()
            if (spkis.isEmpty()) return fail("no-valid-keys", "no unexpired, un-revoked signing keys remain")
            return linkedMapOf(
                "ok" to true, "trustAnchors" to linkedMapOf("rootSpkiSha256" to spkis), "source" to source, "anchors" to anchors.map { it.toMap() }, "newKeys" to newKeys,
                "removedKeys" to removed, "rejected" to rejected,
            )
        }

        /**
         * The anchors for `issuer` at `nowMs`: `{ok: true, trustAnchors: {rootSpkiSha256}, source: cache | fetched | stale-cache, anchors, newKeys, removedKeys,
         * rejected}` (ready for the Azure MAA verifier), or `{ok: false, code, reason}` with `code` one of untrusted-issuer, corrupt-state, clock-regression,
         * fetch-failed, stale-exceeded, no-valid-keys, no-baseline, too-many-new-keys, no-overlap, repin-invalid, builtin-pins-invalid. `repin` is
         * `{manifest, verify}`: an operator-signed allowlist manifest carrying `maa-signing-spki` entries labelled with the issuer URL, and its verification
         * options (`nowMs` is supplied here).
         */
        @JvmOverloads
        fun getTrustAnchors(issuer: String, nowArg: Any?, repin: Map<String, Any?>? = null): Map<String, Any?> {
            try {
                if (issuer !in trusted) return fail("untrusted-issuer", "issuer is not in policy.trustedIssuers")
                if (!IntentJs.isSafeInteger(nowArg)) return fail("clock-regression", "nowMs must be an integer")
                val nowMs = IntentJs.num(nowArg)!!

                // Operator approvals and revocations (a re-pin manifest).
                val approved = LinkedHashSet<String>()
                val denied = LinkedHashSet<String>()
                if (repin != null) {
                    val opts = LinkedHashMap(repin["verify"] as Map<String, Any?>)
                    opts["nowMs"] = nowArg
                    val v = AttestAllowlist.verifyAllowlistManifest(repin["manifest"], opts)
                    if (v["ok"] != true) return fail("repin-invalid", "${v["code"]}: ${v["reason"]}")
                    val p = AttestAllowlist.projectAllowlist(v, nowMs)
                    for (s in ((p["maaSigningSpkis"] as Map<String, Any?>)[issuer] as List<Any?>? ?: emptyList())) approved.add(s as String)
                    for (r in p["revoked"] as List<Map<String, Any?>>) if (r["kind"] == "maa-signing-spki" && r["label"] == issuer) denied.add(r["value"] as String)
                }
                // Built-in release-signed pins (default on): the offline root of the first accepted set.
                var effPolicy: Map<String, Any?> = policy
                var builtinBaseline: List<String> = emptyList()
                var builtinReason: String? = null
                if (policy["builtinPins"] != false) {
                    val src = policy["builtinPins"] as? Map<String, Any?>
                    val b = AttestMaaPins.loadBuiltinMaaPins(linkedMapOf<String, Any?>("nowMs" to nowArg).also { if (src != null) it["source"] = src })
                    if (b["ok"] == true) {
                        builtinBaseline = ((b["maaSigningSpkis"] as Map<String, Any?>)[issuer] as List<Any?>? ?: emptyList()).map { it as String }
                        for (r in ((b["revokedSigningSpkis"] as Map<String, Any?>)[issuer] as List<Any?>? ?: emptyList())) denied.add(r as String)
                        val eff = LinkedHashMap(policy)
                        if (eff["chainRootSpkiSha256"] == null) eff["chainRootSpkiSha256"] = b["maaChainRootSpkis"]
                        if (eff["chainIntermediateSpkiSha256"] == null) eff["chainIntermediateSpkiSha256"] = b["maaChainIntermediateSpkis"]
                        if (eff["chainLeafCn"] == null) eff["chainLeafCn"] = ArrayList(AttestMaaPins.BUILTIN_CHAIN_LEAF_CN)
                        effPolicy = eff
                        // The pinned Microsoft intermediate only counts for issuers the release actually pinned (no leak to others).
                        if (builtinBaseline.isNotEmpty()) builtinBaseline = builtinBaseline + (b["maaChainIntermediateSpkis"] as List<Any?>).map { it as String }
                    } else builtinReason = b["reason"] as String
                }
                fun allow(a: List<Anchor>) = a.filter { it.spki !in denied }

                val rawState = store.get(issuer)
                var state: State? = null
                if (rawState != null) {
                    state = parseState(rawState, issuer) ?: return fail("corrupt-state", "persisted MAA key state failed validation")
                    if (!(nowMs >= state.fetchedAtMs - skew)) return fail("clock-regression", "clock is behind the last persisted fetch time")
                }

                // 1. Fresh cache.
                if (state != null && nowMs - state.fetchedAtMs < ttl && nowMs >= state.fetchedAtMs) {
                    val a = allow(live(state.anchors, nowMs))
                    if (a.isNotEmpty()) return build("cache", a, emptyList(), emptyList(), emptyList())
                }

                // 2. Refresh.
                val jwks: Map<String, Any?> = try {
                    fetchMaaCerts(issuer, fetch, policy["fetchTimeoutMs"], policy["maxBodyBytes"])
                } catch (e: RuntimeException) {
                    val why = e.message ?: "fetch error"
                    if (state == null) return fail("fetch-failed", "$why; no cached key set")
                    if (!(nowMs - state.fetchedAtMs <= maxStale)) return fail("stale-exceeded", "$why; cached set is older than maxStaleMs")
                    val a = allow(live(state.anchors, nowMs))
                    if (a.isEmpty()) return fail("stale-exceeded", "$why; every cached key has expired or been revoked")
                    return build("stale-cache", a, emptyList(), emptyList(), emptyList())
                }

                val (evAccepted, evRejected) = evaluate(jwks, issuer, effPolicy, nowMs)
                val accepted = evAccepted.filter { it.spki !in denied }
                if (accepted.isEmpty()) {
                    return fail("no-valid-keys", "no JWKS key passed validation (${evRejected.joinToString("; ") { "${ZkJs.string(it.first)}: ${it.second}" }.ifEmpty { "empty JWKS" }})")
                }

                // 3. Rotation policy.
                val prevAnchors = if (state != null) live(state.anchors, nowMs) else emptyList()
                val baseline = LinkedHashSet<String>(prevAnchors.map { it.spki })
                if (state == null) {
                    for (p in ((policy["initialPins"] as? Map<String, Any?>)?.get(issuer) as? List<Any?>) ?: emptyList()) baseline.add((p as String).lowercase())
                    for (p in builtinBaseline) baseline.add(p)
                }
                for (p in builtinBaseline) approved.add(p)
                val acceptedSet = LinkedHashSet(accepted.map { it.spki })
                val approvedHere = acceptedSet.filter { it in approved }
                val unapprovedNew = acceptedSet.filter { it !in baseline && it !in approved }
                if (baseline.isEmpty()) {
                    if (approvedHere.isEmpty() && !ZkJs.truthy(policy["allowTrustOnFirstUse"])) {
                        if (builtinReason != null) return fail("builtin-pins-invalid", "built-in pins unusable ($builtinReason); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use")
                        return fail("no-baseline", "no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use")
                    }
                    if (acceptedSet.size > maxInitial && approvedHere.size < acceptedSet.size) return fail("too-many-new-keys", "initial set of ${acceptedSet.size} keys exceeds maxInitialKeys")
                } else {
                    if (unapprovedNew.size > maxNew) return fail("too-many-new-keys", "${unapprovedNew.size} new keys exceed maxNewKeysPerFetch=${maxNew.toLong()}")
                    val overlap = acceptedSet.any { it in baseline } || approvedHere.isNotEmpty()
                    if (requireOverlap && !overlap) return fail("no-overlap", "the new key set shares no key with the previous set and is not covered by a signed re-pin")
                }

                // 4. Persist (monotone fetchedAtMs) and return.
                val firstSeen = HashMap<String, Long>()
                state?.anchors?.forEach { firstSeen[it.spki] = it.firstSeen }
                val records = accepted.map { Anchor(it.spki, it.kind, it.from.toLong(), it.to.toLong(), firstSeen[it.spki] ?: nowMs.toLong()) }
                val fetchedAtMs = if (state != null) Math.max(state.fetchedAtMs.toDouble(), nowMs).toLong() else nowMs.toLong()
                store.set(
                    issuer, linkedMapOf("v" to IntentJs.ofLong(1), "issuer" to issuer, "fetchedAtMs" to IntentJs.ofLong(fetchedAtMs), "anchors" to records.map { it.toMap() }),
                )
                val newKeys = records.filter { it.spki !in baseline }.map { it.spki }
                val removed = baseline.filter { it !in acceptedSet }
                val rejected = evRejected.map { linkedMapOf<String, Any?>("kid" to it.first, "reason" to it.second) }
                return build("fetched", records, newKeys, removed, rejected)
            } catch (e: RuntimeException) {
                return fail("fetch-failed", e.message ?: "unexpected error")
            }
        }
    }

    /**
     * Build the key trust over `policy` (`trustedIssuers` (non-empty https origins), `ttlMs` 1 h, `maxStaleMs` 24 h, `maxNewKeysPerFetch` 2, `maxInitialKeys` 8,
     * `maxKeyAgeMs` 400 days, `requireOverlap` true, `allowTrustOnFirstUse` false, `initialPins`, `chainRootSpkiSha256`, `chainIntermediateSpkiSha256`,
     * `builtinPins` (default on; false disables; an object substitutes another signed source), `chainLeafCn`, `clockSkewMs` 60 s, `fetchTimeoutMs` 10 s,
     * `maxBodyBytes` 1 MiB), a state store and the injected transport. The policy is copied: later edits change nothing.
     */
    @JvmStatic
    fun createMaaKeyTrust(policy: Map<String, Any?>?, store: MaaKeyStateStore, fetch: MaaFetch?): MaaKeyTrust {
        if (fetch == null) typeError("createMaaKeyTrust: fetch must be injected")
        val issuers = policy?.get("trustedIssuers") as? List<*>
        if (issuers == null || issuers.isEmpty() || issuers.any { it !is String || !ISSUER_URL.matches(it) }) {
            typeError("createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs")
        }
        return MaaKeyTrust(LinkedHashMap(policy!!), store, fetch)
    }

    // ---- multi-vantage corroboration ----

    private fun bad(code: String, reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "code" to code, "reason" to reason)

    /**
     * Accept a FIRST-USE key set only if at least `k` (>= 2) DISTINCT vantage points observed the same issuer and ALL supplied observations validate (per
     * [evaluateMaaJwks]) to the IDENTICAL SPKI set. Any disagreement, even from a single vantage beyond the k, fails closed (a divergent view is evidence of a
     * path attack or an in-flight rotation). `sets` is a list of `{vantage, issuer, jwks}`, `opts` is `{issuer, nowMs, policy?}`. The result
     * `{ok: true, issuer, spkis, vantages, k}` is directly usable as `initialPins[issuer]`; a refusal is `{ok: false, code, reason}`. Guarantees only what the
     * vantage labels honestly are: independence is the caller's claim. It defeats an attacker on ONE network path to the issuer, not one on k of them.
     */
    @JvmStatic
    fun corroborateMaaKeySets(sets: Any?, k: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        try {
            if (!IntentJs.isSafeInteger(k) || IntentJs.num(k)!! < 2) return bad("malformed", "k must be an integer >= 2")
            val kk = IntentJs.num(k)!!
            val o = opts ?: return bad("malformed", "issuer/nowMs invalid")
            val issuer = o["issuer"]
            if (issuer !is String || !ISSUER_URL.matches(issuer) || !IntentJs.isSafeInteger(o["nowMs"])) return bad("malformed", "issuer/nowMs invalid")
            if (sets !is List<*>) return bad("malformed", "sets must be an array")
            val nowMs = IntentJs.num(o["nowMs"])!!
            val policy = linkedMapOf<String, Any?>("trustedIssuers" to listOf(issuer))
            (o["policy"] as? Map<String, Any?>)?.let { policy.putAll(it) }
            val byVantage = LinkedHashMap<String, String>()
            for (o in sets) {
                val ov = o as? Map<*, *>
                val vantage = ov?.get("vantage")
                if (ov == null || vantage !is String || vantage.isEmpty() || vantage.length > 100) return bad("malformed", "vantage label must be a non-empty string")
                if (ov["issuer"] != issuer) return bad("malformed", "observation from '$vantage' is for a different issuer")
                val (acc, rej) = evaluate(ov["jwks"], issuer, policy, nowMs)
                if (acc.isEmpty()) return bad("no-valid-keys", "vantage '$vantage' observed no valid key (${rej.joinToString("; ") { it.second }.ifEmpty { "empty" }})")
                val fp = acc.map { it.spki }.sorted().joinToString(",")
                val prior = byVantage[vantage]
                if (prior != null && prior != fp) return bad("vantage-disagreement", "vantage '$vantage' supplied two different key sets")
                byVantage[vantage] = fp
            }
            if (byVantage.size < kk) return bad("insufficient-vantages", "${byVantage.size} distinct vantage(s) < k=${kk.toLong()}")
            val distinct = LinkedHashSet(byVantage.values)
            if (distinct.size != 1) {
                return bad("vantage-disagreement", "vantages disagree: " + byVantage.entries.joinToString(" | ") { (v, f) -> "$v=" + f.split(",").joinToString("+") { it.take(8) } })
            }
            return linkedMapOf("ok" to true, "issuer" to issuer, "spkis" to distinct.first().split(","), "vantages" to byVantage.keys.sorted(), "k" to IntentJs.ofLong(kk.toLong()))
        } catch (e: RuntimeException) {
            return bad("malformed", e.message ?: "corroboration error")
        }
    }
}
