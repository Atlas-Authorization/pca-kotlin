package net.atlasauth.pca.notary

import java.security.MessageDigest
import java.security.SecureRandom
import net.atlasauth.pca.grants.GrantSigning
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * External-fact attestation for proof-carrying actions (the zkTLS / TLSNotary direction). A NOTARY witnesses one HTTP
 * request/response and signs a canonical record of it: method, URL, a digest of the request headers, the response status and a
 * salted-Merkle COMMITMENT to the response body. The prover can later disclose ONE field with an inclusion proof while every other
 * field stays hidden (each leaf carries a random salt), and bind the fact to a specific PCActn.
 *
 * TRUST BOUNDARY: this relies on a trusted or semi-trusted notary that actually observed the TLS session. It is not trustless zkTLS
 * (MPC-TLS): a colluding or compromised notary can attest anything. Every verification fails CLOSED.
 *
 * Values are JSON-shaped (maps, lists, strings, [Json.Num] / Long / Int numbers). A key is a b64u String, raw ByteArray (public key)
 * or a [Keys.EdKey].
 */
object Notary {
    /** Algorithm tag for the body commitment (salted RFC-6962-shape Merkle tree over SHA-256). */
    const val BODY_COMMIT_ALG = "salted-merkle-sha256-v1"

    /** Caveat type tag for "this action is admitted only if a notarized external fact holds". */
    const val ATTESTED_FACT_CAVEAT = "attested_fact"

    private const val NOTARY_DOMAIN = "atlas-pca/notary/v1\u0000"

    // ---- helpers ----

    @Suppress("UNCHECKED_CAST")
    private fun asMap(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private fun asList(o: Any?): List<Any?>? = o as? List<Any?>

    /** Number.isSafeInteger over the JSON-shaped values (a -0 lexeme counts, as in JavaScript). */
    private fun isSafeIntJs(o: Any?): Boolean {
        if (o is Json.Num && o.raw == "-0") return true
        return Json.isSafeInt(o)
    }

    private fun isNegZero(o: Any?): Boolean = o is Json.Num && o.raw == "-0"

    /** `o === 1` for a JSON-shaped value. */
    private fun isOne(o: Any?): Boolean = Json.isSafeInt(o) && Json.asLong(o) == 1L

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    /** Canonical equality over JSON values (same strict canonical bytes). Fails closed (false) on any error. */
    private fun canonicalEqual(a: Any?, b: Any?): Boolean = try {
        Pca.hashCanonical(a) == Pca.hashCanonical(b)
    } catch (e: RuntimeException) {
        false
    }

    private fun req(m: Map<String, Any?>?, k: String): Any? {
        if (m == null || !m.containsKey(k)) throw IllegalArgumentException("canonicalize: unsupported type undefined")
        return m[k]
    }

    /** Normalize a disclosure path: a list is copied; a bare string is a single top-level key. */
    private fun normalizePath(path: Any?): MutableList<Any?> {
        if (path is String) return arrayListOf(path)
        val l = asList(path) ?: throw IllegalArgumentException("path.slice is not a function")
        return ArrayList(l)
    }

    /** The b64u public key of a key input: a b64u string, raw public-key bytes or a key pair. */
    private fun toPubB64u(key: Any?): String = when (key) {
        is String -> key
        is ByteArray -> Keys.b64u(key)
        is Keys.EdKey -> key.id()
        else -> throw IllegalArgumentException("unsupported key")
    }

    // ---- body flattening ----

    private class BareLeaf(val path: List<Any?>, val value: Any?)

    private fun plus(prefix: List<Any?>, seg: Any?): List<Any?> = ArrayList<Any?>(prefix).also { it.add(seg) }

    private fun flatten(value: Any?, prefix: List<Any?>, out: MutableList<BareLeaf>) {
        val arr = asList(value)
        if (arr != null) {
            if (arr.isEmpty()) { out.add(BareLeaf(prefix, ArrayList<Any?>())); return }
            for (i in arr.indices) flatten(arr[i], plus(prefix, i.toLong()), out)
            return
        }
        val obj = asMap(value)
        if (obj != null) {
            val keys = ArrayList(obj.keys)
            keys.sortWith { a, b -> Json.compareUtf8(a, b) }
            if (keys.isEmpty()) { out.add(BareLeaf(prefix, LinkedHashMap<String, Any?>())); return }
            for (k in keys) flatten(obj[k], plus(prefix, k), out)
            return
        }
        out.add(BareLeaf(prefix, value))
    }

    /** Split a string into [size]-character chunks (by code point, never splitting a surrogate pair). */
    private fun chunkString(s: String, size: Long): List<BareLeaf> {
        val cps = ArrayList<Int>()
        var j = 0
        while (j < s.length) { val cp = s.codePointAt(j); cps.add(cp); j += Character.charCount(cp) }
        val out = ArrayList<BareLeaf>()
        if (cps.isEmpty()) {
            out.add(BareLeaf(arrayListOf("#chunk", 0L), ""))
            return out
        }
        var idx = 0L
        var i = 0L
        while (i < cps.size) {
            val n = Math.min(size, cps.size - i).toInt()
            val sb = StringBuilder()
            for (k in 0 until n) sb.appendCodePoint(cps[(i + k).toInt()])
            out.add(BareLeaf(arrayListOf("#chunk", idx), sb.toString()))
            i += size
            idx++
        }
        return out
    }

    private fun leafObject(path: Any?, value: Any?, salt: Any?): Map<String, Any?> = linkedMapOf("p" to path, "v" to value, "s" to salt)

    private fun leafObjectOf(leaf: Any?): Map<String, Any?> {
        val l = asMap(leaf) ?: throw IllegalArgumentException("Cannot read properties of undefined")
        return leafObject(req(l, "path"), req(l, "value"), req(l, "salt"))
    }

    private fun requestHeadersDigest(headers: Any?): String {
        val norm = LinkedHashMap<String, Any?>()
        val h = asMap(headers)
        if (h != null) for ((k, v) in h) norm[k.lowercase(java.util.Locale.ROOT)] = v
        return Pca.hashCanonical(norm)
    }

    // ---- notaryMessage ----

    /** The canonical bytes the notary signs: `"atlas-pca/notary/v1\0" || sha256(canonical(session))`. */
    fun notaryMessage(session: Any?): ByteArray {
        val d = sha256(Pca.canonBytes(session))
        val pre = NOTARY_DOMAIN.toByteArray(Charsets.UTF_8)
        return pre + d
    }

    // ---- notarizeResponse ----

    /** Options for [notarizeResponse]. */
    class NotarizeOptions(
        /** The notary's signing key (its public key becomes `attestation.notary`). */
        @JvmField val notaryKey: Keys.EdKey,
    ) {
        /** Epoch ms the notary observed the session (a JSON-shaped number); null = now. */
        @JvmField var observedAt: Any? = null

        /** When set (a number >= 1) and the body is a string, commit it as chunks of this many characters. */
        @JvmField var textChunkSize: Any? = null

        /** Source of the 16-byte hiding salts (default: SecureRandom). */
        @JvmField var salt: (() -> ByteArray)? = null
    }

    /** The shareable attestation and the prover's private opening witness. */
    class NotarizeResult internal constructor(@JvmField val attestation: Map<String, Any?>, @JvmField val witness: Map<String, Any?>) {
        fun toMap(): Map<String, Any?> = linkedMapOf("attestation" to attestation, "witness" to witness)
    }

    private val RNG = SecureRandom()

    /**
     * Witness a request/response (`input = {request: {method, url, headers?}, response: {status, body}}`) and produce a signed
     * attestation over the canonical session plus the response-body Merkle root, and the witness the prover keeps to disclose fields.
     */
    fun notarizeResponse(input: Map<String, Any?>?, opts: NotarizeOptions): NotarizeResult {
        val request = asMap(input?.get("request"))
        val response = asMap(input?.get("response"))
        if (request == null || response == null) throw IllegalArgumentException("Cannot read properties of undefined")
        val method = request["method"]
        if (method !is String || method.isEmpty()) throw IllegalArgumentException("notarizeResponse: request.method is required")
        val url = request["url"]
        if (url !is String || url.isEmpty()) throw IllegalArgumentException("notarizeResponse: request.url is required")
        val status = response["status"]
        if (!isSafeIntJs(status)) throw IllegalArgumentException("notarizeResponse: response.status must be an integer")

        val body = response["body"]
        val chunk = if (opts.textChunkSize == null) null else Js.num(opts.textChunkSize)
        val bare = ArrayList<BareLeaf>()
        if (body is String && chunk != null && chunk >= 1) bare.addAll(chunkString(body, Math.min(Math.floor(chunk), 4.0e18).toLong()))
        else flatten(body, ArrayList(), bare)

        val salts: () -> ByteArray = opts.salt ?: { ByteArray(16).also { RNG.nextBytes(it) } }
        val leaves = ArrayList<Any?>()
        val leafObjects = ArrayList<Any?>()
        for (l in bare) {
            val salt = Keys.b64u(salts())
            leaves.add(linkedMapOf("path" to l.path, "value" to l.value, "salt" to salt))
            leafObjects.add(leafObject(l.path, l.value, salt))
        }
        val root = Pca.merkleRoot(leafObjects)

        val commit = linkedMapOf<String, Any?>("alg" to BODY_COMMIT_ALG, "root" to root, "size" to leaves.size.toLong())
        val session = LinkedHashMap<String, Any?>()
        session["v"] = 1L
        session["method"] = method.uppercase(java.util.Locale.ROOT)
        session["url"] = url
        session["requestHeadersDigest"] = requestHeadersDigest(request["headers"])
        session["responseStatus"] = status
        session["responseBodyCommit"] = commit
        session["observedAt"] = opts.observedAt ?: System.currentTimeMillis()

        val attestation = LinkedHashMap<String, Any?>()
        attestation["session"] = session
        attestation["notary"] = opts.notaryKey.id()
        attestation["sig"] = Keys.b64u(opts.notaryKey.sign(notaryMessage(session)))
        val witness = linkedMapOf<String, Any?>("session" to session, "leaves" to leaves)
        return NotarizeResult(attestation, witness)
    }

    // ---- discloseField ----

    /**
     * A redactable disclosure of ONE response field (by [path]: a list, or a bare string for a top-level key) with its Merkle
     * inclusion proof; every other field stays hidden. Throws when [path] names no committed leaf.
     */
    fun discloseField(attestation: Any?, witness: Any?, path: Any?): Map<String, Any?> {
        val want = normalizePath(path)
        val w = asMap(witness)
        val leaves = (if (w == null) null else asList(w["leaves"])) ?: throw IllegalArgumentException("Cannot read properties of undefined (reading 'leaves')")
        var idx = -1
        for (i in leaves.indices) {
            val l = asMap(leaves[i]) ?: throw IllegalArgumentException("Cannot read properties of undefined (reading 'path')")
            if (canonicalEqual(l["path"], want)) { idx = i; break }
        }
        if (idx < 0) throw IllegalArgumentException("discloseField: no committed field at path " + Json.canonicalize(want))
        val leaf = asMap(leaves[idx])!!
        val objs = ArrayList<Any?>()
        for (l in leaves) objs.add(leafObjectOf(l))
        val d = LinkedHashMap<String, Any?>()
        d["path"] = leaf["path"]
        d["value"] = leaf["value"]
        d["salt"] = leaf["salt"]
        d["proof"] = GrantSigning.merkleProof(objs, idx)
        return d
    }

    // ---- verification (fail closed) ----

    private fun validCommit(c: Any?): Boolean {
        val r = asMap(c) ?: return false
        return BODY_COMMIT_ALG == r["alg"] && r["root"] is String && Pca.decodeB64uStrict(r["root"], 32) != null &&
            isSafeIntJs(r["size"]) && Js.num(r["size"])!! >= 1
    }

    private fun validSession(s: Any?): Boolean {
        val r = asMap(s) ?: return false
        return isOne(r["v"]) && r["method"] is String && r["url"] is String && r["requestHeadersDigest"] is String &&
            isSafeIntJs(r["responseStatus"]) && !isNegZero(r["responseStatus"]) &&
            isSafeIntJs(r["observedAt"]) && !isNegZero(r["observedAt"]) &&
            validCommit(r["responseBodyCommit"])
    }

    /**
     * Verify the notary signature AND the session's structural integrity. [notaryKey] is the TRUSTED notary's public key (b64u
     * string, raw bytes or key pair); the recorded signer must equal it and the signature must verify over the canonical session.
     */
    fun verifyNotaryAttestation(attestation: Any?, notaryKey: Any?): Boolean = try {
        val a = asMap(attestation)
        if (a == null) false
        else if (!validSession(a["session"])) false
        else if (a["notary"] !is String || a["sig"] !is String) false
        else if (a["notary"] != toPubB64u(notaryKey)) false
        else Pca.verifyB64u(a["notary"] as String, notaryMessage(a["session"]), a["sig"] as String)
    } catch (e: RuntimeException) {
        false
    }

    /**
     * Verify a disclosed field: the attestation is authentic AND the disclosed leaf is included under the attested body root at a
     * position consistent with the committed size. A lie about the value, path or salt breaks inclusion.
     */
    fun verifyDisclosedField(attestation: Any?, disclosure: Any?, notaryKey: Any?): Boolean {
        try {
            if (!verifyNotaryAttestation(attestation, notaryKey)) return false
            val d = asMap(disclosure) ?: return false
            if (d["path"] !is List<*> || d["salt"] !is String) return false
            val proof = asMap(d["proof"])
            if (proof == null || proof["path"] !is List<*>) return false
            val commit = asMap(asMap(asMap(attestation)!!["session"])!!["responseBodyCommit"])!!
            if (!Json.isSafeInt(proof["size"]) || Json.asLong(proof["size"]) != Json.asLong(commit["size"])) return false
            if (!d.containsKey("value")) return false // an undefined value cannot be canonicalised: the reference refuses it
            return Pca.verifyInclusion(commit["root"] as String, proof, leafObject(d["path"], d["value"], d["salt"]))
        } catch (e: RuntimeException) {
            return false
        }
    }

    // ---- PCA binding ----

    /** A stable digest identifying this attested FACT (independent of any PCActn binding). */
    fun factRef(attestation: Any?): String {
        val a = asMap(attestation) ?: throw IllegalArgumentException("Cannot read properties of undefined (reading 'session')")
        val m = LinkedHashMap<String, Any?>()
        m["fact"] = "atlas-pca-notary/v1"
        m["session"] = req(a, "session")
        m["notary"] = req(a, "notary")
        m["sig"] = req(a, "sig")
        return Pca.hashCanonical(m)
    }

    /** Bind an attested fact to a specific PCActn by stamping the action's digest into the attestation (a new map; the input is untouched). */
    fun bindFactToPcActn(attestation: Any?, pcActn: Any?): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        val a = asMap(attestation)
        if (a != null) out.putAll(a)
        out["fact_binding"] = linkedMapOf<String, Any?>("pcactn_digest" to Pca.hashCanonical(pcActn))
        return out
    }

    /**
     * True iff the fact is bound to [pcActn] in BOTH directions: the fact names the action (`fact_binding.pcactn_digest ==
     * digest(pcActn)`) AND the action commits to the fact (`provenance.trusted_refs` includes [factRef]). False if either side is missing.
     */
    fun factMatchesPcActn(attestation: Any?, pcActn: Any?): Boolean = try {
        val a = asMap(attestation)
        val binding = asMap(a?.get("fact_binding"))
        if (a == null || binding == null || binding["pcactn_digest"] !is String) false
        else if (binding["pcactn_digest"] != Pca.hashCanonical(pcActn)) false
        else {
            val prov = asMap(asMap(pcActn)?.get("provenance"))
            val refs = asList(prov?.get("trusted_refs"))
            refs != null && refs.contains(factRef(attestation))
        }
    } catch (e: RuntimeException) {
        false
    }

    // ---- policy caveat ----

    /**
     * Build an attested_fact caveat: admit an action only when the agent discloses a notarized response field equal to `equals`.
     * [opts] = {notary (b64u string / bytes / key), path, equals, url?, bindToPcActn?}.
     */
    fun requireAttestedFact(opts: Map<String, Any?>): Map<String, Any?> {
        val p = opts["path"]
        // a string has a slice too: it would pass as a one-segment path that no disclosure matches, so only an array is a path
        if (p !is List<*>) throw IllegalArgumentException("requireAttestedFact: path must be an array of segments")
        val m = LinkedHashMap<String, Any?>()
        m["type"] = ATTESTED_FACT_CAVEAT
        m["notary"] = toPubB64u(opts["notary"])
        m["path"] = ArrayList<Any?>(p)
        if (opts.containsKey("equals")) m["equals"] = opts["equals"]
        if (opts.containsKey("url")) m["url"] = opts["url"]
        if (opts.containsKey("bindToPcActn")) m["bindToPcActn"] = opts["bindToPcActn"]
        return m
    }

    /** The JavaScript comparison operand of `observedAt >= bound`: a number, null (0), a boolean or a numeric string. */
    private fun toNumber(o: Any?): Double {
        if (o == null) return 0.0
        if (o is Boolean) return if (o) 1.0 else 0.0
        val d = Js.num(o)
        if (d != null) return d
        if (o is String) {
            val s = o.trim { it.isWhitespace() || it == '﻿' }
            if (s.isEmpty()) return 0.0
            return s.toDoubleOrNull() ?: Double.NaN
        }
        return Double.NaN
    }

    /** True iff [key] is listed in [ring], not revoked, and [observedAt] lies in its [notBefore, notAfter) window. */
    fun notaryKeyUsable(ring: Any?, key: Any?, observedAt: Any?): Boolean {
        val r = asList(ring)
        if (r == null || !isSafeIntJs(observedAt)) return false
        val at = Js.num(observedAt)!!
        var any = false
        var allLive = true
        var someWindow = false
        for (eo in r) {
            val e = asMap(eo)
            if (e == null || !strictEq(e["key"], key)) continue
            any = true
            if (e["revoked"] == true) allLive = false
            val okBefore = !e.containsKey("notBefore") || at >= toNumber(e["notBefore"])
            val okAfter = !e.containsKey("notAfter") || at < toNumber(e["notAfter"])
            if (okBefore && okAfter) someWindow = true
        }
        return any && allLive && someWindow
    }

    /** JavaScript `a === b` over JSON-shaped scalars (numbers by value). */
    private fun strictEq(a: Any?, b: Any?): Boolean {
        if (a == null || b == null) return a == null && b == null
        val x = Js.num(a)
        val y = Js.num(b)
        if (x != null || y != null) return x != null && y != null && x == y
        if (a is String || b is String || a is Boolean || b is Boolean) return a == b
        return false
    }

    private fun result(ok: Boolean, reason: String?, trust: Boolean): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["ok"] = ok
        if (reason != null) m["reason"] = reason
        if (trust) m["trust"] = "notary-trusted"
        return m
    }

    /**
     * Evaluate an attested_fact caveat against disclosed evidence ({attestation, disclosure, pcActn?}) under an optional policy
     * ({now?, maxAgeMs?, keyring?}). Admits (`ok: true, trust: "notary-trusted"`) only when, failing closed at every step: the
     * attestation is authentic under the caveat's notary; the keyring (if given) trusts the signer at the observation time; the
     * attestation is fresh (if `maxAgeMs`); the URL matches (if set); the disclosed field verifies; its path equals the caveat's
     * path; its value canonically equals `equals`; and (if `bindToPcActn`) the fact is two-way bound to the PCActn.
     */
    fun evaluateAttestedFactCaveat(caveat: Any?, evidence: Any?, policy: Map<String, Any?>?): Map<String, Any?> {
        try {
            val cv = asMap(caveat)
            if (cv == null || ATTESTED_FACT_CAVEAT != cv["type"]) return result(false, "not an attested_fact caveat", false)
            if (cv["notary"] !is String || cv["path"] !is List<*>) return result(false, "caveat is malformed (notary/path)", false)
            if (evidence == null) throw IllegalArgumentException("Cannot destructure property 'attestation' of 'evidence' as it is null.")
            val ev = asMap(evidence)
            val attestation = ev?.get("attestation")
            val disclosure = ev?.get("disclosure")
            val pcActn = ev?.get("pcActn")
            if (!verifyNotaryAttestation(attestation, cv["notary"])) return result(false, "notary attestation does not verify (fail closed)", false)
            val att = asMap(attestation)!!
            val session = asMap(att["session"])!!
            if (policy == null) throw IllegalArgumentException("Cannot read properties of null (reading 'keyring')")
            if (policy.containsKey("keyring") && !notaryKeyUsable(policy["keyring"], att["notary"], session["observedAt"])) {
                return result(false, "notary key is not trusted for this observation time (unlisted, revoked or out of window)", false)
            }
            if (policy.containsKey("maxAgeMs")) {
                val now: Any? = policy["now"] ?: System.currentTimeMillis()
                val max = Js.num(policy["maxAgeMs"])
                val nowN = Js.num(now)
                var stale = max == null || max.isInfinite() || max.isNaN() || nowN == null || nowN.isInfinite() || nowN.isNaN()
                if (!stale) {
                    val age = nowN!! - Js.num(session["observedAt"])!!
                    stale = age < 0 || age > max!!
                }
                if (stale) return result(false, "attestation is stale or from the future", false)
            }
            if (cv.containsKey("url") && session["url"] != cv["url"]) {
                return result(false, "attested session URL does not match the caveat", false)
            }
            if (!verifyDisclosedField(attestation, disclosure, cv["notary"])) return result(false, "disclosed field does not verify under the attested root", false)
            val d = asMap(disclosure)!!
            if (!canonicalEqual(d["path"], cv["path"])) return result(false, "disclosed field is not the path the caveat requires", false)
            if (!cv.containsKey("equals") || !canonicalEqual(d["value"], cv["equals"])) {
                return result(false, "disclosed field value does not satisfy the caveat", false)
            }
            if (Js.truthy(cv["bindToPcActn"])) {
                if (!Js.truthy(pcActn)) return result(false, "caveat requires PCActn binding but no PCActn was supplied", false)
                if (!factMatchesPcActn(attestation, pcActn)) return result(false, "fact is not bound to this PCActn", false)
            }
            return result(true, null, true)
        } catch (e: RuntimeException) {
            return result(false, "attested_fact evaluation error (fail closed): " + (e.message ?: "unknown"), false)
        }
    }

    fun evaluateAttestedFactCaveat(caveat: Any?, evidence: Any?): Map<String, Any?> = evaluateAttestedFactCaveat(caveat, evidence, LinkedHashMap())

    /** Type guard: a bare caveat object is an attested_fact caveat. */
    fun isAttestedFactCaveat(cv: Any?): Boolean {
        val m = asMap(cv)
        return m != null && ATTESTED_FACT_CAVEAT == m["type"] && m["notary"] is String && m["path"] is List<*>
    }
}
