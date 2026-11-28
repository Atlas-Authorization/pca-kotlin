package net.atlasauth.pca.gnap

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.Locale
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Predicates
import net.atlasauth.pca.verifier.SignersMore
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * A GNAP (RFC 9635) bridge for Proof-Carrying Authority: the Agent-GNAP profile. Mirrors the reference package's main module
 * (access-rights normalization and mapping onto policy predicates, containment and clamping, grant request to capability,
 * action authorization, bound tokens, the `jwsd` detached-JWS proof, and continuation / step-up). Every verify path fails
 * closed. Values are JSON trees: `Map<String, Any?>`, `List<Any?>`, `String`, `Boolean`, [Json.Num] and null; secrets are
 * 32-byte Ed25519 seeds given as `ByteArray` or base64url text.
 *
 * Deliberate differences from the reference: [grantRequestToCapability] refuses an `issuerPublic` that is not the public key of
 * `issuerSecret` (the reference would sign a chain that can never verify), and [completeGnapContinuation] verifies its own
 * Ed25519 co-signature shares only.
 */
@Suppress("UNCHECKED_CAST")
object Gnap {
    const val GNAP_GRANT_CAVEAT = "gnap_grant"
    const val GNAP_ACCESS_CAVEAT = "gnap_access"
    /** Upper bound on an accepted detached JWS string (adversarial-size guard). */
    const val MAX_DETACHED_JWS_CHARS = 8192
    private const val JWSD_TYP = "gnap-binding-jwsd"
    private const val GNAP_RESOURCE_PREFIX = "gnap"
    /** An argument that is absent (JavaScript undefined): a request body (the proof then covers no content) or a holder override. */
    @JvmField val ABSENT: Any = GnapJs.ABSENT

    /** The replay store of [verifyGnapRequest]: true (or any value but false) means the proof was already seen. */
    fun interface SeenProof { fun seen(proofId: String, expiresSec: Double): Any? }

    // ---- small guards ----
    private fun obj(vararg kv: Pair<String, Any?>) = Issue.obj(*kv)
    private fun map(o: Any?) = o as Map<String, Any?>
    private fun list(o: Any?) = o as List<Any?>
    private fun isRecord(x: Any?) = x is Map<*, *>

    private fun strArr(u: Any?): MutableList<Any?>? = if (u !is List<*>) null else u.filterIsInstance<String>().toMutableList<Any?>()

    /** A canonical, unpadded base64url Ed25519 public key (exactly 32 bytes), or null. */
    private fun asEd25519(x: Any?): String? = if (x is String && Pca.decodeB64uStrict(x, 32) != null) x else null

    private fun secretBytes(o: Any?): ByteArray = when (o) {
        is ByteArray -> o
        is String -> Keys.unb64u(o)
        else -> throw GnapError("a secret key must be 32 bytes (bytes or base64url text)")
    }

    private fun edKey(secret: Any?): Keys.EdKey = Keys.edFromSeed(secretBytes(secret))

    /** The PCA `resource` string for a GNAP (type, location) pair: the namespace actions are matched in. */
    fun gnapActionResource(type: String, location: String): String = "$GNAP_RESOURCE_PREFIX:$type:$location"

    // ---- access-rights normalization and mapping onto predicates ----
    private fun tryNormalizeAccessItem(item: Any?): MutableMap<String, Any?>? {
        if (item is String) return if (item.isEmpty()) null else obj("type" to item)
        if (item !is Map<*, *>) return null
        val m = map(item)
        val type = m["type"]
        if (type !is String || type.isEmpty()) return null
        val out = obj("type" to type)
        strArr(m["actions"])?.takeIf { it.isNotEmpty() }?.let { out["actions"] = it }
        strArr(m["locations"])?.takeIf { it.isNotEmpty() }?.let { out["locations"] = it }
        strArr(m["datatypes"])?.takeIf { it.isNotEmpty() }?.let { out["datatypes"] = it }
        if (m["identifier"] is String) out["identifier"] = m["identifier"]
        strArr(m["privileges"])?.takeIf { it.isNotEmpty() }?.let { out["privileges"] = it }
        return out
    }

    /** Normalize an access array for issuance (throws on any malformed entry). */
    fun normalizeAccess(items: Any?): List<Any?> {
        if (items !is List<*>) throw GnapError("access must be an array")
        return items.map { tryNormalizeAccessItem(it) ?: throw GnapError("malformed access item (needs a non-empty string `type`)") }
    }

    /** Total, fail-closed read of a stored access array (reading signed caveats). Skips malformed entries. */
    private fun readAccessArray(u: Any?): MutableList<Any?> =
        if (u !is List<*>) ArrayList<Any?>() else u.mapNotNull { tryNormalizeAccessItem(it) }.toMutableList<Any?>()

    private fun nonEmpty(l: Any?): List<Any?>? = if (l is List<*> && l.isNotEmpty()) list(l) else null

    /**
     * Map a GNAP access right onto PCA predicates (one per location). `type` namespaces the resource, `actions` become verbs,
     * `locations` become resources, and `datatypes`/`identifier` become `where` conditions on the action's params. An absent
     * `actions`/`locations` means "any".
     */
    fun accessToPredicates(access: Map<String, Any?>): List<Any?> {
        val actions = nonEmpty(access["actions"])
        val locations = nonEmpty(access["locations"]) ?: listOf("*")
        val where = ArrayList<Map<String, Any?>>()
        nonEmpty(access["datatypes"])?.let { where.add(obj("field" to "action.params.datatype", "op" to "in", "value" to ArrayList(it))) }
        if (access["identifier"] is String) where.add(obj("field" to "action.params.identifier", "op" to "eq", "value" to access["identifier"]))
        return locations.map { loc ->
            val p = obj("verb" to (if (actions != null) ArrayList(actions) else "*"), "resource" to gnapActionResource(access["type"] as String, GnapJs.str(loc)))
            if (where.isNotEmpty()) p["where"] = where.map { LinkedHashMap(it) }
            p
        }
    }

    private fun accessArrayToPredicates(access: List<Any?>): List<Any?> = access.flatMap { accessToPredicates(map(it)) }

    // ---- containment ----
    private fun coversStrings(sup: List<Any?>?, sub: List<Any?>?): Boolean {
        if (sup == null) return true // issuer allows all
        if (sub == null) return false // request wants all, issuer has a concrete set
        return sub.all { it in sup }
    }

    private fun coversLocations(sup: List<Any?>?, sub: List<Any?>?): Boolean {
        if (sup == null) return true
        if (sub == null) return "*" in sup
        for (so in sub) {
            val s = so as String
            val any = sup.any { go ->
                val g = go as String
                g == s || g == "*" || (g.endsWith("*") && s.startsWith(g.substring(0, g.length - 1)))
            }
            if (!any) return false
        }
        return true
    }

    private fun strings(l: Any?): List<Any?>? = if (l is List<*>) list(l) else null

    /** Does the issuer's granted right `g` fully contain the requested right `r`? */
    fun accessContains(g: Map<String, Any?>, r: Map<String, Any?>): Boolean {
        if (g["type"] != r["type"]) return false
        if (!coversStrings(strings(g["actions"]), strings(r["actions"]))) return false
        if (!coversLocations(strings(g["locations"]), strings(r["locations"]))) return false
        if (!coversStrings(strings(g["datatypes"]), strings(r["datatypes"]))) return false
        if (r["identifier"] != null && g["identifier"] != null && g["identifier"] != r["identifier"]) return false
        return true
    }

    /** Is `r` within the issuer's granted set `G` (covered by at least one of its rights)? */
    fun accessWithin(G: List<Any?>, r: Map<String, Any?>): Boolean = G.any { accessContains(map(it), r) }

    /** Split a requested access array into the subset within the issuer's authority and the rest: `{granted, dropped}`. */
    fun clampAccess(issuerGranted: List<Any?>, requested: List<Any?>): Map<String, Any?> {
        val granted = ArrayList<Any?>()
        val dropped = ArrayList<Any?>()
        for (r in requested) (if (accessWithin(issuerGranted, map(r))) granted else dropped).add(r)
        return obj("granted" to granted, "dropped" to dropped)
    }

    // ---- provenance caveats ----
    /** The root grant's GNAP provenance caveat's granted access, or null when there is none. */
    private fun readGnapGrantAccess(root: Any?): List<Any?>? {
        val env = Authorize.readEnvelope(root) ?: return null
        val cavs = env["caveats"] as? List<*> ?: return null
        val cv = cavs.firstOrNull { it is Map<*, *> && it["type"] == GNAP_GRANT_CAVEAT } as? Map<*, *> ?: return null
        if (cv["client_id"] !is String || cv["request_digest"] !is String) return null
        return readAccessArray(cv["granted_access"])
    }

    /**
     * The EFFECTIVE granted access of a chain: the most-recent delegated hop's recorded rights, or (for a root-only grant) the
     * root's recorded rights. Every hop is clamped to its issuer at issue time, so the leaf's rights are the narrowest.
     */
    fun grantedAccessOf(chain: Any?): List<Any?> {
        if (chain !is List<*> || chain.isEmpty()) return ArrayList<Any?>()
        val leaf = chain[chain.size - 1] ?: throw IllegalArgumentException("chain leaf is null")
        val cavs = GnapJs.member(leaf, "caveats") as? List<*> ?: emptyList<Any?>()
        for (i in cavs.indices.reversed()) {
            val cv = cavs[i]
            if (cv is Map<*, *> && cv["type"] == GNAP_ACCESS_CAVEAT) return readAccessArray(cv["access"])
        }
        return readGnapGrantAccess(chain[0]) ?: ArrayList<Any?>()
    }

    // ---- holder resolution ----
    /** Resolve the b64u Ed25519 holder key from a request's client key (or an explicit override; [ABSENT] for none). */
    fun resolveHolder(req: Any?, holderOverride: Any?): String {
        if (req == null) throw GnapError("grant request is null")
        val client = GnapJs.member(req, "client")
        val declared = (client as? Map<*, *>)?.get("key")
        if (GnapJs.isObject(declared)) {
            val proof = GnapJs.member(declared, "proof")
            val method = if (proof is String) proof else if (proof is Map<*, *>) proof["method"] else null
            if (method != "jwsd") throw GnapError("unsupported client key proof method: ${if (method is String) method else "none"} (only jwsd is supported)")
        }
        if (holderOverride !== ABSENT) {
            return asEd25519(holderOverride) ?: throw GnapError("holder override is not a canonical base64url Ed25519 public key")
        }
        if (GnapJs.isObject(declared)) {
            val jwk = GnapJs.member(declared, "jwk")
            if (jwk is Map<*, *> && jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519") asEd25519(jwk["x"])?.let { return it }
        }
        throw GnapError("cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override")
    }

    /** The holder key, rendered as a GNAP JWK (for a bound access-token response). */
    fun holderJwk(holder: String): Map<String, Any?> = obj("kty" to "OKP", "crv" to "Ed25519", "x" to holder, "use" to "sig", "alg" to "EdDSA")

    private fun accessOf(req: Any?): List<Any?> {
        val at = GnapJs.member(req, "access_token")
        if (at is Map<*, *> && at["access"] is List<*>) return list(at["access"])
        throw GnapError("grant request must carry access_token.access (single-token request)")
    }

    private fun requestDigestOf(holder: String, granted: List<Any?>, interact: Any?): String =
        Pca.hashCanonical(obj("d" to "atlas-pca/gnap/request/v1", "client_id" to holder, "access" to granted, "interact" to interact))

    // ---- grant request -> PCA capability ----
    /**
     * Convert a GNAP grant request into a PCA capability bound to the client key, ATTENUATED to never exceed the issuer. With no
     * `parent` this MINTS a root grant whose policy-envelope predicates ARE the requested access rights; with a `parent` it
     * DELEGATES a narrower hop, recording the (clamped) rights as an append-only `gnap_access` caveat. `opts`: issuerSecret,
     * issuerPublic, parent, issuerChain, clampToIssuer, holder, interacted, now, goal, riskPolicy, agentBinding, salt. Returns
     * `{grant, chain, holder, grantedAccess, droppedAccess, provenance}`.
     */
    fun grantRequestToCapability(req: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val holder = resolveHolder(req, GnapJs.get(opts, "holder"))
        val requested = normalizeAccess(accessOf(req))
        val nowO = opts["now"]
        val now = if (nowO == null) System.currentTimeMillis() else Math.floor(GnapJs.num(nowO)!!).toLong()
        val interacted = opts["interacted"] == true
        val parent = opts["parent"]
        val delegated = GnapJs.truthy(parent)
        var granted = requested
        var dropped: List<Any?> = ArrayList<Any?>()
        var issuerChain: Any? = null
        if (delegated) {
            issuerChain = opts["issuerChain"] ?: arrayListOf(parent)
            if (opts["clampToIssuer"] != false) {
                val split = clampAccess(grantedAccessOf(issuerChain), requested)
                granted = list(split["granted"])
                dropped = list(split["dropped"])
            }
        }
        val requestDigest = requestDigestOf(holder, granted, if (req == null) null else GnapJs.member(req, "interact"))
        val signer = edKey(opts["issuerSecret"])
        if (delegated) {
            val provenance = obj("type" to GNAP_ACCESS_CAVEAT, "access" to granted, "predicates" to accessArrayToPredicates(granted),
                "request_digest" to requestDigest, "client_id" to holder, "ts" to now)
            val child = Issue.delegate(map(parent), holder, arrayListOf<Any?>(provenance), Keys.ed25519(signer), null)
            val chain = ArrayList(list(issuerChain))
            chain.add(child)
            return obj("grant" to child, "chain" to chain, "holder" to holder, "grantedAccess" to granted, "droppedAccess" to dropped, "provenance" to provenance)
        }
        val provenance = obj("type" to GNAP_GRANT_CAVEAT, "client_id" to holder, "granted_access" to granted, "request_digest" to requestDigest,
            "interacted" to interacted, "ts" to now)
        if (opts["issuerPublic"] !is String || opts["issuerPublic"] != signer.id()) throw GnapError("issuerPublic is not the public key of issuerSecret")
        val goal = opts["goal"] as String? ?: "gnap:grant:$holder"
        val envelope = obj("predicates" to accessArrayToPredicates(granted), "caveats" to arrayListOf<Any?>(provenance),
            "agent_binding" to (opts["agentBinding"] ?: LinkedHashMap<String, Any?>()), "risk_policy" to (opts["riskPolicy"] ?: Issue.defaultRiskPolicy()))
        val g = Issue.mintGrant(Keys.ed25519(signer), holder, null, envelope, goal, opts["salt"] as String?)
        return obj("grant" to g.grant, "chain" to arrayListOf<Any?>(g.grant), "holder" to holder, "grantedAccess" to granted, "droppedAccess" to dropped,
            "provenance" to provenance)
    }

    // ---- action authorization ----
    private fun pqPinsOf(opts: Map<String, Any?>?): Map<String, Any?>? = opts?.get("pqPins") as? Map<String, Any?>

    private fun chainReason(chain: Any?, opts: Map<String, Any?>): String {
        val haveIssuer = opts.containsKey("expectedRootIssuer")
        // a non-text expected issuer never equals a root issuer, so "" refuses exactly as the reference does
        val issuer = opts["expectedRootIssuer"] as? String ?: ""
        return Pca.verifyChain(list(chain), issuer, haveIssuer, null, pqPinsOf(opts), null)
    }

    /**
     * Decide whether `action` (`verb`, `resource`, optional `params`, `reversibility_class`) is authorized by a GNAP-issued
     * capability chain. FAILS CLOSED. The chain must verify, the root policy envelope must permit the action AND every delegated
     * hop's recorded `gnap_access` rights must permit it too. `opts`: expectedRootIssuer, pqPins.
     */
    fun authorizeGnapAction(chain: Any?, action: Map<String, Any?>, opts: Map<String, Any?>?): Map<String, Any?> {
        if (chain !is List<*> || chain.isEmpty()) return obj("allowed" to false, "reason" to "empty chain")
        val vc = chainReason(chain, opts ?: emptyMap())
        if (vc.isNotEmpty()) return obj("allowed" to false, "reason" to "capability chain invalid: $vc")
        val env = Authorize.readEnvelope(chain[0]) ?: return obj("allowed" to false, "reason" to "root grant carries no policy envelope")
        val act = obj("verb" to action["verb"], "resource" to action["resource"])
        if (action.containsKey("params")) act["params"] = action["params"]
        if (action.containsKey("reversibility_class")) act["reversibility_class"] = action["reversibility_class"]
        val ctx = obj("action" to act)
        if (!Predicates.evaluatePredicates(env["predicates"], ctx)) {
            val why = Predicates.denialReason(env["predicates"], ctx)
            return obj("allowed" to false, "reason" to "root authority denies: ${why ?: "no predicate matched"}")
        }
        val caveats = GnapJs.member(chain[chain.size - 1], "caveats")
        if (caveats is List<*>) {
            for (cv in caveats) {
                if (cv !is Map<*, *> || cv["type"] != GNAP_ACCESS_CAVEAT) continue
                val hopPreds = accessArrayToPredicates(readAccessArray(cv["access"]))
                if (!Predicates.evaluatePredicates(hopPreds, ctx)) {
                    val why = Predicates.denialReason(hopPreds, ctx)
                    return obj("allowed" to false, "reason" to "delegated hop denies: ${why ?: "no predicate matched"}")
                }
            }
        }
        return obj("allowed" to true)
    }

    // ---- bound token ----
    /** Encode a capability chain as a GNAP access-token `value`: base64url of the chain's JSON text (re-verified on use). */
    fun encodeBoundToken(chain: Any?): String = Keys.b64u(Jose.utf8(GnapJs.stringify(chain)))

    private fun strOrAbsent(m: Map<String, Any?>, k: String) = !m.containsKey(k) || m[k] is String

    private fun isCapabilityShape(x: Any?): Boolean {
        if (x !is Map<*, *>) return false
        val m = map(x)
        return m["id"] is String && m["issuer"] is String && m["holder"] is String && m["body_digest"] is String && m["sig"] is String &&
            m["caveats"] is List<*> && strOrAbsent(m, "parent") && strOrAbsent(m, "alg") && strOrAbsent(m, "pq_pk") && strOrAbsent(m, "pq_sig")
    }

    /** TextDecoder (fatal): invalid UTF-8 is an error. */
    private fun fatalUtf8(b: ByteArray): String = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString()

    /** Total, fail-closed decode of a bound token back into a capability chain (null on any deviation). */
    private fun decodeBoundToken(value: String): List<Any?>? = try {
        var text = fatalUtf8(Keys.unb64u(value))
        if (text.startsWith("﻿")) text = text.substring(1) // TextDecoder drops a leading BOM
        val parsed = Json.parse(text)
        if (parsed is List<*> && parsed.all { isCapabilityShape(it) }) ArrayList(parsed) else null
    } catch (e: RuntimeException) {
        null
    } catch (e: CharacterCodingException) {
        null
    } catch (e: StackOverflowError) {
        null
    }

    /**
     * Render a (verified) PCA capability chain as a GNAP grant response with a bound access token. `opts`: expiresIn, bearer,
     * instanceId, manageUri, continue.
     */
    fun capabilityToGrantResponse(chain: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        if (chain !is List<*> || chain.isEmpty()) throw GnapError("capabilityToGrantResponse: empty chain")
        val leaf = chain[chain.size - 1] as? Map<*, *> ?: throw GnapError("capabilityToGrantResponse: malformed leaf")
        val o: Map<String, Any?> = opts ?: emptyMap()
        val token = obj("value" to encodeBoundToken(chain), "access" to grantedAccessOf(chain),
            "key" to (if (o["bearer"] == true) false else holderJwk(leaf["holder"] as String)))
        if (o.containsKey("expiresIn")) token["expires_in"] = o["expiresIn"]
        if (o.containsKey("manageUri")) token["manage"] = obj("uri" to o["manageUri"])
        val res = obj("access_token" to token)
        if (o.containsKey("continue")) res["continue"] = o["continue"]
        if (o.containsKey("instanceId")) res["instance_id"] = o["instanceId"]
        return res
    }

    /**
     * Verify an incoming GNAP bound token, mapping it back to a PCA principal and capability. FAILS CLOSED: a token that is not a
     * decodable chain, or whose chain does not verify (optionally against `expectedRootIssuer`), returns `{ok:false}`.
     */
    fun verifyGnapToken(value: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        if (value !is String || value.isEmpty()) return obj("ok" to false, "reason" to "token value is empty")
        val chain = decodeBoundToken(value)
        if (chain == null || chain.isEmpty()) return obj("ok" to false, "reason" to "token is not a decodable PCA capability chain")
        val vc = chainReason(chain, opts ?: emptyMap())
        if (vc.isNotEmpty()) return obj("ok" to false, "reason" to "capability chain invalid: $vc")
        val root = map(chain[0])
        val leaf = map(chain[chain.size - 1])
        return obj("ok" to true, "principal" to root["issuer"], "capability" to leaf, "chain" to chain, "access" to grantedAccessOf(chain))
    }

    // ---- jwsd detached JWS ----
    /** base64url(SHA-256(value)); a value that is not text is encoded as its JavaScript string (TextEncoder: null is "null"). */
    private fun athOf(accessTokenValue: Any?): String = Keys.b64u(GnapJs.sha256(Jose.utf8(GnapJs.str(accessTokenValue))))

    /** JSON.parse(JSON.stringify(v)): the plain JSON a value stands for (`-0` prints as `0`). */
    private fun toPlain(v: Any?): Any? = when (v) {
        is Json.Num -> if (v.raw == "-0") Json.Num("0") else v
        is List<*> -> v.map { toPlain(it) }
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = toPlain(x) }
        else -> v
    }

    /**
     * The JWS payload of a jwsd proof (RFC 9635 7.3.3): the SHA-256 digest of the request CONTENT, or nothing when the request has
     * none ([ABSENT]). A String or ByteArray is the exact content bytes, hashed with no normalization; any other value is hashed as
     * its strict canonical JSON, which is then the content the sender must transmit byte for byte.
     */
    fun gnapContentDigest(body: Any?): ByteArray = when {
        body === ABSENT -> ByteArray(0)
        body is String -> GnapJs.sha256(Jose.utf8(body))
        body is ByteArray -> GnapJs.sha256(body)
        else -> GnapJs.sha256(Jose.utf8(Json.canonicalizeStrict(toPlain(body))))
    }

    private fun bodyOf(args: Map<String, Any?>): Any? = if (args.containsKey("body")) args["body"] else ABSENT

    /**
     * Produce a GNAP `jwsd` detached-JWS proof over `args.body`, signed by the client key. `args`: body, key ({secretKey,
     * publicKey}), htm, uri, created (epoch SECONDS), kid, accessTokenValue. Returns `{detachedJws, header, holder}`.
     */
    fun signGnapRequest(args: Map<String, Any?>): Map<String, Any?> {
        val created = args["created"] ?: Json.Num(Math.floorDiv(System.currentTimeMillis(), 1000L).toString())
        val key = map(args["key"])
        val ed = edKey(key["secretKey"])
        val holder = Keys.b64u(secretBytes(key["publicKey"]))
        val header = obj("alg" to "EdDSA", "typ" to JWSD_TYP, "htm" to (args["htm"] as String).uppercase(Locale.ROOT), "uri" to args["uri"], "created" to created)
        if (args.containsKey("kid")) header["kid"] = args["kid"]
        if (args.containsKey("accessTokenValue")) header["ath"] = athOf(args["accessTokenValue"])
        val payload = gnapContentDigest(bodyOf(args))
        val protectedB64u = Keys.b64u(Jose.utf8(GnapJs.stringify(header)))
        val signingInput = "$protectedB64u.${Keys.b64u(payload)}".toByteArray(Charsets.US_ASCII)
        return obj("detachedJws" to "$protectedB64u..${Keys.b64u(ed.sign(signingInput))}", "header" to header, "holder" to holder)
    }

    private fun canonicalB64uError(seg: String): String? {
        for (c in seg) if (!((c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '-' || c == '_')) return "bad-character"
        if (seg.length % 4 == 1) return "non-canonical-base64url (impossible length)"
        return if (Pca.decodeB64uStrict(seg, -1) == null) "non-canonical-base64url" else null
    }

    private const val JWS_PREFIX = "non-canonical compact JWS: "

    private class SegErr(val msg: String) : Exception(msg)

    /** The canonical-spelling gate for the protected and signature segments of a detached JWS: the header, or [SegErr]. */
    private fun canonicalSegments(p: String, s: String): Map<String, Any?> {
        if (p.length + s.length > 64 * 1024) throw SegErr(JWS_PREFIX + "too-long")
        if (p.isEmpty() || s.isEmpty()) throw SegErr(JWS_PREFIX + "empty-segment")
        canonicalB64uError(p)?.let { throw SegErr(JWS_PREFIX + it) }
        val bytes = Keys.unb64u(p)
        if (bytes.size >= 3 && (bytes[0].toInt() and 0xff) == 0xef && (bytes[1].toInt() and 0xff) == 0xbb && (bytes[2].toInt() and 0xff) == 0xbf)
            throw SegErr(JWS_PREFIX + "bom")
        val text = try { fatalUtf8(bytes) } catch (ex: CharacterCodingException) { throw SegErr(JWS_PREFIX + "bad-utf8") }
        val parsed = try { Json.parse(text) } catch (ex: RuntimeException) { throw SegErr(JWS_PREFIX + "bad-json") } catch (ex: StackOverflowError) {
            throw SegErr(JWS_PREFIX + "bad-json")
        }
        if (parsed !is Map<*, *>) throw SegErr(JWS_PREFIX + "not-an-object")
        canonicalB64uError(s)?.let { throw SegErr(JWS_PREFIX + it) }
        return map(parsed)
    }

    private fun edVerify(holder: String, msg: ByteArray, sigB64u: String): Boolean = try {
        val sig = Pca.decodeB64uStrict(sigB64u, 64)
        val pub = Pca.decodeB64uStrict(holder, 32)
        if (sig == null || pub == null) false
        else {
            val v = Ed25519Signer()
            v.init(false, Ed25519PublicKeyParameters(pub, 0))
            v.update(msg, 0, msg.size)
            v.verifySignature(sig)
        }
    } catch (e: RuntimeException) {
        false
    }

    /** What the JOSE library accepts of the protected header before it checks the signature: a recognized `crit` only, an EdDSA alg. */
    private fun joseHeaderOk(h: Map<String, Any?>): Boolean {
        if (h.containsKey("crit")) {
            val crit = h["crit"]
            if (crit !is List<*> || crit.isEmpty()) return false
            if (crit.any { it != "b64" }) return false
            if (h["b64"] !is Boolean) return false
        }
        return h["alg"] == "EdDSA"
    }

    private fun fail(reason: String) = obj("ok" to false, "reason" to reason)

    /**
     * Verify a GNAP `jwsd` detached-JWS proof and bind the request to the holder key. FAILS CLOSED on a bad signature, a tampered
     * body, a wrong holder, a mismatched `htm`/`uri`, a stale or future `created`, an `ath` that does not bind the named access token,
     * or a replayed proof. `args`: detachedJws, body, holder, htm, uri, maxAgeSec, now (epoch ms), accessTokenValue, seenProof
     * ([SeenProof]), replayCheck (`"unchecked"`). Throws [GnapError] when neither a replay store nor the explicit opt-out is given.
     */
    fun verifyGnapRequest(args: Map<String, Any?>): Map<String, Any?> {
        val seen = args["seenProof"]
        if (seen !is SeenProof && args["replayCheck"] != "unchecked")
            throw GnapError("verifyGnapRequest: supply args.seenProof (a replay store) or set args.replayCheck to 'unchecked'")
        val dj = args["detachedJws"]
        if (dj is String && dj.length > MAX_DETACHED_JWS_CHARS) return fail("detached JWS exceeds the size limit")
        return try {
            verifyJwsd(args, dj, seen as? SeenProof)
        } catch (e: RuntimeException) {
            fail("malformed jwsd request")
        } catch (e: StackOverflowError) {
            fail("malformed jwsd request")
        }
    }

    private fun verifyJwsd(args: Map<String, Any?>, dj: Any?, seen: SeenProof?): Map<String, Any?> {
        if (dj !is String) return fail("malformed jwsd request")
        val parts = dj.split(".")
        if (parts.size != 3) return fail("not a compact JWS (expected three dot-separated parts)")
        val (protectedB64u, mid, signature) = parts
        val holder = asEd25519(args["holder"]) ?: return fail("holder is not a canonical base64url Ed25519 public key")
        val payloadB64u = Keys.b64u(gnapContentDigest(bodyOf(args)))
        if (mid.isNotEmpty() && mid != payloadB64u) return fail("not a DETACHED compact JWS")
        val header = try { canonicalSegments(protectedB64u, signature) } catch (e: SegErr) { return fail("non-canonical detached JWS: ${e.msg}") }
        val sigFail = "jwsd signature does not verify under the holder key (or body was tampered)"
        if (!joseHeaderOk(header)) return fail(sigFail)
        if (!edVerify(holder, "$protectedB64u.$payloadB64u".toByteArray(Charsets.US_ASCII), signature)) return fail(sigFail)
        if (header["typ"] != JWSD_TYP) return fail("unexpected typ (not gnap-binding-jwsd)")
        if (header["alg"] != "EdDSA") return fail("unexpected alg (not EdDSA)")
        val htm = header["htm"]
        if (htm !is String || htm.uppercase(Locale.ROOT) != (args["htm"] as String).uppercase(Locale.ROOT)) return fail("htm does not match the request method")
        val uri = header["uri"]
        if (uri !is String || uri != args["uri"]) return fail("uri does not match the request target")
        val createdO = header["created"]
        val created = if (createdO is Json.Num) GnapJs.num(createdO) else null
        if (created == null || created.isNaN() || created.isInfinite()) return fail("missing or malformed created")
        val nowO = args["now"]
        val nowMs = if (nowO == null) System.currentTimeMillis().toDouble() else GnapJs.num(nowO)!!
        val nowSec = Math.floor(nowMs / 1000)
        val maxO = args["maxAgeSec"]
        val maxAge = if (maxO == null) 300.0 else GnapJs.num(maxO)!!
        if (!(nowSec.isFinite() && created <= nowSec + 60)) return fail("created is in the future")
        if (!(maxAge.isFinite() && nowSec - created <= maxAge)) return fail("jwsd proof is stale")
        val ath = header["ath"]
        if (args.containsKey("accessTokenValue") && (ath !is String || ath != athOf(args["accessTokenValue"]))) return fail("ath does not bind the named access token")
        if (seen != null) {
            val replayed = try { seen.seen(athOf(dj), created + maxAge) != false } catch (e: Exception) { true }
            if (replayed) return fail("jwsd proof replayed (or the replay store failed)")
        }
        val out = obj("alg" to "EdDSA", "typ" to JWSD_TYP, "htm" to htm, "uri" to uri, "created" to createdO)
        if (header["kid"] is String) out["kid"] = header["kid"]
        if (ath is String) out["ath"] = ath
        return obj("ok" to true, "holder" to holder, "header" to out)
    }

    // ---- continuation / step-up ----
    /**
     * Decide whether a grant request needs a continuation / step-up: it does when GNAP interaction is requested, when an explicit
     * higher tier is asked for, or when the request asks for rights BEYOND the issuer's own authority. `opts`: issuerChain, tier.
     * Returns `{required, reason, beyond, tier}`.
     */
    fun gnapRequestRequiresStepUp(req: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        val o: Map<String, Any?> = opts ?: emptyMap()
        val beyond = ArrayList<Any?>()
        if (GnapJs.truthy(o["issuerChain"])) {
            val G = grantedAccessOf(o["issuerChain"])
            for (r in normalizeAccess(accessOf(req))) if (!accessWithin(G, map(r))) beyond.add(r)
        }
        if (req == null) throw GnapError("grant request is null")
        var interactRequested = false
        if (GnapJs.has(req, "interact")) {
            val it = map(req)["interact"] ?: throw GnapError("interact is null")
            val start = GnapJs.member(it, "start")
            interactRequested = start is List<*> && start.isNotEmpty()
        }
        val tierO = o["tier"]
        val tierN = if (tierO == null) null else GnapJs.num(tierO)
        val required = interactRequested || beyond.isNotEmpty() || (tierN != null && tierN > 1)
        val tier = tierO ?: Json.Num(if (beyond.isEmpty()) "2" else "3")
        val reason = when {
            !required -> "no step-up required"
            beyond.isNotEmpty() -> "requested rights exceed the issuer's authority (${beyond.size} right(s) beyond)"
            interactRequested -> "GNAP interaction requested"
            else -> "tier ${GnapJs.str(tier)} step-up required"
        }
        return obj("required" to required, "reason" to reason, "beyond" to beyond, "tier" to tier)
    }

    /**
     * Begin a GNAP continuation: emit the `continue` handle and the PCA step-up it resolves through. `args`: signerSet, t, tier,
     * continueUri, continueToken, wait, reason. Returns `{response, stepUp}`.
     */
    fun beginGnapContinuation(args: Map<String, Any?>): Map<String, Any?> {
        val cont = obj("uri" to args["continueUri"], "access_token" to obj("value" to args["continueToken"], "bound" to true))
        if (args.containsKey("wait")) cont["wait"] = args["wait"]
        val reason = args["reason"] ?: "tier ${GnapJs.str(args["tier"])} co-signature required to continue"
        return obj("response" to obj("continue" to cont),
            "stepUp" to obj("tier" to args["tier"], "t" to args["t"], "signerSet" to args["signerSet"], "reason" to reason, "continueToken" to args["continueToken"]))
    }

    private fun validT(t: Any?): Int {
        val d = GnapJs.num(t)
        if (d == null || (d != 1.0 && d != 2.0 && d != 3.0)) throw IllegalArgumentException("shareMessage: t must be 1, 2 or 3")
        return d.toInt()
    }

    /**
     * One role's step-up co-signature share over the action's PCActn: the co-signature a guardian or principal device returns through
     * the GNAP continuation. It binds the signer set and `t` (replay-safe).
     */
    fun gnapStepUpShare(body: Map<String, Any?>, role: String, secret: Any?, signerSet: Any?, t: Any?): Map<String, Any?> {
        // the reference hashes a signer set that is not an array as the empty set
        val set = if (signerSet is List<*>) list(signerSet) else ArrayList<Any?>()
        return SignersMore.signThresholdShare(role, Keys.ed25519(edKey(secret)), Pca.thresholdMessage(body), set, validT(t))
    }

    /**
     * Resolve a continuation: build the action's PCActn (agent leaf signature) and FOLD the step-up co-signatures into its `threshold`,
     * then verify the threshold `t` is reached. `args`: grant, chain, plan, nodeId, params, counter, aud, now, ttlMs, agentLeafSecret,
     * signerSet, t, cosignSecrets ([{role, secret}]). Returns `{pcactn, threshold, verdict}`.
     */
    fun completeGnapContinuation(args: Map<String, Any?>): Map<String, Any?> {
        val chainO = args["chain"]
        if (chainO !is List<*> || chainO.isEmpty()) throw GnapError("completeGnapContinuation: empty chain")
        val agent = Keys.ed25519(edKey(args["agentLeafSecret"]))
        val s = Issue.ActSpec(
            grant = map(args["grant"]),
            chain = list(chainO),
            plan = Issue.commitPlan(list(args["plan"]).map { map(it) }),
            nodeId = args["nodeId"] as String,
            counter = Json.asLong(args["counter"]),
            signer = agent,
            aud = args["aud"] as String,
            params = if (args.containsKey("params")) map(args["params"]) else null,
            iat = if (args.containsKey("now")) Json.asLong(args["now"]) else null,
            ttlMs = if (args.containsKey("ttlMs")) Json.asLong(args["ttlMs"]) else null,
        )
        val pcactn = Issue.buildPCActn(s)
        val message = Pca.thresholdMessage(pcactn)
        val t = validT(args["t"])
        val signerSet = list(args["signerSet"])
        val shares = ArrayList<Any?>()
        shares.add(SignersMore.signThresholdShare("agent", agent, message, signerSet, t))
        for (cs in list(args["cosignSecrets"]))
            shares.add(SignersMore.signThresholdShare(map(cs)["role"] as String, Keys.ed25519(edKey(map(cs)["secret"])), message, signerSet, t))
        val threshold = obj("shares" to shares)
        val verdict = GnapThreshold.verify(threshold, message, signerSet, t)
        val withThreshold = LinkedHashMap(pcactn)
        withThreshold["threshold"] = threshold
        return obj("pcactn" to withThreshold, "threshold" to threshold, "verdict" to verdict)
    }

    // ---- the profile ----
    /** The machine-readable Agent-GNAP profile spec. */
    fun agentGnapProfile(): Map<String, Any?> = GnapProfile.profile()
}
