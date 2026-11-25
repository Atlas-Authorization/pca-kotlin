package net.atlasauth.pca.txntokens

import java.util.Date
import java.util.UUID
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.Jws
import net.atlasauth.pca.verifier.Keys

/** The replay hook: called with the token's txn (draft-11) or jti (legacy) and its exp; a truthy result means "already seen" and refuses the token. */
fun interface SeenTxn {
    fun seen(id: String, exp: Double): Any?
}

/** Thrown when a verifier is configured without a required security component. [code]: replay_store_required. */
class TxnTokenError(val code: String, message: String) : RuntimeException(message)

/**
 * The OAuth chain-of-custody PROFILE of a PCA capability chain: the RFC 8693 nested `act` projection ([subActChain], [actDepth],
 * [toRfc8693Act]) and the EdDSA-signed Transaction Token of draft-ietf-oauth-transaction-tokens ([toTransactionToken],
 * [fromTransactionToken]). The token is an interop envelope, not a bearer credential: the PCActn's signed capability chain stays the
 * credential. Maps use the reference's member names; a refusal throws IllegalArgumentException (or [TxnTokenError] for a verifier
 * configured without a replay store).
 */
object TxnTokens {
    /** draft-ietf-oauth-transaction-tokens-11 header typ. */
    const val TXN_TOKEN_TYP_DRAFT_11 = "txntoken+jwt"
    /** Upper bound on an accepted token string (adversarial-size guard, checked before any parsing). */
    const val MAX_TOKEN_CHARS = 16384
    private const val TXN_TOKEN_TYP = "txn_token+jwt"
    private const val DEFAULT_TTL_SEC = 120.0
    private const val EDDSA = "EdDSA"
    private val systemClock: () -> Long = { System.currentTimeMillis() }

    private fun bad(msg: String): Nothing = throw IllegalArgumentException(msg)

    // ---- RFC 8693 section 4.1 nested actor claim ----

    /** {sub: root issuer, act: {sub: holder0, act: {sub: holder1 ...}}}: one nested act per delegation hop, root to leaf. */
    fun subActChain(chain: Any?): Map<String, Any?> {
        if (chain !is List<*> || chain.isEmpty()) bad("subActChain: chain must be a non-empty CapabilityChain")
        var act: Map<String, Any?>? = null
        for (i in chain.indices.reversed()) {
            val holder = Js.get(chain[i], "holder")
            if (!Js.nonEmptyString(holder)) bad("subActChain: hop $i has no holder")
            act = Js.obj("sub" to holder).also { if (act != null) it["act"] = act }
        }
        val issuer = Js.get(chain[0], "issuer")
        if (!Js.nonEmptyString(issuer)) bad("subActChain: root hop has no issuer (principal)")
        return Js.obj("sub" to issuer, "act" to act)
    }

    /** The number of nested act levels (the top-level sub does not count). */
    fun actDepth(claim: Any?): Long {
        if (!Js.isObjectLike(claim)) bad("actDepth: expected a sub/act claim object")
        var depth = 0L
        var cur = Js.get(claim, "act")
        while (Js.truthy(cur)) {
            depth++
            cur = Js.get(cur, "act")
        }
        return depth
    }

    /** RFC 8693 ordering of an act chain: the MOST RECENT actor outermost. The sub is unchanged. */
    fun toRfc8693Act(claim: Any?): Map<String, Any?> {
        if (claim == null) bad("toRfc8693Act: claim is required")
        val actors = ArrayList<Pair<Boolean, Any?>>() // (sub present, sub)
        var c = Js.get(claim, "act")
        while (Js.truthy(c)) {
            actors.add(Js.own(c, "sub") to Js.get(c, "sub"))
            c = Js.get(c, "act")
        }
        var act: Map<String, Any?>? = null
        for ((has, sub) in actors) {
            act = Js.obj().also { if (has) it["sub"] = sub; if (act != null) it["act"] = act }
        }
        return Js.obj().also { if (Js.own(claim, "sub")) it["sub"] = Js.get(claim, "sub"); if (act != null) it["act"] = act }
    }

    // ---- Transaction Token ----

    private fun signingKey(key: Any?): Keys.EdKey = when (key) {
        is ByteArray -> if (key.size != 32) bad("toTransactionToken: a raw Ed25519 secret key must be 32 bytes") else Keys.edFromSeed(key)
        is Keys.EdKey -> key
        else -> bad("toTransactionToken: issuerKey must be a 32-byte Ed25519 seed")
    }

    /**
     * Mint a signed Transaction Token carrying the chain's custody (sub / act) and the action as its transaction context (tctx). Args
     * (reference names): chain, action {verb, resource, aud}, issuerKey (32-byte Ed25519 seed as ByteArray, or a [Keys.EdKey]), issuer,
     * ttlSec (120), profile (draft-11 default, or legacy), and for draft-11 scope, reqWl, txn (random UUID), trustDomain (action.aud).
     * [clock]: epoch ms.
     */
    fun toTransactionToken(args: Map<String, Any?>, clock: () -> Long = systemClock): String {
        val issuer = args["issuer"]
        if (!Js.nonEmptyString(issuer)) bad("toTransactionToken: `issuer` is required")
        val action = args["action"]
        if (action !is Map<*, *> || action["verb"] !is String || action["resource"] !is String || action["aud"] !is String) {
            bad("toTransactionToken: `action` must have string verb, resource and aud")
        }
        val custody = subActChain(args["chain"])
        val ttlO = args["ttlSec"]
        val ttl = if (ttlO == null) DEFAULT_TTL_SEC else Js.num(ttlO) ?: Double.NaN
        if (ttl.isNaN() || ttl.isInfinite() || ttl <= 0) bad("toTransactionToken: ttlSec must be > 0")
        val nowSec = Math.floorDiv(clock(), 1000L)
        val key = signingKey(args["issuerKey"])
        val profile = args["profile"]
        val draft = profile == null || profile == "draft-11"
        if (profile != null && profile != "legacy" && !draft) bad("toTransactionToken: profile must be legacy or draft-11")

        val tctx = Js.obj("verb" to action["verb"], "resource" to action["resource"], "aud" to action["aud"])
        val header = Js.obj("alg" to EDDSA)
        val claims = Js.obj("tctx" to tctx)
        if (custody["act"] != null) claims["act"] = custody["act"]
        if (draft) {
            if (!Js.nonEmptyString(args["scope"])) bad("toTransactionToken: draft-11 requires `scope`")
            if (!Js.nonEmptyString(args["reqWl"])) bad("toTransactionToken: draft-11 requires `reqWl`")
            val td = args["trustDomain"] ?: action["aud"]
            if (!Js.nonEmptyString(td)) bad("toTransactionToken: draft-11 requires a non-empty trust domain (aud)")
            claims["txn"] = args["txn"] ?: UUID.randomUUID().toString()
            claims["scope"] = args["scope"]
            claims["req_wl"] = args["reqWl"]
            header["typ"] = TXN_TOKEN_TYP_DRAFT_11
            claims["iat"] = Js.n(nowSec)
            claims["iss"] = issuer
            claims["sub"] = custody["sub"]
            claims["aud"] = td
            claims["exp"] = Js.jsNum(nowSec + ttl)
        } else {
            header["typ"] = TXN_TOKEN_TYP
            claims["iat"] = Js.n(nowSec)
            claims["iss"] = issuer
            claims["sub"] = custody["sub"]
            claims["aud"] = action["aud"]
            claims["exp"] = Js.jsNum(nowSec + ttl)
            claims["jti"] = UUID.randomUUID().toString()
        }
        return Jws.signEd25519(header, claims, key)
    }

    /**
     * Verify a Transaction Token's EdDSA signature and parse out the custody chain and the transaction context. [verifyKey]: the raw
     * 32-byte Ed25519 public key (ByteArray), a public JWK map or a public key. Options (reference names): profile, audience (required for
     * draft-11), clockToleranceSec, now (epoch ms as a number, or a Date), seenTxn ([SeenTxn]), replayCheck ('unchecked').
     * Returns {chain, action?, tctx, claims}.
     */
    fun fromTransactionToken(jwt: Any?, verifyKey: Any?, opts: Map<String, Any?>? = null, clock: () -> Long = systemClock): Map<String, Any?> {
        val o = opts ?: emptyMap()
        val profile = o["profile"]
        val draft = profile == null || profile == "draft-11"
        if (profile != null && profile != "legacy" && !draft) bad("fromTransactionToken: profile must be legacy or draft-11")
        if (draft && !Js.nonEmptyString(o["audience"])) bad("fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)")
        val seen = o["seenTxn"] as? SeenTxn
        if (seen == null && o["replayCheck"] != "unchecked") {
            throw TxnTokenError("replay_store_required", "fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'")
        }
        // A non-finite tolerance or an invalid clock makes every exp/nbf comparison pass.
        if (o["clockToleranceSec"] != null) {
            val tol = Js.num(o["clockToleranceSec"]) ?: Double.NaN
            if (!(tol.isFinite() && tol >= 0)) throw IllegalArgumentException("fromTransactionToken: clockToleranceSec must be a finite number >= 0")
        }
        if (o["now"] != null && o["now"] !is Date && Js.num(o["now"])?.isFinite() != true) bad("fromTransactionToken: now must be a number or a Date")
        if (jwt is String && jwt.length > MAX_TOKEN_CHARS) bad("transaction token: token exceeds the size limit")
        val canon = Jws.assertCanonicalCompactJws(jwt) // canonical-spelling gate BEFORE the JOSE layer
        val key: Any? = if (verifyKey is ByteArray) {
            if (verifyKey.size != 32) bad("fromTransactionToken: a raw Ed25519 public key must be 32 bytes")
            Jws.ed25519(verifyKey)
        } else verifyKey
        val now = o["now"]
        val nowMs = when {
            now is Date -> now.time
            now != null -> (Js.num(now)?.takeIf { it.isFinite() } ?: bad("fromTransactionToken: now must be a number or a Date")).toLong()
            else -> clock()
        }
        val vo = Jws.JwtOptions(
            typ = if (draft) TXN_TOKEN_TYP_DRAFT_11 else TXN_TOKEN_TYP,
            algorithms = listOf(EDDSA),
            requiredClaims = if (draft) listOf("iat", "exp", "aud", "sub", "txn", "scope", "req_wl") else listOf("exp"),
            audience = o["audience"],
            clockTolerance = o["clockToleranceSec"],
        )
        val payload = Jws.jwtVerify(jwt as String, canon, key, vo, nowMs).payload
        if (draft) for (k in listOf("txn", "scope", "req_wl")) if (!Js.nonEmptyString(payload[k])) bad("transaction token: `$k` must be a non-empty string")
        if (!Js.nonEmptyString(payload["sub"])) bad("transaction token: missing `sub` (root principal)")
        val (tctx, action) = readTctx(payload["tctx"], draft)
        if (draft && payload.containsKey("rctx") && payload["rctx"] !is Map<*, *>) bad("transaction token: malformed `rctx`")
        val act = if (payload.containsKey("act")) normalizeAct(payload["act"]) else null
        // Consume the identifier last: a token refused for any other reason never burns its transaction id.
        if (seen != null) {
            val id = if (draft) payload["txn"] else payload["jti"]
            if (!Js.nonEmptyString(id)) bad("transaction token: no transaction identifier to check for replay")
            if (Js.truthy(seen.seen(id as String, Js.num(payload["exp"]) ?: Double.NaN))) bad("transaction token: replayed (transaction identifier already seen)")
        }
        val chain = Js.obj("sub" to payload["sub"]).also { if (act != null) it["act"] = act }
        return Js.obj("chain" to chain).also {
            if (action != null) it["action"] = action
            it["tctx"] = tctx
            it["claims"] = payload
        }
    }

    /** Validate and normalize an untrusted nested act claim (the signature is verified, the shape is not). */
    private fun normalizeAct(node: Any?): Map<String, Any?> {
        if (node !is Map<*, *>) bad("transaction token: malformed `act` claim")
        if (!Js.nonEmptyString(node["sub"])) bad("transaction token: `act.sub` must be a non-empty string")
        return Js.obj("sub" to node["sub"]).also { if (node.containsKey("act")) it["act"] = normalizeAct(node["act"]) }
    }

    /**
     * The transaction context. The draft's tctx is a free-form JSON object, so the draft profile accepts any object; when it uses any of
     * the PCA action keys (verb, resource, aud) it must use all three as strings. The legacy profile requires the PCA action. The
     * action is null only for a free-form draft tctx.
     */
    @Suppress("UNCHECKED_CAST")
    private fun readTctx(raw: Any?, draft: Boolean): Pair<Map<String, Any?>, Map<String, Any?>?> {
        if (raw !is Map<*, *>) bad("transaction token: missing or malformed `tctx`")
        val r = raw as Map<String, Any?>
        val usesPca = r.containsKey("verb") || r.containsKey("resource") || r.containsKey("aud")
        if (!draft || usesPca) {
            if (r["verb"] !is String || r["resource"] !is String || r["aud"] !is String) bad("transaction token: missing or malformed `tctx`")
            return r to Js.obj("verb" to r["verb"], "resource" to r["resource"], "aud" to r["aud"])
        }
        return r to null
    }
}
