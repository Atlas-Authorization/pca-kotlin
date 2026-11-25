package net.atlasauth.pca.payments

import net.atlasauth.pca.payments.PayJs.copy
import net.atlasauth.pca.payments.PayJs.get
import net.atlasauth.pca.payments.PayJs.has
import net.atlasauth.pca.payments.PayJs.map
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Agent payment network tokens: a `NetworkTokenBinding` ties a PCA grant holder to an OPAQUE network-token reference (never a PAN) and carries
 * the PCActn digest onto the charge so the card-network record joins the PCA ledger entry (the reference's network-token module). The Visa and
 * Mastercard adapters are GENERIC mappings of PCA controls onto a neutral shape and make no network call themselves: the caller supplies the
 * [PartnerTransport]. Every check is exact; malformed input is a refusal.
 */
@Suppress("UNCHECKED_CAST")
object NetworkToken {
    const val NETWORK_TOKEN_BINDING_KIND = "pca.network_token_binding"

    /** `token_ref` is an opaque handle: 8..128 chars of [A-Za-z0-9_.:-]. */
    private val REF_RE = Regex("[A-Za-z0-9_.:-]{8,128}")

    private fun luhn(d: String): Boolean {
        var sum = 0
        var dbl = false
        for (i in d.length - 1 downTo 0) {
            var n = d[i].code - 48
            if (dbl) {
                n *= 2
                if (n > 9) n -= 9
            }
            sum += n
            dbl = !dbl
        }
        return sum % 10 == 0
    }

    /** True when a maximal digit run (spaces and hyphens removed) is 13..19 long and Luhn-valid. Whole runs only: no sliding windows. */
    @JvmStatic
    fun looksLikePan(s: String): Boolean {
        // JavaScript's \s: whitespace and line terminators (the Unicode set), plus the hyphen
        val t = s.filter { !PayJs.isWs(it) && it != '-' }
        val run = StringBuilder()
        for (i in 0..t.length) {
            val c = if (i < t.length) t[i] else 'x'
            if (c in '0'..'9') {
                run.append(c)
                continue
            }
            if (run.length in 13..19 && luhn(run.toString())) return true
            run.setLength(0)
        }
        return false
    }

    /** null when the reference is acceptable, else token_ref_malformed or token_ref_looks_like_pan. */
    @JvmStatic
    fun tokenRefError(ref: Any?): String? {
        if (ref !is String || !REF_RE.matches(ref)) return "token_ref_malformed"
        if (looksLikePan(ref)) return "token_ref_looks_like_pan"
        return null
    }

    private fun bodyOf(provider: Any?, tokenRef: Any?, grantDigest: Any?, issuerNonce: Any?, holder: Any?): Map<String, Any?> =
        map(
            "kind" to NETWORK_TOKEN_BINDING_KIND, "v" to Json.Num("1"), "provider" to provider, "token_ref" to tokenRef,
            "grant_digest" to grantDigest, "issuer_nonce" to issuerNonce, "holder" to holder,
        )

    /** The exact bytes the holder signs: utf8 of the canonical-JSON digest of the body (domain-separated by `kind`). */
    @JvmStatic
    fun bindingMessage(b: Map<String, Any?>): ByteArray =
        Pca.hashCanonical(bodyOf(b["provider"], b["token_ref"], b["grant_digest"], b["issuer_nonce"], b["holder"])).toByteArray(Charsets.UTF_8)

    /**
     * Bind a token reference to the grant and its holder. [opts]: provider, tokenRef, grant, issuerNonce (at least 16 chars), holderSecret
     * (32-byte seed) and holderPublic (32 bytes), bytes as ByteArray or `{"$bytes": b64url}`.
     */
    @JvmStatic
    fun bindNetworkToken(opts: Map<String, Any?>): Map<String, Any?> {
        val e = tokenRefError(opts["tokenRef"])
        if (e != null) throw IllegalArgumentException("bindNetworkToken: $e")
        if ((opts["issuerNonce"] as String).length < 16) throw IllegalArgumentException("bindNetworkToken: issuer nonce must be at least 16 chars")
        val seed = PayJs.bytes(opts["holderSecret"])
        val pub = PayJs.bytes(opts["holderPublic"])
        if (seed == null || pub == null) throw IllegalArgumentException("bindNetworkToken: holderSecret and holderPublic are required")
        val core = map(
            "provider" to opts["provider"], "token_ref" to opts["tokenRef"], "grant_digest" to Pca.hashCanonical(opts["grant"]),
            "issuer_nonce" to opts["issuerNonce"], "holder" to Keys.b64u(pub),
        )
        val out = LinkedHashMap<String, Any?>()
        out["kind"] = NETWORK_TOKEN_BINDING_KIND
        out.putAll(core)
        out["binding_proof"] = Keys.b64u(Keys.edFromSeed(seed).sign(bindingMessage(core)))
        return out
    }

    /**
     * Total. null = valid, else the refusal code. [expect]: grant (the one the caller verified), holder (the key the caller expects: the grant's
     * leaf holder), issuerNonce, and optionally provider.
     */
    @JvmStatic
    fun verifyNetworkTokenBinding(b: Any?, expect: Map<String, Any?>): String? {
        try {
            if (b !is Map<*, *> || get(b, "kind") != NETWORK_TOKEN_BINDING_KIND) return "binding_malformed"
            val x = copy(b)
            val e = tokenRefError(x["token_ref"])
            if (e != null) return e
            val prov = x["provider"]
            if (prov !is String || prov.isEmpty() || (has(expect, "provider") && prov != expect["provider"])) return "provider_mismatch"
            if (!has(expect, "grant")) return "binding_malformed"
            if (x["grant_digest"] != Pca.hashCanonical(expect["grant"])) return "grant_digest_mismatch"
            if (x["holder"] != expect["holder"]) return "holder_mismatch"
            if (x["issuer_nonce"] != expect["issuerNonce"]) return "issuer_nonce_mismatch"
            val pk = Keys.unb64u(x["holder"] as String)
            val msg = bindingMessage(x)
            val sig = Keys.unb64u(x["binding_proof"] as String)
            return if (Pca.ed25519Strict(pk, msg, sig)) null else "binding_proof_invalid"
        } catch (ex: RuntimeException) {
            return "binding_malformed"
        }
    }

    // ---- controls + provider interface ----

    /** The network-side controls: always an upper-bounded copy of the rail limits, echoing the grant digest as metadata. */
    @JvmStatic
    fun controlsFromLimits(limits: Map<String, Any?>, grant: Any?): Map<String, Any?> {
        val out = map(
            "currency" to limits["currency"], "perAuthorizationMax" to limits["perAuthorizationMax"], "totalMax" to limits["totalMax"],
            "categories" to ArrayList(limits["categories"] as List<Any?>), "merchants" to ArrayList(limits["merchants"] as List<Any?>),
        )
        if (has(limits, "expiresAt")) out["expiresAt"] = limits["expiresAt"]
        out["metadata"] = map("grant_digest" to Pca.hashCanonical(grant))
        return out
    }

    /** A token provider (Visa, Mastercard, generic). */
    interface NetworkTokenProvider {
        fun id(): String

        /** Issue/activate a token whose own controls equal [controls]; returns `{token_ref}`. */
        fun issue(controls: Map<String, Any?>, agentId: String): Map<String, Any?>

        /** Suspend the token (grant revoked). Must be idempotent. */
        fun suspend(tokenRef: String, reason: String)
    }

    /**
     * Issuance gate: builds the controls from the rail limits, asks the provider to issue, then binds the returned reference to the grant and
     * holder. A provider response whose token_ref is malformed or PAN-shaped is refused. [opts]: limits, grant, agentId, holderSecret,
     * holderPublic, issuerNonce. Returns `{binding, controls}`.
     */
    @JvmStatic
    fun issueBoundNetworkToken(provider: NetworkTokenProvider, opts: Map<String, Any?>): Map<String, Any?> {
        val controls = controlsFromLimits(opts["limits"] as Map<String, Any?>, opts["grant"])
        val r = provider.issue(controls, opts["agentId"] as String)
        val bo = map(
            "provider" to provider.id(), "tokenRef" to r["token_ref"], "grant" to opts["grant"], "issuerNonce" to opts["issuerNonce"],
            "holderSecret" to opts["holderSecret"], "holderPublic" to opts["holderPublic"],
        )
        return map("binding" to bindNetworkToken(bo), "controls" to controls)
    }

    /** Grant revoked: suspend. Provider errors propagate (a failed suspend is not a success). */
    @JvmStatic
    fun suspendOnRevoke(provider: NetworkTokenProvider, binding: Map<String, Any?>) = provider.suspend(binding["token_ref"] as String, "grant_revoked")

    // ---- the charge carries the PCActn digest ----

    /** The metadata a charge/authorization carries: fixed keys, digest values (no PII, no PAN). */
    @JvmStatic
    fun settlementMetadata(binding: Map<String, Any?>, pcactnDigest: String): Map<String, Any?> =
        map("pca_grant" to binding["grant_digest"], "pca_pcactn" to pcactnDigest, "pca_token_ref" to binding["token_ref"])

    /**
     * The one way to start a network-token charge: builds the signed PCActn for the charge and returns the metadata for the network request,
     * derived from THAT PCActn's digest. Returns `{pcactn, node, metadata, pcactnDigest}`; [opts] are those of [Payments.chargeToPCActn].
     */
    @JvmStatic
    fun chargeWithNetworkToken(binding: Map<String, Any?>, mandate: Map<String, Any?>, charge: Map<String, Any?>, opts: Map<String, Any?>): Map<String, Any?> {
        if (tokenRefError(binding["token_ref"]) != null) throw IllegalArgumentException("chargeWithNetworkToken: bad binding")
        if (binding["grant_digest"] != Pca.hashCanonical(mandate["grant"])) throw IllegalArgumentException("chargeWithNetworkToken: binding is for another grant")
        val r = Payments.chargeToPCActn(mandate, charge, opts)
        val digest = Pca.hashCanonical(r["pcactn"])
        return map("pcactn" to r["pcactn"], "node" to r["node"], "metadata" to settlementMetadata(binding, digest), "pcactnDigest" to digest)
    }

    /** A network settlement record joins the ledger entry only if all three echoed values match exactly: `{ok: true}` or `{ok: false, reasons}`. */
    @JvmStatic
    fun reconcileNetworkSettlement(expected: Map<String, Any?>, record: Map<String, Any?>?): Map<String, Any?> {
        val m = get(record, "metadata") ?: map()
        val reasons = ArrayList<Any?>()
        val pc = get(m, "pca_pcactn")
        // a settlement without the PCActn digest never joins, even if the expectation is empty too
        if (pc !is String || pc.isEmpty() || emptyLength(expected["pcactnDigest"])) reasons.add("pcactn_digest_missing")
        if (get(m, "pca_grant") != expected["grantDigest"]) reasons.add("grant_digest_mismatch")
        if (pc != expected["pcactnDigest"]) reasons.add("pcactn_digest_mismatch")
        if (get(m, "pca_token_ref") != expected["tokenRef"]) reasons.add("token_ref_mismatch")
        return if (reasons.isEmpty()) map("ok" to true) else map("ok" to false, "reasons" to reasons)
    }

    /** `x.length === 0`: undefined/null has no length (TypeError), a number has none (false). */
    private fun emptyLength(x: Any?): Boolean {
        if (x == null) throw NullPointerException("expected.pcactnDigest is required")
        return PayJs.jsLength(x) == 0.0
    }

    // ---- generic partner-gated adapters ----

    /** The partner's HTTP surface; the caller supplies it (these adapters make no network call themselves). */
    fun interface PartnerTransport {
        fun post(path: String, body: Map<String, Any?>): Map<String, Any?>
    }

    internal fun encodeUriComponent(s: String): String {
        if (Json.hasLoneSurrogate(s)) throw IllegalArgumentException("URI malformed") // the JavaScript URIError
        val sb = StringBuilder()
        for (b in Json.utf8(s)) {
            val c = (b.toInt() and 0xff).toChar()
            if (c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || "-_.!~*'()".indexOf(c) >= 0) sb.append(c)
            else sb.append('%').append(Character.toUpperCase(Character.forDigit((b.toInt() shr 4) and 15, 16))).append(Character.toUpperCase(Character.forDigit(b.toInt() and 15, 16)))
        }
        return sb.toString()
    }

    /**
     * LABEL: GENERIC MAPPING, NOT THE PARTNER WIRE FORMAT. The path and body names are placeholders; replace them with the partner's documented
     * ones once access exists. The control VALUES are exact copies of PCA's limits.
     */
    private fun partnerAdapter(id: String, scopeKey: String, t: PartnerTransport): NetworkTokenProvider = object : NetworkTokenProvider {
        override fun id(): String = id

        override fun issue(controls: Map<String, Any?>, agentId: String): Map<String, Any?> {
            val scope = map(
                "currency" to controls["currency"], "per_authorization_max" to controls["perAuthorizationMax"], "total_max" to controls["totalMax"],
                "merchant_categories" to controls["categories"], "merchants" to controls["merchants"],
            )
            if (has(controls, "expiresAt")) scope["expires_at"] = controls["expiresAt"]
            val r = t.post("/tokens", map("agent_id" to agentId, scopeKey to scope, "metadata" to controls["metadata"]))
            val ref = r["token_ref"]
            val e = tokenRefError(ref)
            if (e != null) throw IllegalStateException("$id: provider returned $e")
            return map("token_ref" to ref)
        }

        override fun suspend(tokenRef: String, reason: String) {
            t.post("/tokens/" + encodeUriComponent(tokenRef) + "/suspend", map("reason" to reason))
        }
    }

    /** Visa Intelligent Commerce, generic mapping (partner-gated; unverified field names). */
    @JvmStatic
    fun visaIntelligentCommerceAdapter(t: PartnerTransport): NetworkTokenProvider = partnerAdapter("visa_ic", "instructions", t)

    /** Mastercard Agent Pay (agentic tokens over MDES), generic mapping (partner-gated; unverified field names). */
    @JvmStatic
    fun mastercardAgentPayAdapter(t: PartnerTransport): NetworkTokenProvider = partnerAdapter("mastercard_agent_pay", "session_scope", t)
}
