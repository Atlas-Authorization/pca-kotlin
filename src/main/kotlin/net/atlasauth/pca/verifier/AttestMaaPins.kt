package net.atlasauth.pca.verifier

/**
 * BUILT-IN, release-signed pins for the Azure MAA token-signing keys: the offline root of the first accepted key set.
 *
 * What ships is a signed allowlist manifest carrying (a) `maa-signing-spki` pins for the self-signed per-instance MAA keys, (b) the SPKI pin of the Microsoft
 * chain root and of the `Microsoft Azure Attestation PCA 2019` intermediate that Microsoft-chained keys must pass through, and (c) a signed
 * `attest-corroboration` record of how many independent network vantage points saw identical key material and by what method. The manifest is verified at
 * load against the issuer public key embedded in this SDK, with the usual expiry and version-floor checks.
 *
 * Guaranteed: with the default key-trust policy there is no trust-on-first-use (the first accepted key set must overlap these signed pins, then the rotation
 * rules apply) and Microsoft-chained keys are accepted only through the pinned root AND intermediate with the leaf CN `Microsoft Azure Attestation 2020`; the
 * manifest cannot be edited, re-signed by another key, rolled back below the shipped version floor or used after its expiry (fail closed: pins expire, so ship
 * a new release or pass explicit `initialPins`); at least three independent vantages corroborated the pins, and that count is inside the signed bytes.
 *
 * Not guaranteed: the offline root is the release signing key plus the recorded corroboration, not a Microsoft-issued root for the self-signed instance keys
 * (Microsoft publishes none). A compromise of the release key, or of every vantage at signing time, defeats it. The Microsoft chain root pin is an anchor in
 * Microsoft's own PKI, narrowed here to the MAA intermediate; no CRL or revocation is consulted. A key the release does not know is accepted only through the
 * rotation rules, never as a fresh root.
 */
@Suppress("UNCHECKED_CAST")
object AttestMaaPins {
    /** The leaf CN Microsoft's MAA signing certificates carry. */
    @JvmField val BUILTIN_CHAIN_LEAF_CN: List<String> = listOf("Microsoft Azure Attestation 2020")

    const val BUILTIN_MAA_PINS_ISSUER_ID: String = AttestMaaPinsData.ISSUER_ID

    /** Where trust is rooted: the embedded release issuer key, as an issuer-key registry. */
    @JvmField val BUILTIN_MAA_PINS_ISSUER_KEYS: Map<String, Any?> = linkedMapOf(AttestMaaPinsData.ISSUER_ID to Json.parse(AttestMaaPinsData.ISSUER_KEY_JSON))

    private const val MAX_LIFETIME_MS = 400.0 * 24 * 3_600_000
    private const val MIN_VANTAGES = 3
    private val CORROBORATION = Regex("vantages=([0-9]+);method=(.*)")

    private fun fail(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    private class Verified(val value: Map<String, Any?>, val notBefore: Double, val expiresAt: Double)

    private fun evaluate(manifest: Any?, issuerKeys: Any?, minVersion: Any?, nowMs: Any?): Pair<Verified?, String?> {
        val body = (manifest as? Map<*, *>)?.get("body") as? Map<*, *>
        val nb = body?.get("notBefore")
        val v0 = AttestAllowlist.verifyAllowlistManifest(
            manifest,
            linkedMapOf("issuerKeys" to issuerKeys, "nowMs" to (nb ?: nowMs), "minVersion" to (minVersion ?: IntentJs.ofLong(1)), "maxLifetimeMs" to IntentJs.ofLong(MAX_LIFETIME_MS.toLong())),
        )
        if (v0["ok"] != true) return Pair(null, "${v0["code"]}: ${v0["reason"]}")
        val vb = v0["body"] as Map<String, Any?>
        val p = AttestAllowlist.projectAllowlist(v0, IntentJs.num(vb["notBefore"])!!)
        val corr = p["corroboration"] as List<Map<String, Any?>>
        if (corr.size != 1) return Pair(null, "manifest must carry exactly one attest-corroboration entry")
        val m = CORROBORATION.matchEntire(corr[0]["label"] as String)
        val vantages = m?.groupValues?.get(1)?.toDouble() ?: 0.0
        if (m == null || vantages < MIN_VANTAGES) return Pair(null, "corroboration records ${vantages.toLong()} vantages < required $MIN_VANTAGES")
        val spkis = p["maaSigningSpkis"] as Map<String, Any?>
        if (spkis.isEmpty()) return Pair(null, "manifest pins no MAA signing key")
        val roots = p["maaChainRootSpkis"] as List<Any?>
        val inters = p["maaChainIntermediateSpkis"] as List<Any?>
        if (roots.isEmpty() || inters.isEmpty()) return Pair(null, "manifest lacks the Microsoft chain root / intermediate pins")
        val revoked = LinkedHashMap<String, Any?>()
        for (r in p["revoked"] as List<Map<String, Any?>>) if (r["kind"] == "maa-signing-spki") (revoked.getOrPut(r["label"] as String) { ArrayList<Any?>() } as MutableList<Any?>).add(r["value"])
        val value = linkedMapOf<String, Any?>(
            "ok" to true, "version" to v0["version"], "digest" to v0["digest"], "expiresAt" to vb["expiresAt"], "maaSigningSpkis" to spkis, "revokedSigningSpkis" to revoked,
            "maaChainRootSpkis" to roots, "maaChainIntermediateSpkis" to inters, "vantages" to IntentJs.ofLong(vantages.toLong()), "method" to m.groupValues[2],
        )
        return Pair(Verified(value, IntentJs.num(vb["notBefore"])!!, IntentJs.num(vb["expiresAt"])!!), null)
    }

    private val SHIPPED: Map<String, Any?> by lazy {
        linkedMapOf("manifest" to Json.parse(AttestMaaPinsData.MANIFEST_JSON), "issuerKeys" to BUILTIN_MAA_PINS_ISSUER_KEYS, "minVersion" to IntentJs.ofLong(AttestMaaPinsData.MIN_VERSION.toLong()))
    }

    /**
     * Load and verify the built-in pin set at `opts.nowMs`, or the substitute `opts.source` `{manifest, issuerKeys, minVersion?}` (tests, or a fork that signs
     * its own pins; the rollback floor of a custom source defaults to 1). Never throws. `{ok: true, version, digest, expiresAt, maaSigningSpkis (by issuer
     * URL), revokedSigningSpkis, maaChainRootSpkis, maaChainIntermediateSpkis, vantages, method}` or `{ok: false, reason}`. The signature is verified at a time
     * inside the manifest's window; the window itself is checked on every call.
     */
    @JvmStatic
    fun loadBuiltinMaaPins(opts: Map<String, Any?>): Map<String, Any?> {
        try {
            val nowRaw = opts["nowMs"]
            if (!IntentJs.isSafeInteger(nowRaw)) return fail("nowMs must be an integer")
            val nowMs = IntentJs.num(nowRaw)!!
            val src: Map<String, Any?> = (opts["source"] as? Map<String, Any?>) ?: SHIPPED
            val (r, why) = evaluate(src["manifest"], src["issuerKeys"], src["minVersion"], nowRaw)
            if (r == null) return fail(why!!)
            if (!(nowMs >= r.notBefore)) return fail("built-in pins are not yet valid (clock behind the release)")
            if (!(nowMs <= r.expiresAt)) return fail("built-in pins expired; update the package or pass explicit initialPins")
            return r.value
        } catch (e: RuntimeException) {
            return fail(e.message ?: "built-in pins error")
        }
    }
}
