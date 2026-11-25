package net.atlasauth.pca.verifier

/**
 * Shared helpers of the K3 operational-plane artifacts ([FreshAt], [Bundle], [ListAuthorized], [GrantResource]): a domain-separated
 * Ed25519 signature over `utf8(domain) || strictCanonical(body)` (packages/pca-grants/src/sig.ts) and the reference's value guards.
 * Every function is total.
 */
object K3Sig {
    @Suppress("UNCHECKED_CAST")
    internal fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    internal fun list(o: Any?): List<Any?>? = o as? List<Any?>

    /** `Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0)` (strict profile). */
    internal fun isSafeInt(o: Any?): Boolean = IntentJs.isNonNeg(o)

    /** A non-empty string of at most `max` UTF-16 code units (`s.length`). */
    internal fun isStr(o: Any?, max: Int = 512): Boolean = o is String && o.isNotEmpty() && o.length <= max

    /** The map without the given member (a copy, insertion order kept). */
    internal fun without(m: Map<String, Any?>, key: String): LinkedHashMap<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for ((k, v) in m) if (k != key) out[k] = v
        return out
    }

    /** True iff `sig` is a canonical 64-byte base64url signature by `signer` over exactly `body` under `domain`. Never throws. */
    // verifyEd already requires a String sig that decodes strictly to 64 bytes (Pca.verifyB64u), so no pre-check here
    internal fun verifyBody(domain: String, body: Any?, signer: Any?, sig: Any?): Boolean = try {
        IntentJs.verifyEd(signer, IntentJs.message(domain, body), sig)
    } catch (e: RuntimeException) {
        false
    }

    /** `String(x)` of a JSON value as the reference prints a number or string into a reason (absent members print `undefined`). */
    internal fun jsText(o: Any?, present: Boolean): String = when {
        !present -> "undefined"
        o == null -> "null"
        // Json.Num.toString() is its raw lexeme, so a number needs no branch of its own
        else -> o.toString()
    }

    /** `hashCanonical({<k1>: v1, ...})` of an ordered list of members. */
    internal fun digestOf(vararg members: Pair<String, Any?>): String {
        val m = LinkedHashMap<String, Any?>()
        for ((k, v) in members) m[k] = v
        return Pca.hashCanonical(m)
    }
}
