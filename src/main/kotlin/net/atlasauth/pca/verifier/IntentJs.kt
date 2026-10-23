package net.atlasauth.pca.verifier

import java.math.BigDecimal
import java.math.MathContext
import java.math.RoundingMode
import java.nio.charset.StandardCharsets

/**
 * Shared helpers of the Intent Layer v2 rules (13-18): JavaScript value semantics over the [Json] tree, so every rule
 * judges numbers by their IEEE-754 binary64 value exactly like the TypeScript reference (packages/pca/src).
 *
 * Verifier-held state (the `context.intent_v2` object, the W-B primitive inputs, plaintext params) is NORMALIZED once on
 * entry with [normalize]: every [Json.Num] becomes the number `JSON.parse` would yield, spelled as JavaScript prints it
 * (integral values as plain digits, others as the shortest round-trip decimal; `-0` stays `"-0"`). After that the strict
 * canonicalizer and every numeric test agree with the reference on any lexical form (`1.0`, `1e3`, `950000.0`).
 */
object IntentJs {
    internal const val MAX_SAFE = 9007199254740991.0

    // ---- values ----
    internal fun isObj(o: Any?): Boolean = o is Map<*, *>
    internal fun isArr(o: Any?): Boolean = o is List<*>
    internal fun isStr(o: Any?): Boolean = o is String

    @Suppress("UNCHECKED_CAST")
    internal fun obj(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    internal fun arr(o: Any?): List<Any?> = o as List<Any?>

    /** Own member (JSON null counts as present, like a defined property). */
    internal fun own(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    /**
     * An optional member: ABSENT means [dflt]; a member that is present (JSON null included) is returned as is, so a
     * present null reaches the type check and fails closed (it is malformed, never a default).
     */
    internal fun opt(o: Any?, k: String, dflt: Any?): Any? = if (own(o, k)) get(o, k) else dflt

    /** `o[k]` or null when absent (callers that need presence use [own]). */
    internal fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    /** The binary64 value of a JSON number (Num, Int, Long, Double), else null (not a number). */
    internal fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Int -> o.toDouble()
        is Long -> o.toDouble()
        is Double -> o
        else -> null
    }

    internal fun isNumber(o: Any?): Boolean = num(o) != null
    internal fun isNegZero(d: Double): Boolean = d == 0.0 && java.lang.Double.doubleToRawLongBits(d) != 0L

    /** `Number.isSafeInteger` (accepts -0). */
    internal fun isSafeInteger(o: Any?): Boolean {
        val d = num(o) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= MAX_SAFE
    }

    /** The reference `isInt`: a safe integer that is not -0. */
    internal fun isInt(o: Any?): Boolean = isSafeInteger(o) && !isNegZero(num(o)!!)

    /** The reference `isNonNeg`: [isInt] and >= 0. */
    internal fun isNonNeg(o: Any?): Boolean = isInt(o) && num(o)!! >= 0

    /** Value of a safe integer (call after [isSafeInteger]). */
    internal fun lng(o: Any?): Long = num(o)!!.toLong()

    /** `Number.isFinite`. */
    internal fun isFinite(o: Any?): Boolean {
        val d = num(o) ?: return false
        return !d.isNaN() && !d.isInfinite()
    }

    /** JavaScript `String(n)` of a safe integer. */
    internal fun ofLong(v: Long): Json.Num = Json.Num(v.toString())

    /**
     * Equality of the lenient canonical JSON texts (the predicate DSL's `deepEq`) computed structurally: numbers by
     * binary64 value (`-0` prints as `0`), strings by UTF-16 code units, objects by key set and member values, arrays
     * element-wise. A non-JSON value (or a non-finite number) never equals anything.
     */
    internal fun jsonEquals(a: Any?, b: Any?): Boolean {
        if (a == null || b == null) return a == null && b == null
        if (a is String || b is String) return a == b
        if (a is Boolean || b is Boolean) return a == b
        val x = num(a)
        val y = num(b)
        if (x != null || y != null) return x != null && y != null && isFinite(a) && isFinite(b) && x == y
        if (a is List<*> && b is List<*>) {
            if (a.size != b.size) return false
            for (i in a.indices) if (!jsonEquals(a[i], b[i])) return false
            return true
        }
        if (a is Map<*, *> && b is Map<*, *>) {
            if (a.size != b.size) return false
            for ((k, v) in a) if (!b.containsKey(k) || !jsonEquals(v, b[k])) return false
            return true
        }
        return false
    }

    // ---- strings ----
    /** UTF-8 byte length as `TextEncoder` counts it (a lone surrogate encodes as U+FFFD: 3 bytes). */
    internal fun u8len(s: String): Int {
        var n = 0
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c.code < 0x80) n += 1
            else if (c.code < 0x800) n += 2
            else if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { n += 4; i++ }
            else n += 3
            i++
        }
        return n
    }

    internal fun utf8(s: String): ByteArray = s.toByteArray(StandardCharsets.UTF_8)
    internal fun hasLoneSurrogate(s: String): Boolean = Json.hasLoneSurrogate(s)
    fun compareUtf8(a: String, b: String): Int = Json.compareUtf8(a, b)
    internal fun sortedUtf8(keys: Collection<String>): List<String> = keys.sortedWith { a, b -> Json.compareUtf8(a, b) }

    /** Canonical base64url of exactly 32 bytes (a "digest"). */
    internal fun b32(o: Any?): Boolean = Pca.decodeB64uStrict(o, 32) != null

    /** Canonical base64url of any length. */
    internal fun b64any(o: Any?): Boolean = Pca.decodeB64uStrict(o, -1) != null

    // ---- hashing ----
    internal fun canon(v: Any?): String = Json.canonicalizeStrict(v)
    internal fun canonBytes(v: Any?): ByteArray = utf8(Json.canonicalizeStrict(v))
    internal fun hashCanonical(v: Any?): String = Pca.hashCanonical(v)

    /** `utf8(domain) || strictCanonical(body)`. */
    internal fun message(domain: String, body: Any?): ByteArray = Pca.concat(utf8(domain), canonBytes(body))

    /** `{d: domain, <slot>: value}` hashed (an artifact reference). */
    internal fun ref(domain: String, slot: String, value: Any?): String =
        hashCanonical(linkedMapOf<String, Any?>("d" to domain, slot to value))

    // ---- signatures ----
    /** Strict Ed25519 (rule 7) under a b64u key; a malformed key or signature is a failed signature. */
    internal fun verifyEd(pub: Any?, msg: ByteArray, sig: Any?): Boolean =
        pub is String && sig is String && Pca.verifyB64u(pub, msg, sig)

    /** The reason token of a signature refused because this SDK's suite dispatch does not implement the artifact's suite. */
    const val UNSUPPORTED_SUITE = "unsupported_suite"

    /**
     * The suite capability rule (README "suite capability"): an absent `alg` is ed25519; a non-string `alg` is malformed;
     * an `alg` this SDK's suite dispatch does not implement fails with [UNSUPPORTED_SUITE]. Null = ok.
     */
    internal fun suiteError(alg: Any?, algPresent: Boolean): String? {
        if (!algPresent) return null
        if (alg !is String) return "alg must be a string"
        return if (Pq.resolveSigAlg(alg, true) != null) null else "$UNSUPPORTED_SUITE: '$alg'"
    }

    /** The implemented suite an artifact names (absent = ed25519), or null. */
    internal fun suiteOf(artifact: Map<String, Any?>): String? =
        Pq.resolveSigAlg(artifact["alg"], artifact.containsKey("alg"))?.alg

    /**
     * `bindSuiteFields(base, alg, pqPk)`: for a non-ed25519 suite the suite name and the PQ key are signed into the body;
     * for ed25519 (or an unknown suite) the body is unchanged.
     */
    internal fun bindSuiteFields(base: Map<String, Any?>, alg: Any?, algPresent: Boolean, pqPk: Any?, pqPresent: Boolean): Map<String, Any?> {
        val s = Pq.resolveSigAlg(alg, algPresent)
        if (s == null || s.alg == "ed25519") return base
        val out = LinkedHashMap(base)
        out["alg"] = s.alg
        if (pqPresent) out["pq_pk"] = pqPk
        return out
    }

    /**
     * `verifyPinnedSuite`: ed25519 verifies under `identity`; a PQ / hybrid suite verifies only under a PQ key the VERIFIER
     * pins for `identity` (`pqPins`), never the artifact's own key alone. Every signature goes through the suite dispatch
     * ([Pq.verifySuite]). Never throws.
     */
    internal fun verifyPinnedSuite(
        alg: Any?, algPresent: Boolean, identity: String?, artifactPqPk: Any?, msg: ByteArray,
        sig: Any?, pqSig: Any?, pqPins: Map<String, Any?>?,
    ): Boolean = try {
        val s = Pq.resolveSigAlg(alg, algPresent)
        when {
            s == null -> false
            s.alg == "ed25519" -> verifyEd(identity, msg, sig)
            else -> {
                val pq = PinnedPq.resolve(identity, artifactPqPk, null, pqPins, null)
                pq != null && Pq.verifySuite(alg, algPresent, identity, pq, msg, sig, pqSig)
            }
        }
    } catch (e: RuntimeException) {
        false
    }

    internal fun pin(identity: String, pqPk: Any?): Map<String, Any?>? =
        if (pqPk !is String) null else linkedMapOf<String, Any?>(identity to pqPk)

    // ---- JSON.parse semantics for verifier state ----
    /**
     * A deep copy of a JSON tree with every number spelled as JavaScript would print the value `JSON.parse` yields. Maps
     * keep their insertion order; non-JSON values are kept as they are. Depth is bounded by the tree itself (the lenient
     * parser caps nesting at 512).
     */
    fun normalize(v: Any?): Any? = when (v) {
        is Json.Num -> normNum(v.raw)
        is Double -> normDouble(v, v.toString())
        is Map<*, *> -> {
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in v) out[k as String] = normalize(x)
            out
        }
        is List<*> -> v.mapTo(ArrayList()) { normalize(it) }
        else -> v
    }

    internal fun normNum(raw: String): Json.Num {
        val d = raw.toDoubleOrNull() ?: return Json.Num(raw)
        return normDouble(d, raw)
    }

    private fun normDouble(d: Double, raw: String): Json.Num {
        if (d.isNaN() || d.isInfinite()) return Json.Num(raw) // refused by every strict consumer
        if (isNegZero(d)) return Json.Num("-0")
        // JavaScript's digits for every finite value, integral ones included: above 2^53 `String(n)` prints the SHORTEST
        // round-trip digits zero-padded (2^60 -> "1152921504606847000"), not the exact binary value.
        return Json.Num(shortest(d))
    }

    /** The shortest decimal that round-trips to `d` (JavaScript's digits), printed without an exponent. */
    internal fun shortest(d: Double): String {
        val exact = BigDecimal(d)
        for (p in 1..17) {
            val r = exact.round(MathContext(p, RoundingMode.HALF_EVEN))
            if (r.toDouble() == d) return r.stripTrailingZeros().toPlainString()
        }
        return exact.toPlainString()
    }
}
