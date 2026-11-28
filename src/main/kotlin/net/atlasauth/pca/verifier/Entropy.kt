package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.security.SecureRandom
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

/**
 * QRNG entropy as an ADD to key generation, never a trust dependency: every seed is `HKDF-SHA256(local CSPRNG || quantum)`, so a hostile
 * quantum source cannot lower the result below the local CSPRNG. Quantum bytes are never used raw. This is not a quantum root of trust
 * and makes no post-quantum claim. The library carries no network client: the HTTP source takes an injected transport.
 */
object Entropy {
    /** HKDF-SHA256 output cap: 255 * 32. */
    const val MAX_HKDF_OUTPUT = 255 * 32

    /** Minimum local CSPRNG input the combiner accepts. */
    const val MIN_LOCAL_BYTES = 16
    const val DEFAULT_SEED_BYTES = 32
    const val DEFAULT_MAX_QRNG_BYTES = 1024
    const val DEFAULT_TIMEOUT_MS = 5000

    private const val MIX_LABEL = "atlas-pca/entropy/mix/v1"
    private val MIX_SALT = "atlas-pca/entropy/salt/v1".toByteArray(Charsets.UTF_8)

    /** A source of quantum random bytes: `fetch(n)` returns EXACTLY n bytes or throws. */
    interface QrngSource {
        /** Short, log-safe identifier (never contains secrets). */
        val name: String

        @Throws(Exception::class)
        fun fetch(numBytes: Int): ByteArray
    }

    /** A source that always fails with `QRNG unavailable: <reason>`. */
    class NullQrngSource(private val reason: String = "no QRNG source configured") : QrngSource {
        override val name: String = "null-qrng"
        override fun fetch(numBytes: Int): ByteArray = throw IllegalStateException("QRNG unavailable: $reason")
    }

    /** The shared unavailable source; a null reason means the default one. */
    fun unavailableSource(reason: String?): QrngSource = if (reason == null) NullQrngSource() else NullQrngSource(reason)

    // ---- SP 800-90B 4.4 continuous health tests ----

    /** `h` = assessed min-entropy per byte (1..8), `window` = adaptive-proportion window. */
    class HealthTestOptions(val h: Double = 8.0, val window: Double = 512.0)

    /** `test` is "repetition-count" or "adaptive-proportion" when not ok. */
    class HealthVerdict(val ok: Boolean, val test: String?)

    /** SP 800-90B 4.4.1 cutoff: 1 + ceil(20 / h) (a double: h = 0 gives Infinity). */
    fun repetitionCutoff(h: Double): Double = 1 + Math.ceil(20 / h)

    /** The largest window of [proportionCutoff] (the tail is exact integer arithmetic over w * 61 bits). */
    const val PROPORTION_MAX_WINDOW = 65_536

    /**
     * 2^-h for h a multiple of 1/8 in [1/8, 64], from IEEE operations every platform computes identically: 0.5 multiplied floor(8h / 8) times, then
     * by sqrt(0.5) if bit 4 of (8h mod 8) is set, by sqrt(sqrt(0.5)) if bit 2 is set, by sqrt(sqrt(sqrt(0.5))) if bit 1 is set, in that order.
     */
    private fun proportionP(h: Double): Double {
        val n = h * 8
        if (!(n == Math.floor(n) && !n.isInfinite() && n >= 1 && n <= 512)) throw IllegalArgumentException("proportionCutoff: h must be a multiple of 1/8 in [1/8, 64]")
        var p = 1.0
        for (i in 0 until Math.floor(n / 8).toInt()) p *= 0.5
        val f = (n % 8).toInt()
        val s1 = Math.sqrt(0.5)
        val s2 = Math.sqrt(s1)
        val s3 = Math.sqrt(s2)
        if (f and 4 != 0) p *= s1
        if (f and 2 != 0) p *= s2
        if (f and 1 != 0) p *= s3
        return p
    }

    /**
     * SP 800-90B 4.4.2 cutoff: 1 + CRITBINOM(W, p, 1 - 2^-20) with p = 2^-h: the smallest k (at most W) with P[X <= k] >= 1 - 2^-20 for X ~ Bin(W, p),
     * plus one. Computed EXACTLY: p is the dyadic rational m / 2^e of its own bits, every binomial term is an integer over 2^(e*W), and the comparison
     * with 1 - 2^-20 is an integer comparison, so no libm can move the cutoff. h must be a multiple of 1/8 in [1/8, 64] and W an integer in [2, 65536];
     * anything else throws (never rounded).
     */
    fun proportionCutoff(h: Double, w: Double): Double {
        if (!(w == Math.floor(w) && !w.isInfinite() && w >= 2 && w <= PROPORTION_MAX_WINDOW)) throw IllegalArgumentException("proportionCutoff: the window must be an integer in [2, 65536]")
        val p = proportionP(h)
        val bits = java.lang.Double.doubleToRawLongBits(p)
        val m = BigInteger.valueOf((bits and ((1L shl 52) - 1)) or (1L shl 52))
        val e = 1075 - (bits ushr 52).toInt() // p = m / 2^e (p is a normal double in [2^-64, 1/2])
        val d = BigInteger.ONE.shiftLeft(e)
        val q = d.subtract(m) // 1 - p = q / d
        val wi = w.toInt()
        val big = BigInteger.valueOf(wi.toLong())
        val target = BigInteger.ONE.shiftLeft(20).subtract(BigInteger.ONE).multiply(d.pow(wi)) // cdf >= 1 - 2^-20  <=>  cdf * 2^20 >= (2^20 - 1) * d^W
        var term = q.pow(wi)
        var cdf = term
        var k = 0
        while (cdf.shiftLeft(20) < target && k < wi) {
            term = term.multiply(big.subtract(BigInteger.valueOf(k.toLong()))).multiply(m).divide(BigInteger.valueOf(k + 1L).multiply(q))
            k++
            cdf = cdf.add(term)
        }
        return (1 + k).toDouble()
    }

    /** Repetition-count and adaptive-proportion over one buffer; fails closed on bad parameters and on an empty buffer. */
    fun healthTestBytes(bytes: ByteArray, h: Double = 8.0, window: Double = 512.0): HealthVerdict {
        val badWindow = window.isNaN() || window.isInfinite() || window != Math.rint(window) || window < 2
        if (!(h >= 1 && h <= 8 && h * 8 == Math.floor(h * 8)) || badWindow || bytes.isEmpty()) return HealthVerdict(false, "repetition-count")
        val rc = repetitionCutoff(h)
        var run = 1
        for (i in 1 until bytes.size) {
            run = if (bytes[i] == bytes[i - 1]) run + 1 else 1
            if (run >= rc) return HealthVerdict(false, "repetition-count")
        }
        val w = Math.min(Math.min(window, bytes.size.toDouble()), PROPORTION_MAX_WINDOW.toDouble()).toInt()
        if (w < 2) return HealthVerdict(true, null) // a window of one byte can never reach the cutoff
        val ac = proportionCutoff(h, w.toDouble())
        var start = 0
        while (start + w <= bytes.size) {
            val first = bytes[start]
            var count = 0
            for (i in start until start + w) if (bytes[i] == first) count++
            if (count >= ac) return HealthVerdict(false, "adaptive-proportion")
            start += w
        }
        return HealthVerdict(true, null)
    }

    // ---- parsers ----

    private fun isByte(v: Any?): Boolean {
        val d = IntentJs.num(v) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && d >= 0 && d <= 255
    }

    /** ANU / hardware-REST JSON shape `{success?: boolean, data: number[]}`, each element a 0..255 integer. */
    fun parseAnuUint8(body: Any?): ByteArray {
        if (body !is Map<*, *>) throw IllegalArgumentException("QRNG: response body is not a JSON object")
        if (body.containsKey("success") && body["success"] != true) throw IllegalArgumentException("QRNG: response reports success=false")
        val data = body["data"] as? List<*> ?: throw IllegalArgumentException("QRNG: response `data` is not an array")
        val out = ByteArray(data.size)
        for (i in data.indices) {
            if (!isByte(data[i])) throw IllegalArgumentException("QRNG: response data[$i] is not a 0..255 integer")
            out[i] = IntentJs.num(data[i])!!.toInt().toByte()
        }
        return out
    }

    private fun hexDigit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    /** A flat hex string; refuses odd length and non-hex characters. */
    fun parseHex(text: String): ByteArray {
        if (text.length % 2 != 0) throw IllegalArgumentException("QRNG: malformed hex payload")
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            val a = hexDigit(text[2 * i])
            val b = hexDigit(text[2 * i + 1])
            if (a < 0 || b < 0) throw IllegalArgumentException("QRNG: malformed hex payload")
            out[i] = (a * 16 + b).toByte()
        }
        return out
    }

    private fun b64Digit(c: Char): Int = when (c) {
        in 'A'..'Z' -> c - 'A'
        in 'a'..'z' -> c - 'a' + 26
        in '0'..'9' -> c - '0' + 52
        '+' -> 62
        '/' -> 63
        else -> -1
    }

    /**
     * Standard base64 as the WHATWG forgiving-base64 decode (`atob`) reads it, after the same alphabet check: up to two trailing '=' are
     * stripped only when the length is a multiple of 4, a remainder of 1 mod 4 is invalid, missing padding is accepted and non-canonical
     * trailing bits are dropped.
     */
    fun parseBase64(text: String): ByteArray {
        var end = text.length
        var pad = 0
        while (end > 0 && text[end - 1] == '=') { end--; pad++ }
        if (pad > 2) throw IllegalArgumentException("QRNG: malformed base64 payload")
        for (i in 0 until end) if (b64Digit(text[i]) < 0) throw IllegalArgumentException("QRNG: malformed base64 payload")
        if (pad > 0 && text.length % 4 != 0) throw IllegalArgumentException("QRNG: malformed base64 payload")
        if (end % 4 == 1) throw IllegalArgumentException("QRNG: malformed base64 payload")
        val out = ByteArray(end * 6 / 8)
        var acc = 0
        var bits = 0
        var o = 0
        for (i in 0 until end) {
            acc = (acc shl 6) or b64Digit(text[i])
            bits += 6
            if (bits >= 8) { bits -= 8; out[o++] = (acc shr bits).toByte(); acc = acc and ((1 shl bits) - 1) }
        }
        return out
    }

    // ---- combiner ----

    internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val g = HKDFBytesGenerator(SHA256Digest())
        g.init(HKDFParameters(ikm, salt, info))
        val out = ByteArray(length)
        g.generateBytes(out, 0, length)
        return out
    }

    /**
     * Robust randomness combiner: `HKDF-SHA256(ikm = len(local) || len(quantum) || local || quantum, salt, info = label || context || len)`.
     * Fails closed on a local input under 16 bytes or a length outside 1..8160; the quantum input may be empty. A null or empty context
     * adds nothing to the label; a null length means the local length.
     */
    fun mixEntropy(local: ByteArray, quantum: ByteArray, length: Int? = null, context: String? = null): ByteArray {
        require(local.size >= MIN_LOCAL_BYTES) { "mixEntropy: local CSPRNG must be >= $MIN_LOCAL_BYTES bytes (fail-closed)" }
        val len = length ?: local.size
        require(len in 1..MAX_HKDF_OUTPUT) { "mixEntropy: length must be an integer in 1..$MAX_HKDF_OUTPUT" }
        val ikm = ByteArray(8 + local.size + quantum.size)
        putU32(ikm, 0, local.size)
        putU32(ikm, 4, quantum.size)
        System.arraycopy(local, 0, ikm, 8, local.size)
        System.arraycopy(quantum, 0, ikm, 8 + local.size, quantum.size)
        val label = Json.utf8(if (!context.isNullOrEmpty()) "$MIX_LABEL/$context" else MIX_LABEL)
        val info = ByteArray(label.size + 4)
        System.arraycopy(label, 0, info, 0, label.size)
        putU32(info, label.size, len)
        val out = hkdfSha256(ikm, MIX_SALT, info, len)
        ikm.fill(0)
        return out
    }

    private fun putU32(b: ByteArray, o: Int, v: Int) {
        b[o] = (v ushr 24).toByte(); b[o + 1] = (v ushr 16).toByte(); b[o + 2] = (v ushr 8).toByte(); b[o + 3] = v.toByte()
    }

    // ---- secureSeed ----

    /** Options for [secureSeed]. Null fields take the reference defaults. */
    class SecureSeedOptions {
        /** Output seed length (default 32). */
        var length: Int? = null

        /** QRNG source for best-effort quantum entropy; null = CSPRNG only. */
        var source: QrngSource? = null

        /** Quantum bytes to request (default max(32, length)). */
        var quantumBytes: Int? = null

        /** Local CSPRNG bytes to draw (default max(32, length)). */
        var localBytes: Int? = null
        var context: String? = null

        /** Throw [EntropyError] (quantum_required) instead of falling back to CSPRNG-only. */
        var requireQuantum: Boolean = false

        /** SP 800-90B tests on every quantum buffer; null disables them (tests only). */
        var healthTest: HealthTestOptions? = HealthTestOptions()

        /** Observability hook when the QRNG is skipped or fails; its own exceptions are swallowed. */
        var onQrngError: ((Throwable) -> Unit)? = null

        /** Inject a CSPRNG (tests); must return exactly n bytes. Default: the platform CSPRNG. */
        var randomBytesImpl: ((Int) -> ByteArray?)? = null

        internal fun copy(): SecureSeedOptions {
            val o = SecureSeedOptions()
            o.length = length; o.source = source; o.quantumBytes = quantumBytes; o.localBytes = localBytes; o.context = context
            o.requireQuantum = requireQuantum; o.healthTest = healthTest; o.onQrngError = onQrngError; o.randomBytesImpl = randomBytesImpl
            return o
        }
    }

    /** `source` is the source name, or null when none was used. */
    class SecureSeedResult(val seed: ByteArray, val usedQuantum: Boolean, val quantumByteCount: Int, val source: String?)

    private val RNG = SecureRandom()

    private fun drawLocal(impl: ((Int) -> ByteArray?)?, n: Int): ByteArray {
        val b = if (impl != null) impl(n) else ByteArray(n).also { RNG.nextBytes(it) }
        check(b != null && b.size == n) { "secureSeed: local CSPRNG did not return the requested bytes (fail-closed)" }
        return b
    }

    /**
     * `mixEntropy(CSPRNG, best-effort QRNG)`. A missing, failing, slow or adversarial QRNG never blocks and never lowers the seed below
     * CSPRNG strength: it falls back to CSPRNG-only (usedQuantum false). The only throws are configuration errors, a misbehaving local
     * CSPRNG, and `requireQuantum` without usable quantum bytes.
     */
    fun secureSeed(opts: SecureSeedOptions = SecureSeedOptions()): SecureSeedResult {
        val length = opts.length ?: DEFAULT_SEED_BYTES
        require(length in 1..MAX_HKDF_OUTPUT) { "secureSeed: length must be an integer in 1..$MAX_HKDF_OUTPUT" }
        val localBytes = opts.localBytes ?: maxOf(DEFAULT_SEED_BYTES, length)
        require(localBytes >= MIN_LOCAL_BYTES) { "secureSeed: localBytes must be an integer >= $MIN_LOCAL_BYTES" }
        val quantumBytes = opts.quantumBytes ?: maxOf(DEFAULT_SEED_BYTES, length)
        require(quantumBytes > 0) { "secureSeed: quantumBytes must be a positive integer" }

        val local = drawLocal(opts.randomBytesImpl, localBytes)
        var quantum = ByteArray(0)
        var used = false
        var sourceName: String? = null
        val source = opts.source
        if (source != null) {
            sourceName = source.name
            try {
                val q: ByteArray? = source.fetch(quantumBytes)
                if (q == null || q.size != quantumBytes) {
                    throw IllegalStateException("QRNG: source returned ${if (q == null) "non-bytes" else q.size.toString()}, expected $quantumBytes")
                }
                val ht = opts.healthTest
                if (ht != null) {
                    val v = healthTestBytes(q, ht.h, ht.window)
                    if (!v.ok) throw EntropyError("health_test_failed", "QRNG: ${v.test ?: "health"} test failed; source rejected")
                }
                quantum = q
                used = true
            } catch (err: Exception) {
                used = false
                quantum = ByteArray(0)
                val hook = opts.onQrngError
                if (hook != null) {
                    try { hook(err) } catch (swallowed: RuntimeException) { /* observability must never break key generation */ }
                }
            }
        }
        if (opts.requireQuantum && !used) {
            local.fill(0)
            throw EntropyError("quantum_required", "secureSeed: quantum entropy is required but was not obtained (fail-closed)")
        }
        val seed = mixEntropy(local, quantum, length, opts.context)
        local.fill(0)
        return SecureSeedResult(seed, used, if (used) quantum.size else 0, sourceName)
    }

    /** An Ed25519 key pair whose secret is a [secureSeed]. */
    class EntropyKeyPair(val secretKey: ByteArray, val publicKey: ByteArray, val usedQuantum: Boolean)

    /**
     * Ed25519 key pair whose 32-byte secret is `secureSeed` (CSPRNG mixed with a health-tested QRNG). A caller length is ignored; a null
     * context becomes "ed25519-key", an explicit empty one stays empty. Honors requireQuantum.
     */
    fun generateKeyPairWithEntropy(opts: SecureSeedOptions = SecureSeedOptions()): EntropyKeyPair {
        val o = opts.copy()
        o.length = 32
        if (o.context == null) o.context = "ed25519-key"
        val r = secureSeed(o)
        return EntropyKeyPair(r.seed, Keys.edFromSeed(r.seed).pub, r.usedQuantum)
    }
}
