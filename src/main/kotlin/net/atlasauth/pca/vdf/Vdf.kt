package net.atlasauth.pca.vdf

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Wesolowski Verifiable Delay Function over an RSA group (port of the reference vdf module).
 * BigInteger (JDK) is the big-number primitive; the Fiat-Shamir challenge prime derivation, the fixed-base Miller-Rabin and the
 * strong Lucas test are ported 1:1 so prover and verifier derive the SAME prime as the reference.
 *
 * TRUSTED SETUP: an RSA-group VDF only delays anybody if the modulus has unknown factorisation. [insecureDevSetup] knows its
 * trapdoor and is refused by the timelock layer unless the caller opts in by name.
 */
object Vdf {
    const val CHALLENGE_PRIME_BITS = 256
    const val INSECURE_DEV_SETUP_DEFAULT_BITS = 2048
    const val MIN_PRODUCTION_MODULUS_BITS = 2048

    /** 2^53 - 1: JavaScript's largest safe integer (the reference's step-count domain). */
    internal const val MAX_SAFE = 9007199254740991.0

    /** The RSA Factoring Challenge RSA-2048 modulus (factorisation never published). */
    val RSA_2048_CHALLENGE_MODULUS: BigInteger = BigInteger(
        "2519590847565789349402718324004839857142928212620403202777713783604366202070" +
            "7595556264018525880784406918290641249515082189298559149176184502808489120072" +
            "8449926873928072877767359714183472702618963750149718246911650776133798590957" +
            "0009733045974880842840179742910064245869181719511874612151517265463228221686" +
            "9987549182422433637259085141865462043576798423387184774447920739934236584823" +
            "8242811981638150106748104516603773060562016196762561338441436038339044149526" +
            "3443219011465754445417842402092461651572335077870774981712577246796292638635" +
            "6373289912154831438167899885040445364023527381951378636564391212010397122822" +
            "120720357",
    )
    val DEFAULT_MODULUS: BigInteger = RSA_2048_CHALLENGE_MODULUS

    private val ZERO = BigInteger.ZERO
    private val ONE = BigInteger.ONE
    private val TWO = BigInteger.valueOf(2)
    private val THREE = BigInteger.valueOf(3)
    private val FOUR = BigInteger.valueOf(4)

    /** A VDF proof: `y = x^(2^T) mod N` and `pi = x^floor(2^T / l) mod N`. */
    class VdfProof(val y: BigInteger, val pi: BigInteger)

    /** The development modulus plus its trapdoor factors. */
    class InsecureDevVdfSetup internal constructor(val N: BigInteger, val p: BigInteger, val q: BigInteger) {
        val insecureDevOnly: Boolean = true
        val bits: Int = N.bitLength()
    }

    /** Verification result with the machine-readable refusal reason (malformed-input, bad-modulus, bad-steps, non-canonical-y, non-canonical-pi, bad-input-x, equation-mismatch). */
    class VdfVerdict internal constructor(val ok: Boolean, val reason: String?) {
        internal companion object {
            val OK = VdfVerdict(true, null)
            fun no(r: String) = VdfVerdict(false, r)
        }
    }

    /** Outcome of [checkProductionModulus]. */
    class ModulusCheck internal constructor(val ok: Boolean, val reason: String?)

    // ---- bigint / byte helpers ----

    /** Big-endian bytes -> non-negative integer (empty -> 0). */
    @JvmStatic
    fun bytesToBigInt(bytes: ByteArray): BigInteger = if (bytes.isEmpty()) ZERO else BigInteger(1, bytes)

    /** Non-negative integer -> minimal big-endian bytes (0 -> a single 0x00). */
    @JvmStatic
    fun bigIntToBytes(value: BigInteger): ByteArray {
        require(value.signum() >= 0) { "bigIntToBytes: negative value" }
        if (value.signum() == 0) return byteArrayOf(0)
        val b = value.toByteArray()
        return if (b[0].toInt() == 0 && b.size > 1) b.copyOfRange(1, b.size) else b
    }

    private fun u32be(n: Long): ByteArray = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())

    private fun u64be(v0: Long): ByteArray {
        var v = v0
        val b = ByteArray(8)
        for (i in 7 downTo 0) { b[i] = v.toByte(); v = v ushr 8 }
        return b
    }

    private fun ByteArrayOutputStream.put(b: ByteArray) = write(b, 0, b.size)

    private fun lp(out: ByteArrayOutputStream, b: ByteArray) { out.put(u32be(b.size.toLong())); out.put(b) }

    private fun sha256(m: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(m)

    /** True for a JavaScript safe integer >= 0. */
    internal fun isSafeSteps(t: Double): Boolean = t >= 0 && t <= MAX_SAFE && t == Math.floor(t)

    private fun normalizeSteps(t: Long): BigInteger {
        require(!(t < 0 || t > MAX_SAFE.toLong())) { "VDF: steps T must be a non-negative safe integer, got $t" }
        return BigInteger.valueOf(t)
    }

    @JvmStatic
    fun gcd(a: BigInteger, b: BigInteger): BigInteger = a.abs().gcd(b.abs())

    private fun isUnit(v: BigInteger, n: BigInteger): Boolean = v.signum() > 0 && v < n && v.gcd(n) == ONE

    private fun red(v: BigInteger, n: BigInteger): BigInteger = v.mod(n)

    /** `base^exp mod mod`; exp >= 0, mod > 0. */
    @JvmStatic
    fun modpow(base: BigInteger, exp: BigInteger, mod: BigInteger): BigInteger {
        require(mod.signum() > 0) { "modpow: modulus must be positive" }
        if (mod == ONE) return ZERO
        require(exp.signum() >= 0) { "modpow: negative exponent (no inverse in a group of unknown order)" }
        return base.mod(mod).modPow(exp, mod)
    }

    // ---- primality ----

    private val SMALL = longArrayOf(2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)

    private fun jacobi(a0: BigInteger, n0: BigInteger): Int {
        var a = a0
        var n = n0
        var r = 1
        a = a.mod(n)
        while (a.signum() != 0) {
            while (!a.testBit(0)) {
                a = a.shiftRight(1)
                val m = n.toInt() and 7
                if (m == 3 || m == 5) r = -r
            }
            val t = a; a = n; n = t
            if ((a.toInt() and 3) == 3 && (n.toInt() and 3) == 3) r = -r
            a = a.mod(n)
        }
        return if (n == ONE) r else 0
    }

    /** floor(sqrt(n)) by Newton's iteration (BigInteger.sqrt is JDK 9+, not on Android API 24). */
    internal fun isqrt(n: BigInteger): BigInteger {
        if (n.signum() == 0) return ZERO
        var x = ONE.shiftLeft((n.bitLength() + 1) / 2)
        while (true) {
            val y = x.add(n.divide(x)).shiftRight(1)
            if (y >= x) return x
            x = y
        }
    }

    internal fun isPerfectSquare(n: BigInteger): Boolean {
        if (n.signum() < 0) return false
        if (n < TWO) return true
        val s = isqrt(n)
        return s.multiply(s) == n
    }

    private fun half(x: BigInteger, n: BigInteger): BigInteger = (if (x.testBit(0)) x.add(n) else x).shiftRight(1)

    /** Strong Lucas probable-prime test, Selfridge method A (P = 1, Q = (1 - D) / 4). Expects odd n > 2. */
    @JvmStatic
    fun isStrongLucasProbablePrime(n: BigInteger): Boolean {
        if (n < THREE || !n.testBit(0) || isPerfectSquare(n)) return false
        var d5 = BigInteger.valueOf(5)
        while (true) {
            val j = jacobi(d5, n)
            if (j == -1) break
            if (j == 0 && d5.abs() != n) return false
            d5 = if (d5.signum() > 0) d5.add(TWO).negate() else d5.negate().add(TWO)
        }
        val bigD = d5
        val p = ONE
        val q = ONE.subtract(bigD).divide(FOUR)
        var d = n.add(ONE)
        var s = 0
        while (!d.testBit(0)) { d = d.shiftRight(1); s++ }
        var u = ONE
        var v = p
        var qk = q.mod(n)
        val bits = d.toString(2)
        for (i in 1 until bits.length) {
            u = u.multiply(v).mod(n)
            v = v.multiply(v).subtract(TWO.multiply(qk)).mod(n)
            qk = qk.multiply(qk).mod(n)
            if (bits[i] == '1') {
                val u1 = half(p.multiply(u).add(v).mod(n), n)
                val v1 = half(bigD.multiply(u).add(p.multiply(v)).mod(n), n)
                u = u1
                v = v1
                qk = qk.multiply(q).mod(n)
            }
        }
        if (u.signum() == 0 || v.signum() == 0) return true
        for (r in 1 until s) {
            v = v.multiply(v).subtract(TWO.multiply(qk)).mod(n)
            if (v.signum() == 0) return true
            qk = qk.multiply(qk).mod(n)
        }
        return false
    }

    /** Strong (Miller-Rabin) probable-prime test of odd n > 2 against the fixed bases 2..97; refuses even n and n < 3. */
    @JvmStatic
    fun isMillerRabinProbablePrime(n: BigInteger): Boolean {
        if (n < THREE || !n.testBit(0)) return false
        val nm1 = n.subtract(ONE)
        val s = nm1.lowestSetBit
        val d = nm1.shiftRight(s)
        witness@ for (a in SMALL) {
            val base = BigInteger.valueOf(a).mod(n)
            if (base.signum() == 0) continue
            var x = base.modPow(d, n)
            if (x == ONE || x == nm1) continue
            for (i in 1 until s) {
                x = x.multiply(x).mod(n)
                if (x == nm1) continue@witness
            }
            return false
        }
        return true
    }

    /** Trial division, Miller-Rabin over the fixed bases, then strong Lucas (deterministic: prover and verifier agree). */
    @JvmStatic
    fun isProbablePrime(n: BigInteger): Boolean {
        if (n < TWO) return false
        for (p in SMALL) {
            val bp = BigInteger.valueOf(p)
            if (n == bp) return true
            if (n.mod(bp).signum() == 0) return false
        }
        return isMillerRabinProbablePrime(n) && isStrongLucasProbablePrime(n)
    }

    // ---- hash-to-prime ----

    private val H2P_DOMAIN = "atlas-pca/vdf/wesolowski/hash-to-prime/v1\u0000".toByteArray(Charsets.UTF_8)

    /** Fiat-Shamir challenge prime from the transcript (x, y, T, N); byte-identical to the reference. */
    @JvmStatic
    @JvmOverloads
    fun hashToPrime(x: BigInteger, y: BigInteger, t: Long, n: BigInteger, bits: Int = CHALLENGE_PRIME_BITS): BigInteger {
        require(bits in 8..8192) { "hashToPrime: bits must be an integer in [8, 8192]" }
        val steps = normalizeSteps(t)
        val xr = red(x, n)
        val yr = red(y, n)
        val tr = ByteArrayOutputStream()
        tr.put(H2P_DOMAIN)
        lp(tr, bigIntToBytes(xr))
        lp(tr, bigIntToBytes(yr))
        lp(tr, bigIntToBytes(steps))
        lp(tr, bigIntToBytes(n))
        lp(tr, u32be(bits.toLong()))
        val seed = sha256(tr.toByteArray())
        val bytesNeeded = (bits + 7) / 8
        val topBit = ONE.shiftLeft(bits - 1)
        val mask = ONE.shiftLeft(bits).subtract(ONE)
        var counter = 0L
        while (true) {
            val raw = ByteArrayOutputStream()
            var blockIndex = 0
            while (raw.size() < bytesNeeded) {
                val inp = ByteArrayOutputStream()
                inp.put(seed)
                inp.put(u64be(counter))
                inp.put(u32be(blockIndex.toLong()))
                raw.put(sha256(inp.toByteArray()))
                blockIndex++
            }
            val cut = raw.toByteArray().copyOfRange(0, bytesNeeded)
            val candidate = bytesToBigInt(cut).and(mask).or(topBit).or(ONE)
            if (isProbablePrime(candidate)) return candidate
            counter++
        }
    }

    // ---- the VDF ----

    /** `x^(2^T) mod N` by T real sequential squarings. */
    @JvmStatic
    fun sequentialSquare(x: BigInteger, t: Long, n: BigInteger): BigInteger {
        require(n > ONE) { "VDF: modulus N must be > 1" }
        val steps = normalizeSteps(t)
        var y = red(x, n)
        var i = 0L
        val cnt = steps.toLong()
        while (i < cnt) { y = y.multiply(y).mod(n); i++ }
        return y
    }

    private fun wesolowskiProof(x: BigInteger, t: Long, l: BigInteger, n: BigInteger): BigInteger {
        val xr = red(x, n)
        var pi = ONE.mod(n)
        var r = ONE.mod(l)
        var i = 0L
        while (i < t) {
            val twoR = r.shiftLeft(1)
            val b = twoR >= l
            r = if (b) twoR.subtract(l) else twoR
            pi = pi.multiply(pi).mod(n)
            if (b) pi = pi.multiply(xr).mod(n)
            i++
        }
        return pi
    }

    private fun requireModulus(n: BigInteger) {
        require(!(n <= THREE || !n.testBit(0))) { "VDF: modulus N must be odd and > 3" }
    }

    private fun requireInput(x: BigInteger, n: BigInteger): BigInteger {
        val xr = red(x, n)
        require(!(!isUnit(xr, n) || xr == ONE || xr == n.subtract(ONE))) {
            "VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)"
        }
        return xr
    }

    /** y = x^(2^T) mod N by T sequential squarings, plus the Wesolowski proof. */
    @JvmStatic
    fun vdfEval(x: BigInteger, t: Long, n: BigInteger): VdfProof {
        requireModulus(n)
        normalizeSteps(t)
        requireInput(x, n)
        val y = sequentialSquare(x, t, n)
        val l = hashToPrime(x, y, t, n)
        return VdfProof(y, wesolowskiProof(x, t, l, n))
    }

    @JvmStatic
    fun canonicalVdfOutput(y: BigInteger, n: BigInteger): BigInteger = if (y > n.subtract(y)) n.subtract(y) else y

    /** Evaluate with a unique (canonical, y and pi both <= N/2) output. */
    @JvmStatic
    fun vdfEvalCanonical(x: BigInteger, t: Long, n: BigInteger): VdfProof {
        requireModulus(n)
        normalizeSteps(t)
        requireInput(x, n)
        val y = canonicalVdfOutput(sequentialSquare(x, t, n), n)
        val l = hashToPrime(x, y, t, n)
        return VdfProof(y, canonicalVdfOutput(wesolowskiProof(x, t, l, n), n))
    }

    /** Verify in O(log) work; fails closed (never throws), returning why on refusal. */
    @JvmStatic
    fun vdfVerifyDetailed(x: BigInteger, y: BigInteger, pi: BigInteger, t: Double, n: BigInteger): VdfVerdict = verify(x, y, pi, t, n, false)

    @JvmStatic
    fun vdfVerifyDetailed(x: BigInteger, y: BigInteger, pi: BigInteger, t: Long, n: BigInteger): VdfVerdict = verify(x, y, pi, t.toDouble(), n, false)

    /** Verify a canonical-output proof: y and pi must be <= N/2; the relation holds up to sign. */
    @JvmStatic
    fun vdfVerifyCanonicalDetailed(x: BigInteger, y: BigInteger, pi: BigInteger, t: Double, n: BigInteger): VdfVerdict = verify(x, y, pi, t, n, true)

    @JvmStatic
    fun vdfVerifyCanonicalDetailed(x: BigInteger, y: BigInteger, pi: BigInteger, t: Long, n: BigInteger): VdfVerdict = verify(x, y, pi, t.toDouble(), n, true)

    private fun verify(x: BigInteger?, y: BigInteger?, pi: BigInteger?, t: Double, n: BigInteger?, canonical: Boolean): VdfVerdict {
        try {
            if (x == null || y == null || pi == null || n == null) return VdfVerdict.no("malformed-input")
            if (n <= THREE || !n.testBit(0)) return VdfVerdict.no("bad-modulus")
            if (!isSafeSteps(t)) return VdfVerdict.no("bad-steps")
            val steps = t.toLong()
            if (!isUnit(y, n) || (canonical && y > n.subtract(y))) return VdfVerdict.no("non-canonical-y")
            if (!isUnit(pi, n) || (canonical && pi > n.subtract(pi))) return VdfVerdict.no("non-canonical-pi")
            val xr = red(x, n)
            if (!isUnit(xr, n) || xr == ONE || xr == n.subtract(ONE)) return VdfVerdict.no("bad-input-x")
            val l = hashToPrime(x, y, steps, n)
            val r = modpow(TWO, BigInteger.valueOf(steps), l)
            val lhs = modpow(pi, l, n).multiply(modpow(xr, r, n)).mod(n)
            val ok = lhs == y || (canonical && lhs == n.subtract(y))
            return if (ok) VdfVerdict.OK else VdfVerdict.no("equation-mismatch")
        } catch (e: RuntimeException) {
            return VdfVerdict.no("malformed-input")
        }
    }

    @JvmStatic
    fun vdfVerify(x: BigInteger, y: BigInteger, pi: BigInteger, t: Long, n: BigInteger): Boolean = vdfVerifyDetailed(x, y, pi, t, n).ok

    @JvmStatic
    fun vdfVerifyCanonical(x: BigInteger, y: BigInteger, pi: BigInteger, t: Long, n: BigInteger): Boolean = vdfVerifyCanonicalDetailed(x, y, pi, t, n).ok

    // ---- DEV / TEST-ONLY modulus generation ----

    private val INSECURE_DEV_MODULI: MutableSet<BigInteger> = ConcurrentHashMap.newKeySet()

    private fun randomPrime(bits: Int, rnd: SecureRandom): BigInteger {
        require(bits >= 16) { "randomPrime: bits too small" }
        val nb = (bits + 7) / 8
        val topBit = ONE.shiftLeft(bits - 1)
        val mask = ONE.shiftLeft(bits).subtract(ONE)
        for (attempt in 0 until 50_000) {
            val b = ByteArray(nb)
            rnd.nextBytes(b)
            val c = bytesToBigInt(b).and(mask).or(topBit).or(ONE)
            if (isProbablePrime(c)) return c
        }
        throw IllegalStateException("insecureDevSetup: randomness source failed to yield a prime")
    }

    /** DEVELOPMENT / TESTS ONLY: generates N = p*q and therefore KNOWS the trapdoor; the timelock layer refuses it unless opted in by name. */
    @JvmStatic
    @JvmOverloads
    fun insecureDevSetup(bits: Int = INSECURE_DEV_SETUP_DEFAULT_BITS, rnd: SecureRandom = SecureRandom()): InsecureDevVdfSetup {
        require(bits >= 32) { "insecureDevSetup: bits must be an integer >= 32" }
        val half = bits / 2
        val p = randomPrime(half, rnd)
        var q = randomPrime(bits - half, rnd)
        var i = 0
        while (p == q) {
            check(i < 8) { "insecureDevSetup: randomness source returned the same prime repeatedly" }
            q = randomPrime(bits - half, rnd)
            i++
        }
        val n = p.multiply(q)
        INSECURE_DEV_MODULI.add(n)
        return InsecureDevVdfSetup(n, p, q)
    }

    private val SCREEN_PRIMES: List<Int> by lazy {
        val limit = 1 shl 16
        val sieve = BooleanArray(limit)
        val out = ArrayList<Int>()
        for (i in 2 until limit) {
            if (sieve[i]) continue
            out.add(i)
            var j = i.toLong() * i
            while (j < limit) { sieve[j.toInt()] = true; j += i }
        }
        out
    }

    /** Screen a modulus for the production timelock path (a screen, not a proof of unknown factorisation). */
    @JvmStatic
    fun checkProductionModulus(n: BigInteger?): ModulusCheck {
        if (n == null) return ModulusCheck(false, "modulus is not a bigint")
        if (INSECURE_DEV_MODULI.contains(n)) return ModulusCheck(false, "modulus came from insecureDevSetup(): its factors are known, so it provides no delay")
        if (n <= THREE) return ModulusCheck(false, "modulus is too small")
        if (n.bitLength() < MIN_PRODUCTION_MODULUS_BITS) return ModulusCheck(false, "modulus is below $MIN_PRODUCTION_MODULUS_BITS bits")
        if (!n.testBit(0)) return ModulusCheck(false, "modulus is even")
        if (isPerfectSquare(n)) return ModulusCheck(false, "modulus is a perfect square")
        if (isProbablePrime(n)) return ModulusCheck(false, "modulus is prime (group order N-1 is public)")
        for (p in SCREEN_PRIMES) {
            if (n.mod(BigInteger.valueOf(p.toLong())).signum() == 0) return ModulusCheck(false, "modulus has the small prime factor $p")
        }
        return ModulusCheck(true, null)
    }
}
