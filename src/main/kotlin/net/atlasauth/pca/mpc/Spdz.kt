package net.atlasauth.pca.mpc

import net.atlasauth.pca.verifier.Json

import java.math.BigInteger
import java.security.MessageDigest
import net.atlasauth.pca.mpc.Field.PRIME
import net.atlasauth.pca.mpc.Field.fadd
import net.atlasauth.pca.mpc.Field.fmul
import net.atlasauth.pca.mpc.Field.fneg
import net.atlasauth.pca.mpc.Field.mod

/**
 * SPDZ-style authenticated secret sharing over F_p: the malicious-with-abort (dishonest-majority) layer. A global MAC key alpha is
 * additively shared; every authenticated value carries MAC shares summing to alpha*x under MAC_KEYS independent keys; the batched
 * commit-then-open MAC-check aborts on any deviation, so the result is correct or an abort. The authenticated triples come from a
 * trusted dealer (the explicit trust assumption) or the no-dealer offline phase; the online phase is the real thing.
 */
object Spdz {
    /** One global MAC key, additively shared. [alpha] is for dealer preprocessing and tests only. */
    class MacKey(val alphaShares: Array<BigInteger>, val alpha: BigInteger)

    /** The global MAC keys: key 0 is alphaShares/alpha; extraKeys are further independent keys. */
    class MacContext(val n: Int, val alphaShares: Array<BigInteger>, val alpha: BigInteger, val extraKeys: List<MacKey>)

    /** value shares sum to x, mac shares to alpha*x (key 0), extraMac[l-1] to extraKeys[l-1].alpha*x. */
    class AuthSV(val value: Array<BigInteger>, val mac: Array<BigInteger>, val extraMac: Array<Array<BigInteger>>)

    class AuthTriple(val a: AuthSV, val b: AuthSV, val c: AuthSV)

    const val MAC_KEYS = 2
    const val MIN_MAC_SOUNDNESS_BITS = 100
    const val SACRIFICE_PARTNERS = 2

    @JvmStatic fun macKeys(ctx: MacContext): List<MacKey> {
        val out = ArrayList<MacKey>()
        out.add(MacKey(ctx.alphaShares, ctx.alpha))
        out.addAll(ctx.extraKeys)
        return out
    }

    /** keys * (log2 p - 1): the soundness in bits of the batched MAC-check. */
    @JvmStatic @JvmOverloads fun macSoundnessBits(keys: Int, p: BigInteger = PRIME): Double {
        val d = p.toDouble()
        var l = Math.log(d) / Math.log(2.0)
        val r = Math.rint(l)
        if (Math.abs(l - r) < 1e-9 && Math.pow(2.0, r) == d) l = r
        return keys * (l - 1)
    }

    /** Raised when the MAC-check detects an inconsistent opening/MAC: the protocol ABORTS, no output. */
    open class MacCheckAbort(message: String) : RuntimeException(message)

    @JvmStatic @JvmOverloads fun setupMac(n: Int, rng: FieldSource, keys: Int = MAC_KEYS): MacContext {
        require(n >= 1) { "setupMac: n must be a positive integer" }
        require(keys in 1..16) { "setupMac: keys must be an integer in [1, 16]" }
        val first = mk(n, rng)
        val extra = ArrayList<MacKey>()
        for (i in 0 until keys - 1) extra.add(mk(n, rng))
        return MacContext(n, first.alphaShares, first.alpha, extra)
    }

    private fun mk(n: Int, rng: FieldSource): MacKey {
        val alpha = rng.next()
        return MacKey(Sharing.share(alpha, n, rng), alpha)
    }

    @JvmStatic fun authShare(secret: BigInteger, ctx: MacContext, rng: FieldSource): AuthSV {
        val v = mod(secret)
        val value = Sharing.share(v, ctx.n, rng)
        val mac = Sharing.share(fmul(ctx.alpha, v), ctx.n, rng)
        val extra = Array(ctx.extraKeys.size) { l -> Sharing.share(fmul(ctx.extraKeys[l].alpha, v), ctx.n, rng) }
        return AuthSV(value, mac, extra)
    }

    @JvmStatic fun authConstant(c: BigInteger, ctx: MacContext): AuthSV {
        val v = mod(c)
        val value = Array<BigInteger>(ctx.n) { BigInteger.ZERO }
        value[0] = v
        val mac = scaleAll(ctx.alphaShares, v)
        val extra = Array(ctx.extraKeys.size) { l -> scaleAll(ctx.extraKeys[l].alphaShares, v) }
        return AuthSV(value, mac, extra)
    }

    private fun scaleAll(xs: Array<BigInteger>, c: BigInteger): Array<BigInteger> = Array(xs.size) { fmul(xs[it], c) }

    private fun negAll(xs: Array<BigInteger>): Array<BigInteger> = Array(xs.size) { fneg(xs[it]) }

    private inline fun zip(x: Array<BigInteger>, y: Array<BigInteger>, f: (BigInteger, BigInteger) -> BigInteger): Array<BigInteger> =
        Array(x.size) { f(x[it], y[it]) }

    @JvmStatic fun addAuth(x: AuthSV, y: AuthSV): AuthSV {
        requireSame(x, y)
        return AuthSV(
            zip(x.value, y.value) { a, b -> fadd(a, b) },
            zip(x.mac, y.mac) { a, b -> fadd(a, b) },
            Array(x.extraMac.size) { l -> zip(x.extraMac[l], y.extraMac[l]) { a, b -> fadd(a, b) } },
        )
    }

    @JvmStatic fun subAuth(x: AuthSV, y: AuthSV): AuthSV {
        requireSame(x, y)
        return AuthSV(
            zip(x.value, y.value) { a, b -> Field.fsub(a, b) },
            zip(x.mac, y.mac) { a, b -> Field.fsub(a, b) },
            Array(x.extraMac.size) { l -> zip(x.extraMac[l], y.extraMac[l]) { a, b -> Field.fsub(a, b) } },
        )
    }

    @JvmStatic fun negAuth(x: AuthSV): AuthSV = AuthSV(negAll(x.value), negAll(x.mac), Array(x.extraMac.size) { l -> negAll(x.extraMac[l]) })

    @JvmStatic fun scaleAuth(x: AuthSV, c: BigInteger): AuthSV {
        val k = mod(c)
        return AuthSV(scaleAll(x.value, k), scaleAll(x.mac, k), Array(x.extraMac.size) { l -> scaleAll(x.extraMac[l], k) })
    }

    /** x + c for a PUBLIC constant c: c to one party's value share, alpha_i*c to every party's MAC share under every key. */
    @JvmStatic fun addPublicAuth(x: AuthSV, c: BigInteger, ctx: MacContext): AuthSV {
        val n = ctx.n
        require(!(x.value.size != n || x.mac.size != n || ctx.alphaShares.size != n)) { "addPublicAuth: shared value and MAC context disagree on the party count" }
        require(x.extraMac.size == ctx.extraKeys.size) { "addPublicAuth: shared value and MAC context disagree on the key count" }
        val k = mod(c)
        val value = x.value.clone()
        value[0] = fadd(value[0], k)
        val mac = Array(n) { i -> fadd(x.mac[i], fmul(ctx.alphaShares[i], k)) }
        val extra = Array(x.extraMac.size) { l ->
            val row = x.extraMac[l]
            val key = ctx.extraKeys[l]
            require(!(row.size != n || key.alphaShares.size != n)) { "addPublicAuth: extra MAC party count mismatch" }
            Array(n) { i -> fadd(row[i], fmul(key.alphaShares[i], k)) }
        }
        return AuthSV(value, mac, extra)
    }

    @JvmStatic fun notBitAuth(b: AuthSV, ctx: MacContext): AuthSV = addPublicAuth(negAuth(b), BigInteger.ONE, ctx)

    @JvmStatic fun genAuthTriple(ctx: MacContext, rng: FieldSource): AuthTriple {
        val a = rng.next()
        val b = rng.next()
        val asv = authShare(a, ctx, rng)
        val bsv = authShare(b, ctx, rng)
        val csv = authShare(fmul(a, b), ctx, rng)
        return AuthTriple(asv, bsv, csv)
    }

    /** A triple to deliver plus its sacrifice partners (every partner shares keep.b). */
    class TripleWithPartners(val keep: AuthTriple, val partners: List<AuthTriple>)

    /** TEST-ONLY lying-dealer fault: the dealer authenticates a wrong product. Null entries mean no delta. */
    class DealerFault(val keepCDelta: BigInteger?, val partnerCDelta: List<BigInteger?>?)

    @JvmStatic @JvmOverloads
    fun genTripleWithPartners(ctx: MacContext, rng: FieldSource, partners: Int = SACRIFICE_PARTNERS, fault: DealerFault? = null): TripleWithPartners {
        require(partners in 1..8) { "genTripleWithPartners: partners must be in [1, 8]" }
        val a = rng.next()
        val b = rng.next()
        val bSV = authShare(b, ctx, rng)
        val kd = fault?.keepCDelta ?: BigInteger.ZERO
        val keepA = authShare(a, ctx, rng)
        val keepC = authShare(fadd(fmul(a, b), kd), ctx, rng)
        val keep = AuthTriple(keepA, bSV, keepC)
        val ps = ArrayList<AuthTriple>()
        for (r in 0 until partners) {
            val ah = rng.next()
            val pcd = fault?.partnerCDelta
            val pd = if (pcd != null && r < pcd.size && pcd[r] != null) pcd[r]!! else BigInteger.ZERO
            val pa = authShare(ah, ctx, rng)
            val pc = authShare(fadd(fmul(ah, b), pd), ctx, rng)
            ps.add(AuthTriple(pa, bSV, pc))
        }
        return TripleWithPartners(keep, ps)
    }

    /** Sacrifice check: certifies the kept triples or throws [MacCheckAbort], emitting nothing. */
    @JvmStatic fun sacrificeVerify(batch: List<TripleWithPartners>, ctx: MacContext, rng: FieldSource, deviations: List<Deviation>?): List<AuthTriple> {
        val engine = SpdzEngine(ctx, deviations)
        val taus = ArrayList<BigInteger>()
        for (t in batch) {
            val keep = t.keep
            if (t.partners.isEmpty()) throw MacCheckAbort("sacrifice: a triple without partners cannot be certified")
            for (sac in t.partners) {
                if (!sac.b.value.contentEquals(keep.b.value)) throw MacCheckAbort("sacrifice: partner does not share b with the triple")
                var e = rng.next()
                if (e.signum() == 0) e = BigInteger.ONE
                val rho = engine.open(subAuth(scaleAuth(keep.a, e), sac.a), "sacrifice:rho")
                var tau = subAuth(scaleAuth(keep.c, e), sac.c)
                tau = subAuth(tau, scaleAuth(keep.b, rho))
                taus.add(engine.open(tau, "sacrifice:tau"))
            }
        }
        engine.macCheck(rng)
        for (t in taus) {
            if (t.signum() != 0) {
                throw MacCheckAbort("Beaver-triple sacrifice FAILED: residual tau=$t != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted")
            }
        }
        return batch.map { it.keep }
    }

    /**
     * A party's broadcast deviation in the online phase (models an active cheater). Null valueDelta / macDelta mean none; macKey
     * defaults to 0.
     */
    class Deviation(val openIndex: Int, val party: Int, val valueDelta: BigInteger?, val macDelta: BigInteger?, val macKey: Int?)

    /** One partial opening as it reaches the MAC-check: the public value and macShares[key][party]. */
    class OpenedValue(val value: BigInteger, val macShares: Array<Array<BigInteger>>, val label: String)

    /** Arithmetic core of the batched MAC-check over an arbitrary modulus p; returns sigma[key][party]. */
    @JvmStatic
    fun macResiduals(p: BigInteger, alphaShares: Array<Array<BigInteger>>, opened: List<OpenedValue>, challenges: Array<Array<BigInteger>>): Array<Array<BigInteger>> {
        return Array(alphaShares.size) { l ->
            val r = challenges[l]
            var a = BigInteger.ZERO
            for (j in opened.indices) a = a.add(r[j].multiply(opened[j].value)).mod(p)
            val alphas = alphaShares[l]
            Array(alphas.size) { i ->
                var gamma = BigInteger.ZERO
                for (j in opened.indices) gamma = gamma.add(r[j].multiply(opened[j].macShares[l][i])).mod(p)
                gamma.subtract(alphas[i].multiply(a)).mod(p)
            }
        }
    }

    /** The SPDZ online engine: partial openings and the batched MAC-check. */
    class SpdzEngine(private val ctx: MacContext, deviations: List<Deviation>? = null) {
        private val deviations: List<Deviation> = deviations ?: emptyList()
        private val opened = ArrayList<OpenedValue>()
        private var counter = 0

        init {
            val bits = macSoundnessBits(1 + ctx.extraKeys.size)
            require(bits >= MIN_MAC_SOUNDNESS_BITS) {
                "SpdzEngine: MAC context gives only ${Math.round(bits)} bits of statistical soundness (< $MIN_MAC_SOUNDNESS_BITS); use setupMac(n, rng) with the default $MAC_KEYS keys"
            }
        }

        fun openCount(): Int = counter

        @JvmOverloads fun open(x: AuthSV, label: String = ""): BigInteger {
            val idx = counter++
            require(x.extraMac.size == ctx.extraKeys.size) { "open: value and MAC context disagree on the key count" }
            val valueShares = x.value.clone()
            val macShares = Array(1 + x.extraMac.size) { l -> if (l == 0) x.mac.clone() else x.extraMac[l - 1].clone() }
            for (d in deviations) {
                if (d.openIndex != idx) continue
                require(d.party >= 0 && d.party < ctx.n) { "Deviation.party out of range" }
                if (d.valueDelta != null) valueShares[d.party] = fadd(valueShares[d.party], d.valueDelta)
                if (d.macDelta != null) {
                    val key = d.macKey ?: 0
                    require(key >= 0 && key < macShares.size) { "Deviation.macKey out of range" }
                    macShares[key][d.party] = fadd(macShares[key][d.party], d.macDelta)
                }
            }
            var value = BigInteger.ZERO
            for (s in valueShares) value = fadd(value, s)
            opened.add(OpenedValue(value, macShares, label))
            return value
        }

        /** Batched MAC-check over every partial open so far; throws [MacCheckAbort] on any inconsistency. */
        fun macCheck(rng: FieldSource) {
            if (opened.isEmpty()) return
            val keys = macKeys(ctx)
            val challenges = Array(keys.size) { Array(opened.size) { rng.next() } }
            val alphas = Array(keys.size) { keys[it].alphaShares }
            val sigma = macResiduals(PRIME, alphas, opened, challenges)

            for (l in sigma.indices) {
                val nonces = Array(sigma[l].size) { rng.next() }
                val commitments = Array(nonces.size) { commit(sigma[l][it], nonces[it]) }
                for (i in commitments.indices) {
                    if (commit(sigma[l][i], nonces[i]) != commitments[i]) {
                        throw MacCheckAbort("MAC-check: commitment from party $i did not open consistently")
                    }
                }
            }
            for (l in sigma.indices) {
                var residual = BigInteger.ZERO
                for (s in sigma[l]) residual = fadd(residual, s)
                if (residual.signum() != 0) {
                    throw MacCheckAbort("MAC-check FAILED (key $l): residual $residual != 0 — an actively-malicious party was detected; aborting with no output")
                }
            }
        }
    }

    /** Authenticated Beaver multiplication consuming [triple]; the d and e openings are recorded for the MAC-check. */
    @JvmStatic fun beaverMulAuth(x: AuthSV, y: AuthSV, triple: AuthTriple, ctx: MacContext, engine: SpdzEngine, label: String): AuthSV {
        requireSame(x, triple.a)
        requireSame(x, triple.b)
        requireSame(x, triple.c)
        requireSame(x, y)
        val d = engine.open(subAuth(x, triple.a), "$label:d")
        val e = engine.open(subAuth(y, triple.b), "$label:e")
        val z = addAuth(triple.c, addAuth(scaleAuth(triple.b, d), scaleAuth(triple.a, e)))
        return addPublicAuth(z, fmul(d, e), ctx)
    }

    @JvmStatic fun authValue(x: AuthSV): BigInteger {
        var a = BigInteger.ZERO
        for (s in x.value) a = fadd(a, s)
        return a
    }

    /** SHA-256 binding commitment to a field element under a nonce. */
    internal fun commit(value: BigInteger, nonce: BigInteger): String {
        val h = MessageDigest.getInstance("SHA-256").digest(Json.utf8((value.toString(16) + ":" + nonce.toString(16))))
        val sb = StringBuilder(h.size * 2)
        for (b in h) {
            val v = b.toInt() and 0xff
            sb.append("0123456789abcdef"[v ushr 4]).append("0123456789abcdef"[v and 15])
        }
        return sb.toString()
    }

    private fun requireSame(x: AuthSV, y: AuthSV) {
        require(!(x.value.size != y.value.size || x.mac.size != y.mac.size)) { "authenticated shared values must have the same party count" }
        require(x.extraMac.size == y.extraMac.size) { "authenticated shared values must carry the same number of MAC keys" }
        for (l in x.extraMac.indices) {
            require(x.extraMac[l].size == y.extraMac[l].size) { "authenticated shared values must have the same party count" }
        }
    }
}
