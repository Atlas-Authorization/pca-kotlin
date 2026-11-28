package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.mpc.Field.fadd
import net.atlasauth.pca.mpc.Field.fmul
import net.atlasauth.pca.mpc.Field.fneg
import net.atlasauth.pca.mpc.Field.fsub

/**
 * Pairwise-authenticated field shares for the identifiable-abort mode of the networked runner: each share carries one tag per verifier
 * and one key per peer, so a bad opening is attributable to the party that sent it. The operations are linear and local.
 */
object NetPa {
    /** x with tag[j] (my tag for verifier j) and key[j] (my key for verifying j's share). */
    class PA(val x: BigInteger, val tag: Array<BigInteger>, val key: Array<BigInteger>)

    /** An authenticated value: a value share plus one MAC share per global key, each pairwise-authenticated. */
    class AW(val v: PA, val m: Array<PA>)

    class PaEnv(val id: Int, val n: Int, val delta: BigInteger, val tagged: Boolean)

    private inline fun zip(a: Array<BigInteger>, b: Array<BigInteger>, f: (BigInteger, BigInteger) -> BigInteger): Array<BigInteger> =
        Array(a.size) { f(a[it], b[it]) }

    @JvmStatic fun paAdd(a: PA, b: PA): PA = PA(fadd(a.x, b.x), zip(a.tag, b.tag) { p, q -> fadd(p, q) }, zip(a.key, b.key) { p, q -> fadd(p, q) })
    @JvmStatic fun paSub(a: PA, b: PA): PA = PA(fsub(a.x, b.x), zip(a.tag, b.tag) { p, q -> fsub(p, q) }, zip(a.key, b.key) { p, q -> fsub(p, q) })
    @JvmStatic fun paNeg(a: PA): PA = PA(fneg(a.x), Array(a.tag.size) { fneg(a.tag[it]) }, Array(a.key.size) { fneg(a.key[it]) })
    @JvmStatic fun paScale(a: PA, c: BigInteger): PA =
        PA(fmul(a.x, c), Array(a.tag.size) { fmul(a.tag[it], c) }, Array(a.key.size) { fmul(a.key[it], c) })

    /** Adds a PUBLIC constant to party 0's share (every party applies the same call). */
    @JvmStatic fun paAddPublic0(env: PaEnv, a: PA, c: BigInteger): PA {
        if (env.id == 0) return PA(fadd(a.x, c), a.tag, a.key)
        if (!env.tagged) return a
        val key = a.key.clone()
        key[0] = fsub(key[0], fmul(env.delta, c))
        return PA(a.x, a.tag, key)
    }

    @JvmStatic fun wAdd(a: AW, b: AW): AW = AW(paAdd(a.v, b.v), Array(a.m.size) { l -> paAdd(a.m[l], b.m[l]) })

    @JvmStatic fun wSub(a: AW, b: AW): AW = AW(paSub(a.v, b.v), Array(a.m.size) { l -> paSub(a.m[l], b.m[l]) })

    @JvmStatic fun wNeg(a: AW): AW = AW(paNeg(a.v), Array(a.m.size) { paNeg(a.m[it]) })

    @JvmStatic fun wScale(a: AW, c: BigInteger): AW = AW(paScale(a.v, c), Array(a.m.size) { paScale(a.m[it], c) })

    /** x + c for a PUBLIC c: party 0's value share moves by c and every MAC share moves by alpha_i * c. */
    @JvmStatic fun wAddPublic(env: PaEnv, a: AW, c: BigInteger, alpha: Array<PA>): AW =
        AW(paAddPublic0(env, a.v, c), Array(a.m.size) { l -> paAdd(a.m[l], paScale(alpha[l], c)) })

    /** Verifies peer [from]'s opened share x with tag against my key for that peer. */
    @JvmStatic fun paVerify(env: PaEnv, a: PA, from: Int, x: BigInteger, tag: BigInteger): Boolean = fadd(a.key[from], fmul(env.delta, x)) == tag

    // ---- wire codec ----

    @JvmStatic fun paWidth(n: Int, tagged: Boolean): Int = if (tagged) 1 + 2 * (n - 1) else 1

    @JvmStatic fun paFlat(a: PA, id: Int, n: Int, tagged: Boolean): List<BigInteger> {
        val out = ArrayList<BigInteger>()
        out.add(a.x)
        if (tagged) {
            for (j in 0 until n) if (j != id) out.add(a.tag[j])
            for (j in 0 until n) if (j != id) out.add(a.key[j])
        }
        return out
    }

    @JvmStatic fun paParse(nums: List<BigInteger>, off: Int, id: Int, n: Int, tagged: Boolean): PA {
        val x = nums[off]
        if (!tagged) return PA(x, emptyArray(), emptyArray())
        val tag = Array<BigInteger>(n) { BigInteger.ZERO }
        val key = Array<BigInteger>(n) { BigInteger.ZERO }
        var o = off + 1
        for (j in 0 until n) if (j != id) tag[j] = nums[o++]
        for (j in 0 until n) if (j != id) key[j] = nums[o++]
        return PA(x, tag, key)
    }

    @JvmStatic fun awWidth(n: Int, keys: Int, tagged: Boolean): Int = (1 + keys) * paWidth(n, tagged)

    @JvmStatic fun awFlat(a: AW, id: Int, n: Int, tagged: Boolean): List<BigInteger> {
        val out = ArrayList(paFlat(a.v, id, n, tagged))
        for (p in a.m) out.addAll(paFlat(p, id, n, tagged))
        return out
    }

    @JvmStatic fun awParse(nums: List<BigInteger>, off: Int, id: Int, n: Int, keys: Int, tagged: Boolean): AW {
        val w = paWidth(n, tagged)
        val v = paParse(nums, off, id, n, tagged)
        return AW(v, Array(keys) { l -> paParse(nums, off + (1 + l) * w, id, n, tagged) })
    }
}
