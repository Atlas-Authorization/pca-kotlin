package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.mpc.Field.fadd
import net.atlasauth.pca.mpc.Field.fmul

/** Secure multiplication of two additively-shared values with Beaver triples (a trusted dealer supplies the triples). */
object Beaver {
    /** A Beaver triple (a, b, c = a*b), each component additively shared. */
    class Triple(val a: Array<BigInteger>, val b: Array<BigInteger>, val c: Array<BigInteger>)

    /** One opened (public) protocol message; [label] is "d" or "e". */
    class OpenedMsg(val label: String, val value: BigInteger, val shares: Array<BigInteger>)

    @JvmStatic fun genTriples(count: Int, n: Int, rng: FieldSource): List<Triple> {
        val out = ArrayList<Triple>()
        for (i in 0 until count) out.add(genTriple(n, rng))
        return out
    }

    @JvmStatic fun genTriple(n: Int, rng: FieldSource): Triple {
        val a = rng.next()
        val b = rng.next()
        val c = fmul(a, b)
        return Triple(Sharing.share(a, n, rng), Sharing.share(b, n, rng), Sharing.share(c, n, rng))
    }

    /** x*y consuming [triple]; every opened value is appended to [transcript] when non-null. */
    @JvmStatic fun beaverMul(x: Array<BigInteger>, y: Array<BigInteger>, triple: Triple, transcript: MutableList<OpenedMsg>?): Array<BigInteger> {
        require(x.size == y.size) { "beaverMul: operand party counts differ" }
        for (part in arrayOf(triple.a, triple.b, triple.c)) {
            require(part.size == x.size) { "beaverMul: triple party count differs from the operands" }
        }
        val dShares = Sharing.subSV(x, triple.a)
        val eShares = Sharing.subSV(y, triple.b)
        val d = Sharing.reconstruct(dShares)
        val e = Sharing.reconstruct(eShares)
        transcript?.add(OpenedMsg("d", d, dShares))
        transcript?.add(OpenedMsg("e", e, eShares))
        val de = fmul(d, e)
        return Array(x.size) { i ->
            val zi = fadd(triple.c[i], fadd(fmul(d, triple.b[i]), fmul(e, triple.a[i])))
            if (i == 0) fadd(zi, de) else zi
        }
    }
}
