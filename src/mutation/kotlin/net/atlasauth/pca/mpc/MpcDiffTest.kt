package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.mpc.MpcSupport.B
import net.atlasauth.pca.mpc.MpcSupport.BA
import net.atlasauth.pca.mpc.MpcSupport.BAA
import net.atlasauth.pca.mpc.MpcSupport.BAn
import net.atlasauth.pca.mpc.MpcSupport.D
import net.atlasauth.pca.mpc.MpcSupport.I
import net.atlasauth.pca.mpc.MpcSupport.IA
import net.atlasauth.pca.mpc.MpcSupport.L
import net.atlasauth.pca.mpc.MpcSupport.LL
import net.atlasauth.pca.mpc.MpcSupport.M
import net.atlasauth.pca.mpc.MpcSupport.authSV
import net.atlasauth.pca.mpc.MpcSupport.ctx
import net.atlasauth.pca.mpc.MpcSupport.devs
import net.atlasauth.pca.mpc.MpcSupport.fault
import net.atlasauth.pca.mpc.MpcSupport.map
import net.atlasauth.pca.mpc.MpcSupport.rng
import net.atlasauth.pca.mpc.MpcSupport.triple
import net.atlasauth.pca.mpc.MpcSupport.vectors
import net.atlasauth.pca.mpc.Spdz.AuthSV
import net.atlasauth.pca.mpc.Spdz.MacContext
import net.atlasauth.pca.mpc.Spdz.OpenedValue
import net.atlasauth.pca.mpc.Spdz.SpdzEngine
import net.atlasauth.pca.mpc.Spdz.TripleWithPartners
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Differential tests of the MPC deterministic layer against the TypeScript reference corpus (every draw from a seeded SplitMix64). */
@Suppress("UNCHECKED_CAST")
class MpcDiffTest {
    private val MOD = "ref-mpc"

    private fun opened(l: List<Beaver.OpenedMsg>): List<Any?> = l.map { M("label" to it.label, "value" to it.value.toString(), "shares" to L(it.shares)) }

    @Test fun field() {
        OracleCases.each(MOD, "mod") { a -> Field.mod(B(a[0])).toString() }
        OracleCases.each(MOD, "fneg") { a -> Field.fneg(B(a[0])).toString() }
        OracleCases.each(MOD, "fadd") { a -> Field.fadd(B(a[0]), B(a[1])).toString() }
        OracleCases.each(MOD, "fsub") { a -> Field.fsub(B(a[0]), B(a[1])).toString() }
        OracleCases.each(MOD, "fmul") { a -> Field.fmul(B(a[0]), B(a[1])).toString() }
        OracleCases.each(MOD, "fieldRng") { a ->
            val g = rng(a[0])
            val o = ArrayList<Any?>()
            for (i in 0 until I(a[1])) o.add(g.next().toString())
            o
        }
        OracleCases.each(MOD, "fieldRngDefault") { a ->
            val g = Field.FieldRng()
            val o = ArrayList<Any?>()
            for (i in 0 until I(a[0])) o.add(g.next().toString())
            o
        }
    }

    @Test fun sharing() {
        OracleCases.each(MOD, "share") { a -> L(Sharing.share(B(a[0]), I(a[1]), rng(a[2]))) }
        OracleCases.each(MOD, "reconstruct") { a -> Sharing.reconstruct(BAn(a[0])).toString() }
        OracleCases.each(MOD, "shareConstant") { a -> L(Sharing.shareConstant(B(a[0]), I(a[1]))) }
        OracleCases.each(MOD, "sv") { a ->
            val op = a[0] as String
            val x = BA(a[1])
            when (op) {
                "add" -> L(Sharing.addSV(x, BA(a[2])))
                "sub" -> L(Sharing.subSV(x, BA(a[2])))
                "neg" -> L(Sharing.negSV(x))
                "scale" -> L(Sharing.scaleSV(x, B(a[2])))
                "addPublic" -> L(Sharing.addPublicSV(x, B(a[2])))
                "notBit" -> L(Sharing.notBitSV(x))
                else -> throw IllegalArgumentException(op)
            }
        }
    }

    @Test fun gf128() = OracleCases.each(MOD, "gf") { a ->
        val op = a[0] as String
        val x = B(a[1])
        when (op) {
            "add" -> Gf128.add(x, B(a[2])).toString()
            "mul" -> Gf128.mul(x, B(a[2])).toString()
            "mulX" -> Gf128.mulX(x).toString()
            "mulByXi" -> Gf128.mulByXi(x, I(a[2])).toString()
            else -> throw IllegalArgumentException(op)
        }
    }

    @Test fun enc() {
        OracleCases.each(MOD, "encBits") { a -> Enc.encBits(I(a[0])) }
        OracleCases.each(MOD, "makeGadget") { a ->
            val g = rng(a[1])
            L(Enc.makeGadget(I(a[0]), g, a[2] == true))
        }
        OracleCases.each(MOD, "plainShare") { a ->
            val e = Enc.plainShare(B(a[0]))
            M("value" to e.value.toString(), "bits" to L(e.bits))
        }
        OracleCases.each(MOD, "plainGadget") { _ -> L(Enc.plainGadget()) }
        OracleCases.each(MOD, "randomBits") { a -> L(Enc.randomBits(I(a[0]), rng(a[1]))) }
        OracleCases.each(MOD, "sampleEnc") { a ->
            val g = rng(a[1])
            val gad = Enc.makeGadget(I(a[0]), g, true)
            val e = Enc.sampleEnc(gad, g)
            M("gadget" to L(gad), "e" to M("value" to e.value.toString(), "bits" to L(e.bits)))
        }
        OracleCases.each(MOD, "encValue") { a -> Enc.encValue(BA(a[0]), IA(a[1])).toString() }
    }

    @Test fun beaver() {
        OracleCases.each(MOD, "genTriple") { a ->
            val t = Beaver.genTriple(I(a[0]), rng(a[1]))
            M("a" to L(t.a), "b" to L(t.b), "c" to L(t.c))
        }
        OracleCases.each(MOD, "beaverMul") { a ->
            val op = ArrayList<Beaver.OpenedMsg>()
            val z = Beaver.beaverMul(BA(a[0]), BA(a[1]), Beaver.Triple(BA(a[2]), BA(a[3]), BA(a[4])), op)
            M("z" to L(z), "opened" to opened(op))
        }
    }

    @Test fun composition() {
        OracleCases.each(MOD, "thermometerEncode") { a -> L(Thermometer.thermometerEncode(D(a[0]), I(a[1]))) }
        OracleCases.each(MOD, "thermometerDecode") { a ->
            var c = 0
            for (b in a[0] as List<Any?>) if (b is Json.Num && net.atlasauth.pca.jose.Js.num(b) == 1.0) c++
            c
        }
        OracleCases.each(MOD, "quantizeR") { a -> Party.quantizeR(D(a[0]), I(a[1])) }
        OracleCases.each(MOD, "composeClear") { a ->
            val d = Compose.composeClear(vectors(a[0]), I(a[1]))
            M("allow" to d.allow, "t" to d.t, "rQuant" to d.rQuant)
        }
        OracleCases.each(MOD, "assertDecisionVectors") { a ->
            Compose.assertDecisionVectors(vectors(a[0]), I(a[1]))
            true
        }
        OracleCases.each(MOD, "composeSecure") { a ->
            val r = Runner.composeSecure(vectors(a[0]), I(a[1]), B(a[2]))
            val sh = r.sharings.map { M("label" to it.label, "party" to it.party, "secret" to it.secret.toString(), "shares" to L(it.shares)) }
            val held = r.views[0].heldShares.map { it.toString() }
            M(
                "composed" to M("allow" to r.composed.allow, "t" to r.composed.t, "rQuant" to r.composed.rQuant),
                "parties" to r.parties, "Q" to r.q, "multiplications" to r.multiplications, "opened" to opened(r.opened),
                "sharings" to sh, "heldShares0" to held, "viewsLen" to r.views.size,
            )
        }
    }

    @Test fun spdzAuthShares() {
        OracleCases.each(MOD, "setupMac") { a -> ctx(Spdz.setupMac(I(a[0]), rng(a[1]), I(a[2]))) }
        OracleCases.each(MOD, "macSoundnessBits") { a -> if (a.size == 1) Spdz.macSoundnessBits(I(a[0])) else Spdz.macSoundnessBits(I(a[0]), B(a[1])) }
        OracleCases.each(MOD, "authShare") { a ->
            val g = rng(a[1])
            val c = Spdz.setupMac(I(a[0]), g)
            M("ctx" to ctx(c), "sv" to authSV(Spdz.authShare(B(a[2]), c, g)))
        }
        OracleCases.each(MOD, "authConstant") { a -> authSV(Spdz.authConstant(B(a[2]), Spdz.setupMac(I(a[0]), rng(a[1])))) }
        OracleCases.each(MOD, "authOp") { a ->
            val op = a[0] as String
            val g = rng(a[2])
            val c = Spdz.setupMac(I(a[1]), g)
            val x = Spdz.authShare(B(a[3]), c, g)
            val y = Spdz.authShare(B(a[4]), c, g)
            val k = B(a[5])
            if (op == "open") return@each M("val" to Spdz.authValue(x).toString())
            val res: AuthSV = when (op) {
                "add" -> Spdz.addAuth(x, y)
                "sub" -> Spdz.subAuth(x, y)
                "neg" -> Spdz.negAuth(x)
                "scale" -> Spdz.scaleAuth(x, k)
                "addPublic" -> Spdz.addPublicAuth(x, k, c)
                "notBit" -> Spdz.notBitAuth(x, c)
                else -> throw IllegalArgumentException(op)
            }
            val v = Spdz.authValue(res)
            val rows = ArrayList<Array<BigInteger>>()
            rows.add(res.mac)
            rows.addAll(res.extraMac)
            var ok = true
            for (l in rows.indices) {
                var sum = BigInteger.ZERO
                for (m in rows[l]) sum = Field.fadd(sum, m)
                ok = ok && sum == Field.fmul(Spdz.macKeys(c)[l].alpha, v)
            }
            M("res" to authSV(res), "val" to v.toString(), "okMac" to ok)
        }
        OracleCases.each(MOD, "genAuthTriple") { a ->
            val g = rng(a[1])
            triple(Spdz.genAuthTriple(Spdz.setupMac(I(a[0]), g), g))
        }
    }

    private fun partnered(t: TripleWithPartners): Any = M("keep" to triple(t.keep), "partners" to t.partners.map { triple(it) })

    @Test fun spdzTriples() {
        OracleCases.each(MOD, "genTripleWithPartners") { a ->
            if (a.size == 2) {
                val g = rng(a[1])
                partnered(Spdz.genTripleWithPartners(Spdz.setupMac(I(a[0]), g), g))
            } else {
                val g = rng(a[0])
                partnered(Spdz.genTripleWithPartners(Spdz.setupMac(2, g), g, I(a[1]), fault(a[2])))
            }
        }
        OracleCases.each(MOD, "sacrifice") { a ->
            val g = rng(a[1])
            val c = Spdz.setupMac(I(a[0]), g)
            val f = fault(a[4])
            val batch = ArrayList<TripleWithPartners>()
            for (i in 0 until I(a[2])) batch.add(Spdz.genTripleWithPartners(c, g, I(a[3]), if (i == 0) f else null))
            M("certified" to Spdz.sacrificeVerify(batch, c, g, devs(a[5])).map { triple(it) })
        }
    }

    @Test fun spdzEngine() {
        OracleCases.each(MOD, "engineRun") { a ->
            val g = rng(a[1])
            val c = Spdz.setupMac(I(a[0]), g, if (a.size > 4) I(a[4]) else Spdz.MAC_KEYS)
            val e = SpdzEngine(c, devs(a[3]))
            val outs = ArrayList<Any?>()
            val values = a[2] as List<Any?>
            for (i in values.indices) outs.add(e.open(Spdz.authShare(B(values[i]), c, g), "v$i").toString())
            e.macCheck(g)
            M("outs" to outs, "count" to e.openCount())
        }
        OracleCases.each(MOD, "macResiduals") { a ->
            val op = (a[2] as List<Any?>).map { o ->
                val m = map(o)
                OpenedValue(B(m["value"]), BAA(m["macShares"]), "")
            }
            LL(Spdz.macResiduals(B(a[0]), BAA(a[1]), op, BAA(a[3])))
        }
        OracleCases.each(MOD, "beaverAuth") { a ->
            val g = rng(a[1])
            val c: MacContext = Spdz.setupMac(I(a[0]), g)
            val e = SpdzEngine(c, devs(a[4]))
            val x = Spdz.authShare(B(a[2]), c, g)
            val y = Spdz.authShare(B(a[3]), c, g)
            val t = Spdz.genAuthTriple(c, g)
            val z = Spdz.beaverMulAuth(x, y, t, c, e, "m")
            val v = Spdz.authValue(z)
            val out = e.open(z, "out")
            e.macCheck(g)
            M("z" to authSV(z), "val" to v.toString(), "out" to out.toString(), "opens" to e.openCount())
        }
    }
}
