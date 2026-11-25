package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.mpc.MpcSupport.B
import net.atlasauth.pca.mpc.MpcSupport.BA
import net.atlasauth.pca.mpc.MpcSupport.I
import net.atlasauth.pca.mpc.MpcSupport.L
import net.atlasauth.pca.mpc.MpcSupport.M
import net.atlasauth.pca.mpc.MpcSupport.authSV
import net.atlasauth.pca.mpc.MpcSupport.ctx
import net.atlasauth.pca.mpc.MpcSupport.devs
import net.atlasauth.pca.mpc.MpcSupport.fault
import net.atlasauth.pca.mpc.MpcSupport.map
import net.atlasauth.pca.mpc.MpcSupport.triple
import net.atlasauth.pca.mpc.MpcSupport.vectors
import net.atlasauth.pca.mpc.Spdz.AuthSV
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** The MASCOT no-dealer offline phase and the malicious-secure runners against the TypeScript reference corpora. */
@Suppress("UNCHECKED_CAST")
class MpcOfflineDiffTest {
    /** Decodes a composeSecureMalicious config object (Q, seed, deviations, insecureTrustedDealer, dealer). */
    private fun config(m: Map<String, Any?>): SpdzRunner.MaliciousMpcConfig {
        val c = SpdzRunner.MaliciousMpcConfig()
        if (m["Q"] != null) c.q = I(m["Q"])
        if (m["seed"] != null) c.seed = B(m["seed"])
        if (m["deviations"] != null) c.deviations = devs(m["deviations"])
        c.insecureTrustedDealer = m["insecureTrustedDealer"] == true
        if (m["dealer"] != null) {
            val d = map(m["dealer"])
            val o = SpdzRunner.DealerOptions()
            if (d["verifyTriples"] != null) o.verifyTriples = d["verifyTriples"] as Boolean
            if (d["partners"] != null) o.partners = I(d["partners"])
            o.fault = fault(d["fault"])
            c.dealer = o
        }
        return c
    }

    private fun summary(r: SpdzRunner.MaliciousMpcResult): Any = M(
        "composed" to M("allow" to r.composed.allow, "t" to r.composed.t, "rQuant" to r.composed.rQuant), "parties" to r.parties, "Q" to r.q, "opens" to r.opens,
        "multiplications" to r.multiplications, "offlineMode" to r.offlineMode, "triplesVerified" to r.triplesVerified, "macChecked" to r.macChecked,
    )

    @Test fun maliciousRunnerTrustedDealer() =
        OracleCases.each("ref-mpc", "composeSecureMalicious") { a -> summary(SpdzRunner.composeSecureMalicious(vectors(a[0]), config(map(a[1])))) }

    @Test fun mascot() {
        OracleCases.each("ref-mpc-ot", "offline") { a ->
            val n = I(a[0])
            val seed = B(a[1])
            val what = a[2] as String
            val o: Map<String, Any?>? = if (a[3] == null) null else map(a[3])
            var opts: Mascot.NoDealerOptions? = null
            if (o != null) {
                val op = Mascot.NoDealerOptions()
                if (o["sacrifice"] != null) op.sacrifice = o["sacrifice"] as Boolean
                if (o["partners"] != null) op.sacrificePartners = I(o["partners"])
                if (o["keys"] != null) op.macKeys = I(o["keys"])
                if (o["statSec"] != null) op.statSec = I(o["statSec"])
                op.unsafeStatSec = o["unsafe"] == true
                if (o["dev"] != null) {
                    val d = o["dev"] as List<Any?>
                    op.deviation = Mascot.OfflineDeviation(I(d[0]), B(d[1]))
                }
                opts = op
            }
            val off = Mascot.makeNoDealerOffline(n, seed, opts)
            val base = M("n" to off.n, "statSec" to off.statSec, "ctx" to ctx(off.macContext()))
            when (what) {
                "ctx" -> base
                "triple" -> {
                    base["t"] = triple(off.genAuthTriple())
                    base
                }
                "input" -> {
                    base["v"] = authSV(off.authInput(B(o!!["value"]), I(o["owner"])))
                    base
                }
                "multiply" -> {
                    val x = BA(o!!["x"])
                    val y = BA(o["y"])
                    val z = off.otShareMultiply(x.toList(), y)
                    var sum = BigInteger.ZERO
                    var sx = BigInteger.ZERO
                    var sy = BigInteger.ZERO
                    for (v in z) sum = Field.fadd(sum, v)
                    for (v in x) sx = Field.fadd(sx, v)
                    for (v in y) sy = Field.fadd(sy, v)
                    base["z"] = L(z)
                    base["sum"] = sum.toString()
                    base["expect"] = Field.fmul(sx, sy).toString()
                    base
                }
                "consistency" -> {
                    val values = o!!["values"] as List<Any?>
                    val ins = ArrayList<AuthSV>()
                    for (i in values.indices) ins.add(off.authInput(B(values[i]), i % n))
                    if (o["tamper"] == true) ins[0].value[0] = Field.fadd(ins[0].value[0], BigInteger.ONE)
                    off.checkInputConsistency(ins)
                    base["ok"] = true
                    base
                }
                else -> throw IllegalArgumentException(what)
            }
        }
        OracleCases.each("ref-mpc-ot", "offlineBlame") { a ->
            val opts = Mascot.NoDealerOptions()
            opts.deviation = Mascot.OfflineDeviation(I(a[2]), B(a[3]))
            try {
                Mascot.makeNoDealerOffline(I(a[0]), B(a[1]), opts).genAuthTriple()
                M("aborted" to false)
            } catch (e: Mascot.OfflineCheatingAbort) {
                M("aborted" to true, "name" to "OfflineCheatingAbort", "blamed" to ArrayList<Any?>(e.blamed))
            }
        }
        OracleCases.each("ref-mpc-ot", "noDealerRun") { a -> summary(SpdzRunner.composeSecureMalicious(vectors(a[0]), config(map(a[1])))) }
    }
}
