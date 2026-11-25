package net.atlasauth.pca.mpc

import java.math.BigInteger
import net.atlasauth.pca.mpc.MpcSupport.B
import net.atlasauth.pca.mpc.MpcSupport.BA
import net.atlasauth.pca.mpc.MpcSupport.D
import net.atlasauth.pca.mpc.MpcSupport.I
import net.atlasauth.pca.mpc.MpcSupport.IA
import net.atlasauth.pca.mpc.MpcSupport.L
import net.atlasauth.pca.mpc.MpcSupport.M
import net.atlasauth.pca.mpc.MpcSupport.map
import net.atlasauth.pca.mpc.NetForensics.SlotDisclosure
import net.atlasauth.pca.mpc.NetPa.AW
import net.atlasauth.pca.mpc.NetPa.PA
import net.atlasauth.pca.mpc.NetPa.PaEnv
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Differential tests of the pure parts of the MPC networked runner (wire codec, pairwise-authenticated shares, forensics, codecs). */
@Suppress("UNCHECKED_CAST", "FunctionName")
class MpcNetDiffTest {
    private val MOD = "ref-mpc-net"

    private fun by(o: Any?): ByteArray = Keys.unb64u(map(o)["\$bytes"] as String)

    private fun nullableInt(o: Any?): Int? = if (o == null) null else I(o)

    // ---- wire ----
    @Test fun frames() {
        OracleCases.each(MOD, "encodeFrame") { a ->
            val f = map(a[0])
            NetWire.encodeFrame(NetWire.Frame(f["v"], f["ty"] as String?, f["sid"] as String?, f["seq"], f["rd"] as String?, f["d"]))
        }
        OracleCases.each(MOD, "split") { a ->
            val s = NetWire.FrameSplitter()
            val out = ArrayList<Any?>()
            for (c in a[0] as List<Any?>) out.addAll(s.push(by(c)))
            M("frames" to out)
        }
        OracleCases.each(MOD, "peekVersion") { a -> NetWire.peekVersion(by(a[0])) }
        OracleCases.each(MOD, "parseFrame") { a -> NetWire.parseFrame(by(a[0])) }
        OracleCases.each(MOD, "versionMismatch") { a -> NetWire.versionMismatch(by(a[0])) }
        OracleCases.each(MOD, "hx") { a -> NetWire.hx(B(a[0])) }
        OracleCases.each(MOD, "unhx") { a -> NetWire.unhx(a[0])?.toString() }
        OracleCases.each(MOD, "unhxArray") { a -> NetWire.unhxArray(a[0], I(a[1]))?.let { L(it) } }
        OracleCases.each(MOD, "netAbort") { a ->
            val cb = a[5]
            val op: Map<String, Any?>? = if (a[6] == null) null else map(a[6])
            val e = NetWire.NetAbort(
                a[0] as String, nullableInt(a[1]), I(a[2]), a[3] as String, a[4] as String?,
                if (cb is Json.Num) I(cb) else null, op?.get("reason") as String?, op?.get("evidence"),
                if (op == null || op["deadlineMs"] == null) null else I(op["deadlineMs"]),
            )
            M(
                "message" to e.message, "name" to "NetAbort", "kind" to e.kind, "blamed" to e.blamed, "reporter" to e.reporter, "reason" to e.reason,
                "claimedKind" to e.claimedKind, "claimedBlame" to e.claimedBlame, "evidence" to e.evidence, "deadlineMs" to e.deadlineMs,
            )
        }
        OracleCases.each(MOD, "abortKinds") { _ -> NetWire.ABORT_KINDS.toSortedSet().toList() }
    }

    // ---- pairwise-authenticated shares ----
    private fun pa(o: Any?): PA {
        val m = map(o)
        return PA(B(m["x"]), BA(m["tag"]), BA(m["key"]))
    }

    private fun aw(o: Any?): AW {
        val m = map(o)
        val ms = m["m"] as List<Any?>
        return AW(pa(m["v"]), Array(ms.size) { i -> pa(ms[i]) })
    }

    private fun paJ(p: PA): Map<String, Any?> = M("x" to p.x.toString(), "tag" to L(p.tag), "key" to L(p.key))

    private fun awJ(a: AW): Map<String, Any?> = M("v" to paJ(a.v), "m" to a.m.map { paJ(it) })

    private fun nums(l: List<BigInteger>): List<Any?> = l.map { it.toString() }

    @Test fun pairwiseShares() {
        OracleCases.each(MOD, "pa") { a ->
            val op = a[0] as String
            val p = pa(a[1])
            val n = p.tag.size
            when (op) {
                "add" -> paJ(NetPa.paAdd(p, pa(a[2])))
                "sub" -> paJ(NetPa.paSub(p, pa(a[2])))
                "neg" -> paJ(NetPa.paNeg(p))
                "scale" -> paJ(NetPa.paScale(p, B(a[2])))
                "addPublic0" -> paJ(NetPa.paAddPublic0(PaEnv(I(a[2]), n, B(a[3]), a[4] == true), p, B(a[5])))
                "verify" -> NetPa.paVerify(PaEnv(I(a[2]), n, B(a[3]), true), p, I(a[4]), B(a[5]), B(a[6]))
                "flat" -> {
                    val id = I(a[2])
                    val tg = a[3] == true
                    val f = NetPa.paFlat(p, id, n, tg)
                    M("f" to nums(f), "w" to NetPa.paWidth(n, tg), "back" to paJ(NetPa.paParse(f, 0, id, n, tg)))
                }
                else -> throw IllegalArgumentException(op)
            }
        }
        OracleCases.each(MOD, "aw") { a ->
            if (a.size == 1) return@each NetCodec.sharingsPerTriple(I(a[0]))
            if (a.size == 3) {
                val x = aw(a[0])
                val n = x.v.tag.size
                val keys = x.m.size
                val id = I(a[1])
                val tg = a[2] == true
                val f = NetPa.awFlat(x, id, n, tg)
                return@each M("f" to nums(f), "w" to NetPa.awWidth(n, keys, tg), "back" to awJ(NetPa.awParse(f, 0, id, n, keys, tg)))
            }
            val x = aw(a[0])
            val y = aw(a[1])
            val n = x.v.tag.size
            val al = a[2] as List<Any?>
            val alpha = Array(al.size) { i -> pa(al[i]) }
            val tg = a[3] == true
            val c = B(a[4])
            M(
                "add" to awJ(NetPa.wAdd(x, y)), "sub" to awJ(NetPa.wSub(x, y)), "neg" to awJ(NetPa.wNeg(x)), "scale" to awJ(NetPa.wScale(x, c)),
                "addPublic" to awJ(NetPa.wAddPublic(PaEnv(1, n, BigInteger.valueOf(7), tg), x, c, alpha)),
                "addPublic0" to awJ(NetPa.wAddPublic(PaEnv(0, n, BigInteger.valueOf(7), tg), x, c, alpha)),
            )
        }
    }

    // ---- forensics ----
    private fun sideJ(m: Map<Int, Array<BigInteger>>): List<Any?> = m.entries.map { listOf<Any?>(it.key, L(it.value)) }

    private fun dis(o: Any?): List<SlotDisclosure> = (o as List<Any?>).map { so ->
        val s = map(so)
        SlotDisclosure(IA(s["bits"]), B(s["y"]), B(s["z"]), sideIn(s["recv"]), sideIn(s["rho"]))
    }

    private fun sideIn(o: Any?): Map<Int, Array<BigInteger>> {
        val m = LinkedHashMap<Int, Array<BigInteger>>()
        for (e in o as List<Any?>) m[I((e as List<Any?>)[0])] = BA(e[1])
        return m
    }

    @Test fun forensics() = OracleCases.each(MOD, "forensics") { a ->
        when (a.size) {
            1 -> NetForensics.slotsFor(I(a[0]))
            3 -> {
                if (a[0] is Map<*, *>) {
                    val all = LinkedHashMap<Int, List<SlotDisclosure>>()
                    for ((k, v) in map(a[0])) all[k.toInt()] = dis(v)
                    if (a[2] != null) all.remove(I(a[2]))
                    val res = NetForensics.auditDisclosures(all, BA(a[1]))
                    val pb = res.pairBad.map { listOf<Any?>(it[0], it[1]) }
                    val blame = ArrayList<Any?>()
                    for (me in 0 until 3) blame.add(NetForensics.blameFrom(me, res))
                    M("selfBad" to res.selfBad.toSortedSet().toList(), "pairBad" to pb, "blame" to blame)
                } else {
                    val sb = HashSet<Int>()
                    for (x in a[1] as List<Any?>) sb.add(I(x))
                    val pb = ArrayList<IntArray>()
                    for (x in a[2] as List<Any?>) pb.add(intArrayOf(I((x as List<Any?>)[0]), I(x[1])))
                    NetForensics.blameFrom(I(a[0]), NetForensics.AuditResult(sb, pb))
                }
            }
            4 -> {
                val peers = ArrayList<Int>()
                for (x in a[3] as List<Any?>) peers.add(I(x))
                val dd = NetForensics.parseDisclosure(a[0], I(a[1]), I(a[2]), peers)
                val ddj = dd.map { s -> M("bits" to L(s.bits), "y" to s.y.toString(), "z" to s.z.toString(), "recv" to sideJ(s.recv), "rho" to sideJ(s.rho)) }
                M("dd" to ddj, "back" to NetForensics.wireDisclosure(dd))
            }
            6 -> NetForensics.disclosureCommit(a[0] as String, I(a[1]), I(a[2]), D(a[3]).toLong(), a[4] as String, a[5])
            else -> throw IllegalArgumentException("forensics arity")
        }
    }

    // ---- codecs ----
    @Test fun codecs() = OracleCases.each(MOD, "codec") { a ->
        when (val op = a[0] as String) {
            "unb64" -> NetCodec.unb64(a[1], if (a[2] == null) -1 else I(a[2]))
            "b64" -> NetCodec.b64(by(a[1]))
            "hexBig" -> NetCodec.hexBig(a[1]).toString()
            "jPt" -> NetCodec.ptJ(NetCodec.jPt(a[1]))
            "ptJ" -> NetCodec.ptJ(Ec.mulBase(B(a[1])))
            "gadgetCommit" -> NetCodec.gadgetCommit(a[1] as String, I(a[2]), by(a[3]))
            "gadgetStatement" -> NetCodec.gadgetStatement(a[1] as String, a[2] as String, I(a[3]), a[4] as String)
            else -> throw IllegalArgumentException(op)
        }
    }
}
