package net.atlasauth.pca.mpc

import java.math.BigInteger
import java.security.MessageDigest
import java.util.TreeSet
import net.atlasauth.pca.mpc.Field.fadd
import net.atlasauth.pca.mpc.Field.fmul
import net.atlasauth.pca.mpc.Field.fsub
import net.atlasauth.pca.mpc.Field.mod
import net.atlasauth.pca.verifier.Json

/**
 * Forensic disclosures of a failed offline triple: each party discloses its OT choice bits, operands, claimed product share and the
 * per-peer OT messages; the cross-check names the party whose own data are inconsistent or whose counterpart's transcript disagrees.
 * This object holds the pure parts (strict parsing, audit, blame, the commit-first binding); the timed exchange over the mesh is part of
 * the networked driver.
 */
object NetForensics {
    /** One product item's disclosure; recv and rho are keyed by peer index (insertion ordered). */
    class SlotDisclosure(val bits: IntArray, val y: BigInteger, val z: BigInteger, val recv: Map<Int, Array<BigInteger>>, val rho: Map<Int, Array<BigInteger>>)

    @JvmStatic fun slotsFor(partners: Int): Int = 1 + partners

    /** The wire (JSON) form of a disclosure. */
    @JvmStatic fun wireDisclosure(d: List<SlotDisclosure>): List<Any?> {
        val out = ArrayList<Any?>()
        for (s in d) {
            val m = LinkedHashMap<String, Any?>()
            val bits = StringBuilder()
            for (b in s.bits) bits.append(b)
            m["bits"] = bits.toString()
            m["y"] = NetWire.hx(s.y)
            m["z"] = NetWire.hx(s.z)
            m["recv"] = side(s.recv)
            m["rho"] = side(s.rho)
            out.add(m)
        }
        return out
    }

    private fun side(x: Map<Int, Array<BigInteger>>): List<Any?> {
        val out = ArrayList<Any?>()
        for ((k, v) in x) out.add(listOf<Any?>(k, v.map { NetWire.hx(it) }))
        return out
    }

    private fun field(s: Any?): BigInteger = NetWire.unhx(s) ?: throw IllegalArgumentException("bad field element")

    /** Strict parse of a peer's disclosure; throws on any deviation from the expected shape. */
    @JvmStatic fun parseDisclosure(raw: Any?, slots: Int, rows: Int, peers: List<Int>): List<SlotDisclosure> {
        require(raw is List<*> && raw.size == slots) { "bad forensic disclosure" }
        val out = ArrayList<SlotDisclosure>()
        val bitsRe = Regex("^[01]{" + rows + "}$")
        for (o in raw) {
            require(o is Map<*, *>) { "bad choice bits" }
            val bs = o["bits"]
            require(bs is String && bitsRe.matches(bs)) { "bad choice bits" }
            val bits = IntArray(bs.length) { i -> if (bs[i] == '1') 1 else 0 }
            val y = field(o["y"])
            val z = field(o["z"])
            out.add(SlotDisclosure(bits, y, z, sideParse(o["recv"], rows, peers), sideParse(o["rho"], rows, peers)))
        }
        return out
    }

    private fun sideParse(x: Any?, rows: Int, peers: List<Int>): Map<Int, Array<BigInteger>> {
        require(x is List<*> && x.size == peers.size) { "bad peer table" }
        val m = LinkedHashMap<Int, Array<BigInteger>>()
        for (e in x) {
            require(e is List<*> && e.size == 2 && e[0] is Json.Num) { "bad peer entry" }
            val pd = e[0].toString().toDouble()
            val p: Int? = if (pd == Math.rint(pd) && Math.abs(pd) < 1e9) pd.toInt() else null
            if (p == null || !peers.contains(p) || m.containsKey(p)) throw IllegalArgumentException("bad peer entry")
            val vals = e[1]
            require(vals is List<*> && vals.size == rows) { "bad row table" }
            m[p] = Array(rows) { i -> field(vals[i]) }
        }
        return m
    }

    /** selfBad: parties whose own disclosure is inconsistent; pairBad: ordered [receiver, sender] pairs whose OT transcripts disagree. */
    class AuditResult(val selfBad: Set<Int>, val pairBad: List<IntArray>)

    /** Cross-checks every party's disclosure of one failed triple against the public gadget. */
    @JvmStatic fun auditDisclosures(all: Map<Int, List<SlotDisclosure>>, gadget: Array<BigInteger>): AuditResult {
        val selfBad = HashSet<Int>()
        val pairBad = ArrayList<IntArray>()
        val parties = ArrayList(TreeSet(all.keys))
        for (i in parties) {
            val di = all[i]!!
            for (s in di.indices) {
                val sd = di[s]
                var value = BigInteger.ZERO
                for (k in gadget.indices) if (k < sd.bits.size && sd.bits[k] == 1) value = value.add(gadget[k])
                var implied = fmul(mod(value), sd.y)
                for (p in parties) {
                    if (p == i) continue
                    for (v in sd.recv[p]!!) implied = fadd(implied, mod(v))
                    for (v in sd.rho[p]!!) implied = fsub(implied, v)
                }
                if (implied != sd.z) selfBad.add(i)
                for (p in parties) {
                    if (p == i) continue
                    val sp = all[p]!![s]
                    val rho = sp.rho[i]!!
                    val got = sd.recv[p]!!
                    val y = mod(sp.y)
                    var bad = false
                    var k = 0
                    while (k < gadget.size && !bad) {
                        val want = fadd(rho[k], if (k < sd.bits.size && sd.bits[k] == 1) fmul(gadget[k], y) else BigInteger.ZERO)
                        if (mod(got[k]) != want) bad = true
                        k++
                    }
                    if (bad) pairBad.add(intArrayOf(i, p))
                }
            }
        }
        return AuditResult(selfBad, pairBad)
    }

    /** The party the verifier [me] blames, or null when the evidence cannot name one. */
    @JvmStatic fun blameFrom(me: Int, r: AuditResult): Int? {
        val own = TreeSet<Int>()
        for (p in r.selfBad) if (p != me) own.add(p)
        if (own.isNotEmpty()) return own.first()
        for (pr in r.pairBad) {
            if (pr[0] == me) return pr[1]
            if (pr[1] == me) return pr[0]
        }
        return null
    }

    const val DEFAULT_FORENSIC_DEADLINE_MS = 30_000

    /** Binding commitment to a disclosure: session, party, triple index, deadline, a 256-bit nonce and the canonical wire form. */
    @JvmStatic fun disclosureCommit(sessionId: String, party: Int, tripleIndex: Int, deadlineMs: Long, nonce: String, wire: Any?): String {
        val h = MessageDigest.getInstance("SHA-256")
        h.update("atlas-pca-mpc/forensic-commit/v1\u0000".toByteArray(Charsets.UTF_8))
        val arr = listOf<Any?>(sessionId, party, tripleIndex, deadlineMs, nonce, wire)
        h.update(Json.utf8(NetWire.stringify(arr)))
        return NetCodec.hex(h.digest())
    }
}
