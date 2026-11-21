package net.atlasauth.pca.mpc.net

import java.security.SecureRandom
import net.atlasauth.pca.mpc.NetCodec
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.verifier.Json

/**
 * Agreement on the joint choice-bit gadget seeds: a signed commit-reveal with an echo round, so ONE corrupt party cannot make
 * honest parties derive different gadgets and then blame each other. Every commitment and opening is signed with the sender's
 * pinned TLS identity key; after the reveal each party echoes the signed values it got from every third party (round gd-e).
 * An echoed signature that does not verify blames the echoer; a verifying statement that differs from the one received
 * directly blames the signer with both statements as transferable evidence. With n = 2 the echo is skipped.
 */
object Gadget {
    private val HEX64 = Regex("^[0-9a-f]{64}$")
    private val HEXSIG = Regex("^[0-9a-f]{16,200}$")

    private fun isSigned(x: Any?, valueRe: Regex): Boolean {
        if (x !is Map<*, *>) return false
        val v = x["v"]
        val s = x["s"]
        return v is String && valueRe.matches(v) && s is String && HEXSIG.matches(s)
    }

    private fun signed(mesh: Mesh, round: String, value: String): Map<String, Any?> {
        val sig = mesh.sign(NetCodec.gadgetStatement(mesh.sessionId(), round, mesh.selfId, value))
        return linkedMapOf("v" to value, "s" to NetHex.enc(sig))
    }

    private fun check(mesh: Mesh, signer: Int, round: String, m: Map<*, *>): Boolean = try {
        mesh.verify(signer, NetCodec.gadgetStatement(mesh.sessionId(), round, signer, m["v"] as String), NetHex.dec(m["s"] as String))
    } catch (e: RuntimeException) {
        false
    }

    private fun intOf(o: Any?): Int? {
        if (o !is Json.Num) return null
        val d = o.toString().toDoubleOrNull() ?: return null
        return if (d == Math.rint(d) && Math.abs(d) < 1e9) d.toInt() else null
    }

    @JvmStatic fun agreeGadgetSeeds(mesh: Mesh, n: Int, io: Exchanger): Array<ByteArray> {
        val seed = ByteArray(32)
        SecureRandom().nextBytes(seed)
        return agreeGadgetSeeds(mesh, n, io, seed)
    }

    /** Run the signed commit / reveal / echo and return every party's seed in party order (mine included). [mySeed] is injectable for tests. */
    @Suppress("UNCHECKED_CAST")
    @JvmStatic fun agreeGadgetSeeds(mesh: Mesh, n: Int, io: Exchanger, mySeed: ByteArray): Array<ByteArray> {
        val id = mesh.selfId
        val sid = mesh.sessionId()
        val myCommit = NetCodec.gadgetCommit(sid, id, mySeed)
        val commits: Map<Int, Map<String, Any?>> = io.exchange("gd-c", { _ -> signed(mesh, "gd-c", myCommit) }, { p, raw ->
            if (!isSigned(raw, HEX64)) throw io.bad(p, "bad gadget commitment")
            if (!check(mesh, p, "gd-c", raw as Map<*, *>)) throw io.bad(p, "gadget commitment signature does not verify")
            raw as Map<String, Any?>
        })
        val mySeedHex = NetHex.enc(mySeed)
        val opens: Map<Int, Map<String, Any?>> = io.exchange("gd-o", { _ -> signed(mesh, "gd-o", mySeedHex) }, { p, raw ->
            if (!isSigned(raw, HEX64)) throw io.bad(p, "bad gadget seed")
            val m = raw as Map<String, Any?>
            if (!check(mesh, p, "gd-o", m)) throw io.bad(p, "gadget seed signature does not verify")
            if (NetCodec.gadgetCommit(sid, p, NetHex.dec(m["v"] as String)) != commits[p]!!["v"]) {
                throw NetAbort("commitment", p, id, "party $p opened a gadget seed that does not match its commitment")
            }
            m
        })
        if (n >= 3) {
            val others = ArrayList<Int>()
            for (i in 0 until n) if (i != id) others.add(i)
            io.exchange("gd-e", { peer ->
                val out = ArrayList<Any?>()
                for (j in others) {
                    if (j == peer) continue
                    out.add(linkedMapOf<String, Any?>("j" to j, "c" to commits[j], "o" to opens[j]))
                }
                out
            }, { p, raw ->
                val expect = ArrayList<Int>()
                for (j in others) if (j != p) expect.add(j)
                if (raw !is List<*> || raw.size != expect.size) throw io.bad(p, "bad gadget echo")
                for (k in expect.indices) {
                    val eo = raw[k]
                    val j = expect[k]
                    if (eo !is Map<*, *>) throw io.bad(p, "bad gadget echo entry")
                    val e = eo as Map<String, Any?>
                    val ej = intOf(e["j"])
                    if (ej == null || ej != j || !isSigned(e["c"], HEX64) || !isSigned(e["o"], HEX64)) throw io.bad(p, "bad gadget echo entry")
                    val ec = e["c"] as Map<String, Any?>
                    val eoo = e["o"] as Map<String, Any?>
                    // a statement that does not verify under j's pinned key was forged by the echoer p
                    if (!check(mesh, j, "gd-c", ec) || !check(mesh, j, "gd-o", eoo)) throw io.bad(p, "gadget echo carries a statement that party $j did not sign")
                    val mineC = commits[j]!!
                    val mineO = opens[j]!!
                    val cDiff = ec["v"] != mineC["v"]
                    if (cDiff || eoo["v"] != mineO["v"]) {
                        // both statements verify under j's key and differ: j signed two values for one round
                        val ev = linkedMapOf<String, Any?>(
                            "signer" to j,
                            "round" to (if (cDiff) "gd-c" else "gd-o"),
                            "statements" to (if (cDiff) listOf(mineC, ec) else listOf(mineO, eoo)),
                        )
                        throw NetAbort(
                            "equivocation", j, id,
                            "party $j signed different gadget " + (if (cDiff) "commitments" else "seeds") + " for different parties (shown by party $p's echo)",
                            null, null, null, ev, null,
                        )
                    }
                }
                true
            })
        }
        return Array(n) { p -> if (p == id) mySeed.clone() else NetHex.dec(opens[p]!!["v"] as String) }
    }
}
