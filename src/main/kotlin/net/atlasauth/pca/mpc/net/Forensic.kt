package net.atlasauth.pca.mpc.net

import java.security.SecureRandom
import net.atlasauth.pca.mpc.NetForensics
import net.atlasauth.pca.mpc.NetForensics.SlotDisclosure
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.verifier.Json

/**
 * Commit-first disclosure exchange for a failed triple (dealer-free mode). Nobody opens before every commitment is in hand
 * (round forensic-c completes first), so no party's disclosure can depend on another's; an opening that does not match its
 * commitment is blamed, a late or absent party times out at the shared deadline.
 */
object Forensic {
    private val HEX64 = Regex("^[0-9a-f]{64}$")

    /** Every OTHER party's verified disclosure. */
    @JvmStatic fun exchangeDisclosures(
        sessionId: String, id: Int, n: Int, tripleIndex: Int, mine: List<SlotDisclosure>, slots: Int, rows: Int, deadlineMs: Long, io: Exchanger,
    ): Map<Int, List<SlotDisclosure>> {
        val wire = NetForensics.wireDisclosure(mine)
        val nb = ByteArray(32)
        SecureRandom().nextBytes(nb)
        val nonce = NetHex.enc(nb)
        val myCommit = NetForensics.disclosureCommit(sessionId, id, tripleIndex, deadlineMs, nonce, wire)
        val commits: Map<Int, String> = io.exchange("forensic-c", { _ ->
            linkedMapOf<String, Any?>("c" to myCommit, "d" to deadlineMs)
        }, { p, raw ->
            val o = raw as? Map<*, *>
            val c = o?.get("c")
            if (o == null || c !is String || !HEX64.matches(c)) throw io.bad(p, "bad forensic commitment")
            val d = o["d"]
            if (d !is Json.Num || d.toString() != deadlineMs.toString()) throw io.bad(p, "forensic deadline $d differs from the agreed $deadlineMs")
            c
        }, deadlineMs)
        return io.exchange("forensic-o", { _ ->
            linkedMapOf<String, Any?>("w" to wire, "nonce" to nonce)
        }, { p, raw ->
            val o = raw as? Map<*, *>
            val nn = o?.get("nonce")
            if (o == null || nn !is String || !HEX64.matches(nn)) throw io.bad(p, "bad forensic opening")
            if (NetForensics.disclosureCommit(sessionId, p, tripleIndex, deadlineMs, nn, o["w"]) != commits[p]) {
                throw NetAbort("commitment", p, id, "party $p opened a forensic disclosure that does not match its commitment")
            }
            val peers = ArrayList<Int>()
            for (q in 0 until n) if (q != p) peers.add(q)
            NetForensics.parseDisclosure(o["w"], slots, rows, peers)
        }, deadlineMs)
    }
}
