package net.atlasauth.pca.mpc.net

import java.security.MessageDigest
import net.atlasauth.pca.mpc.Ec.Point
import net.atlasauth.pca.mpc.Ec.SchnorrProof
import net.atlasauth.pca.mpc.NetCodec
import net.atlasauth.pca.mpc.NetWire
import net.atlasauth.pca.mpc.NetWire.NetAbort
import net.atlasauth.pca.mpc.Ot
import net.atlasauth.pca.mpc.Ot.BaseOtAbort
import net.atlasauth.pca.mpc.Ot.BaseOtBinding
import net.atlasauth.pca.verifier.Json

/**
 * Pairwise base oblivious transfer OVER THE NETWORK: the malicious-secure Chou-Orlandi-style base OT on Ed25519 with a Schnorr
 * proof of knowledge and subgroup validation of every received point. A FUNCTIONAL-CORRECTNESS demonstration: afterwards the
 * receiver reveals its choice bits and a hash of each received pad (a demo-only step, NOT part of the OT) so the sender can
 * check the pads over a real network. The post-quantum endemic-LWE variant lives in the separate lwe-ot adapter.
 */
object OtNet {
    data class Result(val role: String, val count: Int, val matched: Boolean, val padDigest: String)

    private fun sha(vararg parts: ByteArray): ByteArray {
        val h = MessageDigest.getInstance("SHA-256")
        for (p in parts) h.update(p)
        return h.digest()
    }

    private fun hex(b: ByteArray): String = NetCodec.hex(b)

    /** Binding of a base OT on this mesh: session (hashed to a fixed length), who sends, who receives, which round. */
    @JvmStatic
    fun netBinding(mesh: Mesh, senderIndex: Int, receiverIndex: Int, round: String): BaseOtBinding {
        val sid = sha("atlas-pca-mpc/net-session/v2".toByteArray(Charsets.UTF_8), Json.utf8(mesh.sessionId()))
        return BaseOtBinding(sid, senderIndex.toLong(), receiverIndex.toLong(), round)
    }

    private fun <T> parsing(mesh: Mesh, peer: Int, rd: String, f: () -> T): T {
        try {
            return f()
        } catch (e: RuntimeException) {
            val ne = NetAbort("malformed", peer, mesh.selfId, "round '$rd': ${e.message}")
            mesh.fail(ne, null)
            throw ne
        }
    }

    private fun bit(o: Any?): Int {
        if (o is Json.Num && o.toString() == "0") return 0
        if (o is Json.Num && o.toString() == "1") return 1
        return -1
    }

    private fun digest(pads: Array<ByteArray>): String {
        val all = java.io.ByteArrayOutputStream()
        for (p in pads) all.write(p, 0, p.size)
        return hex(sha(all.toByteArray()))
    }

    @JvmStatic
    fun runOtSender(mesh: Mesh, peer: Int, count: Int): Result {
        val rng = Ot.secureOtRandom()
        val binding = netBinding(mesh, mesh.selfId, peer, "ot-ec")
        val setup = Ot.malBaseOtSenderSetup(rng, binding)
        val sm = LinkedHashMap<String, Any?>()
        sm["S"] = NetCodec.ptJ(setup.S)
        sm["U"] = NetCodec.ptJ(setup.proof.U)
        sm["z"] = NetWire.hx(setup.proof.z)
        mesh.send(peer, "ot-S", sm)
        val rRaw = mesh.recv(peer, "ot-R")
        val rPts: Array<Point> = parsing(mesh, peer, "ot-R") {
            require(rRaw is List<*> && rRaw.size == count) { "bad R array" }
            Array(count) { i -> NetCodec.jPt(rRaw[i]) }
        }
        val pads: Array<Array<ByteArray>> = try {
            Ot.malBaseOtSenderDerive(setup.y, setup.T, rPts, setup.S, binding)
        } catch (e: RuntimeException) {
            val ne = NetAbort("malformed", peer, mesh.selfId, e.message.toString())
            mesh.fail(ne, null)
            throw ne
        }
        // demo-only verification: the receiver reveals choices + pad hashes
        val v = mesh.recv(peer, "ot-verify")
        val ok = parsing(mesh, peer, "ot-verify") {
            val o = v as? Map<*, *>
            val choices = o?.get("choices")
            val hashes = o?.get("padHashes")
            require(choices is List<*> && hashes is List<*> && choices.size == count && hashes.size == count) { "bad verify message" }
            var good = true
            for (i in 0 until count) {
                val c = bit(choices[i])
                if (c < 0 || hex(sha(pads[i][c])) != hashes[i]) {
                    good = false
                    break
                }
            }
            good
        }
        val done = LinkedHashMap<String, Any?>()
        done["matched"] = ok
        mesh.send(peer, "ot-done", done)
        mesh.finish()
        val flat = Array(count * 2) { j -> pads[j / 2][j % 2] }
        return Result("sender", count, ok, digest(flat))
    }

    @JvmStatic
    fun runOtReceiver(mesh: Mesh, peer: Int, count: Int): Result {
        val rng = Ot.secureOtRandom()
        val cb = rng.bytes(count)
        val choices = IntArray(count) { i -> cb[i].toInt() and 1 }
        val sRaw = mesh.recv(peer, "ot-S")
        var sPt: Point? = null
        val proof: SchnorrProof = parsing(mesh, peer, "ot-S") {
            require(sRaw is Map<*, *>) { "bad S message" }
            val pr = SchnorrProof(NetCodec.jPt(sRaw["U"]), NetCodec.hexBig(sRaw["z"]))
            sPt = NetCodec.jPt(sRaw["S"])
            pr
        }
        val res: Ot.ReceiverResponse = try {
            Ot.malBaseOtReceiverRespond(sPt!!, proof, choices, rng, netBinding(mesh, peer, mesh.selfId, "ot-ec"))
        } catch (e: RuntimeException) {
            val ne = NetAbort(if (e is BaseOtAbort) "commitment" else "malformed", peer, mesh.selfId, e.message.toString())
            mesh.fail(ne, null)
            throw ne
        }
        mesh.send(peer, "ot-R", res.R.map { NetCodec.ptJ(it) })
        val vm = LinkedHashMap<String, Any?>()
        val cs = ArrayList<Any?>()
        val hs = ArrayList<Any?>()
        for (i in 0 until count) {
            cs.add(choices[i])
            hs.add(hex(sha(res.recvPads[i])))
        }
        vm["choices"] = cs
        vm["padHashes"] = hs
        mesh.send(peer, "ot-verify", vm)
        val d = mesh.recv(peer, "ot-done")
        val matched = d is Map<*, *> && d["matched"] == true
        mesh.finish()
        return Result("receiver", count, matched, digest(res.recvPads))
    }
}
