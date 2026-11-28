package net.atlasauth.pca.mpc

import java.security.MessageDigest
import net.atlasauth.pca.mpc.Ec.Point
import net.atlasauth.pca.mpc.Ot.BaseOtFn
import net.atlasauth.pca.mpc.Ot.BaseOtTamper
import net.atlasauth.pca.mpc.Ot.OtRandom

/**
 * Hybrid base OT: the elliptic-curve random OT and the ML-KEM random OT run side by side and BOTH secrets are folded into every transfer
 * key, so the transfer is secure if either the classical or the post-quantum assumption holds. The keys encrypt the messages and a
 * per-message commitment catches an inconsistent sender.
 */
object HybridOt {
    private val TAG_HYBRID_SID = "atlas-pca-mpc/hybrid-ot-sid".toByteArray(Charsets.UTF_8)
    private val TAG_HYBRID_KEY = "atlas-pca-mpc/hybrid-ot-transfer-key".toByteArray(Charsets.UTF_8)
    private val TAG_HYBRID_COMMIT = "atlas-pca-mpc/hybrid-ot-msg-commit".toByteArray(Charsets.UTF_8)

    private fun sha256(vararg chunks: ByteArray): ByteArray {
        val h = MessageDigest.getInstance("SHA-256")
        for (c in chunks) h.update(c)
        return h.digest()
    }

    private fun xor(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "hybrid-ot: XOR length mismatch" }
        return ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }
    }

    /** A hybrid base OT aborted: the sender's ciphertext is inconsistent with its commitment. */
    class HybridOtAbort(message: String) : RuntimeException(message)

    @JvmStatic fun hybridSessionId(kemSid: ByteArray, ecS: Point): ByteArray = sha256(TAG_HYBRID_SID, kemSid, Ec.encodePoint(ecS))

    @JvmStatic fun hybridTransferKey(sid: ByteArray, index: Int, slot: Int, ssEc: ByteArray, ssKem: ByteArray, len: Int): ByteArray {
        require(!(len < 0 || len > 1 shl 20)) { "hybridTransferKey: length must be an integer in [0, 1 MiB]" }
        val out = ByteArray(len)
        var produced = 0
        var ctr = 0L
        while (produced < len) {
            val block = sha256(TAG_HYBRID_KEY, sid, Ot.u32(index.toLong()), byteArrayOf((slot and 1).toByte()), Ot.u32(ctr), ssEc, ssKem)
            var k = 0
            while (k < block.size && produced < len) {
                out[produced++] = block[k]
                k++
            }
            ctr++
        }
        return out
    }

    private fun hybridCommit(sid: ByteArray, index: Int, slot: Int, msg: ByteArray, key: ByteArray): ByteArray =
        sha256(TAG_HYBRID_COMMIT, sid, Ot.u32(index.toLong()), byteArrayOf((slot and 1).toByte()), msg, key)

    class HybridSenderMessage(val encrypted: Array<Array<ByteArray>>, val commitments: Array<Array<ByteArray>>)

    @JvmStatic fun hybridSenderEncrypt(sid: ByteArray, messages: Array<Array<ByteArray>>, ecSecrets: Array<Array<ByteArray>>, kemSecrets: Array<Array<ByteArray>>): HybridSenderMessage {
        require(!(messages.size != ecSecrets.size || messages.size != kemSecrets.size)) { "hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch" }
        val encrypted = ArrayList<Array<ByteArray>>()
        val commitments = ArrayList<Array<ByteArray>>()
        for (i in messages.indices) {
            val m0 = messages[i][0]
            val m1 = messages[i][1]
            require(m0.size == m1.size) { "hybridSenderEncrypt (index $i): the two messages must be equal length" }
            val k0 = hybridTransferKey(sid, i, 0, ecSecrets[i][0], kemSecrets[i][0], m0.size)
            val k1 = hybridTransferKey(sid, i, 1, ecSecrets[i][1], kemSecrets[i][1], m1.size)
            encrypted.add(arrayOf(xor(m0, k0), xor(m1, k1)))
            commitments.add(arrayOf(hybridCommit(sid, i, 0, m0, k0), hybridCommit(sid, i, 1, m1, k1)))
        }
        return HybridSenderMessage(encrypted.toTypedArray(), commitments.toTypedArray())
    }

    @JvmStatic fun hybridReceiverRecover(sid: ByteArray, choices: IntArray, sender: HybridSenderMessage, ecRecv: Array<ByteArray>, kemRecv: Array<ByteArray>): Array<ByteArray> {
        val n = choices.size
        require(!(sender.encrypted.size != n || sender.commitments.size != n || ecRecv.size != n || kemRecv.size != n)) { "hybridReceiverRecover: length mismatch" }
        return Array(n) { i ->
            val c = choices[i] and 1
            val e = sender.encrypted[i][c]
            val key = hybridTransferKey(sid, i, c, ecRecv[i], kemRecv[i], e.size)
            val m = xor(e, key)
            if (!MessageDigest.isEqual(hybridCommit(sid, i, c, m, key), sender.commitments[i][c])) {
                throw HybridOtAbort("hybrid base OT (index $i): sender ciphertext inconsistent with its commitment; aborting")
            }
            m
        }
    }

    /** TEST-ONLY injection points (null = honest). */
    class HybridBaseOtTamper {
        @JvmField var ec: BaseOtTamper? = null
        @JvmField var kem: KemOt.KemMalTamper? = null
        @JvmField var tamperEncrypted: ((Array<Array<ByteArray>>) -> Unit)? = null
    }

    class HybridBaseOtTranscript(val sid: ByteArray, val ecS: Point, val kemSid: ByteArray, val encrypted: Array<Array<ByteArray>>, val commitments: Array<Array<ByteArray>>)

    class HybridBaseOtResult(val received: Array<ByteArray>, val transcript: HybridBaseOtTranscript)

    @JvmStatic fun hybridBaseOT(messages: Array<Array<ByteArray>>, choices: IntArray, rng0: OtRandom?, tamper: HybridBaseOtTamper?): HybridBaseOtResult {
        val rng = rng0 ?: Ot.secureOtRandom()
        require(messages.size == choices.size) { "hybridBaseOT: messages/choices length mismatch" }
        val ec = Ot.malBaseRandomOT(choices, rng, tamper?.ec, null)
        val kem = KemOt.kemBaseOtMalRandom(choices, rng, tamper?.kem)
        val sid = hybridSessionId(kem.sid, ec.S)
        val sender = hybridSenderEncrypt(sid, messages, ec.senderPads, kem.senderSecrets)
        tamper?.tamperEncrypted?.invoke(sender.encrypted)
        val received = hybridReceiverRecover(sid, choices, sender, ec.recvPads, kem.recvSecrets)
        return HybridBaseOtResult(received, HybridBaseOtTranscript(sid, ec.S, kem.sid, sender.encrypted, sender.commitments))
    }

    /** The hybrid base OT as a pluggable base OT for [Ot.OtChannel]. */
    @JvmStatic fun withHybridBaseOt(): BaseOtFn = BaseOtFn { m, c, r -> hybridBaseOT(m, c, r, null).received }
}
