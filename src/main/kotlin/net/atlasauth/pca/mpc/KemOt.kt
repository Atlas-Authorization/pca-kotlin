package net.atlasauth.pca.mpc

import net.atlasauth.pca.verifier.Json

import java.security.MessageDigest
import net.atlasauth.pca.mpc.Ot.BaseOtFn
import net.atlasauth.pca.mpc.Ot.OtRandom
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters

/**
 * Post-quantum base OT from ML-KEM-768 (FIPS 203): the receiver publishes a public-key pair with a known secret key for only its chosen
 * slot, the sender encapsulates to both and pads each message with the shared secret. Variants: the semi-honest transfer ([kemBaseOT]),
 * the commit-then-open malicious-secure transfer with a session id ([kemBaseOtMal]), and the random-OT form that outputs fixed-width
 * secrets for the hybrid base OT ([kemBaseOtMalRandom]).
 */
object KemOt {
    private fun utf8(s: String): ByteArray = Json.utf8(s)

    private val TAG_KEMOT = utf8("atlas-pca-mpc/kem-ot-pad")
    private val TAG_KEMOT_COMMIT = utf8("atlas-pca-mpc/kem-ot-commit")
    private val TAG_KEMOT_SID = utf8("atlas-pca-mpc/kem-ot-sid")
    private val TAG_KEMOT_MALPAD = utf8("atlas-pca-mpc/kem-ot-mal-pad")
    private val TAG_KEMOT_MALSECRET = utf8("atlas-pca-mpc/kem-ot-mal-secret")
    private const val NONCE_BYTES = 32
    const val KEM_OT_SECRET_BYTES = 32

    private fun sha256(vararg chunks: ByteArray): ByteArray {
        val h = MessageDigest.getInstance("SHA-256")
        for (c in chunks) h.update(c)
        return h.digest()
    }

    private fun u32(x: Long): ByteArray = Ot.u32(x)

    private fun xor(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "kem-ot: XOR length mismatch" }
        return ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }
    }

    private fun ctEqual(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    private fun expand(tag: ByteArray, prefix: List<ByteArray>, index: Long, slot: Int, sharedSecret: ByteArray, len: Int): ByteArray {
        val out = ByteArray(len)
        var produced = 0
        var ctr = 0L
        while (produced < len) {
            val parts = ArrayList<ByteArray>()
            parts.add(tag)
            parts.addAll(prefix)
            parts.add(u32(index))
            parts.add(byteArrayOf((slot and 1).toByte()))
            parts.add(u32(ctr))
            parts.add(sharedSecret)
            val block = sha256(*parts.toTypedArray())
            var k = 0
            while (k < block.size && produced < len) {
                out[produced++] = block[k]
                k++
            }
            ctr++
        }
        return out
    }

    /** Pad of [len] bytes (at most 1 MiB) from the shared secret: SHA-256 in counter mode. */
    @JvmStatic fun kemOtPad(index: Int, slot: Int, sharedSecret: ByteArray, len: Int): ByteArray {
        require(!(len < 0 || len > 1 shl 20)) { "kemOtPad: length must be an integer in [0, 1 MiB]" }
        return expand(TAG_KEMOT, emptyList(), index.toLong(), slot, sharedSecret, len)
    }

    /** Receiver state of the semi-honest transfer. */
    class KemOtReceiverState(val choices: IntArray, val secretKeys: Array<MLKEMPrivateKeyParameters>)

    class KemOtReceiverMessage(val publicKeys: Array<Array<ByteArray>>)

    class KemOtSenderMessage(val ciphertexts: Array<Array<ByteArray>>, val encrypted: Array<Array<ByteArray>>)

    class KemBaseOtTranscript(val publicKeys: Array<Array<ByteArray>>, val ciphertexts: Array<Array<ByteArray>>, val encrypted: Array<Array<ByteArray>>)

    class KemBaseOtResult(val received: Array<ByteArray>, val transcript: KemBaseOtTranscript)

    class ReceiverStep(val message: KemOtReceiverMessage, val state: KemOtReceiverState)

    /** Draws the chosen and the other key pair for each choice (chosen first), returning the pairs in slot order. */
    private class KeyPairs(val publicKeys: Array<Array<ByteArray>>, val secretKeys: Array<MLKEMPrivateKeyParameters>, val retained: IntArray)

    private fun drawKeys(choices: IntArray, rng: OtRandom, onEach: ((Int, ByteArray, ByteArray) -> Unit)?): KeyPairs {
        val sks = ArrayList<MLKEMPrivateKeyParameters>()
        val pks = ArrayList<Array<ByteArray>>()
        val retained = IntArray(choices.size)
        for (i in choices.indices) {
            val c = choices[i] and 1
            val chosen = MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES))
            val other = MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES))
            val p0 = if (c == 0) chosen.publicKey else other.publicKey
            val p1 = if (c == 0) other.publicKey else chosen.publicKey
            pks.add(arrayOf(p0, p1))
            sks.add(chosen.secretKey)
            retained[i] = c
            onEach?.invoke(i, p0, p1)
        }
        return KeyPairs(pks.toTypedArray(), sks.toTypedArray(), retained)
    }

    @JvmStatic fun kemBaseOtReceive(choices: IntArray, rng0: OtRandom?): ReceiverStep {
        val rng = rng0 ?: Ot.secureOtRandom()
        val k = drawKeys(choices, rng, null)
        return ReceiverStep(KemOtReceiverMessage(k.publicKeys), KemOtReceiverState(k.retained, k.secretKeys))
    }

    @JvmStatic fun kemBaseOtSend(messages: Array<Array<ByteArray>>, receiverMessage: KemOtReceiverMessage, rng0: OtRandom?): KemOtSenderMessage {
        val rng = rng0 ?: Ot.secureOtRandom()
        val publicKeys = receiverMessage.publicKeys
        require(messages.size == publicKeys.size) { "kemBaseOtSend: messages/publicKeys length mismatch" }
        val cts = ArrayList<Array<ByteArray>>()
        val encrypted = ArrayList<Array<ByteArray>>()
        for (i in messages.indices) {
            val m0 = messages[i][0]
            val m1 = messages[i][1]
            require(m0.size == m1.size) { "kemBaseOtSend (index $i): the two messages must be equal length" }
            val e0 = MlKem768.encapsulate(publicKeys[i][0], rng.bytes(MlKem768.MSG_BYTES))
            val e1 = MlKem768.encapsulate(publicKeys[i][1], rng.bytes(MlKem768.MSG_BYTES))
            cts.add(arrayOf(e0.cipherText, e1.cipherText))
            encrypted.add(arrayOf(xor(m0, kemOtPad(i, 0, e0.sharedSecret, m0.size)), xor(m1, kemOtPad(i, 1, e1.sharedSecret, m1.size))))
        }
        return KemOtSenderMessage(cts.toTypedArray(), encrypted.toTypedArray())
    }

    @JvmStatic fun kemBaseOtOpen(state: KemOtReceiverState, senderMessage: KemOtSenderMessage): Array<ByteArray> {
        val n = state.choices.size
        require(!(senderMessage.ciphertexts.size != n || senderMessage.encrypted.size != n)) { "kemBaseOtOpen: transcript/state length mismatch" }
        return Array(n) { i ->
            val c = state.choices[i] and 1
            val ss = MlKem768.decapsulate(senderMessage.ciphertexts[i][c], state.secretKeys[i])
            val e = senderMessage.encrypted[i][c]
            xor(e, kemOtPad(i, c, ss, e.size))
        }
    }

    @JvmStatic fun kemBaseOT(messages: Array<Array<ByteArray>>, choices: IntArray, rng0: OtRandom?): KemBaseOtResult {
        val rng = rng0 ?: Ot.secureOtRandom()
        require(messages.size == choices.size) { "kemBaseOT: messages/choices length mismatch" }
        val r = kemBaseOtReceive(choices, rng)
        val s = kemBaseOtSend(messages, r.message, rng)
        val received = kemBaseOtOpen(r.state, s)
        return KemBaseOtResult(received, KemBaseOtTranscript(r.message.publicKeys, s.ciphertexts, s.encrypted))
    }

    /** The semi-honest KEM OT as a pluggable base OT for [Ot.OtChannel]. */
    @JvmStatic fun withKemBaseOt(): BaseOtFn = BaseOtFn { m, c, r -> kemBaseOT(m, c, r).received }

    // ---- malicious-secure (commit-then-open, session id) ----

    /** A KEM base OT aborted: the opened keys do not match the receiver's commitment. */
    class KemBaseOtAbort(message: String) : RuntimeException(message)

    private fun kemMalCommit(rn: ByteArray, index: Int, pk0: ByteArray, pk1: ByteArray): ByteArray = sha256(TAG_KEMOT_COMMIT, rn, u32(index.toLong()), pk0, pk1)

    private fun kemMalSid(rn: ByteArray, sn: ByteArray): ByteArray = sha256(TAG_KEMOT_SID, rn, sn)

    private fun kemOtMalPad(sid: ByteArray, com: ByteArray, index: Int, slot: Int, ss: ByteArray, len: Int): ByteArray =
        expand(TAG_KEMOT_MALPAD, listOf(sid, com), index.toLong(), slot, ss, len)

    private fun kemOtMalSecret(sid: ByteArray, com: ByteArray, index: Int, slot: Int, ss: ByteArray): ByteArray {
        val h = sha256(TAG_KEMOT_MALSECRET, sid, com, u32(index.toLong()), byteArrayOf((slot and 1).toByte()), ss)
        return h.copyOf(KEM_OT_SECRET_BYTES)
    }

    class KemMalCommitMessage(val rn: ByteArray, val commitments: Array<ByteArray>)

    class KemMalOpenMessage(val publicKeys: Array<Array<ByteArray>>)

    class KemMalSenderNonce(val sn: ByteArray)

    class KemMalSenderMessage(val ciphertexts: Array<Array<ByteArray>>, val encrypted: Array<Array<ByteArray>>)

    class KemMalReceiverState(val choices: IntArray, val secretKeys: Array<MLKEMPrivateKeyParameters>, val publicKeys: Array<Array<ByteArray>>, val rn: ByteArray)

    class KemMalTranscript(
        val rn: ByteArray,
        val commitments: Array<ByteArray>,
        val sn: ByteArray,
        val publicKeys: Array<Array<ByteArray>>,
        val ciphertexts: Array<Array<ByteArray>>,
        val encrypted: Array<Array<ByteArray>>,
    )

    class KemBaseOtMalResult(val received: Array<ByteArray>, val transcript: KemMalTranscript)

    /** TEST-ONLY injection points for a malicious sender or receiver (null = honest). */
    class KemMalTamper {
        @JvmField var tamperOpenedKeys: ((Array<Array<ByteArray>>) -> Unit)? = null
        @JvmField var tamperReceiverSid: ((ByteArray) -> ByteArray)? = null
    }

    class CommitStep(val message: KemMalCommitMessage, val state: KemMalReceiverState)

    @JvmStatic fun kemBaseOtMalCommit(choices: IntArray, rng0: OtRandom?): CommitStep {
        val rng = rng0 ?: Ot.secureOtRandom()
        val rn = rng.bytes(NONCE_BYTES)
        val commitments = ArrayList<ByteArray>()
        val k = drawKeys(choices, rng) { i, p0, p1 -> commitments.add(kemMalCommit(rn, i, p0, p1)) }
        return CommitStep(KemMalCommitMessage(rn, commitments.toTypedArray()), KemMalReceiverState(k.retained, k.secretKeys, k.publicKeys, rn))
    }

    @JvmStatic fun kemBaseOtMalSenderNonce(rng0: OtRandom?): KemMalSenderNonce {
        val rng = rng0 ?: Ot.secureOtRandom()
        return KemMalSenderNonce(rng.bytes(NONCE_BYTES))
    }

    /** The receiver's opening: a copy of its public-key pairs. */
    @JvmStatic fun kemBaseOtMalOpen(state: KemMalReceiverState): KemMalOpenMessage =
        KemMalOpenMessage(Array(state.publicKeys.size) { i -> arrayOf(state.publicKeys[i][0], state.publicKeys[i][1]) })

    @JvmStatic fun kemBaseOtMalSend(
        messages: Array<Array<ByteArray>>,
        commit: KemMalCommitMessage,
        senderNonce: KemMalSenderNonce,
        opening: KemMalOpenMessage,
        rng0: OtRandom?,
    ): KemMalSenderMessage {
        val rng = rng0 ?: Ot.secureOtRandom()
        val publicKeys = opening.publicKeys
        require(!(messages.size != publicKeys.size || commit.commitments.size != publicKeys.size)) { "kemBaseOtMalSend: messages/commitments/publicKeys length mismatch" }
        val sid = kemMalSid(commit.rn, senderNonce.sn)
        val cts = ArrayList<Array<ByteArray>>()
        val encrypted = ArrayList<Array<ByteArray>>()
        for (i in messages.indices) {
            val m0 = messages[i][0]
            val m1 = messages[i][1]
            require(m0.size == m1.size) { "kemBaseOtMalSend (index $i): the two messages must be equal length" }
            val com = kemMalCommit(commit.rn, i, publicKeys[i][0], publicKeys[i][1])
            if (!ctEqual(com, commit.commitments[i])) throw KemBaseOtAbort("kem base OT (index $i): opened public keys do not match the receiver's commitment; aborting")
            val e0 = MlKem768.encapsulate(publicKeys[i][0], rng.bytes(MlKem768.MSG_BYTES))
            val e1 = MlKem768.encapsulate(publicKeys[i][1], rng.bytes(MlKem768.MSG_BYTES))
            cts.add(arrayOf(e0.cipherText, e1.cipherText))
            encrypted.add(arrayOf(xor(m0, kemOtMalPad(sid, com, i, 0, e0.sharedSecret, m0.size)), xor(m1, kemOtMalPad(sid, com, i, 1, e1.sharedSecret, m1.size))))
        }
        return KemMalSenderMessage(cts.toTypedArray(), encrypted.toTypedArray())
    }

    @JvmStatic fun kemBaseOtMalRecover(state: KemMalReceiverState, senderNonce: KemMalSenderNonce, senderMessage: KemMalSenderMessage, tamper: KemMalTamper?): Array<ByteArray> {
        val n = state.choices.size
        require(!(senderMessage.ciphertexts.size != n || senderMessage.encrypted.size != n)) { "kemBaseOtMalRecover: transcript/state length mismatch" }
        var sid = kemMalSid(state.rn, senderNonce.sn)
        val ts = tamper?.tamperReceiverSid
        if (ts != null) sid = ts(sid)
        return Array(n) { i ->
            val c = state.choices[i] and 1
            val com = kemMalCommit(state.rn, i, state.publicKeys[i][0], state.publicKeys[i][1])
            val ss = MlKem768.decapsulate(senderMessage.ciphertexts[i][c], state.secretKeys[i])
            val e = senderMessage.encrypted[i][c]
            xor(e, kemOtMalPad(sid, com, i, c, ss, e.size))
        }
    }

    @JvmStatic fun kemBaseOtMal(messages: Array<Array<ByteArray>>, choices: IntArray, rng0: OtRandom?, tamper: KemMalTamper?): KemBaseOtMalResult {
        val rng = rng0 ?: Ot.secureOtRandom()
        require(messages.size == choices.size) { "kemBaseOtMal: messages/choices length mismatch" }
        val cs = kemBaseOtMalCommit(choices, rng)
        val nonce = kemBaseOtMalSenderNonce(rng)
        val opening = kemBaseOtMalOpen(cs.state)
        tamper?.tamperOpenedKeys?.invoke(opening.publicKeys)
        val sm = kemBaseOtMalSend(messages, cs.message, nonce, opening, rng)
        val received = kemBaseOtMalRecover(cs.state, nonce, sm, tamper)
        return KemBaseOtMalResult(received, KemMalTranscript(cs.message.rn, cs.message.commitments, nonce.sn, opening.publicKeys, sm.ciphertexts, sm.encrypted))
    }

    /** The malicious-secure KEM OT as a pluggable base OT for [Ot.OtChannel]. */
    @JvmStatic fun withKemBaseOtMal(): BaseOtFn = BaseOtFn { m, c, r -> kemBaseOtMal(m, c, r, null).received }

    // ---- random-OT form (fixed-width secrets, for the hybrid base OT) ----

    class KemMalRandomSenderMessage(val ciphertexts: Array<Array<ByteArray>>, val senderSecrets: Array<Array<ByteArray>>)

    class KemMalRandomTranscript(val rn: ByteArray, val commitments: Array<ByteArray>, val sn: ByteArray, val publicKeys: Array<Array<ByteArray>>, val ciphertexts: Array<Array<ByteArray>>)

    class KemBaseOtMalRandomResult(val senderSecrets: Array<Array<ByteArray>>, val recvSecrets: Array<ByteArray>, val sid: ByteArray, val transcript: KemMalRandomTranscript)

    @JvmStatic fun kemBaseOtMalRandomSend(commit: KemMalCommitMessage, senderNonce: KemMalSenderNonce, opening: KemMalOpenMessage, rng0: OtRandom?): KemMalRandomSenderMessage {
        val rng = rng0 ?: Ot.secureOtRandom()
        val publicKeys = opening.publicKeys
        require(commit.commitments.size == publicKeys.size) { "kemBaseOtMalRandomSend: commitments/publicKeys length mismatch" }
        val sid = kemMalSid(commit.rn, senderNonce.sn)
        val cts = ArrayList<Array<ByteArray>>()
        val secrets = ArrayList<Array<ByteArray>>()
        for (i in publicKeys.indices) {
            val com = kemMalCommit(commit.rn, i, publicKeys[i][0], publicKeys[i][1])
            if (!ctEqual(com, commit.commitments[i])) throw KemBaseOtAbort("kem base OT (index $i): opened public keys do not match the receiver's commitment; aborting")
            val e0 = MlKem768.encapsulate(publicKeys[i][0], rng.bytes(MlKem768.MSG_BYTES))
            val e1 = MlKem768.encapsulate(publicKeys[i][1], rng.bytes(MlKem768.MSG_BYTES))
            cts.add(arrayOf(e0.cipherText, e1.cipherText))
            secrets.add(arrayOf(kemOtMalSecret(sid, com, i, 0, e0.sharedSecret), kemOtMalSecret(sid, com, i, 1, e1.sharedSecret)))
        }
        return KemMalRandomSenderMessage(cts.toTypedArray(), secrets.toTypedArray())
    }

    @JvmStatic fun kemBaseOtMalRandomRecover(state: KemMalReceiverState, senderNonce: KemMalSenderNonce, senderMessage: KemMalRandomSenderMessage, tamper: KemMalTamper?): Array<ByteArray> {
        val n = state.choices.size
        require(senderMessage.ciphertexts.size == n) { "kemBaseOtMalRandomRecover: transcript/state length mismatch" }
        var sid = kemMalSid(state.rn, senderNonce.sn)
        val ts = tamper?.tamperReceiverSid
        if (ts != null) sid = ts(sid)
        return Array(n) { i ->
            val c = state.choices[i] and 1
            val com = kemMalCommit(state.rn, i, state.publicKeys[i][0], state.publicKeys[i][1])
            val ss = MlKem768.decapsulate(senderMessage.ciphertexts[i][c], state.secretKeys[i])
            kemOtMalSecret(sid, com, i, c, ss)
        }
    }

    @JvmStatic fun kemBaseOtMalRandom(choices: IntArray, rng0: OtRandom?, tamper: KemMalTamper?): KemBaseOtMalRandomResult {
        val rng = rng0 ?: Ot.secureOtRandom()
        val cs = kemBaseOtMalCommit(choices, rng)
        val nonce = kemBaseOtMalSenderNonce(rng)
        val opening = kemBaseOtMalOpen(cs.state)
        tamper?.tamperOpenedKeys?.invoke(opening.publicKeys)
        val sm = kemBaseOtMalRandomSend(cs.message, nonce, opening, rng)
        val recv = kemBaseOtMalRandomRecover(cs.state, nonce, sm, tamper)
        return KemBaseOtMalRandomResult(
            sm.senderSecrets, recv, kemMalSid(cs.message.rn, nonce.sn),
            KemMalRandomTranscript(cs.message.rn, cs.message.commitments, nonce.sn, opening.publicKeys, sm.ciphertexts),
        )
    }
}
