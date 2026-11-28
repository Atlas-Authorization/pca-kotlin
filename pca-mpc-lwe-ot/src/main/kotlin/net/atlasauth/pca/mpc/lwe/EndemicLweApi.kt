package net.atlasauth.pca.mpc.lwe

import java.util.function.Consumer
import net.atlasauth.pca.mpc.Ot
import net.atlasauth.pca.mpc.Ot.BaseOtFn
import net.atlasauth.pca.mpc.Ot.OtRandom

/*
 * The endemic Module-LWE base OT under the names of the reference's `endemic-ot` module. Every lattice operation (K-PKE key generation,
 * encryption and decryption, ring addition and subtraction, hash-to-ring) is the audited pqc_kyber reference reached through liblweot by the
 * Java adapter ([Lattice], [EndemicOt]); nothing here implements a primitive, these are the same functions under the reference's names.
 * liblweot must be loadable (`-Dpca.lweot.lib`, see [EndemicLweOt.available]) for everything but [endemicSessionId].
 */

/** The abort a cheating sender or a malformed message raises. */
typealias EndemicLweOtAbort = EndemicOt.EndemicAbort

const val PK_BYTES: Int = Lattice.PK_BYTES
const val SK_BYTES: Int = Lattice.SK_BYTES
const val CT_BYTES: Int = Lattice.CT_BYTES
const val TVEC_BYTES: Int = Lattice.TVEC_BYTES
const val SYM_BYTES: Int = Lattice.SYM_BYTES

/** The length of a random-OT pad. */
const val ENDEMIC_SECRET_BYTES: Int = EndemicOt.ENDEMIC_SECRET_BYTES

/** K-PKE key generation from a 32-byte seed (the pre-standard derivation the endemic OT uses). */
fun kpkeKeygen(seed: ByteArray): Lattice.KeyPair = Lattice.keygen(seed)

/** K-PKE key generation under FIPS 203 (with the `k` domain separation). */
fun kpkeKeygenFips203(seed: ByteArray): Lattice.KeyPair = Lattice.keygenFips203(seed)

fun kpkeEnc(publicKey: ByteArray, message: ByteArray, coins: ByteArray): ByteArray = Lattice.enc(publicKey, message, coins)

fun kpkeDec(secretKey: ByteArray, ciphertext: ByteArray): ByteArray = Lattice.dec(secretKey, ciphertext)

fun ringAdd(a: ByteArray, b: ByteArray): ByteArray = Lattice.ringAdd(a, b)

fun ringSub(a: ByteArray, b: ByteArray): ByteArray = Lattice.ringSub(a, b)

fun hashToRing(input: ByteArray): ByteArray = Lattice.hashToRing(input)

/** The session id of a receiver nonce. */
fun endemicSessionId(rn: ByteArray): ByteArray = EndemicOt.sessionId(rn)

/** The pad of slot [slot] of transfer [index] (`len` bytes) derived from a decrypted [payload]. */
fun endemicLwePad(sid: ByteArray, index: Int, slot: Int, payload: ByteArray, len: Int): ByteArray = EndemicOt.pad(sid, index, slot, payload, len)

/** The receiver's first round: a message for the sender and the state that recovers the chosen pads. */
@JvmOverloads
fun endemicLweReceive(choices: IntArray, rng: OtRandom = Ot.secureOtRandom()): EndemicOt.Receive = EndemicOt.receive(choices, rng)

/** The sender's round of the random OT: both pads per transfer stay with the sender. [tamper] is test-only. */
@JvmOverloads
fun endemicLweSendRandom(message: EndemicOt.ReceiverMessage, rng: OtRandom = Ot.secureOtRandom(), tamper: Consumer<Array<Array<ByteArray>>>? = null): EndemicOt.SenderMessage =
    EndemicOt.sendRandom(message, rng, tamper)

/** The receiver's recovery of the pad of its choice; a malformed ciphertext aborts with [EndemicLweOtAbort]. */
fun endemicLweRecoverRandom(state: EndemicOt.ReceiverState, sender: EndemicOt.SenderMessage): Array<ByteArray> = EndemicOt.recoverRandom(state, sender)

/** What the in-process random OT produced. */
class EndemicLweRandomResult(
    /** The sender's pads `[k_0, k_1]` per transfer (the sender learns both). */
    val senderPads: Array<Array<ByteArray>>,
    /** The receiver's chosen pad per transfer (the honest receiver learns one). */
    val recvPads: Array<ByteArray>,
    val sid: ByteArray,
    val message: EndemicOt.ReceiverMessage,
    val ciphertexts: Array<Array<ByteArray>>,
)

/** The random endemic base OT with both parties in-process. */
@JvmOverloads
fun endemicLweBaseOtRandom(choices: IntArray, rng: OtRandom = Ot.secureOtRandom(), tamper: Consumer<Array<Array<ByteArray>>>? = null): EndemicLweRandomResult {
    val rv = EndemicOt.receive(choices, rng)
    val sm = EndemicOt.sendRandom(rv.message(), rng, tamper)
    return EndemicLweRandomResult(sm.senderPads(), EndemicOt.recoverRandom(rv.state(), sm), rv.state().sid(), rv.message(), sm.ciphertexts())
}

/** The chosen-message endemic base OT in-process, with the transcript; a cheating sender aborts with [EndemicLweOtAbort]. [tamperEncrypted] is test-only. */
@JvmOverloads
fun endemicLweBaseOT(messages: Array<Array<ByteArray>>, choices: IntArray, rng: OtRandom = Ot.secureOtRandom(), tamperEncrypted: Consumer<Array<Array<ByteArray>>>? = null): EndemicOt.Result =
    EndemicOt.baseOT(messages, choices, rng, tamperEncrypted)

/** The chosen-message endemic base OT as the OT extension's base-OT seam. */
val endemicLweBaseOtFn: BaseOtFn get() = EndemicOt.withEndemicBaseOt()

/** The base-OT seam of the OT extension: `OtChannel(rng, withEndemicLweBaseOt(), binding)`. */
fun withEndemicLweBaseOt(): BaseOtFn = EndemicOt.withEndemicBaseOt()
