package net.atlasauth.pca.mpc.lwe

import net.atlasauth.pca.mpc.Ot
import net.atlasauth.pca.mpc.Ot.BaseOtFn
import net.atlasauth.pca.mpc.Ot.OtRandom

/**
 * Kotlin face of the post-quantum endemic base OT (Masny-Rindal over Module-LWE, Kyber-768 K-PKE). Every lattice operation is the audited pqc_kyber
 * reference reached through liblweot (JNA, `-Dpca.lweot.lib`) by the Java adapter; this object only reshapes arguments. The Java classes
 * ([EndemicOt], [Lattice]) stay reachable for the round-level API (receive, sendRandom, recoverRandom).
 */
object EndemicLweOt {
    /** True when liblweot can be loaded. */
    fun available(): Boolean = Lattice.available()

    /** The chosen-message base OT in-process: returns the message each choice selects; a cheating sender aborts with [EndemicOt.EndemicAbort]. */
    fun baseOt(messages: List<Pair<ByteArray, ByteArray>>, choices: IntArray, rng: OtRandom = Ot.secureOtRandom()): List<ByteArray> {
        val m = Array(messages.size) { arrayOf(messages[it].first, messages[it].second) }
        return EndemicOt.baseOT(m, choices, rng, null).received().toList()
    }

    /** The base-OT seam of the OT extension: `OtChannel(rng, EndemicLweOt.baseOtFn(), binding)`. */
    fun baseOtFn(): BaseOtFn = EndemicOt.withEndemicBaseOt()
}
