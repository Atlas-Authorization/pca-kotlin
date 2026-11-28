package net.atlasauth.pca.wallet

/** The wallet's view of the effective grant (the learner's acceptance and the ceilings), consulted by the question channel. */
interface WalletView {
    /** p_k(c): the probability the principal's intent admits the cell. */
    fun p(verb: String, idx: IntArray): Double

    fun vetoed(verb: String, idx: IntArray): Boolean

    /** Outside every ceiling the principal cannot widen: never a question. */
    fun outsideCeiling(verb: String, idx: IntArray): Boolean

    /** Cells currently in the effective grant (for near-boundary canaries): maps {verb, idx}. */
    fun confirmed(): List<Map<String, Any?>>
}
