package net.atlasauth.pca.mpc

import java.math.BigInteger

/** A source of the SPDZ offline phase: the MAC key, authenticated triples and authenticated input sharings. */
interface OfflineProvider {
    fun n(): Int
    fun macContext(): Spdz.MacContext
    fun genAuthTriple(): Spdz.AuthTriple

    /** Authenticated sharing of [value] contributed by party [owner]. */
    fun authInput(value: BigInteger, owner: Int): Spdz.AuthSV
}
