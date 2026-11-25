package net.atlasauth.pca.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/** The Beta posterior upper bound for integer parameters is the exact Clopper-Pearson inversion (k = a - 1 successes in n = a + b - 1 trials). */
class WalletBetaUpperExactTest {
    @Test fun itIsTheExactInversion() {
        for ((a, b) in listOf(Pair(1.0, 1.0), Pair(2.0, 5.0), Pair(7.0, 3.0), Pair(30.0, 40.0))) {
            assertEquals("$a $b", WalletStats.clopperPearsonUpper(a - 1, a + b - 1, 0.01), WalletStats.betaUpperExact(0.01, a, b), 0.0)
        }
    }

    @Test fun nonIntegerOrNonPositiveParametersAreRefused() {
        for ((a, b) in listOf(Pair(1.5, 2.0), Pair(2.0, 0.5), Pair(0.0, 2.0), Pair(2.0, 0.0), Pair(Double.NaN, 2.0), Pair(2.0, Double.POSITIVE_INFINITY))) {
            try {
                WalletStats.betaUpperExact(0.01, a, b)
                fail("a=$a b=$b must be refused")
            } catch (e: IllegalArgumentException) {
                assertEquals("betaUpperExact: a and b must be positive integers", e.message)
            }
        }
    }
}
