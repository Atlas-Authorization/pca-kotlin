package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The strict integer range by lexeme: every length class around 2^53-1 (16 digits), decided without parsing a long lexeme. */
class Kill15JsonSafeIntegerTest {
    private val range = "integer outside the safe range"

    @Test fun safeIntegersAreCanonical() {
        for (raw in listOf("0", "7", "999999999999999", "1000000000000000", "9007199254740990", "9007199254740991", "-9007199254740991", "-1000000000000000"))
            assertNull(raw, Json.numberError(raw))
    }

    @Test fun integersPastTwoToTheFiftyThreeAreRefusedAtEveryLength() {
        for (raw in listOf(
            "9007199254740992", "-9007199254740992", "9999999999999999", "9100000000000000", // 16 digits, above the bound
            "10000000000000000", "-10000000000000000", "12345678901234567", // 17 digits
            "99999999999999999999", "1" + "0".repeat(100_000),
        )) assertEquals(raw.take(40), range, Json.numberError(raw))
    }
}
