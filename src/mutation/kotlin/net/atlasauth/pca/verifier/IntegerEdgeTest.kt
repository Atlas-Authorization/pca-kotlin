package net.atlasauth.pca.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IntegerEdgeTest {
    @Test fun longMinValueIsNotASafeInteger() {
        // Math.abs(Long.MIN_VALUE) is negative, so an abs()-based range check accepted it.
        assertFalse(Json.isSafeInt(Long.MIN_VALUE))
        assertFalse(Json.isSafeInt(Long.MAX_VALUE))
        assertFalse(Json.isSafeInt(-9007199254740992L))
        assertFalse(Json.isSafeInt(9007199254740992L))
        assertTrue(Json.isSafeInt(-9007199254740991L))
        assertTrue(Json.isSafeInt(9007199254740991L))
        assertFalse(Json.isStrictNumber(Long.MIN_VALUE))
    }
}
