package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/** The replay clock is the corpus header's clockMs; a header without it (an older corpus) gives the fallback. */
class BaseOracleClockTest {
    @Test fun headerClockIsRead() {
        assertEquals(1_700_000_000_000.0, BaseOracle.clockOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"clockMs\":1700000000000,\"cases\":["), 0.0)
    }

    @Test fun missingHeaderClockFallsBack() {
        assertEquals(BaseOracle.FALLBACK_CLOCK_MS, BaseOracle.clockOfHeader("{\"about\":\"a\",\"generator\":\"g.mts\",\"count\":3,\"cases\":["), 0.0)
        assertEquals(BaseOracle.FALLBACK_CLOCK_MS, BaseOracle.clockOfHeader(null), 0.0)
    }
}
