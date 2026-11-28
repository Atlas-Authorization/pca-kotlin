package net.atlasauth.pca.signals

import net.atlasauth.pca.sdjwt.Sdjwt
import net.atlasauth.pca.verifier.Json
import org.junit.Assert.assertEquals
import org.junit.Test

/** A clock beyond the range of a Date (+-8.64e15 ms) is refused, as is a non-finite one: a JOSE library would read it as no clock at all. */
class UnrepresentableTimeTest {
    @Test fun aSignalReceiverRefusesAnUnrepresentableNowSec() {
        for (nowSec in listOf("8640000000001", "-8640000000001", "1e300")) {
            val opts = linkedMapOf<String, Any?>(
                "issuer" to "https://tx.example", "audience" to "rx", "replayStore" to Signals.createInMemorySetReplayStore(null),
                "state" to Signals.createRevocationState(), "maxAgeSec" to Json.Num("600"), "nowSec" to Json.Num(nowSec),
            )
            val r = Signals.receiveSET("e30.e30.eA", null, opts)
            assertEquals(nowSec, false, r.ok)
            assertEquals(nowSec, "verify_failed", r.code)
            assertEquals(nowSec, "nowSec is not a representable time", r.reason)
        }
    }

    @Test fun aSelectiveDisclosureVerifierRefusesAnUnrepresentableNow() {
        for (now in listOf("8640000000000001", "-8640000000000001", "1e300")) {
            val r = Sdjwt.verifyPcaSdJwt("x", linkedMapOf<String, Any?>("now" to Json.Num(now)))
            assertEquals(now, false, r["ok"])
            assertEquals(now, "now is not a representable time", r["reason"])
        }
    }
}
