package net.atlasauth.pca.payments

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the payments pieces that sit on the core decision and the optimistic path. */
@Suppress("UNCHECKED_CAST")
class PaymentsCoreDiffTest {
    private val module = "ref-payments-java-extra"

    private fun m(o: Any?) = o as Map<String, Any?>

    private fun num(o: Any?): Double? = when (o) {
        is Json.Num -> o.raw.toDoubleOrNull()
        is Number -> o.toDouble()
        else -> null
    }

    @Test fun authorizeChargeCore() = OracleCases.each(module, "authorizeChargeCore") { a -> Payments.authorizeCharge(m(a[0]), m(a[1]), a[2]) }

    @Test fun openChargeBond() = OracleCases.each(module, "openChargeBond") { a ->
        val o = m(a[1])
        val op = ChargeBond.OpenOptions(o["bondRef"] as String, num(o["claimedR"]) ?: Double.NaN)
        if (o.containsKey("challengeWindowMs")) op.challengeWindowMs = num(o["challengeWindowMs"])
        if (o.containsKey("issuedAt")) op.issuedAt = num(o["issuedAt"])
        if (o.containsKey("serverNow")) op.serverNow = num(o["serverNow"])
        Payments.openChargeBond(m(a[0]), op, Keys.edFromSeed(Keys.unb64u(a[2] as String)))
    }
}
