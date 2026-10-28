package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The K4 corpus (`k4-vectors.json`): escalation pricing, network-token binding, ERC-7715 check. A missing file fails. */
@Suppress("UNCHECKED_CAST")
class K4VectorsTest {
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test
    fun escalation() {
        val esc = m(ParityVectors.load("k4-vectors.json")["escalation"])
        assertTrue(l(esc["config_cases"]).size >= 6)
        for (x in l(esc["config_cases"])) assertEquals(m(x)["name"].toString(), m(x)["expect"], K4.pricingConfigError(m(x)["config"]))
        assertTrue(l(esc["decisions"]).size >= 14)
        for (x in l(esc["decisions"])) {
            val g = K4.decide(esc["config"], m(x)["calibration"], m(x)["risk"])
            assertEquals(m(x)["risk"].toString(), m(m(x)["expect"])["ask"], g.ask)
            assertEquals(m(x)["risk"].toString(), m(m(x)["expect"])["reason"], g.reason)
        }
        for (x in l(esc["calibration"])) {
            val c = m(x)
            val g = K4.updateCalibration(c["config"], IntentJs.lng(m(c["start"])["multiplierPpm"]), l(m(c["start"])["seen"]).map { it as String }, l(c["answers"]), m(c["risks"]))
            assertEquals(c["name"].toString(), IntentJs.lng(m(c["expect"])["multiplierPpm"]), g.multiplierPpm)
            assertEquals(c["name"].toString(), m(c["expect"])["seen"], g.seen)
        }
    }

    @Test
    fun binding() {
        val cs = l(m(m(ParityVectors.load("k4-vectors.json"))["network_binding"])["cases"])
        assertTrue(cs.size >= 15)
        for (x in cs) {
            val c = m(x)
            val e = m(c["expect_in"])
            assertEquals(c["name"].toString(), c["expect"], K4.verifyBinding(c["binding"], e["grant"], e["holder"] as String, e["issuer_nonce"] as String, e["provider"] as String?))
        }
    }

    @Test
    fun erc7715() {
        val cs = l(m(ParityVectors.load("k4-vectors.json")["erc7715"])["cases"])
        assertTrue(cs.size >= 24)
        for (x in cs) {
            val c = m(x)
            val o = m(c["opts"])
            val ctx = if (o.containsKey("contexts")) m(o["contexts"]) else emptyMap()
            assertEquals(c["name"].toString(), c["expect"], K4.verifyGranted(c["envelope"], c["sent"], c["got"], l(o["allowedManagers"]).map { it as String }) { k -> ctx[k] as String? })
        }
    }
}
