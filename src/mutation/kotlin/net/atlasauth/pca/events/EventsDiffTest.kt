package net.atlasauth.pca.events

import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the TypeScript-reference vectors of the step-up events and signed webhooks package. */
@Suppress("UNCHECKED_CAST")
class EventsDiffTest {
    private val m = "ref-events"

    private fun mm(o: Any?) = o as Map<String, Any?>?

    /** A secret: a JSON string, {"$bytes": b64u} for a byte secret, any other value as is. */
    private fun secret(o: Any?): Any? = ((o as? Map<*, *>)?.get("\$bytes") as? String)?.let { Keys.unb64u(it) } ?: o

    @Test fun buildStepUpEvent() = OracleCases.each(m, "buildStepUpEvent") { Events.buildStepUpEvent(it[0], it[1]) }
    @Test fun serializeEvent() = OracleCases.each(m, "serializeEvent") { Events.serializeEvent(it[0]) }
    @Test fun parseEvent() = OracleCases.each(m, "parseEvent") { Events.parseEvent(it[0] as? String ?: throw IllegalArgumentException("not a string")) }
    @Test fun signWebhook() = OracleCases.each(m, "signWebhook") { Events.signWebhook(secret(it[0]), it[1] as String, mm(it[2])) }
    /** The reference ran under a frozen clock: a verification that names no `now` is replayed at that clock (in seconds). */
    private fun frozen(o: Map<String, Any?>?): Map<String, Any?>? =
        if (o != null && o.containsKey("now")) o else LinkedHashMap(o ?: emptyMap()).also { it["now"] = Json.Num(java.math.BigDecimal(net.atlasauth.pca.verifier.BaseOracle.clockMs("$m.json.gz") / 1000).toPlainString()) }

    @Test fun verifyWebhook() = OracleCases.each(m, "verifyWebhook") { Events.verifyWebhook(secret(it[0]), it[1] as String, it[2], frozen(mm(it[3]))) }
    @Test fun webhookHeaders() = OracleCases.each(m, "webhookHeaders") { Events.webhookHeaders(secret(it[0]), it[1] as String, mm(it[2])) }
    @Test fun minSecretBytes() = OracleCases.each(m, "minSecretBytes") { Events.MIN_SECRET_BYTES }

    private class Throwing(private val refuse: Boolean) : Authorize.StateStore {
        override fun claim(key: String, counter: Long): Authorize.ClaimResult = throw IllegalStateException("unused")
        override fun consumeOnce(key: String, retainUntil: Long, now: Long): Boolean = if (refuse) false else throw IllegalStateException("down")
    }

    @Test fun deliveries() = OracleCases.each(m, "deliveryScenario") { a ->
        val spec = mm(a[0])!!
        val store: Authorize.StateStore = when (spec["store"]) {
            "throws" -> Throwing(false)
            "refuses" -> Throwing(true)
            else -> Authorize.MemoryStateStore()
        }
        val noReplay = spec["noReplay"] == true
        val noOpts = spec["noOpts"] == true
        (spec["deliveries"] as List<*>).map { dO ->
            val d = mm(dO)!!
            val opts = LinkedHashMap<String, Any?>()
            mm(d["opts"])?.let { opts.putAll(it) }
            val replayNulled = opts.containsKey("replay")
            opts.remove("replay")
            val sec = secret(if (d.containsKey("secret")) d["secret"] else "whsec_0123456789abcdef0123456789")
            val v = Events.verifyDelivery(sec, d["payload"] as String, d["header"], if (noReplay || replayNulled) null else store, if (noOpts) null else opts)
            val out = LinkedHashMap(v.toMap())
            val r = v.reason
            if (!v.ok && r != null) {
                if (r.startsWith("canonicalize:")) out["reason"] = "<canonicalize>"
                else if (r.startsWith(Events.SYNTAX_PREFIX)) out["reason"] = "<json>"
            }
            out
        }
    }

    @Test fun signAndVerifyWithTheClock() {
        val secret = "whsec_0123456789abcdef0123456789"
        val sig = Events.signWebhook(secret, "body")
        assertTrue(Events.verifyWebhook(secret, "body", sig))
        assertFalse(Events.verifyWebhook(secret, "other", sig))
        val e = Events.buildStepUpEvent("step_up.created", Json.parseLenient("{\"grant_ref\":\"g\",\"action\":{\"verb\":\"v\",\"resource\":\"r\"},\"tier\":2}"))
        assertNotNull(e["at"])
        assertEquals(e["id"], Events.parseEvent(Events.serializeEvent(e))["id"])
        assertEquals(16, Events.MIN_SECRET_BYTES)
    }
}
