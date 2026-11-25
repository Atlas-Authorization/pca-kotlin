package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import org.junit.Test

/** Replays the reference vectors of the lazy just-in-time elicitation: visit decision, cell coordinates, delta grants, the intent_required question and the wallet check. */
@Suppress("UNCHECKED_CAST")
class IntentJitDiffTest {
    private val m = "ref-intent-jit"
    private val prefix = "action.params."

    private fun mp(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>

    private fun ls(o: Any?): List<Any?> = o as List<Any?>

    private fun make(omega: Any?, mapOpts: Any?, obs: Any?): IntentLearner {
        val l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts))
        for (xo in ls(obs)) {
            val x = mp(xo)
            l.observe(IntentOmega.outcomeFromJson(x), IntentOmega.dbl(x["y"]).toInt(), x["source"] as String, null)
        }
        return l
    }

    private fun ints(o: Any?): IntArray = ls(o).map { IntentOmega.dbl(it).toInt() }.toIntArray()

    private fun ceiling(name: String): (VerbSpace, Outcome) -> Boolean = when (name) {
        "all" -> ({ _, _ -> true })
        "none" -> ({ _, _ -> false })
        "amountLe60" -> ({ _, o -> o.values[prefix + "amount"] !is Double || (o.values[prefix + "amount"] as Double) <= 60 })
        else -> ({ _, o -> o.verb != "gmail.send" })
    }

    private fun verb(om: Omega, v: String): VerbSpace? = om.verbs.firstOrNull { it.verb == v }

    @Test fun visitScenario() = OracleCases.each(m, "visitScenario") { a ->
        val cs = ls(a[5]).map { ceiling(it as String) }
        IntentJit.decideVisit(make(a[0], a[1], a[2]), IntentOmega.outcomeFromJson(a[3]), mp(a[4]), cs, a[6] == true)
    }

    @Test fun cellCoords() = OracleCases.each(m, "cellCoords") { a -> IntentJit.cellCoords(IntentOmega.verbSpaceFromJson(a[0]), ints(a[1])) }

    @Test fun cellFromCoords() = OracleCases.each(m, "cellFromCoords") { a ->
        IntentJit.cellFromCoords(IntentOmega.verbSpaceFromJson(a[0]), mp(a[1]))?.map { it }
    }

    @Test fun deltaScenario() = OracleCases.each(m, "deltaScenario") { a ->
        val both = ls(a[2]) + ls(a[3])
        val prev = make(a[0], a[1], a[2])
        val next = make(a[0], a[1], both)
        val d = IntentJit.deltaCells(prev, next)
        val cells = LinkedHashMap<String, Any?>()
        for ((k, v) in d) cells[k] = v.map { it.toDouble() }
        linkedMapOf("cells" to cells, "predicates" to IntentJit.deltaPredicates(next.omega, d))
    }

    @Test fun requiredScenario() = OracleCases.each(m, "requiredScenario") { a ->
        val om = IntentOmega.omegaFromJson(a[0])
        val vs = verb(om, a[1] as String)!!
        val cell = ints(a[2])
        val inp = mp(a[3])
        val site = Keys.ed25519(Keys.edFromSeed(Keys.unb64u(a[4] as String)))
        val body = IntentJit.intentRequiredBody(inp, vs, cell)
        linkedMapOf("signed" to IntentJit.signedIntentRequired(inp, vs, cell, "site-1", site), "body" to body)
    }

    @Test fun walletScenario() = OracleCases.each(m, "walletScenario") { a ->
        val om = IntentOmega.omegaFromJson(a[0])
        val inp = mp(a[1])
        val mutation = a[2] as String
        val siteKey = Keys.edFromSeed(Keys.unb64u(a[7] as String))
        val signed = IntentJit.signedIntentRequired(inp, verb(om, "stripe.refund")!!, intArrayOf(1, 0), "site-1", Keys.ed25519(siteKey))
        var body: Any? = IntentJs.normalize(signed)
        val b = mp(body)
        when (mutation) {
            "coords" -> mp(mp(mp(b["cell"])["coords"])).put(prefix + "amount", arrayListOf<Any?>(Json.Num("2"), Json.Num("2")))
            "verb" -> mp(b["cell"])["verb"] = "gmail.send"
            "sig" -> { val v = mp(b["sig"])["value"] as String; mp(b["sig"])["value"] = v.substring(0, v.length - 2) + "AA" }
            "kid" -> mp(b["sig"])["kid"] = "other"
            "session" -> b["session"] = Pca.b64(Pca.sha("other".toByteArray()))
            "action" -> b["action_digest"] = Pca.b64(Pca.sha("other".toByteArray()))
            "null" -> body = null
            else -> {}
        }
        val key = linkedMapOf<String, Any?>("kid" to "site-1", "alg" to "ed25519", "pk" to siteKey.id())
        val keys = arrayListOf<Any?>(key)
        val now = IntentOmega.dbl(a[3])
        val nowL = if (now != Math.floor(now)) Long.MIN_VALUE else now.toLong()
        IntentJit.walletCheckIntentRequired(body, keys, nowL, a[5] as String, a[6] as String, om, IntentOmega.outcomeFromJson(a[4]), mp(inp["pcactn"]))
    }

    @Test fun mintScenario() = OracleCases.each(m, "mintScenario") { a ->
        val both = ls(a[2]) + ls(a[3])
        val prev = make(a[0], a[1], a[2])
        val next = make(a[0], a[1], both)
        val principal = Keys.ed25519(Keys.edFromSeed(Keys.unb64u(a[5] as String)))
        IntentJit.mintDelta(prev, next, mp(a[4]), principal)
    }
}
