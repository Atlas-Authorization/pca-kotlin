package net.atlasauth.pca.wallet

import java.security.MessageDigest
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle for the wallet package. */
@Suppress("UNCHECKED_CAST")
class WalletDiffTest {
    companion object {
        const val MODULE = "ref-wallet"
        private var omegasCache: Map<String, Any?>? = null

        @Synchronized fun omegas(): Map<String, Any?> {
            if (omegasCache == null) omegasCache = OracleCases.of(MODULE, "omegas")[0]["out"] as Map<String, Any?>
            return omegasCache!!
        }

        fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
        fun l(o: Any?): List<Any?> = o as List<Any?>
        fun d(o: Any?): Double = net.atlasauth.pca.jose.Js.num(o) ?: Double.NaN
        fun n(o: Any?): Long = d(o).toLong()
        fun ints(o: Any?): IntArray = WalletNoise.idxOf(o)
        fun s(o: Any?): String = o as String
        fun obj(vararg kv: Any?): LinkedHashMap<String, Any?> {
            val r = LinkedHashMap<String, Any?>()
            var i = 0
            while (i < kv.size) { r[kv[i] as String] = kv[i + 1]; i += 2 }
            return r
        }

        fun seed(label: String): ByteArray = MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/$label".toByteArray(Charsets.UTF_8))

        /** Replace the {"$omega": id} and {"$seed": label} placeholders of an argument tree. */
        fun sub(x: Any?): Any? {
            if (x is Map<*, *>) {
                if (x.size == 1 && x.containsKey("\$omega")) return omegas()[x["\$omega"]]
                if (x.size == 1 && x.containsKey("\$seed")) return seed(x["\$seed"] as String)
                val out = LinkedHashMap<String, Any?>()
                for ((k, v) in x) out[k as String] = sub(v)
                return out
            }
            if (x is List<*>) return x.map { sub(it) }
            return x
        }

        fun each(fn: String, f: (List<Any?>) -> Any?) = OracleCases.each(MODULE, fn) { a -> f(l(sub(a))) }

        fun vs(id: Any?, verb: Any?): Map<String, Any?> = WalletOmega.verbSpace(m(omegas()[id]), verb)!!

        fun seq(xs: List<Any?>): () -> Double {
            val i = intArrayOf(0)
            return { if (i[0] >= xs.size) throw IllegalStateException("rand exhausted"); d(xs[i[0]++]) }
        }

        fun tableView(v: Map<String, Any?>): WalletView {
            val p = m(v["p"])
            val vetoed = l(v["vetoed"])
            val ceiling = l(v["ceiling"])
            return object : WalletView {
                override fun p(verb: String, idx: IntArray): Double { val x = p[WalletNoise.cellKey(verb, idx)]; return if (x == null) 0.0 else d(x) }
                override fun vetoed(verb: String, idx: IntArray): Boolean = vetoed.contains(WalletNoise.cellKey(verb, idx))
                override fun outsideCeiling(verb: String, idx: IntArray): Boolean = ceiling.contains(WalletNoise.cellKey(verb, idx))
                override fun confirmed(): List<Map<String, Any?>> {
                    val out = ArrayList<Map<String, Any?>>()
                    if (v["confirmed"] != null) for (c in l(v["confirmed"])) out.add(m(c))
                    return out
                }
            }
        }
    }

    // ---- friction and the wire ----

    @Test fun isFrictionTier() = each("isFrictionTier") { a -> Wallet.isFrictionTier(a[0]) }
    @Test fun frictionRank() = each("frictionRank") { a -> Wallet.frictionRank(a[0]).toLong() }
    @Test fun isProvenanceLevel() = each("isProvenanceLevel") { a -> Wallet.isProvenanceLevel(a[0]) }
    @Test fun worstProvenance() = each("worstProvenance") { a -> Wallet.worstProvenance(a[0]) }
    @Test fun satisfiesTier() = each("satisfiesTier") { a -> Wallet.satisfiesTier(a[0], a[1]) }
    @Test fun maxFriction() = each("maxFriction") { a -> Wallet.maxFriction(a) }
    @Test fun frictionFor() = each("frictionFor") { a -> if (a.size > 1) Wallet.frictionFor(m(a[0]), m(a[1])) else Wallet.frictionFor(m(a[0])) }
    @Test fun pcaActionDigest() = each("pcaActionDigest") { a -> Wallet.pcaActionDigest(m(a[0])) }
    @Test fun actionValuesOf() = each("actionValuesOf") { a -> Wallet.actionValuesOf(m(a[0])) }
    @Test fun isB64u32() = each("isB64u32") { a -> Wallet.isB64u32(a[0]) }
    @Test fun isObj() = each("isObj") { a -> Wallet.isObj(a[0]) }
    @Test fun coordsError() = each("coordsError") { a -> Wallet.coordsError(a[0]) }
    @Test fun answerShapeError() = each("answerShapeError") { a -> Wallet.answerShapeError(a[0]) }
    @Test fun signIntentAnswer() = each("signIntentAnswer") { a -> Wallet.signIntentAnswer(m(a[0]), a[1] as ByteArray) }

    @Test fun verifyIntentAnswer() = each("verifyIntentAnswer") { a ->
        val r = Wallet.verifyIntentAnswer(a[0], if (a.size > 1) a[1] else null)
        if (r["ok"] == false && (r["reason"] as String).startsWith("malformed answer:")) obj("ok", false, "reason", "malformed answer") else r
    }

    @Test fun answerRef() = each("answerRef") { a -> Wallet.answerRef(a[0]) }
    @Test fun typedDigest() = each("typedDigest") { a -> Wallet.typedDigest(s(a[0]), s(a[1])) }

    @Test fun deviceChallenge() = each("deviceChallenge") { a ->
        val x = m(a[0])
        Wallet.deviceChallenge(s(x["questionId"]), s(x["renderedDigest"]), n(x["y"]), x["actionDigest"] as String?)
    }

    // ---- numerics ----

    @Test fun lnGamma() = each("lnGamma") { a -> WalletStats.lnGamma(d(a[0])) }
    @Test fun betacf() = each("betacf") { a -> WalletStats.betacf(d(a[0]), d(a[1]), d(a[2])) }
    @Test fun betaInc() = each("betaInc") { a -> WalletStats.betaInc(d(a[0]), d(a[1]), d(a[2])) }
    @Test fun betaQuantile() = each("betaQuantile") { a -> WalletStats.betaQuantile(d(a[0]), d(a[1]), d(a[2])) }
    @Test fun clopperPearsonUpper() = each("clopperPearsonUpper") { a -> WalletStats.clopperPearsonUpper(d(a[0]), d(a[1]), d(a[2])) }
    @Test fun binEnt() = each("binEnt") { a -> WalletStats.binEnt(d(a[0])) }

    // ---- canaries and fatigue ----

    @Test fun recordCanary() = each("recordCanary") { a -> WalletNoise.recordCanary(m(a[0]), a[1], a[2]) }
    @Test fun estimateNoise() = each("estimateNoise") { a -> if (a.size > 1) WalletNoise.estimateNoise(m(a[0]), d(a[1])) else WalletNoise.estimateNoise(m(a[0])) }
    @Test fun cellKey() = each("cellKey") { a -> WalletNoise.cellKey(s(a[0]), ints(a[1])) }

    @Test fun boundaryNeighbours() = each("boundaryNeighbours") { a ->
        WalletNoise.boundaryNeighbours(m(a[0]), l(a[1]).map { m(it) })
    }

    @Test fun pickCanary() = each("pickCanary") { a ->
        val x = m(a[0])
        val c = WalletNoise.CanaryContext()
        c.omega = m(x["omega"])
        c.confirmed = l(x["confirmed"]).map { m(it) }
        val kn = m(x["knownNo"])
        c.knownNo = WalletNoise.KnownNo { verb, idx -> kn[WalletNoise.cellKey(verb, idx)] as String? }
        c.knownYes = l(x["knownYes"]).map { m(it) }
        c.exclude = l(x["exclude"]).map { s(it) }.toSet()
        c.rand = seq(l(x["rands"]))
        if (x.containsKey("rho")) c.rho = d(x["rho"])
        c.lowHarmSession = x["lowHarmSession"] == true
        c.canariesSoFar = d(x["canariesSoFar"])
        WalletNoise.pickCanary(c)
    }

    @Test fun etaUnderLoad() = each("etaUnderLoad") { a -> WalletNoise.etaUnderLoad(d(a[0]), d(a[1]), d(a[2])) }
    @Test fun noiseState() = each("noiseState") { a -> if (a.size > 2) WalletNoise.noiseState(m(a[0]), d(a[1]), m(a[2])) else WalletNoise.noiseState(m(a[0]), d(a[1])) }
    @Test fun admissionPolicy() = each("admissionPolicy") { a -> if (a.size > 1) WalletNoise.admissionPolicy(m(a[0]), m(a[1])) else WalletNoise.admissionPolicy(m(a[0])) }
    @Test fun doubleConfirmed() = each("doubleConfirmed") { a -> WalletNoise.doubleConfirmed(l(a[0]).map { m(it) }) }

    @Test fun slidingWindow() = each("slidingWindow") { a ->
        val c = if (a[0] == null) WalletNoise.SlidingWindowCounter() else WalletNoise.SlidingWindowCounter(d(a[0]))
        val out = ArrayList<Any?>()
        for (opO in l(a[1])) {
            val op = l(opO)
            try {
                out.add(obj("v", if ("count" == op[0]) c.count(d(op[1])).toLong() else c.tryAdd(d(op[1]), d(op[2]))))
            } catch (e: RuntimeException) { out.add(obj("err", true)) }
        }
        out
    }

    // ---- risk-priced escalation ----

    @Test fun signPricingConfig() = each("signPricingConfig") { a -> WalletPricing.signPricingConfig(m(a[0]), a[1] as ByteArray) }
    @Test fun pricingConfigError() = each("pricingConfigError") { a -> WalletPricing.pricingConfigError(a[0]) }
    @Test fun freshCalibration() = each("freshCalibration") { _ -> WalletPricing.freshCalibration() }
    @Test fun decideEscalation() = each("decideEscalation") { a -> WalletPricing.decideEscalation(m(a[0]), a[1], a[2]) }
    @Test fun signAnswer() = each("signAnswer") { a -> WalletPricing.signAnswer(m(a[0]), a[1] as ByteArray) }
    @Test fun updateCalibration() = each("updateCalibration") { a -> WalletPricing.updateCalibration(m(a[0]), m(a[1]), l(a[2]), m(a[3])) }
    @Test fun signAutonomyRaise() = each("signAutonomyRaise") { a -> WalletPricing.signAutonomyRaise(m(a[0]), a[1] as ByteArray) }
    @Test fun applyAutonomyRaise() = each("applyAutonomyRaise") { a -> WalletPricing.applyAutonomyRaise(m(a[0]), m(a[1]), a[2] as ByteArray) }

    // ---- the outcome space ----

    @Test fun omegaVerbCellCount() = OracleCases.each(MODULE, "omega.verbCellCount") { a -> WalletOmega.verbCellCount(vs(a[0], a[1])) }
    @Test fun omegaCellCount() = OracleCases.each(MODULE, "omega.cellCount") { a -> WalletOmega.cellCount(WalletOmega.dim(vs(a[0], a[1]), n(a[2]).toInt())).toLong() }

    @Test fun omegaNumCells() = OracleCases.each(MODULE, "omega.numCells") { a ->
        WalletOmega.numCells(WalletOmega.dim(vs(a[0], a[1]), n(a[2]).toInt())).map { obj("lo", it[0], "hi", it[1]) }
    }

    @Test fun omegaLabelOf() = OracleCases.each(MODULE, "omega.labelOf") { a -> WalletOmega.labelOf(s(a[0])) }
    @Test fun omegaDecodeCell() = OracleCases.each(MODULE, "omega.decodeCell") { a -> WalletNoise.idxList(WalletOmega.decodeCell(vs(a[0], a[1]), d(a[2]))) }

    @Test fun omegaCellStats() = OracleCases.each(MODULE, "omega.cellStats") { a ->
        val r = WalletOmega.cellStats(vs(a[0], a[1]), ints(a[2]), WalletOmega.DEFAULT_HARM)
        obj("mass", r[0], "harm", r[1])
    }

    @Test fun omegaCellRep() = OracleCases.each(MODULE, "omega.cellRep") { a -> WalletOmega.cellRep(vs(a[0], a[1]), ints(a[2])) }

    @Test fun omegaCellOf() = OracleCases.each(MODULE, "omega.cellOf") { a ->
        val r = WalletOmega.cellOf(vs(a[0], a[1]), m(a[2]))
        if (r == null) null else WalletNoise.idxList(r)
    }

    // ---- cell coordinates ----

    @Test fun coordKeyOf() = each("coordKeyOf") { a -> WalletBox.coordKeyOf(s(a[0])) }
    @Test fun resolveCoords() = each("resolveCoords") { a -> WalletBox.resolveCoords(m(a[0]), s(a[1]), m(a[2])).toMap() }
    @Test fun coordsOfBox() = each("coordsOfBox") { a -> WalletBox.coordsOfBox(vs(a[0], a[1]), WalletBox.boxOf(a[2])) }
    @Test fun coordsOfCell() = each("coordsOfCell") { a -> WalletBox.coordsOfCell(vs(a[0], a[1]), ints(a[2])) }
    @Test fun cellInBox() = each("cellInBox") { a -> WalletBox.cellInBox(WalletBox.boxOf(a[0]), ints(a[1])) }
    @Test fun boxCells() = each("boxCells") { a -> WalletBox.boxCells(WalletBox.boxOf(a[0])).map { WalletNoise.idxList(it) } }
    @Test fun boxSize() = each("boxSize") { a -> WalletBox.boxSize(WalletBox.boxOf(a[0])) }

    @Test fun cellOfAction() = OracleCases.each(MODULE, "cellOfAction") { a -> WalletBox.cellOfAction(m(omegas()[a[0]]), m(a[1]))?.toMap() }
    @Test fun flatIndex() = OracleCases.each(MODULE, "flatIndex") { a -> WalletBox.flatIndex(vs(a[0], a[1]), ints(a[2])) }

    // ---- the card ----

    @Test fun cleanText() = each("cleanText") { a -> WalletCard.cleanText(s(a[0]), n(a[1]).toInt()) }
    @Test fun last4() = each("last4") { a -> WalletCard.last4(s(a[0])) }
    @Test fun formatNumber() = each("formatNumber") { a -> WalletCard.formatNumber(d(a[0]), if (a.size > 1) a[1] else null) }

    @Test fun renderCard() = OracleCases.each(MODULE, "renderCard") { a ->
        val inp = LinkedHashMap(m(sub(a[0])))
        val id = inp.remove("omegaId")
        inp["omega"] = omegas()[id]
        WalletCard.renderCard(inp)
    }

    @Test fun cardDigest() = each("cardDigest") { a -> WalletCard.cardDigest(m(a[0])) }
    @Test fun cardDigestMatches() = each("cardDigestMatches") { a -> WalletCard.cardDigestMatches(m(a[0])) }
    @Test fun cardText() = each("cardText") { a -> WalletCard.cardText(m(a[0])) }
    @Test fun partialError() = each("partialError") { a -> WalletCard.partialError(m(a[0]), m(a[1])) }
    @Test fun normalizeTyped() = each("normalizeTyped") { a -> WalletCard.normalizeTyped(s(a[0]), s(a[1]), if (a.size > 2) a[2] else null) }
    @Test fun expectedTyped() = each("expectedTyped") { a -> WalletCard.expectedTyped(m(a[0]), m(a[1])) }

    // ---- clarification ----

    @Test fun parseClarifyRequest() = each("parseClarifyRequest") { a -> WalletClarify.parseClarifyRequest(a[0]) }
    @Test fun informationGain() = each("informationGain") { a -> WalletClarify.informationGain(d(a[0]), d(a[1]), d(a[2])) }

    @Test fun planClarification() = each("planClarification") { a ->
        val x = m(a[0])
        WalletClarify.planClarification(m(x["omega"]), tableView(m(x["view"])), l(x["candidates"]).map { m(it) }, null, l(x["asked"]).map { s(it) }.toSet(),
            d(x["etaPos"]), d(x["etaNeg"]), WalletOmega.DEFAULT_HARM).toMap()
    }

    // ---- constants ----

    @Test fun constants() = each("constants") { _ ->
        obj("FRICTION_ORDER", ArrayList<Any?>(Wallet.FRICTION_ORDER), "INTENT_ANSWER_SIG_DOMAIN", Wallet.INTENT_ANSWER_SIG_DOMAIN, "INTENT_ANSWER_REF_DOMAIN", Wallet.INTENT_ANSWER_REF_DOMAIN,
            "INTENT_TYPED_DOMAIN", Wallet.INTENT_TYPED_DOMAIN, "INTENT_DEVICE_CHALLENGE_DOMAIN", Wallet.INTENT_DEVICE_CHALLENGE_DOMAIN, "MIN_HOLD_MS", Wallet.MIN_HOLD_MS,
            "PROVENANCE_ORDER", ArrayList<Any?>(Wallet.PROVENANCE_ORDER), "DEFAULT_FRICTION_THRESHOLDS", Wallet.defaultFrictionThresholds(), "CARD_DOMAIN", WalletCard.CARD_DOMAIN,
            "CLARIFY_REASONS", ArrayList<Any?>(WalletCard.CLARIFY_REASONS), "REASON_LABELS", LinkedHashMap<String, Any?>(WalletCard.REASON_LABELS), "MAX_CANDIDATES", WalletClarify.MAX_CANDIDATES.toLong(),
            "EMPTY_NOISE", WalletNoise.emptyNoise(), "NOISE_PRIOR", obj("a", WalletNoise.PRIOR_A, "b", WalletNoise.PRIOR_B), "DEFAULT_FATIGUE", WalletNoise.defaultFatigue(), "PPM", WalletPricing.PPM,
            "MAX_MULTIPLIER_PPM", WalletPricing.MAX_MULTIPLIER_PPM, "POPULATION_VOTE_DOMAIN", WalletPopulation.POPULATION_VOTE_DOMAIN, "BETA_MAX", WalletPopulation.BETA_MAX)
    }

    // ---- population priors ----

    @Test fun gaussianSigma() = each("gaussianSigma") { a -> WalletPopulation.gaussianSigma(d(a[0]), d(a[1]), d(a[2])) }
    @Test fun gaussian() = each("gaussian") { a -> WalletPopulation.gaussian(seq(l(a[0]))) }
    @Test fun rrKeepProbability() = each("rrKeepProbability") { a -> WalletPopulation.rrKeepProbability(d(a[0])) }
    @Test fun randomizedResponse() = each("randomizedResponse") { a -> WalletPopulation.randomizedResponse(n(a[0]), d(a[1])) { d(a[2]) } }
    @Test fun debiasRandomizedResponse() = each("debiasRandomizedResponse") { a -> WalletPopulation.debiasRandomizedResponse(d(a[0]), d(a[1]), d(a[2])) }

    @Test fun populationCellKey() = OracleCases.each(MODULE, "populationCellKey") { a -> WalletPopulation.populationCellKey(s(a[0]), vs(a[1], a[2]), ints(a[3])) }

    @Test fun aggregate() = each("aggregate") { a ->
        val opts = m(a[2])
        val agg = WalletPopulation.Aggregator(s(a[0]), d(a[1]), if (opts.containsKey("maxCellsPerPrincipal")) d(opts["maxCellsPerPrincipal"]) else null, seq(l(a[5])))
        val votes = ArrayList<Any?>()
        for (v in l(a[3])) votes.add(agg.contribute(m(v)))
        val rel = m(a[4])
        val release: Any? = try {
            agg.release(d(rel["epsilon"]), d(rel["delta"]), if (rel.containsKey("qMin")) d(rel["qMin"]) else null, if (rel.containsKey("minCount")) d(rel["minCount"]) else null)
        } catch (e: RuntimeException) { obj("err", true) }
        obj("votes", votes, "release", release)
    }

    @Test fun populationPrior() = each("populationPrior") { a ->
        val pm = WalletPopulation.populationPrior(m(a[0]), d(a[1]))
        val inSet = l(a[4]).map { n(it).toInt() }.toSet()
        obj("beta", pm.beta, "weight", pm.weight(vs(a[2], a[3])) { inSet.contains(it) })
    }

    // ---- delivery ----

    @Test fun siteQuestionNotice() = each("siteQuestionNotice") { a -> WalletDelivery.siteQuestionNotice(m(a[0]), a[1], a[2], a[3], if (a.size > 4) a[4] else null) }
    @Test fun clarificationNotice() = each("clarificationNotice") { a -> WalletDelivery.clarificationNotice(a[0], a[1], if (a.size > 2) a[2] else null) }
    @Test fun questionText() = each("questionText") { a -> WalletDelivery.questionText(m(a[0]), s(a[1])) }

    @Test fun webhookChannel() = each("webhookChannel") { a ->
        val cfg = m(a[0])
        val script = l(a[1])
        val calls = ArrayList<Any?>()
        val i = intArrayOf(0)
        val tr = WalletDelivery.Transport { url, headers, body ->
            calls.add(obj("url", url, "method", "POST", "headers", LinkedHashMap<String, Any?>(headers), "body", body))
            val step = if (i[0] < script.size) m(script[i[0]++]) else obj("ok", true, "status", 200L)
            if (step["throw"] != null) throw RuntimeException(step["throw"] as String)
            WalletDelivery.TransportResult(step["ok"] == true, n(step["status"]).toInt())
        }
        var headers: Map<String, String>? = null
        if (cfg["headers"] != null) { val h = LinkedHashMap<String, String>(); for ((k, v) in m(cfg["headers"])) h[k] = s(v); headers = h }
        val ch = WalletDelivery.questionWebhookChannel(cfg["url"] as String?, headers, tr)
        val deliveries = ArrayList<Any?>()
        for (nn in l(a[2])) deliveries.add(ch.notify(m(nn)))
        obj("kind", ch.kind(), "enabled", ch.enabled(), "deliveries", deliveries, "calls", calls)
    }

    @Test fun textChannel() = each("textChannel") { a ->
        val script = if (a[2] == null) null else l(a[2])
        val sent = ArrayList<Any?>()
        val i = intArrayOf(0)
        val send: WalletDelivery.TextSender? = if (script == null) null else WalletDelivery.TextSender { body ->
            sent.add(body)
            val st = if (i[0] < script.size) script[i[0]] else null
            i[0]++
            if (st is Map<*, *> && st["throw"] != null) throw RuntimeException(st["throw"] as String)
        }
        val ch = WalletDelivery.questionTextChannel(s(a[0]), send, s(a[1]))
        val deliveries = ArrayList<Any?>()
        for (nn in l(a[3])) deliveries.add(ch.notify(m(nn)))
        obj("kind", ch.kind(), "enabled", ch.enabled(), "deliveries", deliveries, "sent", sent)
    }

    @Test fun dispatcher() = each("dispatcher") { a ->
        val chans = ArrayList<WalletDelivery.QuestionChannel>()
        for (cO in l(a[0])) {
            val c = m(cO)
            if ("webhook" == c["type"]) chans.add(WalletDelivery.questionWebhookChannel(c["url"] as String?, null) { _, _, _ -> WalletDelivery.TransportResult(true, 200) })
            else chans.add(WalletDelivery.questionTextChannel(s(c["type"]), if (c["enabled"] == true) WalletDelivery.TextSender { } else null, "S"))
        }
        obj("n", chans.size.toLong(), "deliveries", ArrayList<Any?>(WalletDelivery.notifyAll(chans, m(a[1]))))
    }

    // ---- the question channel (scenarios) ----

    @Test fun channel() = each("channel") { a -> runScenario(m(a[0])) }

    private fun runScenario(spec: Map<String, Any?>): Map<String, Any?> {
        val hourly = if (spec["windowMs"] != null) WalletNoise.SlidingWindowCounter(d(spec["windowMs"])) else WalletNoise.SlidingWindowCounter()
        for (ts in l(spec["hourlyPre"])) hourly.tryAdd(d(ts), 9007199254740991.0)
        val t = doubleArrayOf(d(spec["t0"]))
        val counts = arrayOf(m(spec["noise"]))
        val o = TrustedChannel.Options()
        o.omega = m(spec["omega"])
        o.session = s(spec["session"])
        val mapDigest = s(spec["mapDigest"])
        o.mapDigest = { mapDigest }
        o.principalSeed = seed(s(spec["principal"]))
        val site = m(spec["site"])
        o.siteOrigin = s(site["origin"])
        o.siteName = s(site["name"])
        o.siteKeys = l(site["keys"])
        if (spec.containsKey("statementText")) o.statementText = s(spec["statementText"])
        if (spec["units"] != null) o.units = m(spec["units"])
        if (spec["sensitivity"] != null) o.sensitivity = m(spec["sensitivity"])
        if (spec["identityPaths"] != null) o.identityPaths = l(spec["identityPaths"]).map { s(it) }
        o.view = tableView(m(spec["view"]))
        o.hourly = hourly
        o.noise = { counts[0] }
        o.onNoise = { nn -> counts[0] = nn }
        o.rand = seq(l(spec["rands"]))
        o.now = { t[0] }
        if (spec["caps"] != null) {
            val caps = m(spec["caps"])
            if (caps.containsKey("perSession")) o.perSession = n(caps["perSession"]).toInt()
            if (caps.containsKey("perHour")) o.perHour = n(caps["perHour"]).toInt()
        }
        if (spec.containsKey("rho")) o.rho = d(spec["rho"])
        if (spec["fatigue"] != null) o.fatigue = m(spec["fatigue"])
        if (spec.containsKey("maxPerScreen")) o.maxPerScreen = n(spec["maxPerScreen"]).toInt()
        if (spec.containsKey("maxBoxCells")) o.maxBoxCells = n(spec["maxBoxCells"]).toInt()
        var dev: TrustedChannel.DeviceTrust? = null
        if (spec["device"] != null) {
            val dm = m(spec["device"])
            dev = TrustedChannel.DeviceTrust()
            dev.rpId = s(dm["rpId"])
            dev.origins = l(dm["origins"])
            dev.credentials = m(dm["credentials"])
            dev.signCounts = if (dm["signCounts"] == null) null else LinkedHashMap(m(dm["signCounts"]))
            o.device = dev
        }
        if (spec["lift"] != null) {
            val add = m(m(spec["lift"])["add"])
            o.lift = { act ->
                val v = Wallet.actionValuesOf(act)
                val vals = LinkedHashMap(m(v["values"]))
                vals.putAll(add)
                obj("verb", v["verb"], "values", vals)
            }
        }
        if (spec["liftCand"] != null) {
            val add = m(spec["liftCand"])
            o.liftCandidate = { c ->
                val vals = LinkedHashMap(m(c["values"]))
                vals.putAll(add)
                obj("verb", c["verb"], "values", vals)
            }
        }
        val ch = TrustedChannel(o)
        val seen = ArrayList<String>()
        val steps = ArrayList<Any?>()
        val session = o.session
        val resolver = WalletHandlers.ChannelResolver { sid -> if (session == sid) ch else null }
        for (stO in l(spec["steps"])) {
            val st = m(stO)
            val op = s(st["op"])
            var r: Any?
            try {
                val qid: String? = if (st["q"] != null) (if (n(st["q"]) < seen.size) seen[n(st["q"]).toInt()] else null) else st["qid"] as String?
                r = when (op) {
                    "time" -> { t[0] = d(st["t"]); obj("t", st["t"]) }
                    "receive" -> ch.receive(m(st["ir"]), m(st["action"]))
                    "next" -> {
                        val scr = ch.nextScreen()
                        if (scr != null) for (q in l(scr["questions"])) seen.add(s(m(q)["questionId"]))
                        scr
                    }
                    "answer" -> ch.answer(qid!!, m(st["response"]))
                    "clarify" -> ch.clarify(st["body"])
                    "hQuestion" -> WalletHandlers.question(resolver, if (st["sid"] != null) s(st["sid"]) else session, st["body"])
                    "hClarify" -> WalletHandlers.clarify(resolver, if (st["sid"] != null) s(st["sid"]) else session, st["body"])
                    "summary" -> ch.summary()
                    "state" -> obj("digest", ch.stateDigest(), "asked", ch.questionsAsked().toLong())
                    "noise" -> obj("noise", ch.noise(), "admission", ch.admission())
                    "challenge" -> ch.deviceChallengeFor(qid!!)
                    else -> throw IllegalStateException("bad op $op")
                }
            } catch (e: RuntimeException) {
                r = obj("\$err", true)
            }
            steps.add(obj("op", op, "r", r))
        }
        return obj("steps", steps, "noise", counts[0], "signCounts", dev?.signCounts)
    }
}
