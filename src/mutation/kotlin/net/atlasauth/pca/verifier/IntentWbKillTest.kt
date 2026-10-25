package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.b64seed
import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import net.atlasauth.pca.verifier.IntentTestKit.norm
import net.atlasauth.pca.verifier.IntentTestKit.pub
import net.atlasauth.pca.verifier.IntentTestKit.sign
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mutation kills for the W-B rules 16 (facts, relational, offer sets), 17 (provenance, label receipts, flows), 18 (classifiers) and the unit. */
class IntentWbKillTest {
    private val NOW = 1_800_000_000_000L
    private val AUD = "skyair.example"
    private val SESSION = b64seed("wb/session")

    private fun signed(domain: String, body: Map<String, Any?>, key: String): LinkedHashMap<String, Any?> =
        LinkedHashMap(body).also { it["sig"] = sign(key, IntentJs.message(domain, body)) }
    private fun fact(name: String, subject: String, value: Any?, tObs: Long, oracle: String, key: String) =
        signed(OracleFacts.FACT_DOMAIN, jm("v", 1L, "kind", "pca-fact", "name", name, "subject", subject, "value", value, "t_obs", tObs, "oracle", oracle), key)
    private fun world(min: Int, faulty: Int, fresh: Long) = jm("name", "fx", "subject_path", "action.resource", "freshness_ms", fresh, "min_oracles", min.toLong(), "max_faulty", faulty.toLong(),
        "oracles", jl(jm("kid", "o1", "pk", pub("wb/o1")), jm("kid", "o2", "pk", pub("wb/o2")), jm("kid", "o3", "pk", pub("wb/o3"))))
    private fun action(vararg params: Any?) = jm("verb", "air.book", "resource", "EURUSD", "params", jm(*params))
    private fun decideWorld(facts: List<Any?>, policy: Map<String, Any?>, now: Any?, action: Map<String, Any?>): OracleFacts.WorldResult {
        val committed = facts.map { OracleFacts.factRef(norm(it)) }
        return OracleFacts.decideIntentWorld(jm("now", now, "aud", AUD, "session", SESSION, "action", action, "committed", jm("facts", committed), "facts", facts, "policy", policy))
    }

    @Test fun worldMedianFreshnessAndClock() {
        val pol = jm("worlds", jl(world(3, 1, 60_000L)))
        val f3 = jl(fact("fx", "EURUSD", 7L, NOW, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2"), fact("fx", "EURUSD", 9L, NOW, "o3", "wb/o3"))
        val r = decideWorld(f3, pol, NOW, action())
        assertTrue(r.reason, r.ok)
        assertEquals("7", r.world!!["fx"].toString())
        assertTrue(r.singleSource!!.isEmpty())
        val pol2 = jm("worlds", jl(world(2, 0, 60_000L)))
        assertEquals("1", decideWorld(jl(fact("fx", "EURUSD", 9L, NOW, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).world!!["fx"].toString())
        assertTrue(decideWorld(jl(fact("fx", "EURUSD", 1L, NOW - 60_000, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW + 60_000, "o2", "wb/o2")), pol2, NOW, action()).ok)
        assertFalse(decideWorld(jl(fact("fx", "EURUSD", 1L, NOW - 60_001, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok)
        assertFalse(decideWorld(jl(fact("fx", "EURUSD", 1L, NOW + 60_001, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok)
        for (badNow in listOf<Any?>(NOW.toString(), Json.Num("1800000000000.5"), null))
            assertFalse(badNow.toString(), decideWorld(jl(fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, badNow, action()).ok)
        assertEquals("up", decideWorld(jl(fact("fx", "EURUSD", "up", NOW, "o1", "wb/o1"), fact("fx", "EURUSD", "up", NOW, "o2", "wb/o2")), pol2, NOW, action()).world!!["fx"])
        assertFalse(decideWorld(jl(fact("fx", "EURUSD", "up", NOW, "o1", "wb/o1"), fact("fx", "EURUSD", "dn", NOW, "o2", "wb/o2")), pol2, NOW, action()).ok)
        assertFalse(decideWorld(jl(fact("fx", "EURUSD", "up", NOW, "o1", "wb/o1"), fact("fx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok)
        assertEquals(listOf("fx"), decideWorld(jl(fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1")), jm("worlds", jl(world(1, 0, 60_000L))), NOW, action()).singleSource)
    }

    @Test fun worldRefusals() {
        val pol2 = jm("worlds", jl(world(2, 0, 60_000L)))
        val f1 = fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1")
        assertFalse(decideWorld(jl(f1, fact("fx", "EURUSD", 1L, NOW, "o1", "wb/o1x")), pol2, NOW, action()).ok)
        assertFalse(decideWorld(jl(f1, fact("fx", "EURUSD", 1L, NOW, "o9", "wb/o2")), pol2, NOW, action()).ok)
        assertFalse(decideWorld(jl(f1, fact("fx", "GBPUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok)
        assertFalse(decideWorld(jl(f1, fact("fx", "EURUSD", 2L, NOW + 1, "o1", "wb/o1")), pol2, NOW, action()).ok)
        assertFalse(decideWorld(jl(f1, fact("gx", "EURUSD", 1L, NOW, "o2", "wb/o2")), pol2, NOW, action()).ok)
        assertFalse(OracleFacts.decideIntentWorld(jm("now", NOW, "aud", AUD, "session", SESSION, "action", action(), "committed", jm("facts", jl(b64seed("wb/none"))), "facts", jl(f1), "policy", jm())).ok)
        assertTrue(OracleFacts.decideIntentWorld(jm("now", NOW, "aud", AUD, "session", SESSION, "action", action(), "committed", jm(), "facts", jl(f1), "policy", jm())).ok)
        assertFalse(decideWorld(jl(), jm("worlds", jl(world(2, 1, 60_000L))), NOW, action()).ok)
        assertFalse(decideWorld(jl(), jm("skew_ms", -1L), NOW, action()).ok)
        assertTrue(decideWorld(jl(), jm("skew_ms", 0L), NOW, action()).ok)
    }

    @Test fun relational() {
        val pol = jm("relational", jl(jm("name", "d", "fn", "sub", "a", "action.params.a", "b", "action.params.b"), jm("name", "r", "fn", "ratio_ppm", "a", "env.world.d", "b", "action.params.b")))
        val ok = decideWorld(jl(), pol, NOW, action("a", 3L, "b", 2L))
        assertTrue(ok.reason, ok.ok)
        assertEquals("1", ok.world!!["d"].toString())
        assertEquals("500000", ok.world!!["r"].toString())
        assertEquals("-1", decideWorld(jl(), jm("relational", jl(jm("name", "d", "fn", "sub", "a", "action.params.a", "b", "action.params.b"))), NOW, action("a", 1L, "b", 2L)).world!!["d"].toString())
        assertFalse(decideWorld(jl(), pol, NOW, action("a", 3L, "b", 0L)).ok)
        assertFalse(decideWorld(jl(), pol, NOW, action("a", 1L, "b", 2L)).ok)
        assertFalse(decideWorld(jl(), pol, NOW, action("a", 9007199254740991L, "b", -9007199254740991L)).ok)
        assertTrue(decideWorld(jl(), pol, "x", action("a", 3L, "b", 2L)).ok)
        assertFalse(decideWorld(jl(), jm("relational", jl(jm("name", "d", "fn", "sub", "a", "env.world.d", "b", "action.params.b"))), NOW, action("b", 1L)).ok)
        assertEquals("1", decideWorld(jl(), jm("relational", jl(jm("name", "constructor", "fn", "sub", "a", "action.params.a", "b", "action.params.b"))), NOW, action("a", 3L, "b", 2L)).world!!["constructor"].toString())
    }

    private fun offerSet(vararg over: Any?): LinkedHashMap<String, Any?> {
        val body = jm("v", 1L, "kind", "pca-offer-set", "site", AUD, "session", SESSION, "query", jm("from", "SFO"), "rank", "price_asc", "complete", true,
            "offers", jl(jm("offer_id", "A", "price", 100L, "cabin", "eco"), jm("offer_id", "B", "price", 150L, "cabin", "eco"), jm("offer_id", "C", "price", 90L, "cabin", "biz")),
            "issued_at", NOW - 1_000L, "kid", "s1")
        body.putAll(jm(*over))
        return signed(OracleFacts.OFFER_SET_DOMAIN, body, "wb/site")
    }
    private fun offersPolicy(maxAge: Long) = jm("offers", jm("name", "excess", "site_keys", jl(jm("kid", "s1", "pk", pub("wb/site"))), "max_age_ms", maxAge, "offer_param", "action.params.offer_id",
        "filter", jm("query", jm("from", "SFO"), "offer", jm("cabin", "eco"))))
    private fun decideOffers(os: Map<String, Any?>, pol: Map<String, Any?>, now: Any?, chosen: String) =
        OracleFacts.decideIntentWorld(jm("now", now, "aud", AUD, "session", SESSION, "action", action("offer_id", chosen),
            "committed", jm("offer_set", OracleFacts.offerSetRef(norm(os))), "offer_set", os, "policy", pol))

    @Test fun offerSets() {
        val ok = decideOffers(offerSet(), offersPolicy(60_000L), NOW, "B")
        assertTrue(ok.reason, ok.ok)
        assertEquals("50", ok.world!!["excess"].toString())
        assertEquals("0", decideOffers(offerSet(), offersPolicy(60_000L), NOW, "A").world!!["excess"].toString())
        assertFalse(decideOffers(offerSet(), offersPolicy(60_000L), NOW, "C").ok)
        assertFalse(decideOffers(offerSet(), offersPolicy(60_000L), NOW, "Z").ok)
        assertTrue(decideOffers(offerSet(), offersPolicy(1_000L), NOW, "A").ok)
        assertFalse(decideOffers(offerSet(), offersPolicy(999L), NOW, "A").ok)
        assertFalse(decideOffers(offerSet(), offersPolicy(60_000L), NOW.toString(), "A").ok)
        assertFalse(decideOffers(offerSet("complete", false), offersPolicy(60_000L), NOW, "A").ok)
        assertFalse(decideOffers(offerSet("site", "other.example"), offersPolicy(60_000L), NOW, "A").ok)
        assertFalse(decideOffers(offerSet("query", jm("from", "SFO", "to", "JFK")), offersPolicy(60_000L), NOW, "A").ok)
        assertTrue(decideOffers(offerSet("query", jm()), offersPolicy(60_000L), NOW, "A").ok)
        assertFalse(decideOffers(offerSet("issued_at", NOW + 60_001L), offersPolicy(120_000L), NOW, "A").ok)
        assertTrue(decideOffers(offerSet("issued_at", NOW + 60_000L), offersPolicy(120_000L), NOW, "A").ok)
        assertFalse(OracleFacts.offerMatches(jm("x", 2L), jm("x", "2")))
        assertTrue(OracleFacts.offerMatches(jm("x", 2L), jm("x", Json.Num("2"))))
    }

    // ---- rule 17 ----
    private fun labels(site: String, kid: String, key: String, fields: Map<String, Any?>) =
        signed(ParamProvenance.LABELS_DOMAIN, jm("v", 1L, "kind", "pca-labels", "site", site, "session", SESSION, "response_digest", b64seed("wb/resp"), "fields", fields, "issued_at", NOW, "kid", kid), key)
    private fun prov(params: Map<String, Any?>, prov: Map<String, Any?>, receipts: List<Any?>, policy: Map<String, Any?>): ParamProvenance.ProvResult {
        val committed = receipts.map { ParamProvenance.labelsRef(norm(it)) }
        return ParamProvenance.decide(jm("aud", AUD, "session", SESSION, "action", jm("params", params), "prov", prov, "committed_labels", committed, "labels", receipts, "policy", policy))
    }

    @Test fun provenance() {
        val reg = jm("vouched", "trusted", "fp", "first_party", "web", "web")
        val pol = jm("params", jm("action.params.offer_id", "material", "action.params.total", "critical"), "registry", reg)
        val pass = prov(jm("offer_id", "A", "total", 5L), jm("action.params.offer_id", jl("fp"), "action.params.total", jl("vouched")), jl(), pol)
        assertEquals(pass.reason, "pass", pass.outcome)
        assertEquals("first_party", pass.labels["action.params.offer_id"])
        val q = prov(jm("offer_id", "A", "total", 5L), jm("action.params.offer_id", jl("web"), "action.params.total", jl("vouched")), jl(), pol)
        assertEquals("question", q.outcome)
        assertEquals("tap", q.friction)
        assertEquals("typed", prov(jm("offer_id", "A", "total", 5L), jm("action.params.offer_id", jl("fp"), "action.params.total", jl("web")), jl(), pol).friction)
        assertEquals("agent", prov(jm("offer_id", "A", "total", 5L), jm("action.params.offer_id", jl("fp")), jl(), pol).labels["action.params.total"])
        assertEquals("web", prov(jm("offer_id", "A"), jm("action.params.offer_id", jl("fp", "web")), jl(), jm("params", jm(), "registry", reg)).labels["action.params.offer_id"])
        assertEquals("agent", prov(jm("offer_id", "A"), jm("action.params.offer_id", jl("constructor")), jl(), jm("params", jm(), "registry", reg)).labels["action.params.offer_id"])
        val strict = LinkedHashMap(pol).also { it["critical_max"] = "first_party" }
        assertEquals("deny", prov(jm("offer_id", "A", "total", 5L), jm("action.params.offer_id", jl("fp"), "action.params.total", jl("web")), jl(), strict).outcome)
        val allow = LinkedHashMap(pol).also { it["material_tainted"] = "allow" }
        assertEquals("pass", prov(jm("offer_id", "A", "total", 5L), jm("action.params.offer_id", jl("web"), "action.params.total", jl("vouched")), jl(), allow).outcome)
        val bad = LinkedHashMap(pol).also { it["critical_tainted"] = "allow" }
        assertEquals("deny", prov(jm("offer_id", "A"), jm(), jl(), bad).outcome)
        assertEquals("deny", prov(jm(), jm("action.params.offer_id", jl("fp")), jl(), pol).outcome)
        assertEquals("deny", prov(jm("constructor", "x"), jm("action.params.constructor", jl("fp")), jl(), jm("params", jm())).outcome)
    }

    @Test fun labelReceiptsAndFlows() {
        val keys = jm("params", jm("action.params.offer_id", "material"), "label_keys", jl(jm("site", AUD, "kid", "k1", "pk", pub("wb/site")), jm("site", "gov.example", "kid", "g1", "pk", pub("wb/gov"))))
        val mine = labels(AUD, "k1", "wb/site", jm("offer", jm("class", "pii.contact", "value_digest", IntentJs.hashCanonical("A"))))
        val ref = "pca-labels:" + ParamProvenance.labelsRef(norm(mine)) + "#offer"
        val fp = prov(jm("offer_id", "A"), jm("action.params.offer_id", jl(ref)), jl(mine), keys)
        assertEquals(fp.reason, "pass", fp.outcome)
        assertEquals("first_party", fp.labels["action.params.offer_id"])
        assertEquals(listOf("pii.contact"), fp.classes["action.params.offer_id"])
        assertEquals("question", prov(jm("offer_id", "B"), jm("action.params.offer_id", jl(ref)), jl(mine), keys).outcome)
        val gov = labels("gov.example", "g1", "wb/gov", jm("offer", jm("class", "pii.contact", "value_digest", IntentJs.hashCanonical("A"))))
        val gref = "pca-labels:" + ParamProvenance.labelsRef(norm(gov)) + "#offer"
        assertEquals("deny", prov(jm("offer_id", "A"), jm("action.params.offer_id", jl(gref)), jl(gov), keys).outcome)
        val flows = LinkedHashMap(keys).also { it["flows"] = jm("pii.*", jl(AUD)) }
        assertEquals("question", prov(jm("offer_id", "A"), jm("action.params.offer_id", jl(gref)), jl(gov), flows).outcome)
        val narrower = LinkedHashMap(keys).also { it["flows"] = jm("pii.*", jl(AUD), "pii.contact", jl("x.example")) }
        assertEquals("deny", prov(jm("offer_id", "A"), jm("action.params.offer_id", jl(gref)), jl(gov), narrower).outcome)
        assertEquals("deny", prov(jm("offer_id", "A"), jm("action.params.offer_id", jl(ref.replace("#offer", "#nope"))), jl(mine), keys).outcome)
        assertEquals("deny", prov(jm("offer_id", "A"), jm("action.params.offer_id", jl(ref.replace("#offer", "#"))), jl(mine), keys).outcome)
        assertEquals("deny", ParamProvenance.decide(jm("aud", AUD, "session", SESSION, "action", jm("params", jm("offer_id", "A")),
            "prov", jm("action.params.offer_id", jl(ref)), "committed_labels", jl(), "labels", jl(mine), "policy", keys)).outcome)
        assertEquals("deny", ParamProvenance.decide(jm("aud", AUD, "session", b64seed("wb/other"), "action", jm("params", jm("offer_id", "A")),
            "prov", jm("action.params.offer_id", jl(ref)), "committed_labels", jl(ParamProvenance.labelsRef(norm(mine))), "labels", jl(mine), "policy", keys)).outcome)
        val rules = jm("pii.*", jl("a"), "pii.contact.*", jl("b"), "*", jl("c"))
        assertEquals("pii.contact.*", ParamProvenance.flowRuleFor(rules, "pii.contact.email"))
        assertEquals("pii.*", ParamProvenance.flowRuleFor(rules, "pii.contact"))
        assertEquals("*", ParamProvenance.flowRuleFor(rules, "piix"))
        assertTrue(ParamProvenance.flowAllowed(jm(), "x", "o", "o"))
        assertTrue(ParamProvenance.flowAllowed(jm(), "public", "o", "a"))
        assertFalse(ParamProvenance.flowAllowed(jm(), "x", "o", "a"))
    }

    @Test fun readPurpose() {
        val fields = jl(jm("path", "passengers[].name", "class", "pii.identity"), jm("path", "passengers[].email", "class", "pii.contact", "optional", true),
            jm("path", "loyalty", "class", "internal", "optional", true), jm("path", "fares", "class", "public"))
        val cov = jm("booking", jl("pii.identity", "itinerary"), "support", jl("pii.*", "internal"), "comparison", jl())
        val b = ParamProvenance.decideReadPurpose(jm("fields", fields, "purpose", "booking", "coverage", cov))
        assertEquals("allow", b.outcome)
        assertEquals(listOf("loyalty", "passengers[].email"), b.minimise)
        assertEquals("question", ParamProvenance.decideReadPurpose(jm("fields", fields, "purpose", "comparison", "coverage", cov)).outcome)
        assertEquals("deny", ParamProvenance.decideReadPurpose(jm("fields", fields, "purpose", "comparison", "coverage", cov, "on_uncovered", "deny")).outcome)
        assertEquals(listOf("passengers[].name"), ParamProvenance.decideReadPurpose(jm("fields", fields, "purpose", "constructor", "coverage", cov)).uncovered)
        assertEquals("allow", ParamProvenance.decideReadPurpose(jm("fields", fields, "purpose", "support", "coverage", cov)).outcome)
        for (bad in listOf(jm("fields", null, "purpose", "booking", "coverage", cov), jm("fields", fields, "purpose", null, "coverage", cov),
            jm("fields", fields, "purpose", "booking", "coverage", jm("booking", "x")), jm("fields", jl(jm("path", "x", "class", "c", "optional", null)), "purpose", "booking", "coverage", cov),
            jm("fields", fields, "purpose", "booking", "coverage", cov, "on_uncovered", "allow"))) {
            val r = ParamProvenance.decideReadPurpose(bad)
            assertEquals("deny", r.outcome)
            assertTrue(r.minimise.isEmpty() && r.uncovered.isEmpty())
        }
        // UTF-8 byte order: U+FFFD before U+1F600 (UTF-16 order would invert them)
        val u = ParamProvenance.decideReadPurpose(jm("fields", jl(jm("path", "z😀", "class", "s"), jm("path", "z�", "class", "s")), "purpose", "p", "coverage", jm()))
        assertEquals(listOf("z�", "z😀"), u.uncovered)
    }

    // ---- rule 18 ----
    private fun verdict(classifier: String, label: String, measurement: String, key: String, content: Any?) =
        signed(IntentClassifier.INTENT_CLASSIFIER_DOMAIN, jm("v", 1L, "kind", "pca-intent-classification", "classifier", classifier, "session", SESSION,
            "content_digest", IntentJs.hashCanonical(content), "label", label, "measurement", measurement, "judge", pub(key)), key)
    private fun classify(verdicts: List<Any?>, k: Long, measurements: Any?): IntentClassifier.ClassResult {
        val c = jm("id", "tone", "param", "action.params.body", "labels", jl("apologetic", "neutral"), "keys", jl(pub("wb/j1"), pub("wb/j2"), pub("wb/j3")), "k", k)
        if (measurements != null) c["measurements"] = measurements
        val committed = verdicts.map { IntentClassifier.verdictRef(norm(it)) }
        return IntentClassifier.decide(jm("session", SESSION, "action", jm("params", jm("body", "sorry")), "committed", committed, "verdicts", verdicts, "policy", jm("classifiers", jl(c))))
    }

    @Test fun classifiers() {
        val a1 = verdict("tone", "apologetic", "m1", "wb/j1", "sorry")
        val a2 = verdict("tone", "apologetic", "m1", "wb/j2", "sorry")
        val n3 = verdict("tone", "neutral", "m1", "wb/j3", "sorry")
        val r = classify(jl(a1, a2, n3), 2, null)
        assertTrue(r.reason, r.ok)
        assertEquals("apologetic", r.classes!!["tone"])
        assertFalse(classify(jl(a1, n3), 2, null).ok)
        assertFalse(classify(jl(a1, n3), 1, null).ok)
        assertTrue(classify(jl(a1), 1, null).ok)
        assertFalse(classify(jl(a1), 4, null).ok)
        assertFalse(classify(jl(a1), 0, null).ok)
        assertFalse(classify(jl(a1, verdict("tone", "apologetic", "m1", "wb/j1", "sorry")), 1, null).ok)
        assertFalse(classify(jl(a1, verdict("tone", "neutral", "m1", "wb/j1", "sorry")), 1, null).ok)
        assertFalse(classify(jl(verdict("tone", "apologetic", "m1", "wb/stranger", "sorry")), 1, null).ok)
        assertFalse(classify(jl(verdict("tone", "apologetic", "m1", "wb/j1", "other")), 1, null).ok)
        assertFalse(classify(jl(verdict("tone", "angry", "m1", "wb/j1", "sorry")), 1, null).ok)
        assertTrue(classify(jl(a1), 1, jl("m1")).ok)
        assertFalse(classify(jl(a1), 1, jl("m2")).ok)
        assertFalse(classify(jl(a1), 1, "m1").ok)
        val c = jm("id", "tone", "param", "action.params.body", "labels", jl("constructor", "toString"), "keys", jl(pub("wb/j1")), "k", 1L)
        val v = verdict("tone", "constructor", "m1", "wb/j1", "sorry")
        val proto = IntentClassifier.decide(jm("session", SESSION, "action", jm("params", jm("body", "sorry")),
            "committed", jl(IntentClassifier.verdictRef(norm(v))), "verdicts", jl(v), "policy", jm("classifiers", jl(c))))
        assertTrue(proto.reason, proto.ok)
        assertEquals("constructor", proto.classes!!["tone"])
    }

    // ---- the unit and activity ----
    @Test fun activityIsStrictlyTyped() {
        assertArrayEquals(booleanArrayOf(false, false, false), IntentWB.active(jm("intent_session", jm(), "policy", jm())))
        assertArrayEquals(booleanArrayOf(true, true, true), IntentWB.active(jm("intent_session", jm("facts", jl(SESSION), "prov", jm(), "classes", jl(SESSION)), "policy", jm())))
        assertArrayEquals(booleanArrayOf(false, true, false), IntentWB.active(jm("intent_session", jm("facts", jl(), "prov", null, "classes", jl()), "policy", jm())))
        assertArrayEquals(booleanArrayOf(true, false, false), IntentWB.active(jm("intent_session", jm("offer_set", SESSION), "policy", jm())))
        assertArrayEquals(booleanArrayOf(false, false, false), IntentWB.active(jm("intent_session", jm("offer_set", 1L, "labels", jl()), "policy", jm())))
        assertArrayEquals(booleanArrayOf(false, false, false), IntentWB.active(jm("intent_session", jm(), "policy",
            jm("world", jm("worlds", jm("length", 1L), "offers", jl()), "provenance", jl(), "classifiers", jm("length", 1L)))))
        assertArrayEquals(booleanArrayOf(true, true, true), IntentWB.active(jm("intent_session", jm(), "policy",
            jm("world", jm("offers", jm()), "provenance", jm(), "classifiers", jl(jm())))))
    }

    @Test fun unitOrder() {
        val r = IntentWB.decide(jm("now", NOW, "aud", AUD, "session", SESSION, "action", action(), "intent_session", jm(),
            "policy", jm("world", jm("worlds", jl(jm())), "provenance", jm("params", jm()), "classifiers", jl(jm()))))
        assertEquals("deny", r.outcome)
        assertEquals(listOf("facts"), r.checks.keys.toList())
        val pol = jm("provenance", jm("params", jm("action.params.x", "material")), "classifiers", jl(jm()))
        val q = IntentWB.decide(jm("now", NOW, "aud", AUD, "session", SESSION, "action", action("x", "1"), "intent_session", jm(), "policy", pol))
        assertEquals(listOf("provenance", "classes"), q.checks.keys.toList())
        assertEquals("question", q.checks["provenance"])
        assertEquals("fail", q.checks["classes"])
    }
}
