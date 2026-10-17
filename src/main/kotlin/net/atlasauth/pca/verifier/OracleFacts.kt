package net.atlasauth.pca.verifier

import java.math.BigInteger

/**
 * Rule 16: intent world facts, relational dimensions and offer sets (packages/pca/src/oracle-facts.ts
 * `decideIntentWorld` and offer-set.ts `decideOfferSet`). The verifier computes `env.world`; the agent only commits the
 * artifacts (`intent_session.facts` / `offer_set`). First failure wins, every failure is `ok: false`; never throws.
 */
object OracleFacts {
    const val FACT_DOMAIN = "atlas-pca/fact/v1\u0000"
    const val FACT_REF_DOMAIN = "atlas-pca/fact-ref/v1"
    const val OFFER_SET_DOMAIN = "atlas-pca/offer-set/v1\u0000"
    const val OFFER_SET_REF_DOMAIN = "atlas-pca/offer-set-ref/v1"
    const val MAX_COMMITTED_FACTS = 16
    const val MAX_WORLDS = 16
    const val MAX_RELATIONAL = 16
    const val DEFAULT_WORLD_SKEW_MS = 60_000L
    const val MAX_OFFERS = 256
    const val MAX_OFFER_ATTRS = 32
    const val MAX_QUERY_KEYS = 32
    private val MAX_SAFE_BIG: BigInteger = BigInteger.valueOf(9007199254740991L)

    /** The rule-16 verdict: `world` (world names, then relational names, then the offers name) and `singleSource`. */
    class WorldResult internal constructor(
        val ok: Boolean,
        val reason: String?,
        val world: Map<String, Any?>?,
        val singleSource: List<String>?,
    ) {
        internal companion object {
            fun fail(reason: String) = WorldResult(false, "facts: $reason", null, null)
        }
    }

    // ---- wire ----
    internal fun validateFactWire(fo: Any?): String? {
        if (fo !is Map<*, *>) return "fact must be an object"
        val f = IntentJs.obj(fo)
        val m = IntentArtifacts.closedMembers(f, listOf("v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig"), IntentArtifacts.SUITE_MEMBERS, "fact")
        if (m != null) return m
        if (!isOne(f["v"]) || "pca-fact" != f["kind"]) return "fact must be {v: 1, kind: \"pca-fact\"}"
        if (!IntentArtifacts.isName(f["name"])) return "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$"
        if (!IntentArtifacts.isBoundedString(f["subject"], 256)) return "'fact.subject' must be a non-empty string (<= 256 bytes)"
        if (!IntentJs.isInt(f["value"]) && !IntentArtifacts.isBoundedString(f["value"], 256)) return "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)"
        if (!IntentJs.isInt(f["t_obs"]) || IntentJs.num(f["t_obs"])!! < 0) return "'fact.t_obs' must be a non-negative safe integer"
        if (!IntentArtifacts.isBoundedString(f["oracle"], 64)) return "'fact.oracle' must be a non-empty string (<= 64 bytes)"
        if (f["sig"] !is String) return "'fact.sig' must be a string"
        return null
    }

    /** `x === 1` for a JSON number. */
    internal fun isOne(v: Any?): Boolean = IntentJs.num(v) == 1.0

    fun factRef(f: Map<String, Any?>): String = IntentArtifacts.artifactRef(FACT_REF_DOMAIN, "f", f)
    fun offerSetRef(o: Map<String, Any?>): String = IntentArtifacts.artifactRef(OFFER_SET_REF_DOMAIN, "o", o)

    internal fun ratioPpm(a: Long, b: Long): Long? {
        if (b <= 0 || a < 0) return null
        val q = BigInteger.valueOf(a).multiply(BigInteger.valueOf(1_000_000L)).divide(BigInteger.valueOf(b))
        return if (q <= MAX_SAFE_BIG) q.toLong() else null
    }

    /** A non-empty ARRAY (strict typing: nothing else makes a check active). */
    internal fun nonEmpty(x: Any?): Boolean = x is List<*> && x.isNotEmpty()

    private fun nonNegInt(o: Any?): Boolean = IntentJs.isInt(o) && IntentJs.num(o)!! >= 0

    // ---- policy ----
    internal fun validateWorldPolicy(po: Any?): String? {
        if (po !is Map<*, *>) return "world policy must be an object"
        val p = IntentJs.obj(po)
        val cm = IntentArtifacts.closedMembers(p, listOf(), listOf("skew_ms", "worlds", "relational", "offers"), "policy")
        if (cm != null) return cm
        if (p.containsKey("skew_ms") && !nonNegInt(p["skew_ms"])) return "skew_ms must be a non-negative safe integer"
        val names = HashSet<String>()
        val worldsO = IntentJs.opt(p, "worlds", listOf<Any?>())
        if (worldsO !is List<*> || worldsO.size > MAX_WORLDS) return "worlds must be a list of at most $MAX_WORLDS"
        for (wo in worldsO) {
            if (wo !is Map<*, *>) return "world entry must be an object"
            val w = IntentJs.obj(wo)
            val wm = IntentArtifacts.closedMembers(w, listOf("name", "subject_path", "oracles", "freshness_ms", "min_oracles", "max_faulty"), listOf(), "world")
            if (wm != null) return wm
            val e = claim(names, w["name"])
            if (e != null) return e
            val n = w["name"].toString()
            val sp = w["subject_path"]
            if (sp !is String || !sp.startsWith("action.")) return "world '$n': subject_path must be rooted at action."
            if (!nonNegInt(w["freshness_ms"])) return "world '$n': freshness_ms must be a non-negative safe integer"
            if (!nonNegInt(w["max_faulty"])) return "world '$n': max_faulty must be a non-negative safe integer"
            if (!IntentJs.isInt(w["min_oracles"]) || IntentJs.num(w["min_oracles"])!! < 2 * IntentJs.num(w["max_faulty"])!! + 1)
                return "world '$n': min_oracles must be a safe integer >= 2*max_faulty+1"
            val oracles = w["oracles"]
            if (oracles !is List<*> || oracles.size < IntentJs.num(w["min_oracles"])!!) return "world '$n': fewer pinned oracles than min_oracles"
            val kids = HashSet<String>()
            for (o in oracles) {
                if (o !is Map<*, *> || IntentArtifacts.closedMembers(IntentJs.obj(o), listOf("kid", "pk"), listOf("pq_pk"), "oracle") != null ||
                    !IntentArtifacts.isBoundedString(o["kid"], 64) || !IntentArtifacts.isDigest(o["pk"]) ||
                    !IntentArtifacts.pinPqOk(o) || (o["kid"] as String) in kids
                ) return "world '$n': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
                kids.add(o["kid"] as String)
            }
        }
        val relO = IntentJs.opt(p, "relational", listOf<Any?>())
        if (relO !is List<*> || relO.size > MAX_RELATIONAL) return "relational must be a list of at most $MAX_RELATIONAL"
        for (ro in relO) {
            if (ro !is Map<*, *>) return "relational entry must be an object"
            val r = IntentJs.obj(ro)
            val rm = IntentArtifacts.closedMembers(r, listOf("name", "fn", "a", "b"), listOf(), "relational")
            if (rm != null) return rm
            val e = claim(names, r["name"])
            if (e != null) return e
            val n = r["name"] as String
            if ("sub" != r["fn"] && "ratio_ppm" != r["fn"]) return "relational '$n': fn must be \"sub\" or \"ratio_ppm\""
            for (op in listOf(r["a"], r["b"])) {
                var ok = IntentArtifacts.isParamPath(op)
                if (!ok && op is String && op.startsWith("env.world.")) {
                    val rest = op.substring("env.world.".length)
                    ok = rest in names && rest != n
                }
                if (!ok) return "relational '$n': operand '$op' must be an action.params path or an earlier env.world dimension"
            }
        }
        if (p.containsKey("offers")) {
            var e = validateOfferPolicy(p["offers"])
            if (e == null) e = claim(names, (p["offers"] as Map<*, *>)["name"])
            if (e != null) return e
        }
        return null
    }

    private fun claim(names: MutableSet<String>, n: Any?): String? {
        if (!IntentArtifacts.isName(n)) return "dimension name '$n' must match ^[a-z][a-z0-9_]{0,63}$"
        if (n in names) return "duplicate dimension name '$n'"
        names.add(n as String)
        return null
    }

    internal fun validateOfferPolicy(po: Any?): String? {
        if (po !is Map<*, *>) return "offers policy must be an object"
        val p = IntentJs.obj(po)
        val cm = IntentArtifacts.closedMembers(p, listOf("name", "site_keys", "max_age_ms", "offer_param", "filter"), listOf(), "offers")
        if (cm != null) return cm
        if (p["name"] !is String) return "offers policy needs a name"
        val siteKeys = p["site_keys"]
        if (siteKeys !is List<*> || siteKeys.isEmpty()) return "offers policy needs at least one pinned site key"
        val kids = HashSet<String>()
        for (k in siteKeys) {
            if (k !is Map<*, *> || IntentArtifacts.closedMembers(IntentJs.obj(k), listOf("kid", "pk"), listOf("pq_pk"), "site_key") != null ||
                !IntentArtifacts.isBoundedString(k["kid"], 64) || !IntentArtifacts.isDigest(k["pk"]) ||
                !IntentArtifacts.pinPqOk(k) || (k["kid"] as String) in kids
            ) return "offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk"
            kids.add(k["kid"] as String)
        }
        if (!nonNegInt(p["max_age_ms"])) return "offers policy: max_age_ms must be a non-negative safe integer"
        val offerParam = p["offer_param"]
        if (offerParam !is String || !offerParam.startsWith("action.params.")) return "offers policy: offer_param must be an action.params.* path"
        val f = p["filter"]
        if (f !is Map<*, *> || IntentArtifacts.closedMembers(IntentJs.obj(f), listOf("query", "offer"), listOf(), "filter") != null ||
            f["query"] !is Map<*, *> || f["offer"] !is Map<*, *>
        ) return "offers policy: filter must be exactly {query: {}, offer: {}}"
        for (v in (f["query"] as Map<*, *>).values) if (!IntentArtifacts.isScalar(v)) return "offers policy: filter values must be scalars"
        for (v in (f["offer"] as Map<*, *>).values) if (!IntentArtifacts.isScalar(v)) return "offers policy: filter values must be scalars"
        return null
    }

    /**
     * True iff rule 16 is active: `facts` a non-empty array, `offer_set` a string, `worlds` / `relational` a non-empty
     * array, or `offers` a plain object.
     */
    fun intentWorldActive(committed0: Any?, policy0: Any?): Boolean {
        val committed = if (committed0 is Map<*, *>) committed0 else emptyMap<String, Any?>()
        val policy = if (policy0 is Map<*, *>) policy0 else emptyMap<String, Any?>()
        return nonEmpty(committed["facts"]) || committed["offer_set"] is String ||
            nonEmpty(policy["worlds"]) || nonEmpty(policy["relational"]) || policy["offers"] is Map<*, *>
    }

    /** `o.k` with JavaScript semantics: a property read on null / undefined throws. */
    private fun prop(o: Any?, k: String): Any? {
        if (o == null) throw IllegalArgumentException("cannot read '$k' of null")
        return IntentJs.get(o, k)
    }

    private fun subjectOf(action: Any?, path: String): String? {
        if (path == "action.resource") return prop(action, "resource") as? String
        if (path == "action.verb") return prop(action, "verb") as? String
        if (action == null) throw IllegalArgumentException("no action")
        val r = IntentArtifacts.resolveParamPath(IntentArtifacts.actionParams(action), path)
        return if (r.found) r.value as? String else null
    }

    /** The `primitives.intent_world` entry point: normalizes `input`, then [decide]. */
    fun decideIntentWorld(input: Any?): WorldResult = try {
        decide(IntentJs.obj(IntentJs.normalize(input)))
    } catch (e: RuntimeException) {
        WorldResult.fail("evaluation error (fail closed): " + e.javaClass.simpleName)
    }

    /** Rule 16 over an already normalized input `{now, aud, session, action, committed, facts?, offer_set?, policy}`. */
    internal fun decide(input: Map<String, Any?>): WorldResult {
        try {
            val policyO = IntentJs.opt(input, "policy", LinkedHashMap<String, Any?>())
            val pe = validateWorldPolicy(policyO)
            if (pe != null) return WorldResult.fail("policy misconfigured (fail closed): $pe")
            val policy = IntentJs.obj(policyO)
            // CLOCK: a `now` that is not a safe integer is never coerced: every fact and every offer set is stale
            val clock = IntentJs.isInt(input["now"])
            val now = if (clock) IntentJs.num(input["now"])!! else Double.NaN
            val skew = if (policy.containsKey("skew_ms")) IntentJs.num(policy["skew_ms"])!! else DEFAULT_WORLD_SKEW_MS.toDouble()
            if (input["action"] !is Map<*, *>) return WorldResult.fail("action must be an object")
            if (IntentJs.opt(input["action"], "params", emptyMap<String, Any?>()) !is Map<*, *>) return WorldResult.fail("action.params must be an object")
            val committed = IntentJs.opt(input, "committed", LinkedHashMap<String, Any?>())
            if (committed !is Map<*, *>) return WorldResult.fail("committed must be an object")
            val committedFacts = IntentJs.opt(committed, "facts", listOf<Any?>())
            if (committedFacts !is List<*> || committedFacts.size > MAX_COMMITTED_FACTS)
                return WorldResult.fail("committed facts must be a list of at most $MAX_COMMITTED_FACTS digests")
            val seen = HashSet<String>()
            for (d in committedFacts) {
                if (!IntentArtifacts.isDigest(d)) return WorldResult.fail("a committed fact digest is not canonical base64url (32 bytes)")
                if (!seen.add(d as String)) return WorldResult.fail("duplicate committed fact digest")
            }
            val offerCommitted = IntentJs.own(committed, "offer_set")
            val committedOffer = IntentJs.get(committed, "offer_set")
            if (offerCommitted && !IntentArtifacts.isDigest(committedOffer)) return WorldResult.fail("the committed offer_set is not canonical base64url (32 bytes)")

            val supplied = IntentJs.opt(input, "facts", listOf<Any?>())
            if (supplied !is List<*>) return WorldResult.fail("facts must be an array")
            if (input.containsKey("offer_set") && input["offer_set"] !is Map<*, *>) return WorldResult.fail("offer_set must be an object")
            val byRef = HashMap<String, Map<String, Any?>>()
            for (f in IntentArtifacts.iterable(supplied)) {
                if (validateFactWire(f) != null) continue
                try { byRef[factRef(IntentJs.obj(f))] = IntentJs.obj(f) } catch (e: RuntimeException) { /* no reference */ }
            }
            val worlds = IntentJs.opt(policy, "worlds", listOf<Any?>()) as List<*>
            val accepted = ArrayList<Map<String, Any?>>()
            val pairs = HashSet<String>()
            for (d in committedFacts) {
                val fact = byRef[d] ?: return WorldResult.fail("a committed fact was not supplied (or is malformed)")
                val se = IntentArtifacts.artifactSuiteError(fact)
                if (se != null) return WorldResult.fail("fact signature suite: $se")
                val w = worlds.firstOrNull { fact["name"] == IntentJs.get(it, "name") }?.let { IntentJs.obj(it) }
                    ?: return WorldResult.fail("fact for undeclared world '${fact["name"]}'")
                val pin = (w["oracles"] as List<*>).firstOrNull { fact["oracle"] == IntentJs.get(it, "kid") }?.let { IntentJs.obj(it) }
                    ?: return WorldResult.fail("oracle '${fact["oracle"]}' is not pinned for world '${w["name"]}'")
                if (!IntentArtifacts.verifyArtifactSig(FACT_DOMAIN, fact, pin["pk"], pin["pq_pk"])) return WorldResult.fail("bad oracle signature on a '${w["name"]}' fact")
                val subject = subjectOf(input["action"], w["subject_path"] as String)
                if (subject == null || fact["subject"] != subject) return WorldResult.fail("a '${w["name"]}' fact names another subject")
                val pair = "${w["name"]}\u0000${fact["oracle"]}"
                if (!pairs.add(pair)) return WorldResult.fail("two facts from oracle '${fact["oracle"]}' for world '${w["name"]}'")
                accepted.add(fact)
            }

            val world = LinkedHashMap<String, Any?>()
            val singleSource = ArrayList<String>()
            for (wo in worlds) {
                val w = IntentJs.obj(wo)
                val name = w["name"] as String
                val freshness = IntentJs.num(w["freshness_ms"])!!
                val fresh = ArrayList<Map<String, Any?>>()
                for (f in accepted) {
                    val t = IntentJs.num(f["t_obs"])!!
                    if (clock && name == f["name"] && t <= now + skew && now - t <= freshness) fresh.add(f)
                }
                val minOracles = IntentJs.num(w["min_oracles"])!!
                if (fresh.size < minOracles) return WorldResult.fail("world '$name' has ${fresh.size} fresh fact(s), needs ${IntentJs.lng(w["min_oracles"])}")
                val nums = ArrayList<Long>()
                for (f in fresh) if (IntentJs.isNumber(f["value"])) nums.add(IntentJs.lng(f["value"]))
                if (nums.size == fresh.size) {
                    nums.sort()
                    world[name] = IntentJs.ofLong(nums[(nums.size - 1) / 2])
                } else if (nums.isEmpty()) {
                    val v = fresh[0]["value"]
                    for (f in fresh) if (v != f["value"]) return WorldResult.fail("world '$name': string facts disagree")
                    world[name] = v
                } else return WorldResult.fail("world '$name': facts mix integer and string values")
                if (minOracles == 1.0) singleSource.add(name)
            }

            val rel = IntentJs.opt(policy, "relational", listOf<Any?>()) as List<*>
            for (ro in rel) {
                val r = IntentJs.obj(ro)
                val a = operand(world, input, r["a"] as String)
                val b = operand(world, input, r["b"] as String)
                if (a == null || b == null) return WorldResult.fail("relational '${r["name"]}': an operand is missing or not a safe integer")
                val v = if ("sub" == r["fn"]) a - b else ratioPpm(a, b)
                if (v == null || Math.abs(v) > 9007199254740991L) return WorldResult.fail("relational '${r["name"]}': result undefined or outside the safe integer range")
                world[r["name"] as String] = IntentJs.ofLong(v)
            }

            if (policy.containsKey("offers")) {
                val op = IntentJs.obj(policy["offers"])
                val od = decideOfferSet(
                    op, if (offerCommitted) committedOffer as String else null, input.containsKey("offer_set"), input["offer_set"],
                    actionParams(input), input["aud"], input["session"], clock, now, skew,
                )
                if (od.reason != null) return WorldResult.fail(od.reason)
                world[op["name"] as String] = IntentJs.ofLong(od.excess)
            }
            return WorldResult(true, null, world, singleSource)
        } catch (e: RuntimeException) {
            return WorldResult.fail("evaluation error (fail closed): " + e.javaClass.simpleName)
        }
    }

    /** `input.action.params ?? {}` (reading a member of a missing action throws, like JavaScript). */
    private fun actionParams(input: Map<String, Any?>): Any? {
        if (input["action"] == null) throw IllegalArgumentException("no action")
        return IntentArtifacts.actionParams(input["action"])
    }

    private fun operand(world: Map<String, Any?>, input: Map<String, Any?>, path: String): Long? {
        if (path.startsWith("env.world.")) {
            val v = world[path.substring("env.world.".length)]
            return if (IntentJs.isInt(v)) IntentJs.lng(v) else null
        }
        val r = IntentArtifacts.resolveParamPath(actionParams(input), path)
        return if (r.found && IntentJs.isInt(r.value)) IntentJs.lng(r.value) else null
    }

    // ---- offer sets ----
    internal fun validateOfferSetWire(oo: Any?): String? {
        if (oo !is Map<*, *>) return "offer set must be an object"
        val o = IntentJs.obj(oo)
        val m = IntentArtifacts.closedMembers(o, listOf("v", "kind", "site", "session", "query", "rank", "complete", "offers", "issued_at", "kid", "sig"), IntentArtifacts.SUITE_MEMBERS, "offer_set")
        if (m != null) return m
        if (!isOne(o["v"]) || "pca-offer-set" != o["kind"]) return "offer set must be {v: 1, kind: \"pca-offer-set\"}"
        if (!IntentArtifacts.isBoundedString(o["site"], 256)) return "'offer_set.site' must be a non-empty string (<= 256 bytes)"
        if (!IntentArtifacts.isDigest(o["session"])) return "'offer_set.session' must be canonical base64url (32 bytes)"
        val query = o["query"]
        if (query !is Map<*, *> || query.size > MAX_QUERY_KEYS) return "'offer_set.query' must be an object with <= $MAX_QUERY_KEYS keys"
        for ((k, v) in query) if (!IntentArtifacts.isBoundedString(k, 64) || !IntentArtifacts.isScalar(v)) return "'offer_set.query.$k' must be a scalar"
        if ("price_asc" != o["rank"]) return "'offer_set.rank' must be \"price_asc\""
        if (o["complete"] !is Boolean) return "'offer_set.complete' must be a boolean"
        val offers = o["offers"]
        if (offers !is List<*> || offers.isEmpty() || offers.size > MAX_OFFERS) return "'offer_set.offers' must hold 1..$MAX_OFFERS offers"
        val ids = HashSet<String>()
        for (i in offers.indices) {
            val of = offers[i]
            if (of !is Map<*, *>) return "offer $i must be an object"
            val x = IntentJs.obj(of)
            if (!IntentArtifacts.isBoundedString(x["offer_id"], 128)) return "offer $i: 'offer_id' must be a non-empty string (<= 128 bytes)"
            if (!ids.add(x["offer_id"] as String)) return "offer $i: duplicate offer_id"
            if (!nonNegInt(x["price"])) return "offer $i: 'price' must be a non-negative safe integer"
            val attrs = x.keys.count { it != "offer_id" && it != "price" }
            if (attrs > MAX_OFFER_ATTRS) return "offer $i: more than $MAX_OFFER_ATTRS attributes"
            for (k in x.keys) {
                if (k == "offer_id" || k == "price") continue
                if (!IntentArtifacts.isBoundedString(k, 64) || !IntentArtifacts.isScalar(x[k])) return "offer $i: attribute '$k' must be a scalar"
            }
        }
        if (!nonNegInt(o["issued_at"])) return "'offer_set.issued_at' must be a non-negative safe integer"
        if (!IntentArtifacts.isBoundedString(o["kid"], 64)) return "'offer_set.kid' must be a non-empty string (<= 64 bytes)"
        if (o["sig"] !is String) return "'offer_set.sig' must be a string"
        return null
    }

    internal fun offerMatches(offer: Map<*, *>, f: Map<*, *>): Boolean =
        f.entries.all { (k, v) -> offer.containsKey(k) && IntentArtifacts.scalarEq(offer[k], v) }

    internal fun queryCovers(query: Map<*, *>, fq: Map<*, *>): Boolean =
        query.entries.all { (k, v) -> fq.containsKey(k) && IntentArtifacts.scalarEq(fq[k], v) }

    /** An offer-set decision: a `reason` on failure, else the price `excess` over the cheapest matching offer. */
    internal class OfferDecision(val reason: String?, val excess: Long)

    private fun refuse(reason: String) = OfferDecision(reason, 0)

    internal fun decideOfferSet(
        policy: Map<String, Any?>, committed: String?, supplied: Boolean, o: Any?, params: Any?, aud: Any?,
        session: Any?, clock: Boolean, now: Double, skewMs: Double,
    ): OfferDecision {
        if (committed == null) return refuse("offers: the PCActn commits no offer set but the policy requires one")
        if (!supplied) return refuse("offers: the committed offer set was not supplied")
        val w = validateOfferSetWire(o)
        if (w != null) return refuse("offers: $w")
        val os = IntentJs.obj(o)
        val ref = try { offerSetRef(os) } catch (e: RuntimeException) { return refuse("offers: the offer set is not strictly canonical") }
        if (ref != committed) return refuse("offers: the supplied offer set does not match the committed reference")
        val se = IntentArtifacts.artifactSuiteError(os)
        if (se != null) return refuse("offers: signature suite: $se")
        val key = (policy["site_keys"] as List<*>).firstOrNull { os["kid"] == IntentJs.get(it, "kid") }?.let { IntentJs.obj(it) }
            ?: return refuse("offers: signing key '${os["kid"]}' is not pinned")
        if (!IntentArtifacts.verifyArtifactSig(OFFER_SET_DOMAIN, os, key["pk"], key["pq_pk"])) return refuse("offers: bad site signature")
        if (os["site"] != aud) return refuse("offers: the offer set was issued for another audience")
        if (os["session"] != session) return refuse("offers: the offer set is bound to another session")
        if (!clock) return refuse("offers: no usable clock (now must be a safe integer): the offer set counts as stale")
        val issued = IntentJs.num(os["issued_at"])!!
        if (issued > now + skewMs) return refuse("offers: the offer set is issued in the future")
        if (now - issued > IntentJs.num(policy["max_age_ms"])!!) return refuse("offers: the offer set is stale")
        if (os["complete"] != true) return refuse("offers: the offer set is not declared complete")
        val filter = policy["filter"] as Map<*, *>
        if (!queryCovers(os["query"] as Map<*, *>, filter["query"] as Map<*, *>)) return refuse("offers: the search was narrowed beyond the intent filter (coverage)")
        val id = IntentArtifacts.resolveParamPath(params, policy["offer_param"])
        if (!id.found || id.value !is String) return refuse("offers: the action names no offer id at the declared parameter")
        val chosen = (os["offers"] as List<*>).firstOrNull { id.value == (it as Map<*, *>)["offer_id"] } as Map<*, *>?
            ?: return refuse("offers: the chosen offer is not in the signed offer set")
        val fOffer = filter["offer"] as Map<*, *>
        if (!offerMatches(chosen, fOffer)) return refuse("offers: the chosen offer does not satisfy the intent filter")
        val price = IntentJs.lng(chosen["price"])
        var min = price
        for (x in os["offers"] as List<*>) {
            val px = IntentJs.lng((x as Map<*, *>)["price"])
            if (offerMatches(x, fOffer) && px < min) min = px
        }
        return OfferDecision(null, price - min)
    }
}
