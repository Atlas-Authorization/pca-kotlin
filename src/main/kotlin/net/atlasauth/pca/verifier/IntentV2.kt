package net.atlasauth.pca.verifier

/**
 * The Intent Layer v2 checks of the core verifier (packages/pca/src/intent-v2.ts `decideIntentV2`), in their normative
 * order after `intent` (rule 12): `schema` (rule 14) -> `intent_session` (rule 13) -> `layers` (V5) -> `accumulators`
 * (rule 15) -> `facts` / `provenance` / `classes` (rules 16-18, [IntentWB]).
 *
 * REPORTING: `schema` iff the PCActn carries `intent_session` or the policy sets `schema.closed_world: true`;
 * `intent_session` iff the PCActn carries it or `session.require` is true; `layers` iff the PCActn carries
 * `intent_session` and the verifier configured `layers`; `accumulators` iff the PCActn carries `intent_session`; the W-B
 * checks iff the PCActn carries `intent_session` and [IntentWB] reports them. Checks 1-4 are independent; the W-B checks
 * are one unit. A rule-17 `question` fails `provenance` with reason `intent_required: ...`. Within a check the FIRST
 * failing step wins. Never throws.
 */
object IntentV2 {
    /**
     * The verifier state the v2 checks read (verifier-held, never the agent's): `{policy?, params?, schema?: {docs, keys},
     * session?: {root?, grants?, revocation?}, layers?, wb?: {artifacts?, policy?}, acc?: {state?, monitors?, receipts?,
     * last_seq?, sequencer_keys?}}` as a JSON tree (the `context.intent_v2` object of the vectors).
     */
    class Context private constructor(
        internal val raw: Map<String, Any?>,
        /** False for a PRESENT context that is not a JSON object (null included): every reportable v2 check fails. */
        internal val wellFormed: Boolean,
    ) {
        /** A copy with `params` replaced (a host supplying the plaintext params it parsed from the request). */
        fun withParams(params: Any?): Context {
            val m = LinkedHashMap(raw)
            m["params"] = IntentJs.normalize(params)
            return Context(m, wellFormed)
        }

        internal fun get(vararg path: String): Any? {
            var cur: Any? = raw
            for (k in path) cur = IntentJs.get(cur, k)
            return cur
        }

        internal fun has(vararg path: String): Boolean {
            var cur: Any? = raw
            for (i in 0 until path.size - 1) cur = IntentJs.get(cur, path[i])
            return IntentJs.own(cur, path[path.size - 1])
        }

        companion object {
            /**
             * From the parsed JSON value of a PRESENT `intent_v2` member (normalized to binary64 number semantics). A
             * non-object (JSON null included) is a malformed context, never "no context": pass null only when the member is
             * absent.
             */
            fun fromJson(o: Any?): Context {
                val n = IntentJs.normalize(o)
                return if (n is Map<*, *>) Context(IntentJs.obj(n), true) else Context(LinkedHashMap(), false)
            }

            /** From raw JSON text (lenient parse); a non-object is a malformed context. */
            fun fromJsonText(text: String): Context = fromJson(Json.parseLenient(text))
        }
    }

    /** One reported v2 check. */
    class Check internal constructor(val name: String, val ok: Boolean, val reason: String?)

    /** The checks in reporting order and the verifier-computed predicate env (`canon`, `acc`, `mon`, `world`, `prov`, `class`). */
    class Decision {
        val checks: MutableList<Check> = ArrayList()
        val env: MutableMap<String, Any?> = LinkedHashMap()
    }

    /** True iff any v2 check would be reported. */
    fun active(p: Map<String, Any?>, ctx: Context?): Boolean = p.containsKey("intent_session") || closedWorld(ctx) || sessionRequired(ctx) || mapRequired(ctx)

    private fun mapRequired(ctx: Context?): Boolean = ctx != null && ctx.get("policy", "map", "require") == true

    /** The PCActn's `intent_session.map_form` is `"commit"` (rule 19). */
    private fun mapCommitted(p: Map<String, Any?>): Boolean = IntentJs.get(p["intent_session"], "map_form") == IntentMap.MAP_FORM_COMMIT

    private fun closedWorld(ctx: Context?): Boolean = ctx != null && ctx.get("policy", "schema", "closed_world") == true
    private fun sessionRequired(ctx: Context?): Boolean = ctx != null && ctx.get("policy", "session", "require") == true

    private fun isMap(o: Any?): Boolean = o is Map<*, *>
    private fun optMap(o: Any?, k: String): Boolean = !IntentJs.own(o, k) || isMap(IntentJs.get(o, k))
    private fun optList(o: Any?, k: String): Boolean = !IntentJs.own(o, k) || IntentJs.get(o, k) is List<*>

    /**
     * The verifier context is closed and typed at the top level (README "absent vs null" and "the v2 policy is closed and
     * typed"): a malformed member fails every reportable v2 check. Null = well-formed.
     */
    internal fun contextError(ctx: Context?): String? {
        if (ctx == null) return null
        if (!ctx.wellFormed) return "the v2 verifier context must be an object"
        val c = ctx.raw
        if (!optMap(c, "policy")) return "policy must be an object"
        if (c.containsKey("policy")) {
            val pr = IntentJs.obj(c["policy"])
            for (k in pr.keys) if (k != "session" && k != "schema" && k != "acc" && k != "map") return "policy: unknown member '$k'"
            if (!optMap(pr, "session")) return "policy.session must be an object"
            if (pr.containsKey("session")) {
                val o = IntentJs.obj(pr["session"])
                for (k in o.keys) if (k != "require" && k != "max_revocation_age_s") return "policy.session: unknown member '$k'"
                if (o.containsKey("require") && o["require"] !is Boolean) return "policy.session.require must be a boolean"
                if (o.containsKey("max_revocation_age_s") && !IntentJs.isNonNeg(o["max_revocation_age_s"])) return "policy.session.max_revocation_age_s must be a non-negative safe integer"
            }
            if (!optMap(pr, "schema")) return "policy.schema must be an object"
            if (pr.containsKey("schema")) {
                val o = IntentJs.obj(pr["schema"])
                for (k in o.keys) if (k != "closed_world") return "policy.schema: unknown member '$k'"
                if (o.containsKey("closed_world") && o["closed_world"] !is Boolean) return "policy.schema.closed_world must be a boolean"
            }
            if (!optMap(pr, "acc")) return "policy.acc must be an object"
            if (pr.containsKey("acc")) {
                val o = IntentJs.obj(pr["acc"])
                for (k in o.keys) if (k != "max_receipt_age_s" && k != "max_keyset_age_s") return "policy.acc: unknown member '$k'"
                for (k in listOf("max_receipt_age_s", "max_keyset_age_s"))
                    if (o.containsKey(k) && !IntentJs.isNonNeg(o[k])) return "policy.acc.$k must be a non-negative safe integer"
            }
            if (!optMap(pr, "map")) return "policy.map must be an object"
            if (pr.containsKey("map")) {
                val o = IntentJs.obj(pr["map"])
                for (k in o.keys) if (k != "require" && k != "max_residual_risk_ppm") return "policy.map: unknown member '$k'"
                if (o.containsKey("require") && o["require"] !is Boolean) return "policy.map.require must be a boolean"
                if (o.containsKey("max_residual_risk_ppm") && !IntentJs.isNonNeg(o["max_residual_risk_ppm"])) return "policy.map.max_residual_risk_ppm must be a non-negative safe integer"
            }
        }
        if (!optMap(c, "params")) return "params must be an object"
        for (k in listOf("schema", "session", "acc")) if (!optMap(c, k)) return "$k must be an object"
        if (!optMap(c, "map")) return "map must be an object"
        if (c.containsKey("map")) for (k in IntentJs.obj(c["map"]).keys) if (k != "disclosure") return "map: unknown member '$k'"
        if (c.containsKey("layers")) {
            if (!isMap(c["layers"])) return "layers must be an object"
            for ((k, v) in IntentJs.obj(c["layers"])) {
                if (k !in listOf("org", "site", "std")) return "layers: unknown member '$k'"
                if (!isMap(v) || IntentJs.get(v, "predicates") !is List<*>) return "layers.$k must be {predicates: [...]}"
            }
        }
        if (c.containsKey("wb")) {
            val wb = c["wb"]
            if (!isMap(wb)) return "wb must be an object"
            if (!optMap(wb, "artifacts")) return "wb.artifacts must be an object"
            if (IntentJs.own(wb, "artifacts")) {
                val a = IntentJs.get(wb, "artifacts")
                for (k in listOf("facts", "labels", "verdicts")) if (!optList(a, k)) return "wb.artifacts.$k must be an array"
                if (!optMap(a, "offer_set")) return "wb.artifacts.offer_set must be an object"
            }
            if (!optMap(wb, "policy")) return "wb.policy must be an object"
            if (IntentJs.own(wb, "policy")) {
                val p = IntentJs.get(wb, "policy")
                if (!optMap(p, "world") || !optMap(p, "provenance")) return "wb.policy.world / provenance must be objects"
                if (!optList(p, "classifiers")) return "wb.policy.classifiers must be an array"
            }
        }
        return null
    }

    private fun schemaCtxError(ctx: Context?): String? {
        if (ctx == null || !ctx.has("schema")) return null
        val sc = ctx.get("schema")
        if (!isMap(sc) || IntentJs.get(sc, "docs") !is List<*> || IntentJs.get(sc, "keys") !is List<*>) return "the schema context must be {docs: [...], keys: [...]}"
        return null
    }

    private fun sessionCtxError(ctx: Context?): String? {
        if (ctx == null || !ctx.has("session")) return null
        val se = ctx.get("session")
        if (!isMap(se)) return "the session context must be an object"
        if (!optList(se, "grants")) return "the session grants must be an array"
        if (!optMap(se, "revocation")) return "the session revocation evidence must be an object"
        if (!optMap(se, "revocation_last")) return "the tracked last revocation epoch must be an object"
        if (IntentJs.own(se, "pq_pins")) {
            val pp = IntentJs.get(se, "pq_pins")
            if (pp !is Map<*, *> || pp.values.any { it !is String }) return "the session pq_pins must be an object of strings"
        }
        return null
    }

    private fun accCtxError(ctx: Context?): String? {
        if (ctx == null || !ctx.has("acc")) return null
        val a = ctx.get("acc")
        if (!isMap(a)) return "the accumulator context must be an object"
        for (k in listOf("state", "monitors", "last_seq", "keyset_versions")) if (!optMap(a, k)) return "acc.$k must be an object"
        if (IntentJs.own(a, "keyset_versions")) for (v in IntentJs.obj(IntentJs.get(a, "keyset_versions")).values) IntentAcc.trackedKeySetError(v)?.let { return "acc.keyset_versions: $it" }
        for (k in listOf("receipts", "sequencer_keys")) if (!optList(a, k)) return "acc.$k must be an array"
        if (IntentJs.own(a, "last_seq")) for (v in IntentJs.obj(IntentJs.get(a, "last_seq")).values) if (!IntentJs.isNonNeg(v)) return "acc.last_seq values must be non-negative safe integers"
        return null
    }

    private fun cget(ctx: Context?, vararg path: String): Any? = ctx?.get(*path)

    private fun schemaDigestIs(d: Any?, want: Any?): Boolean = try { ActionSchema.digest(d) == want } catch (e: RuntimeException) { false }

    // ---- rule 14 ----
    private class Matched { var doc: Any? = null }

    private fun schemaStep(p: Map<String, Any?>, ctx: Context?, matched: Matched): String? {
        val ce = schemaCtxError(ctx)
        if (ce != null) return ce
        val docs = cget(ctx, "schema", "docs")
        if (docs !is List<*> || docs.isEmpty()) return "this verifier has no action schema configured"
        val doc: Any?
        if (p.containsKey("intent_session")) {
            val want = IntentJs.get(p["intent_session"], "schema")
            doc = docs.firstOrNull { schemaDigestIs(it, want) } ?: return "intent_session.schema names no schema this verifier accepts"
        } else doc = docs[0]
        val v = ActionSchema.verify(doc, ctx!!.get("schema", "keys"))
        if (v != null) return "schema does not verify: $v"
        if (IntentJs.get(doc, "aud") != p["aud"]) return "schema aud does not match the PCActn aud"
        val params = cget(ctx, "params")
        if (params !is Map<*, *>) return "no plaintext params to check against the schema (closed world needs them)"
        if (Pca.paramsDigest(params) != IntentJs.get(p["action"], "params_digest")) return "params do not hash to action.params_digest"
        val c = ActionSchema.conform(doc, verbOf(p), params)
        if (!c.ok) return "schema_violation: ${c.code}: ${c.reason}"
        matched.doc = doc
        return null
    }

    private fun verbOf(p: Map<String, Any?>): String = IntentRevocation.jsText(IntentJs.get(p["action"], "verb"), IntentJs.own(p["action"], "verb"))
    private fun resourceOf(p: Map<String, Any?>): String = IntentRevocation.jsText(IntentJs.get(p["action"], "resource"), IntentJs.own(p["action"], "resource"))

    // ---- the bound root (rules 13 and 15) ----
    private class Bound { var root: Map<String, Any?> = emptyMap() }

    private fun boundRoot(isn: Map<String, Any?>, ctx: Context?, now: Double, out: Bound): String? {
        if (ctx == null || !ctx.has("session", "root")) return "no session root for this session"
        val s = ctx.get("session", "root")
        // a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals
        val v = IntentSession.verifyRoot(s, if (ctx.has("session", "pq_pins")) ctx.get("session", "pq_pins") else null)
        if (v != null) return "session root: $v"
        if (IntentSession.rootDigest(s) != isn["root"]) return "intent_session.root is not the digest of the session root"
        if (IntentJs.get(s, "session") != isn["session"]) return "the session root names another session"
        if (!(now < IntentJs.num(IntentJs.get(s, "expires_at"))!!)) return "the session root has expired"
        out.root = IntentJs.obj(s)
        return null
    }

    // ---- rule 13 ----
    private fun sessionStep(p: Map<String, Any?>, grant: Map<String, Any?>?, ctx: Context?, now: Double): String? {
        val maxAgeSet = ctx != null && ctx.has("policy", "session", "max_revocation_age_s")
        val maxAgeS = cget(ctx, "policy", "session", "max_revocation_age_s")
        if (maxAgeSet && !IntentJs.isNonNeg(maxAgeS)) return "session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)"
        if (!p.containsKey("intent_session")) return "this verifier requires an intent_session but the PCActn carries none"
        val ce = sessionCtxError(ctx)
        if (ce != null) return ce
        val isn = IntentJs.obj(p["intent_session"])
        if (!p.containsKey("intent")) return "an intent_session needs the envelope.intent binding"
        val intent = IntentJs.obj(p["intent"])
        val b = Bound()
        val e = boundRoot(isn, ctx, now, b)
        if (e != null) return e
        val s = b.root
        if (s["intent_ref"] != intent["ref"]) return "intent.ref is not the session statement"
        if (IntentJs.get(s["schema"], "digest") != isn["schema"]) return "intent_session.schema is not the session schema"
        if (IntentJs.get(s["schema"], "aud") != p["aud"]) return "the session schema is for another audience"
        val seq = IntentJs.lng(isn["seq"])
        if (seq == 0L && intent["map_digest"] != IntentJs.get(IntentJs.get(s["layers"], "task"), "map_digest")) return "a seq-0 action must use the session task map"
        val gc = IntentSession.grantSessionCaveat(grant)
        val ge = IntentSession.caveatError(gc)
        if (ge != null) return "admitting root: $ge"
        gc!!
        if (gc["session"] != isn["session"] || gc["root"] != isn["root"] || IntentJs.lng(gc["seq"]) != seq)
            return "the admitting root is bound to another session, root or seq"
        val principals = LinkedHashSet<String>()
        for (x in s["principals"] as List<*>) principals.add(IntentJs.get(x, "key") as String)
        if (IntentJs.get(grant, "issuer") !in principals) return "the admitting root is not signed by a session principal"
        val prior = (if (ctx!!.has("session", "grants")) ctx.get("session", "grants") else listOf<Any?>()) as List<*>
        if (prior.size < seq) return "the verifier does not hold the $seq earlier grants of this session"
        for (i in 0 until seq.toInt()) {
            val g = prior[i]
            if (!isMap(g) || IntentJs.get(g, "id") !is String || IntentJs.get(g, "issuer") !is String) return "session grant $i is not a capability"
            val gse = IntentJs.suiteError(IntentJs.get(g, "alg"), IntentJs.own(g, "alg"))
            if (gse != null) return "session grant $i: $gse"
            val c = IntentSession.grantSessionCaveat(g)
            if (IntentSession.caveatError(c) != null || c!!["session"] != isn["session"] || c["root"] != isn["root"] || IntentJs.lng(c["seq"]) != i.toLong())
                return "session grant $i does not belong to this session at seq $i"
            if (IntentJs.get(g, "issuer") !in principals) return "session grant $i is not signed by a session principal"
            if (i > 0 && !IntentJs.jsonEquals(c["prev"], IntentJs.get(prior[i - 1], "id"))) return "session grant $i does not chain to grant ${i - 1}"
        }
        if (seq > 0 && !IntentJs.jsonEquals(gc["prev"], IntentJs.get(prior[seq.toInt() - 1], "id"))) return "the admitting root does not chain to grant ${seq - 1}"
        val sRev = s.containsKey("revocation")
        if (sRev || maxAgeSet) {
            var ages = Double.POSITIVE_INFINITY
            if (sRev) ages = minOf(ages, IntentJs.num(IntentJs.get(s["revocation"], "max_age_s"))!!)
            if (maxAgeSet) ages = minOf(ages, IntentJs.num(maxAgeS)!!)
            val maxAgeMs = ages * 1000
            if (!sRev) return "revocation: the policy requires a revocation epoch but the session root names no revocation authority"
            val authority = IntentJs.get(s["revocation"], "key")
            val ids = ArrayList<String>()
            ids.add(IntentRevocation.sessionRevocationId(isn["session"] as String))
            ids.add(IntentRevocation.mapRevocationId(intent["map_digest"] as String))
            for (i in 0 until seq.toInt()) ids.add(IntentRevocation.deltaRevocationId(IntentRevocation.jsText(IntentJs.get(prior[i], "id"), IntentJs.own(prior[i], "id"))))
            ids.add(IntentRevocation.deltaRevocationId(IntentRevocation.jsText(grant?.get("id"), grant?.containsKey("id") == true)))
            val std = IntentJs.get(s["layers"], "std")
            if (IntentRevocation.truthy(std))
                ids.add(IntentRevocation.profileRevocationId(IntentJs.get(std, "profile") as String, IntentRevocation.jsText(IntentJs.get(std, "version"), true)))
            // only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
            val pqPins = LinkedHashMap<String, Any?>()
            if (IntentJs.own(s["revocation"], "pq_pk")) pqPins[authority as String] = IntentJs.get(s["revocation"], "pq_pk")
            val lastPresent = ctx.has("session", "revocation_last")
            val rv = IntentRevocation.checkSessionRevocation(
                cget(ctx, "session", "revocation"), isn["session"] as String, authority, ids, now, maxAgeMs, null, pqPins,
                lastPresent, if (lastPresent) ctx.get("session", "revocation_last") else null,
            )
            if (rv != null) return "revocation: $rv"
        }
        return null
    }

    // ---- rule 15 ----
    private fun accStep(p: Map<String, Any?>, ctx: Context?, now: Double, accEnv: MutableMap<String, Any?>, monEnv: MutableMap<String, Any?>): String? {
        val isn = IntentJs.obj(p["intent_session"])
        val b = Bound()
        val e = boundRoot(isn, ctx, now, b)
        if (e != null) return e
        ctx!!
        val s = b.root
        val ce = accCtxError(ctx) ?: schemaCtxError(ctx)
        if (ce != null) return ce
        val verb = verbOf(p)
        val claims = isn["acc"] as? List<*> ?: listOf<Any?>()
        val accs = s["accumulators"] as List<*>
        for (c in claims) {
            val a = findById(accs, IntentJs.get(c, "id")) ?: return "claim '${IntentJs.get(c, "id")}' names no accumulator of the session"
            if ("wallet" == IntentJs.get(a["holder"], "kind")) return "accumulator '${IntentJs.get(c, "id")}' is wallet-held and cannot be claimed at a site"
        }
        val docs = cget(ctx, "schema", "docs")
        val schemaDoc = if (docs is List<*>) docs.firstOrNull { schemaDigestIs(it, isn["schema"]) } else null
        val params = cget(ctx, "params")
        val state = if (ctx.has("acc", "state")) ctx.get("acc", "state") else emptyMap<String, Any?>()
        for (aO in accs) {
            val a = IntentJs.obj(aO)
            val id = a["id"] as String
            val holder = IntentJs.obj(a["holder"])
            val hk = holder["kind"]
            if ("wallet" == hk) continue
            val sel = IntentJs.obj(a["sel"])
            if (sel.containsKey("accumulates_into") && schemaDoc == null) return "accumulator '$id' selects by accumulates_into but the session schema is not available"
            val selected = IntentAcc.accSelects(a, verb, schemaDoc)
            val claim = findById(claims, id)
            val hasPre = IntentJs.own(state, id)
            val pre = if (hasPre) IntentJs.get(state, id) else null
            if (!selected) {
                if (claim != null) return "claim '$id' for an accumulator this action does not feed"
                if ("site_local" == hk && hasPre) {
                    val pe = IntentAcc.preStateError(a["agg"], pre)
                    if (pe != null) return "accumulator '$id': $pe"
                    accEnv[id] = postOf(IntentAcc.preValue(a["agg"], pre as Map<*, *>))
                }
                continue
            }
            if (claim == null) return "no claim for accumulator '$id' that this action feeds"
            if (params !is Map<*, *>) return "no plaintext params to compute accumulator values"
            val pm = IntentJs.obj(params)
            if (a["key"] != null) {
                val key = a["key"] as String
                val name = key.substring("action.params.".length)
                if (!pm.containsKey(name)) return "accumulator '$id': the key parameter $key is missing"
                val verbDecl = if (schemaDoc != null) ActionSchema.schemaVerb(schemaDoc, verb) else null
                val kd = if (verbDecl == null) null else IntentJs.get(verbDecl["params"], key)
                if (kd == null || (IntentJs.get(kd, "semantic") as String).startsWith("text."))
                    return "accumulator '$id': the key must be a schema-declared identity (not free text)"
            }
            val v = IntentAcc.accValueOf(a, verb, pm, schemaDoc)
            if (v.reason != null) return "accumulator '$id': ${v.reason}"
            val post: Long
            if ("site_local" == hk) {
                if (claim.containsKey("receipt")) return "accumulator '$id' is site-local: a receipt is not accepted"
                if (!hasPre) return "no state for site-local accumulator '$id'"
                val pe = IntentAcc.preStateError(a["agg"], pre)
                if (pe != null) return "accumulator '$id': $pe"
                post = IntentAcc.combineAcc(a["agg"], pre as Map<*, *>, v) ?: return "accumulator '$id' overflows 2^53-1"
            } else {
                if (!claim.containsKey("receipt")) return "accumulator '$id' is sequenced: the claim needs a reservation receipt"
                val rcs = if (ctx.has("acc", "receipts")) ctx.get("acc", "receipts") else listOf<Any?>()
                var rc: Map<String, Any?>? = null
                for (x in IntentArtifacts.iterable(rcs)) {
                    val hit = try { IntentAcc.receiptDigest(x) == claim["receipt"] } catch (ex: RuntimeException) { false }
                    if (hit && x is Map<*, *>) { rc = IntentJs.obj(x); break }
                }
                if (rc == null) return "the reservation receipt for '$id' was not presented"
                val keySets = if (ctx.has("acc", "sequencer_keys")) ctx.get("acc", "sequencer_keys") else listOf<Any?>()
                val pa = ctx.get("policy", "acc")
                val root = holder["root"]
                val maxReceiptAgeMs = if (IntentJs.own(pa, "max_receipt_age_s")) IntentJs.num(IntentJs.get(pa, "max_receipt_age_s"))!! * 1000 else IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS.toDouble()
                val maxKeySetAgeMs = if (IntentJs.own(pa, "max_keyset_age_s")) IntentJs.num(IntentJs.get(pa, "max_keyset_age_s"))!! * 1000 else IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS.toDouble()
                val kv = ctx.get("acc", "keyset_versions")
                val tracked = if (root is String && IntentJs.own(kv, root)) IntentJs.get(kv, root) else null
                if (!IntentAcc.verifyReceiptAgainstHolder(rc, holder, keySets, now, maxReceiptAgeMs, maxKeySetAgeMs, tracked)) {
                    val rse = IntentJs.suiteError(rc["alg"], rc.containsKey("alg"))
                    if (rse != null && rse.startsWith(IntentJs.UNSUPPORTED_SUITE)) return "the reservation receipt for '$id': ${IntentJs.UNSUPPORTED_SUITE}"
                    return "the reservation receipt for '$id' is not signed by a key the session sequencer's root-signed key set lists for its issue time"
                }
                if (rc["session"] != isn["session"] || rc["acc"] != id || rc["aud"] != p["aud"])
                    return "the reservation receipt for '$id' is for another session, accumulator or audience"
                if (rc["pcactn_digest"] != IntentAcc.pcactnReservationDigest(p)) return "the reservation receipt for '$id' is for another action"
                if (!(now <= IntentJs.num(rc["expires_at"])!!)) return "the reservation receipt for '$id' has expired"
                val lastSeq = if (ctx.has("acc", "last_seq")) ctx.get("acc", "last_seq") else emptyMap<String, Any?>()
                if (IntentJs.own(lastSeq, id)) {
                    val last = IntentJs.get(lastSeq, id)
                    if (!(IntentJs.num(rc["seq"])!! > IntentJs.num(last)!!))
                        return "the reservation receipt for '$id' replays seq ${IntentJs.lng(rc["seq"])} (last accepted ${IntentJs.lng(last)})"
                }
                if (!IntentAcc.receiptArithmeticOk(a["agg"], rc, v.value)) return "the reservation receipt for '$id' does not add up"
                post = IntentJs.lng(rc["post"])
            }
            if (a.containsKey("domain_max") && post > IntentJs.lng(a["domain_max"])) return "accumulator '$id' post $post is outside its domain (max ${IntentJs.lng(a["domain_max"])})"
            if (IntentJs.lng(claim["post"]) != post) return "claimed post ${IntentJs.lng(claim["post"])} for '$id' differs from the verifier's $post"
            accEnv[id] = postOf(post)
        }
        val mons = if (ctx.has("acc", "monitors")) ctx.get("acc", "monitors") else emptyMap<String, Any?>()
        for (mO in s["monitors"] as List<*>) {
            val m = IntentJs.obj(mO)
            val id = m["id"] as String
            val st = if (IntentJs.own(mons, id)) IntentJs.get(mons, id) else null
            if (st !is String || st !in IntentAcc.monitorStates(m)) return "no valid state for monitor '$id'"
            monEnv[id] = linkedMapOf<String, Any?>("state" to st)
        }
        return null
    }

    private fun postOf(post: Long): Map<String, Any?> = linkedMapOf("post" to IntentJs.ofLong(post))

    private fun findById(xs: List<*>, id: Any?): Map<String, Any?>? =
        xs.firstOrNull { it is Map<*, *> && id != null && id == it["id"] }?.let { IntentJs.obj(it) }

    private fun run(out: Decision, name: String, clockOk: Boolean, f: () -> String?) {
        val why: String? = try {
            if (clockOk) f() else "the verifier clock is not a safe integer (fail closed)"
        } catch (e: RuntimeException) {
            "$name error (fail closed): " + e.javaClass.simpleName
        } catch (e: StackOverflowError) {
            "$name error (fail closed): " + e.javaClass.simpleName
        }
        out.checks.add(Check(name, why == null, why))
    }

    private fun layersStep(ctx: Context, actx: Map<String, Any?>): String? {
        val layers = ctx.get("layers")
        for (k in listOf("org", "site", "std")) {
            if (!IntentJs.own(layers, k)) continue
            val layer = IntentJs.get(layers, k)
            if (IntentJs.obj(layer).size != 1) return "layers: the $k ceiling is malformed (null or not {predicates: [...]})"
            if (!Predicates.evaluatePredicates(IntentJs.get(layer, "predicates"), actx))
                return "layers: the action is outside the $k ceiling (a ceiling is never a question)"
        }
        return null
    }

    /**
     * Run the v2 checks for a wire-valid PCActn `p` under the verifier's root `grant` (never throws: an internal error
     * fails the check being evaluated).
     */
    fun decide(p: Map<String, Any?>, grant: Map<String, Any?>?, ctx: Context?, nowL: Long): Decision {
        val out = Decision()
        val now = nowL.toDouble()
        val present = p.containsKey("intent_session")
        val clockOk = Math.abs(nowL) <= 9007199254740991L
        val ctxErr = contextError(ctx)
        if (ctxErr != null) {
            // a malformed verifier context fails closed: every v2 check that could be reported fails with the reason
            out.checks.add(Check("schema", false, "malformed v2 context: $ctxErr"))
            out.checks.add(Check("intent_session", false, "malformed v2 context: $ctxErr"))
            if (present) out.checks.add(Check("accumulators", false, "malformed v2 context: $ctxErr"))
            if (present && mapCommitted(p)) out.checks.add(Check("map", false, "malformed v2 context: $ctxErr"))
            return out
        }
        if (present || closedWorld(ctx)) {
            run(out, "schema", clockOk) {
                val matched = Matched()
                val why = schemaStep(p, ctx, matched)
                if (why == null) out.env["canon"] = ActionSchema.canonProjection(matched.doc, verbOf(p), IntentJs.obj(ctx!!.get("params")))
                why
            }
        }
        if (present || sessionRequired(ctx)) run(out, "intent_session", clockOk) { sessionStep(p, grant, ctx, now) }
        val mapActive = mapCommitted(p) || mapRequired(ctx)
        val params = cget(ctx, "params")
        val action = linkedMapOf<String, Any?>(
            "verb" to verbOf(p),
            "resource" to resourceOf(p),
            "params" to (if (params is Map<*, *>) params else LinkedHashMap<String, Any?>()),
        )
        if (present && ctx != null && ctx.has("layers")) {
            run(out, "layers", clockOk) {
                val env = LinkedHashMap<String, Any?>()
                if (out.env.containsKey("canon")) env["canon"] = out.env["canon"]
                layersStep(ctx, linkedMapOf("action" to action, "env" to env))
            }
        }
        if (present) {
            run(out, "accumulators", clockOk) {
                val acc = LinkedHashMap<String, Any?>()
                val mon = LinkedHashMap<String, Any?>()
                val why = accStep(p, ctx, now, acc, mon)
                if (why == null) { out.env["acc"] = acc; out.env["mon"] = mon }
                why
            }
            if (mapActive) run(out, "map", clockOk) { mapStep(p, ctx) }
            var wb: IntentWB.Result? = null
            try {
                val inp = LinkedHashMap<String, Any?>()
                inp["now"] = IntentJs.ofLong(nowL)
                inp["aud"] = IntentRevocation.jsText(p["aud"], p.containsKey("aud"))
                inp["session"] = IntentJs.get(p["intent_session"], "session")
                inp["action"] = action
                inp["intent_session"] = p["intent_session"]
                if (ctx != null && ctx.has("wb", "artifacts")) inp["artifacts"] = ctx.get("wb", "artifacts")
                if (ctx != null && ctx.has("wb", "policy")) inp["policy"] = ctx.get("wb", "policy")
                wb = IntentWB.decide(inp)
            } catch (e: RuntimeException) {
                out.checks.add(Check("facts", false, "W-B error (fail closed): " + e.javaClass.simpleName))
            }
            if (wb != null) {
                for (name in listOf("facts", "provenance", "classes")) {
                    val c = wb.checks[name] ?: continue
                    if (c == "pass") out.checks.add(Check(name, true, null))
                    else out.checks.add(
                        Check(
                            name, false,
                            if (c == "question") "intent_required: " + (wb.reason ?: "a question is required") else (wb.reason ?: "rejected"),
                        ),
                    )
                }
                if (wb.outcome != "deny") {
                    wb.world?.let { out.env["world"] = it }
                    wb.prov?.let { out.env["prov"] = it }
                    wb.cls?.let { out.env["class"] = it }
                }
            }
        } else if (mapActive) {
            run(out, "map", clockOk) { mapStep(p, ctx) }
        }
        return out
    }

    /**
     * Rule 19 (`map`, V15 Z0): reported iff the PCActn's `intent_session.map_form` is `"commit"` or the policy sets
     * `map.require: true`; evaluated after `accumulators` (independent of the earlier checks) and before W-B.
     */
    private fun mapStep(p: Map<String, Any?>, ctx: Context?): String? {
        if (!mapCommitted(p)) return "this verifier requires a committed map (intent_session.map_form \"commit\")"
        if (!p.containsKey("intent")) return "a committed map needs the envelope.intent binding"
        if (ctx == null || !ctx.has("map", "disclosure")) return "no disclosure of the committed map was presented"
        val eps = if (ctx.has("policy", "map", "max_residual_risk_ppm")) IntentJs.num(ctx.get("policy", "map", "max_residual_risk_ppm")) else null
        val d = IntentMap.decide(
            IntentJs.get(p["intent"], "map_digest"), if (p.containsKey("action")) p["action"] else LinkedHashMap<String, Any?>(),
            ctx.has("params"), ctx.get("params"), ctx.get("map", "disclosure"), eps,
        )
        return if (d.ok) null else d.reason
    }
}
