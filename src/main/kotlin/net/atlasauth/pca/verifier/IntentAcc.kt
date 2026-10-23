package net.atlasauth.pca.verifier

/**
 * Rule 15: accumulators, monitors, sequencer reservation receipts and the sequencer's root-signed key sets
 * (packages/pca/src/intent-acc.ts). The verifier never takes an accumulator value from the agent: it recomputes the
 * post-action value from its own pre-state (site-local) or from a sequencer-signed receipt, and the agent's signed claim
 * must equal it.
 */
object IntentAcc {
    const val MAX_SESSION_ACCUMULATORS = 16
    const val MAX_SESSION_MONITORS = 16
    const val MAX_MONITOR_WITHIN = 64
    const val ACC_RECEIPT_DOMAIN = "atlas-pca/acc-receipt/v1\u0000"
    const val ACC_RECEIPT_REF_DOMAIN = "atlas-pca/acc-receipt-ref/v1"
    const val ACC_RESERVE_DOMAIN = "atlas-pca/acc-reserve/v1"
    const val SEQUENCER_KEYS_DOMAIN = "atlas-pca/sequencer-keys/v1\u0000"
    const val SEQUENCER_KEYS_REF_DOMAIN = "atlas-pca/sequencer-keys-ref/v1"
    const val RECEIPT_SKEW_MS = 60_000L
    /** A receipt lives at most this long: `issued_at <= expires_at <= issued_at + 900000` (15 min). */
    const val MAX_RECEIPT_LIFETIME_MS = 900_000L
    /** Default bound on a receipt's age at verification, policy `acc.max_receipt_age_s` (15 min). */
    const val DEFAULT_MAX_RECEIPT_AGE_MS = 900_000L
    /** Default bound on a key set's age, policy `acc.max_keyset_age_s` (1 h). */
    const val DEFAULT_MAX_KEYSET_AGE_MS = 3_600_000L
    private const val MAX_SAFE = 9007199254740991L
    internal val ACC_AGGS = listOf("sum", "count", "distinct", "max")
    internal val MONITOR_KINDS = listOf("requires_prior", "precedes", "never", "always", "responds_within")
    internal val ACC_ID_RE = Regex("[A-Za-z0-9_]{1,64}")
    internal val KID_RE = Regex("[A-Za-z0-9_.:-]{1,64}")
    private val PARAM_PATH_RE = Regex("action\\.params\\.[A-Za-z0-9_]{1,64}")
    private val UNIT_RE = Regex("[a-z0-9_]+(?:\\.[a-z0-9_]+)*")
    private val RECEIPT_KEYS = listOf(
        "v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at",
        "expires_at", "kid", "ledger", "signer", "alg", "pq_pk", "sig", "pq_sig",
    )

    private fun idOk(v: Any?): Boolean = v is String && ACC_ID_RE.matches(v)
    private fun declIdOk(v: Any?): Boolean = idOk(v) && v !in ActionSchema.RESERVED_NAMES
    private fun onlyKeys(m: Map<*, *>, vararg allowed: String): Boolean = m.keys.all { it in allowed }
    private fun exactKeys(o: Any?, vararg keys: String): Boolean {
        if (o !is Map<*, *>) return false
        if (o.size != keys.size) return false
        return keys.all { o.containsKey(it) }
    }
    private fun matches(re: Regex, v: Any?): Boolean = v is String && re.matches(v)

    /** The state set Q of a monitor. */
    internal fun monitorStates(m: Map<String, Any?>): List<String> = when (m["kind"].toString()) {
        "requires_prior", "precedes" -> listOf("unmet", "met")
        "never" -> listOf("clean", "seen")
        "always" -> listOf("ok", "broken")
        "responds_within" -> {
            val w = if (IntentJs.isInt(m["within"])) IntentJs.lng(m["within"]) else 0L
            val out = ArrayList<String>()
            out.add("idle")
            for (i in 1..w) out.add("pending:$i")
            out.add("missed")
            out
        }
        else -> listOf()
    }

    private fun predicateShapeOk(p: Any?): Boolean {
        if (p !is Map<*, *>) return false
        val verb = p["verb"]
        if (verb is String) return true
        if (verb !is List<*> || verb.isEmpty()) return false
        return verb.all { it is String }
    }

    /** Shape of an accumulator declaration in S. Null = well-formed. */
    internal fun accumulatorDeclError(aO: Any?): String? {
        if (aO !is Map<*, *>) return "accumulator must be an object"
        val a = IntentJs.obj(aO)
        for (k in a.keys) if (k !in listOf("id", "agg", "val", "unit", "sel", "win", "key", "domain_max", "cap", "holder")) return "accumulator: unknown member '$k'"
        if (!declIdOk(a["id"])) return "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
        val at = "accumulator '${a["id"]}'"
        if (a["agg"] !is String || a["agg"] !in ACC_AGGS) return "$at: unknown agg"
        if (a.containsKey("val") && !matches(PARAM_PATH_RE, a["val"])) return "$at: val must be action.params.<name>"
        if (a.containsKey("unit") && (a["unit"] !is String || (a["unit"] as String).length > 64 || !matches(UNIT_RE, a["unit"]))) return "$at: unit must be a unit id"
        if (a["sel"] !is Map<*, *>) return "$at: sel must be an object"
        val sel = IntentJs.obj(a["sel"])
        for (k in sel.keys) if (k !in listOf("verbs", "accumulates_into", "event")) return "$at: sel has unknown member '$k'"
        if (sel.containsKey("verbs")) {
            val vs = sel["verbs"]
            val ok = vs is List<*> && vs.isNotEmpty() && vs.size <= 64 && vs.all { it is String && it.isNotEmpty() }
            if (!ok) return "$at: sel.verbs must be 1..64 verb names"
        }
        if (sel.containsKey("accumulates_into") && !matches(UNIT_RE, sel["accumulates_into"]))
            return "$at: sel.accumulates_into must be a unit id"
        if (sel.containsKey("event") && sel["event"] !in listOf("intent_required", "question", "clarification")) return "$at: unknown sel.event"
        val actionSel = sel.containsKey("verbs") || sel.containsKey("accumulates_into")
        if (actionSel == sel.containsKey("event")) return "$at: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind"
        if (a["win"] !is Map<*, *>) return "$at: win must be an object"
        val w = IntentJs.obj(a["win"])
        when (w["kind"]) {
            "task" -> if (w.size != 1) return "$at: win {kind: task} has no other member"
            "sliding" -> if (!exactKeys(w, "kind", "ms") || !(IntentJs.isInt(w["ms"]) && IntentJs.num(w["ms"])!! > 0)) return "$at: win sliding needs a positive ms"
            "period" -> if (!exactKeys(w, "kind", "ms", "t0") || !(IntentJs.isInt(w["ms"]) && IntentJs.num(w["ms"])!! > 0) || !IntentJs.isNonNeg(w["t0"])) return "$at: win period needs a positive ms and t0 >= 0"
            else -> return "$at: unknown win kind"
        }
        val keyNull = a.containsKey("key") && a["key"] == null
        if (!keyNull && !matches(PARAM_PATH_RE, a["key"])) return "$at: key must be null or action.params.<name>"
        if (a.containsKey("domain_max") && !IntentJs.isNonNeg(a["domain_max"])) return "$at: domain_max must be a non-negative safe integer"
        if (a.containsKey("cap") && !IntentJs.isNonNeg(a["cap"])) return "$at: cap must be a non-negative safe integer"
        if (a["holder"] !is Map<*, *>) return "$at: holder must be an object"
        val h = IntentJs.obj(a["holder"])
        val hk = h["kind"]
        if ("site_local" == hk || "wallet" == hk) {
            if (h.size != 1) return "$at: holder $hk has no other member"
        } else if ("sequenced" == hk) {
            for (k in h.keys) if (k !in listOf("kind", "uri", "root", "root_alg", "root_pq_pk", "keys_uri")) return "$at: holder sequenced has unknown member '$k'"
            val uri = h["uri"]
            if (uri !is String || uri.isEmpty()) return "$at: holder sequenced needs a uri"
            if (!IntentJs.b32(h["root"])) return "$at: holder.root is not canonical base64url (32 bytes)"
            val rse = IntentJs.suiteError(h["root_alg"], h.containsKey("root_alg"))
            if (rse != null) return "$at: holder.root_alg: $rse"
            if (h.containsKey("root_pq_pk") && !IntentJs.b64any(h["root_pq_pk"])) return "$at: holder.root_pq_pk is not canonical base64url"
            val ku = h["keys_uri"]
            if (h.containsKey("keys_uri") && (ku !is String || ku.isEmpty())) return "$at: holder.keys_uri must be a non-empty string"
        } else return "$at: unknown holder kind"
        val wallet = "wallet" == hk
        if (wallet != sel.containsKey("event")) return "$at: wallet events are wallet-held and only wallet events are"
        if (!wallet) {
            val agg = a["agg"]
            if ("count" != agg && !a.containsKey("val") && !sel.containsKey("accumulates_into")) return "$at: $agg needs val (or sel.accumulates_into for a sum)"
            if ("sum" != agg && "count" != agg && !a.containsKey("val")) return "$at: $agg needs val"
            if ("count" == agg && a.containsKey("val")) return "$at: count takes no val"
        }
        return null
    }

    /** Shape of a monitor declaration in S. Null = well-formed. */
    internal fun monitorDeclError(mO: Any?): String? {
        if (mO !is Map<*, *>) return "monitor must be an object"
        val m = IntentJs.obj(mO)
        for (k in m.keys) if (k !in listOf("id", "kind", "p", "q", "status", "within")) return "monitor: unknown member '$k'"
        if (!declIdOk(m["id"])) return "monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
        val at = "monitor '${m["id"]}'"
        val kind = m["kind"]
        if (kind !is String || kind !in MONITOR_KINDS) return "$at: unknown kind"
        if (!predicateShapeOk(m["p"])) return "$at: p must be a predicate"
        val needsQ = "requires_prior" == kind || "precedes" == kind || "responds_within" == kind
        if (needsQ != m.containsKey("q")) return "$at: q is required exactly for requires_prior / precedes / responds_within"
        if (m.containsKey("q") && !predicateShapeOk(m["q"])) return "$at: q must be a predicate"
        if (m.containsKey("status") && "admitted" != m["status"] && "committed" != m["status"]) return "$at: status must be admitted or committed"
        if (("responds_within" == kind) != m.containsKey("within")) return "$at: within is required exactly for responds_within"
        if (m.containsKey("within") && !(IntentJs.isInt(m["within"]) && IntentJs.num(m["within"])!! >= 1 && IntentJs.num(m["within"])!! <= MAX_MONITOR_WITHIN))
            return "$at: within must be an integer in 1..$MAX_MONITOR_WITHIN"
        return null
    }

    // ---- selection, values, combination ----
    /** The action is selected: its verb is listed, or its schema verb has a parameter feeding `sel.accumulates_into`. */
    internal fun accSelects(a: Map<String, Any?>, verb: String, schema: Any?): Boolean {
        val sel = IntentJs.obj(a["sel"])
        if (sel.containsKey("event")) return false
        val verbs = sel["verbs"]
        if (verbs is List<*> && verbs.contains(verb)) return true
        if (sel.containsKey("accumulates_into") && schema != null) {
            val v = ActionSchema.schemaVerb(schema, verb)
            return v != null && ActionSchema.accumulationParams(v, sel["accumulates_into"] as String).isNotEmpty()
        }
        return false
    }

    /** val(omega): a value (and the distinct key), or the reason it has none. */
    internal class AccValue(val reason: String?, val value: Long, val key: String?)

    internal fun distinctKey(x: Any?): String? {
        if (x is String || IntentJs.isInt(x)) {
            return try { IntentJs.canon(x) } catch (e: RuntimeException) { null }
        }
        return null
    }

    internal fun accValueOf(a: Map<String, Any?>, verb: String, params: Map<String, Any?>, schema: Any?): AccValue {
        val agg = a["agg"]
        if ("count" == agg) return AccValue(null, 1, null)
        if ("distinct" == agg) {
            val name = (a["val"] as String).substring("action.params.".length)
            val k = if (params.containsKey(name)) distinctKey(params[name]) else null
            return if (k == null) AccValue("${a["val"]} must be a string or a safe integer", 0, null) else AccValue(null, 1, k)
        }
        if (a.containsKey("val")) {
            val name = (a["val"] as String).substring("action.params.".length)
            val x = params[name]
            return if (params.containsKey(name) && IntentJs.isNonNeg(x)) AccValue(null, IntentJs.lng(x), null)
            else AccValue("${a["val"]} must be a non-negative safe integer", 0, null)
        }
        val v = (if (schema != null) ActionSchema.schemaVerb(schema, verb) else null)
            ?: return AccValue("no schema entry for '$verb' to read accumulates_into", 0, null)
        var s = 0L
        for (p in ActionSchema.accumulationParams(v, IntentJs.get(a["sel"], "accumulates_into") as String)) {
            val name = p.substring("action.params.".length)
            if (!params.containsKey(name)) continue
            val x = params[name]
            if (!IntentJs.isNonNeg(x)) return AccValue("$p must be a non-negative safe integer", 0, null)
            s += IntentJs.lng(x)
            if (s > MAX_SAFE) return AccValue("accumulated value exceeds 2^53-1", 0, null)
        }
        return AccValue(null, s, null)
    }

    private fun want(agg: Any?): String = when (agg) {
        "sum" -> "sum"
        "count" -> "count"
        "max" -> "max"
        else -> "values"
    }

    internal fun preStateError(agg: Any?, sO: Any?): String? {
        if (sO !is Map<*, *>) return "pre-state must be an object"
        val want = want(agg)
        if (sO.size != 1 || !sO.containsKey(want)) return "pre-state of a $agg accumulator is {$want}"
        if (want == "values") {
            val vs = sO["values"]
            if (vs !is List<*>) return "pre-state values must be strings"
            for (x in vs) if (x !is String) return "pre-state values must be strings"
            if (HashSet<Any?>(vs).size != vs.size) return "pre-state values must be distinct"
            return null
        }
        return if (IntentJs.isNonNeg(sO[want])) null else "pre-state $want must be a non-negative safe integer"
    }

    /** The post-action value (null when it leaves the safe-integer range). */
    internal fun combineAcc(agg: Any?, pre: Map<*, *>, v: AccValue): Long? {
        val post: Long = when (agg.toString()) {
            "sum" -> IntentJs.lng(pre["sum"]) + v.value
            "count" -> IntentJs.lng(pre["count"]) + 1
            "max" -> maxOf(IntentJs.lng(pre["max"]), v.value)
            else -> {
                val vs = pre["values"] as List<*>
                vs.size + (if (vs.contains(v.key)) 0L else 1L)
            }
        }
        return if (post <= MAX_SAFE) post else null
    }

    internal fun preValue(agg: Any?, pre: Map<*, *>): Long = when (agg.toString()) {
        "sum" -> IntentJs.lng(pre["sum"])
        "count" -> IntentJs.lng(pre["count"])
        "max" -> IntentJs.lng(pre["max"])
        else -> (pre["values"] as List<*>).size.toLong()
    }

    // ---- receipts ----
    /** The digest a reservation binds: the PCActn without sig, pq_sig, threshold and intent_session. */
    fun pcactnReservationDigest(p: Map<String, Any?>): String {
        val body = LinkedHashMap(p)
        for (k in listOf("sig", "pq_sig", "threshold", "intent_session")) body.remove(k)
        return IntentJs.ref(ACC_RESERVE_DOMAIN, "b", body)
    }

    internal fun receiptShapeError(rO: Any?): String? {
        if (rO !is Map<*, *>) return "receipt is not an object"
        val r = IntentJs.obj(rO)
        for (k in r.keys) if (k !in RECEIPT_KEYS) return "receipt: unknown member '$k'"
        if (!OracleFacts.isOne(r["v"]) || "pca-acc-receipt" != r["kind"]) return "not a pca-acc-receipt v1"
        if (!IntentJs.b32(r["session"])) return "receipt.session is not canonical base64url (32 bytes)"
        if (!idOk(r["acc"])) return "receipt.acc is not an accumulator id"
        if (!(IntentJs.isInt(r["seq"]) && IntentJs.num(r["seq"])!! >= 1)) return "receipt.seq must be a safe integer >= 1"
        if (!IntentJs.isNonNeg(r["pre"]) || !IntentJs.isNonNeg(r["delta"]) || !IntentJs.isNonNeg(r["post"])) return "receipt pre / delta / post must be non-negative safe integers"
        if (!IntentJs.b32(r["pcactn_digest"])) return "receipt.pcactn_digest is not canonical base64url (32 bytes)"
        val aud = r["aud"]
        if (aud !is String || aud.isEmpty()) return "receipt.aud must be a non-empty string"
        if (!IntentJs.isNonNeg(r["issued_at"]) || !IntentJs.isNonNeg(r["expires_at"])) return "receipt.issued_at / expires_at must be non-negative safe integers"
        val ia = IntentJs.num(r["issued_at"])!!
        val ea = IntentJs.num(r["expires_at"])!!
        if (!(ea >= ia && ea - ia <= MAX_RECEIPT_LIFETIME_MS)) return "receipt.expires_at must be within $MAX_RECEIPT_LIFETIME_MS ms after issued_at"
        if (!matches(KID_RE, r["kid"])) return "receipt.kid must match [A-Za-z0-9_.:-]{1,64}"
        val l = r["ledger"]
        if (!exactKeys(l, "head", "index") || !IntentJs.isNonNeg(IntentJs.get(l, "index")) || !IntentJs.b32(IntentJs.get(l, "head"))) return "receipt.ledger must be {index, head}"
        if (!IntentJs.b32(r["signer"])) return "receipt.signer is not canonical base64url (32 bytes)"
        val rse = IntentJs.suiteError(r["alg"], r.containsKey("alg"))
        if (rse != null) return "receipt.alg: $rse"
        if (IntentJs.suiteOf(r) == "ed25519" && (r.containsKey("pq_pk") || r.containsKey("pq_sig"))) return "an ed25519 receipt must not carry pq_pk / pq_sig"
        if (r["sig"] !is String) return "receipt.sig must be a string"
        return null
    }

    private fun receiptBody(r: Map<String, Any?>): Map<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid")) b[k] = r[k]
        b["ledger"] = linkedMapOf<String, Any?>("index" to IntentJs.get(r["ledger"], "index"), "head" to IntentJs.get(r["ledger"], "head"))
        b["signer"] = r["signer"]
        return b
    }

    internal fun verifyReceiptSignature(r: Map<String, Any?>, expectedSigner: String, pin: Map<String, Any?>?): Boolean = try {
        if (receiptShapeError(r) != null || r["signer"] != expectedSigner) false
        else {
            val msg = IntentJs.message(ACC_RECEIPT_DOMAIN, IntentJs.bindSuiteFields(receiptBody(r), r["alg"], r.containsKey("alg"), r["pq_pk"], r.containsKey("pq_pk")))
            IntentJs.verifyPinnedSuite(r["alg"], r.containsKey("alg"), r["signer"] as String, r["pq_pk"], msg, r["sig"], r["pq_sig"], pin)
        }
    } catch (e: RuntimeException) {
        false
    }

    /** The receipt's content address (what `intent_session.acc[].receipt` carries). */
    fun receiptDigest(r: Any?): String = IntentJs.ref(ACC_RECEIPT_REF_DOMAIN, "r", r)

    internal fun receiptArithmeticOk(agg: Any?, r: Map<String, Any?>, value: Long): Boolean {
        val pre = IntentJs.lng(r["pre"])
        val delta = IntentJs.lng(r["delta"])
        val post = IntentJs.lng(r["post"])
        return when (agg.toString()) {
            "sum" -> delta == value && post == pre + delta
            "count" -> delta == 1L && post == pre + 1
            "max" -> delta == value && post == maxOf(pre, delta)
            else -> (delta == 0L || delta == 1L) && post == pre + delta
        }
    }

    // ---- sequencer key sets ----
    internal fun keySetShapeError(kO: Any?): String? {
        if (kO !is Map<*, *>) return "key set is not an object"
        val k = IntentJs.obj(kO)
        for (x in k.keys) if (x !in listOf("v", "kind", "sequencer", "version", "issued_at", "keys", "alg", "pq_pk", "sig", "pq_sig")) return "key set: unknown member '$x'"
        if (!OracleFacts.isOne(k["v"]) || "pca-sequencer-keys" != k["kind"]) return "not a pca-sequencer-keys v1"
        if (!IntentJs.b32(k["sequencer"])) return "sequencer is not canonical base64url (32 bytes)"
        if (!(IntentJs.isNonNeg(k["version"]) && IntentJs.num(k["version"])!! >= 1)) return "version must be a safe integer >= 1"
        if (!IntentJs.isNonNeg(k["issued_at"])) return "issued_at must be a non-negative safe integer"
        val keys = k["keys"]
        if (keys !is List<*> || keys.isEmpty() || keys.size > 256) return "keys must be 1..256 entries"
        val kids = HashSet<String>()
        for (eO in keys) {
            if (eO !is Map<*, *> || !onlyKeys(eO, "kid", "pk", "alg", "pq_pk", "not_before", "not_after")) return "keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}"
            val e = IntentJs.obj(eO)
            if (!matches(KID_RE, e["kid"]) || !kids.add(e["kid"] as String)) return "key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct"
            if (!IntentJs.b32(e["pk"])) return "key pk is not canonical base64url (32 bytes)"
            val kse = IntentJs.suiteError(e["alg"], e.containsKey("alg"))
            if (kse != null) return "key alg: $kse"
            if (e.containsKey("pq_pk") && !IntentJs.b64any(e["pq_pk"])) return "key pq_pk is not canonical base64url"
            if (!IntentJs.isNonNeg(e["not_before"]) ||
                (e.containsKey("not_after") && !(IntentJs.isNonNeg(e["not_after"]) && IntentJs.num(e["not_after"])!! >= IntentJs.num(e["not_before"])!!))
            ) return "key validity must be 0 <= not_before <= not_after"
        }
        val ase = IntentJs.suiteError(k["alg"], k.containsKey("alg"))
        if (ase != null) return "alg: $ase"
        if (IntentJs.suiteOf(k) == "ed25519" && (k.containsKey("pq_pk") || k.containsKey("pq_sig"))) return "an ed25519 key set must not carry pq_pk / pq_sig"
        if (k["sig"] !is String) return "sig must be a string"
        return null
    }

    internal fun verifyKeySet(kO: Any?, root: String, rootPqPk: Any?, rootPqPresent: Boolean): Boolean = try {
        if (keySetShapeError(kO) != null) false
        else {
            val k = IntentJs.obj(kO)
            if (root != k["sequencer"]) false
            else {
                val pin = if (rootPqPresent) IntentJs.pin(root, rootPqPk) else null
                val body = LinkedHashMap<String, Any?>()
                for (x in listOf("v", "kind", "sequencer", "version", "issued_at", "keys")) body[x] = k[x]
                val msg = IntentJs.message(SEQUENCER_KEYS_DOMAIN, IntentJs.bindSuiteFields(body, k["alg"], k.containsKey("alg"), k["pq_pk"], k.containsKey("pq_pk")))
                IntentJs.verifyPinnedSuite(k["alg"], k.containsKey("alg"), root, k["pq_pk"], msg, k["sig"], k["pq_sig"], pin)
            }
        }
    } catch (e: RuntimeException) {
        false
    }

    /** A key set's content address: `base64url(sha256(strictCanonical({"d":"atlas-pca/sequencer-keys-ref/v1","k":set})))`. */
    fun keySetDigest(ks: Any?): String = IntentJs.ref(SEQUENCER_KEYS_REF_DOMAIN, "k", ks)

    /** `acc.keyset_versions[root]` is exactly `{version, digest}`: version a safe integer >= 1, digest 32-byte base64url. Null = ok. */
    internal fun trackedKeySetError(t: Any?): String? {
        if (t !is Map<*, *>) return "a tracked key set must be an object {version, digest}"
        for (k in t.keys) if (k != "version" && k != "digest") return "a tracked key set has the unknown member '$k'"
        val v = t["version"]
        if (!IntentJs.isInt(v) || IntentJs.num(v)!! < 1) return "a tracked key set version must be a safe integer >= 1"
        if (!IntentJs.b32(t["digest"])) return "a tracked key set digest must be canonical base64url (32 bytes)"
        return null
    }

    private fun nonNegSafe(d: Double): Boolean = d.isFinite() && d == Math.rint(d) && d >= 0 && d <= IntentJs.MAX_SAFE && !IntentJs.isNegZero(d)

    /**
     * Verify a receipt against the sequenced holder of S (rule 15 step 3, sequenced). False unless ALL hold: the clock and every
     * bound are safe integers; the receipt is well-formed (lifetime at most 15 min), `issued_at <= now + 60 s` and
     * `now - issued_at <= maxReceiptAgeMs`; SOME presented key set verifies under `holder.root` (PQ: pinned by
     * `holder.root_pq_pk`), and, when the verifier tracks `{version, digest}` for the root, `version >= tracked.version` (no
     * rollback) and at `version == tracked.version` the same key-set digest (no equivocation), `issued_at <= now + 60 s` and
     * `now - issued_at <= maxKeySetAgeMs`, and lists `receipt.kid` with `pk == receipt.signer`, `not_before <= receipt.issued_at`
     * and, when `not_after` is set, `receipt.issued_at <= not_after` AND `not_after >= now - 60 s` (a retired key stops
     * verifying), the entry's suite equal to the receipt's; and the receipt verifies under that entry (its PQ key pinned by the
     * entry).
     */
    internal fun verifyReceiptAgainstHolder(
        r: Map<String, Any?>, holder: Map<String, Any?>, keySets: Any?, now: Double,
        maxReceiptAgeMs: Double, maxKeySetAgeMs: Double, tracked: Any?,
    ): Boolean {
        if (!(now.isFinite() && now == Math.rint(now) && Math.abs(now) <= IntentJs.MAX_SAFE && !IntentJs.isNegZero(now))) return false
        if (!nonNegSafe(maxReceiptAgeMs) || !nonNegSafe(maxKeySetAgeMs) || (tracked != null && trackedKeySetError(tracked) != null)) return false
        if (keySets !is List<*> || receiptShapeError(r) != null) return false
        val issued = IntentJs.num(r["issued_at"])!!
        if (!(issued <= now + RECEIPT_SKEW_MS) || !(now - issued <= maxReceiptAgeMs)) return false
        val rs = IntentJs.suiteOf(r)
        for (kO in keySets) {
            if (!verifyKeySet(kO, holder["root"] as String, holder["root_pq_pk"], holder.containsKey("root_pq_pk"))) continue
            if (tracked != null) {
                val v = IntentJs.num(IntentJs.get(kO, "version"))!!
                val tv = IntentJs.num(IntentJs.get(tracked, "version"))!!
                if (v < tv || (v == tv && keySetDigest(kO) != IntentJs.get(tracked, "digest"))) continue // rollback / equivocation
            }
            val ksIssued = IntentJs.num(IntentJs.get(kO, "issued_at"))!!
            if (!(ksIssued <= now + RECEIPT_SKEW_MS) || !(now - ksIssued <= maxKeySetAgeMs)) continue
            val e = (IntentJs.get(kO, "keys") as List<*>).firstOrNull { r["kid"] == IntentJs.get(it, "kid") }?.let { IntentJs.obj(it) } ?: continue
            if (e["pk"] != r["signer"] || issued < IntentJs.num(e["not_before"])!!) continue
            if (e.containsKey("not_after") && (issued > IntentJs.num(e["not_after"])!! || IntentJs.num(e["not_after"])!! < now - RECEIPT_SKEW_MS)) continue
            val es = IntentJs.suiteOf(e)
            if ((es ?: "ed25519") != (rs ?: "x")) continue
            val pin = if (e.containsKey("pq_pk")) IntentJs.pin(e["pk"] as String, e["pq_pk"]) else null
            if (verifyReceiptSignature(r, e["pk"] as String, pin)) return true
        }
        return false
    }
}
