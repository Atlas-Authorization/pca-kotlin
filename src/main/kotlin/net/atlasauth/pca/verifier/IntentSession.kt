package net.atlasauth.pca.verifier

/**
 * Rule 13: the PCActn member `intent_session` (wire), the `intent_session` grant caveat and the principal-signed session
 * root S (`pca-intent-session` v1), mirroring packages/pca/src/intent-session.ts and intent-session-caveat.ts.
 */
object IntentSession {
    const val INTENT_SESSION_KIND = "pca-intent-session"
    const val INTENT_SESSION_SIG_DOMAIN = "atlas-pca/intent-session/v1\u0000"
    const val INTENT_SESSION_REF_DOMAIN = "atlas-pca/intent-session-ref/v1"
    const val INTENT_SESSION_CAVEAT = "intent_session"
    const val INTENT_GOAL_V2_PREFIX = "pca-intent:v2:"
    /** Session grants over a COMMITTED map (rule 19): `pca-intent:v2c:<session>:<map_commit>`. */
    const val INTENT_GOAL_V2C_PREFIX = "pca-intent:v2c:"
    const val MAX_SESSION_SEQ = 2_147_483_647L
    const val MAX_IS_ACC = 16
    const val MAX_IS_FACTS = 16
    const val MAX_IS_PROV_PATHS = 32
    const val MAX_IS_PROV_REFS = 8
    const val MAX_IS_CLASSES = 8
    const val MAX_IS_LABELS = 16
    const val MAX_IS_STRING_BYTES = 256
    const val MAX_SESSION_PRINCIPALS = 16
    internal val INTENT_SESSION_FIELDS = listOf("session", "root", "seq", "schema", "acc", "facts", "offer_set", "prov", "classes", "labels", "map_form")
    internal val ACC_ID_RE = Regex("[A-Za-z0-9_]{1,64}")
    private val PROV_KEY_RE = Regex("action\\.params\\.[A-Za-z0-9_]{1,64}")
    private val ROOT_KEYS = listOf(
        "v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors",
        "question_uri", "revocation", "flows", "expires_at", "signer", "alg", "pq_pk", "sig", "pq_sig",
    )

    private fun b32(o: Any?): Boolean = IntentJs.b32(o)
    private fun shortStr(v: Any?): Boolean =
        v is String && v.isNotEmpty() && !Json.hasLoneSurrogate(v) && IntentJs.u8len(v) <= MAX_IS_STRING_BYTES

    private fun digestList(v: Any?, name: String, max: Int): String? {
        if (v !is List<*> || v.size > max) return "'intent_session.$name' must be an array of at most $max digests"
        for (x in v) if (!b32(x)) return "'intent_session.$name' entries must be canonical base64url (32 bytes)"
        if (HashSet<Any?>(v).size != v.size) return "'intent_session.$name' entries must be distinct"
        return null
    }

    /** Wire validation of `intent_session` (part of the terminal `wire` check). Null = well-formed. */
    fun validateWire(vO: Any?): String? {
        if (vO !is Map<*, *>) return "'intent_session' must be an object"
        val v = IntentJs.obj(vO)
        for (k in v.keys) if (k !in INTENT_SESSION_FIELDS) return "unknown field 'intent_session.$k'"
        for (k in listOf("session", "root", "seq", "schema")) if (!v.containsKey(k)) return "missing field 'intent_session.$k'"
        for (k in listOf("session", "root", "schema")) if (!b32(v[k])) return "'intent_session.$k' is not canonical base64url (32 bytes)"
        if (!IntentJs.isNonNeg(v["seq"]) || IntentJs.num(v["seq"])!! > MAX_SESSION_SEQ) return "'intent_session.seq' must be a safe integer in [0, 2147483647]"
        if (v.containsKey("acc")) {
            val acc = v["acc"]
            if (acc !is List<*> || acc.size > MAX_IS_ACC) return "'intent_session.acc' must be an array of at most $MAX_IS_ACC entries"
            val ids = HashSet<String>()
            for (i in acc.indices) {
                val a = acc[i]
                if (a !is Map<*, *>) return "'intent_session.acc[$i]' must be an object"
                for (k in a.keys) if (k !in listOf("id", "post", "receipt")) return "unknown field 'intent_session.acc[$i].$k'"
                val id = IntentJs.get(a, "id")
                if (id !is String || !ACC_ID_RE.matches(id)) return "'intent_session.acc[$i].id' must match [A-Za-z0-9_]{1,64}"
                if (!ids.add(id)) return "'intent_session.acc' ids must be distinct"
                if (!IntentJs.isNonNeg(IntentJs.get(a, "post"))) return "'intent_session.acc[$i].post' must be a non-negative safe integer"
                if (IntentJs.own(a, "receipt") && !b32(IntentJs.get(a, "receipt"))) return "'intent_session.acc[$i].receipt' is not canonical base64url (32 bytes)"
            }
        }
        if (v.containsKey("facts")) digestList(v["facts"], "facts", MAX_IS_FACTS)?.let { return it }
        if (v.containsKey("offer_set") && !b32(v["offer_set"])) return "'intent_session.offer_set' is not canonical base64url (32 bytes)"
        if (v.containsKey("prov")) {
            val prov = v["prov"]
            if (prov !is Map<*, *> || prov.size > MAX_IS_PROV_PATHS) return "'intent_session.prov' must be an object of at most $MAX_IS_PROV_PATHS entries"
            for ((k, refs) in IntentJs.obj(prov)) {
                if (!PROV_KEY_RE.matches(k)) return "'intent_session.prov' key '$k' is not action.params.<name>"
                val ok = refs is List<*> && refs.isNotEmpty() && refs.size <= MAX_IS_PROV_REFS && refs.all { shortStr(it) }
                if (!ok) return "'intent_session.prov.$k' must be 1..$MAX_IS_PROV_REFS non-empty strings of at most $MAX_IS_STRING_BYTES UTF-8 bytes"
            }
        }
        if (v.containsKey("classes")) digestList(v["classes"], "classes", MAX_IS_CLASSES)?.let { return it }
        if (v.containsKey("labels")) digestList(v["labels"], "labels", MAX_IS_LABELS)?.let { return it }
        if (v.containsKey("map_form") && v["map_form"] != IntentMap.MAP_FORM_COMMIT) return "'intent_session.map_form' must be \"commit\" when present"
        return null
    }

    /** The goal a session grant commits to: `pca-intent:v2:<session>:<map_digest>`. */
    fun intentGoalV2(session: String, mapDigest: String): String = "$INTENT_GOAL_V2_PREFIX$session:$mapDigest"

    /** The goal a session grant over a COMMITTED map commits to (rule 19): `pca-intent:v2c:<session>:<map_commit>`. */
    fun intentGoalV2c(session: String, mapCommit: String): String = "$INTENT_GOAL_V2C_PREFIX$session:$mapCommit"

    /** The FIRST caveat of `grant` whose type is `intent_session` (as is), or null. */
    internal fun grantSessionCaveat(grant: Any?): Map<String, Any?>? {
        val cs = IntentJs.get(grant, "caveats")
        if (grant !is Map<*, *> || cs !is List<*>) return null
        return cs.firstOrNull { it is Map<*, *> && INTENT_SESSION_CAVEAT == it["type"] }?.let { IntentJs.obj(it) }
    }

    /** Shape of an `intent_session` grant caveat: exactly {type, session, seq, root, prev?}, prev present iff seq > 0. */
    fun caveatError(cO: Any?): String? {
        if (cO !is Map<*, *> || INTENT_SESSION_CAVEAT != cO["type"]) return "not an intent_session caveat"
        val c = IntentJs.obj(cO)
        for (k in c.keys) if (k !in listOf("type", "session", "seq", "root", "prev")) return "intent_session caveat: unknown member '$k'"
        if (!b32(c["session"]) || !b32(c["root"])) return "intent_session caveat: session and root must be canonical base64url (32 bytes)"
        if (!IntentJs.isNonNeg(c["seq"]) || IntentJs.num(c["seq"])!! > MAX_SESSION_SEQ) return "intent_session caveat: seq must be a safe integer in [0, 2147483647]"
        if ((IntentJs.num(c["seq"]) == 0.0) != !c.containsKey("prev")) return "intent_session caveat: prev is present exactly when seq > 0"
        if (c.containsKey("prev") && !b32(c["prev"])) return "intent_session caveat: prev must be canonical base64url (32 bytes)"
        return null
    }

    private fun sortedKeysAre(o: Any?, vararg keys: String): Boolean {
        if (o !is Map<*, *>) return false
        if (o.size != keys.size) return false
        return keys.all { o.containsKey(it) }
    }

    /** Structural validation of a signed session root. Null = well-formed. Never throws. */
    fun rootShapeError(sO: Any?): String? {
        try {
            if (sO !is Map<*, *>) return "session root is not an object"
            val s = IntentJs.obj(sO)
            for (k in s.keys) if (k !in ROOT_KEYS) return "session root: unknown member '$k'"
            if (!OracleFacts.isOne(s["v"]) || INTENT_SESSION_KIND != s["kind"]) return "not a pca-intent-session v1"
            if (!b32(s["session"]) || !b32(s["intent_ref"])) return "session and intent_ref must be canonical base64url (32 bytes)"
            val ps = s["principals"]
            if (ps !is List<*> || ps.isEmpty() || ps.size > MAX_SESSION_PRINCIPALS) return "principals must be 1..$MAX_SESSION_PRINCIPALS keys"
            val keys = HashSet<String>()
            for (p in ps) {
                val ok = p is Map<*, *> && b32(IntentJs.get(p, "key")) && p.keys.all { it in listOf("key", "alg", "pq_pk") }
                if (!ok) return "principals entries are {key, alg?, pq_pk?} with a 32-byte key"
                val pse = IntentJs.suiteError(IntentJs.get(p, "alg"), IntentJs.own(p, "alg"))
                if (pse != null) return "principal alg: $pse"
                if (IntentJs.own(p, "pq_pk") && !IntentJs.b64any(IntentJs.get(p, "pq_pk"))) return "principal pq_pk is not canonical base64url"
                if (!keys.add(IntentJs.get(p, "key") as String)) return "principal keys must be distinct"
            }
            val sc = s["schema"]
            val scAud = IntentJs.get(sc, "aud")
            if (!sortedKeysAre(sc, "aud", "digest") || scAud !is String || scAud.isEmpty() || !b32(IntentJs.get(sc, "digest")))
                return "schema must be {aud, digest}"
            val layers = s["layers"]
            if (layers !is Map<*, *>) return "layers must be an object"
            for (k in layers.keys) if (k !in listOf("org", "std", "task")) return "layers: unknown member '$k'"
            val task = IntentJs.get(layers, "task")
            if (!sortedKeysAre(task, "map_digest") || !b32(IntentJs.get(task, "map_digest"))) return "layers.task must be {map_digest}"
            val org = IntentJs.get(layers, "org")
            if (IntentJs.own(layers, "org") && (org !is Map<*, *> || !b32(IntentJs.get(org, "digest")))) return "layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)"
            val std = IntentJs.get(layers, "std")
            if (IntentJs.own(layers, "std")) {
                val prof = IntentJs.get(std, "profile")
                val ver = IntentJs.get(std, "version")
                if (!sortedKeysAre(std, "digest", "profile", "version") || prof !is String || prof.isEmpty() || IntentJs.u8len(prof) > 128 ||
                    !(IntentJs.isInt(ver) && IntentJs.num(ver)!! >= 1) || !b32(IntentJs.get(std, "digest"))
                ) return "layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)"
            }
            val accs = s["accumulators"]
            if (accs !is List<*> || accs.size > IntentAcc.MAX_SESSION_ACCUMULATORS) return "accumulators must be an array of at most ${IntentAcc.MAX_SESSION_ACCUMULATORS}"
            val ids = HashSet<String>()
            for (a in accs) {
                val e = IntentAcc.accumulatorDeclError(a)
                if (e != null) return e
                if (!ids.add(IntentJs.get(a, "id") as String)) return "accumulator and monitor ids must be distinct"
            }
            val mons = s["monitors"]
            if (mons !is List<*> || mons.size > IntentAcc.MAX_SESSION_MONITORS) return "monitors must be an array of at most ${IntentAcc.MAX_SESSION_MONITORS}"
            val mids = HashSet<String>()
            for (m in mons) {
                val e = IntentAcc.monitorDeclError(m)
                if (e != null) return e
                if (!mids.add(IntentJs.get(m, "id") as String)) return "monitor ids must be distinct"
            }
            val q = s["question_uri"]
            if (q !is String || q.isEmpty() || IntentJs.u8len(q) > 2048) return "question_uri must be a non-empty string"
            if (s.containsKey("revocation")) {
                val r = s["revocation"]
                val ok = r is Map<*, *> && r.keys.all { it in listOf("epoch_uri", "max_age_s", "key", "pq_pk") }
                if (!ok) return "revocation must be {epoch_uri, max_age_s, key, pq_pk?}"
                val eu = IntentJs.get(r, "epoch_uri")
                if (eu !is String || eu.isEmpty()) return "revocation.epoch_uri must be a non-empty string"
                if (!IntentJs.isNonNeg(IntentJs.get(r, "max_age_s"))) return "revocation.max_age_s must be a non-negative safe integer"
                if (!b32(IntentJs.get(r, "key"))) return "revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)"
                if (IntentJs.get(r, "key") in keys) return "revocation.key must not be a session principal (a dedicated revocation authority)"
                if (IntentJs.own(r, "pq_pk") && !IntentJs.b64any(IntentJs.get(r, "pq_pk"))) return "revocation.pq_pk must be canonical base64url"
            }
            if (s.containsKey("flows") && s["flows"] !is Map<*, *>) return "flows must be an object"
            if (!IntentJs.isNonNeg(s["expires_at"])) return "expires_at must be a non-negative safe integer (epoch ms)"
            if (!b32(s["signer"])) return "signer must be canonical base64url (32 bytes)"
            if (s["signer"] !in keys) return "signer is not one of the session principals"
            val ase = IntentJs.suiteError(s["alg"], s.containsKey("alg"))
            if (ase != null) return "alg: $ase"
            val suite = IntentJs.suiteOf(s)
            if (suite == "ed25519" && (s.containsKey("pq_pk") || s.containsKey("pq_sig"))) return "an ed25519 session root must not carry pq_pk / pq_sig"
            if (s["sig"] !is String) return "sig must be a string"
            IntentJs.canonBytes(rootBody(s))
            return null
        } catch (e: RuntimeException) {
            return "malformed session root: " + e.message
        }
    }

    private fun rootBody(s: Map<String, Any?>): MutableMap<String, Any?> {
        val b = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri")) b[k] = s[k]
        if (s.containsKey("revocation")) b["revocation"] = s["revocation"]
        if (s.containsKey("flows")) b["flows"] = s["flows"]
        b["expires_at"] = s["expires_at"]
        return b
    }

    /**
     * Verify S: shape, signer listed, suite signature. Null = valid. R3-01 (fail closed): a non-ed25519 root verifies only
     * under the VERIFIER's pin for its signer ([pqPins] = context `session.pq_pins`, an object whose member for the signer
     * is a string), never under the root's own `principals[].pq_pk`; the signer's own entry, when it declares a `pq_pk`,
     * must agree. An ed25519 root never consults the pins.
     */
    fun verifyRoot(sO: Any?, pqPins: Any? = null): String? {
        try {
            val bad = rootShapeError(sO)
            if (bad != null) return bad
            val s = IntentJs.obj(sO)
            val signer = s["signer"] as String
            val p = IntentJs.obj((s["principals"] as List<*>).first { signer == IntentJs.get(it, "key") })
            var pin: Map<String, Any?>? = null
            val suite = Pq.resolveSigAlg(s["alg"], s.containsKey("alg"))
            if (suite != null && suite.needsPqPk) {
                val pv = if (pqPins is Map<*, *> && pqPins.containsKey(signer)) pqPins[signer] else null
                if (pv !is String) return "session root suite '${suite.alg}' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it"
                if (!s.containsKey("pq_pk") || s["pq_pk"] != pv) return "session root pq_pk does not match the verifier's pin for the signer"
                if (p.containsKey("pq_pk") && p["pq_pk"] != pv) return "session root pq_pk does not match the signer's principals entry"
                pin = IntentJs.pin(signer, pv)
            }
            val body = rootBody(s)
            body["signer"] = signer
            val msg = IntentJs.message(INTENT_SESSION_SIG_DOMAIN, IntentJs.bindSuiteFields(body, s["alg"], s.containsKey("alg"), s["pq_pk"], s.containsKey("pq_pk")))
            if (!IntentJs.verifyPinnedSuite(s["alg"], s.containsKey("alg"), signer, s["pq_pk"], msg, s["sig"], s["pq_sig"], pin)) return "session root signature invalid"
            return null
        } catch (e: RuntimeException) {
            return "malformed session root: " + e.message
        }
    }

    /** digest(S): the content address of the whole signed session root. */
    fun rootDigest(s: Any?): String = IntentJs.ref(INTENT_SESSION_REF_DOMAIN, "s", s)
}
