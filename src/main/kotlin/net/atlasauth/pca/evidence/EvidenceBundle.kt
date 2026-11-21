package net.atlasauth.pca.evidence

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * The dispute evidence bundle `pca-intent-evidence` v1: closed-member shape validation, the deterministic normal form, the
 * commitments-only normal form and the bundle digest. A bundle is a JSON tree (Map / List / String / Boolean / Json.Num / null);
 * every function mirrors the reference export of the same name.
 */
object EvidenceBundle {
    const val EVIDENCE_DOMAIN = "atlas-pca/intent-evidence/v1"

    private val TOP_KEYS = listOf(
        "v", "kind", "subject", "statement", "session_root", "schema", "root_grant", "maps", "answers", "canary_labels", "canaries",
        "deltas", "pcactns", "verdicts", "accumulator", "facts", "classifier", "offer_sets", "labels", "effects", "settlements", "revocation_epochs", "anchors",
    )

    // ---- JavaScript-flavoured helpers (shared by the evidence package) ----

    internal fun isObj(v: Any?): Boolean = v is Map<*, *>

    /** `typeof v === 'number' && Number.isSafeInteger(v)`. */
    private fun isSafeInteger(v: Any?): Boolean {
        val d = Js.num(v) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0
    }

    /** `Number.isSafeInteger(v) && !Object.is(v, -0)`. */
    internal fun isInt(v: Any?): Boolean = isSafeInteger(v) && !Js.isNegZero(v)

    internal fun isNonNegInt(v: Any?): Boolean = isInt(v) && Js.num(v)!! >= 0

    internal fun numIs(v: Any?, want: Double): Boolean { val d = Js.num(v); return d != null && d == want }

    /** `Object.keys`: array-index keys ascending first, then the others in insertion order. */
    internal fun jsKeys(m: Map<*, *>): List<String> {
        val idx = ArrayList<String>()
        val rest = ArrayList<String>()
        for (k in m.keys) {
            val s = k as String
            if (isArrayIndex(s)) idx.add(s) else rest.add(s)
        }
        idx.sortBy { it.toLong() }
        idx.addAll(rest)
        return idx
    }

    private fun isArrayIndex(s: String): Boolean {
        if (s.isEmpty() || s.length > 10) return false
        for (c in s) if (c < '0' || c > '9') return false
        if (s.length > 1 && s[0] == '0') return false
        return s.toLong() < 4294967295L
    }

    /** `JSON.parse(JSON.stringify(v))`: a deep copy with every number as JSON prints it (-0 becomes 0). */
    internal fun plain(v: Any?): Any? = when (v) {
        is Json.Num, is Double, is Float -> {
            val n = IntentJs.normalize(if (v is Float) v.toDouble() else v)
            if (n is Json.Num && n.raw == "-0") Json.Num("0") else n
        }
        is Map<*, *> -> {
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in v) out[k as String] = plain(x)
            out
        }
        is List<*> -> v.mapTo(ArrayList<Any?>()) { plain(it) }
        else -> v
    }

    /** Sign of `a < b ? -1 : a > b ? 1 : 0` for two strings; anything else compares equal. */
    internal fun cmp(a: Any?, b: Any?): Int {
        if (a !is String || b !is String) return 0
        val c = a.compareTo(b)
        return if (c < 0) -1 else if (c > 0) 1 else 0
    }

    /** `a - b || next()`: a zero or NaN difference falls through to the next key. */
    internal fun by(a: Any?, b: Any?, next: () -> Int): Int {
        val x = Js.num(a)
        val y = Js.num(b)
        val d = if (x == null || y == null) Double.NaN else x - y
        if (d == 0.0 || d.isNaN()) return next()
        return if (d < 0) -1 else 1
    }

    @Suppress("UNCHECKED_CAST")
    internal fun asMap(o: Any?, what: String): MutableMap<String, Any?> {
        if (o !is Map<*, *>) throw JsTypeError("TypeError: $what is not an object")
        return o as MutableMap<String, Any?>
    }

    @Suppress("UNCHECKED_CAST")
    internal fun asList(o: Any?, what: String): MutableList<Any?> {
        if (o !is List<*>) throw JsTypeError("TypeError: $what is not an array")
        return o as MutableList<Any?>
    }

    // ---- shape ----

    private fun closed(o: Any?, keys: List<String>, where: String): String? {
        if (!isObj(o)) return "$where must be an object"
        for (k in jsKeys(o as Map<*, *>)) if (!keys.contains(k)) return "$where: unknown member \"$k\""
        return null
    }

    private fun g(o: Any?, k: String): Any? = (o as Map<*, *>)[k]

    private fun isStr(o: Any?): Boolean = o is String

    private fun present(o: Any?, k: String): Boolean = (o as Map<*, *>).containsKey(k)

    /** Closed-member shape validation (unknown members are refused at every level the bundle owns). Null when valid. */
    fun bundleShapeError(b: Any?): String? {
        val top = closed(b, TOP_KEYS, "bundle")
        if (top != null) return top
        val x = b
        if (!numIs(g(x, "v"), 1.0) || "pca-intent-evidence" != g(x, "kind")) return "not a pca-intent-evidence v1 bundle"
        val subj = closed(g(x, "subject"), listOf("pcactn_digest", "aud", "session"), "subject")
        if (subj != null) return subj
        val s = g(x, "subject")
        if (!isStr(g(s, "pcactn_digest")) || !isStr(g(s, "aud")) || !isStr(g(s, "session"))) return "subject members must be strings"
        val st = closed(g(x, "statement"), listOf("commit", "opening"), "statement")
        if (st != null) return st
        if (!isStr(g(g(x, "statement"), "commit"))) return "statement.commit must be a string"
        val sr = g(x, "session_root")
        if (!isObj(sr) || !numIs(g(sr, "v"), 1.0) || "pca-intent-session" != g(sr, "kind")) return "session_root is not a pca-intent-session v1"
        if (!isStr(g(sr, "session")) || !isStr(g(sr, "intent_ref")) || !isInt(g(sr, "expires_at"))) return "session_root is missing session / intent_ref / expires_at"
        val pr = g(sr, "principals")
        var prOk = pr is List<*> && pr.isNotEmpty()
        if (prOk) for (p in pr as List<*>) if (!(isObj(p) && isStr(g(p, "key")))) { prOk = false; break }
        if (!prOk) return "session_root.principals must be a non-empty key list"
        val sc = closed(g(x, "schema"), listOf("doc", "anchor"), "schema")
        if (sc != null) return sc
        val doc = g(g(x, "schema"), "doc")
        if (!isObj(doc) || "pca-action-schema" != g(doc, "kind") || !isObj(g(doc, "sig"))) return "schema.doc is not a signed pca-action-schema"
        if (!isObj(g(x, "root_grant"))) return "root_grant must be a capability"
        for (k in listOf("maps", "answers", "canary_labels", "deltas", "pcactns", "verdicts", "effects", "revocation_epochs", "anchors")) {
            if (g(x, k) !is List<*>) return "$k must be an array"
        }
        for (k in listOf("facts", "classifier", "offer_sets", "labels", "settlements")) {
            if (present(x, k) && g(x, k) !is List<*>) return "$k must be an array"
        }
        val maps = g(x, "maps") as List<*>
        for (i in maps.indices) {
            val m = maps[i]
            val e = closed(m, listOf("seq", "commit", "map", "disclosed"), "maps[$i]")
            if (e != null) return e
            if (!isInt(g(m, "seq")) || Js.num(g(m, "seq"))!! < 0 || !isStr(g(m, "commit"))) return "maps[$i] needs an integer seq and a commit"
        }
        val cl = g(x, "canary_labels") as List<*>
        for (i in cl.indices) {
            val c = cl[i]
            val e = closed(c, listOf("question_id", "label"), "canary_labels[$i]")
            if (e != null) return e
            if (!isStr(g(c, "question_id")) || !(numIs(g(c, "label"), 0.0) || numIs(g(c, "label"), 1.0))) return "canary_labels[$i] is malformed"
        }
        val cs = closed(g(x, "canaries"), listOf("asked", "false_yes", "false_no"), "canaries")
        if (cs != null) return cs
        val cn = g(x, "canaries")
        if (!(isNonNegInt(g(cn, "asked")) && isNonNegInt(g(cn, "false_yes")) && isNonNegInt(g(cn, "false_no")))) return "canaries counts must be non-negative integers"
        val ac = closed(g(x, "accumulator"), listOf("holder", "events", "receipts", "sequencer_keys"), "accumulator")
        if (ac != null) return ac
        val acc = g(x, "accumulator")
        if ("site_local" != g(acc, "holder") && "sequenced" != g(acc, "holder")) return "accumulator.holder must be site_local or sequenced"
        if (g(acc, "events") !is List<*>) return "accumulator.events must be an array"
        val evs = g(acc, "events") as List<*>
        for (i in evs.indices) {
            val ev = evs[i]
            val e = closed(ev, listOf("acc", "post", "pcactn_digest", "delta", "status"), "accumulator.events[$i]")
            if (e != null) return e
            if (!isStr(g(ev, "acc")) || !isNonNegInt(g(ev, "post")) || !isStr(g(ev, "pcactn_digest"))) return "accumulator.events[$i] is malformed"
            if (present(ev, "delta") && !isNonNegInt(g(ev, "delta"))) return "accumulator.events[$i].delta must be a non-negative integer"
        }
        if (present(acc, "receipts") && g(acc, "receipts") !is List<*>) return "accumulator.receipts must be an array"
        if (present(acc, "sequencer_keys") && g(acc, "sequencer_keys") !is List<*>) return "accumulator.sequencer_keys must be an array"
        val re = g(x, "revocation_epochs") as List<*>
        for (i in re.indices) {
            val r = re[i]
            val e = closed(r, listOf("epoch", "revoked"), "revocation_epochs[$i]")
            if (e != null) return e
            if (!isObj(g(r, "epoch")) || g(r, "revoked") !is List<*>) return "revocation_epochs[$i] needs an epoch and its revoked list"
        }
        val an = g(x, "anchors") as List<*>
        for (i in an.indices) {
            val e = closed(an[i], listOf("kind", "digest", "index", "proof", "signed_tree_head"), "anchors[$i]")
            if (e != null) return e
        }
        val ef = g(x, "effects") as List<*>
        for (i in ef.indices) {
            val e = ef[i]
            if (!isObj(e) || !isStr(g(e, "pcactn_digest"))) return "effects[$i] needs a pcactn_digest"
        }
        return null
    }

    // ---- normal form ----

    private val MAX_SAFE = Json.Num("9007199254740991")

    private fun seqOf(cap: Any?): Any? {
        val cvs = Js.member(cap, "caveats")
        if (cvs !is List<*>) throw JsTypeError("TypeError: caveats.find is not a function")
        for (k in cvs) {
            if ("intent_session" == Js.member(k, "type")) {
                val s = Js.member(k, "seq")
                return if (isInt(s)) s else MAX_SAFE
            }
        }
        return MAX_SAFE
    }

    private fun mem(o: Any?, k: String): Any? = Js.member(o, k)

    /** A member that goes into a hashed object: an absent one is `undefined`, which the strict canonical form refuses. */
    private fun committed(o: Any?, k: String): Any? {
        val v = Js.member(o, k)
        if (v == null && !(o is Map<*, *> && o.containsKey(k))) throw IllegalArgumentException("canonicalize: unsupported type undefined")
        return v
    }

    private fun key(v: Any?): String = Pca.hashCanonical(v)

    private fun sortSet(arr: Any?) {
        if (arr == null || arr == false) return
        asList(arr, "set").sortWith { a, c -> cmp(key(a), key(c)) }
    }

    private fun withoutParams(e: Any?): Map<String, Any?> {
        val k = LinkedHashMap<String, Any?>(asMap(e, "effect"))
        k.remove("params")
        return k
    }

    /**
     * Deterministic normal form. Members that are SETS (answers, deltas, PCActns, verdicts, effects, epochs, anchors, maps,
     * canary labels) are sorted by a content key; `accumulator.events` is a SEQUENCE and is never reordered.
     */
    fun normalizeBundle(b: Any?): Map<String, Any?> {
        val x = asMap(plain(b), "bundle")
        asList(x["maps"], "maps").sortWith { a, c -> by(mem(a, "seq"), mem(c, "seq")) { cmp(mem(a, "commit"), mem(c, "commit")) } }
        asList(x["answers"], "answers").sortWith { a, c ->
            by(mem(a, "observed_at"), mem(c, "observed_at")) {
                val q = cmp(mem(a, "question_id"), mem(c, "question_id"))
                if (q != 0) q else cmp(mem(a, "sig"), mem(c, "sig"))
            }
        }
        asList(x["canary_labels"], "canary_labels").sortWith { a, c ->
            val q = cmp(mem(a, "question_id"), mem(c, "question_id"))
            if (q != 0) q else by(mem(a, "label"), mem(c, "label")) { 0 }
        }
        asList(x["deltas"], "deltas").sortWith { a, c -> by(seqOf(a), seqOf(c)) { cmp(mem(a, "id"), mem(c, "id")) } }
        asList(x["pcactns"], "pcactns").sortWith { a, c ->
            by(mem(a, "iat"), mem(c, "iat")) { by(mem(a, "counter"), mem(c, "counter")) { cmp(key(a), key(c)) } }
        }
        asList(x["verdicts"], "verdicts").sortWith { a, c ->
            val q = cmp(mem(a, "pcactn_digest"), mem(c, "pcactn_digest"))
            if (q != 0) q else cmp(key(a), key(c))
        }
        asList(x["effects"], "effects").sortWith { a, c ->
            val q = cmp(mem(a, "pcactn_digest"), mem(c, "pcactn_digest"))
            if (q != 0) q else cmp(key(withoutParams(a)), key(withoutParams(c)))
        }
        asList(x["revocation_epochs"], "revocation_epochs").sortWith { a, c ->
            by(mem(mem(a, "epoch"), "issued_at"), mem(mem(c, "epoch"), "issued_at")) {
                by(mem(mem(a, "epoch"), "epoch"), mem(mem(c, "epoch"), "epoch")) { cmp(key(a), key(c)) }
            }
        }
        asList(x["anchors"], "anchors").sortWith { a, c ->
            val q = cmp(mem(a, "kind"), mem(c, "kind"))
            if (q != 0) q else by(mem(a, "index"), mem(c, "index")) { cmp(mem(a, "digest"), mem(c, "digest")) }
        }
        sortSet(x["facts"])
        sortSet(x["classifier"])
        sortSet(x["offer_sets"])
        sortSet(x["labels"])
        sortSet(x["settlements"])
        val acc = mem(x["accumulator"], "receipts")
        if (Js.truthy(acc)) asList(acc, "receipts").sortWith { a, c -> cmp(key(a), key(c)) }
        return x
    }

    /** Assemble a bundle in normal form. Throws on a malformed part (the exporter's bug, not evidence). */
    fun buildEvidenceBundle(parts: Map<String, Any?>): Map<String, Any?> {
        val raw = LinkedHashMap<String, Any?>()
        raw["v"] = Json.Num("1")
        raw["kind"] = "pca-intent-evidence"
        raw.putAll(parts)
        val b = normalizeBundle(raw)
        val bad = bundleShapeError(b)
        if (bad != null) throw IllegalArgumentException("buildEvidenceBundle: $bad")
        return b
    }

    /** The commitments-only normal form: no anchors, no statement opening, no full maps, no effect params. */
    fun commitmentForm(b: Any?): Map<String, Any?> {
        val n = normalizeBundle(b)
        val out = LinkedHashMap<String, Any?>(n)
        out.remove("anchors")
        out["statement"] = linkedMapOf<String, Any?>("commit" to committed(n["statement"], "commit"))
        val maps = ArrayList<Any?>()
        for (m in asList(n["maps"], "maps")) {
            val e = LinkedHashMap<String, Any?>()
            e["seq"] = committed(m, "seq")
            e["commit"] = committed(m, "commit")
            if (m is Map<*, *> && m.containsKey("disclosed")) e["disclosed"] = m["disclosed"]
            maps.add(e)
        }
        out["maps"] = maps
        val effects = ArrayList<Any?>()
        for (e in asList(n["effects"], "effects")) effects.add(withoutParams(e))
        out["effects"] = effects
        return out
    }

    /** The bundle's content address: H over the commitments-only normal form. */
    fun evidenceDigest(b: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to EVIDENCE_DOMAIN, "b" to commitmentForm(b)))
}
