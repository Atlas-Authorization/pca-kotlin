package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.Workflow.ID_RE
import net.atlasauth.pca.verifier.Workflow.LABEL_RE
import net.atlasauth.pca.verifier.Workflow.NAME_RE
import net.atlasauth.pca.verifier.Workflow.isB32
import net.atlasauth.pca.verifier.Workflow.isScalarMap
import net.atlasauth.pca.verifier.Workflow.isStr
import net.atlasauth.pca.verifier.Workflow.isUint
import net.atlasauth.pca.verifier.Workflow.obj
import net.atlasauth.pca.verifier.Workflow.onlyKeys
import net.atlasauth.pca.verifier.Workflow.sortedUnique
import net.atlasauth.pca.verifier.Workflow.verifyBody

/**
 * Read-side authorization (K5, C-310..C-319): what an agent may SEE, proven, and where it may go next. A principal signs a read
 * grant (per verb / resource prefix / purpose a mask mode per data class, per-class caps, per-sink label rules); [ReadSide.redactRead]
 * applies it to one response (every field is shown, masked or dropped; TIGHTEN-ONLY), the resource server signs a read receipt, and
 * [ReadSide.checkSink] denies / escalates a write whose sink the grant does not allow those labels to reach. Total and pure.
 * Replays packages/pca/conformance/readside-vectors.json; mirrors packages/pca/src/readside.ts check for check.
 */
object ReadSide {
    const val READ_GRANT_DOMAIN = "atlas-pca/read-grant/v1\u0000"
    const val READ_RECEIPT_DOMAIN = "atlas-pca/read-receipt/v1\u0000"
    private const val RG_REF = "atlas-pca/read-grant-ref/v1"
    private const val RR_REF = "atlas-pca/read-receipt-ref/v1"
    private const val RH = "atlas-pca/read-hash/v1"
    private const val RT = "atlas-pca/read-token/v1"
    private const val RV = "atlas-pca/read-value/v1"
    private const val SALT_MIN = 16

    private val RANK = mapOf("show" to 0, "last4" to 1, "bucket" to 2, "token" to 3, "hash" to 4, "drop" to 5)
    private val MODE_RE = Regex("(show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8})")
    private fun isMode(x: Any?): Boolean = x is String && MODE_RE.matches(x)
    private fun rank(m: String): Int = RANK[if (m.startsWith("bucket:")) "bucket" else m]!!

    private fun validEntry(x: Any?): Boolean {
        val e = obj(x) ?: return false
        if (!onlyKeys(e, listOf("verb", "resource_prefix", "purposes", "modes", "default_mode"))) return false
        val modes = obj(e["modes"]) ?: return false
        return isStr(e["verb"], 128) && isStr(e["resource_prefix"], 512) && sortedUnique(e["purposes"], ID_RE, 16) && (e["purposes"] as List<*>).isNotEmpty() &&
            modes.size <= 32 && modes.all { (k, v) -> LABEL_RE.matches(k) && isMode(v) } && isMode(e["default_mode"])
    }

    /** Shape of a read grant body (no signature). */
    @JvmStatic
    fun validReadGrantBody(x: Any?): Boolean {
        val b = obj(x) ?: return false
        if (!onlyKeys(b, listOf("v", "id", "principal", "issued_at", "expires_at", "reads", "caps", "sinks")) || !(Json.isSafeInt(b["v"]) && Json.asLong(b["v"]) == 1L)) return false
        if (b["id"] !is String || !ID_RE.matches(b["id"] as String) || !isB32(b["principal"]) || !isUint(b["issued_at"]) || !isUint(b["expires_at"])) return false
        val reads = b["reads"] as? List<*> ?: return false
        if (reads.isEmpty() || reads.size > 32 || !reads.all({ validEntry(it) })) return false
        val caps = obj(b["caps"]) ?: return false
        if (caps.size > 32 || !caps.all { (k, v) -> LABEL_RE.matches(k) && isUint(v) }) return false
        val s = obj(b["sinks"]) ?: return false
        if (s.size > 16) return false
        return s.all { (k, v) ->
            val m = obj(v)
            ID_RE.matches(k) && m != null && onlyKeys(m, listOf("allow", "escalate")) && sortedUnique(m["allow"], LABEL_RE, 16) && sortedUnique(m["escalate"], LABEL_RE, 16) &&
                strs(m["allow"]).none { it in strs(m["escalate"]) }
        }
    }

    private fun strs(o: Any?): List<String> = (o as List<*>).map { it as String }

    @JvmStatic
    fun readGrantDigest(b: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to RG_REF, "g" to b))

    @JvmStatic
    fun readReceiptRef(r: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to RR_REF, "r" to r))

    private val RECEIPT_KEYS = listOf("v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer", "sig")

    private fun recBody(r: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for (k in RECEIPT_KEYS) if (k != "sig") m[k] = r[k]
        return m
    }

    class ReadField(val cls: String, val action: String, val kind: String?, val vd: String) {
        fun toMap(): Map<String, Any?> = linkedMapOf("class" to cls, "action" to action, "kind" to kind, "vd" to vd)
    }

    class ReadResult(val decision: String, val code: String?, val view: Map<String, Any?>, val fields: Map<String, ReadField>, val labels: List<String>, val counts: Map<String, Any?>) {
        fun toMap(): Map<String, Any?> = linkedMapOf(
            "decision" to decision, "code" to code, "view" to view, "fields" to fields.mapValues { it.value.toMap() }, "labels" to labels, "counts" to counts,
        )
    }

    /** All members are parsed JSON values (or null). */
    class ReadInput(
        val grant: Any?, val principal: Any?, val now: Any?, val verb: Any?, val resource: Any?, val purpose: Any?,
        /** `{fields: {path: class}, required: [path]}` */
        val schema: Any?, val record: Any?,
        /** class -> a STRICTER mode asked for by the caller; a weaker one is ignored (tighten-only) */
        val tighten: Any?,
        /** a per-read secret of at least 16 characters */
        val salt: Any?,
        /** reads already charged per class in the current window */
        val counts: Any?,
    )

    private fun out(decision: String, code: String?, counts: Map<String, Any?> = emptyMap()) = ReadResult(decision, code, emptyMap(), emptyMap(), emptyList(), counts)
    private fun sorted(xs: Collection<String>): List<String> = xs.toSet().sorted()
    private fun bmp(s: String): Boolean = s.codePoints().allMatch { it < 0x10000 }

    private class Grade(val body: Map<String, Any?>?, val code: String?)

    private fun gradeGrant(g: Any?, principal: Any?, now: Any?): Grade {
        if (!isB32(principal) || !isUint(now)) return Grade(null, "bad_request")
        val sg = obj(g)
        if (sg == null || !onlyKeys(sg, listOf("body", "sig")) || !validReadGrantBody(sg["body"])) return Grade(null, "bad_grant")
        val body = obj(sg["body"])!!
        if (body["principal"] != principal || !verifyBody(READ_GRANT_DOMAIN, body, principal, sg["sig"])) return Grade(null, "bad_signature")
        val n = Json.asLong(now)
        if (n < Json.asLong(body["issued_at"])) return Grade(null, "not_yet")
        if (n >= Json.asLong(body["expires_at"])) return Grade(null, "expired")
        return Grade(body, null)
    }

    /** Apply a read grant to one response. Never throws. */
    @JvmStatic
    fun redactRead(inp: ReadInput): ReadResult = try {
        redact(inp)
    } catch (e: Exception) {
        out("deny", "bad_request")
    }

    private fun redact(inp: ReadInput): ReadResult {
        val g = gradeGrant(inp.grant, inp.principal, inp.now)
        if (g.code != null) return out("deny", g.code)
        val body = g.body!!
        val bad = out("deny", "bad_request")
        if (!isB32(inp.principal) || !isStr(inp.verb, 128) || !isStr(inp.resource, 512) || inp.purpose !is String || !ID_RE.matches(inp.purpose) ||
            inp.salt !is String || inp.salt.length < SALT_MIN) return bad
        val verb = inp.verb as String
        val resource = inp.resource as String
        val purpose = inp.purpose as String
        val salt = inp.salt as String
        val sc = obj(inp.schema) ?: return bad
        val scFields = obj(sc["fields"]) ?: return bad
        if (!scFields.all { (k, v) -> NAME_RE.matches(k) && v is String && LABEL_RE.matches(v) }) return bad
        val required = sc["required"] as? List<*> ?: return bad
        if (!required.all { it is String && scFields.containsKey(it) }) return bad
        val record = obj(inp.record)
        val tighten = obj(inp.tighten)
        if (!isScalarMap(inp.record) || record == null || tighten == null || !tighten.all { (k, v) -> LABEL_RE.matches(k) && isMode(v) }) return bad
        val counts0 = obj(inp.counts)
        if (counts0 == null || !counts0.all { (k, v) -> LABEL_RE.matches(k) && isUint(v) }) return bad
        val entry = (body["reads"] as List<*>).map { obj(it)!! }.find {
            it["verb"] == verb && resource.startsWith(it["resource_prefix"] as String) && purpose in strs(it["purposes"])
        } ?: return out("deny", "no_read_scope", counts0)
        val modes = obj(entry["modes"])!!
        val fields = LinkedHashMap<String, ReadField>()
        val view = LinkedHashMap<String, Any?>()
        val used = LinkedHashMap<String, Int>()
        for (path in sorted(record.keys)) {
            val v = record[path]
            val cls = scFields[path] as String?
            // a field the schema does not classify is never shown
            val vd = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to RV, "salt" to salt, "p" to path, "v" to v))
            if (cls == null) {
                fields[path] = ReadField("unclassified", "dropped", null, vd)
                continue
            }
            var mode = (modes[cls] ?: entry["default_mode"]) as String
            val t = tighten[cls] as String?
            if (t != null && rank(t) > rank(mode)) mode = t
            var shown: Any? = null
            var action = "masked"
            var kind: String? = if (mode.startsWith("bucket:")) "bucket" else mode
            if (mode == "show") {
                shown = v
                action = "shown"
                kind = null
            } else if (mode == "last4") {
                if (v is String && bmp(v)) {
                    val cps = v.codePoints().toArray()
                    if (cps.size > 4) shown = "****" + String(cps, cps.size - 4, 4)
                }
            } else if (mode.startsWith("bucket:")) {
                val n = mode.substring(7).toLong()
                if (Json.isSafeInt(v) && Json.asLong(v) >= 0L) shown = Json.Num((Json.asLong(v) - (Json.asLong(v) % n)).toString())
            } else if (mode == "hash") {
                shown = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to RH, "salt" to salt, "c" to cls, "v" to v))
            } else if (mode == "token") {
                shown = "tok_" + Pca.hashCanonical(linkedMapOf<String, Any?>("d" to RT, "salt" to salt, "c" to cls, "v" to v)).substring(0, 22)
            }
            if (shown == null) {
                fields[path] = ReadField(cls, "dropped", null, vd)
                continue
            }
            fields[path] = ReadField(cls, action, kind, vd)
            view[path] = shown
            used[cls] = (used[cls] ?: 0) + 1
        }
        val caps = obj(body["caps"])!!
        val counts = LinkedHashMap<String, Long>()
        for ((k, c) in counts0) counts[k] = Json.asLong(c)
        for ((c, n) in used) {
            counts[c] = (counts[c] ?: 0L) + n
            if (caps.containsKey(c) && counts[c]!! > Json.asLong(caps[c])) return out("deny", "read_cap", counts0)
        }
        if (required.any { !view.containsKey(it as String) }) return out("escalate", "required_dropped", counts0)
        val labels = sorted(fields.values.filter { it.action != "dropped" }.map { it.cls })
        return ReadResult("allow", null, view, fields, labels, counts.mapValues { Json.Num(it.value.toString()) })
    }

    private fun validReadReceipt(x: Any?): Boolean {
        val r = obj(x) ?: return false
        if (!onlyKeys(r, RECEIPT_KEYS) || !(Json.isSafeInt(r["v"]) && Json.asLong(r["v"]) == 1L)) return false
        if (!isB32(r["grant"]) || !isStr(r["verb"], 128) || !isStr(r["resource"], 512) || r["purpose"] !is String || !ID_RE.matches(r["purpose"] as String) || !isUint(r["seq"]) ||
            !(r["prev"] == null || isB32(r["prev"])) || (Json.asLong(r["seq"]) == 0L) != (r["prev"] == null)) return false
        val fields = obj(r["fields"])
        if (!isUint(r["issued_at"]) || !isB32(r["signer"]) || r["sig"] !is String || !sortedUnique(r["labels"], LABEL_RE, 32) || fields == null || fields.size > 64) return false
        return fields.all { (k, fx) ->
            val f = obj(fx)
            val cls = f?.get("class")
            val act = f?.get("action")
            NAME_RE.matches(k) && f != null && onlyKeys(f, listOf("class", "action", "kind", "vd")) && cls is String && (cls == "unclassified" || LABEL_RE.matches(cls)) &&
                (act == "shown" || act == "masked" || act == "dropped") && (f["kind"] == null || f["kind"] is String) && isB32(f["vd"])
        }
    }

    /** [labels] is non-null on success; otherwise [code] (`bad_receipt`) and the offending index [at]. */
    class ChainResult(val labels: List<String>?, val code: String? = null, val at: Int = 0)

    /** The labels carried by a verified, unbroken chain of read receipts, or an error code. */
    @JvmStatic
    fun readChainLabels(receipts: Any?, rsSigner: String, grantDigest: String, now: Long): ChainResult {
        val list = receipts as? List<*> ?: return ChainResult(null, "bad_receipt", 0)
        val all = HashSet<String>()
        var prev: Map<String, Any?>? = null
        for (i in list.indices) {
            val r = obj(list[i])
            if (r == null || !validReadReceipt(r) || r["signer"] != rsSigner || r["grant"] != grantDigest || Json.asLong(r["seq"]) != i.toLong() || Json.asLong(r["issued_at"]) > now) return ChainResult(null, "bad_receipt", i)
            val p = prev
            if ((if (p == null) r["prev"] != null else r["prev"] != readReceiptRef(p)) || !verifyBody(READ_RECEIPT_DOMAIN, recBody(r), rsSigner, r["sig"])) return ChainResult(null, "bad_receipt", i)
            // the receipt's labels must be exactly the classes of its non-dropped fields: an understated label list would launder data
            val want = sorted(obj(r["fields"])!!.values.map { obj(it)!! }.filter { it["action"] != "dropped" }.map { it["class"] as String })
            if (want != strs(r["labels"])) return ChainResult(null, "bad_receipt", i)
            all.addAll(want)
            prev = r
        }
        return ChainResult(sorted(all))
    }

    /** All members are parsed JSON values (or null). */
    class SinkInput(val grant: Any?, val principal: Any?, val rsSigner: Any?, val now: Any?, val sink: Any?, val receipts: Any?)

    class SinkResult(val decision: String, val code: String?, val labels: List<String>) {
        fun toMap(): Map<String, Any?> = linkedMapOf("decision" to decision, "code" to code, "labels" to labels)
    }

    /** May data read under these receipts reach `sink`? Deny on any label the grant does not allow; escalate on an "ask" label. */
    @JvmStatic
    fun checkSink(inp: SinkInput): SinkResult {
        fun no(code: String) = SinkResult("deny", code, emptyList())
        try {
            val g = gradeGrant(inp.grant, inp.principal, inp.now)
            if (g.code != null) return no(g.code)
            val body = g.body!!
            if (!isB32(inp.rsSigner) || inp.sink !is String) return no("bad_request")
            val sinks = obj(body["sinks"])!!
            if (!sinks.containsKey(inp.sink)) return no("unknown_sink")
            val rule = obj(sinks[inp.sink])!!
            val c = readChainLabels(inp.receipts, inp.rsSigner as String, readGrantDigest(body), Json.asLong(inp.now))
            if (c.labels == null) return no(c.code!!)
            val allow = strs(rule["allow"])
            val escalate = strs(rule["escalate"])
            if (c.labels.any { it !in allow && it !in escalate }) return SinkResult("deny", "label_flow", c.labels)
            if (c.labels.any { it in escalate }) return SinkResult("escalate", "label_escalate", c.labels)
            return SinkResult("allow", null, c.labels)
        } catch (e: Exception) {
            return no("bad_request")
        }
    }
}
