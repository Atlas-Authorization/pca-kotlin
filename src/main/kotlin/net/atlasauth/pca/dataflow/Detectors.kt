package net.atlasauth.pca.dataflow

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.IntentArtifacts
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Detector adapters: vendor guardrail responses to signed, tighten-only receipts. The gateway that calls a detector signs what it
 * saw; the verifier pins the gateway key and folds the receipts, where `suspicious` can only lower a decision and `no_finding` is
 * exactly no receipt. The adapters are deliberately one-sided: a response is `no_finding` only when it is well-formed AND says nothing
 * was detected; anything malformed, unexpected or ambiguous becomes `suspicious` with the category `detector_error`. Responses are
 * JSON trees. The adapter context is a Map: `detector`, `version`, `content` (any JSON), `secretKey` (the gateway's 32-byte Ed25519
 * seed, a `ByteArray`), `now` (epoch ms), and the optional `session` / `calibration_ref`. Receipts are signed with Ed25519.
 */
object Detectors {
    const val DETECTOR_RECEIPT_DOMAIN = "atlas-pca/detector-receipt/v1\u0000"
    const val DETECTOR_RECEIPT_REF_DOMAIN = "atlas-pca/detector-receipt-ref/v1"

    /** The most receipts one action may carry; a longer list is malformed (the signal escalates). */
    const val MAX_DETECTOR_RECEIPTS = 32

    @JvmField val DETECTOR_VERDICTS: List<String> = listOf("suspicious", "no_finding")
    private val CAT_RE = Regex("[a-z][a-z0-9_]{0,63}")
    private val NON_ALNUM = Regex("[^a-z0-9]+")
    private val EDGE_UNDERSCORES = Regex("^_+|_+$")
    private val LEADING_DIGIT = Regex("^([0-9])")
    private val REQUIRED = listOf("v", "kind", "detector", "version", "input_digest", "verdict", "categories", "iat", "sig")
    private val OPTIONAL = listOf("session", "calibration_ref", "alg", "pq_pk", "pq_sig")

    /** The digest a receipt binds: b64u(sha256(strictCanonical({d, content}))). */
    @JvmStatic fun detectorInputDigest(content: Any?): String =
        Pca.hashCanonical(linkedMapOf<String, Any?>("d" to "atlas-pca/detector-input/v1", "content" to content))

    /** Vendor category text to a receipt category id (lowercase, non-alphanumerics to `_`); unusable text becomes `other`. */
    @JvmStatic fun categoryId(s: Any?): String {
        if (s !is String) return "other"
        var c = s.lowercase(java.util.Locale.ROOT)
        c = NON_ALNUM.replace(c, "_")
        c = EDGE_UNDERSCORES.replace(c, "")
        c = LEADING_DIGIT.replace(c, "c_$1")
        if (c.length > 64) c = c.substring(0, 64)
        return if (CAT_RE.matches(c)) c else "other"
    }

    private fun u8len(s: String): Int {
        var n = 0
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c.code < 0x80) n += 1
            else if (c.code < 0x800) n += 2
            else if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { n += 4; i++ }
            else n += 3 // BMP, or a lone surrogate (U+FFFD in UTF-8)
            i++
        }
        return n
    }

    private fun boundedString(v: Any?, max: Int): Boolean = v is String && v.isNotEmpty() && u8len(v) <= max

    internal fun isSafeInteger(o: Any?): Boolean {
        val d = Js.num(o) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0
    }

    /** Null when the receipt is well-formed (the shape the gateway signs). */
    internal fun receiptShapeError(r: Map<String, Any?>): String? {
        for (k in r.keys) if (!REQUIRED.contains(k) && !OPTIONAL.contains(k)) return "unknown member 'receipt.$k'"
        for (k in REQUIRED) if (!r.containsKey(k)) return "missing member 'receipt.$k'"
        if (Js.num(r["v"]) != 1.0 || "pca-detector-receipt" != r["kind"]) return "not a pca-detector-receipt v1"
        val det = r["detector"]
        if (det !is String || !CAT_RE.matches(det)) return "detector id is malformed"
        if (!boundedString(r["version"], 64)) return "version must be 1..64 bytes"
        if (Pca.decodeB64uStrict(r["input_digest"], 32) == null) return "input_digest must be a b64u 32-byte digest"
        if ("suspicious" != r["verdict"] && "no_finding" != r["verdict"]) return "verdict must be 'suspicious' or 'no_finding'"
        val cl = r["categories"]
        if (cl !is List<*> || cl.size > 8) return "categories must be 0..8 ids"
        for (x in cl) if (x !is String || !CAT_RE.matches(x)) return "categories must be 0..8 ids"
        for (i in 1 until cl.size) if ((cl[i - 1] as String) >= (cl[i] as String)) return "categories must be sorted and distinct"
        if ("no_finding" == r["verdict"] && cl.isNotEmpty()) return "a no_finding receipt carries no categories"
        val iat = r["iat"]
        val iv = Js.num(iat)
        if (!(isSafeInteger(iat) && iv!! >= 0 && !Js.isNegZero(iat))) return "iat must be a non-negative integer"
        if (r.containsKey("session") && Pca.decodeB64uStrict(r["session"], 32) == null) return "session must be a b64u 32-byte id"
        if (r.containsKey("calibration_ref") && !boundedString(r["calibration_ref"], 256)) return "calibration_ref must be 1..256 bytes"
        if (r["sig"] !is String) return "sig must be a string"
        return IntentArtifacts.artifactSuiteError(r)
    }

    private fun receipt(ctx: Map<String, Any?>, suspicious: Boolean, categories: Set<String>): Map<String, Any?> {
        val cats = ArrayList<Any?>()
        if (suspicious) cats.addAll(categories.sorted().take(8))
        val body = LinkedHashMap<String, Any?>()
        body["v"] = Json.Num("1")
        body["kind"] = "pca-detector-receipt"
        body["detector"] = ctx["detector"]
        body["version"] = ctx["version"]
        body["input_digest"] = detectorInputDigest(ctx["content"])
        body["verdict"] = if (suspicious) "suspicious" else "no_finding"
        body["categories"] = cats
        body["iat"] = ctx["now"]
        if (ctx.containsKey("session")) body["session"] = ctx["session"]
        if (ctx.containsKey("calibration_ref")) body["calibration_ref"] = ctx["calibration_ref"]
        val seed = ctx["secretKey"] as ByteArray
        val signed = Issue.signArtifact(DETECTOR_RECEIPT_DOMAIN, body, Keys.ed25519(Keys.edFromSeed(seed)))
        val e = receiptShapeError(signed)
        require(e == null) { "signDetectorReceipt: $e" }
        return signed
    }

    private fun errorReceipt(ctx: Map<String, Any?>): Map<String, Any?> = receipt(ctx, true, linkedSetOf("detector_error"))

    /** Lakera Guard v2 `/guard` response. */
    @JvmStatic fun lakeraReceipt(response: Any?, ctx: Map<String, Any?>): Map<String, Any?> {
        if (response !is Map<*, *> || response["flagged"] !is Boolean) return errorReceipt(ctx)
        val cats = LinkedHashSet<String>()
        if (response.containsKey("breakdown")) {
            val bd = response["breakdown"] as? List<*> ?: return errorReceipt(ctx)
            for (b in bd) {
                if (b !is Map<*, *> || b["detected"] !is Boolean) return errorReceipt(ctx)
                if (b["detected"] == true) cats.add(categoryId(b["detector_type"]))
            }
        }
        val suspicious = response["flagged"] == true || cats.isNotEmpty()
        if (suspicious && cats.isEmpty()) cats.add("flagged")
        return receipt(ctx, suspicious, cats)
    }

    /** Prompt Security `/api/protect` response (shape UNVERIFIED against the vendor; both open-source integration shapes accepted). */
    @JvmStatic fun promptSecurityReceipt(response: Any?, ctx: Map<String, Any?>): Map<String, Any?> {
        val rm = (response as? Map<*, *>)?.get("result") as? Map<*, *> ?: return errorReceipt(ctx)
        val hasP = rm.containsKey("prompt")
        val p = rm["prompt"]
        if (hasP && p !is Map<*, *>) return errorReceipt(ctx)
        val actions = ArrayList<Any?>()
        if (rm.containsKey("action")) actions.add(rm["action"])
        if (p is Map<*, *> && p.containsKey("action")) actions.add(p["action"])
        if (actions.isEmpty() || actions.any { it !is String }) return errorReceipt(ctx)
        val hasV = p is Map<*, *> && p.containsKey("violations")
        val violations = if (hasV) (p as Map<*, *>)["violations"] else null
        if (hasV && violations !is List<*>) return errorReceipt(ctx)
        val cats = LinkedHashSet<String>()
        if (violations is List<*>) for (v in violations) cats.add(categoryId(v))
        if (actions.contains("block")) cats.add("blocked")
        if (actions.contains("modify")) cats.add("modified")
        return receipt(ctx, cats.isNotEmpty(), cats)
    }

    /** Any detector that answers `{flagged, categories?}`. */
    @JvmStatic fun genericReceipt(response: Any?, ctx: Map<String, Any?>): Map<String, Any?> {
        if (response !is Map<*, *> || response["flagged"] !is Boolean) return errorReceipt(ctx)
        val hasC = response.containsKey("categories")
        val cs = response["categories"]
        if (hasC && cs !is List<*>) return errorReceipt(ctx)
        val cats = LinkedHashSet<String>()
        if (cs is List<*>) for (c in cs) cats.add(categoryId(c))
        val flagged = response["flagged"] == true
        if (!flagged && cats.isNotEmpty()) return errorReceipt(ctx) // categories on a clean answer: ambiguous
        if (flagged && cats.isEmpty()) cats.add("flagged")
        return receipt(ctx, flagged, cats)
    }

    /** Content address of a receipt (signature included). */
    @JvmStatic fun detectorReceiptRef(r: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to DETECTOR_RECEIPT_REF_DOMAIN, "receipt" to r))

    /** Null when the receipt is well-formed. */
    @Suppress("UNCHECKED_CAST")
    @JvmStatic fun detectorReceiptShapeError(r: Any?): String? = if (r is Map<*, *>) receiptShapeError(r as Map<String, Any?>) else "receipt must be an object"

    private fun closedOk(m: Map<*, *>, required: List<String>, optional: List<String>): Boolean =
        m.keys.all { it in required || it in optional } && required.all { m.containsKey(it) }

    /** Null when the policy `{detectors: [{id, keys, on_suspicious, max_age_ms, categories?}]}` is well-formed. */
    @JvmStatic fun detectorPolicyError(p: Any?): String? {
        if (p !is Map<*, *> || !closedOk(p, listOf("detectors"), emptyList())) return "policy must be {detectors}"
        val ds = p["detectors"] as? List<*>
        if (ds == null || ds.size > 16) return "detectors must hold at most 16 entries"
        val ids = HashSet<String>()
        for (d in ds) {
            if (d !is Map<*, *> || !closedOk(d, listOf("id", "keys", "on_suspicious", "max_age_ms"), listOf("categories"))) return "detector entry is malformed"
            val id = d["id"]
            if (id !is String || !CAT_RE.matches(id) || id == "invalid" || !ids.add(id)) return "detector ids must be distinct ids other than \"invalid\""
            val keys = d["keys"] as? List<*>
            if (keys == null || keys.size < 1 || keys.size > 8 || !keys.all { k -> k is Map<*, *> && k["pk"] is String && (!k.containsKey("pq_pk") || k["pq_pk"] is String) }) return "detector '$id': keys must hold 1..8 pins"
            if (d["on_suspicious"] != "escalate" && d["on_suspicious"] != "deny") return "detector '$id': on_suspicious must be escalate or deny"
            if (d.containsKey("categories")) {
                val c = d["categories"]
                if (!(c is List<*> && c.size >= 1 && c.all { it is String && CAT_RE.matches(it) })) return "detector '$id': categories must be 1+ ids"
            }
            val age = d["max_age_ms"]
            val av = Js.num(age)
            if (!(isSafeInteger(age) && av != null && av >= 1 && av <= 86_400_000)) return "detector '$id': max_age_ms must be 1..86400000"
        }
        return null
    }

    private val RANK = mapOf("ok" to 2, "escalate" to 1, "deny" to 0)

    @Suppress("UNCHECKED_CAST")
    private fun receiptProblem(r: Any?, policy: Map<String, Any?>, digests: List<*>, session: Any?, now: Double): String? {
        val se = detectorReceiptShapeError(r)
        if (se != null) return "malformed: $se"
        val rc = r as Map<String, Any?>
        val d = (policy["detectors"] as List<*>).map { it as Map<String, Any?> }.firstOrNull { it["id"] == rc["detector"] } ?: return "undeclared detector '${rc["detector"]}'"
        val id = d["id"]
        val signed = (d["keys"] as List<*>).any { k -> k is Map<*, *> && IntentArtifacts.verifyArtifactSig(DETECTOR_RECEIPT_DOMAIN, rc, k["pk"], k["pq_pk"]) }
        if (!signed) return "detector '$id': no pinned key signed it"
        if (!digests.contains(rc["input_digest"])) return "detector '$id': the receipt is about other content"
        if (rc.containsKey("session") && rc["session"] != session) return "detector '$id': bound to another session"
        val iat = Js.num(rc["iat"])!!
        if (!(iat <= now)) return "detector '$id': from the future"
        if (!(now - iat <= Js.num(d["max_age_ms"])!!)) return "detector '$id': stale"
        return null
    }

    /**
     * The tighten-only fold of detector receipts. Total. [input] is `{receipts?, policy, input_digests, session?, now}`. A malformed
     * policy is `deny`. For each receipt: shape, declared detector, a pinned key's signature, content in `input_digests`, session (when
     * the receipt has one it must equal `session`), `iat <= now`, age `<= max_age_ms`. A valid `suspicious` with an acting category
     * lowers the signal to the detector's `on_suspicious`; a valid `no_finding` does nothing; an invalid receipt lowers it to
     * `escalate`. The outcome with any set of receipts is at most the outcome with none. Returns `{signal, env: {detect}, flagged, rejected}`.
     */
    @Suppress("UNCHECKED_CAST")
    @JvmStatic fun detectorSignal(input: Map<String, Any?>): Map<String, Any?> {
        val flagged = java.util.TreeSet<String>()
        val rejected = ArrayList<Any?>()
        var signal = "ok"
        fun lower(s: String) { if (RANK[s]!! < RANK[signal]!!) signal = s }
        fun rej(index: Long, reason: String) { rejected.add(linkedMapOf<String, Any?>("index" to index, "reason" to reason)) }
        val env = LinkedHashMap<String, Any?>()
        try {
            val policy = input["policy"]
            val pe = detectorPolicyError(policy)
            if (pe != null) {
                return linkedMapOf(
                    "signal" to "deny", "env" to linkedMapOf<String, Any?>("detect" to linkedMapOf<String, Any?>("invalid" to 0L)),
                    "flagged" to ArrayList<Any?>(), "rejected" to arrayListOf<Any?>(linkedMapOf<String, Any?>("index" to -1L, "reason" to "policy: $pe")),
                )
            }
            val pol = policy as Map<String, Any?>
            val dets = (pol["detectors"] as List<*>).map { it as Map<String, Any?> }
            for (d in dets) env[d["id"] as String] = false
            val receiptsRaw = if (input.containsKey("receipts") && input["receipts"] != null) input["receipts"] else ArrayList<Any?>()
            val digests = input["input_digests"] as? List<*> ?: emptyList<Any?>()
            val nowRaw = input["now"]
            if (receiptsRaw !is List<*> || receiptsRaw.size > MAX_DETECTOR_RECEIPTS || !isSafeInteger(nowRaw)) {
                lower("escalate")
                rej(-1L, "receipt list or clock malformed")
            } else {
                val now = Js.num(nowRaw)!!
                receiptsRaw.forEachIndexed { index, r ->
                    val why = receiptProblem(r, pol, digests, input["session"], now)
                    if (why != null) {
                        rej(index.toLong(), why)
                        lower("escalate")
                    } else {
                        val rc = r as Map<String, Any?>
                        if (rc["verdict"] == "suspicious") {
                            val d = dets.first { it["id"] == rc["detector"] }
                            val cats = d["categories"] as? List<*>
                            val rcCats = rc["categories"] as List<*>
                            if (!(cats != null && rcCats.isNotEmpty() && rcCats.none { cats.contains(it) })) {
                                flagged.add(d["id"] as String)
                                env[d["id"] as String] = true
                                lower(d["on_suspicious"] as String)
                            }
                        }
                    }
                }
            }
        } catch (e: RuntimeException) {
            lower("deny")
            rej(-1L, "evaluation error (fail closed): " + (e.message ?: "unknown"))
        }
        env["invalid"] = rejected.size.toLong()
        return linkedMapOf("signal" to signal, "env" to linkedMapOf<String, Any?>("detect" to env), "flagged" to ArrayList<Any?>(flagged), "rejected" to rejected)
    }
}
