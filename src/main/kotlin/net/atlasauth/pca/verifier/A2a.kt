package net.atlasauth.pca.verifier

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * The A2A binding (verification side): typed needs (`pca_need`), per-hop chain extension, the pure gate of AUTH_REQUIRED resumption,
 * push-token binding and signed task-update receipts. Total. Per-hop PCActn verification is the ordinary verifier's job; this is what
 * surrounds it. Replays packages/pca/conformance/a2a-vectors.json.
 */
object A2a {
    const val RECEIPT_DOMAIN = "atlas-pca/a2a-receipt/v1\u0000"
    private val NEED_MEMBERS = setOf("v", "kind", "verb", "resource", "scopes", "grant_ref", "limits", "discharges", "tier", "policy_digest")
    private val TERMINAL = setOf("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED")
    private val STATES = TERMINAL + setOf("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED")

    private fun num(o: Any?): Double? = if (o is Json.Num) o.raw.toDoubleOrNull()?.takeIf { it.isFinite() } else null

    /** null when valid, else the refusal code. */
    @JvmStatic
    fun needError(v: Any?): String? {
        val x = K3Sig.map(v) ?: return "bad_shape"
        if (x.keys.any { it !in NEED_MEMBERS }) return "unknown_member"
        if (num(x["v"]) != 1.0) return "bad_version"
        val kind = x["kind"]
        if (kind != "scope" && kind != "grant" && kind != "discharge" && kind != "escalate") return "bad_kind"
        if (!K3Sig.isStr(x["verb"], 128) || !K3Sig.isStr(x["resource"], 512)) return "bad_field"
        if (x.containsKey("scopes")) {
            val sc = K3Sig.list(x["scopes"])
            if (sc == null || sc.size > 16 || !sc.all { K3Sig.isStr(it, 128) && (it as String).none { c -> c.isWhitespace() } }) return "bad_field"
        }
        for (k in listOf("grant_ref", "policy_digest")) if (x.containsKey(k) && !K3Sig.isStr(x[k], 128)) return "bad_field"
        if (x.containsKey("tier")) {
            val t = num(x["tier"])
            if ((t != 2.0 && t != 3.0) || kind != "escalate") return "bad_field"
        }
        if (x.containsKey("limits")) {
            val l = K3Sig.map(x["limits"])
            if (l == null || l.size > 16 || !l.all { K3Sig.isStr(it.key, 64) && (num(it.value) ?: -1.0) >= 0.0 }) return "bad_field"
        }
        if (x.containsKey("discharges")) {
            val d = K3Sig.list(x["discharges"])
            if (d == null || d.size > 16 || !d.all { e ->
                    val m = K3Sig.map(e)
                    m != null && m.keys.all { it == "issuer" || it == "claim" } && K3Sig.isStr(m["issuer"], 512) && K3Sig.isStr(m["claim"], 256)
                }) return "bad_field"
        }
        if (kind == "escalate" && !x.containsKey("tier")) return "bad_field"
        return null
    }

    /** [need] is null on failure and [code] then names the refusal. */
    class Decoded(val need: Map<String, Any?>?, val code: String?)

    @JvmStatic
    fun decodeNeed(value: Any?): Decoded {
        if (value !is String || value.isEmpty()) return Decoded(null, "bad_base64")
        if (value.length > 2048) return Decoded(null, "too_long")
        val raw = Pca.decodeB64uStrict(value, -1) ?: return Decoded(null, "bad_base64")
        val text = try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString()
        } catch (e: CharacterCodingException) {
            return Decoded(null, "bad_utf8")
        }
        val parsed = try {
            Json.parse(text)
        } catch (e: RuntimeException) {
            return Decoded(null, "bad_json")
        }
        val code = needError(parsed)
        return if (code == null) Decoded(K3Sig.map(parsed), null) else Decoded(null, code)
    }

    @JvmStatic
    fun needDigest(need: Map<String, Any?>): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to "atlas-pca/need/v1", "need" to need))

    /** null when ok, else (failedHop, reason). */
    @JvmStatic
    fun checkChainExtension(chains: List<List<String>>): Pair<Int, String>? {
        for ((i, ids) in chains.withIndex()) {
            if (ids.isEmpty()) return i to "no_chain"
            if (i > 0) {
                val prev = chains[i - 1]
                if (ids.size < prev.size || ids.subList(0, prev.size) != prev) return i to "chain_does_not_extend_previous_hop"
            }
        }
        return null
    }

    /** null when the full verifier may now be asked, else the refusal code. A null [proofVerb] means no proof. */
    @JvmStatic
    fun resumeGate(state: String?, needEncoded: Any?, answerDigest: Any?, proofVerb: String?, proofResource: String?): String? {
        if (state != "TASK_STATE_AUTH_REQUIRED" && state != "auth-required") return "task_not_auth_required"
        val need = if (needEncoded == null) null else decodeNeed(needEncoded).need
        if (need == null) return "no_valid_need"
        if (answerDigest != needDigest(need)) return "answer_not_bound_to_need"
        if (proofVerb == null || proofResource == null) return "no_proof"
        if (proofVerb != need["verb"] || proofResource != need["resource"]) return "action_mismatch"
        return null
    }

    /** null where the reference throws (a salt shorter than 16 characters). */
    @JvmStatic
    fun pushToken(taskId: String, chainIds: List<String>, salt: Any?): String? {
        if (salt !is String || salt.length < 16) return null
        return Pca.hashCanonical(linkedMapOf<String, Any?>("d" to "atlas-pca/a2a-push/v1", "task_id" to taskId, "chain" to PcaGrant.chainDigest(chainIds), "salt" to salt))
    }

    /** null when ok, else the reason. */
    @JvmStatic
    fun checkPush(taskId: String, chainIds: List<String>, salt: String, token: Any?, payload: Any?): String? {
        if (token !is String || token.isEmpty()) return "no_token"
        val want = pushToken(taskId, chainIds, salt)
        if (want == null || want != token) return "token_mismatch"
        val p = K3Sig.map(payload)
        if (p != null) {
            for ((key, field) in listOf("task" to "id", "statusUpdate" to "taskId", "artifactUpdate" to "taskId")) {
                val v = K3Sig.map(p[key])?.get(field)
                if (v != null) return if (v == taskId) null else "task_mismatch"
            }
        }
        return "task_mismatch"
    }

    @JvmStatic
    fun receiptDigest(r: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to "atlas-pca/a2a-receipt-ref/v1", "r" to r))

    @JvmStatic
    fun verifyReceipt(v: Any?, signer: String): Boolean {
        val r = K3Sig.map(v) ?: return false
        if (num(r["v"]) != 1.0 || r["signer"] != signer) return false
        if (!K3Sig.isStr(r["task_id"], 4096) || r["state"] !in STATES) return false
        if (!K3Sig.isSafeInt(r["seq"]) || !K3Sig.isSafeInt(r["issued_at"])) return false
        if (Pca.decodeB64uStrict(r["chain"], 32) == null) return false
        val prev = r["prev"]
        if (prev != null && Pca.decodeB64uStrict(prev, 32) == null) return false
        if ((IntentJs.lng(r["seq"]) == 0L) != (prev == null)) return false
        val body = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer")) body[k] = r[k]
        return K3Sig.verifyBody(RECEIPT_DOMAIN, body, signer, r["sig"])
    }

    /** [code] null means ok. */
    class ReceiptChain(val code: String?, val at: Int = -1, val terminal: Boolean = false, val lastState: String? = null)

    @JvmStatic
    fun checkReceiptChain(receipts: List<Any?>, signer: String, taskId: String, chainIds: List<String>): ReceiptChain {
        if (receipts.isEmpty()) return ReceiptChain("empty")
        val chain = PcaGrant.chainDigest(chainIds)
        var prev: Map<String, Any?>? = null
        for ((i, x) in receipts.withIndex()) {
            if (!verifyReceipt(x, signer)) return ReceiptChain("bad_receipt", i)
            val r = K3Sig.map(x)!!
            if (r["task_id"] != taskId) return ReceiptChain("wrong_task", i)
            if (r["chain"] != chain) return ReceiptChain("wrong_chain", i)
            val seq = IntentJs.lng(r["seq"])
            val p = prev
            if (p == null) {
                if (seq != 0L) return ReceiptChain("bad_start", i)
            } else {
                if (p["state"] in TERMINAL) return ReceiptChain("after_terminal", i)
                if (seq != IntentJs.lng(p["seq"]) + 1 || r["prev"] != receiptDigest(p)) return ReceiptChain("broken_link", i)
            }
            prev = r
        }
        val last = prev!!["state"] as String
        return ReceiptChain(null, -1, last in TERMINAL, last)
    }

    @JvmStatic
    fun mayTriggerNext(receipts: List<Any?>, signer: String, taskId: String, chainIds: List<String>): Boolean {
        val r = checkReceiptChain(receipts, signer, taskId, chainIds)
        return r.code == null && r.lastState == "TASK_STATE_COMPLETED"
    }
}
