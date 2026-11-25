package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets

/**
 * List-authorized receipts and page cursors (packages/pca-grants/src/list-authorized.ts), VERIFICATION only: the signed receipt that
 * binds a returned object list to the subject, type, policy, filter and consistency token it was computed under, and the signed cursor that
 * binds a page to those same inputs. Ed25519 over `domain || strictCanonical(body)`. Total: never throws.
 */
object ListAuthorized {
    const val LIST_RECEIPT_DOMAIN = "atlas-pca/list-receipt/v1\u0000"
    const val LIST_CURSOR_DOMAIN = "atlas-pca/list-cursor/v1\u0000"
    const val LIST_OBJECTS_DOMAIN = "atlas-pca/list-objects/v1"

    /** Digest of the returned object ids, in order. */
    @JvmStatic
    fun objectsDigest(objects: Any?): String = K3Sig.digestOf("d" to LIST_OBJECTS_DOMAIN, "o" to objects)

    /**
     * What a cursor is bound to. `bind` holds `subject`, `resourceType`, `filterId`, `policyDigest`, `limit` and optionally
     * `relation: {relation}`; changing any of them between pages is refused.
     */
    @JvmStatic
    fun listBind(bind: Map<String, Any?>): String {
        val relation = (bind["relation"] as? Map<*, *>)?.get("relation")
        return K3Sig.digestOf(
            "s" to bind["subject"], "t" to bind["resourceType"], "f" to bind["filterId"], "p" to bind["policyDigest"], "r" to relation, "l" to bind["limit"],
        )
    }

    /**
     * The receipt is well formed and signed by `signer`; with `objects` (the list the caller received) it must also commit to exactly
     * those ids (same count, same order-sensitive digest).
     */
    @JvmStatic
    fun verifyReceipt(receipt: Any?, signer: String, objects: List<Any?>? = null): Boolean {
        return try {
            val r = K3Sig.map(receipt) ?: return false
            if (IntentJs.num(r["v"]) != 1.0 || r["signer"] != signer || !K3Sig.isStr(r["subject"]) || !K3Sig.isStr(r["resource_type"]) || !K3Sig.isSafeInt(r["count"]) || !K3Sig.isSafeInt(r["issued_at"])) return false
            if (!K3Sig.verifyBody(LIST_RECEIPT_DOMAIN, K3Sig.without(r, "sig"), signer, r["sig"])) return false
            objects == null || (objects.size.toLong() == IntentJs.lng(r["count"]) && objectsDigest(objects) == r["objects_digest"])
        } catch (e: RuntimeException) {
            false
        }
    }

    /** `ok`: the resume point ([inner] when present, [skip]). Otherwise [reason] is `malformed`, `signature` or `bind`. */
    class Cursor(val ok: Boolean, val inner: String? = null, val skip: Any? = null, val reason: String = "") {
        /** The vector form. */
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (ok) {
                if (inner != null) m["inner"] = inner
                m["skip"] = skip
            } else m["reason"] = reason
            return m
        }
    }

    private fun bad(reason: String) = Cursor(false, reason = reason)

    /** Verify a page cursor: shape, signature by `signer` and, when `bind` is given, that it was issued for exactly those inputs. */
    @JvmStatic
    fun verifyCursor(token: Any?, signer: String, bind: Map<String, Any?>? = null): Cursor {
        if (token !is String) return bad("malformed")
        return try {
            val parts = token.split('.')
            val p = parts[0]
            val s = parts.getOrNull(1)
            val extra = parts.getOrNull(2)
            val raw = if (p.isNotEmpty()) Pca.decodeB64uStrict(p, -1) else null
            val c = if (raw != null) {
                try { K3Sig.map(Json.parseLenient(String(raw, StandardCharsets.UTF_8))) } catch (e: RuntimeException) { return bad("malformed") }
            } else null
            if (extra != null || c == null || s.isNullOrEmpty() || IntentJs.num(c["v"]) != 1.0 || c["bind"] !is String || !K3Sig.isSafeInt(c["skip"]) ||
                (c.containsKey("inner") && c["inner"] !is String)
            ) return bad("malformed")
            if (c["signer"] != signer || !K3Sig.verifyBody(LIST_CURSOR_DOMAIN, c, signer, s)) return bad("signature")
            if (bind != null && c["bind"] != listBind(bind)) return bad("bind")
            Cursor(true, if (c.containsKey("inner")) c["inner"] as String else null, c["skip"])
        } catch (e: RuntimeException) {
            bad("malformed")
        }
    }
}
