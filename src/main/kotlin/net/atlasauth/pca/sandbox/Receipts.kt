package net.atlasauth.pca.sandbox

import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * Runtime classes and the append-only hash chain of use receipts: every handle use and every egress decision, refusals
 * included. Receipts are JSON objects (maps), byte-identical to the reference's.
 */
@Suppress("UNCHECKED_CAST")
object Receipts {
    /** Runtime classes, weakest first. The class is a claim by the host operator, recorded in every receipt. */
    @JvmField
    val RUNTIME_CLASSES: List<String> = listOf("none", "os_confined", "egress_default_deny", "wasi_no_ambient")

    const val GENESIS = "genesis"

    /** True only when both names are known and [attested] is at least [required]. An unknown name never satisfies. */
    @JvmStatic
    fun satisfiesRuntimeClass(attested: Any?, required: Any?): Boolean {
        val a = if (attested is String) RUNTIME_CLASSES.indexOf(attested) else -1
        val r = if (required is String) RUNTIME_CLASSES.indexOf(required) else -1
        return a >= 0 && r >= 0 && a >= r
    }

    /** Append-only hash chain of receipts. [now]: the host clock as a JSON number (default: epoch ms); [sign]: optional host signature over a digest. */
    class ReceiptLog @JvmOverloads constructor(now: (() -> Any?)? = null, private val sign: ((String) -> String)? = null) {
        private val entriesList = ArrayList<Map<String, Any?>>()
        private val now: () -> Any? = now ?: { System.currentTimeMillis() }

        fun entries(): List<Map<String, Any?>> = entriesList

        /** Append a receipt; [body] carries kind, subject, outcome and reason. A throwing clock or signer appends nothing. */
        @Synchronized
        fun append(runtimeClass: String, body: Map<String, Any?>): Map<String, Any?> {
            val unsigned = LinkedHashMap<String, Any?>()
            unsigned["v"] = 1L
            unsigned["seq"] = entriesList.size.toLong()
            unsigned["prev"] = if (entriesList.isEmpty()) GENESIS else entriesList[entriesList.size - 1]["digest"]
            unsigned["at"] = now()
            unsigned["runtime_class"] = runtimeClass
            unsigned.putAll(body)
            val digest = Pca.hashCanonical(unsigned)
            val r = LinkedHashMap(unsigned)
            r["digest"] = digest
            if (sign != null) r["sig"] = sign.invoke(digest)
            entriesList.add(r)
            return r
        }
    }

    /**
     * Recompute the chain. Fails on a bad digest, a broken link, a gap, a reorder, or (with [verifySig]) a bad signature.
     * Returns `{ok:true}` or `{ok:false, at, reason}`. A receipt list that is not a list, or a null receipt, throws (as the reference does).
     */
    @JvmStatic
    fun verifyReceiptChain(receipts: Any?, verifySig: ((String, String) -> Boolean)?): Map<String, Any?> {
        if (receipts !is List<*>) throw JsTypeError("receipts is not iterable")
        var prev = GENESIS
        for (i in receipts.indices) {
            val r = receipts[i] ?: throw JsTypeError("cannot read 'v' of null")
            val vn = IntentJs.num(if (r is Map<*, *>) r["v"] else null)
            val sn = IntentJs.num(if (r is Map<*, *>) r["seq"] else null)
            if (vn == null || vn != 1.0 || sn == null || sn != i.toDouble()) return fail(i, "bad_seq")
            val m = r as Map<String, Any?>
            if (prev != m["prev"]) return fail(i, "broken_link")
            val rest = LinkedHashMap<String, Any?>()
            for ((k, v) in m) if (k != "digest" && k != "sig") rest[k] = v
            val digest = m["digest"]
            if (Pca.hashCanonical(rest) != digest) return fail(i, "bad_digest")
            val sig = m["sig"]
            if (verifySig != null && (sig !is String || !verifySig(digest as String, sig))) return fail(i, "bad_sig")
            prev = digest as String
        }
        return linkedMapOf("ok" to true)
    }

    private fun fail(at: Int, reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "at" to at.toLong(), "reason" to reason)
}
