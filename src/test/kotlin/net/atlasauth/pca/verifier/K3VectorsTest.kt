package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * K3 operational-plane artifacts (consistency tokens, signed policy bundles, decision log, list receipts and cursors, authority
 * comparison, grant amendment / revocation / needs approval) replayed over the shared `k3-vectors.json`: every `{name, input, expect}`
 * entry must reproduce `expect` exactly (codes, reasons, digests; key order is irrelevant, so both sides are compared in canonical form).
 */
@Suppress("UNCHECKED_CAST")
class K3VectorsTest {
    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun run(kind: String, i: Map<String, Any?>): Any? = when (kind) {
        "fresh_at_verify" -> mapOf("valid" to FreshAt.verify(i["token"], i["signer"] as String))
        "fresh_at_digest" -> mapOf("digest" to FreshAt.digest(i["token"]))
        "fresh_at_check" -> {
            val o = m(i["options"])
            val age = if (o.containsKey("maxTokenAgeMs")) Json.asLong(o["maxTokenAgeMs"]) else null
            FreshAt.check(i["token"], FreshAt.State.fromJson(i["local"])!!, o["signer"] as String, o["scope"] as String, Json.asLong(o["now"]), age).toJson()
        }
        "bundle_digest" -> mapOf("digest" to Bundle.digest(i["bundle"]))
        "bundle_verify" -> {
            val o = m(i["options"])
            val last = (o["last"] as? Map<String, Any?>)?.let { Bundle.Last(Json.asLong(it["revision"]), it["digest"] as String) }
            val signers = (o["signers"] as List<*>).map { it as String }
            Bundle.verify(i["bundle"], signers, Json.asLong(o["threshold"]), o["verifierVersion"] as String, last).toJson()
        }
        "log_commit" -> mapOf("commit" to Bundle.recordCommit(i["record"]))
        "log_head_verify" -> mapOf("valid" to Bundle.verifyLogHead(i["head"], i["signer"] as String))
        "log_inclusion" -> mapOf("valid" to Bundle.verifyRecordInclusion(i["record"], i["proof"], i["head"], i["signer"] as String))
        "log_batch_verify" -> {
            val st = m(i["state"])
            Bundle.verifyBatch(i["batch"], Json.asLong(st["next"]), st["lastCommit"] as String, i["signer"] as String).toJson()
        }
        "list_objects_digest" -> mapOf("digest" to ListAuthorized.objectsDigest(i["objects"]))
        "list_receipt_verify" -> mapOf("valid" to ListAuthorized.verifyReceipt(i["receipt"], i["signer"] as String, (i["objects"] as? List<*>)?.toList()))
        "list_bind" -> mapOf("digest" to ListAuthorized.listBind(m(i["bind"])))
        "list_cursor_verify" -> ListAuthorized.verifyCursor(i["cursor"], i["signer"] as String, i["bind"] as? Map<String, Any?>).toJson()
        "authority_digest" -> mapOf("digest" to GrantResource.authorityDigest(m(i["authority"])))
        "authority_compare" -> mapOf("order" to GrantResource.compareAuthority(m(i["old"]), m(i["new"])))
        "amend_verify" -> GrantResource.verifyAmendment(m(i["grant"]), i["request"], i["step_up_ok"] == true).toJson()
        "revoke_verify" -> GrantResource.verifyRevokeSignature(m(i["root"]), i["scope"], i["sig"]).toJson()
        "need_approve_verify" -> GrantResource.verifyNeedApproval(m(i["need_request"]), m(i["grant"]), i["approved"], i["sig"], i["step_up_ok"] == true).toJson()
        else -> throw IllegalStateException("unknown K3 vector kind $kind")
    }

    private val kinds = listOf(
        "fresh_at_verify", "fresh_at_digest", "fresh_at_check", "bundle_digest", "bundle_verify", "log_commit", "log_head_verify", "log_inclusion",
        "log_batch_verify", "list_objects_digest", "list_receipt_verify", "list_bind", "list_cursor_verify", "authority_digest", "authority_compare",
        "amend_verify", "revoke_verify", "need_approve_verify",
    )

    @Test
    fun everyKindReplaysExactly() {
        val prim = m(ParityVectors.load("k3-vectors.json")["primitives"])
        // a kind added to the corpus must be replayed here (never skipped)
        assertEquals(kinds.sorted(), prim.keys.sorted())
        var n = 0
        for (kind in kinds) {
            val entries = prim[kind] as List<Any?>
            assertTrue("$kind has vectors", entries.isNotEmpty())
            for (e in entries) {
                val x = m(e)
                val got = Json.canonicalize(run(kind, m(x["input"])))
                assertEquals("$kind / ${x["name"]}", Json.canonicalize(x["expect"]), got)
                n++
            }
        }
        assertTrue("replayed $n vectors", n >= 120)
    }
}
