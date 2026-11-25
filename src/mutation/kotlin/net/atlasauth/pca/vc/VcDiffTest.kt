package net.atlasauth.pca.vc

import java.util.Base64
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/**
 * Replays the TypeScript-reference vectors of the verifiable-identity bridge: base58btc and did:key, the bundled JSON-LD context, the
 * agent-passport SD-JWT VC (issuance compared in normalized form: random salts) and RFC 9421 / Web Bot Auth request signatures. The
 * reference ran under a pinned clock; the same instant is passed here as `now`.
 */
@Suppress("UNCHECKED_CAST")
class VcDiffTest {
    private val m = "ref-vc"
    private val now = 1_700_000_100_000.0

    private fun mm(o: Any?) = o as? Map<String, Any?>
    private fun bytes(o: Any?): ByteArray? = if (o == null) null else Keys.unb64u(mm(o)!!["\$bytes"] as String)
    private fun str(o: Any?): String = o as? String ?: throw IllegalArgumentException("not a string")
    private fun json(b64: String): Any? = Json.parseLenient(String(Base64.getUrlDecoder().decode(b64), Charsets.UTF_8))
    private fun sha(ascii: String) = Keys.b64u(Jose.sha256(ByteArray(ascii.length) { ascii[it].code.toByte() }))
    private fun filled(v: Int) = ByteArray(32) { v.toByte() }

    @Test fun base58btcEncode() = OracleCases.each(m, "base58btcEncode") { Vc.base58btcEncode(bytes(it[0])!!) }
    @Test fun base58btcDecode() = OracleCases.each(m, "base58btcDecode") { Vc.base58btcDecode(str(it[0])) }
    @Test fun didKeyFromEd25519() = OracleCases.each(m, "didKeyFromEd25519") { Vc.didKeyFromEd25519(bytes(it[0])!!) }
    @Test fun ed25519FromDidKey() = OracleCases.each(m, "ed25519FromDidKey") { Vc.ed25519FromDidKey(str(it[0])) }

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf(
            "VC_CONTEXT" to Vc.VC_CONTEXT, "AGENT_PASSPORT_CONTEXT" to Vc.AGENT_PASSPORT_CONTEXT, "AGENT_PASSPORT_VC_TYPE" to Vc.AGENT_PASSPORT_VC_TYPE,
            "AGENT_PASSPORT_CONTEXT_DIGEST" to Vc.AGENT_PASSPORT_CONTEXT_DIGEST, "AGENT_PASSPORT_CONTEXT_DOC" to Vc.AGENT_PASSPORT_CONTEXT_DOC,
        )
    }

    @Test fun resolveAgentPassportContext() = OracleCases.each(m, "resolveAgentPassportContext") { Vc.resolveAgentPassportContext(it[0]) }

    /** The reference's normalized view of an issued credential (salts are random). */
    private fun normVc(sd: String): Map<String, Any?> {
        val parts = sd.split("~")
        val ds = parts.subList(1, parts.size - 1)
        val hp = parts[0].split(".")
        val h = json(hp[0])
        val p = mm(json(hp[1]))!!
        val cs = mm(mm(p["vc"])?.get("credentialSubject")) as MutableMap<String, Any?>?
        val sdl = ((cs?.get("_sd") as? List<*>) ?: emptyList<Any?>()).map { it as String }.sorted()
        cs?.remove("_sd")
        val verified = try {
            Vc.verifyPassportVC(sd, Keys.edFromSeed(filled(1)).pub, linkedMapOf("now" to now))
            true
        } catch (e: RuntimeException) {
            false
        }
        val dig = ds.map { sha(it) }.sorted()
        val disc = ds.map { d -> (json(d) as List<*>).let { t -> listOf(t[1], t[2]) } }.sortedBy { it[0].toString() }
        return linkedMapOf(
            "end" to parts.last(), "header" to h, "payload" to p, "n" to ds.size, "digestsOk" to (dig == sdl), "disclosures" to disc, "verified" to verified,
        )
    }

    @Test fun passportToVC() = OracleCases.each(m, "passportToVC") { a ->
        val pp = a[0] ?: throw IllegalArgumentException("Cannot read properties of null")
        val o = mm(a[1])!!
        val args = linkedMapOf<String, Any?>("issuerKey" to bytes(o["issuer_seed"]))
        if (o.containsKey("issuer_did")) args["issuerDid"] = o["issuer_did"]
        if (o.containsKey("subject_did")) args["subjectDid"] = o["subject_did"]
        if (o.containsKey("ttl_sec")) args["ttlSec"] = o["ttl_sec"]
        args["now"] = now
        normVc(Vc.passportToVC(mm(pp) ?: emptyMap(), args))
    }

    @Test fun verifyPassportVC() = OracleCases.each(m, "verifyPassportVC") { a ->
        val o = linkedMapOf<String, Any?>("now" to now)
        val opts = if (a.size > 2) mm(a[2]) else null
        if (opts != null && opts.containsKey("expectedIssuerDid")) o["expectedIssuerDid"] = opts["expectedIssuerDid"]
        Vc.verifyPassportVC(a[0], bytes(a[1]), o)
    }

    @Test fun signRequestMessage() = OracleCases.each(m, "signRequestMessage") { a ->
        val i = mm(a[0])!!
        val args = linkedMapOf("method" to i["method"], "url" to i["url"], "headers" to i["headers"], "key" to bytes(i["key"]), "keyid" to i["keyid"])
        if (i.containsKey("created")) args["created"] = i["created"]
        if (i.containsKey("signature_agent")) args["signatureAgent"] = i["signature_agent"]
        args["now"] = now
        Vc.signRequestMessage(args)
    }

    private val names = listOf(
        "method" to "method", "url" to "url", "headers" to "headers", "signature_input" to "signatureInput", "signature" to "signature",
        "signature_agent" to "signatureAgent", "required_components" to "requiredComponents", "max_age_sec" to "maxAgeSec", "now_sec" to "nowSec",
    )

    @Test fun verifyRequestSignature() = OracleCases.each(m, "verifyRequestSignature") { a ->
        val i = mm(a[0])!!
        val args = LinkedHashMap<String, Any?>()
        for ((snake, cc) in names) if (i.containsKey(snake)) args[cc] = i[snake]
        args["now"] = now
        Vc.verifyRequestSignature(args, bytes(a[1]))
    }
}
