package net.atlasauth.pca.notary

import java.security.MessageDigest
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the notary (attestation, selective disclosure, PCActn binding and the attested_fact caveat). */
class NotaryDiffTest {
    private val m = "ref-notary"

    @Suppress("UNCHECKED_CAST")
    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun isBytes(o: Any?): Boolean = o is Map<*, *> && o.containsKey("\$bytes")

    private fun bytes(o: Any?): ByteArray = Keys.unb64u(map(o)["\$bytes"] as String)

    /** The oracle's key forms: a b64u string, {"$bytes"} public bytes, a {secretKey, publicKey} pair; anything else is passed through (and refused). */
    private fun keyArg(o: Any?): Any? {
        if (isBytes(o)) return bytes(o)
        if (o is Map<*, *>) {
            val mm = map(o)
            if (isBytes(mm["secretKey"]) && isBytes(mm["publicKey"])) return Keys.edFromSeed(bytes(mm["secretKey"]))
            // the lane copy of the corpus carries a repeated-byte test seed as its label: {"$seed": "fill:<n>"} is 32 bytes of n
            val sk = mm["secretKey"]
            if (sk is Map<*, *> && isBytes(mm["publicKey"])) {
                val label = sk["\$seed"] as? String
                if (label != null && label.startsWith("fill:")) return Keys.edFromSeed(ByteArray(32) { label.substring(5).toInt().toByte() })
            }
        }
        return o
    }

    /** The oracle's salts: salt_i = sha256("notary-oracle-salt/" + i)[:16], the counter restarting at 0 for every call. */
    private fun salts(): () -> ByteArray {
        var i = 0
        return { MessageDigest.getInstance("SHA-256").digest("notary-oracle-salt/${i++}".toByteArray(Charsets.UTF_8)).copyOf(16) }
    }

    @Test fun constants() = OracleCases.each(m, "constants") { _ ->
        linkedMapOf<String, Any?>("BODY_COMMIT_ALG" to Notary.BODY_COMMIT_ALG, "ATTESTED_FACT_CAVEAT" to Notary.ATTESTED_FACT_CAVEAT)
    }

    @Test fun notaryMessage() = OracleCases.each(m, "notaryMessage") { a -> Notary.notaryMessage(a[0]) }

    @Test fun notarizeResponse() = OracleCases.each(m, "notarizeResponse") { a ->
        val opts = map(a[1])
        val o = Notary.NotarizeOptions(keyArg(opts["notaryKey"]) as Keys.EdKey)
        o.observedAt = opts["observedAt"]
        o.textChunkSize = opts["textChunkSize"]
        o.salt = salts()
        Notary.notarizeResponse(if (a[0] == null) null else map(a[0]), o).toMap()
    }

    @Test fun discloseField() = OracleCases.each(m, "discloseField") { a -> Notary.discloseField(a[0], a[1], a[2]) }

    @Test fun verifyNotaryAttestation() = OracleCases.each(m, "verifyNotaryAttestation") { a -> Notary.verifyNotaryAttestation(a[0], keyArg(a[1])) }

    @Test fun verifyDisclosedField() = OracleCases.each(m, "verifyDisclosedField") { a -> Notary.verifyDisclosedField(a[0], a[1], keyArg(a[2])) }

    @Test fun factRef() = OracleCases.each(m, "factRef") { a -> Notary.factRef(a[0]) }

    @Test fun bindFactToPcActn() = OracleCases.each(m, "bindFactToPcActn") { a -> Notary.bindFactToPcActn(a[0], a[1]) }

    @Test fun factMatchesPcActn() = OracleCases.each(m, "factMatchesPcActn") { a -> Notary.factMatchesPcActn(a[0], a[1]) }

    @Test fun requireAttestedFact() = OracleCases.each(m, "requireAttestedFact") { a ->
        val opts = LinkedHashMap(map(a[0]))
        if (opts.containsKey("notary")) opts["notary"] = keyArg(opts["notary"])
        Notary.requireAttestedFact(opts)
    }

    @Test fun isAttestedFactCaveat() = OracleCases.each(m, "isAttestedFactCaveat") { a -> Notary.isAttestedFactCaveat(a[0]) }

    @Test fun notaryKeyUsable() = OracleCases.each(m, "notaryKeyUsable") { a -> Notary.notaryKeyUsable(a[0], a[1], a[2]) }

    @Test fun evaluateAttestedFactCaveat() = OracleCases.each(m, "evaluateAttestedFactCaveat") { a ->
        if (a.size > 2) Notary.evaluateAttestedFactCaveat(a[0], a[1], if (a[2] == null) null else map(a[2]))
        else Notary.evaluateAttestedFactCaveat(a[0], a[1])
    }
}
