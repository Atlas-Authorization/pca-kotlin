package net.atlasauth.pca.txntokens

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.Jws
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Test

/** Replays the TypeScript-reference vectors of the Transaction Token package (act projection, mint, verify). */
class TxnTokensDiffTest {
    private val m = "ref-txn-tokens-java"
    private val t0 = 1_800_000_000_000L
    private val uuid = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    @Suppress("UNCHECKED_CAST")
    private fun mm(o: Any?) = o as Map<String, Any?>

    private fun pubRaw(label: String) = Keys.edFromSeed(OracleCases.seed(label)).pub

    private fun keyDesc(k: Any?): ByteArray {
        val d = mm(k)
        return when {
            d.containsKey("label") -> OracleCases.seed(d["label"] as String)
            d.containsKey("pubLabel") -> pubRaw(d["pubLabel"] as String)
            else -> ByteArray(Js.num(d["len"])!!.toInt())
        }
    }

    @Test fun subActChain() = OracleCases.each(m, "subActChain") { TxnTokens.subActChain(it[0]) }
    @Test fun actDepth() = OracleCases.each(m, "actDepth") { TxnTokens.actDepth(it[0]) }
    @Test fun toRfc8693Act() = OracleCases.each(m, "toRfc8693Act") { TxnTokens.toRfc8693Act(it[0]) }

    @Test fun toTransactionToken() = OracleCases.each(m, "toTransactionToken") { a ->
        val args = LinkedHashMap(mm(a[0]))
        val kd = args.remove("issuerKey")
        if (kd != null) args["issuerKey"] = keyDesc(kd)
        val token = TxnTokens.toTransactionToken(args) { t0 }
        val canon = Jws.assertCanonicalCompactJws(token)
        val payload = LinkedHashMap(canon.payload)
        val random = payload.containsKey("jti") || !args.containsKey("txn")
        (payload["jti"] as? String)?.let { if (uuid.matches(it)) payload["jti"] = "<uuid>" }
        if (!args.containsKey("txn")) (payload["txn"] as? String)?.let { if (uuid.matches(it)) payload["txn"] = "<uuid>" }
        val verified = try {
            Jws.jwtVerify(token, canon, Jws.ed25519(pubRaw(mm(kd)["label"] as String)), Jws.JwtOptions(algorithms = listOf("EdDSA")), t0)
            true
        } catch (e: RuntimeException) {
            false
        }
        Js.obj("header" to canon.header, "payload" to payload, "verified" to verified).also { if (!random) it["token"] = token }
    }

    @Test fun fromTransactionToken() = OracleCases.each(m, "fromTransactionToken") { a ->
        val consumed = ArrayList<Any?>()
        val out = Js.obj()
        try {
            val opts = (a[2] as? Map<*, *>)?.let { LinkedHashMap(mm(it)) }
            if (opts != null) {
                val nowMs = opts.remove("nowMs")
                val seen = opts.remove("seen")
                if (nowMs != null) opts["now"] = nowMs
                if (seen != null) {
                    opts["seenTxn"] = SeenTxn { id, exp ->
                        consumed.add(listOf(id, exp))
                        when (seen) {
                            "throws" -> throw IllegalStateException("store down")
                            "seen" -> true
                            "truthy" -> 1
                            else -> false
                        }
                    }
                }
            }
            out["result"] = TxnTokens.fromTransactionToken(a[0], keyDesc(a[1]), opts)
            out["ok"] = true
        } catch (e: TxnTokenError) {
            out["ok"] = false
            out["code"] = e.code
        } catch (e: RuntimeException) {
            out["ok"] = false
            out["code"] = "other"
        }
        out["consumed"] = consumed
        out
    }

    @Test fun constants() {
        assertEquals("txntoken+jwt", TxnTokens.TXN_TOKEN_TYP_DRAFT_11)
        assertEquals(16384, TxnTokens.MAX_TOKEN_CHARS)
    }
}
