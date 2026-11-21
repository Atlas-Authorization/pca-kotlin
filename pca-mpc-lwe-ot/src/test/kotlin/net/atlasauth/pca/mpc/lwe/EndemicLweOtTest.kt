package net.atlasauth.pca.mpc.lwe

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.GZIPInputStream
import net.atlasauth.pca.mpc.Ot
import net.atlasauth.pca.mpc.Ot.OtRandom
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * Replays the TypeScript-reference corpus (test-data/ref-mpc-endemic.json.gz) through the Kotlin face over liblweot. Bytes are {"$bytes": b64url};
 * {"$throws": ...} means the native must refuse. Run with -Dpca.lweot.lib=... (-Dpca.lweot.required=true fails instead of skipping).
 */
class EndemicLweOtTest {
    @Before fun native() {
        val ok = EndemicLweOt.available()
        if (java.lang.Boolean.getBoolean("pca.lweot.required")) assertTrue("liblweot must load (-Dpca.lweot.lib)", ok)
        assumeTrue("liblweot not available", ok)
    }

    private fun cases(fn: String): List<JsonObject> {
        val head = "{\"fn\":\"$fn\","
        val out = ArrayList<JsonObject>()
        BufferedReader(InputStreamReader(GZIPInputStream(File("test-data/ref-mpc-endemic.json.gz").inputStream()), Charsets.UTF_8)).use { r ->
            while (true) {
                var line = r.readLine() ?: break
                if (!line.startsWith(head)) continue
                if (line.endsWith(",")) line = line.dropLast(1)
                out.add(JsonParser.parseString(line).asJsonObject)
            }
        }
        assertTrue("no oracle cases for $fn", out.isNotEmpty())
        return out
    }

    private fun b64(b: ByteArray): JsonElement = JsonObject().also { it.addProperty("\$bytes", Base64.getUrlEncoder().withoutPadding().encodeToString(b)) }

    private fun by(e: JsonElement): ByteArray = Base64.getUrlDecoder().decode(e.asJsonObject.get("\$bytes").asString)

    private fun bl(a: List<ByteArray>): JsonElement = JsonArray().also { j -> a.forEach { j.add(b64(it)) } }

    private fun bp(a: List<Array<ByteArray>>): JsonElement = JsonArray().also { j -> a.forEach { j.add(bl(it.toList())) } }

    private fun ints(e: JsonElement) = e.asJsonArray.map { it.asInt }.toIntArray()

    private fun seed(label: JsonElement): ByteArray = MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label.asString).toByteArray())

    private fun rng(e: JsonElement): OtRandom = Ot.otRandom(Ot.splitMix64(BigInteger(e.asString)))

    private fun flip(b: ByteArray) = ByteArray(b.size) { (b[it].toInt() xor 1).toByte() }

    private fun fill(n: Int, k: Int) = ByteArray(n) { (it * 31 + k * 7 + (it shr 3)).toByte() }

    private fun obj(vararg kv: Pair<String, JsonElement>): JsonElement = JsonObject().also { o -> kv.forEach { o.add(it.first, it.second) } }

    /** A reference throw needs a native throw; otherwise the result must equal the reference value (structurally). */
    private fun replay(fn: String, f: (JsonArray) -> JsonElement) {
        val bad = ArrayList<String>()
        for (c in cases(fn)) {
            val want = c.get("out")
            val wantThrow = want.isJsonObject && want.asJsonObject.has("\$throws")
            var got: JsonElement? = null
            var err: Throwable? = null
            try { got = f(c.getAsJsonArray("args")) } catch (t: Throwable) { err = t }
            val name = c.get("name").asString
            when {
                wantThrow -> if (err == null) bad.add("$name: want a refusal, got a value")
                err != null -> bad.add("$name: unexpected $err")
                got != want -> bad.add("$name: value differs from the reference")
            }
        }
        assertTrue("${bad.size} divergent case(s) of $fn:\n" + bad.take(20).joinToString("\n"), bad.isEmpty())
    }

    @Test fun lweKeygenFips() = replay("lweKeygenFips") { a ->
        val k = Lattice.keygenFips203(seed(a[0]))
        obj("pk" to b64(k.publicKey()), "skSha256" to JsonPrimitive(MessageDigest.getInstance("SHA-256").digest(k.secretKey()).joinToString("") { "%02x".format(it) }))
    }

    @Test fun lweKeygen() = replay("lweKeygen") { a ->
        val k = Lattice.keygen(seed(a[0]))
        obj("pk" to b64(k.publicKey()), "skSha256" to JsonPrimitive(MessageDigest.getInstance("SHA-256").digest(k.secretKey()).joinToString("") { "%02x".format(it) }))
    }

    @Test fun lweEnc() = replay("lweEnc") { a -> b64(Lattice.enc(Lattice.keygen(seed(a[0])).publicKey(), by(a[1]), by(a[2]))) }

    @Test fun lweDec() = replay("lweDec") { a -> b64(Lattice.dec(Lattice.keygen(seed(a[0])).secretKey(), by(a[1]))) }

    @Test fun lweRing() = replay("lweRing") { a -> b64(if (a[0].asString == "add") Lattice.ringAdd(by(a[1]), by(a[2])) else Lattice.ringSub(by(a[1]), by(a[2]))) }

    @Test fun lweHash() = replay("lweHash") { a -> b64(Lattice.hashToRing(by(a[0]))) }

    @Test fun randomOt() = replay("randomOt") { a ->
        val rv = EndemicOt.receive(ints(a[0]), rng(a[1]))
        val sm = EndemicOt.sendRandom(rv.message(), rng(a[2]), null)
        obj(
            "rn" to b64(rv.message().rn()), "points" to bp(rv.message().points().toList()), "rhos" to bl(rv.message().rhos().toList()),
            "ciphertexts" to bp(sm.ciphertexts().toList()), "senderPads" to bp(sm.senderPads().toList()),
            "recvPads" to bl(EndemicOt.recoverRandom(rv.state(), sm).toList()),
        )
    }

    @Test fun randomOtTamper() = replay("randomOtTamper") { a ->
        val rv = EndemicOt.receive(ints(a[0]), rng(a[1]))
        val sm = EndemicOt.sendRandom(rv.message(), rng(a[2])) { c -> c[0][0] = c[0][0].copyOf(1087) }
        bl(EndemicOt.recoverRandom(rv.state(), sm).toList())
    }

    @Test fun baseOt() = replay("baseOt") { a ->
        val messages = Array(a[0].asJsonArray.size()) { i -> arrayOf(by(a[0].asJsonArray[i].asJsonArray[0]), by(a[0].asJsonArray[i].asJsonArray[1])) }
        val choices = ints(a[1])
        val tamper: java.util.function.Consumer<Array<Array<ByteArray>>>? = when (a[3].asString) {
            "enc" -> java.util.function.Consumer { e -> e[0][0] = flip(e[0][0]) }
            "encChosen" -> java.util.function.Consumer { e -> e[0][choices[0] and 1] = flip(e[0][choices[0] and 1]) }
            else -> null
        }
        val r = rng(a[2]).let { one -> EndemicOt.baseOT(messages, choices, one, one, tamper) } // one generator serves the receiver, then the sender
        obj("received" to bl(r.received().toList()), "ciphertexts" to bp(r.transcript().ciphertexts().toList()),
            "encrypted" to bp(r.transcript().encrypted().toList()), "commitments" to bp(r.transcript().commitments().toList()))
    }

    @Test fun sendMalformed() = replay("sendMalformed") { a ->
        val m = EndemicOt.receive(intArrayOf(0, 1), rng(JsonPrimitive("77"))).message()
        var rn = m.rn()
        val points = arrayOf(m.points()[0].clone(), m.points()[1].clone())
        var rhos = m.rhos().clone()
        when (a[0].asString) {
            "nonce" -> rn = fill(31, 1)
            "count" -> rhos = rhos.copyOfRange(1, rhos.size)
            "point" -> points[1][0] = fill(1151, 1)
            "rho" -> rhos[0] = fill(33, 1)
        }
        JsonPrimitive(EndemicOt.sendRandom(EndemicOt.ReceiverMessage(rn, points, rhos), rng(JsonPrimitive("78")), null).ciphertexts().size)
    }
}
