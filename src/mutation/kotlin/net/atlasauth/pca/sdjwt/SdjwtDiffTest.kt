package net.atlasauth.pca.sdjwt

import java.util.Base64
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Replays the TypeScript-reference vectors of the SD-JWT bridge: constants, key helpers, issuance (compared in normalized form: random
 * salts), presentation (exact strings: Ed25519 key-binding signatures are deterministic), verification and recovery through the core.
 * A verification refusal reason is compared exactly only when it is this package's own (or the canonical gate's); a reason in the JOSE
 * library's wording only has to be a refusal.
 */
@Suppress("UNCHECKED_CAST")
class SdjwtDiffTest {
    private val m = "ref-sdjwt"

    private fun mm(o: Any?) = o as? Map<String, Any?>

    /** {"$bytes": b64u} members (at any depth) become ByteArray. */
    private fun rev(v: Any?): Any? = when (v) {
        is List<*> -> v.map { rev(it) }
        is Map<*, *> -> if (v.size == 1 && v["\$bytes"] is String) Keys.unb64u(v["\$bytes"] as String)
        else LinkedHashMap<String, Any?>().also { o -> for ((k, x) in v) o[k as String] = rev(x) }
        else -> v
    }

    /** Replays every case of [fn] with [cmp]; a reference throw requires a throw. */
    private fun eachCmp(fn: String, f: (List<Any?>) -> Any?, cmp: (Any?, Any?) -> Boolean) {
        val bad = ArrayList<String>()
        for (c in OracleCases.of(m, fn)) {
            val name = c["name"]
            val want = c["out"]
            var got: Any? = null
            var err: Throwable? = null
            try { got = f(c["args"] as List<Any?>) } catch (t: Throwable) { err = t }
            if (mm(want)?.containsKey("\$throws") == true) {
                if (err == null) bad.add("$name: want a throw, got $got")
                continue
            }
            if (err != null) { bad.add("$name: threw $err"); continue }
            val norm = IntentJs.normalize(OracleCases.toJson(got))
            if (!cmp(norm, want)) bad.add("$name\n  want: ${Json.canonicalize(want)}\n  got:  ${Json.canonicalize(norm)}")
        }
        assertTrue("${bad.size} divergent case(s) of $fn:\n" + bad.take(30).joinToString("\n"), bad.isEmpty())
    }

    private val own = listOf(
        "pca-sdjwt:", "non-canonical compact JWS", "required disclosure", "KB-JWT ", "cnf key does not", "key binding required", "duplicate disclosure",
        "unsupported _sd_alg", "a presented disclosure", "a digest appears", "an array", "an object-property", "disclosure claim", "_sd must be", "'",
    )

    private fun clip(r: String) = if (r.startsWith("non-canonical compact JWS: bad-json")) r.split(" (")[0] else r

    private fun cmpVerify(got: Any?, want: Any?): Boolean {
        val g = mm(got)!!
        val w = mm(want)!!
        if (w["ok"] == false) {
            if (g["ok"] != false) return false
            val r = w["reason"] as String
            val gr = g["reason"] as String
            if (r.startsWith("KB-JWT signature/claims invalid")) return gr.startsWith("KB-JWT signature/claims invalid")
            for (p in own) if (r.startsWith(p)) return clip(gr) == clip(r)
            return true
        }
        return IntentJs.jsonEquals(want, got)
    }

    private val camel = linkedMapOf(
        "required_disclosures" to "requiredDisclosures", "expected_audience" to "expectedAudience", "expected_kb_audience" to "expectedKbAudience",
        "expected_nonce" to "expectedNonce", "require_key_binding" to "requireKeyBinding", "algorithms" to "algorithms", "kb_algorithms" to "kbAlgorithms",
        "now" to "now", "kb_max_age_sec" to "kbMaxAgeSec", "clock_tolerance_sec" to "clockToleranceSec", "key_binding_key" to "keyBindingKey",
    )

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf(
            "SD_ALG" to Sdjwt.SD_ALG, "PCA_SD_JWT_TYP" to Sdjwt.PCA_SD_JWT_TYP, "KB_JWT_TYP" to Sdjwt.KB_JWT_TYP,
            "DEFAULT_SIGNING_ALG" to Sdjwt.DEFAULT_SIGNING_ALG, "PCA_CAPABILITY_CLAIMS" to Sdjwt.PCA_CAPABILITY_CLAIMS,
        )
    }

    @Test fun ed25519PublicJwk() = OracleCases.each(m, "ed25519PublicJwk") { Sdjwt.ed25519PublicJwk(rev(it[0]) as ByteArray?) }
    @Test fun importEd25519PrivateKey() = OracleCases.each(m, "importEd25519PrivateKey") { Sdjwt.importEd25519PrivateKey(rev(it[0]) as ByteArray?); "ok" }
    @Test fun importEd25519PublicKey() = OracleCases.each(m, "importEd25519PublicKey") { Sdjwt.importEd25519PublicKey(rev(it[0]) as ByteArray?); "ok" }

    private fun b64json(s: String): Any? = Json.parseLenient(String(Base64.getUrlDecoder().decode(s), Charsets.UTF_8))

    private fun sha(ascii: String) = Jose.b64u(Jose.sha256(ByteArray(ascii.length) { ascii[it].code.toByte() }))

    /** The reference's normalized view of an issued SD-JWT (salts are random). */
    private fun normalizeIssued(sd: String, seed: ByteArray): Map<String, Any?> {
        val parts = sd.split("~")
        val ds = parts.subList(1, parts.size - 1)
        val hp = parts[0].split(".")
        val h = mm(b64json(hp[0]))
        val p = mm(b64json(hp[1]))!!
        val disc = ds.map { d -> (b64json(d) as List<*>).let { t -> listOf(t[1], t[2]) } }.sortedBy { it[0] as String }
        val dig = ds.map { sha(it) }.sorted()
        val sdl = ((p["_sd"] as? List<*>) ?: emptyList<Any?>()).map { it as String }.sorted()
        val rest = LinkedHashMap(p).apply { remove("_sd") }
        val ver = Sdjwt.verifyPcaSdJwt(
            sd,
            linkedMapOf("issuerKey" to Sdjwt.importEd25519PublicKey(Keys.edFromSeed(seed).pub), "now" to Js.num(p["iat"])!! * 1000),
        )
        return linkedMapOf(
            "end" to parts.last(), "header" to h, "payload" to rest, "n" to ds.size, "digestsOk" to (dig == sdl), "disclosures" to disc,
            "verified" to ver["ok"],
        )
    }

    @Test fun issuePcaSdJwt() = eachCmp("issuePcaSdJwt", { a ->
        val pc = mm(a[0]) ?: throw IllegalArgumentException("pca-sdjwt: pcActn must be an object")
        val opt = mm(a[1])!!
        val seed = rev(opt["issuer_seed"]) as ByteArray
        val o2 = linkedMapOf<String, Any?>("issuerKey" to Sdjwt.importEd25519PrivateKey(seed))
        for (k in listOf("disclosable", "iss", "sub", "typ")) if (opt.containsKey(k)) o2[k] = opt[k]
        if (opt.containsKey("signing_alg")) o2["signingAlg"] = opt["signing_alg"]
        if (opt.containsKey("key_binding")) {
            val kb = opt["key_binding"]
            val kbm = mm(kb)
            o2["keyBinding"] = if (kbm != null && kbm.containsKey("holder_public_key")) linkedMapOf("holderPublicKey" to rev(kbm["holder_public_key"])) else rev(kb)
        }
        normalizeIssued(Sdjwt.issuePcaSdJwt(pc, o2), seed)
    }) { got, want -> IntentJs.jsonEquals(want, got) }

    @Test fun present() = OracleCases.each(m, "present") { a ->
        val options = LinkedHashMap<String, Any?>()
        val opt = if (a.size > 2) mm(a[2]) else null
        if (opt != null && opt.containsKey("key_binding")) {
            val kb = mm(opt["key_binding"])!!
            val k = linkedMapOf<String, Any?>("holderKey" to Sdjwt.importEd25519PrivateKey(rev(kb["holder_seed"]) as ByteArray))
            for (n in listOf("audience", "nonce", "iat", "alg")) if (kb.containsKey(n)) k[n] = kb[n]
            options["keyBinding"] = k
        }
        Sdjwt.present(a[0], a[1], options)
    }

    @Test fun verifyPcaSdJwt() = eachCmp("verifyPcaSdJwt", { a ->
        val opt = mm(a[1])!!
        val ik = rev(opt["issuer_key"])
        val o2 = linkedMapOf<String, Any?>("issuerKey" to if (ik is ByteArray) Sdjwt.importEd25519PublicKey(ik) else mm(ik))
        for ((snake, cc) in camel) if (opt.containsKey(snake)) o2[cc] = rev(opt[snake])
        Sdjwt.verifyPcaSdJwt(a[0], o2)
    }, ::cmpVerify)

    @Test fun verifyRecovered() = eachCmp("verifyRecovered", { a ->
        val opt = mm(a[1])!!
        val aud = opt["audience"]
        val audience = when {
            !opt.containsKey("audience") -> Pca.Audience.Unset
            aud is String -> Pca.Audience.Of(aud)
            else -> Pca.Audience.Any
        }
        val now = if (opt.containsKey("now")) Js.num(opt["now"]) else null
        val r = Sdjwt.verifyRecovered(mm(a[0])!!, mm(opt["grant"]), audience, now?.toLong(), opt["insecure_skip_plan_root_check"] == true)
        linkedMapOf("allow" to r.allow, "reason" to r.reason)
    }) { got, want ->
        val g = mm(got)!!
        val w = mm(want)!!
        val r = w["reason"]
        g["allow"] == w["allow"] && (!(r is String && r.startsWith("pca-sdjwt:")) || r == g["reason"])
    }
}
