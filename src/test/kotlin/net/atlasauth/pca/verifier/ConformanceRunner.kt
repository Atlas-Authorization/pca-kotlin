package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path

/**
 * JUnit-free conformance runner for the native Kotlin PCA verifier (wire format v2). It loads the SHARED
 * golden corpus `packages/pca/conformance/vectors.json` (the same file the other language verifiers consume —
 * never copied) and asserts the verdict for every vector, then the primitive suites, and finally the
 * cross-implementation counterexamples under `tools/pca-diff-fuzz/counterexamples/`.
 *
 * Run (from sdks/kotlin-pca, with BouncyCastle + kotlin-stdlib on the classpath):
 *   java -cp <out>:<kotlin-stdlib>:<bcprov> net.atlasauth.pca.verifier.ConformanceRunnerKt [confDir] [ceDir]
 */

@Suppress("UNCHECKED_CAST")
private fun load(p: String): Map<String, Any?> =
    Json.parseLenient(Files.readString(Path.of(p))) as Map<String, Any?>

/** Runs the full conformance suite and returns the number of failed assertions (0 == all green). */
@Suppress("UNCHECKED_CAST")
fun runConformance(confDir: String, counterexampleDir: String): Int {
    var checks = 0
    var fails = 0
    fun check(ok: Boolean, msg: String) {
        checks++
        if (!ok) { fails++; println("  FAIL: $msg") }
    }

    val dir = confDir.trimEnd('/') + "/"
    val ceDir = counterexampleDir.trimEnd('/') + "/"
    val ORDER = arrayOf("wire", "version", "audience", "validity", "chain", "plan_inclusion", "leaf_signature", "counter")

    val doc = load(dir + "vectors.json")
    check(Json.asLong(doc["format"]) == 2L && Json.asLong(doc["ver"]) == 2L, "format-2 vectors")
    val vs = doc["vectors"] as List<Any?>
    if (vs.isEmpty()) throw IllegalStateException("no vectors")

    // This verifier implements the classical ed25519 suite AND the B4 post-quantum suites (ml-dsa-65 and
    // hybrid-ed25519-ml-dsa-65, FIPS-204 via BouncyCastle), so both the "ed25519" and "pq" corpora run. Any
    // vector tagged with a `requires` suite we do not support is skipped EXPLICITLY, not silently.
    val supportedSuites = setOf("ed25519", "pq")
    var vecFails = 0
    var skipped = 0
    for (x in vs) {
        val v = x as Map<String, Any?>
        val req = v["requires"]
        if (req is String && req.isNotEmpty() && !supportedSuites.contains(req)) {
            skipped++
            continue
        }
        val before = fails
        val ctx = v["context"] as Map<String, Any?>
        val now = Json.asLong(ctx["now"])
        val aud = ctx["aud"]
        val audience = if (aud is String) Pca.Audience.Of(aud) else Pca.Audience.Unset
        val grant = v["grant"] as Map<String, Any?>
        val got = if (v.containsKey("pcactn_json"))
            Pca.verifyPcactnJson(v["pcactn_json"] as String, grant, now, audience)
        else Pca.verifyPcactn(v["pcactn"], grant, now, audience)
        val exp = v["expect"] as Map<String, Any?>
        check(got.allow == exp["allow"], "${v["name"]}: allow=${got.allow} want ${exp["allow"]} (${got.reason})")
        val want = exp["checks"] as Map<String, Any?>
        check(want.keys == got.checks.keys, "${v["name"]}: check set ${got.checks.keys} want ${want.keys}")
        for ((k, wantV) in want)
            check(wantV == got.checks[k], "${v["name"]}: check $k=${got.checks[k]} want $wantV (${got.reason})")
        val ok = fails == before
        if (!ok) vecFails++
    }
    val ran = vs.size - skipped
    println("vectors: ${vs.size} total, ${ran - vecFails} passed, $vecFails failed, $skipped skipped")

    val prim = doc["primitives"] as Map<String, Any?>
    var primFails = fails
    for (x in prim["canonical"] as List<Any?>) {
        val c = x as Map<String, Any?>
        val s = Json.canonicalizeStrict(c["value"])
        check(s == c["expect"], "canonical $s vs ${c["expect"]}")
        check(Pca.hashStrict(c["value"]) == c["hash"], "hash for $s")
    }
    for (x in prim["json_parse"] as List<Any?>) {
        val j = x as Map<String, Any?>
        val inp = j["input"] as String
        var accepted: Boolean
        var canon: String? = null
        try { canon = Json.canonicalizeStrict(Json.parse(inp)); accepted = true } catch (e: RuntimeException) { accepted = false }
        check(accepted == j["accept"], "json_parse accept=$accepted for $inp")
        if (accepted && j.containsKey("canonical")) check(canon == j["canonical"], "json_parse canonical $canon for $inp")
    }
    for (x in prim["b64u"] as List<Any?>) {
        val b = x as Map<String, Any?>
        val len = if (b.containsKey("len")) Json.asLong(b["len"]).toInt() else -1
        val valid = Pca.decodeB64uStrict(b["input"], len) != null
        check(valid == b["valid"], "b64u valid=$valid for '${b["input"]}' len $len")
    }
    for (x in prim["merkle"] as List<Any?>) {
        val m = x as Map<String, Any?>
        val leaves = m["leaves"] as List<Any?>
        val root = Pca.merkleRoot(leaves)
        check(root == m["root"], "merkle root $root vs ${m["root"]}")
        val proofs = m["proofs"] as List<Any?>
        for (i in proofs.indices)
            check(Pca.verifyInclusion(root, proofs[i] as Map<String, Any?>, leaves[i]), "merkle proof $i")
    }
    check(Pca.paramsDigest(null) == prim["params_digest_empty"], "empty params digest")

    // threshold primitives: exercise signerSetHash / shareMessage / single-share verification (threshold.ts)
    for (x in prim["threshold_share"] as List<Any?>) {
        val t = x as Map<String, Any?>
        val role = t["role"] as String
        val tt = Json.asLong(t["t"]).toInt()
        val signerSet = (t["signer_set"] as List<Any?>).map {
            val s = it as Map<String, Any?>
            Threshold.Signer(s["role"] as String, s["publicKey"] as String)
        }
        check(Pca.b64(Threshold.signerSetHash(signerSet)) == t["signer_set_hash"], "signer_set_hash for role $role")
        val tmsg = Pca.decodeB64uStrict(t["threshold_message"], -1)!!
        val expShareMsg = Pca.decodeB64uStrict(t["share_message"], -1)!!
        check(Pca.b64(Threshold.shareMessage(role, tmsg, signerSet, tt)) == Pca.b64(expShareMsg), "share_message for role $role")
        val sh = t["share"] as Map<String, Any?>
        val share = Threshold.ThresholdShare(sh["role"] as String, sh["publicKey"] as String, sh["sig"] as String)
        // the share must verify under its role's shareMessage (role/set/t bound) and count once
        val verdict = Threshold.verifyThreshold(listOf(share), tmsg, signerSet, tt)
        check(verdict.count >= 1 && verdict.roles.contains(role), "threshold share verifies for role $role (count=${verdict.count})")
    }
    println("primitives: ${fails - primFails} failures")

    // cross-implementation counterexamples (the fuzz oracle is normative for a strict verifier)
    val ceIndexPath = Path.of(ceDir + "INDEX.json")
    if (Files.exists(ceIndexPath)) {
        val index = Json.parseLenient(Files.readString(ceIndexPath)) as List<Any?>
        var ceFails = 0
        for (e in index) {
            val entry = e as Map<String, Any?>
            val file = entry["file"] as String
            val before = fails
            val cx = Json.parseLenient(Files.readString(Path.of(ceDir + file))) as Map<String, Any?>
            val ctx = cx["context"] as Map<String, Any?>
            val now = Json.asLong(ctx["now"])
            val aud = ctx["aud"]
            val audience = if (aud is String) Pca.Audience.Of(aud) else Pca.Audience.Unset
            // In the fuzz corpus the grant capability is carried as a JSON-encoded string.
            val grantRaw = cx["grant"]
            val grant = (if (grantRaw is String) Json.parseLenient(grantRaw) else grantRaw) as Map<String, Any?>
            val got = if (cx.containsKey("pcactn_json"))
                Pca.verifyPcactnJson(cx["pcactn_json"] as String, grant, now, audience)
            else Pca.verifyPcactn(cx["pcactn"], grant, now, audience)
            // Expected verdict = the oracle result when present, else the INDEX allow flag.
            val results = cx["results"] as? Map<String, Any?>
            val oracle = results?.get("oracle") as? Map<String, Any?>
            val wantAllow = (oracle?.get("allow") ?: entry["allow"])
            check(got.allow == wantAllow, "$file: allow=${got.allow} want $wantAllow (${got.reason})")
            if (oracle != null) {
                val wantChecks = oracle["checks"] as Map<String, Any?>
                for ((k, wv) in wantChecks)
                    check(wv == got.checks[k], "$file: check $k=${got.checks[k]} want $wv (${got.reason})")
            }
            if (fails != before) ceFails++
        }
        println("counterexamples: ${index.size} total, ${index.size - ceFails} passed, $ceFails failed")
    } else {
        println("counterexamples: INDEX.json not found at $ceDir (skipped)")
    }

    println("TOTAL: $checks assertions, $fails failures")
    return fails
}

fun main(args: Array<String>) {
    val confDir = if (args.isNotEmpty()) args[0] else "conformance/"
    val ceDir = if (args.size > 1) args[1] else "../../tools/pca-diff-fuzz/counterexamples/"
    System.exit(if (runConformance(confDir, ceDir) == 0) 0 else 1)
}
