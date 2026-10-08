package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path

/**
 * JUnit-free conformance runner for the native Kotlin PCA verifier (wire format v2 + the post-quantum suites +
 * the v2.1 agent-leaf threshold-share binding). It loads the SHARED golden corpus
 * `packages/pca/conformance/vectors.json` (the same file every other language verifier consumes — never copied)
 * and asserts the verdict for every vector, then the primitive suites, and finally the cross-implementation
 * counterexamples under `tools/pca-diff-fuzz/counterexamples/`.
 *
 * This verifier implements the three CROSS-IMPL suites every verifier at parity must cover (GAP 1):
 * `ed25519`, `ml-dsa-65` and `hybrid-ed25519-ml-dsa-65`, for BOTH the leaf signature (`requires:"pq"`) AND
 * non-leaf capability-chain hops (`requires:"pq-nonleaf"`). A vector whose suite is a REGISTERED post-quantum
 * suite this verifier does not implement (ml-dsa-87, slh-dsa-*, the nested hybrid, and their hybrids) is
 * SKIPPED with an explicit per-suite count — never silently, never faked. Deliberately unknown-alg / stray-field
 * wire negatives still RUN (they are suite-agnostic fail-closed checks: an unregistered `alg` is terminal
 * `{wire:false}` and must be rejected). It also enforces the v2.1 agent-leaf share binding (GAP 2): a BARE
 * agent share and a cross-signer-set replay are REJECTED, a properly bound agent share is ACCEPTED.
 *
 * Run (from sdks/kotlin-pca, with BouncyCastle + kotlin-stdlib on the classpath):
 *   java -cp <out>:<kotlin-stdlib>:<bcprov> net.atlasauth.pca.verifier.ConformanceRunnerKt [confDir] [ceDir]
 */

/** The suites this verifier implements — the three cross-impl suites required at parity (GAP 1). */
private val IMPLEMENTED_SUITES = setOf("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")

/** Every registered suite in the corpus (README: 10 suites). */
private val ALL_REGISTERED_SUITES = setOf(
    "ed25519", "ml-dsa-65", "ml-dsa-87", "hybrid-ed25519-ml-dsa-65", "hybrid-ed25519-ml-dsa-87",
    "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s",
    "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s",
)

@Suppress("UNCHECKED_CAST")
private fun load(p: String): Map<String, Any?> =
    Json.parseLenient(Files.readString(Path.of(p))) as Map<String, Any?>

/**
 * The set of signature suites a vector exercises: the leaf `alg` plus every cap-chain hop `alg`. An absent
 * `alg` is the default ed25519 and contributes nothing to skip (so downgrade vectors, which strip the suite
 * fields, always RUN as the structural negatives they are). Only inspects the parsed `pcactn`; raw
 * `pcactn_json` vectors are all ed25519 core, so none is ever suite-skipped.
 */
@Suppress("UNCHECKED_CAST")
private fun suitesExercised(v: Map<String, Any?>): Set<String> {
    val out = LinkedHashSet<String>()
    val pco = v["pcactn"] as? Map<String, Any?> ?: return out
    (pco["alg"] as? String)?.let { out.add(it) }
    (pco["cap_chain"] as? List<Any?>)?.forEach { h ->
        ((h as? Map<String, Any?>)?.get("alg") as? String)?.let { out.add(it) }
    }
    return out
}

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

    val doc = load(dir + "vectors.json")
    check(Json.asLong(doc["format"]) == 2L && Json.asLong(doc["ver"]) == 2L, "format-2 vectors")
    check(doc["agent_leaf_binding"] == "2.1", "agent_leaf_binding == 2.1")
    val vs = doc["vectors"] as List<Any?>
    if (vs.isEmpty()) throw IllegalStateException("no vectors")

    var ran = 0
    var vecFails = 0
    var skipped = 0
    // Per-skipped-suite tally and a record of which cross-impl suites got a PASSING positive LEAF / HOP vector.
    val skipBySuite = sortedMapOf<String, Int>()
    val crossImplPositiveLeafPassed = LinkedHashSet<String>()
    val crossImplPositiveHopPassed = LinkedHashSet<String>()
    for (x in vs) {
        val v = x as Map<String, Any?>
        val suites = suitesExercised(v)
        // Skip iff the vector exercises a REGISTERED suite we do not implement. A bogus/unknown alg
        // (e.g. "ml-dsa-999") is NOT registered, so it still runs and is correctly rejected fail-closed.
        val unsupported = suites.firstOrNull { it in ALL_REGISTERED_SUITES && it !in IMPLEMENTED_SUITES }
        if (unsupported != null) {
            skipped++
            skipBySuite[unsupported] = (skipBySuite[unsupported] ?: 0) + 1
            println("SKIP ${v["name"]} (unimplemented suite: $unsupported)")
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
        val wantAllow = exp["allow"]
        check(got.allow == wantAllow, "${v["name"]}: allow=${got.allow} want $wantAllow (${got.reason})")
        val want = exp["checks"] as Map<String, Any?>
        check(want.keys == got.checks.keys, "${v["name"]}: check set ${got.checks.keys} want ${want.keys}")
        for ((k, wv) in want)
            check(wv == got.checks[k], "${v["name"]}: check $k=${got.checks[k]} want $wv (${got.reason})")
        val ok = fails == before
        ran++
        if (!ok) vecFails++

        // GAP 1 evidence: record each cross-impl suite proven by a passing positive (allow==true) vector.
        if (ok && wantAllow == true) {
            val req = v["requires"]
            val pco = v["pcactn"] as? Map<String, Any?>
            if (req == "pq") { // LEAF suite under test
                val leaf = (pco?.get("alg") as? String) ?: "ed25519"
                if (leaf in IMPLEMENTED_SUITES) crossImplPositiveLeafPassed.add(leaf)
            } else if (req == "pq-nonleaf") { // capability-chain HOP suite under test
                suites.filter { it in IMPLEMENTED_SUITES }.forEach { crossImplPositiveHopPassed.add(it) }
            } else if (req == null || req == "") { // core positives exercise the ed25519 leaf AND ed25519 hops
                crossImplPositiveLeafPassed.add("ed25519")
                crossImplPositiveHopPassed.add("ed25519")
            }
        }
    }

    // ---- GAP 1: the three cross-impl suites must each be exercised by a passing positive, leaf AND hop -------
    for (s in listOf("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")) {
        check(crossImplPositiveLeafPassed.contains(s), "GAP1 LEAF: cross-impl suite exercised by a passing positive: $s")
        check(crossImplPositiveHopPassed.contains(s), "GAP1 HOP: cross-impl suite exercised by a passing positive: $s")
    }

    val prim = doc["primitives"] as Map<String, Any?>
    val primFailsBefore = fails
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
    println("primitives: ${fails - primFailsBefore} failures")

    // ---- GAP 2: v2.1 agent-leaf threshold-share binding ----------------------------------------------------
    // Recompute the role/signer-set/t-bound share message for EVERY entry (signerSetHash recomputed from the
    // signer set) and verify share.sig over it. A bare pre-v2.1 agent share and a cross-signer-set replay MUST
    // be rejected; a properly bound agent share MUST be accepted.
    var shareChecks = 0
    var bareAgentRejected = false
    var wrongSetRejected = false
    var boundAgentAccepted = false
    for (x in prim["threshold_share"] as List<Any?>) {
        val e = x as Map<String, Any?>
        val role = Pca.asStr(e["role"])
        val t = Json.asLong(e["t"]).toInt()
        val signerSet = e["signer_set"] as List<Any?>
        val tmsg = Pca.decodeB64uStrict(e["threshold_message"], -1)
            ?: throw IllegalStateException("threshold_share ${e["name"]}: threshold_message not base64url")
        val share = e["share"] as Map<String, Any?>
        val wantValid = !e.containsKey("valid") || e["valid"] == true
        val gotValid = Threshold.verifyShare(role, tmsg, signerSet, t, share)
        val nm = e["name"] as? String ?: "$role-t$t"
        check(gotValid == wantValid, "threshold_share $nm: verify=$gotValid want $wantValid")
        shareChecks++
        when (nm) {
            "agent-bare-rejected" -> bareAgentRejected = !gotValid
            "agent-bound-wrong-set" -> wrongSetRejected = !gotValid
            "agent-bound-t1", "agent-bound-t2" -> boundAgentAccepted = gotValid
        }
    }
    check(bareAgentRejected, "GAP2: bare pre-v2.1 agent share (agent-bare-rejected) is REJECTED")
    check(wrongSetRejected, "GAP2: cross-signer-set agent share (agent-bound-wrong-set) is REJECTED")
    check(boundAgentAccepted, "GAP2: a v2.1 signerSetHash||t-bound agent share is ACCEPTED")

    // ---- post-quantum artifact signatures (same agility seam as the leaf) ----------------------------------
    var artRan = 0
    var artSkipped = 0
    for (x in prim["pq_artifact"] as List<Any?>) {
        val a = x as Map<String, Any?>
        val alg = Pca.asStr(a["alg"])
        if (alg in ALL_REGISTERED_SUITES && alg !in IMPLEMENTED_SUITES) { artSkipped++; continue }
        val wantValid = !a.containsKey("valid") || a["valid"] == true
        val gotValid = try {
            val msg = Pca.decodeB64uStrict(a["message"], -1)
                ?: throw IllegalStateException("pq_artifact ${a["artifact"]}: message not base64url")
            Pq.verifyArtifactSignature(alg, a["ed_pub"] as? String, a["pq_pk"], msg, a["sig"], a["pq_sig"])
        } catch (ex: RuntimeException) {
            false // fail-closed
        }
        check(gotValid == wantValid, "pq_artifact ${a["artifact"]}/$alg: verify=$gotValid want $wantValid")
        artRan++
    }

    // ---- report --------------------------------------------------------------------------------------------
    println("VECTORS: ${ran + skipped} total = $ran run (${ran - vecFails} passed, $vecFails failed), $skipped skipped")
    if (skipBySuite.isNotEmpty()) {
        val sb = StringBuilder()
        for ((k, n) in skipBySuite) sb.append("\n    ").append(k).append(": ").append(n)
        println("  skipped by unimplemented suite:$sb")
    }
    println("THRESHOLD_SHARE (v2.1 agent-leaf binding): $shareChecks shares checked; "
        + "bare-agent rejected=$bareAgentRejected, wrong-set rejected=$wrongSetRejected, bound-agent accepted=$boundAgentAccepted")
    println("PQ_ARTIFACT: $artRan run, $artSkipped skipped (unimplemented suites)")

    // ---- cross-implementation counterexamples (the fuzz oracle is normative for a strict verifier) ---------
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

    println("ASSERTIONS: $checks checked, $fails failures")
    return fails
}

fun main(args: Array<String>) {
    val confDir = if (args.isNotEmpty()) args[0] else "conformance/"
    val ceDir = if (args.size > 1) args[1] else "../../tools/pca-diff-fuzz/counterexamples/"
    System.exit(if (runConformance(confDir, ceDir) == 0) 0 else 1)
}
