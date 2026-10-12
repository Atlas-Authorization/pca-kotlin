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

/** primitives.depth `expand`: the marker string (value) / substring (text) becomes `levels` nested arrays around `leaf`, built iteratively. */
@Suppress("UNCHECKED_CAST")
private fun expandDepthInput(api: String, input: Any?, ex: Map<String, Any?>?): Any? {
    if (ex == null) return input
    val marker = ex["marker"] as String
    val levels = Json.asLong(ex["levels"]).toInt()
    val leaf = ex["leaf"]
    if (api == "pcactn_json" || api == "json_parse") {
        val i = LinkedHashMap(input as Map<String, Any?>)
        val text = i["text"] as String
        val at = text.indexOf(marker)
        i["text"] = text.substring(0, at) + "[".repeat(levels) + Json.canonicalize(leaf) + "]".repeat(levels) + text.substring(at + marker.length)
        return i
    }
    var nest: Any? = leaf
    repeat(levels) { nest = arrayListOf(nest) }
    val st = ArrayDeque<Any?>()
    st.addLast(input)
    while (st.isNotEmpty()) { // the input itself is shallow; replace the single marker value in place
        when (val o = st.removeLast()) {
            is MutableMap<*, *> -> for (e in (o as MutableMap<String, Any?>).entries) { if (e.value == marker) e.setValue(nest) else st.addLast(e.value) }
            is MutableList<*> -> { val l = o as MutableList<Any?>; for (k in l.indices) { if (l[k] == marker) l[k] = nest else st.addLast(l[k]) } }
        }
    }
    return input
}

/** primitives.depth verdict per api (true == accepted / verifies / counts / parses). */
@Suppress("UNCHECKED_CAST")
private fun depthVerdict(api: String, input: Any?): Boolean = when (api) {
    "chain" -> { val i = input as Map<String, Any?>; Pca.verifyChain(i["chain"] as List<Any?>, i["expected_root_issuer"] as String, true) == "" }
    "threshold_share" -> Threshold.verifyShareEntry(input)
    "pcactn_json" -> {
        val i = input as Map<String, Any?>
        Pca.verifyPcactnJson(i["text"] as String, i["grant"] as Map<String, Any?>, Json.asLong(i["now"]), Pca.Audience.Of(i["aud"] as String)).allow
    }
    "json_parse" -> try { Json.parse((input as Map<String, Any?>)["text"] as String); true } catch (e: IllegalArgumentException) { false }
    else -> throw IllegalStateException("unknown depth api $api")
}

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

    val core = load(dir + "vectors.json")
    // Optional: also run the FULL adversarial set. PCA_CONFORMANCE_ADV names an uncompressed copy
    // (`gunzip -c packages/pca/conformance/vectors-adversarial.json.gz > $PCA_CONFORMANCE_ADV`); the core's sampled adv-*
    // vectors are replaced by the full set and the adversarial json_parse/b64u/canonical rows are appended to the base ones.
    val advPath = System.getenv("PCA_CONFORMANCE_ADV")
    val doc: Map<String, Any?> = if (advPath.isNullOrEmpty()) core else {
        val adv = load(advPath)
        val base = mapOf("json_parse" to 54, "b64u" to 21, "canonical" to 5)
        val prim = (core["primitives"] as Map<String, Any?>).toMutableMap()
        val advPrim = adv["primitives"] as Map<String, Any?>
        for ((k, n) in base) prim[k] = (prim[k] as List<Any?>).take(n) + (advPrim[k] as List<Any?>)
        val coreVs = (core["vectors"] as List<Any?>).filter { !((it as Map<String, Any?>)["name"] as String).startsWith("adv-") }
        core.toMutableMap().also { it["primitives"] = prim; it["vectors"] = coreVs + (adv["vectors"] as List<Any?>) }
    }
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
            // 0.4.1: a vector may name the suite it needs in `requires` (e.g. a threshold share under ml-dsa-87).
            ?: (v["requires"] as? String)?.takeIf { it in ALL_REGISTERED_SUITES && it !in IMPLEMENTED_SUITES }
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
        val allowedSuites = (ctx["allowed_suites"] as? List<*>)?.map { it.toString() }
        val got = if (v.containsKey("pcactn_json"))
            Pca.verifyPcactnJson(v["pcactn_json"] as String, grant, now, audience, allowedSuites)
        else Pca.verifyPcactn(v["pcactn"], grant, now, audience, allowedSuites)
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

    // ---- standalone chain API: root PQ authority (R4-01) ----------------------------------------------------
    // primitives.chain_pin[]: Pca.verifyChain(chain, expected_root_issuer, true, allowed_suites, pq_pins, trusted_root). A non-ed25519
    // ROOT needs a verifier-side pin or the stored grant. The suites involved (ed25519, ml-dsa-65, hybrid) are all implemented here.
    val chainPins = prim["chain_pin"] as? List<Any?> ?: emptyList()
    check(chainPins.size >= 25, "primitives.chain_pin: expected >= 25 vectors, got ${chainPins.size}")
    var cpRan = 0
    for (x in chainPins) {
        val v = x as Map<String, Any?>
        val exp = v["expect"] as Map<String, Any?>
        val reason = exp["reason"] as? String ?: ""
        val eri = v["expected_root_issuer"] as? String
        val got = Pca.verifyChain(
            v["chain"] as List<Any?>, eri ?: "", eri != null,
            (v["allowed_suites"] as? List<*>)?.map { it.toString() },
            v["pq_pins"] as? Map<String, Any?>,
            v["trusted_root"] as? Map<String, Any?>,
        )
        check((got == "") == (exp["ok"] == true), "chain_pin ${v["name"]}: ok=${got == ""} want ${exp["ok"]} ($got)")
        if (reason.startsWith("hop 0: root suite")) check(got == reason, "chain_pin ${v["name"]}: reason '$got' want '$reason'")
        cpRan++
    }
    println("CHAIN_PIN: $cpRan run of ${chainPins.size}")

    // ---- round 6: whole signer-set validation, signer-set hash, malformed input (gen-conformance-r6.mjs) -------
    var tsRan = 0
    var tsSkipped = 0
    var malformedRan = 0
    for (x in prim["threshold_set"] as List<Any?>) {
        val e = x as Map<String, Any?>
        val req = e["requires"] as? String
        if (req != null && req !in IMPLEMENTED_SUITES) { tsSkipped++; continue }
        val want = e["valid"] == true
        val got = try { Threshold.verifyShareEntry(e) } catch (th: Throwable) { check(false, "threshold_set ${e["name"]}: THREW $th"); continue }
        check(got == want, "threshold_set ${e["name"]}: verify=$got want $want")
        tsRan++
    }
    for (x in prim["signer_set_hash"] as List<Any?>) {
        val e = x as Map<String, Any?>
        val h = Threshold.signerSetHashB64u(e["signer_set"])
        check(h == e["hash"], "signer_set_hash ${e["name"]}: got $h")
    }
    for (x in prim["malformed"] as List<Any?>) {
        val m = x as Map<String, Any?>
        val nm = m["name"].toString()
        val input = m["input"]
        malformedRan++
        try {
            val accepted = when (m["api"]) {
                "chain" -> {
                    val i = input as Map<String, Any?>
                    Pca.verifyChain(i["chain"] as List<Any?>, i["expected_root_issuer"] as String, true) == ""
                }
                "threshold_share" -> Threshold.verifyShareEntry(input)
                "pcactn_json" -> {
                    val i = input as Map<String, Any?>
                    Pca.verifyPcactnJson(i["text"] as String, i["grant"] as Map<String, Any?>, Json.asLong(i["now"]), Pca.Audience.Of(i["aud"] as String)).allow
                }
                else -> true
            }
            check(!accepted, "malformed $nm: accepted")
        } catch (th: Throwable) {
            check(false, "malformed $nm: THREW $th")
        }
    }
    check(tsRan + tsSkipped >= 55 && malformedRan >= 80, "round-6 primitives present (threshold_set ${tsRan + tsSkipped}, malformed $malformedRan)")
    println("ROUND6: threshold_set $tsRan run, $tsSkipped skipped; malformed $malformedRan")

    // ---- nesting depth (gen-conformance-depth.mjs): limit-1 / limit / limit+1 and a huge (expanded) depth per entry point.
    // Each case runs on a 512 KiB-stack thread (a typical servlet worker): the verdict must equal `valid` and nothing may escape.
    var depthRan = 0
    for (x in prim["depth"] as List<Any?>) {
        val d = x as Map<String, Any?>
        val nm = d["name"].toString()
        val api = d["api"].toString()
        val input = expandDepthInput(api, d["input"], d["expand"] as Map<String, Any?>?)
        val want = d["valid"] == true
        var out: Any? = null
        val t = Thread(null, { out = try { depthVerdict(api, input) } catch (th: Throwable) { th } }, "depth", 512L * 1024)
        t.start(); t.join()
        if (out is Throwable) check(false, "depth $nm: THREW $out") else check(out == want, "depth $nm: verdict=$out want $want")
        depthRan++
    }
    check(depthRan >= 20, "depth primitives present ($depthRan)")
    println("DEPTH: $depthRan run")

    // ---- 0.4.1: policy-layer caveats, root caveats included (primitives.caveat_eval) --------------------------
    var caveatRan = 0
    for (x in (prim["caveat_eval"] as? List<Any?>).orEmpty()) {
        val e = x as Map<String, Any?>
        val exp = e["expect"] as Map<String, Any?>
        val r = try { Caveats.evaluateCaveats(Caveats.policyCaveats(e["grant"], e["chain"]), e["context"]) }
            catch (th: Throwable) { check(false, "caveat_eval ${e["name"]}: THREW $th"); continue }
        check(r.ok == exp["allow"], "caveat_eval ${e["name"]}: allow=${r.ok} want ${exp["allow"]} ${r.failed}")
        check(r.failed == exp["failed"], "caveat_eval ${e["name"]}: failed=${r.failed} want ${exp["failed"]}")
        caveatRan++
    }
    check(caveatRan >= 40, "caveat_eval primitives present ($caveatRan)")
    println("CAVEAT_EVAL: $caveatRan run")
    // primitives.pca_header is N/A here: this verifier has no HTTP middleware and decodes no PCA-Action header.
    println("PCA_HEADER: N/A (no HTTP middleware in the Kotlin verifier), ${(prim["pca_header"] as? List<*>)?.size ?: 0} vectors not applicable")

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
