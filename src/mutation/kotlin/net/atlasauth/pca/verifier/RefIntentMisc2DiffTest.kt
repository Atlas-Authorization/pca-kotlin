package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The leftovers of the intent modules against the reference (ref-intent-misc2, 770 cases): one test per module, each handling every function of its module
 * and asserting its case total. The shared strict-artifact helpers come first; the ask-the-principal question, the classifier, the accumulator receipts and
 * the session-store admission follow in their own tests below.
 */
@Suppress("UNCHECKED_CAST")
class RefIntentMisc2DiffTest {
    private val mod = "ref-intent-misc2"

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    private fun seed(o: Any?): ByteArray = Pca.decodeB64uStrict((o as? Map<*, *>)?.get("\$bytes"), 32) ?: throw IllegalArgumentException("not a signing key")

    private fun signer(secret: Any?, suite: Any?): Keys.SuiteKey {
        val s = suite as Map<String, Any?>?
        val alg = if (s != null && s.containsKey("alg")) s["alg"] as String else "ed25519"
        val pq = s?.get("pqSeed")?.let { Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed(it)) }
        return Keys.suite(alg, Keys.edFromSeed(seed(secret)), pq)
    }

    private fun regex(r: Regex) = linkedMapOf<String, Any?>("\$regex" to "^" + r.pattern + "$")

    /** Replays every case of [fns] through [f] (an unhandled fn fails) and asserts the group's case total. */
    private fun replay(fns: Set<String>, total: Int, f: (String, List<Any?>) -> Any?, skip: Set<String> = emptySet()) {
        var n = 0
        val bad = ArrayList<String>()
        for (fn in fns) {
            for (c in OracleCases.of(mod, fn)) {
                n++
                if (c["name"] in skip) continue
                val case = LinkedHashMap(c)
                case["args"] = OracleCases.decNum(c["args"])
                OracleCases.diff(case, c["out"]) { x -> f(fn, x) }?.let { bad.add(it) }
            }
        }
        assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        assertEquals(total, n)
        assertTrue(BaseOracle.fns("$mod.json.gz").containsAll(fns))
    }

    // ---- intent-artifacts ----

    private val artifactFns = setOf(
        "isPathSegment", "isPlainObject", "isSafeInt", "utf8Len", "isBoundedString", "isDigest", "isScalar", "scalarEq", "closedMembers", "pinPqOk", "artifactSuiteError",
        "artifactMessage", "signArtifact", "verifyArtifactSig", "artifactRef", "publicKeyB64u", "resolveParamPath", "isParamPath", "setNested", "isClock", "ownGet", "nullRecord",
    )

    private fun artifacts(fn: String, a: List<Any?>): Any? = when (fn) {
        "isPathSegment" -> IntentArtifacts.isPathSegment(net.atlasauth.pca.jose.Js.template(a[0])) // the reference tests the string form of any value (5 and null are segments)
        "isPlainObject" -> IntentArtifacts.isPlainObject(a[0])
        "isSafeInt" -> IntentArtifacts.isSafeInt(a[0])
        "utf8Len" -> IntentArtifacts.utf8Len(a[0] as String)
        "isBoundedString" -> IntentArtifacts.isBoundedString(a[0], IntentJs.num(a[1]) ?: Double.NaN)
        "isDigest" -> IntentArtifacts.isDigest(a[0])
        "isScalar" -> IntentArtifacts.isScalar(a[0])
        "scalarEq" -> IntentArtifacts.scalarEq(a[0], a[1])
        "closedMembers" -> IntentArtifacts.closedMembers(map(a[0]), a[1] as List<String>, (arg(a, 2) as List<String>?) ?: emptyList(), (arg(a, 3) as String?) ?: "object")
        "pinPqOk" -> IntentArtifacts.pinPqValueOk(arg(a, 0), a.isNotEmpty())
        "artifactSuiteError" -> IntentArtifacts.artifactSuiteError(a[0])
        "artifactMessage" -> IntentArtifacts.artifactMessage(a[0] as String, map(a[1]))
        "signArtifact" -> Issue.signArtifact(a[0] as String, map(a[1]), signer(a[2], arg(a, 3)))
        "verifyArtifactSig" -> {
            val pin = a[2]
            val artifact = a[1] as? Map<String, Any?>
            when {
                artifact == null -> false
                pin is String -> IntentArtifacts.verifyArtifactSig(a[0] as String, artifact, pin, null)
                pin is Map<*, *> -> IntentArtifacts.verifyArtifactSig(a[0] as String, artifact, pin["pk"], pin["pq_pk"])
                else -> false
            }
        }
        "artifactRef" -> IntentArtifacts.artifactRef(a[0] as String, a[1] as String, a[2])
        "publicKeyB64u" -> Keys.edFromSeed(seed(a[0])).id()
        "resolveParamPath" -> IntentArtifacts.resolveParamPath(a[0], a[1]).let { r -> if (r.found) linkedMapOf("found" to true, "value" to r.value) else linkedMapOf("found" to false) }
        "isParamPath" -> IntentArtifacts.isParamPath(a[0])
        "setNested" -> {
            val x = map(a[0])
            val root = (x["root"] as Map<String, Any?>).toMutableMap().let { LinkedHashMap(it) }
            val ok = IntentArtifacts.setNested(root, x["path"] as String, x["value"])
            linkedMapOf("ok" to ok, "root" to root)
        }
        "isClock" -> IntentArtifacts.isClock(a[0])
        "ownGet" -> IntentArtifacts.ownGet(a[0], a[1] as String)
        "nullRecord" -> IntentArtifacts.nullRecord()
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun artifactHelpers() = replay(artifactFns, 254, ::artifacts)

    // ---- intent-required ----

    private val requiredFns = setOf("intentActionDigest", "cellCoordsError", "intentRequiredShapeError", "signIntentRequired", "verifyIntentRequired", "verifyIntentRequiredAt", "intentProblem")

    private fun required(fn: String, a: List<Any?>): Any? = when (fn) {
        "intentActionDigest" -> IntentRequired.intentActionDigest(a[0])
        "cellCoordsError" -> IntentRequired.cellCoordsError(a[0])
        "intentRequiredShapeError" -> IntentRequired.intentRequiredShapeError(a[0], (arg(a, 1) as Map<String, Any?>?)?.get("signed") != false)
        "signIntentRequired" -> IntentRequired.signIntentRequired(a[0] as? Map<String, Any?> ?: throw IllegalArgumentException("signIntentRequired: not an object"), a[1] as String, signer(a[2], arg(a, 3)))
        "verifyIntentRequired" -> IntentRequired.verifyIntentRequired(a[0], a[1], a[2])
        "verifyIntentRequiredAt" -> IntentRequired.verifyIntentRequiredAt(a[0], a[1], a[2])
        "intentProblem" -> {
            val o = arg(a, 1) as Map<String, Any?>?
            IntentRequired.intentProblem(a[0], if (o != null && o.containsKey("detail")) o["detail"] else ZkJs.UNDEF, o?.get("body"))
        }
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun askThePrincipal() = replay(requiredFns, 224, ::required)

    // ---- intent-classifier ----

    private val classifierFns = setOf(
        "validateClassifierVerdictWire", "classifierContentDigest", "signClassifierVerdict", "classifierVerdictRef", "validateClassifierPolicy", "classifierCheckActive",
        "decideClassifierDimensions", "verifyClassifierAttestation",
    )

    private fun classifier(fn: String, a: List<Any?>): Any? = when (fn) {
        "validateClassifierVerdictWire" -> IntentClassifier.validateClassifierVerdictWire(a[0])
        "classifierContentDigest" -> IntentClassifier.classifierContentDigest(a[0])
        "signClassifierVerdict" -> IntentClassifier.signClassifierVerdict(map(a[0]), signer(a[1], arg(a, 2)))
        "classifierVerdictRef" -> IntentClassifier.classifierVerdictRef(a[0])
        "validateClassifierPolicy" -> IntentClassifier.validateClassifierPolicy(a[0])
        "classifierCheckActive" -> IntentClassifier.classifierCheckActive(a[0])
        "decideClassifierDimensions" -> IntentClassifier.decideClassifierDimensions(a[0])
        "verifyClassifierAttestation" -> IntentClassifier.verifyClassifierAttestation(a[0], arg(a, 1), arg(a, 2))
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun classifierVerdicts() = replay(classifierFns, 158, ::classifier)

    // ---- intent-acc ----

    private val accFns = setOf(
        "monitorStates", "monitorInitialState", "distinctKey", "sortedDistinct", "signAccReceipt", "accReceiptDigest", "accReceiptCoreDigest", "verifyReceiptSignature",
        "signSequencerKeySet", "sequencerKeySetDigest", "verifyKeySet",
    )

    private fun acc(fn: String, a: List<Any?>): Any? = when (fn) {
        "monitorStates" -> IntentAcc.monitorStates(a[0])
        "monitorInitialState" -> IntentAcc.monitorInitialState(a[0])
        "distinctKey" -> IntentAcc.distinctKey(a[0])
        "sortedDistinct" -> IntentAcc.sortedDistinct((a[0] as List<Any?>).map { it as String })
        "signAccReceipt" -> IntentAcc.signAccReceipt(map(a[0]), signer(a[1], arg(a, 2)))
        "accReceiptDigest" -> IntentAcc.accReceiptDigest(a[0])
        "accReceiptCoreDigest" -> IntentAcc.accReceiptCoreDigest(a[0])
        "verifyReceiptSignature" -> IntentAcc.verifyAccReceiptSignature(a[0], a[1] as String, (arg(a, 2) as Map<String, Any?>?)?.get("pqPins") as Map<String, Any?>?)
        "signSequencerKeySet" -> IntentAcc.signSequencerKeySet(map(a[0]), signer(a[1], arg(a, 2)))
        "sequencerKeySetDigest" -> IntentAcc.sequencerKeySetDigest(a[0])
        "verifyKeySet" -> IntentAcc.verifySequencerKeySet(a[0], a[1] as String, arg(a, 2) as String?)
        else -> throw AssertionError("unhandled fn $fn")
    }

    /** The reference's `allowUnboundPq` opt-in (accept an artifact's own, unpinned PQ key) is not offered natively: that case must be refused. */
    private val unboundPq = "verifyReceiptSignature/pq-unbound#725"

    @Test fun accumulatorReceipts() {
        val c = OracleCases.of(mod, "verifyReceiptSignature").first { it["name"] == unboundPq }
        val a = OracleCases.decNum(c["args"]) as List<Any?>
        assertEquals(false, acc("verifyReceiptSignature", a))
        replay(accFns, 109, ::acc, setOf(unboundPq))
    }

    // ---- intent-history ----

    private val historyFns = setOf("accContextFor", "admit")

    private fun admit(ops: List<Any?>): Any? {
        var store: IntentHistory.MemoryIntentSessionStore = IntentHistory.MemoryIntentSessionStore(true)
        val out = ArrayList<Any?>()
        for (opo in ops) {
            val op = opo as List<Any?>
            try {
                when (op[0]) {
                    "store" -> {
                        val d = map(op[1])["durable"]
                        store = IntentHistory.MemoryIntentSessionStore(if (d == "absent") null else d != false)
                        out.add(null)
                    }
                    "admit" -> {
                        val a = map(op[1])
                        val v = IntentHistory.admitIntentAction(
                            store, a["session"] as String, a["root"], map(a["event"]),
                            { acc ->
                                if (a["verifyAs"] == "throws") throw IllegalStateException("verify boom")
                                out.add(linkedMapOf("acc" to acc))
                                linkedMapOf("allow" to map(a["verifyAs"])["allow"])
                            },
                            a["schema"], a["requireDurable"] != false,
                        )
                        out.add(linkedMapOf("allow" to v["allow"]))
                    }
                    "settle" -> out.add(IntentHistory.settleIntentEvent(store, op[1] as String, op[2] as String, op[3] as String))
                    "events" -> out.add(store.snapshot(op[1] as String))
                    else -> out.add(linkedMapOf("\$err" to "op"))
                }
            } catch (e: RuntimeException) {
                out.add(linkedMapOf("\$err" to true))
            }
        }
        return out
    }

    private fun history(fn: String, a: List<Any?>): Any? = when (fn) {
        "accContextFor" -> IntentHistory.accContextFor(a[0], a[1] as List<Any?>, map(a[2]), arg(a, 3))
        "admit" -> admit(a[0] as List<Any?>)
        else -> throw AssertionError("unhandled fn $fn")
    }

    @Test fun sessionAdmission() = replay(historyFns, 24, ::history)

    // ---- every exported constant of the five modules, and the corpus as a whole ----

    private fun constants(): Map<String, Any?> = linkedMapOf(
        "DATA_CLASS_RE" to regex(IntentArtifacts.DATA_CLASS_RE), "INTENT_NAME_RE" to regex(IntentArtifacts.INTENT_NAME_RE), "PARAM_SEGMENT_RE" to regex(IntentArtifacts.PARAM_SEGMENT_RE),
        "SUITE_MEMBERS" to IntentArtifacts.SUITE_MEMBERS, "FRICTIONS" to IntentRequired.FRICTIONS, "INTENT_ACTION_DOMAIN" to IntentRequired.INTENT_ACTION_DOMAIN,
        "INTENT_PROBLEM_KINDS" to IntentRequired.INTENT_PROBLEM_KINDS, "INTENT_REQUIRED_DOMAIN" to IntentRequired.INTENT_REQUIRED_DOMAIN, "PROBLEM_BASE" to IntentRequired.PROBLEM_BASE,
        "INTENT_CLASSIFIER_DOMAIN" to IntentClassifier.INTENT_CLASSIFIER_DOMAIN, "INTENT_CLASSIFIER_REF_DOMAIN" to IntentClassifier.INTENT_CLASSIFIER_REF_DOMAIN,
        "MAX_CLASSIFIER_LABELS" to IntentClassifier.MAX_CLASSIFIER_LABELS, "MAX_COMMITTED_CLASSES" to IntentClassifier.MAX_COMMITTED_CLASSES,
        "ACC_AGGS" to IntentAcc.ACC_AGGS, "ACC_ID_RE" to regex(IntentAcc.ACC_ID_RE), "ACC_RECEIPT_CORE_DOMAIN" to IntentAcc.ACC_RECEIPT_CORE_DOMAIN,
        "ACC_RECEIPT_DOMAIN" to IntentAcc.ACC_RECEIPT_DOMAIN, "ACC_RECEIPT_REF_DOMAIN" to IntentAcc.ACC_RECEIPT_REF_DOMAIN, "ACC_RESERVE_DOMAIN" to IntentAcc.ACC_RESERVE_DOMAIN,
        "ACC_SCOPES" to IntentAcc.ACC_SCOPES, "DEFAULT_MAX_KEYSET_AGE_MS" to IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS, "DEFAULT_MAX_RECEIPT_AGE_MS" to IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS,
        "KID_RE" to regex(IntentAcc.KID_RE), "MAX_MONITOR_WITHIN" to IntentAcc.MAX_MONITOR_WITHIN, "MAX_RECEIPT_LIFETIME_MS" to IntentAcc.MAX_RECEIPT_LIFETIME_MS,
        "MAX_SESSION_ACCUMULATORS" to IntentAcc.MAX_SESSION_ACCUMULATORS, "MAX_SESSION_MONITORS" to IntentAcc.MAX_SESSION_MONITORS, "MONITOR_KINDS" to IntentAcc.MONITOR_KINDS,
        "RECEIPT_SKEW_MS" to IntentAcc.RECEIPT_SKEW_MS, "SEQUENCER_KEYS_DOMAIN" to IntentAcc.SEQUENCER_KEYS_DOMAIN, "SEQUENCER_KEYS_REF_DOMAIN" to IntentAcc.SEQUENCER_KEYS_REF_DOMAIN,
        "COUNTED_STATUSES" to IntentHistory.COUNTED_STATUSES, "EVENT_STATUSES" to IntentHistory.EVENT_STATUSES,
    )

    @Test fun constantsAndTheWholeCorpus() {
        replay(setOf("constants"), 1, { _, _ -> constants() })
        // the five groups above handle every function of the corpus and their totals add up to all of it
        val handled = artifactFns + requiredFns + classifierFns + accFns + historyFns + "constants"
        assertEquals(BaseOracle.fns("$mod.json.gz"), handled)
        assertEquals(770, 254 + 224 + 158 + 109 + 24 + 1)
    }
}
