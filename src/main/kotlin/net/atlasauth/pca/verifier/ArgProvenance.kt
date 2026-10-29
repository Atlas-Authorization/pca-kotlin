package net.atlasauth.pca.verifier

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

/**
 * PROVENANCE BY DEFAULT (packages/pca/src/arg-provenance.ts; spec provenance-by-default): an agent cannot be steered by injected
 * content into choosing who, where or how much.
 *
 * A MEDIATOR (the agent harness, a gateway, an MCP client: whatever sees bytes enter the model's context, with a key the model cannot
 * reach) signs one receipt per context segment into a per-session hash chain: the principal's message (`principal`), a tool result
 * (`tool`), a retrieved document (`retrieval`), a fetched page (`web`) and finally the chosen action (`action`, bound to the exact
 * operation). [decide] re-derives every label from that chain: a value is TRUSTED when the context was purely principal, when it
 * occurs verbatim (as a whole token) in a principal message the chain binds, or when the principal authorized the exact operation (a
 * plan node). A SENSITIVE action (anything not defined as read-only, and every unknown action) whose choice or any sink argument is
 * not trusted is `escalate`; a forged or malformed chain is `deny`. No chain, or a chain from a mediator this verifier does not pin,
 * leaves everything at `agent` (the top).
 *
 * Not to be confused with [ProvenanceGate] (build provenance) or Intent v2 rule 17 ([ParamProvenance], check `provenance`): this is
 * the `provenance_flow` check of [Authorize.authorize]. Values are the [Json] tree. Every function is total: malformed input fails
 * closed, never throws (except the [Recorder], which refuses bad configuration up front).
 *
 * Token matching ([occursAsToken]) runs on Kotlin strings, which are UTF-16 code units exactly like the reference's.
 */
@Suppress("UNCHECKED_CAST")
object ArgProvenance {
    const val RECEIPT_DOMAIN = "atlas-pca/prov-receipt/v1\u0000"
    const val RECEIPT_REF_DOMAIN = "atlas-pca/prov-receipt-ref/v1"
    const val ACTION_DOMAIN = "atlas-pca/prov-action/v1"

    /** Request header carrying a bundle (base64url of its JSON). */
    const val HEADER = "PCA-Provenance"

    /** Request body member carrying a bundle. */
    const val BODY_MEMBER = "pca_provenance"
    const val MAX_RECEIPTS = 256

    /** Largest principal message a bundle may carry (UTF-8 bytes). */
    const val MAX_CONTENT_BYTES = 65_536

    /** Leaves examined per parameter; a larger value keeps the context label. */
    const val MAX_LEAVES = 4096
    private const val MAX_DEPTH = 32

    val ORIGINS: List<String> = listOf("principal", "tool", "retrieval", "web", "action")

    /** The label lattice (rank = index): trusted < first_party < tool < web < agent. */
    val LEVELS: List<String> = listOf("trusted", "first_party", "tool", "web", "agent")

    /** Traits a read-only action may carry and still be non-sensitive. */
    val READ_SAFE_TRAITS: List<String> = listOf("pca.financial_data_read", "pca.pii_access", "pca.regulated_data")
    private val FLOORS = listOf("first_party", "tool", "agent")
    private val OBSERVABLE = listOf("tool", "retrieval", "web")

    /** The level of each segment origin (`action` contributes nothing: it is the model's own output). */
    private val ORIGIN_LEVEL = mapOf("principal" to "trusted", "tool" to "tool", "retrieval" to "tool", "web" to "web")
    private val CONTENT_KEY = Regex("0|[1-9][0-9]{0,8}")

    private fun rank(l: String): Int = LEVELS.indexOf(l)
    private fun join(a: String, b: String): String = if (rank(a) >= rank(b)) a else b
    private fun sortU(xs: Iterable<String>): List<String> = xs.toSet().sortedWith { a, b -> Json.compareUtf8(a, b) }

    // ---------------------------------------------------------------------------------------------------------------- wire

    /** The digest an `action` receipt binds: the exact operation (verb, resource, params). Throws on out-of-profile params. */
    fun actionDigest(verb: String, resource: String, params: Map<String, Any?>): String =
        Pca.hashCanonical(linkedMapOf<String, Any?>("d" to ACTION_DOMAIN, "verb" to verb, "resource" to resource, "params" to params))

    /** Content address of a receipt (signature included). */
    fun receiptRef(r: Map<String, Any?>): String = IntentArtifacts.artifactRef(RECEIPT_REF_DOMAIN, "r", r)

    /** Is `k` a well-formed mediator pin `{mediator, kid, pk, pq_pk?}`? */
    fun isMediatorPin(k: Any?): Boolean {
        if (k !is Map<*, *>) return false
        val m = k as Map<String, Any?>
        return IntentArtifacts.closedMembers(m, listOf("mediator", "kid", "pk"), listOf("pq_pk"), "pin") == null &&
            IntentArtifacts.isBoundedString(m["mediator"], 256) && IntentArtifacts.isBoundedString(m["kid"], 64) &&
            IntentArtifacts.isDigest(m["pk"]) && IntentArtifacts.pinPqOk(m)
    }

    /** Wire validation of one receipt. Null = well-formed. */
    fun receiptWireError(r: Any?): String? {
        if (r !is Map<*, *>) return "a receipt must be an object"
        val m = r as Map<String, Any?>
        val cm = IntentArtifacts.closedMembers(
            m, listOf("v", "kind", "mediator", "kid", "session", "seq", "prev", "origin", "source", "content_digest", "issued_at", "sig"),
            IntentArtifacts.SUITE_MEMBERS, "receipt",
        )
        if (cm != null) return cm
        if (!OracleFacts.isOne(m["v"]) || m["kind"] != "pca-prov") return "a receipt must be {v: 1, kind: \"pca-prov\"}"
        if (!IntentArtifacts.isBoundedString(m["mediator"], 256)) return "'mediator' must be a non-empty string (<= 256 bytes)"
        if (!IntentArtifacts.isBoundedString(m["kid"], 64)) return "'kid' must be a non-empty string (<= 64 bytes)"
        if (!IntentArtifacts.isDigest(m["session"])) return "'session' must be canonical base64url (32 bytes)"
        if (!IntentJs.isNonNeg(m["seq"])) return "'seq' must be a non-negative safe integer"
        if (m["prev"] != null && !IntentArtifacts.isDigest(m["prev"])) return "'prev' must be null or canonical base64url (32 bytes)"
        if (m["origin"] !in ORIGINS) return "'origin' must be one of ${ORIGINS.joinToString(", ")}"
        if (!IntentArtifacts.isBoundedString(m["source"], 256)) return "'source' must be a non-empty string (<= 256 bytes)"
        if (!IntentArtifacts.isDigest(m["content_digest"])) return "'content_digest' must be canonical base64url (32 bytes)"
        if (!IntentJs.isNonNeg(m["issued_at"])) return "'issued_at' must be a non-negative safe integer"
        if (m["sig"] !is String) return "'sig' must be a string"
        return IntentArtifacts.artifactSuiteError(m)
    }

    /** Validate action facts `{effects?, traits?, params?}`. Null = well-formed. */
    fun actionInfoError(a: Any?): String? {
        if (a !is Map<*, *>) return "action info must be an object"
        val m = a as Map<String, Any?>
        val cm = IntentArtifacts.closedMembers(m, emptyList(), listOf("effects", "traits", "params"), "action info")
        if (cm != null) return cm
        for (k in listOf("effects", "traits")) {
            if (!m.containsKey(k)) continue
            val v = m[k]
            if (!(v is List<*> && v.size <= 64 && v.all { IntentArtifacts.isBoundedString(it, 128) })) return "action info '$k' must be a list of strings"
        }
        if (m.containsKey("params")) {
            val p = m["params"] as? Map<*, *> ?: return "action info 'params' must be an object"
            for ((k, v) in p) if (!IntentArtifacts.isBoundedString(k, 128) || v !in FLOORS) return "action info param '$k' must map to first_party | tool | agent"
        }
        return null
    }

    /** Is an action with these facts non-sensitive (it only reads)? Null (unknown facts) is sensitive. */
    fun isReadOnlyAction(a: Any?): Boolean {
        val m = a as? Map<*, *> ?: return false
        val effects = m["effects"] as? List<*> ?: return false
        if (effects.isEmpty() || !effects.all { it == "read" }) return false
        val traits = if (m.containsKey("traits")) m["traits"] as? List<*> ?: return false else emptyList<Any?>()
        return traits.all { it in READ_SAFE_TRAITS }
    }

    /** The grant envelope member `provenance` `{mode?: enforce | insecure_off, mediators?: Pin[] (<= 16)}`. Null when well-formed. */
    fun envelopeError(p: Any?): String? {
        if (p !is Map<*, *>) return "provenance must be an object"
        val m = p as Map<String, Any?>
        val cm = IntentArtifacts.closedMembers(m, emptyList(), listOf("mode", "mediators"), "provenance")
        if (cm != null) return cm
        if (m.containsKey("mode") && m["mode"] != "enforce" && m["mode"] != "insecure_off") return "provenance.mode must be 'enforce' or 'insecure_off'"
        if (m.containsKey("mediators")) {
            val l = m["mediators"]
            if (!(l is List<*> && l.size <= 16 && l.all { isMediatorPin(it) })) return "provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}"
        }
        return null
    }

    // ---------------------------------------------------------------------------------------------------------------- tokens

    /** Word characters for token boundaries: ASCII letters, digits, `_`, and every non-ASCII code unit (fail closed: fewer matches). */
    private fun isWord(c: Char): Boolean = c in '0'..'9' || c in 'A'..'Z' || c in 'a'..'z' || c == '_' || c.code >= 0x80

    /**
     * Does [needle] occur in [text] as a whole token? An occurrence counts when the code unit before it is not a word character (or
     * the needle starts with a non-word character), and likewise after it. Exact, case-sensitive, on UTF-16 code units. An empty
     * needle never occurs.
     */
    fun occursAsToken(text: String, needle: String): Boolean {
        if (needle.isEmpty()) return false
        val headWord = isWord(needle[0])
        val tailWord = isWord(needle[needle.length - 1])
        var i = text.indexOf(needle)
        while (i >= 0) {
            val okB = !headWord || i == 0 || !isWord(text[i - 1])
            val end = i + needle.length
            val okA = !tailWord || end == text.length || !isWord(text[end])
            if (okB && okA) return true
            i = text.indexOf(needle, i + 1)
        }
        return false
    }

    /**
     * The text of every leaf of a value: strings as they are, object keys included (in the reference's member order), other scalars
     * in strict canonical form. Null when deeper than 32 levels, more than [MAX_LEAVES] leaves, or not strict-canonical.
     */
    fun provLeaves(v: Any?): List<String>? {
        val out = ArrayList<String>()
        fun walk(x: Any?, depth: Int): Boolean {
            if (depth > MAX_DEPTH || out.size > MAX_LEAVES) return false
            when (x) {
                is String -> out.add(x)
                is List<*> -> for (y in x) if (!walk(y, depth + 1)) return false
                is Map<*, *> -> for (k in IntentJs.jsKeys(x)) {
                    out.add(k)
                    if (!walk(x[k], depth + 1)) return false
                }
                else -> out.add(try { Json.canonicalizeStrict(x) } catch (e: RuntimeException) { return false })
            }
            return out.size <= MAX_LEAVES
        }
        return try { if (walk(v, 0)) out else null } catch (e: StackOverflowError) { null }
    }

    // ---------------------------------------------------------------------------------------------------------------- decision

    /**
     * The decision for one operation. `outcome` is `pass`, `escalate` (the principal must confirm) or `deny` (forged or malformed
     * provenance, `code` says why). `labels` is the label of every top-level parameter, `tainted` the sink parameters above their
     * floor, `path` where untrusted content came from (`origin:source`, `unlabelled` without a verified chain), all in UTF-8 order.
     */
    class Decision internal constructor(
        val outcome: String,
        val code: String?,
        val reason: String?,
        val sensitive: Boolean,
        val verified: Boolean,
        val control: String,
        val labels: Map<String, String>,
        val tainted: List<String>,
        val path: List<String>,
    ) {
        override fun toString(): String = "ArgProvenance.Decision(outcome=$outcome, code=$code, reason=$reason)"
    }

    private class Chain(val verified: Boolean, val context: String, val path: List<String>, val texts: List<String>)
    private class Bad(val code: String, val reason: String)

    private val UNVERIFIED = Chain(false, "agent", listOf("unlabelled"), emptyList())

    /** Verify a bundle against the pins and the operation: a [Chain], or a [Bad] deny. */
    private fun verifyChain(bundle: Any?, verb: String, resource: String, params: Map<String, Any?>, pins: List<*>): Any {
        if (bundle == null) return UNVERIFIED
        if (bundle !is Map<*, *>) return Bad("malformed_bundle", "the bundle must be an object")
        val b = bundle as Map<String, Any?>
        val cm = IntentArtifacts.closedMembers(b, listOf("v", "kind", "receipts"), listOf("contents"), "bundle")
        if (cm != null) return Bad("malformed_bundle", cm)
        if (!OracleFacts.isOne(b["v"]) || b["kind"] != "pca-provenance") return Bad("malformed_bundle", "the bundle must be {v: 1, kind: \"pca-provenance\"}")
        val rs = b["receipts"] as? List<*>
        if (rs == null || rs.isEmpty() || rs.size > MAX_RECEIPTS) return Bad("malformed_bundle", "the bundle must hold 1..$MAX_RECEIPTS receipts")
        for (i in rs.indices) {
            val e = receiptWireError(rs[i])
            if (e != null) return Bad("malformed_bundle", "receipt $i: $e")
        }
        val contents = if (b.containsKey("contents")) b["contents"] else emptyMap<String, Any?>()
        if (contents !is Map<*, *>) return Bad("malformed_bundle", "'contents' must be an object")
        val receipts = rs.map { it as Map<String, Any?> }
        val first = receipts[0]
        for (i in receipts.indices) {
            val r = receipts[i]
            if (IntentJs.num(r["seq"]) != i.toDouble()) return Bad("broken_chain", "receipt $i has seq ${K3Sig.jsText(r["seq"], true)}")
            if (r["session"] != first["session"] || r["mediator"] != first["mediator"] || r["kid"] != first["kid"])
                return Bad("broken_chain", "receipt $i belongs to another session or mediator")
            val linked = if (i == 0) r["prev"] == null else r["prev"] == receiptRef(receipts[i - 1])
            if (!linked) return Bad("broken_chain", "receipt $i does not link to its predecessor")
            if (i > 0 && IntentJs.num(r["issued_at"])!! < IntentJs.num(receipts[i - 1]["issued_at"])!!) return Bad("broken_chain", "receipt $i is older than its predecessor")
        }
        val last = receipts[receipts.size - 1]
        if (last["origin"] != "action" || last["source"] != verb || last["content_digest"] != actionDigest(verb, resource, params))
            return Bad("unbound_action", "the last receipt is not the action receipt of this operation")
        val cs = contents as Map<String, Any?>
        val keys = IntentJs.jsKeys(cs)
        for (k in keys) {
            val r = if (CONTENT_KEY.matches(k)) receipts.getOrNull(k.toInt()) else null
            if (r == null || r["origin"] != "principal") return Bad("malformed_bundle", "contents '$k' does not name a principal receipt")
            val text = cs[k]
            if (text !is String || IntentJs.u8len(text) > MAX_CONTENT_BYTES) return Bad("malformed_bundle", "contents '$k' must be a string of at most $MAX_CONTENT_BYTES bytes")
            val d = try { Pca.hashCanonical(text) } catch (e: RuntimeException) { return Bad("content_mismatch", "contents '$k' is not canonical text") }
            if (d != r["content_digest"]) return Bad("content_mismatch", "contents '$k' does not hash to its receipt")
        }
        // a chain from a mediator this verifier does not pin vouches for nothing: every value stays at the top (escalate, never allow)
        val pin = pins.firstOrNull { val m = it as Map<*, *>; m["mediator"] == first["mediator"] && m["kid"] == first["kid"] } as Map<*, *>? ?: return UNVERIFIED
        for (i in receipts.indices) {
            if (!IntentArtifacts.verifyArtifactSig(RECEIPT_DOMAIN, receipts[i], pin["pk"], pin["pq_pk"])) return Bad("bad_signature", "receipt $i does not verify under the pinned mediator key")
        }
        val before = receipts.subList(0, receipts.size - 1).filter { it["origin"] != "action" }
        var context = if (before.isEmpty()) "agent" else "trusted"
        val path = ArrayList<String>()
        for (r in before) {
            context = join(context, ORIGIN_LEVEL.getValue(r["origin"] as String))
            if (r["origin"] != "principal") path.add("${r["origin"]}:${r["source"]}")
        }
        if (before.isEmpty()) path.add("unlabelled")
        return Chain(true, context, sortU(path), keys.map { cs[it] as String })
    }

    /**
     * The provenance decision (spec steps 0-6, first failure wins). [bundle] is the presented bundle (null = none), [operation] the
     * JSON object `{verb, resource, params}` this request executes, [mediators] the list of pinned mediator keys, [action] the action
     * facts (`{effects?, traits?, params?}`; null = an unknown action, which is sensitive), [principalPlan] = the principal authorized
     * this exact operation (an executable principal-authorized plan node), [principalControl] = an admitted step of the principal's
     * signed workflow (the CHOICE is trusted, the values are not), [observed] = untrusted content this server itself saw reach the
     * agent (`[{origin: tool | retrieval | web, source}]`, raise only). Never throws.
     */
    @JvmOverloads
    fun decide(
        bundle: Any?, operation: Any?, mediators: Any?, action: Any? = null,
        principalPlan: Boolean = false, principalControl: Boolean = false, observed: Any? = null,
    ): Decision {
        var sensitive = true
        var verified = false
        var control = "agent"
        var labels: Map<String, String> = emptyMap()
        var tainted: List<String> = emptyList()
        var path: List<String> = emptyList()
        fun deny(code: String, reason: String) = Decision("deny", code, reason, sensitive, verified, control, labels, tainted, path)
        try {
            if (mediators !is List<*> || !mediators.all { isMediatorPin(it) }) return deny("malformed_config", "mediator pins must be a list of {mediator, kid, pk, pq_pk?}")
            val op = operation as? Map<*, *>
            val verb = op?.get("verb")
            val resource = op?.get("resource")
            val params = op?.get("params")
            if (verb !is String || !IntentArtifacts.isBoundedString(verb, 256) || resource !is String || params !is Map<*, *>)
                return deny("malformed_operation", "the operation needs a verb, a resource and a params object")
            if (action != null) {
                val e = actionInfoError(action)
                if (e != null) return deny("malformed_action", e)
            }
            val obs = observed ?: emptyList<Any?>()
            if (obs !is List<*> || !obs.all { it is Map<*, *> && it["origin"] in OBSERVABLE && IntentArtifacts.isBoundedString(it["source"], 256) })
                return deny("malformed_config", "observations must be a list of {origin, source}")
            sensitive = !isReadOnlyAction(action)
            val p = params as Map<String, Any?>
            val ch = verifyChain(bundle, verb, resource, p, mediators)
            if (ch is Bad) return deny(ch.code, ch.reason)
            ch as Chain
            verified = ch.verified
            var context = ch.context
            val pth = ArrayList(ch.path)
            for (o in obs) {
                val om = o as Map<*, *>
                context = join(context, ORIGIN_LEVEL.getValue(om["origin"] as String))
                pth.add("${om["origin"]}:${om["source"]}")
            }
            path = sortU(pth)
            control = if (principalPlan || principalControl) "trusted" else context
            val lab = LinkedHashMap<String, String>()
            for (name in sortU(p.keys)) {
                if (principalPlan) {
                    lab[name] = "trusted"
                    continue
                }
                val leaves = provLeaves(p[name])
                if (leaves == null) {
                    lab[name] = context
                    continue
                }
                var l = "trusted"
                for (leaf in leaves) {
                    // a leaf the principal typed verbatim is the principal's choice whatever else the context held
                    val leafLevel = if (context == "trusted" || ch.texts.any { occursAsToken(it, leaf) }) "trusted" else context
                    l = join(l, leafLevel)
                }
                lab[name] = l
            }
            labels = lab
            val floors = (action as? Map<*, *>)?.get("params") as? Map<*, *> ?: emptyMap<String, Any?>()
            val t = ArrayList<String>()
            for ((name, l) in lab) {
                val f = if (floors.containsKey(name)) floors[name] as String else if (sensitive) "first_party" else "agent"
                if (rank(l) > rank(f)) t.add(name)
            }
            tainted = sortU(t)
            // no segment origin maps to first_party, so a control label is trusted or untrusted
            val badControl = sensitive && control != "trusted"
            if (!badControl && tainted.isEmpty()) return Decision("pass", null, null, sensitive, verified, control, labels, tainted, path)
            val where = if (path.isNotEmpty()) " [${path.joinToString(", ")}]" else ""
            val code = if (badControl && tainted.isNotEmpty()) "untrusted_control_and_args" else if (badControl) "untrusted_control" else "untrusted_args"
            val parts = ArrayList<String>()
            if (badControl) parts.add("the choice of $verb derives from untrusted content")
            if (tainted.isNotEmpty()) parts.add("${tainted.joinToString(", ")} ${if (tainted.size == 1) "derives" else "derive"} from untrusted content")
            return Decision("escalate", code, "${parts.joinToString("; ")}$where: the principal must confirm (prompt-injection path)", sensitive, verified, control, labels, tainted, path)
        } catch (e: RuntimeException) {
            return deny("malformed_config", "evaluation error (fail closed): ${e.javaClass.simpleName}")
        } catch (e: StackOverflowError) {
            return deny("malformed_config", "evaluation error (fail closed): StackOverflowError")
        }
    }

    // ---------------------------------------------------------------------------------------------------------------- request

    private fun strictUtf8(b: ByteArray): String? = try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(b)).toString()
    } catch (e: CharacterCodingException) {
        null
    }

    /** The bundle a `PCA-Provenance` header carries: strict base64url, strict UTF-8, strict JSON. Throws [IllegalArgumentException] when unreadable. */
    fun bundleFromHeader(header: String): Any? {
        val raw = Pca.decodeB64uStrict(header, -1) ?: throw IllegalArgumentException("$HEADER is not canonical base64url")
        val text = strictUtf8(raw) ?: throw IllegalArgumentException("$HEADER is not UTF-8")
        return Json.parse(text)
    }

    /** The body member `pca_provenance` of a request body (its raw bytes); null when absent or the body is not strict JSON. */
    fun bundleFromBody(body: ByteArray?): Any? {
        if (body == null || body.isEmpty()) return null
        val text = strictUtf8(body) ?: return null
        val parsed = try { Json.parse(text) } catch (e: RuntimeException) { return null }
        return (parsed as? Map<*, *>)?.get(BODY_MEMBER)
    }

    // ---------------------------------------------------------------------------------------------------------------- mediator side

    /**
     * The mediator side (the client half): one recorder per agent session. It must run where the bytes enter the model's context (the
     * harness that builds the prompt, a gateway, an MCP client), with a key the model cannot reach. Every receipt is a W-B artifact
     * signed under [key] (any suite of [Keys.SuiteKey] with an Ed25519 identity; random Ed25519 when null). [session] is the
     * canonical base64url of 32 bytes (random when null); [now] the clock in epoch milliseconds. A verifier must pin [pin].
     */
    class Recorder @JvmOverloads constructor(
        val mediator: String,
        val kid: String,
        key: Keys.SuiteKey? = null,
        session: String? = null,
        private val now: () -> Long = { System.currentTimeMillis() },
    ) {
        private val signer: Keys.SuiteKey = key ?: Keys.ed25519(Keys.edGenerate())
        val session: String = session ?: Pca.b64(ByteArray(32).also { SecureRandom().nextBytes(it) })

        /** The pin a verifier (or the principal's grant envelope) must carry for this recorder: `{mediator, kid, pk, pq_pk?}`. */
        val pin: Map<String, Any?>
        private val chain = ArrayList<Map<String, Any?>>()
        private val contents = LinkedHashMap<String, String>()

        init {
            require(IntentArtifacts.isBoundedString(mediator, 256) && IntentArtifacts.isBoundedString(kid, 64)) {
                "ArgProvenance.Recorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required"
            }
            require(IntentArtifacts.isDigest(this.session)) { "ArgProvenance.Recorder: session must be canonical base64url of 32 bytes" }
            val id = requireNotNull(signer.id()) { "ArgProvenance.Recorder: the key needs an Ed25519 identity" }
            val pq = signer.pqPk()
            pin = linkedMapOf<String, Any?>("mediator" to mediator, "kid" to kid, "pk" to id).also { if (pq != null) it["pq_pk"] = pq }
        }

        private fun textOf(c: Any?): String = if (c is String) c else try { Json.canonicalize(c) } catch (e: RuntimeException) { c.toString() }

        private tailrec fun clip(s: String): String =
            if (IntentJs.u8len(s) <= 256) (if (s.isNotEmpty()) s else "-") else clip(s.substring(0, maxOf(1, s.length / 2)))

        private fun append(origin: String, source: String, digest: String): Map<String, Any?> {
            val prevR = chain.lastOrNull()
            val issued = maxOf(if (prevR == null) 0L else IntentJs.lng(prevR["issued_at"]), now())
            val body = linkedMapOf<String, Any?>(
                "v" to 1L, "kind" to "pca-prov", "mediator" to mediator, "kid" to kid, "session" to session, "seq" to chain.size.toLong(),
                "prev" to prevR?.let { receiptRef(it) }, "origin" to origin, "source" to clip(source), "content_digest" to digest, "issued_at" to issued,
            )
            val r: Map<String, Any?> = Issue.signArtifact(RECEIPT_DOMAIN, body, signer)
            chain.add(r)
            return r
        }

        private fun segment(origin: String, source: String, content: Any?): Map<String, Any?> {
            val text = textOf(content)
            val r = append(origin, source, Pca.hashCanonical(text))
            if (origin == "principal" && IntentJs.u8len(text) <= MAX_CONTENT_BYTES) contents[IntentJs.lng(r["seq"]).toString()] = text
            return r
        }

        /** The principal's own message (TRUSTED). */
        @Synchronized
        fun principal(text: String): Map<String, Any?> = segment("principal", "user", text)

        /** A tool result (UNTRUSTED). Non-string output is recorded as its JSON text. */
        @Synchronized
        fun tool(name: String, output: Any?): Map<String, Any?> = segment("tool", name, output)

        /** A retrieved document (UNTRUSTED). */
        @Synchronized
        fun retrieval(source: String, content: Any?): Map<String, Any?> = segment("retrieval", source, content)

        /** A fetched web page or HTTP response (UNTRUSTED). */
        @Synchronized
        fun web(url: String, content: Any?): Map<String, Any?> = segment("web", url, content)

        /** Record the chosen action and return the bundle to present with it (header [HEADER] or body member [BODY_MEMBER]). */
        @Synchronized
        fun forAction(verb: String, resource: String, params: Map<String, Any?>): Map<String, Any?> {
            check(chain.size < MAX_RECEIPTS) { "provenance: the session holds $MAX_RECEIPTS receipts; start a new session with the principal's message" }
            append("action", verb, actionDigest(verb, resource, params))
            val b = linkedMapOf<String, Any?>("v" to 1L, "kind" to "pca-provenance", "receipts" to ArrayList<Any?>(chain))
            if (contents.isNotEmpty()) b["contents"] = LinkedHashMap<String, Any?>(contents)
            return b
        }

        fun forAction(op: Authorize.Operation): Map<String, Any?> = forAction(op.verb, op.resource, op.params)

        /** Every receipt so far. */
        @Synchronized
        fun receipts(): List<Map<String, Any?>> = ArrayList(chain)
    }

    /**
     * The bundle for an operation that came straight from the principal (the application's own UI acting on the user's explicit input,
     * no model in between): one principal segment holding the operation, then the action. Under a pinned recorder key the operation's
     * choice and values are trusted.
     */
    fun principalDirect(recorder: Recorder, verb: String, resource: String, params: Map<String, Any?>): Map<String, Any?> = synchronized(recorder) {
        recorder.principal(Json.canonicalizeStrict(linkedMapOf<String, Any?>("verb" to verb, "resource" to resource, "params" to params)))
        recorder.forAction(verb, resource, params)
    }

    fun principalDirect(recorder: Recorder, op: Authorize.Operation): Map<String, Any?> = principalDirect(recorder, op.verb, op.resource, op.params)

    /** The base64url header value of a bundle (strict canonical JSON). */
    fun headerOf(bundle: Map<String, Any?>): String = Pca.b64(Json.canonicalizeStrict(bundle).toByteArray(StandardCharsets.UTF_8))
}
