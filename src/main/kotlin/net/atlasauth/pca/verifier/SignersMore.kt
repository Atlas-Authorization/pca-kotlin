package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets

/**
 * More producer-side signers: the artifacts an agent, a principal, a guardian, a site, an oracle or a resource server signs beyond
 * the grant and the PCActn ([Issue]). Same wire as the TypeScript reference, byte for byte for Ed25519 and the deterministic
 * post-quantum suites. Every signer runs the reference's checks before signing and throws [IllegalArgumentException] on a malformed
 * body (fail closed): a signer never emits an artifact the verifier would refuse.
 *
 * Signers that take a [Keys.SuiteKey] sign under that key's suite; a suite this SDK cannot sign is refused when the key is made
 * (`unsupported_suite: <alg>`).
 */
@Suppress("UNCHECKED_CAST")
object SignersMore {
    private fun utf8(s: String): ByteArray = s.toByteArray(StandardCharsets.UTF_8)

    private fun edOf(k: Keys.SuiteKey, who: String): Keys.EdKey = k.ed ?: throw IllegalArgumentException("$who: the signer needs an Ed25519 identity")

    // ---- threshold shares (threshold.ts signShare / signPreparedShare) --------------------------------------------------------

    /**
     * Sign already-computed share bytes (the share message a step-up hands a principal device). Ed25519 gives `{role, publicKey, sig}`,
     * byte-identical to the pre-agility share; another suite adds `alg` (and `pq_sig` for a hybrid).
     */
    fun signPreparedShare(role: String, signer: Keys.SuiteKey, prepared: ByteArray): Map<String, Any?> {
        val ed = edOf(signer, "signPreparedShare")
        val sg = signer.sign(prepared)
        val share = Issue.obj("role" to role, "publicKey" to ed.id(), "sig" to sg.first)
        if (signer.alg != "ed25519") {
            share["alg"] = signer.alg
            if (sg.second != null) share["pq_sig"] = sg.second
        }
        return share
    }

    /**
     * A role's EXPLICIT threshold share (agent, guardian or principal) over the bound share message
     * `"atlas-pca/share/<role>\0" || sha256(message) || signerSetHash || t [|| suite tag]`, where `message` is the PCActn's threshold
     * message. The share cannot be replayed into another signer set or threshold.
     */
    fun signThresholdShare(role: String, signer: Keys.SuiteKey, message: ByteArray, signerSet: List<Any?>?, t: Int): Map<String, Any?> {
        if (signerSet == null) throw IllegalArgumentException("signShare: a '$role' share must bind {signerSet, t}")
        if (t < 1 || t > 3) throw IllegalArgumentException("shareMessage: t must be 1, 2 or 3")
        return signPreparedShare(role, signer, Threshold.shareMessage(role, message, signerSet, t, signer.alg, true))
    }

    // ---- PQ key binding (pq.ts signPqBinding) ----------------------------------------------------------------------------------

    internal const val PQ_BIND_DOMAIN = "atlas-pca/pq-binding/v2\u0000"

    internal fun pqBindingMessage(ed: String, pq: String, epoch: Long, aud: String): ByteArray = utf8("$PQ_BIND_DOMAIN$ed\u0000$pq\u0000$epoch\u0000$aud")

    /**
     * An identity's signed statement "this PQ key is mine, as of [epoch], for audience [aud]": an Ed25519 signature over the domain,
     * the identity, the PQ key, the epoch and the audience. [epoch] grows on every rotation (at least 1).
     */
    fun signPqBinding(key: Keys.EdKey, pqPublicKey: String, epoch: Long, aud: String?): Map<String, Any?> {
        if (epoch < 1 || epoch > 9007199254740991L) throw IllegalArgumentException("signPqBinding: epoch must be a positive safe integer")
        if (aud.isNullOrEmpty()) throw IllegalArgumentException("signPqBinding: aud (the instance/audience id) is required")
        return Issue.obj("ed" to key.id(), "pq" to pqPublicKey, "epoch" to epoch, "aud" to aud,
            "sig" to Pca.b64(key.sign(pqBindingMessage(key.id(), pqPublicKey, epoch, aud))))
    }

    // ---- agent-native: caution, lease heartbeat --------------------------------------------------------------------------------

    const val MAX_CAUTION_REASON_LEN = 64
    private val REASON_RE = Regex("^[A-Za-z0-9_.:-]+$")

    private fun msgOf(domain: String, body: Any?): ByteArray = Pca.canonBytes(Issue.obj("d" to domain, "b" to body))

    private fun nonEmpty(v: Any?): Boolean = v is String && v.isNotEmpty()

    /** The reference's caution body check; null when the body may be signed. */
    internal fun cautionBodyError(bO: Any?): String? {
        if (bO !is Map<*, *>) return "not an object"
        if (!nonEmpty(bO["action_digest"])) return "action_digest required"
        if (!nonEmpty(bO["holder"])) return "holder required"
        val c = bO["caution"]
        if (!IntentJs.isFinite(c) || IntentJs.num(c)!! < 0 || IntentJs.num(c)!! > 1) return "caution must be a finite number in [0,1]"
        if (bO.containsKey("reason")) {
            val r = bO["reason"]
            if (r !is String || r.length > MAX_CAUTION_REASON_LEN || !REASON_RE.matches(r)) return "invalid reason"
        }
        return null
    }

    /**
     * The holder's signed caution claim about an action (`{action_digest, caution in [0,1], reason?, holder}`). Throws on an invalid
     * body (an out-of-range caution, a bad reason); members beyond these are dropped.
     */
    fun signCaution(body: Map<String, Any?>, holder: Keys.EdKey): Map<String, Any?> {
        val err = cautionBodyError(body)
        if (err != null) throw IllegalArgumentException("signCaution: $err")
        val clean = Issue.obj("action_digest" to body["action_digest"], "caution" to body["caution"], "holder" to body["holder"])
        if (body.containsKey("reason")) clean["reason"] = body["reason"]
        val out = LinkedHashMap(clean)
        out["sig"] = Pca.b64(holder.sign(msgOf("atlas-pca/caution/v1", clean)))
        return out
    }

    /** The lease holder's signed liveness proof (`{cap_id, seq, at, holder, lease_issued_at}`); other members are dropped. */
    fun signHeartbeat(body: Map<String, Any?>, holder: Keys.EdKey): Map<String, Any?> {
        val clean = LinkedHashMap<String, Any?>()
        for (k in listOf("cap_id", "seq", "at", "holder", "lease_issued_at")) {
            if (!body.containsKey(k)) throw IllegalArgumentException("signHeartbeat: $k required")
            clean[k] = body[k]
        }
        val out = LinkedHashMap(clean)
        out["sig"] = Pca.b64(holder.sign(msgOf("atlas-pca/lease-hb/v2", clean)))
        return out
    }

    // ---- read receipt (readside.ts signReadReceipt, resource-server side) ------------------------------------------------------

    /** The resource server's signed receipt for a read under [grant] (the read grant BODY); [prev] is the previous receipt or null. */
    fun signReadReceipt(rs: Keys.EdKey, grant: Map<String, Any?>, verb: String, resource: String, purpose: String, fields: Map<String, Any?>,
                        labels: List<Any?>, issuedAt: Long, prev: Map<String, Any?>?): Map<String, Any?> {
        val base = Issue.obj("v" to 1L, "grant" to ReadSide.readGrantDigest(grant), "verb" to verb, "resource" to resource, "purpose" to purpose,
            "seq" to (if (prev == null) 0L else Json.asLong(prev["seq"]) + 1), "prev" to prev?.let { ReadSide.readReceiptRef(it) },
            "fields" to fields, "labels" to labels, "issued_at" to issuedAt, "signer" to rs.id())
        val n = Issue.norm(base)
        n["sig"] = Issue.signBody(rs, ReadSide.READ_RECEIPT_DOMAIN, n)
        return n
    }

    // ---- cross-domain mesh (mesh.ts signMeshAction / assembleMeshProof) --------------------------------------------------------

    /** The leaf holder's signature over `{action, tip = capHash(last hop)}`. */
    fun signMeshAction(chain: List<Any?>?, action: Map<String, Any?>, leaf: Keys.EdKey): String {
        if (chain.isNullOrEmpty()) throw IllegalArgumentException("signMeshAction: empty chain")
        val tip = Pca.capHash(Pca.asMap(chain.last()))
        return Pca.b64(leaf.sign(Pca.concat(utf8(Mesh.ACTION_DOMAIN), Pca.canonBytes(Issue.obj("action" to action, "tip" to tip)))))
    }

    /**
     * A compact mesh proof: hops issued against the same head share one table entry (their cosignatures merged by witness), identical
     * revocation bracketing leaves are carried once, and the leaf holder signs the action. Each hop is
     * `{domain, head: {head, sig, cosigs}, inclusion, revocation: {cap, issuer_key}, binding?}`.
     */
    fun assembleMeshProof(chain: List<Any?>, hops: List<Any?>, action: Map<String, Any?>, leaf: Keys.EdKey, pinProofs: List<Any?>? = null): Map<String, Any?> {
        val heads = ArrayList<Any?>()
        val leaves = ArrayList<Any?>()
        val outHops = ArrayList<Any?>()
        val headIdx = HashMap<String, Int>()
        val leafIdx = HashMap<String, Int>()
        fun compact(nO: Any?): Map<String, Any?> {
            val n = Pca.asMap(nO)
            val o = Issue.obj("size" to n["size"])
            for (side in listOf("lo", "hi")) {
                val lp = n[side] ?: continue
                val k = Json.canonicalize(lp)
                val i = leafIdx.getOrPut(k) { leaves.add(lp); leaves.size - 1 }
                o[side] = i.toLong()
            }
            return o
        }
        for (evO in hops) {
            val ev = Pca.asMap(evO)
            val h = Pca.asMap(ev["head"])
            val k = "${h["sig"]}|${Json.canonicalize(h["head"])}"
            var i = headIdx[k]
            if (i == null) {
                i = heads.size
                heads.add(Issue.obj("head" to h["head"], "sig" to h["sig"], "cosigs" to ArrayList<Any?>(Pca.asList(h["cosigs"]))))
                headIdx[k] = i
            } else {
                val cos = Pca.asMap(heads[i])["cosigs"] as MutableList<Any?>
                val have = cos.map { Pca.asMap(it)["witness"] }.toHashSet()
                for (c in Pca.asList(h["cosigs"])) if (Pca.asMap(c)["witness"] !in have) cos.add(c)
            }
            val rev = Pca.asMap(ev["revocation"])
            val o = Issue.obj("domain" to ev["domain"], "head" to i.toLong(), "inclusion" to ev["inclusion"],
                "revocation" to Issue.obj("cap" to compact(rev["cap"]), "issuer_key" to compact(rev["issuer_key"])))
            if (ev["binding"] != null) o["binding"] = ev["binding"]
            outHops.add(o)
        }
        val proof = Issue.obj("chain" to ArrayList<Any?>(chain), "heads" to heads, "rev_leaves" to leaves, "hops" to outHops,
            "action" to action, "action_sig" to signMeshAction(chain, action, leaf))
        if (!pinProofs.isNullOrEmpty()) proof["pin_proofs"] = ArrayList<Any?>(pinProofs)
        return proof
    }

    // ---- Intent v2 session root and session grant (intent-session.ts) ---------------------------------------------------------

    private val ROOT_MEMBERS = listOf("v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri")

    /** Sign the session root as one of its principals: the signer's Ed25519 key must be listed in `principals`. */
    fun signSessionRoot(body: Map<String, Any?>, principal: Keys.SuiteKey): Map<String, Any?> {
        val signer = edOf(principal, "signSessionRoot").id()
        val base = LinkedHashMap<String, Any?>()
        for (k in ROOT_MEMBERS) base[k] = body[k]
        for (k in listOf("revocation", "flows")) if (body.containsKey(k)) base[k] = body[k]
        base["expires_at"] = body["expires_at"]
        base["signer"] = signer
        // the reference's unsigned shape check: the body as given (unknown members included) with the signer and a placeholder sig
        val probe = LinkedHashMap(body)
        for (k in listOf("sig", "alg", "pq_pk", "pq_sig")) probe.remove(k)
        probe["signer"] = signer
        probe["sig"] = ""
        val bad = IntentSession.rootShapeError(probe)
        if (bad == "signer is not one of the session principals") throw IllegalArgumentException("signSessionRoot: the signer is not one of the session principals")
        if (bad != null) throw IllegalArgumentException("signSessionRoot: $bad")
        return Issue.signArtifact(IntentSession.INTENT_SESSION_SIG_DOMAIN, base, principal)
    }

    /** A session grant and the salt that opens its goal commitment (it goes in the PCActn's `intent.goal_salt`). */
    class SessionGrant(val grant: Map<String, Any?>, val goalSalt: String)

    /**
     * G_0 (seq 0) or a delta grant D_k: a principal-signed root capability whose caveats are the envelope (goal
     * `pca-intent:v2:<session>:<mapDigest>`, or `v2c` over a committed map when [mapForm] is `"commit"`) and the `intent_session` caveat.
     */
    fun mintSessionGrant(principal: Keys.SuiteKey, holder: String, session: String, seq: Long, root: String, prev: String? = null, mapDigest: String,
                         mapForm: String? = null, predicates: List<Any?>, caveats: List<Any?>? = null, agentBinding: Map<String, Any?>? = null,
                         riskPolicy: Map<String, Any?>? = null, salt: String? = null, holderPqPk: String? = null): SessionGrant {
        val sc = Issue.obj("type" to "intent_session", "session" to session, "seq" to seq, "root" to root)
        if (prev != null) sc["prev"] = prev
        val bad = IntentSession.caveatError(sc)
        if (bad != null) throw IllegalArgumentException("mintSessionGrant: $bad")
        if (!IntentJs.b32(mapDigest)) throw IllegalArgumentException("mintSessionGrant: mapDigest must be canonical base64url (32 bytes)")
        val goalSalt = salt ?: Issue.randomB64u(16)
        val goal = if (mapForm == IntentMap.MAP_FORM_COMMIT) IntentSession.intentGoalV2c(session, mapDigest) else IntentSession.intentGoalV2(session, mapDigest)
        val envelope = Issue.obj("type" to Issue.ENVELOPE_CAVEAT, "goal_commit" to Issue.goalCommit(goal, goalSalt), "predicates" to predicates,
            "caveats" to (caveats ?: ArrayList<Any?>()), "agent_binding" to (agentBinding ?: LinkedHashMap<String, Any?>()),
            "risk_policy" to (riskPolicy ?: Issue.defaultRiskPolicy()))
        return SessionGrant(Issue.mintRoot(principal, holder, holderPqPk, listOf(envelope, sc)), goalSalt)
    }

    // ---- site-signed documents: action schema, intent_required, labels; oracle facts -------------------------------------------

    /** Sign an action schema as the site: `sig = {alg, kid, value, pq_value?}` over `utf8(domain) || strictCanonical(doc)`. */
    fun signActionSchema(doc: Map<String, Any?>, kid: String, site: Keys.SuiteKey): Map<String, Any?> {
        val bad = ActionSchema.shapeError(doc, false)
        if (bad != null) throw IllegalArgumentException("signActionSchema: $bad")
        // shapeError(doc, false) refused a document carrying `sig`, so `doc` is the body to sign
        val sg = site.sign(Pca.concat(utf8(ActionSchema.ACTION_SCHEMA_DOMAIN), Pca.canonBytes(doc)))
        val sig = Issue.obj("alg" to site.alg, "kid" to kid, "value" to sg.first)
        if (sg.second != null) sig["pq_value"] = sg.second
        val out = LinkedHashMap(doc)
        out["sig"] = sig
        return out
    }

    /** The discovery key entry `{kid, alg, pk, pq_pk?}` a verifier pins for a site signer. */
    fun actionSchemaKeyOf(kid: String, site: Keys.SuiteKey): Map<String, Any?> {
        val k = Issue.obj("kid" to kid, "alg" to site.alg, "pk" to edOf(site, "actionSchemaKeyOf").id())
        site.pqPk()?.let { k["pq_pk"] = it }
        return k
    }

    const val INTENT_REQUIRED_DOMAIN = "atlas-pca/intent-required/v1\u0000"
    private val IR_KEYS = setOf("v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id",
        "friction", "delivered_to", "expires_at", "sig")
    private val QUESTION_ID_RE = Regex("[A-Za-z0-9_-]{1,64}")

    internal fun cellCoordsError(cO: Any?): String? {
        if (cO !is Map<*, *> || cO.isEmpty() || cO.size > 64) return "coords must be an object of 1..64 dimensions"
        for ((kO, v) in cO) {
            val k = kO as String
            if (k.isEmpty() || k.length > 256) return "a coordinate path must be 1..256 characters"
            val l = v as? List<*>
            if (l != null && l.size == 2 && IntentJs.isInt(l[0]) && IntentJs.isInt(l[1])) {
                if (!(IntentJs.num(l[0])!! >= 0 && IntentJs.num(l[0])!! <= IntentJs.num(l[1])!!)) return "coords '$k': need 0 <= lo <= hi"
                continue
            }
            if (l == null || l.isEmpty() || l.size > 256 || l.any { it !is String }) return "coords '$k': an index range [lo, hi] or a value set"
            if (l.toHashSet().size != l.size) return "coords '$k': values must be distinct"
        }
        return null
    }

    /** The reference's shape check of an UNSIGNED `pca-intent-required` v1 body (the signer's pre-check); null when well formed. */
    fun intentRequiredShapeError(bO: Any?): String? {
        if (bO !is Map<*, *>) return "not an object"
        for (k in bO.keys) if (k !in IR_KEYS) return "unknown member '$k'"
        if (!(IntentJs.isSafeInteger(bO["v"]) && IntentJs.lng(bO["v"]) == 1L) || bO["kind"] != "pca-intent-required") return "not a pca-intent-required v1"
        for (k in listOf("session", "map_digest", "schema", "pcactn_digest", "action_digest"))
            if (!IntentJs.b32(bO[k])) return "$k must be canonical base64url (32 bytes)"
        val cell = bO["cell"]
        if (cell !is Map<*, *> || cell.size != 2 || !cell.containsKey("coords") || !cell.containsKey("verb") || !nonEmpty(cell["verb"])) return "cell must be {verb, coords}"
        val ce = cellCoordsError(cell["coords"])
        if (ce != null) return ce
        if (bO["reason"] != "uncertain") return "reason must be 'uncertain'"
        val q = bO["question_id"]
        if (q !is String || !QUESTION_ID_RE.matches(q)) return "question_id must match [A-Za-z0-9_-]{1,64}"
        if (bO["friction"] !in listOf("tap", "hold", "typed", "device")) return "unknown friction tier"
        if (bO["delivered_to"] != "wallet" && bO["delivered_to"] != "agent") return "delivered_to must be 'wallet' or 'agent'"
        if (!IntentJs.isNonNeg(bO["expires_at"])) return "expires_at must be a non-negative safe integer"
        if (bO.containsKey("sig")) return "an unsigned body must not carry sig"
        return null
    }

    /**
     * The site's signed `pca-intent-required` v1 body: `sig = {alg, kid, value, pq_value?}` over `utf8(domain) || strictCanonical(body)`,
     * pinned by the same discovery key entry as the action schema.
     */
    fun signIntentRequired(body: Map<String, Any?>, kid: String, site: Keys.SuiteKey): Map<String, Any?> {
        val bad = intentRequiredShapeError(body)
        if (bad != null) throw IllegalArgumentException("signIntentRequired: $bad")
        val sg = site.sign(Pca.concat(utf8(INTENT_REQUIRED_DOMAIN), Pca.canonBytes(body)))
        val sig = Issue.obj("alg" to site.alg, "kid" to kid, "value" to sg.first)
        if (sg.second != null) sig["pq_value"] = sg.second
        val out = LinkedHashMap(body)
        out["sig"] = sig
        return out
    }

    // ---- progress step (progress.ts signProgressStep, holder side) ------------------------------------------------------------

    const val PROGRESS_SIG_DOMAIN = "atlas-pca/progress-step/v2"

    /**
     * The holder's signed progress step `{step, holder, sig}`: Ed25519 over the domain-separated binding of the step to the holder,
     * goal, action, before/after state, sequence, chain link and step digest.
     */
    fun signProgressStep(step: Map<String, Any?>, holder: Keys.EdKey): Map<String, Any?> {
        val b = Issue.obj("holder" to holder.id(), "goal_commitment" to step["goal_commitment"], "action_digest" to step["action_digest"],
            "before_digest" to step["before_digest"], "after_digest" to step["after_digest"], "seq" to step["seq"], "prev" to step["prev"],
            "step_digest" to step["digest"])
        return Issue.obj("step" to step, "holder" to holder.id(), "sig" to Pca.b64(holder.sign(msgOf(PROGRESS_SIG_DOMAIN, b))))
    }

    /** A site's signed label receipt (`pca-labels` v1). */
    fun signLabels(body: Map<String, Any?>, site: Keys.SuiteKey): Map<String, Any?> {
        val full = Issue.obj("v" to 1L, "kind" to "pca-labels")
        full.putAll(body)
        return Issue.signArtifact(ParamProvenance.LABELS_DOMAIN, full, site)
    }

    /** An oracle's signed fact (`pca-fact` v1). */
    fun signFact(body: Map<String, Any?>, oracle: Keys.SuiteKey): Map<String, Any?> {
        val full = Issue.obj("v" to 1L, "kind" to "pca-fact")
        full.putAll(body)
        return Issue.signArtifact(OracleFacts.FACT_DOMAIN, full, oracle)
    }

    /**
     * A site's signed offer set (`pca-offer-set` v1; the body carries its own v / kind). As in the reference, only the strict
     * canonical profile is checked before signing (the verifier checks the wire).
     */
    fun signOfferSet(body: Map<String, Any?>, site: Keys.SuiteKey): Map<String, Any?> =
        Issue.signArtifact(OracleFacts.OFFER_SET_DOMAIN, body, site)

    // ---- linked policy templates (policy-link.ts signTemplate / signTighten) ---------------------------------------------------

    private const val TEMPLATE_SIG_DOMAIN = "atlas-pca/policy-template/v1\u0000"
    private const val TIGHTEN_SIG_DOMAIN = "atlas-pca/template-tighten/v1\u0000"

    private fun digestMessage(domain: String, digest: String): ByteArray = Pca.concat(utf8(domain), Pca.sha(utf8(digest)))

    /** The principal's signed policy template `{def, signer, sig}`. */
    fun signTemplate(def: Map<String, Any?>, principal: Keys.EdKey): Map<String, Any?> {
        val e = PolicyAuthoring.templateDefError(def)
        if (e != null) throw IllegalArgumentException("signTemplate: $e")
        return Issue.obj("def" to def, "signer" to principal.id(),
            "sig" to Pca.b64(principal.sign(digestMessage(TEMPLATE_SIG_DOMAIN, PolicyAuthoring.templateDigest(def)))))
    }

    /** The principal's signed tighten overlay `{overlay, signer, sig}` (it can only add where conditions and caveats). */
    fun signTighten(overlay: Map<String, Any?>, principal: Keys.EdKey): Map<String, Any?> {
        val e = PolicyAuthoring.tightenOverlayError(overlay)
        if (e != null) throw IllegalArgumentException("signTighten: $e")
        return Issue.obj("overlay" to overlay, "signer" to principal.id(),
            "sig" to Pca.b64(principal.sign(digestMessage(TIGHTEN_SIG_DOMAIN, Pca.hashCanonical(overlay)))))
    }

    // ---- revocation epoch (revocation.ts signRevocationEpoch, guardian side) ---------------------------------------------------

    private val EPOCH_FIELDS = listOf("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after")

    /**
     * The guardian's signed revocation epoch over `{instance_id, grant_ref, epoch, set_size, root, issued_at, not_after}`; a
     * non-ed25519 suite binds `alg` and `pq_pk` into the signed bytes.
     */
    fun signRevocationEpoch(guardian: Keys.SuiteKey, body: Map<String, Any?>): Map<String, Any?> {
        val ed = edOf(guardian, "signRevocationEpoch")
        val fields = LinkedHashMap<String, Any?>()
        for (k in EPOCH_FIELDS) {
            if (!body.containsKey(k)) throw IllegalArgumentException("signRevocationEpoch: $k required")
            fields[k] = body[k]
        }
        val bound = LinkedHashMap(fields)
        if (guardian.alg != "ed25519") {
            bound["alg"] = guardian.alg
            bound["pq_pk"] = guardian.pqPk()
        }
        val sg = guardian.sign(Pca.concat(utf8(IntentRevocation.REVEPOCH_DOMAIN), Pca.canonBytes(bound)))
        val out: MutableMap<String, Any?> = Issue.norm(fields)
        out["guardian"] = ed.id()
        out["sig"] = sg.first
        if (guardian.alg != "ed25519") {
            out["alg"] = guardian.alg
            out["pq_pk"] = guardian.pqPk()
            if (sg.second != null) out["pq_sig"] = sg.second
        }
        return out
    }

    // ---- constitution (prohibitions.ts signConstitution) ----------------------------------------------------------------------

    /** The principal signs a constitution: `{...body, id, sig}`. Refuses a malformed one (every problem, joined with "; "). */
    fun signConstitution(c: Map<String, Any?>, principal: Keys.EdKey): Map<String, Any?> {
        val problems = Prohibitions.validateConstitution(c)
        if (problems.isNotEmpty()) throw IllegalArgumentException("signConstitution: " + problems.joinToString("; "))
        val id = Prohibitions.constitutionId(c)
        val out = Prohibitions.body(c)
        out["id"] = id
        out["sig"] = Pca.b64(principal.sign(Prohibitions.domainMessage(Prohibitions.CONSTITUTION_SIG_DOMAIN, id)))
        return out
    }
}
