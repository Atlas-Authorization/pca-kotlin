package net.atlasauth.pca.verifier

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import org.bouncycastle.math.ec.rfc8032.Ed25519

/**
 * Native Kotlin reference verifier for the CORE PCActn checks, wire format v2. Byte-matches `@atlasauth/pca`
 * (the TypeScript source of truth) and the sibling language verifiers (java-pca, go-pca, python-pca, ...).
 *
 * Normative check order: `wire, version, audience, validity, chain, plan_inclusion, leaf_signature, counter`
 * (a wire failure is terminal). Requires BouncyCastle (`org.bouncycastle.math.ec.rfc8032.Ed25519`), which the
 * module already depends on for the step-up client.
 *
 * This is a faithful Kotlin port of `sdks/java-pca/.../Pca.java` + the audience fail-closed semantics in
 * `packages/pca/src/pcactn.ts` (`verifyPCActnCore`).
 */
object Pca {
    const val WIRE_VERSION = 2L
    const val MAX_CHAIN_HOPS = 16
    const val MAX_LIFETIME_MS = 3_600_000L
    const val MAX_SKEW_MS = 60_000L
    const val MAX_AUD_LEN = 256
    const val MAX_NONCE_LEN = 128

    val SIG_DOMAIN: ByteArray = "atlas-pca/actn/v2\u0000".toByteArray(StandardCharsets.UTF_8)
    val CAP_DOMAIN: ByteArray = "atlas-pca/cap/v1\u0000".toByteArray(StandardCharsets.UTF_8)
    const val DEFAULT_REV = "reversible"

    /**
     * The verifier's own audience, compared to the PCActn's signed `aud` (mirrors `verifyPCActnCore`'s
     * tri-state `audience` option):
     *  - [Of]    => must equal `aud`, else the `audience` check fails;
     *  - [Any]   => deliberate opt-out ("I accept any audience"): the binding is not enforced (never fails);
     *  - [Unset] => FAIL-CLOSED when the PCActn carries a signed `aud` (a verifier that forgets its audience
     *               must not silently lose cross-instance binding); passes only when there is no `aud` at all.
     */
    sealed class Audience {
        data class Of(val id: String) : Audience()
        object Any : Audience()
        object Unset : Audience()
    }

    /** `checks` holds, in normative order, wire alone (wire failure) or all eight checks. */
    class Verdict {
        var allow = false
        val checks = LinkedHashMap<String, Boolean>()
        var reason = ""
        internal fun fail(name: String, why: String) {
            checks[name] = false
            if (reason.isEmpty()) reason = "$name: $why"
        }
    }

    // ---- helpers ----
    private val B64U_ENC = Base64.getUrlEncoder().withoutPadding()
    private val B64U_DEC = Base64.getUrlDecoder()

    fun b64(b: ByteArray): String = B64U_ENC.encodeToString(b)

    /**
     * Strict base64url (RFC 4648 s5): alphabet A-Za-z0-9-_ only, no padding / whitespace, len % 4 != 1, zero
     * trailing bits (re-encode must reproduce the input). `len` >= 0 additionally pins the decoded byte length.
     * Returns null when invalid.
     */
    fun decodeB64uStrict(o: Any?, len: Int): ByteArray? {
        if (o !is String) return null
        for (c in o) {
            val ok = (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '-' || c == '_'
            if (!ok) return null
        }
        if (o.length % 4 == 1) return null
        if (len >= 0 && o.length != (len * 4 + 2) / 3) return null
        val b: ByteArray = try {
            B64U_DEC.decode(o)
        } catch (e: IllegalArgumentException) {
            return null
        }
        if (b64(b) != o) return null // non-canonical trailing bits
        if (len >= 0 && b.size != len) return null
        return b
    }

    fun sha(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        var n = 0
        for (p in parts) n += p.size
        val out = ByteArray(n)
        var o = 0
        for (p in parts) { System.arraycopy(p, 0, out, o, p.size); o += p.size }
        return out
    }

    @Suppress("UNCHECKED_CAST")
    fun asMap(o: Any?): Map<String, Any?> = if (o is Map<*, *>) o as Map<String, Any?> else LinkedHashMap()

    @Suppress("UNCHECKED_CAST")
    fun asList(o: Any?): List<Any?> = if (o is List<*>) o as List<Any?> else ArrayList()

    fun asStr(o: Any?): String = if (o is String) o else ""

    fun canonBytes(v: Any?): ByteArray = Json.canonicalize(v).toByteArray(StandardCharsets.UTF_8)

    fun hashCanonical(v: Any?): String = b64(sha(canonBytes(v)))

    /** base64url(sha256(strictCanonical(v))). */
    fun hashStrict(v: Any?): String = b64(sha(Json.canonicalizeStrict(v).toByteArray(StandardCharsets.UTF_8)))

    // ---- Merkle ----
    private fun leafHash(leaf: Any?): ByteArray = sha(byteArrayOf(0x00), canonBytes(leaf))

    private fun nodeHash(l: ByteArray, r: ByteArray): ByteArray = sha(byteArrayOf(0x01), l, r)

    fun merkleRoot(leaves: List<Any?>): String {
        if (leaves.isEmpty()) throw IllegalArgumentException("empty leaf set")
        val hs = ArrayList<ByteArray>()
        for (l in leaves) hs.add(leafHash(l))
        return b64(build(hs))
    }

    private fun build(hs: List<ByteArray>): ByteArray {
        if (hs.size == 1) return hs[0]
        var k = 1
        while (k * 2 < hs.size) k *= 2
        return nodeHash(build(hs.subList(0, k)), build(hs.subList(k, hs.size)))
    }

    /** Sibling sides (leaf to root) for leaf `index` of `size` leaves (RFC 6962 split). Requires 0 <= index < size. */
    private fun pathShape(index: Long, size: Long): List<String> {
        val out = ArrayList<String>()
        var idx = index
        var n = size
        while (n > 1) {
            var k = 1L
            while (k * 2 < n) k *= 2
            if (idx < k) { out.add("R"); n = k }
            else { out.add("L"); idx -= k; n -= k }
        }
        out.reverse()
        return out
    }

    /** Never throws; malformed proofs return false. index/size are bound to the path shape. */
    fun verifyInclusion(root: String, proof: Map<String, Any?>?, leaf: Any?): Boolean {
        return try {
            if (proof == null || proof["path"] !is List<*>) return false
            if (!Json.isSafeInt(proof["index"]) || !Json.isSafeInt(proof["size"])) return false
            val index = Json.asLong(proof["index"])
            val size = Json.asLong(proof["size"])
            if (size < 1 || index < 0 || index >= size) return false
            val shape = pathShape(index, size)
            val path = asList(proof["path"])
            if (shape.size != path.size) return false
            var h = leafHash(leaf)
            for (i in path.indices) {
                if (path[i] !is Map<*, *>) return false
                val step = asMap(path[i])
                if (shape[i] != step["side"]) return false
                val sib = decodeB64uStrict(step["hash"], 32) ?: return false
                h = if (shape[i] == "L") nodeHash(sib, h) else nodeHash(h, sib)
            }
            b64(h) == root
        } catch (e: RuntimeException) {
            false
        }
    }

    fun paramsDigest(params: Any?): String =
        hashCanonical(params ?: LinkedHashMap<String, Any?>())

    private fun conditionsDigest(pre: Any?, post: Any?): String {
        val m = LinkedHashMap<String, Any?>()
        m["pre"] = pre
        m["post"] = post
        return hashCanonical(m)
    }

    private fun planLeaf(nodeId: Any?, action: Map<String, Any?>, cond: String): Map<String, Any?> {
        if (nodeId == null) throw IllegalArgumentException("missing node_id")
        val pd = action["params_digest"] ?: paramsDigest(null)
        val rc = action["reversibility_class"] ?: DEFAULT_REV
        val m = LinkedHashMap<String, Any?>()
        m["node_id"] = nodeId
        m["verb"] = action["verb"]
        m["resource"] = action["resource"]
        m["params_digest"] = pd
        m["reversibility_class"] = rc
        m["conditions"] = cond
        return m
    }

    // ---- Ed25519 (strict RFC 8032) ----
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val L: BigInteger =
        BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))

    /** y-coordinates of every small-order point: identity (1), order 2 (p-1), order 4 (0), order 8 (two values). */
    private val SMALL_ORDER_Y = arrayOf(
        BigInteger.ONE,
        P.subtract(BigInteger.ONE),
        BigInteger.ZERO,
        BigInteger("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16),
        BigInteger("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826", 16),
    )

    private fun leInt(b: ByteArray, off: Int, len: Int, clearTopBit: Boolean): BigInteger {
        val be = ByteArray(len)
        for (i in 0 until len) be[len - 1 - i] = b[off + i]
        if (clearTopBit) be[0] = (be[0].toInt() and 0x7f).toByte()
        return BigInteger(1, be)
    }

    /** True iff the 32-byte point encoding has a non-canonical y (>= p) or is one of the small-order points. */
    private fun badPointEncoding(b: ByteArray, off: Int): Boolean {
        val y = leInt(b, off, 32, true) // sign bit ignored: both x signs share the same y
        if (y.compareTo(P) >= 0) return true
        for (s in SMALL_ORDER_Y) if (y == s) return true
        return false
    }

    /**
     * Strict Ed25519 verify: rejects non-canonical S (>= L), non-canonical y, small-order and mixed-order
     * public keys AND R (explicit small-order table + BouncyCastle full subgroup validation), then verifies.
     */
    fun ed25519Strict(pk: ByteArray?, msg: ByteArray, sig: ByteArray?): Boolean {
        return try {
            if (pk == null || sig == null || pk.size != 32 || sig.size != 64) return false
            if (badPointEncoding(pk, 0) || badPointEncoding(sig, 0)) return false
            if (leInt(sig, 32, 32, false).compareTo(L) >= 0) return false
            if (!Ed25519.validatePublicKeyFull(pk, 0)) return false
            if (!Ed25519.validatePublicKeyFull(sig, 0)) return false
            Ed25519.verify(sig, 0, pk, 0, msg, 0, msg.size)
        } catch (e: RuntimeException) {
            false
        }
    }

    fun verifyB64u(pub: String?, msg: ByteArray, sig: String?): Boolean {
        val pk = decodeB64uStrict(pub, 32)
        val sg = decodeB64uStrict(sig, 64)
        if (pk == null || sg == null) return false
        return ed25519Strict(pk, msg, sg)
    }

    // ---- capability chain ----
    fun capHash(c: Map<String, Any?>): String = hashCanonical(c)

    private fun bodyOf(c: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["issuer"] = c["issuer"]
        m["holder"] = c["holder"]
        m["caveats"] = c["caveats"]
        m["parent"] = c["parent"]
        return m
    }

    /**
     * [bodyOf] + the suite fields (`alg`, `pq_pk`) bound in for a non-default suite (so a downgrade or ML-DSA
     * key-swap breaks the hop digest), byte-identical to [bodyOf] for ed25519. Mirrors `signableBody` in
     * capability.ts. Returns null for an unknown alg (FAIL-CLOSED).
     */
    private fun signableHopBody(c: Map<String, Any?>): Map<String, Any?>? {
        val suite = Pq.resolveSigAlg(c["alg"], c.containsKey("alg")) ?: return null
        val body = LinkedHashMap(bodyOf(c))
        if (suite.alg != "ed25519") {
            body["alg"] = suite.alg
            if (suite.needsPqPk && c["pq_pk"] is String) body["pq_pk"] = c["pq_pk"]
        }
        return body
    }

    /** Returns "" when OK, else an error label. Suite-agile: an unknown hop alg fails closed before any hashing. */
    private fun checkSig(c: Map<String, Any?>, signer: String, label: String): String {
        val body = signableHopBody(c) ?: return "$label: unknown signature alg '${c["alg"]}'"
        val digest = try {
            hashCanonical(body)
        } catch (e: RuntimeException) {
            return "$label: malformed body"
        }
        val bd = asStr(c["body_digest"])
        val id = asStr(c["id"])
        if (digest != bd || id != bd) return "$label: body digest mismatch"
        val raw = decodeB64uStrict(bd, 32) ?: return "$label: bad signature (not signed by expected key)"
        // Suite-agile hop verification (mirrors verifyLeafSuite): ed25519 == verifyB64u(signer, msg, sig);
        // hybrid requires BOTH the Ed25519 `sig` (under `signer`) AND the ML-DSA `pq_sig` (under `pq_pk`);
        // pure ml-dsa-65 verifies `sig` under `pq_pk`. The signer is the expected Ed25519 key.
        val ok = Pq.verifyLeafSuite(c["alg"], c.containsKey("alg"), signer, c["pq_pk"], concat(CAP_DOMAIN, raw), c["sig"], c["pq_sig"])
        if (!ok) return "$label: bad signature (not signed by expected key)"
        return ""
    }

    /** Returns "" when valid, else the failure reason. The 16-hop cap is enforced BEFORE any signature work. */
    fun verifyChain(chain: List<Any?>, expectedRootIssuer: String, haveIssuer: Boolean): String {
        if (chain.isEmpty()) return "empty chain"
        if (chain.size > MAX_CHAIN_HOPS) return "chain too long (max $MAX_CHAIN_HOPS hops)"
        for (i in chain.indices)
            if (chain[i] !is Map<*, *>) return "hop $i: malformed capability"
        val root = asMap(chain[0])
        if (root.containsKey("parent")) return "hop 0: root must not have a parent"
        if (haveIssuer && root["issuer"] != expectedRootIssuer)
            return "hop 0: root issuer is not the expected principal"
        var e = checkSig(root, asStr(root["issuer"]), "hop 0")
        if (e.isNotEmpty()) return e
        for (i in 1 until chain.size) {
            val label = "hop $i"
            val parent = asMap(chain[i - 1])
            val c = asMap(chain[i])
            val ph = try {
                capHash(parent)
            } catch (ex: RuntimeException) {
                return "$label: broken parent link"
            }
            if (c["parent"] != ph) return "$label: broken parent link"
            if (c["issuer"] != parent["holder"]) return "$label: issuer is not the parent's bound holder"
            e = checkSig(c, asStr(parent["holder"]), label)
            if (e.isNotEmpty()) return e
            val pc = asList(parent["caveats"])
            val cc = asList(c["caveats"])
            if (cc.size < pc.size) return "$label: drops parent caveat(s)"
            for (j in pc.indices) {
                val same = try {
                    hashCanonical(cc[j]) == hashCanonical(pc[j])
                } catch (ex: RuntimeException) {
                    false
                }
                if (!same) return "$label: caveat $j altered or reordered"
            }
        }
        return ""
    }

    // ---- wire format v2 ----
    private val REQUIRED = listOf(
        "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness",
        "counter", "risk_claim", "aud", "iat", "exp", "sig",
    )
    private val OPTIONAL = listOf(
        "nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding",
        "threshold", "zk_compliance", "bond_ref",
        // B4 crypto-agility (additive): absent `alg` == "ed25519" and validates exactly as today.
        "alg", "pq_pk", "pq_sig",
    )

    /** Length unit for aud / nonce limits is UTF-8 BYTES. */
    private fun utf8Len(s: String): Int = s.toByteArray(StandardCharsets.UTF_8).size

    /**
     * Closed capability-hop key set (parent optional). The B4 crypto-agility fields (alg/pq_pk/pq_sig) are
     * additive on a hop exactly as at the top level: absent alg == ed25519 (pq_pk/pq_sig forbidden, byte-identical).
     */
    private val CAP_KEYS = listOf("id", "issuer", "holder", "body_digest", "caveats", "sig", "parent", "alg", "pq_pk", "pq_sig")

    private fun isObj(o: Any?): Boolean = o is Map<*, *>
    private fun isStr(o: Any?): Boolean = o is String

    private fun closedKeys(m: Map<String, Any?>, where: String, vararg allowed: String): String? {
        val ok = allowed.toList()
        for (k in m.keys) if (!ok.contains(k)) return "unknown field '$where.$k'"
        return null
    }

    /** Wire v2 structural + lexical validation. Returns null when well-formed, else a short reason. Never throws. */
    @Suppress("UNCHECKED_CAST")
    fun validateWireV2(po: Any?): String? {
        return try {
            if (!isObj(po)) return "PCActn is not an object"
            val p = po as Map<String, Any?>
            for (k in p.keys) if (!REQUIRED.contains(k) && !OPTIONAL.contains(k)) return "unknown field '$k'"
            for (k in REQUIRED) if (!p.containsKey(k)) return "missing field '$k'"
            // every signed byte must admit the strict canonical encoding (sig/threshold/pq_sig are unsigned)
            val body = LinkedHashMap(p)
            body.remove("sig")
            body.remove("threshold")
            body.remove("pq_sig")
            try {
                Json.canonicalizeStrict(body)
            } catch (e: RuntimeException) {
                return e.message
            }

            if (!Json.isSafeInt(p["ver"])) return "'ver' must be a safe integer"
            if (!Json.isSafeInt(p["counter"])) return "'counter' must be a safe integer"
            if (!Json.isSafeInt(p["iat"])) return "'iat' must be a safe integer"
            if (!Json.isSafeInt(p["exp"])) return "'exp' must be a safe integer"
            val aud = p["aud"]
            if (!isStr(aud) || (aud as String).isEmpty() || utf8Len(aud) > MAX_AUD_LEN) return "'aud' must be a non-empty string"
            if (p.containsKey("nonce")) {
                val n = p["nonce"]
                if (!isStr(n) || (n as String).isEmpty() || utf8Len(n) > MAX_NONCE_LEN) return "'nonce' must be a non-empty string"
            }
            // B4 crypto-agility: validate `alg`/`sig`/`pq_pk`/`pq_sig` per suite. With no `alg` this asserts exactly
            // the classical 64-byte `sig` and that `pq_pk`/`pq_sig` are absent. Unknown `alg` fails closed.
            val sigWire = Pq.validateSignatureWire(p)
            if (sigWire != null) return sigWire
            if (decodeB64uStrict(p["grant_ref"], 32) == null) return "'grant_ref' is not canonical base64url (32 bytes)"

            if (!isObj(p["action"])) return "'action' must be an object"
            val a = p["action"] as Map<String, Any?>
            var e = closedKeys(a, "action", "verb", "resource", "params_digest", "reversibility_class")
            if (e != null) return e
            if (!isStr(a["verb"]) || !isStr(a["resource"]) || !isStr(a["reversibility_class"]))
                return "action.verb/resource/reversibility_class must be strings"
            if (decodeB64uStrict(a["params_digest"], 32) == null) return "'action.params_digest' is not canonical base64url (32 bytes)"

            if (!isObj(p["plan"])) return "'plan' must be an object"
            val pl = p["plan"] as Map<String, Any?>
            e = closedKeys(pl, "plan", "root", "inclusion_proof", "node_id", "conditions_digest")
            if (e != null) return e
            if (decodeB64uStrict(pl["root"], 32) == null) return "'plan.root' is not canonical base64url (32 bytes)"
            if (!isStr(pl["node_id"])) return "'plan.node_id' must be a string"
            if (pl.containsKey("conditions_digest") && decodeB64uStrict(pl["conditions_digest"], 32) == null)
                return "'plan.conditions_digest' must be a canonical base64url string (32 bytes)"
            if (!isObj(pl["inclusion_proof"])) return "'plan.inclusion_proof' must be an object"
            val ip = pl["inclusion_proof"] as Map<String, Any?>
            e = closedKeys(ip, "plan.inclusion_proof", "index", "size", "path")
            if (e != null) return e
            if (!Json.isSafeInt(ip["index"])) return "'plan.inclusion_proof.index' must be a safe integer"
            if (!Json.isSafeInt(ip["size"])) return "'plan.inclusion_proof.size' must be a safe integer"
            if (ip["path"] !is List<*>) return "'plan.inclusion_proof.path' must be an array"
            val path = ip["path"] as List<Any?>
            for (i in path.indices) {
                if (!isObj(path[i])) return "proof step $i must be an object"
                val st = path[i] as Map<String, Any?>
                for (k in st.keys) if (k != "side" && k != "hash") return "unknown field 'path[$i].$k'"
                if ("L" != st["side"] && "R" != st["side"]) return "proof step $i: side must be 'L' or 'R'"
                if (decodeB64uStrict(st["hash"], 32) == null) return "proof step $i: hash is not canonical base64url (32 bytes)"
            }

            if (p["cap_chain"] !is List<*>) return "'cap_chain' must be an array"
            val chain = p["cap_chain"] as List<Any?>
            for (i in chain.indices) {
                if (!isObj(chain[i])) return "cap_chain[$i] must be an object"
                val c = chain[i] as Map<String, Any?>
                for (k in c.keys)
                    if (!CAP_KEYS.contains(k)) return "unknown field 'cap_chain[$i].$k'"
                for (k in arrayOf("id", "issuer", "holder", "body_digest"))
                    if (decodeB64uStrict(c[k], 32) == null) return "cap_chain[$i].$k is not canonical base64url (32 bytes)"
                // B4 crypto-agility: validate the hop's alg/sig/pq_pk/pq_sig per suite, exactly as the leaf.
                // Absent alg asserts a 64-byte sig and that pq_pk/pq_sig are absent (byte-identical pre-B4 hop).
                val hopSigWire = Pq.validateSignatureWire(c)
                if (hopSigWire != null) return "cap_chain[$i]: $hopSigWire"
                if (c.containsKey("parent") && decodeB64uStrict(c["parent"], 32) == null)
                    return "cap_chain[$i].parent is not canonical base64url (32 bytes)"
                if (c["caveats"] !is List<*>) return "cap_chain[$i].caveats must be an array of {type,...} objects"
                for (cv in c["caveats"] as List<Any?>)
                    if (!isObj(cv) || !isStr((cv as Map<String, Any?>)["type"]))
                        return "cap_chain[$i].caveats must be an array of {type,...} objects"
            }

            if (!isObj(p["attestation"])) return "'attestation' must be an object with an integer 'epoch'"
            val at = p["attestation"] as Map<String, Any?>
            if (!Json.isSafeInt(at["epoch"])) return "'attestation' must be an object with an integer 'epoch'"
            if (!isStr(at["quote_digest"]) || !isStr(at["model_id"]) || !isStr(at["measurement"]) || !isStr(at["operator"]))
                return "attestation string fields must be strings"
            if (!isObj(p["provenance"])) return "'provenance' is malformed"
            val pv = p["provenance"] as Map<String, Any?>
            if (!isStr(pv["causal_hash"]) || !Json.isStrictNumber(pv["taint_level"]) || pv["trusted_refs"] !is List<*>)
                return "'provenance' is malformed"
            for (r in pv["trusted_refs"] as List<Any?>) if (!isStr(r)) return "'provenance' is malformed"
            if (!isObj(p["freshness"])) return "'freshness' is malformed"
            val fr = p["freshness"] as Map<String, Any?>
            if (!Json.isSafeInt(fr["epoch"]) || !isStr(fr["beacon_ref"]) || !isStr(fr["accumulator_witness"])) return "'freshness' is malformed"
            if (!isObj(p["risk_claim"])) return "'risk_claim' is malformed"
            val rc = p["risk_claim"] as Map<String, Any?>
            if (!Json.isStrictNumber(rc["r"]) || !isObj(rc["inputs"])) return "'risk_claim' is malformed"

            if (p.containsKey("caution")) {
                val c = p["caution"]
                if (!Json.isStrictNumber(c)) return "'caution' must be a number in [0,1]"
                val d = Json.asDecimal(c)
                if (d.signum() < 0 || d.compareTo(java.math.BigDecimal.ONE) > 0) return "'caution' must be a number in [0,1]"
            }
            if (p.containsKey("rationale_commitment") && decodeB64uStrict(p["rationale_commitment"], 32) == null)
                return "'rationale_commitment' is not canonical base64url (32 bytes)"
            if (p.containsKey("tool_binding") && decodeB64uStrict(p["tool_binding"], 32) == null)
                return "'tool_binding' is not canonical base64url (32 bytes)"
            if (p.containsKey("progress_step") && !isObj(p["progress_step"])) return "'progress_step' must be an object"
            if (p.containsKey("prohibition_evidence") && !isObj(p["prohibition_evidence"]) && p["prohibition_evidence"] !is List<*>)
                return "'prohibition_evidence' must be an object or array"
            if (p.containsKey("threshold")) {
                if (!isObj(p["threshold"]) || (p["threshold"] as Map<String, Any?>)["shares"] !is List<*>)
                    return "'threshold' must be {shares:[...]}"
                val shares = (p["threshold"] as Map<String, Any?>)["shares"] as List<Any?>
                for (i in shares.indices) {
                    if (!isObj(shares[i]) || !isStr((shares[i] as Map<String, Any?>)["role"])) return "threshold.shares[$i] is malformed"
                    val sh = shares[i] as Map<String, Any?>
                    if (decodeB64uStrict(sh["publicKey"], 32) == null) return "threshold.shares[$i].publicKey is not canonical base64url (32 bytes)"
                    if (decodeB64uStrict(sh["sig"], 64) == null) return "threshold.shares[$i].sig is not canonical base64url (64 bytes)"
                }
            }
            null
        } catch (e: RuntimeException) {
            "malformed: $e"
        }
    }

    // ---- PCActn ----
    /** Signed message: "atlas-pca/actn/v2\0" || sha256(strictCanonical(body without sig/threshold/pq_sig)). */
    fun thresholdMessage(p: Map<String, Any?>): ByteArray {
        val body = LinkedHashMap<String, Any?>()
        // `sig`, `threshold` and the B4 `pq_sig` are unsigned (stripped); `alg`/`pq_pk` ARE signed.
        for ((k, v) in p) if (k != "sig" && k != "threshold" && k != "pq_sig") body[k] = v
        return concat(SIG_DOMAIN, sha(Json.canonicalizeStrict(body).toByteArray(StandardCharsets.UTF_8)))
    }

    /** Verify raw PCActn JSON text: strict-profile parse first (any failure, or a non-object, is a wire failure). */
    fun verifyPcactnJson(text: String, grant: Map<String, Any?>, now: Long, audience: Audience): Verdict {
        val parsed: Any?
        try {
            parsed = Json.parse(text)
        } catch (e: RuntimeException) {
            val v = Verdict()
            v.fail("wire", "strict JSON: ${e.message}")
            return v
        }
        return verifyPcactn(parsed, grant, now, audience)
    }

    /**
     * Verify a parsed PCActn (Json.parse / parseLenient tree). Check order: wire (terminal), version, audience,
     * validity, chain, grant_ref_bound, plan_inclusion, leaf_signature, counter. allow = every check true.
     */
    fun verifyPcactn(pcactn: Any?, grant: Map<String, Any?>, now: Long, audience: Audience): Verdict {
        val v = Verdict()
        val wire = validateWireV2(pcactn)
        if (wire != null) {
            v.fail("wire", wire)
            return v
        }
        val p = asMap(pcactn)
        v.checks["wire"] = true
        try {
            // version
            if (Json.asLong(p["ver"]) == WIRE_VERSION) v.checks["version"] = true
            else v.fail("version", "unsupported ver (this verifier requires $WIRE_VERSION)")

            // audience (fail-closed: a signed aud with no supplied audience is a failure, not a pass)
            val hasAud = p["aud"] is String && (p["aud"] as String).isNotEmpty()
            when (audience) {
                is Audience.Any -> v.checks["audience"] = true // opt-out: binding not enforced
                is Audience.Unset -> if (hasAud) v.fail("audience", "PCActn carries a signed aud but this verifier supplied no audience") else v.checks["audience"] = true
                is Audience.Of -> if (audience.id == p["aud"]) v.checks["audience"] = true else v.fail("audience", "aud does not match this resource server / instance")
            }

            // validity
            val iat = Json.asLong(p["iat"])
            val exp = Json.asLong(p["exp"])
            if (!(exp > iat)) v.fail("validity", "exp must be greater than iat")
            else if (exp - iat > MAX_LIFETIME_MS) v.fail("validity", "lifetime exceeds $MAX_LIFETIME_MS ms")
            else if (iat > now + MAX_SKEW_MS) v.fail("validity", "iat is in the future (clock skew)")
            else if (now > exp) v.fail("validity", "the PCActn has expired")
            else v.checks["validity"] = true

            // chain (<= 16 hops, checked before any signature work; root == grant)
            val chain = asList(p["cap_chain"])
            val why: String = when {
                chain.isEmpty() -> "empty chain"
                chain.size > MAX_CHAIN_HOPS -> "chain too long (max $MAX_CHAIN_HOPS hops)"
                capHash(asMap(chain[0])) != capHash(grant) -> "chain root is not the grant"
                else -> verifyChain(chain, asStr(grant["issuer"]), grant["issuer"] is String)
            }
            if (why.isEmpty()) v.checks["chain"] = true else v.fail("chain", why)

            // grant_ref_bound (normative): the signed grant_ref MUST be a non-empty string byte-equal to the id of the
            // ROOT capability of the presented chain (cap_chain[0].id). Independent of the chain verdict; fail-closed
            // on an empty / malformed chain. Replay state is keyed on grant_ref, so it must not be attacker-chosen.
            val gref = p["grant_ref"]
            val rootId = (chain.firstOrNull() as? Map<*, *>)?.get("id")
            if (gref is String && gref.isNotEmpty() && rootId is String && gref == rootId) v.checks["grant_ref_bound"] = true
            else v.fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain")

            // plan inclusion (leaf recomputed from the action itself)
            val plan = asMap(p["plan"])
            val action = asMap(p["action"])
            val cond = if (plan["conditions_digest"] is String) plan["conditions_digest"] as String else conditionsDigest(null, null)
            val incl = try {
                verifyInclusion(asStr(plan["root"]), asMap(plan["inclusion_proof"]), planLeaf(plan["node_id"], action, cond))
            } catch (e: RuntimeException) {
                false
            }
            if (incl) v.checks["plan_inclusion"] = true
            else v.fail("plan_inclusion", "action is not a node of the committed plan")

            // leaf signature — routed through the B4 suite seam (ed25519 / ml-dsa-65 / hybrid). For the default
            // (no `alg`) this is byte-identical to the classical strict-Ed25519 path under the leaf holder.
            var sigOk = false
            if (chain.isNotEmpty()) {
                val holder = asStr(asMap(chain[chain.size - 1])["holder"])
                sigOk = Pq.verifyLeafSuite(
                    p["alg"], p.containsKey("alg"), holder, p["pq_pk"],
                    thresholdMessage(p), p["sig"], p["pq_sig"],
                )
            }
            if (sigOk) v.checks["leaf_signature"] = true
            else v.fail("leaf_signature", "signature does not verify under the leaf holder key")

            // counter
            if (Json.isSafeInt(p["counter"]) && Json.asLong(p["counter"]) >= 0) v.checks["counter"] = true
            else v.fail("counter", "missing or not a non-negative safe integer")
        } catch (e: RuntimeException) {
            if (v.reason.isEmpty()) v.reason = "malformed PCActn: $e"
        }
        // any check not reached (internal error) is a failure; keep normative key order
        val ordered = LinkedHashMap<String, Boolean>()
        for (k in arrayOf("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter"))
            ordered[k] = v.checks[k] == true
        v.checks.clear()
        v.checks.putAll(ordered)
        v.allow = !v.checks.containsValue(false)
        return v
    }
}
