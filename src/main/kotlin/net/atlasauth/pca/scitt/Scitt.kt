package net.atlasauth.pca.scitt

import java.math.BigDecimal
import java.math.BigInteger
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.util.BigIntegers

/** A Transparency Service or issuer PRIVATE key: an Ed25519 seed or a P-256 scalar. */
sealed class ScittPrivateKey {
    class Ed25519(val seed: ByteArray) : ScittPrivateKey()
    class P256(val d: ByteArray) : ScittPrivateKey()
}

/** A PUBLIC key: a raw Ed25519 key or P-256 affine coordinates. A key of the wrong type or off the curve never verifies. */
sealed class ScittPublicKey {
    class Ed25519(val raw: ByteArray) : ScittPublicKey()
    class P256(val x: ByteArray, val y: ByteArray) : ScittPublicKey()
}

/**
 * SCITT transparency receipts for Proof-Carrying Authority (RFC 9943 SCITT architecture + RFC 9942 COSE Receipts). A verified PCActn is
 * registered as a COSE Signed Statement (a COSE_Sign1 over the canonical PCActn), appended to an append-only RFC 9162 Merkle log, and
 * handed back a COSE Receipt: a COSE_Sign1 signed by the Transparency Service carrying an inclusion proof against the log root.
 * The same bytes for the same inputs as the TypeScript reference (Ed25519 and the ES256 low-S normalisation).
 *
 * An inclusion proof is the JSON-shaped map `{index, size, path: [{side: "L"|"R", hash: b64u}]}` used by the core ledger.
 */
object Scitt {
    const val COSE_SIGN1_TAG = 18
    const val HDR_ALG = 1
    const val HDR_CONTENT_TYPE = 3
    const val HDR_CWT_CLAIMS = 15
    const val CWT_ISS = 1
    const val CWT_SUB = 2
    const val HDR_VDS = 395
    const val HDR_VDS_PROOFS = 396
    const val VDS_RFC9162_SHA256 = 1
    const val PROOF_TYPE_INCLUSION = -1
    const val DEFAULT_CONTENT_TYPE = "application/pca+json"

    enum class CoseAlg(internal val label: Long) { EdDSA(-8), ES256(-7) }

    private fun err(m: String) = IllegalArgumentException(m)

    private fun algForLabel(label: Long): CoseAlg? = when (label) {
        -8L -> CoseAlg.EdDSA
        -7L -> CoseAlg.ES256
        else -> null
    }

    // ---- keys ----

    /** The Ed25519 private key for a 32-byte seed. */
    @JvmStatic
    fun ed25519PrivateKey(seed: ByteArray?): ScittPrivateKey {
        if (seed == null || seed.size != 32) throw err("an Ed25519 seed is 32 bytes")
        return ScittPrivateKey.Ed25519(seed.clone())
    }

    /** The Ed25519 public key for a 32-byte raw key. */
    @JvmStatic
    fun ed25519PublicKey(raw: ByteArray?): ScittPublicKey {
        if (raw == null || raw.size != 32) throw err("an Ed25519 public key is 32 bytes")
        return ScittPublicKey.Ed25519(raw.clone())
    }

    /** The P-256 public key for affine coordinates (32-byte big-endian x and y). */
    @JvmStatic
    fun es256PublicKey(x: ByteArray, y: ByteArray): ScittPublicKey = ScittPublicKey.P256(x.clone(), y.clone())

    /** The P-256 private key for a 32-byte big-endian scalar. */
    @JvmStatic
    fun es256PrivateKey(d: ByteArray): ScittPrivateKey = ScittPrivateKey.P256(d.clone())

    // ---- signature suites: EdDSA (Ed25519) and ES256 (ECDSA P-256, IEEE-P1363 raw, low-S) ----

    private val P256_N = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    private val P256_HALF_N = P256_N.shiftRight(1)

    private val domain: ECDomainParameters by lazy {
        val x9 = CustomNamedCurves.getByName("secp256r1")
        ECDomainParameters(x9.curve, x9.g, x9.n, x9.h)
    }

    private fun sha256(b: ByteArray): ByteArray {
        val d = SHA256Digest()
        d.update(b, 0, b.size)
        return ByteArray(32).also { d.doFinal(it, 0) }
    }

    private fun isCanonicalEs256(sig: ByteArray): Boolean {
        if (sig.size != 64) return false
        val r = BigInteger(1, sig.copyOfRange(0, 32))
        val s = BigInteger(1, sig.copyOfRange(32, 64))
        return r.signum() > 0 && r < P256_N && s.signum() > 0 && s <= P256_HALF_N
    }

    private fun signBytes(alg: CoseAlg, key: ScittPrivateKey, msg: ByteArray): ByteArray {
        if (alg == CoseAlg.EdDSA) {
            if (key !is ScittPrivateKey.Ed25519) throw err("not an Ed25519 key")
            return Keys.edFromSeed(key.seed).sign(msg)
        }
        if (key !is ScittPrivateKey.P256) throw err("not a P-256 key")
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(BigInteger(1, key.d), domain))
        val rs = signer.generateSignature(sha256(msg))
        // Normalise to low-S so a statement has exactly ONE valid signature form.
        val s = if (rs[1] > P256_HALF_N) P256_N.subtract(rs[1]) else rs[1]
        return BigIntegers.asUnsignedByteArray(32, rs[0]) + BigIntegers.asUnsignedByteArray(32, s)
    }

    /** May throw (a key of the wrong type); callers treat that as a failed verification. */
    private fun verifyBytes(alg: CoseAlg, key: ScittPublicKey, msg: ByteArray, sig: ByteArray, allowHighS: Boolean): Boolean {
        if (alg == CoseAlg.EdDSA) {
            if (key !is ScittPublicKey.Ed25519) throw err("not an Ed25519 key")
            return Pca.ed25519Strict(key.raw, msg, sig)
        }
        if (key !is ScittPublicKey.P256) throw err("not a P-256 key")
        // ECDSA is malleable: reject high-S (and out-of-range scalars) before the curve check.
        if (!allowHighS && !isCanonicalEs256(sig)) return false
        if (allowHighS && sig.size != 64) return false
        val q = domain.curve.validatePoint(BigInteger(1, key.x), BigInteger(1, key.y))
        val v = ECDSASigner()
        v.init(false, ECPublicKeyParameters(q, domain))
        return v.verifySignature(sha256(msg), BigInteger(1, sig.copyOfRange(0, 32)), BigInteger(1, sig.copyOfRange(32, 64)))
    }

    /** The COSE_Sign1 Sig_structure to-be-signed bytes (RFC 9052 section 4.4), external_aad empty. */
    private fun sigStructure(protectedBytes: ByteArray, payload: ByteArray): ByteArray =
        Cbor.encode(listOf("Signature1", protectedBytes, ByteArray(0), payload))

    // ---- Signed Statements ----

    class SignStatementOpts(
        @JvmField var alg: CoseAlg,
        /** The issuer's PRIVATE key. */
        @JvmField var key: ScittPrivateKey,
        /** Issuer / feed identifier (CWT iss). */
        @JvmField var issuer: String?,
    ) {
        /** Optional subject (CWT sub). */
        @JvmField var subject: String? = null

        /** Payload content type (defaults to [DEFAULT_CONTENT_TYPE]). */
        @JvmField var contentType: String? = null

        fun subject(s: String?): SignStatementOpts { subject = s; return this }

        fun contentType(c: String?): SignStatementOpts { contentType = c; return this }
    }

    /** Sign a PCActn / verdict as a COSE Signed Statement (COSE_Sign1) over the strict-canonical serialization of the payload. */
    @JvmStatic
    fun signStatement(payload: Any?, opts: SignStatementOpts): ByteArray {
        val prot = LinkedHashMap<Any?, Any?>()
        prot[HDR_ALG.toLong()] = opts.alg.label
        prot[HDR_CONTENT_TYPE.toLong()] = opts.contentType ?: DEFAULT_CONTENT_TYPE
        val claims = LinkedHashMap<Any?, Any?>()
        claims[CWT_ISS.toLong()] = opts.issuer
        if (opts.subject != null) claims[CWT_SUB.toLong()] = opts.subject
        prot[HDR_CWT_CLAIMS.toLong()] = claims
        val protectedBytes = Cbor.encode(prot)
        val payloadBytes = Json.canonicalizeStrict(payload).toByteArray(Charsets.UTF_8)
        val sig = signBytes(opts.alg, opts.key, sigStructure(protectedBytes, payloadBytes))
        return Cbor.encode(Cbor.Tag(COSE_SIGN1_TAG.toLong(), listOf(protectedBytes, LinkedHashMap<Any?, Any?>(), payloadBytes, sig)))
    }

    /** A decoded, structurally validated COSE_Sign1. [payload] is null when detached. */
    class CoseSign1 internal constructor(
        @JvmField val protectedBytes: ByteArray,
        @JvmField val protectedMap: Map<Any?, Any?>,
        @JvmField val unprotected: Map<Any?, Any?>,
        @JvmField val payload: ByteArray?,
        @JvmField val signature: ByteArray,
    )

    @Suppress("UNCHECKED_CAST")
    private fun decodeMap(v: Any?): Map<Any?, Any?> {
        if (v !is Map<*, *>) throw err("cbor: expected a map")
        return v as Map<Any?, Any?>
    }

    /** Decode and structurally validate a COSE_Sign1 (tag 18). Throws on any deviation. */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    fun decodeCoseSign1(bytes: ByteArray): CoseSign1 {
        val top = Cbor.decode(bytes)
        if (top !is Cbor.Tag || top.tag != COSE_SIGN1_TAG.toLong()) throw err("cose: not a COSE_Sign1 (tag 18)")
        val arr = top.value
        if (arr !is List<*> || arr.size != 4) throw err("cose: malformed COSE_Sign1 array")
        val protectedBytes = arr[0]
        val unprotected = arr[1]
        val payload = arr[2]
        val signature = arr[3]
        if (protectedBytes !is ByteArray) throw err("cose: protected must be a bstr")
        if (unprotected !is Map<*, *>) throw err("cose: unprotected must be a map")
        if (payload !is ByteArray && payload != null) throw err("cose: payload must be a bstr or nil")
        if (signature !is ByteArray) throw err("cose: signature must be a bstr")
        val pm: Map<Any?, Any?> = if (protectedBytes.isEmpty()) LinkedHashMap() else decodeMap(Cbor.decode(protectedBytes))
        return CoseSign1(protectedBytes, pm, unprotected as Map<Any?, Any?>, payload as ByteArray?, signature)
    }

    private fun algOf(protectedMap: Map<Any?, Any?>): CoseAlg {
        val label = protectedMap[HDR_ALG.toLong()]
        if (label == null && !protectedMap.containsKey(HDR_ALG.toLong())) throw err("cose: missing alg header")
        val alg = if (label is Long) algForLabel(label) else null
        return alg ?: throw err("cose: unsupported alg")
    }

    /** Outcome of [checkStatement]: success, or the specific reason verification failed. */
    class StatementCheck internal constructor(@JvmField val ok: Boolean, @JvmField val reason: String?) {
        /** The reference's shape: {ok: true} or {ok: false, reason}. */
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["ok"] = ok
            if (!ok) m["reason"] = reason
            return m
        }
    }

    private fun fail(reason: String) = StatementCheck(false, reason)

    /**
     * Verify a Signed Statement and say WHY it failed: `malformed: <detail>`, `missing alg header`, `unsupported alg`,
     * `detached payload`, `non-canonical signature (high-S)` (unless [allowHighS]) or `bad signature`.
     * Never throws. The COSE external_aad is always empty.
     */
    @JvmStatic
    @JvmOverloads
    fun checkStatement(statement: ByteArray, publicKey: ScittPublicKey, allowHighS: Boolean = false): StatementCheck {
        val s = try {
            decodeCoseSign1(statement)
        } catch (e: RuntimeException) {
            return fail("malformed: " + e.message)
        }
        val payload = s.payload ?: return fail("detached payload")
        val alg = try {
            algOf(s.protectedMap)
        } catch (e: RuntimeException) {
            return fail(if (e.message != null && e.message!!.contains("missing")) "missing alg header" else "unsupported alg")
        }
        return try {
            val msg = sigStructure(s.protectedBytes, payload)
            if (verifyBytes(alg, publicKey, msg, s.signature, allowHighS)) StatementCheck(true, null)
            else if (alg == CoseAlg.ES256 && !isCanonicalEs256(s.signature) && verifyBytes(alg, publicKey, msg, s.signature, true)) fail("non-canonical signature (high-S)")
            else fail("bad signature")
        } catch (e: Exception) {
            fail("bad signature")
        } catch (e: StackOverflowError) {
            fail("bad signature")
        }
    }

    /** Verify a Signed Statement's COSE_Sign1 signature against the issuer public key. Never throws. */
    @JvmStatic
    @JvmOverloads
    fun verifyStatement(statement: ByteArray, publicKey: ScittPublicKey, allowHighS: Boolean = false): Boolean =
        checkStatement(statement, publicKey, allowHighS).ok

    /** The raw canonical payload bytes carried by a Signed Statement. Throws on a malformed statement. */
    @JvmStatic
    fun statementPayload(statement: ByteArray): ByteArray = decodeCoseSign1(statement).payload ?: throw err("cose: statement payload is detached")

    /** The b64u leaf a statement occupies in the transparency log. */
    @JvmStatic
    fun statementLeaf(statement: ByteArray): String = Keys.b64u(statement)

    // ---- RFC 9162 inclusion proof codec: [tree_size, leaf_index, inclusion_path] ----

    private fun splitN(n: Long): Long {
        var k = 1L
        while (k * 2 < n) k *= 2
        return k
    }

    /** Sibling sides (leaf to root) for [index] in a tree of [size] leaves (RFC 6962 split). */
    @JvmStatic
    fun siblingSides(index: Long, size: Long): List<String> {
        val out = ArrayList<String>()
        var idx = index
        var n = size
        while (n > 1) {
            val k = splitN(n)
            if (idx < k) {
                out.add("R")
                n = k
            } else {
                out.add("L")
                idx -= k
                n -= k
            }
        }
        out.reverse()
        return out
    }

    /** A JSON number or plain number of the proof as the CBOR model value (Long when an exact safe integer, else Double). */
    internal fun numberOf(o: Any?): Any? {
        if (o is Json.Num) {
            val raw = o.raw
            try {
                val d = BigDecimal(raw)
                if (d.signum() == 0 && raw.startsWith("-")) return -0.0
                val i = d.toBigIntegerExact()
                if (i.abs() <= BigInteger.valueOf(Cbor.MAX_SAFE)) return i.toLong()
            } catch (e: ArithmeticException) {
                // not an exact integer
            } catch (e: NumberFormatException) {
                // not an exact integer
            }
            return raw.toDouble()
        }
        return o
    }

    private fun stepHashes(path: Any?): List<ByteArray> {
        if (path !is List<*>) throw err("path.map is not a function")
        val out = ArrayList<ByteArray>()
        for (step in path) {
            if (step !is Map<*, *>) throw err("scitt: proof step hash is not a 32-byte b64u hash")
            out.add(Pca.decodeB64uStrict(step["hash"], 32) ?: throw err("scitt: proof step hash is not a 32-byte b64u hash"))
        }
        return out
    }

    /** Encode a core-Merkle inclusion proof as an RFC 9162 inclusion proof (CBOR). */
    @JvmStatic
    fun encodeInclusionProof(proof: Map<String, Any?>): ByteArray {
        val sibs: List<Any?> = ArrayList<Any?>(stepHashes(proof["path"]))
        if (!proof.containsKey("size") || !proof.containsKey("index")) throw err("cbor: unsupported value")
        return Cbor.encode(listOf(numberOf(proof["size"]), numberOf(proof["index"]), sibs))
    }

    /** A decoded inclusion proof: size, index and the raw sibling hashes (leaf to root). */
    private class Incl(val index: Long, val size: Long, val hashes: List<ByteArray>, val sides: List<String>)

    private fun decodeIncl(bytes: ByteArray): Incl {
        val v = Cbor.decode(bytes)
        if (v !is List<*> || v.size != 3) throw err("scitt: malformed inclusion proof")
        val size = v[0]
        val index = v[1]
        val sibs = v[2]
        if (size !is Long || index !is Long) throw err("scitt: proof size/index must be integers")
        if (size < 1 || index < 0 || index >= size) throw err("scitt: proof size/index out of range")
        if (sibs !is List<*>) throw err("scitt: inclusion path must be an array")
        val sides = siblingSides(index, size)
        if (sibs.size != sides.size) throw err("scitt: inclusion path length does not match (index,size)")
        val hashes = ArrayList<ByteArray>()
        for (h in sibs) {
            if (h !is ByteArray || h.size != 32) throw err("scitt: inclusion path entry must be a 32-byte bstr")
            hashes.add(h)
        }
        return Incl(index, size, hashes, sides)
    }

    /** Decode an RFC 9162 inclusion proof back into the core-Merkle proof map (sides re-derived). */
    @JvmStatic
    fun decodeInclusionProof(bytes: ByteArray): Map<String, Any?> = inclMap(decodeIncl(bytes))

    private fun inclMap(inc: Incl): Map<String, Any?> {
        val path = ArrayList<Any?>()
        for (i in inc.hashes.indices) {
            val step = LinkedHashMap<String, Any?>()
            step["side"] = inc.sides[i]
            step["hash"] = Keys.b64u(inc.hashes[i])
            path.add(step)
        }
        val m = LinkedHashMap<String, Any?>()
        m["index"] = inc.index
        m["size"] = inc.size
        m["path"] = path
        return m
    }

    /** The core-Merkle proof map for leaf [index] of a [size]-leaf tree given its bottom-up sibling hashes. */
    @JvmStatic
    fun inclusionProofMap(index: Long, size: Long, hashes: List<ByteArray>): Map<String, Any?> =
        inclMap(Incl(index, size, hashes, siblingSides(index, size)))

    // ---- COSE Receipts (RFC 9942) ----

    /** [key] is the Transparency Service PRIVATE key; [issuer] (CWT iss in the receipt's protected header) may be null. */
    class ReceiptSignerOpts(@JvmField val alg: CoseAlg, @JvmField val key: ScittPrivateKey, @JvmField val issuer: String?)

    /**
     * Build a signed COSE Receipt for [proof] against ledger root [root] (b64u, 32-byte SHA-256). The payload is detached;
     * the signature covers the root a verifier recomputes from the inclusion proof.
     */
    @JvmStatic
    fun buildReceipt(root: String, proof: Map<String, Any?>, signer: ReceiptSignerOpts): ByteArray {
        val rootBytes = Pca.decodeB64uStrict(root, 32) ?: throw err("scitt: tree root is not a 32-byte b64u hash")
        val prot = LinkedHashMap<Any?, Any?>()
        prot[HDR_ALG.toLong()] = signer.alg.label
        prot[HDR_VDS.toLong()] = VDS_RFC9162_SHA256.toLong()
        if (signer.issuer != null) {
            val claims = LinkedHashMap<Any?, Any?>()
            claims[CWT_ISS.toLong()] = signer.issuer
            prot[HDR_CWT_CLAIMS.toLong()] = claims
        }
        val protectedBytes = Cbor.encode(prot)
        val proofs = LinkedHashMap<Any?, Any?>()
        proofs[PROOF_TYPE_INCLUSION.toLong()] = listOf(encodeInclusionProof(proof))
        val unprotected = LinkedHashMap<Any?, Any?>()
        unprotected[HDR_VDS_PROOFS.toLong()] = proofs
        val sig = signBytes(signer.alg, signer.key, sigStructure(protectedBytes, rootBytes))
        return Cbor.encode(Cbor.Tag(COSE_SIGN1_TAG.toLong(), listOf(protectedBytes, unprotected, null, sig)))
    }

    class VerifyReceiptOpts {
        /** The expected (pinned, out-of-band) tree root (b64u). */
        @JvmField var treeRoot: String? = null

        /** The Transparency Service PUBLIC key. */
        @JvmField var verificationKey: ScittPublicKey? = null

        /** The issuer PUBLIC key of the Signed Statement. */
        @JvmField var statementKey: ScittPublicKey? = null

        /** Accept ES256 signatures with a high S value. Default false. */
        @JvmField var allowHighS: Boolean = false
    }

    /**
     * Verify a COSE Receipt for a Signed Statement. FAIL-CLOSED (returns a boolean, never throws): an anchor is supplied; the receipt's TS
     * signature over the root verifies when `verificationKey` is given; the root equals `treeRoot` when given; the inclusion
     * proof binds the EXACT statement bytes to that root; the statement's own signature verifies when `statementKey` is given.
     */
    @JvmStatic
    fun verifyReceipt(receipt: ByteArray, statement: ByteArray, opts: VerifyReceiptOpts): Boolean {
        try {
            if (opts.treeRoot == null && opts.verificationKey == null) return false
            val cose = decodeCoseSign1(receipt)
            val vds = cose.protectedMap[HDR_VDS.toLong()]
            if (vds !is Long || vds != VDS_RFC9162_SHA256.toLong()) throw err("scitt: receipt is not RFC9162_SHA256")
            val cp = cose.payload
            if (cp != null && cp.size != 32) throw err("scitt: receipt payload (root) must be 32 bytes")
            val proofsRaw = cose.unprotected[HDR_VDS_PROOFS.toLong()]
            if (proofsRaw !is Map<*, *>) throw err("scitt: missing verifiable-data-structure-proofs")
            val inclusion = proofsRaw[PROOF_TYPE_INCLUSION.toLong()]
            if (inclusion !is List<*> || inclusion.size < 1) throw err("scitt: missing inclusion proof")
            val first = inclusion[0]
            if (first !is ByteArray) throw err("scitt: inclusion proof must be a bstr")
            val proof = decodeIncl(first)

            val root = Rfc9162.rootFromInclusionPath(Rfc9162.leafHash(statement), proof.index, proof.size, proof.hashes) ?: return false
            if (cp != null && !cp.contentEquals(root)) return false
            val vk = opts.verificationKey
            if (vk != null) {
                val alg = algOf(cose.protectedMap)
                if (!verifyBytes(alg, vk, sigStructure(cose.protectedBytes, root), cose.signature, opts.allowHighS)) return false
            }
            if (opts.treeRoot != null && opts.treeRoot != Keys.b64u(root)) return false
            val sk = opts.statementKey
            if (sk != null && !verifyStatement(statement, sk, opts.allowHighS)) return false
            return true
        } catch (e: Exception) {
            return false
        } catch (e: StackOverflowError) {
            return false
        }
    }

    /** Result of a consistency proof request: both roots (b64u) and the RFC 9942 consistency-proof-content CBOR. */
    class ConsistencyProofResult(
        @JvmField val oldSize: Long,
        @JvmField val newSize: Long,
        @JvmField val oldRoot: String,
        @JvmField val newRoot: String,
        @JvmField val proof: ByteArray,
    ) {
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["oldSize"] = oldSize
            m["newSize"] = newSize
            m["oldRoot"] = oldRoot
            m["newRoot"] = newRoot
            m["proof"] = proof
            return m
        }
    }

    /** Verify an RFC 9942 / RFC 9162 consistency proof between two pinned roots (b64u). FAIL-CLOSED boolean. */
    @JvmStatic
    fun verifyConsistencyProof(proof: ByteArray, oldRoot: String?, newRoot: String?): Boolean {
        try {
            val v = Cbor.decode(proof)
            if (v !is List<*> || v.size != 3) return false
            val a = v[0]
            val b = v[1]
            val p = v[2]
            if (a !is Long || b !is Long || p !is List<*>) return false
            val path = ArrayList<ByteArray>()
            for (h in p) {
                if (h !is ByteArray) return false
                path.add(h)
            }
            val r1 = Pca.decodeB64uStrict(oldRoot, 32) ?: return false
            val r2 = Pca.decodeB64uStrict(newRoot, 32) ?: return false
            return Rfc9162.verifyConsistencyPath(a, b, r1, r2, path)
        } catch (e: Exception) {
            return false
        } catch (e: StackOverflowError) {
            return false
        }
    }
}
