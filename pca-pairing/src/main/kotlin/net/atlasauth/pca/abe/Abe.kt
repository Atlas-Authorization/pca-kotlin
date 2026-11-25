package net.atlasauth.pca.abe

import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import net.atlasauth.pca.pairing.Bls12
import net.atlasauth.pca.pairing.Gt
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import supranational.blst.P1
import supranational.blst.P2

/**
 * Proof-carrying encryption: ciphertext-policy ABE (FAME, see [Fame]) with the payload sealed under AES-256-GCM, the whole
 * header authenticated. Keys, ciphertexts and the master keys are JSON maps with the TypeScript reference's member names, so
 * material crosses languages unchanged. Every parser is fail-closed: [decrypt] returns null on any deviation and never throws.
 */
@Suppress("UNCHECKED_CAST")
object Abe {
    const val ABE_ALG = "fame-cpabe-bls12381-type3/aes-256-gcm"
    private const val CEK_INFO = "atlas-pca-abe/cek/v3"
    private const val SALT_LEN = 16
    private val RNG = SecureRandom()

    /** An invalid policy, master public key or master secret key. */
    class PcaEncryptionError(m: String) : IllegalArgumentException(m)

    // ---- wire helpers -------------------------------------------------------------------------

    private val B64U = Regex("[A-Za-z0-9_-]*")

    internal fun b64u(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    /** Canonical unpadded base64url only; null otherwise. */
    internal fun unb64u(o: Any?): ByteArray? {
        if (o !is String || !B64U.matches(o)) return null
        return try {
            val b = Base64.getUrlDecoder().decode(o)
            if (b64u(b) == o) b else null
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun obj(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun isTwo(o: Any?): Boolean = AbePolicy.num(o) == 2.0

    /** True iff the string has an unpaired UTF-16 surrogate (such strings alias each other once UTF-8 encoded). */
    internal fun illFormed(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) i++ else return true
            } else if (Character.isLowSurrogate(c)) return true
            i++
        }
        return false
    }

    private fun readG1(x: Any?): P1? {
        val b = unb64u(x) ?: return null
        return try {
            Bls12.decodeG1(b).takeUnless { it.is_inf() }
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun readG2(x: Any?): P2? {
        val b = unb64u(x) ?: return null
        return try {
            Bls12.decodeG2(b).takeUnless { it.is_inf() }
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun readGt(x: Any?): ByteArray? = unb64u(x)?.takeIf { Gt.isElement(it) }

    private fun tri1(x: Any?): Array<P1>? {
        if (x !is List<*> || x.size != 3) return null
        return Array(3) { readG1(x[it]) ?: return null }
    }

    private fun tri2(x: Any?): Array<P2>? {
        if (x !is List<*> || x.size != 3) return null
        return Array(3) { readG2(x[it]) ?: return null }
    }

    private fun enc(p: Array<P1>): List<Any?> = p.map { b64u(it.compress()) }

    private fun enc(p: Array<P2>): List<Any?> = p.map { b64u(it.compress()) }

    // ---- scalars ------------------------------------------------------------------------------

    private fun randomScalar(): BigInteger {
        while (true) {
            val b = ByteArray(64)
            RNG.nextBytes(b)
            val v = Bls12.mod(Bls12.os2ip(b))
            if (v.signum() != 0) return v
        }
    }

    private fun scalarB64(s: BigInteger): String = b64u(Bls12.i2osp(s, 32))

    /** Exactly one encoding per scalar: 32 bytes, non-zero, and below r. */
    private fun canonicalScalar(enc: Any?): BigInteger? {
        val b = unb64u(enc)
        if (b == null || b.size != 32) return null
        val x = Bls12.os2ip(b)
        return if (x.signum() == 0 || x >= Bls12.R) null else x
    }

    // ---- setup / keygen -----------------------------------------------------------------------

    /** A fresh master key pair: `{mpk, msk}`. */
    fun setup(): Map<String, Any?> {
        val a = arrayOf(randomScalar(), randomScalar())
        val b = arrayOf(randomScalar(), randomScalar())
        val d = arrayOf(randomScalar(), randomScalar(), randomScalar())
        val m = Fame.setup(a, b, d)
        val msk = linkedMapOf<String, Any?>(
            "v" to 2L, "curve" to "bls12-381",
            "a" to listOf(scalarB64(a[0]), scalarB64(a[1])),
            "b" to listOf(scalarB64(b[0]), scalarB64(b[1])),
            "g" to m.msk.g.map { b64u(it.compress()) },
        )
        val mpk = linkedMapOf<String, Any?>(
            "v" to 2L, "curve" to "bls12-381",
            "h" to listOf(b64u(m.mpk.h1.compress()), b64u(m.mpk.h2.compress())),
            "t" to listOf(b64u(m.mpk.t1), b64u(m.mpk.t2)),
        )
        return linkedMapOf("mpk" to mpk, "msk" to msk)
    }

    private fun parseMsk(o: Any?): Fame.Msk {
        val m = obj(o)
        if (m == null || !isTwo(m["v"])) throw PcaEncryptionError("invalid master secret key")
        val a = scalarPair(m["a"])
        val b = scalarPair(m["b"])
        val g = tri1(m["g"])
        if (a == null || b == null || g == null) throw PcaEncryptionError("invalid master secret key")
        return Fame.Msk(a, b, g)
    }

    private fun scalarPair(x: Any?): Array<BigInteger>? {
        if (x !is List<*> || x.size != 2) return null
        return Array(2) { canonicalScalar(x[it]) ?: return null }
    }

    private fun parseMpk(o: Any?): Fame.Mpk {
        val m = obj(o)
        val h = m?.get("h")
        val t = m?.get("t")
        if (m != null && isTwo(m["v"]) && h is List<*> && h.size == 2 && t is List<*> && t.size == 2) {
            val h1 = readG2(h[0])
            val h2 = readG2(h[1])
            val t1 = readGt(t[0])
            val t2 = readGt(t[1])
            if (h1 != null && h2 != null && t1 != null && t2 != null) return Fame.Mpk(h1, h2, t1, t2)
        }
        throw PcaEncryptionError("invalid master public key")
    }

    /** Issue a decryption key for an explicit set of attribute tokens (empty or ill-formed names are dropped). */
    fun keygenForAttributes(msk: Any?, attrs: Collection<String?>): MutableMap<String, Any?> {
        val m = parseMsk(msk)
        val names = LinkedHashSet(attrs).filterNotNull().filter { it.isNotEmpty() && !illFormed(it) }
        val sigmas = names.map { randomScalar() }
        val key = Fame.keygen(m, names, arrayOf(randomScalar(), randomScalar()), sigmas, randomScalar())
        val as_ = LinkedHashMap<String, Any?>()
        for (n in names) as_[n] = mapOf("k" to enc(key.attrs[n]!!))
        return linkedMapOf("v" to 2L, "curve" to "bls12-381", "k0" to enc(key.k0), "kp" to enc(key.kp), "attrs" to as_)
    }

    /** Issue a key bound to a capability: its [capabilityAttributes] plus the extra tokens; `holder` is recorded. */
    fun keygenForCapability(msk: Any?, capability: Map<String, Any?>, extra: Collection<String?>, opts: Map<String, Any?>?): Map<String, Any?> {
        val attrs = capabilityAttributes(capability, opts)
        for (a in extra) if (!a.isNullOrEmpty()) attrs.add(a)
        val key = keygenForAttributes(msk, attrs)
        val holder = capability["holder"]
        if (holder is String) key["holder"] = holder
        return key
    }

    /** An untrusted key; a malformed attribute component counts as not held. Null if K0, K' or the container is malformed. */
    private fun parseKey(o: Any?): Fame.Key? {
        val k = obj(o)
        val ka = obj(k?.get("attrs"))
        if (k == null || !isTwo(k["v"]) || ka == null) return null
        val k0 = tri2(k["k0"]) ?: return null
        val kp = tri1(k["kp"]) ?: return null
        val attrs = LinkedHashMap<String, Array<P1>>()
        for ((name, v) in ka) {
            val t = tri1(obj(v)?.get("k"))
            if (t != null) attrs[name] = t
        }
        return Fame.Key(k0, kp, attrs)
    }

    // ---- KDF / AEAD ---------------------------------------------------------------------------

    /** HKDF-SHA256 (RFC 5869), 32 bytes: the content-encryption key from the KEM key. */
    internal fun kdf32(ikm: ByteArray, salt: ByteArray, info: String): ByteArray {
        val h = Mac.getInstance("HmacSHA256")
        h.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
        val prk = h.doFinal(ikm)
        h.init(SecretKeySpec(prk, "HmacSHA256"))
        h.update(Json.utf8(info))
        h.update(1.toByte())
        return h.doFinal()
    }

    private fun seal(key: ByteArray, pt: ByteArray, aad: ByteArray): Array<ByteArray> {
        val iv = ByteArray(12).also { RNG.nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        c.updateAAD(aad)
        val out = c.doFinal(pt)
        return arrayOf(iv, out.copyOfRange(0, out.size - 16), out.copyOfRange(out.size - 16, out.size))
    }

    private fun open(key: ByteArray, iv: ByteArray, ct: ByteArray, tag: ByteArray, aad: ByteArray): ByteArray? {
        if (key.size != 32 || iv.size != 12 || tag.size != 16) return null
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            c.updateAAD(aad)
            c.doFinal(ct + tag)
        } catch (e: GeneralSecurityException) {
            null
        }
    }

    private fun aad(c: Map<String, Any?>): ByteArray {
        val h = LinkedHashMap<String, Any?>()
        for (k in listOf("v", "alg", "salt", "ct0", "tree", "rows")) h[k] = c[k]
        return Json.canonicalizeStrict(h).toByteArray(Charsets.UTF_8)
    }

    // ---- encrypt ------------------------------------------------------------------------------

    /** Encrypt so that only a key whose attributes satisfy `policy` opens it. Throws [PcaEncryptionError] on a bad policy or key. */
    fun encryptForPolicy(mpk: Any?, policy: Any?, plaintext: ByteArray): Map<String, Any?> {
        val norm = AbePolicy.normalize(policy)
        val tree = norm.tree ?: throw PcaEncryptionError("invalid policy: ${norm.reason}")
        Fame.firstRepeatedAttribute(tree)?.let {
            throw PcaEncryptionError("invalid policy: attribute ${Json.canonicalize(it)} is named by more than one leaf (single-use attributes only)")
        }
        val pk = parseMpk(mpk)
        val salt = ByteArray(SALT_LEN).also { RNG.nextBytes(it) }
        val e = Fame.encrypt(pk, tree, arrayOf(randomScalar(), randomScalar()))
        val header = linkedMapOf<String, Any?>(
            "v" to 2L, "alg" to ABE_ALG, "salt" to b64u(salt), "ct0" to enc(e.ct.ct0), "tree" to tree, "rows" to e.ct.rows.map { enc(it) },
        )
        val headerAad = try {
            aad(header)
        } catch (x: IllegalArgumentException) {
            throw PcaEncryptionError("policy cannot be authenticated (header outside the canonical JSON profile)")
        }
        val s = seal(kdf32(e.k, salt, CEK_INFO), plaintext, headerAad)
        header["iv"] = b64u(s[0])
        header["ct"] = b64u(s[1])
        header["tag"] = b64u(s[2])
        return header
    }

    fun encryptForPolicy(mpk: Any?, policy: Any?, plaintext: String): Map<String, Any?> =
        encryptForPolicy(mpk, policy, Json.utf8(plaintext))

    /** Encrypt a JSON value (the payload layer of [decryptWithCapability]). */
    fun encryptToolPayload(mpk: Any?, policy: Any?, payload: Any?): Map<String, Any?> =
        encryptForPolicy(mpk, policy, Json.canonicalize(payload))

    // ---- parse --------------------------------------------------------------------------------

    private fun parseTree(x: Any?, gates: Int, budget: IntArray): Map<String, Any?>? {
        val m = obj(x)
        if (++budget[0] > AbePolicy.MAX_POLICY_NODES || m == null) return null
        if (m["kind"] == "leaf") {
            val a = m["attr"]
            if (a !is String || a.isEmpty() || illFormed(a) || m.size != 2) return null
            return AbePolicy.leaf(a)
        }
        if (m["kind"] == "gate") {
            if (gates + 1 > AbePolicy.MAX_POLICY_DEPTH || m.size != 3) return null
            val t = m["t"]
            val of = m["of"]
            if (!AbePolicy.isPosInt(t) || of !is List<*> || of.isEmpty()) return null
            val td = AbePolicy.num(t)!!
            if (td > of.size || of.size >= AbePolicy.MAX_POLICY_NODES) return null
            val kids = of.map { parseTree(it, gates + 1, budget) ?: return null }
            return AbePolicy.gate(td.toLong(), kids)
        }
        return null
    }

    private fun strTri(x: Any?): List<Any?>? {
        if (x !is List<*> || x.size != 3) return null
        if (x.any { unb64u(it) == null }) return null
        return ArrayList(x)
    }

    /** Validate an untrusted value as a ciphertext; null (fail closed) on any deviation. */
    fun parseCiphertext(o: Any?): Map<String, Any?>? {
        val x = obj(o)
        if (x == null || !isTwo(x["v"]) || x["alg"] != ABE_ALG) return null
        for (k in listOf("salt", "iv", "ct", "tag")) if (unb64u(x[k]) == null) return null
        val ct0 = strTri(x["ct0"])
        val tree = parseTree(x["tree"], 0, IntArray(1))
        val rawRows = x["rows"]
        if (ct0 == null || tree == null || rawRows !is List<*>) return null
        if (rawRows.size != Fame.leafCount(tree) || Fame.firstRepeatedAttribute(tree) != null) return null
        val rows = rawRows.map { strTri(it) ?: return null }
        return linkedMapOf(
            "v" to 2L, "alg" to ABE_ALG, "salt" to x["salt"], "ct0" to ct0, "tree" to tree, "rows" to rows,
            "iv" to x["iv"], "ct" to x["ct"], "tag" to x["tag"],
        )
    }

    // ---- decrypt ------------------------------------------------------------------------------

    /** The plaintext iff the key's attributes satisfy the ciphertext's policy and the AEAD authenticates; otherwise null. Never throws. */
    fun decrypt(key: Any?, ciphertext: Any?): ByteArray? {
        try {
            val ct = parseCiphertext(ciphertext) ?: return null
            val pk = parseKey(key) ?: return null
            val salt = unb64u(ct["salt"])
            val iv = unb64u(ct["iv"])
            val body = unb64u(ct["ct"])
            val tag = unb64u(ct["tag"])
            val ct0 = tri2(ct["ct0"])
            val rows = (ct["rows"] as List<Any?>).map { tri1(it) ?: return null }
            if (salt == null || iv == null || body == null || tag == null || ct0 == null) return null
            val k = Fame.decrypt(pk, ct["tree"] as Map<String, Any?>, Fame.Ciphertext(ct0, rows)) ?: return null
            val headerAad = try {
                aad(ct)
            } catch (e: IllegalArgumentException) {
                return null
            }
            return open(kdf32(k, salt, CEK_INFO), iv, body, tag, headerAad)
        } catch (e: IllegalArgumentException) {
            return null
        } catch (e: ArithmeticException) {
            return null
        } catch (e: ClassCastException) {
            return null
        }
    }

    fun decryptText(key: Any?, ciphertext: Any?): String? = decrypt(key, ciphertext)?.toString(Charsets.UTF_8)

    /** `{ok:true, payload}` or `{ok:false, reason}`. */
    fun decryptWithCapability(key: Any?, ciphertext: Any?): Map<String, Any?> {
        val pt = decrypt(key, ciphertext)
            ?: return linkedMapOf("ok" to false, "reason" to "capability does not satisfy the policy, or ciphertext is invalid")
        return try {
            linkedMapOf("ok" to true, "payload" to Json.parseLenient(pt.toString(Charsets.UTF_8)))
        } catch (e: IllegalArgumentException) {
            linkedMapOf("ok" to false, "reason" to "decrypted payload is not valid JSON")
        }
    }

    // ---- capability attributes ----------------------------------------------------------------

    private fun act(verb: String, resource: String): String = "act:" + Json.canonicalize(listOf(verb, resource))

    private fun verbsOf(v: Any?): List<String> = when (v) {
        is String -> listOf(v)
        is List<*> -> v.filterIsInstance<String>()
        else -> emptyList()
    }

    /**
     * The canonical attribute set a capability possesses (sorted): holder, scope, and (from the ROOT only, never from a
     * delegated hop's own caveats) act/verb/resource tokens. A delegated capability gets scope/act/verb/resource tokens only
     * with a verified chain (root first, ending in the capability); a chain that fails verification yields none (fail closed).
     * `opts`: `chain`, `principal`, `pqPins`.
     */
    fun capabilityAttributes(cap: Map<String, Any?>?, opts: Map<String, Any?>?): MutableSet<String> {
        val out = LinkedHashSet<String>()
        if (cap == null) return out
        var scopeSource: Any? = null
        var envSource: Map<String, Any?>? = null
        if (opts != null && opts.containsKey("chain")) {
            val chain = opts["chain"] as? List<Any?>
            if (chain.isNullOrEmpty()) return out
            val root = obj(chain[0])
            val last = obj(chain[chain.size - 1])
            if (root == null || last == null || last["id"] != cap["id"]) return out
            val principal = opts["principal"] ?: root["issuer"]
            val pins = obj(opts["pqPins"])
            if (Pca.verifyChain(chain, (principal as? String) ?: "", principal is String, null, pins, null).isNotEmpty()) return out
            scopeSource = root["caveats"]
            envSource = root
        } else if (!cap.containsKey("parent")) {
            scopeSource = cap["caveats"]
            envSource = cap
        }
        val holder = cap["holder"]
        if (holder is String && holder.isNotEmpty()) out.add("holder:$holder")
        if (scopeSource is List<*>) {
            for (c in scopeSource) {
                val cv = obj(c) ?: continue
                if (cv["type"] == "scope" && cv["value"] is String) out.add("scope:" + cv["value"])
                val values = cv["values"]
                if (cv["type"] == "scopes" && values is List<*>) for (s in values) if (s is String) out.add("scope:$s")
            }
        }
        val env = envSource?.let { Authorize.readEnvelope(it) }
        val predsRaw = env?.get("predicates")
        if (predsRaw is List<*>) {
            // an array is an object to the reference: it counts, and names no verb or resource
            val preds = predsRaw.mapNotNull { p -> if (p is Map<*, *>) p as Map<String, Any?> else if (p is List<*>) emptyMap() else null }
            for (p in preds) {
                val res = p["resource"]
                if (res is String) for (v in verbsOf(p["verb"])) out.add(act(v, res))
            }
            if (preds.size == 1) {
                val p = preds[0]
                for (v in verbsOf(p["verb"])) out.add("verb:$v")
                val res = p["resource"]
                if (res is String) out.add("resource:$res")
            }
        }
        return out
    }
}
