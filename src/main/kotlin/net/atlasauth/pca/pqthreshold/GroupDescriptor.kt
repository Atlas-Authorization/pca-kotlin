package net.atlasauth.pca.pqthreshold

import java.math.BigDecimal
import java.security.MessageDigest
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * The signed group descriptor that pins a FROST threshold to its group key. A FROST aggregate is a plain Ed25519 signature, so its threshold
 * is a label until an authority the verifier pins attests how the group was formed.
 */
object GroupDescriptor {
    const val GROUP_DESCRIPTOR_VERSION = 1
    const val GROUP_SUITE = "frost-ed25519"
    private const val DESCRIPTOR_DOMAIN = "atlas-pca-pq-threshold/group-descriptor/v1\u0000"
    private const val SIGNER_SET_DOMAIN = "atlas-pca-pq-threshold/signer-set/v1\u0000"
    const val MAX_GROUP_SIZE = 1024

    // ---- JavaScript-flavoured value helpers (wire values arrive as parsed JSON) ----

    /** The JavaScript number value of a parsed JSON number, or null when the value is not a number. */
    internal fun numOf(o: Any?): Double? = Js.num(o)

    /** `Number.isInteger`. */
    internal fun isInteger(o: Any?): Boolean {
        val d = numOf(o)
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.floor(d)
    }

    /** A member of a JSON object; an array or a non-object has no such member (null). */
    internal fun member(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    internal fun isObject(o: Any?): Boolean = o is Map<*, *> || o is List<*>

    internal fun asB64u(k: Any?): String? = if (k is ByteArray) Keys.b64u(k) else k as? String

    /** Number printing for reasons (JavaScript style: integers without a fraction). */
    internal fun fmt(o: Any?): String {
        val d = numOf(o) ?: return o.toString()
        return if (isInteger(o) && Math.abs(d) < 1e21) BigDecimal(d).toBigInteger().toString() else d.toString()
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun withDomain(domain: String, body: ByteArray): ByteArray = Json.utf8(domain) + body

    // ---- signer set ----

    /**
     * `sha256(DOMAIN || canonical(sorted [{id, pk}]))`; order-insensitive, ids distinct. Each participant is a JSON object
     * {identifier (positive safe integer), publicKey (canonical b64u 32 bytes, or raw bytes)}.
     */
    @JvmStatic
    fun signerSetCommitment(participants: List<*>?): String {
        require(!(participants == null || participants.isEmpty() || participants.size > MAX_GROUP_SIZE)) { "signerSetCommitment: need 1..$MAX_GROUP_SIZE participants" }
        val ids = ArrayList<Long>()
        val pks = ArrayList<String>()
        for (p in participants) {
            requireNotNull(p) { "signerSetCommitment: participant is null" }
            val idObj = member(p, "identifier")
            val pk = asB64u(member(p, "publicKey"))
            val id = numOf(idObj)
            require(!(id == null || !isInteger(idObj) || id <= 0 || id > 9007199254740991.0)) { "signerSetCommitment: participant identifiers must be positive safe integers" }
            require(!(pk == null || Pca.decodeB64uStrict(pk, 32) == null)) { "signerSetCommitment: verification share is not a canonical b64u(32) value" }
            ids.add(id!!.toLong())
            pks.add(pk!!)
        }
        val order = ids.indices.sortedWith(Comparator { a, b -> java.lang.Long.compare(ids[a], ids[b]) })
        val rows = ArrayList<Any?>()
        for (i in order.indices) {
            require(!(i > 0 && ids[order[i]] == ids[order[i - 1]])) { "signerSetCommitment: duplicate participant identifier" }
            val row = LinkedHashMap<String, Any?>()
            row["id"] = Js.n(ids[order[i]])
            row["pk"] = pks[order[i]]
            rows.add(row)
        }
        return Keys.b64u(sha256(withDomain(SIGNER_SET_DOMAIN, Json.canonicalize(rows).toByteArray(Charsets.UTF_8))))
    }

    private fun descriptorBytes(v: Any?, suite: Any?, groupPk: Any?, t: Any?, n: Any?, signerSet: Any?): ByteArray {
        val body = LinkedHashMap<String, Any?>()
        body["v"] = v
        body["suite"] = suite
        body["group_pk"] = groupPk
        body["t"] = t
        body["n"] = n
        body["signer_set"] = signerSet
        return withDomain(DESCRIPTOR_DOMAIN, Json.canonicalize(body).toByteArray(Charsets.UTF_8))
    }

    /**
     * Issue a descriptor at dealing time: {descriptor: {v, suite, groupPublicKey, t, n, signerSetCommitment}, authority, sig}. The authority
     * secret is a 32-byte Ed25519 seed. Throws on an impossible group (t < 1, t > n, a non-canonical group key, a bad authority key).
     */
    @JvmStatic
    fun issueGroupDescriptor(authoritySecretKey: ByteArray?, groupPublicKey: Any?, t: Any?, participants: List<*>): Map<String, Any?> {
        val n = participants.size
        val td = numOf(t)
        require(!(td == null || !isInteger(t) || td < 1 || td > n)) { "issueGroupDescriptor: need 1 <= t <= n (t=${fmt(t)}, n=$n)" }
        val gpk = asB64u(groupPublicKey)
        require(!(gpk == null || Pca.decodeB64uStrict(gpk, 32) == null)) { "issueGroupDescriptor: group public key is not canonical b64u(32)" }
        require(!(authoritySecretKey == null || authoritySecretKey.size != 32)) { "issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key" }
        val commitment = signerSetCommitment(participants)
        val tl = td!!.toLong()
        val d = LinkedHashMap<String, Any?>()
        d["v"] = Js.n(GROUP_DESCRIPTOR_VERSION.toLong())
        d["suite"] = GROUP_SUITE
        d["groupPublicKey"] = gpk
        d["t"] = Js.n(tl)
        d["n"] = Js.n(n.toLong())
        d["signerSetCommitment"] = commitment
        val ak = Keys.edFromSeed(authoritySecretKey!!)
        val out = LinkedHashMap<String, Any?>()
        out["descriptor"] = d
        out["authority"] = ak.id()
        out["sig"] = Keys.b64u(ak.sign(descriptorBytes(Js.n(GROUP_DESCRIPTOR_VERSION.toLong()), GROUP_SUITE, gpk, Js.n(tl), Js.n(n.toLong()), commitment)))
        return out
    }

    private fun fail(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

    /**
     * Check a signed descriptor against the verifier's pins; never throws. [trustedAuthorities] are pinned b64u keys (String or byte[]),
     * [groupKey] the pinned group key, [t] the threshold the verifier requires (the descriptor's t must EQUAL it), and
     * [signerSetCommitment] an optional pin (null when absent). Returns {ok: true, descriptor} or {ok: false, reason}.
     */
    @JvmStatic
    fun verifyGroupDescriptor(s: Any?, trustedAuthorities: Any?, groupKey: Any?, t: Any?, signerSetCommitment: String?): Map<String, Any?> {
        try {
            if (!isObject(s)) return fail("no signed group descriptor: the threshold is unattested")
            val d = member(s, "descriptor")
            val authority = member(s, "authority")
            val sig = member(s, "sig")
            if (!isObject(d) || authority !is String || sig !is String) return fail("malformed group descriptor")
            val dvn = numOf(member(d, "v"))
            if (dvn == null || dvn != GROUP_DESCRIPTOR_VERSION.toDouble() || GROUP_SUITE != member(d, "suite")) return fail("unsupported group descriptor version or suite")
            val gpk = member(d, "groupPublicKey")
            val ssc = member(d, "signerSetCommitment")
            if (gpk !is String || ssc !is String) return fail("malformed group descriptor")
            val dt = member(d, "t")
            val dn = member(d, "n")
            if (!isInteger(dt) || !isInteger(dn) || numOf(dt)!! < 1 || numOf(dn)!! < numOf(dt)!! || numOf(dn)!! > MAX_GROUP_SIZE) return fail("malformed group descriptor: need 1 <= t <= n")
            if (trustedAuthorities !is List<*>) return fail("group descriptor could not be verified (malformed)")
            val trusted = HashSet<String>()
            for (a in trustedAuthorities) { val x = asB64u(a); if (x != null) trusted.add(x) }
            if (!trusted.contains(authority)) return fail("group descriptor authority is not trusted")
            if (Pca.decodeB64uStrict(authority, 32) == null || Pca.decodeB64uStrict(sig, 64) == null) return fail("malformed authority key or signature")
            if (!Pca.verifyB64u(authority, descriptorBytes(Js.n(GROUP_DESCRIPTOR_VERSION.toLong()), GROUP_SUITE, gpk, dt, dn, ssc), sig)) return fail("group descriptor signature does not verify")
            if (gpk != asB64u(groupKey)) return fail("group descriptor is for a different group key")
            if (!isInteger(t) || numOf(t)!! < 1) return fail("required t must be a positive integer")
            if (numOf(dt) != numOf(t)) return fail("group was set up as ${fmt(dt)}-of-${fmt(dn)} but ${fmt(t)} is required: the threshold is not bound to this key")
            if (signerSetCommitment != null && ssc != signerSetCommitment) return fail("group descriptor is for a different signer set")
            return linkedMapOf("ok" to true, "descriptor" to d)
        } catch (e: RuntimeException) {
            return fail("group descriptor could not be verified (malformed)")
        }
    }
}
