package net.atlasauth.pca.webbotauth

import net.atlasauth.pca.verifier.Json

import java.security.MessageDigest

/**
 * RFC 9530 Content-Digest: the dictionary field whose members are hash algorithm names with byte-sequence values over the message content.
 * Only sha-256 and sha-512 (the algorithms the RFC marks Active) are produced or accepted. Cover `content-digest` in the signature so
 * it protects the body too; [verifyContentDigest] then checks the body against the covered field and FAILS CLOSED.
 */
object ContentDigest {
    @JvmField
    val CONTENT_DIGEST_ALGS: List<String> = listOf("sha-256", "sha-512")
    const val CONTENT_DIGEST_HEADER = "Content-Digest"

    private val MEMBER = Regex("([a-z*][a-z0-9_\\-.*]*)=:([A-Za-z0-9+/]*={0,2}):")

    private fun bytesOf(body: Any?): ByteArray = when (body) {
        is String -> Json.utf8(body)
        is ByteArray -> body
        else -> throw IllegalArgumentException("body must be a string or bytes")
    }

    private fun nodeAlg(alg: String?): String = when (alg) {
        "sha-256" -> "SHA-256"
        "sha-512" -> "SHA-512"
        else -> throw IllegalArgumentException("unsupported algorithm")
    }

    /** The raw digest bytes of [body] (a String, hashed as UTF-8, or ByteArray) under [alg]. */
    @JvmStatic
    fun contentDigestBytes(body: Any?, alg: String?): ByteArray = WbaJs.sha(nodeAlg(alg), bytesOf(body))

    /** The Content-Digest field value, e.g. `sha-256=:X48E9q...=:` (members in the given order, repeats dropped). */
    @JvmStatic
    @JvmOverloads
    fun contentDigestHeader(body: Any?, algs: List<String> = listOf("sha-256")): String {
        if (algs.isEmpty()) throw IllegalArgumentException("contentDigestHeader: name at least one algorithm")
        val seen = HashSet<String>()
        val parts = ArrayList<String>()
        for (alg in algs) {
            if (!CONTENT_DIGEST_ALGS.contains(alg)) throw IllegalArgumentException("contentDigestHeader: unsupported algorithm $alg")
            if (!seen.add(alg)) continue
            parts.add(alg + "=:" + WbaJs.b64(contentDigestBytes(body, alg)) + ":")
        }
        return parts.joinToString(", ")
    }

    /** Parse the dictionary: key to byte sequence. Throws IllegalArgumentException on anything that is not `key=:base64:` (parameters refused). */
    @JvmStatic
    fun parseContentDigest(value: String): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        for (raw in value.split(",")) {
            val member = WbaJs.trim(raw)
            if (member.isEmpty()) throw IllegalArgumentException("empty dictionary member")
            val m = MEMBER.matchEntire(member) ?: throw IllegalArgumentException("malformed Content-Digest member \"$member\"")
            val key = m.groupValues[1]
            val b64 = m.groupValues[2]
            if (b64.length % 4 != 0) throw IllegalArgumentException("member \"$key\" is not canonical base64")
            val bytes = WbaJs.nodeBase64(b64)
            if (WbaJs.b64(bytes) != b64) throw IllegalArgumentException("member \"$key\" is not canonical base64")
            if (out.containsKey(key)) throw IllegalArgumentException("member \"$key\" appears twice")
            out[key] = bytes
        }
        return out
    }

    /**
     * Check [body] against a Content-Digest field value ([header] null = absent). Every supported member present must match; unsupported
     * members are ignored (RFC 9530 section 2); at least one supported member must be present; every algorithm in [require] (null = none) must
     * be among the matched ones. Returns `{valid, reason?, matched?}`; never throws on a bad header.
     */
    @JvmStatic
    @JvmOverloads
    fun verifyContentDigest(header: String?, body: Any?, require: List<String>? = null): Map<String, Any?> {
        return try {
            if (header == null || WbaJs.trim(header).isEmpty()) return fail("missing Content-Digest")
            val members = parseContentDigest(header)
            val matched = ArrayList<Any?>()
            for (alg in CONTENT_DIGEST_ALGS) {
                val got = members[alg] ?: continue
                if (!MessageDigest.isEqual(got, contentDigestBytes(body, alg))) return fail("$alg digest does not match the content")
                matched.add(alg)
            }
            if (matched.isEmpty()) return fail("no supported digest algorithm (sha-256 or sha-512)")
            if (require != null) for (alg in require) if (!matched.contains(alg)) return fail("required $alg digest is absent")
            linkedMapOf("valid" to true, "matched" to matched)
        } catch (e: RuntimeException) {
            fail("malformed Content-Digest: " + e.message)
        }
    }

    private fun fail(reason: String): Map<String, Any?> = linkedMapOf("valid" to false, "reason" to reason)
}
