package net.atlasauth.pca.webbotauth

import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * Signed key-directory responses (draft-meunier-http-message-signatures-directory section 5.2): the directory body is signed with RFC 9421,
 * covering `"@authority";req`, `tag="http-message-signatures-directory"`, `alg="ed25519"`, a `keyid` that is the RFC 7638
 * thumbprint of the signing key, with `created` and `expires`. One signature per key; a client keeps only the keys that have a valid one.
 */
@Suppress("UNCHECKED_CAST")
object SignedDirectory {
    const val DIRECTORY_SIGNATURE_TAG = "http-message-signatures-directory"
    private const val DEFAULT_LIFETIME_SEC = 86_400.0

    private val X = Regex("[A-Za-z0-9_-]{43}")
    private val AUTHORITY = Regex("[a-z0-9.\\-\\[\\]:]+")
    private val ENTRY = Regex("([a-z][a-z0-9_.*-]*)=\\(\"@authority\";req\\)((?:;[a-z]+=(?:[0-9]+|\"[A-Za-z0-9_.\\-]*\"))*)")
    private val SIG = Regex("([a-z][a-z0-9_.*-]*)=:([A-Za-z0-9+/]+={0,2}):")
    private val DIGITS = Regex("[0-9]+")

    private fun malformed(): Nothing = throw IllegalArgumentException("directory contains a malformed key")

    /** Strictly parse a directory document: every key must be a well-formed Ed25519 OKP JWK with a string `kid`. Throws IllegalArgumentException otherwise. */
    @JvmStatic
    fun parseKeyDirectory(text: String): Map<String, Any?> {
        val doc = Json.parseLenient(text)
        val keys = if (doc is Map<*, *>) doc["keys"] else null
        if (keys !is List<*> || keys.isEmpty()) throw IllegalArgumentException("directory has no keys")
        for (k in keys) {
            if (k !is Map<*, *>) malformed()
            val kid = k["kid"]
            if (k["kty"] != "OKP" || k["crv"] != "Ed25519" || kid !is String || kid.isEmpty()) malformed()
            val x = k["x"]
            if (x !is String || !X.matches(x)) malformed()
            for (f in listOf("nbf", "exp")) {
                if (k.containsKey(f)) {
                    val d = Js.num(k[f])
                    if (d == null || d.isNaN() || d.isInfinite()) malformed()
                }
            }
        }
        return doc as Map<String, Any?>
    }

    private fun nowSec(): Double = (System.currentTimeMillis() / 1000).toDouble()

    /**
     * Sign a directory response. [input]: keys (list of signing keys, each a Keys.EdKey or a map with b64u `secretKey` seed), directory
     * (the document to serve, as built by buildKeyDirectory; every signing key must be in it), authority (lower-case host or host:port), created?,
     * expiresInSec?. Returns `{body, headers}`.
     */
    @JvmStatic
    fun signDirectoryResponse(input: Map<String, Any?>): Map<String, Any?> {
        val keysO = input["keys"]
        val keys: List<*> = if (keysO is List<*>) keysO else emptyList<Any?>()
        if (keys.isEmpty()) throw IllegalArgumentException("signDirectoryResponse: at least one signing key is required")
        val authority = input["authority"]
        if (authority !is String || !AUTHORITY.matches(authority)) throw IllegalArgumentException("signDirectoryResponse: authority must be a lower-case host or host:port")
        val created = if (input["created"] != null) WbaJs.number(input["created"]) else nowSec()
        val expires = created + (if (input["expiresInSec"] != null) WbaJs.number(input["expiresInSec"]) else DEFAULT_LIFETIME_SEC)
        val directory = input["directory"]
        val body = Js.stringify(directory)
        val inputs = ArrayList<String>()
        val sigs = ArrayList<String>()
        for ((i, k) in keys.withIndex()) {
            val key = WebBotAuth.edKey(k)
            val x = Keys.b64u(key.pub)
            val dk = WbaJs.get(directory, "keys")
            val found = dk is List<*> && dk.any { x == WbaJs.get(it, "x") }
            if (!found) throw IllegalArgumentException("signDirectoryResponse: a signing key is not in the directory")
            val keyid = WbaJs.thumbprintOfX(x)
            val label = "sig" + (i + 1)
            val params = "(\"@authority\";req);created=" + WbaJs.numStr(created) + ";expires=" + WbaJs.numStr(expires) + ";keyid=\"" + keyid +
                "\";alg=\"ed25519\";tag=\"" + DIRECTORY_SIGNATURE_TAG + "\""
            val base = "\"@authority\";req: " + authority + "\n\"@signature-params\": " + params
            inputs.add("$label=$params")
            sigs.add(label + "=:" + WbaJs.b64(key.sign(Json.utf8(base))) + ":")
        }
        val headers = LinkedHashMap<String, Any?>()
        headers["content-type"] = "application/http-message-signatures-directory+json"
        headers["signature-input"] = inputs.joinToString(", ")
        headers["signature"] = sigs.joinToString(", ")
        return linkedMapOf("body" to body, "headers" to headers)
    }

    private fun fail(reason: String): Map<String, Any?> = linkedMapOf("valid" to false, "reason" to reason, "keys" to ArrayList<Any?>())

    /**
     * Verify a signed directory response. [input]: authority, headers (`signature-input`, `signature`), body, now?, clockSkewSec?,
     * maxLifetimeSec? (default 86400). Fail closed: `{valid:false, reason, keys:[]}` for a missing or malformed signature header, a body that is not a
     * well-formed directory, or when NO signature is valid. When valid, `keys` holds only the directory keys that carry a valid signature.
     */
    @JvmStatic
    fun verifyDirectoryResponse(input: Map<String, Any?>): Map<String, Any?> {
        try {
            val hdrs = input["headers"]
            val sigInputO = WbaJs.get(hdrs, "signature-input")
            val sigHeaderO = WbaJs.get(hdrs, "signature")
            if (!Js.truthy(sigInputO) || !Js.truthy(sigHeaderO)) return fail("missing signature-input or signature header")
            val sigInput = sigInputO as String
            val sigHeader = sigHeaderO as String
            val dir = parseKeyDirectory(input["body"] as String)
            val sigs = HashMap<String, ByteArray>()
            for (part in sigHeader.split(", ")) {
                val m = SIG.matchEntire(part) ?: return fail("malformed signature header")
                sigs[m.groupValues[1]] = WbaJs.nodeBase64(m.groupValues[2])
            }
            val now = if (input["now"] != null) WbaJs.number(input["now"]) else nowSec()
            val skew = if (input["clockSkewSec"] != null) WbaJs.number(input["clockSkewSec"]) else 0.0
            val maxLife = if (input["maxLifetimeSec"] != null) WbaJs.number(input["maxLifetimeSec"]) else DEFAULT_LIFETIME_SEC
            val good = LinkedHashMap<String, Any?>()
            var lastReason = "no signature entry"
            for (raw in sigInput.split(", ")) {
                val m = ENTRY.matchEntire(raw)
                if (m == null) { lastReason = "malformed signature-input entry (must cover exactly \"@authority\";req)"; continue }
                val label = m.groupValues[1]
                val params = HashMap<String, String>()
                var dup = false
                val ps = m.groupValues[2].split(";")
                for (pi in 1 until ps.size) {
                    val p = ps[pi]
                    val eq = p.indexOf('=')
                    val k = p.substring(0, eq)
                    if (params.containsKey(k)) dup = true
                    params[k] = p.substring(eq + 1)
                }
                if (dup) { lastReason = "duplicate signature parameter"; continue }
                if (DIRECTORY_SIGNATURE_TAG != strParam(params, "tag")) { lastReason = "wrong tag"; continue }
                val alg = params["alg"]
                if (alg != null && alg != "\"ed25519\"") { lastReason = "unsupported alg"; continue }
                val created = numParam(params, "created")
                val expires = numParam(params, "expires")
                if (created == null || expires == null) { lastReason = "created and expires are required"; continue }
                if (!(now.isFinite() && skew.isFinite() && created.isFinite() && created <= now + skew)) { lastReason = "signature created-time is in the future"; continue }
                if (!(expires.isFinite() && now <= expires + skew)) { lastReason = "signature has expired"; continue }
                if (!(expires - created <= maxLife)) { lastReason = "signature lifetime exceeds maxLifetimeSec"; continue }
                val keyid = strParam(params, "keyid")
                if (keyid == null) { lastReason = "missing keyid"; continue }
                val key = (dir["keys"] as List<Any?>).firstOrNull { WbaJs.thumbprintOfX((it as Map<String, Any?>)["x"] as String) == keyid } as Map<String, Any?>?
                if (key == null) { lastReason = "keyid is not the thumbprint of any directory key"; continue }
                val nbf = Js.num(key["nbf"])
                val exp = Js.num(key["exp"])
                if ((nbf != null && !(now + skew >= nbf)) || (exp != null && !(now - skew <= exp))) { lastReason = "directory key is outside its validity window"; continue }
                val sig = sigs[label]
                if (sig == null || sig.size != 64) { lastReason = "no valid signature bytes for the label"; continue }
                val base = "\"@authority\";req: " + input["authority"] + "\n\"@signature-params\": " + raw.substring(label.length + 1)
                val pk = WbaJs.nodeBase64(key["x"] as String)
                if (!Jose.verifyEd25519Strict(pk, Json.utf8(base), sig)) { lastReason = "signature does not verify"; continue }
                good[key["kid"] as String] = key
            }
            if (good.isEmpty()) return fail(lastReason)
            return linkedMapOf("valid" to true, "keys" to ArrayList<Any?>(good.values))
        } catch (e: RuntimeException) {
            return fail("verification failed (fail closed): " + e.message)
        }
    }

    private fun strParam(params: Map<String, String>, k: String): String? {
        val v = params[k]
        return if (v != null && v.startsWith("\"")) v.substring(1, v.length - 1) else null
    }

    private fun numParam(params: Map<String, String>, k: String): Double? {
        val v = params[k]
        return if (v != null && DIGITS.matches(v)) v.toDouble() else null
    }
}
