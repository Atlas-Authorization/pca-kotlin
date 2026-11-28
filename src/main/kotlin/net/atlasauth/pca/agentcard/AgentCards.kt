package net.atlasauth.pca.agentcard

import java.util.TimeZone
import net.atlasauth.pca.a2a.A2aCard
import net.atlasauth.pca.a2a.A2aJws
import net.atlasauth.pca.a2a.A2aPca
import net.atlasauth.pca.jose.Jose
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.oauth.WhatwgUrl
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json

/**
 * Signed Agent Card plus AgentFacts attestor for PCA. The card signing surface is the A2A one ([A2aPca]: same canonical bytes, same
 * detached JWS, same `pca_passport` commitment), so a card issued here verifies there and the reverse. This object adds the card
 * builder, the AgentFacts document (self-asserted claims split from third-party attestations, each a detached JWS over a canonical statement),
 * the well-known hosting handlers and the registry entry. Values are parsed JSON (Map, List, String, Boolean, [Json.Num], null);
 * keys are JWK maps. Everything fails closed.
 *
 * Shortcuts: attestation windows parse ISO 8601 only (a string the reference engine would accept through its legacy date fallback is
 * refused here), a date-time with no offset is read in the JVM's zone as the reference engine reads it in its own, and
 * [toRegistryEntry] derives the card URL for http(s) / ws(s) / ftp service URLs without credentials only.
 */
@Suppress("UNCHECKED_CAST")
object AgentCards {
    const val DEFAULT_ALG = "EdDSA"
    const val PCA_ATTESTOR_ID = "did:atlas:pca-attestor"
    const val WELL_KNOWN_AGENT_CARD_PATH = "/.well-known/agent-card.json"
    const val WELL_KNOWN_AGENT_FACTS_PATH = "/.well-known/agent-facts.json"

    /** The `@context` of a PCA AgentFacts document (a PCA profile, not NANDA-conformant). */
    @JvmField
    val AGENT_FACTS_CONTEXT: List<String> = listOf("https://www.w3.org/ns/did/v1", "https://nanda.ai/agentfacts/v1")
    private const val STATEMENT_DOMAIN = "atlas-pca/agentfacts/attestation/v1"
    private val UNDEF = Any()

    /** RFC 8785 canonical bytes (see [A2aCard.jcsBytes]). */
    @JvmStatic
    fun jcsBytes(value: Any?): ByteArray = A2aCard.jcsBytes(value)

    /** The A2A 1.0 `AgentCard` problems (see [A2aCard.validateAgentCard1]). */
    @JvmStatic
    fun validateAgentCard1(card: Any?): List<String> = A2aCard.validateAgentCard1(card)

    // ---- helpers ----

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun isObj(o: Any?) = o is Map<*, *>

    /** `o[k]` as a member read: null for an absent member or a non-object; a null o throws, as a property read on null does. */
    private fun get(o: Any?, k: String): Any? {
        if (o == null) throw IllegalStateException("TypeError: cannot read properties of null (reading '$k')")
        return if (o is Map<*, *>) o[k] else null
    }

    private fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    /** JavaScript `String(v)` for parsed JSON values. */
    internal fun jsStr(v: Any?): String {
        if (v == null) return "null"
        if (v is String) return v
        if (v is Boolean) return v.toString()
        val d = Js.num(v)
        if (d != null) return AttestUtil.jsNumString(d)
        if (v is List<*>) {
            val sb = StringBuilder()
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                if (x != null) sb.append(jsStr(x))
            }
            return sb.toString()
        }
        return "[object Object]"
    }

    // ---- 1. signed Agent Card ----

    /** [hasUri]: the reference tests `uri !== undefined`, so an explicit null counts as given. */
    private fun passportRefFrom(p: Any?, uri: Any?, hasUri: Boolean): Map<String, Any?> {
        if (p !is Map<*, *>) throw IllegalStateException("TypeError: cannot use 'in' operator on a non-object")
        val m = map(p)
        val out = LinkedHashMap<String, Any?>()
        if (m.containsKey("id")) out["id"] = m["id"]
        if (m.containsKey("model_id")) { if (hasUri) out["uri"] = uri }
        else if (m.containsKey("uri")) out["uri"] = m["uri"]
        else if (hasUri) out["uri"] = uri
        return out
    }

    /**
     * Build an (unsigned) Agent Card from a PCA passport (an AgentPassport, or a bare `{id, uri?}`). [opts]: `name`,
     * `skills`, `url`, `description`, `version`, `passportUri`, `pcaProofRef`.
     */
    @JvmStatic
    fun buildAgentCard(passport: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val card = LinkedHashMap<String, Any?>()
        if (opts.containsKey("name")) card["name"] = opts["name"]
        for (k in listOf("description", "url", "version", "skills")) if (opts.containsKey(k)) card[k] = opts[k]
        card["pcaPassport"] = passportRefFrom(passport, opts["passportUri"], opts.containsKey("passportUri"))
        if (opts.containsKey("pcaProofRef")) card["pcaProof"] = opts["pcaProofRef"]
        return card
    }

    /** Sign an Agent Card (wire-identical to [A2aPca.issueSignedAgentCard]). */
    @JvmStatic
    @JvmOverloads
    fun issueSignedAgentCard(card: Any?, signingKey: Map<String, Any?>, opts: A2aPca.IssueOptions = A2aPca.IssueOptions()): Map<String, Any?> =
        A2aPca.issueSignedAgentCard(card, signingKey, opts)

    /**
     * Validate an Agent Card against its signatures (fail-closed): `{ok, reason?, passportRef?, passport?, pcaProof?}`. Wording after the first
     * colon of a library failure is this port's own.
     */
    @JvmStatic
    fun verifyAgentCard(card: Any?, opts: A2aPca.VerifyCardOptions): Map<String, Any?> = A2aPca.verifyCard(card, opts, true)

    // ---- 2. AgentFacts ----

    private fun statementBytes(issuer: Any?, subject: Any?, attests: Any?, validFrom: Any?, validUntil: Any?): ByteArray {
        val m = LinkedHashMap<String, Any?>()
        m["d"] = STATEMENT_DOMAIN
        m["issuer"] = issuer
        m["subject"] = subject
        m["attests"] = attests
        m["validFrom"] = validFrom
        m["validUntil"] = validUntil
        return Json.canonicalizeStrict(m).toByteArray(Charsets.UTF_8)
    }

    private fun signAttestation(issuer: Any?, subject: Any?, attests: Any?, validFrom: Any?, validUntil: Any?, keyO: Any?, alg: Any?, kid: Any?): Map<String, Any?> {
        if (subject === UNDEF || attests === UNDEF) throw IllegalArgumentException("canonicalize: unsupported type undefined")
        val payload = statementBytes(issuer, subject, attests, validFrom, if (validUntil === UNDEF) null else validUntil)
        val header = LinkedHashMap<String, Any?>()
        header["attestor"] = issuer
        val sig = A2aJws.signDetached(payload, map(keyO), (alg as String?) ?: DEFAULT_ALG, kid as String?, false, header)
        val out = LinkedHashMap<String, Any?>()
        out["issuer"] = issuer
        out["subject"] = subject
        out["attests"] = attests
        out["validFrom"] = validFrom
        if (validUntil !== UNDEF) out["validUntil"] = validUntil
        out["signature"] = sig
        return out
    }

    private fun validFromOf(opts: Map<String, Any?>): Any? =
        if (opts["validFrom"] != null) opts["validFrom"] else A2aPca.toIsoString(if (opts["now"] != null) opts["now"] else System.currentTimeMillis())

    /**
     * Issue an AgentFacts document for a passport with PCA as the third-party attestor. [opts]: `attestorKey` (a private JWK),
     * `attests`, `selfAsserted`, `attestorId`, `agentId`, `alg`, `kid`, `validFrom`, `validUntil`, `now`,
     * `context`. The self-asserted claims are echoed verbatim and never signed.
     */
    @JvmStatic
    fun issueAgentFacts(passport: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val agentId: Any? = if (opts["agentId"] != null) opts["agentId"] else (if (has(passport, "id")) get(passport, "id") else idOrUndef(passport))
        val validFrom = validFromOf(opts)
        val issuer: Any? = if (opts["attestorId"] != null) opts["attestorId"] else PCA_ATTESTOR_ID
        val att = signAttestation(issuer, agentId, if (opts.containsKey("attests")) opts["attests"] else UNDEF, validFrom,
            if (opts.containsKey("validUntil")) opts["validUntil"] else UNDEF, opts["attestorKey"], opts["alg"], opts["kid"])
        val out = LinkedHashMap<String, Any?>()
        out["@context"] = if (opts["context"] != null) opts["context"] else ArrayList<Any?>(AGENT_FACTS_CONTEXT)
        out["id"] = agentId
        out["type"] = "AgentFacts"
        out["selfAsserted"] = if (opts["selfAsserted"] != null) opts["selfAsserted"] else LinkedHashMap<String, Any?>()
        out["attestations"] = arrayListOf<Any?>(att)
        return out
    }

    /** `passport.id` when it is absent: a null passport throws (property read on null), anything else reads undefined. */
    private fun idOrUndef(passport: Any?): Any? {
        get(passport, "id")
        return UNDEF
    }

    /** Append another third-party attestation to an AgentFacts document (a copy; the input is not mutated). [opts] as [issueAgentFacts]. */
    @JvmStatic
    fun addAttestation(facts: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val validFrom = validFromOf(opts)
        val issuer: Any? = if (opts["attestorId"] != null) opts["attestorId"] else PCA_ATTESTOR_ID
        val subject: Any? = if (has(facts, "id")) get(facts, "id") else UNDEF
        val att = signAttestation(issuer, subject, if (opts.containsKey("attests")) opts["attests"] else UNDEF, validFrom,
            if (opts.containsKey("validUntil")) opts["validUntil"] else UNDEF, opts["attestorKey"], opts["alg"], opts["kid"])
        val out = A2aPca.spread(facts)
        val existing = get(facts, "attestations")
        val l = ArrayList<Any?>()
        if (existing is List<*>) l.addAll(existing)
        else if (existing is String) {
            var i = 0
            while (i < existing.length) {
                val cp = existing.codePointAt(i)
                l.add(String(Character.toChars(cp)))
                i += Character.charCount(cp)
            }
        } else throw IllegalStateException("TypeError: facts.attestations is not iterable")
        l.add(att)
        out["attestations"] = l
        return out
    }

    private fun check(issuer: Any?, ok: Boolean, reason: String?): LinkedHashMap<String, Any?> {
        val c = LinkedHashMap<String, Any?>()
        c["issuer"] = issuer
        c["ok"] = ok
        if (reason != null) c["reason"] = reason
        return c
    }

    private fun issuerOf(a: Any?): Any? = if (a is Map<*, *> && a["issuer"] is String) a["issuer"] else "<unknown>"

    private val ISO = Regex("^([+-]\\d{6}|\\d{4})(?:-(\\d{2})(?:-(\\d{2}))?)?(?:T(\\d{2}):(\\d{2})(?::(\\d{2})(?:\\.(\\d+))?)?(Z|[+-]\\d{2}:\\d{2})?)?$")

    /** Days since 1970-01-01 of a proleptic Gregorian date. */
    private fun daysFromCivil(y0: Long, m: Long, d: Long): Long {
        val y = if (m <= 2) y0 - 1 else y0
        val era = Math.floorDiv(y, 400L)
        val yoe = y - era * 400
        val mp = (m + 9) % 12
        val doy = (153 * mp + 2) / 5 + d - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }

    /** `Date.parse`: epoch ms, or NaN. ISO 8601 only (see the object note). */
    @JvmStatic
    fun parseDate(sO: Any?): Double {
        if (sO !is String) return Double.NaN
        val m = ISO.matchEntire(sO) ?: return Double.NaN
        try {
            val g = m.groups
            val ys = g[1]!!.value
            if (ys == "-000000") return Double.NaN
            val y = (if (ys.startsWith("+")) ys.substring(1) else ys).toInt()
            val mo = if (g[2] == null) 1 else g[2]!!.value.toInt()
            val d = if (g[3] == null) 1 else g[3]!!.value.toInt()
            val timed = g[4] != null
            val hh = if (timed) g[4]!!.value.toInt() else 0
            val mi = if (timed) g[5]!!.value.toInt() else 0
            val ss = if (g[6] == null) 0 else g[6]!!.value.toInt()
            val ms = if (g[7] == null) 0 else (g[7]!!.value + "00").substring(0, 3).toInt()
            if (mo < 1 || mo > 12 || d < 1 || d > 31 || mi > 59 || ss > 59 || hh > 24 || (hh == 24 && (mi != 0 || ss != 0 || ms != 0))) return Double.NaN
            // a day past the month's end rolls into the next month, as the reference engine reads it (2026-02-30 is March 2)
            val secs = (daysFromCivil(y.toLong(), mo.toLong(), 1L) + (d - 1)) * 86400L + hh * 3600L + mi * 60L + ss
            val z = g[8]?.value
            val epoch: Long
            if (z == "Z") epoch = secs
            else if (z != null) {
                val sign = if (z[0] == '-') -1 else 1
                val oh = z.substring(1, 3).toInt()
                val om = z.substring(4, 6).toInt()
                if (oh > 23 || om > 59) return Double.NaN
                epoch = secs - sign * (oh * 3600L + om * 60L)
            } else if (!timed) epoch = secs // date-only forms are UTC
            else { // date-time forms with no offset are local time
                val tz = TimeZone.getDefault()
                val guess = secs * 1000L - tz.getOffset(secs * 1000L)
                epoch = secs - tz.getOffset(guess) / 1000L
            }
            val v = epoch * 1000.0 + ms
            return if (Math.abs(v) > 8.64e15) Double.NaN else v
        } catch (e: RuntimeException) {
            return Double.NaN
        }
    }

    private fun verifyOne(a: Any?, docId: Any?, now: Double, resolver: A2aJws.Resolver?): Map<String, Any?> {
        val issuer = issuerOf(a)
        if (!Js.truthy(a) || get(a, "subject") !is String || !isObj(get(a, "attests")) || get(a, "validFrom") !is String)
            return check(issuer, false, "attestation is malformed")
        val subject = get(a, "subject") as String
        if (docId !is String || subject != docId) return check(issuer, false, "attestation subject '$subject' does not match agent id '${jsStr(docId)}'")
        val from = parseDate(get(a, "validFrom"))
        if (from.isNaN()) return check(issuer, false, "attestation validFrom is not a valid date")
        if (!(now.isFinite() && now >= from)) return check(issuer, false, "attestation is not yet valid")
        if (has(a, "validUntil")) {
            val until = parseDate(get(a, "validUntil"))
            if (until.isNaN()) return check(issuer, false, "attestation validUntil is not a valid date")
            if (!(now <= until)) return check(issuer, false, "attestation has expired")
        }
        if (resolver == null) return check(issuer, false, "no verification key or JWKS supplied")
        // the statement bytes are computed outside the verify guard in the reference: no canonical form is an error, not a refusal
        val payload = statementBytes(if (has(a, "issuer")) get(a, "issuer") else UNDEF, subject, get(a, "attests"), get(a, "validFrom"), if (has(a, "validUntil")) get(a, "validUntil") else null)
        if (get(a, "signature") == null) throw IllegalStateException("TypeError: cannot read properties of undefined (reading 'protected')")
        val r = A2aJws.verifyDetached(payload, get(a, "signature"), resolver)
        if (!r.ok) return check(issuer, false, "signature did not verify: ${r.reason}")
        val ok = check(issuer, true, null)
        ok["attests"] = get(a, "attests")
        return ok
    }

    /**
     * Verify an AgentFacts document, fail-closed: a wrong subject, a closed or malformed validity window, or a signature that does not verify refuses
     * that attestation, and any refused attestation refuses the document. [opts]: `jwks` / `key` / `alg` / `now`. The result
     * marks which claims are third-party attested and which merely self-asserted: `{ok, reason?, agentId, attestations[], attested, selfAsserted, claims}`.
     */
    @JvmStatic
    fun verifyAgentFacts(facts: Any?, opts: Map<String, Any?>): Map<String, Any?> {
        val saO = get(facts, "selfAsserted")
        val selfAsserted: Map<String, Any?> = if (isObj(saO)) map(saO) else LinkedHashMap()
        val nowO = opts["now"]
        val now: Double = if (nowO != null) (Js.num(nowO) ?: Double.NaN) else System.currentTimeMillis().toDouble()
        val listO = get(facts, "attestations")
        val hasId = has(facts, "id")
        val id = get(facts, "id")
        if (listO !is List<*>) return result(false, "agent facts has no attestations array", hasId, id, ArrayList(), LinkedHashMap(), selfAsserted, LinkedHashMap())
        val list = listO as List<Any?>
        var resolver: A2aJws.Resolver? = null
        if (list.isNotEmpty()) {
            val res = A2aJws.resolveVerifyKey(opts["jwks"], opts["key"], opts["alg"] as String?)
            if (res.error != null) {
                val missing = ArrayList<Any?>()
                for (a in list) missing.add(check(issuerOf(a), false, "no verification key or JWKS supplied"))
                return result(false, res.error, hasId, id, missing, LinkedHashMap(), selfAsserted, LinkedHashMap())
            }
            resolver = res.resolver
        }
        val checks = ArrayList<Any?>()
        val attested = LinkedHashMap<String, Any?>()
        var allOk = true
        for (a in list) {
            val c = verifyOne(a, id, now, resolver)
            checks.add(c)
            if (c["ok"] != true) { allOk = false; continue }
            val at = c["attests"]
            if (isObj(at)) attested.putAll(map(at))
        }
        val claims = LinkedHashMap<String, Any?>()
        for (k in selfAsserted.keys) claims[k] = "self-asserted"
        for (k in attested.keys) claims[k] = "attested" // attested wins on overlap
        return result(allOk, if (allOk) null else "one or more attestations did not verify", hasId, id, checks, attested, selfAsserted, claims)
    }

    private fun result(ok: Boolean, reason: String?, hasId: Boolean, id: Any?, checks: List<Any?>, attested: Map<String, Any?>, self: Map<String, Any?>, claims: Map<String, Any?>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        out["ok"] = ok
        if (reason != null) out["reason"] = reason
        if (hasId) out["agentId"] = id
        out["attestations"] = checks
        out["attested"] = attested
        out["selfAsserted"] = self
        out["claims"] = claims
        return out
    }

    // ---- 3. well-known hosting ----

    /** A path handler: a request path in, the response `{status, headers, body}` out, or null when the path is not this handler's. */
    fun interface PathHandler {
        fun apply(path: String): Map<String, Any?>?
    }

    private fun jsonResponse(value: Any?): Map<String, Any?> {
        val headers = LinkedHashMap<String, Any?>()
        headers["content-type"] = "application/json"
        headers["cache-control"] = "no-store"
        val r = LinkedHashMap<String, Any?>()
        r["status"] = Json.Num("200")
        r["headers"] = headers
        r["body"] = Jose.stringify(value)
        return r
    }

    private fun normalizePath(path: String): String {
        val q = path.indexOf('?')
        val noQuery = if (q == -1) path else path.substring(0, q)
        return if (noQuery.length > 1 && noQuery.endsWith("/")) noQuery.substring(0, noQuery.length - 1) else noQuery
    }

    /** Serve a signed Agent Card at [path] (null: [WELL_KNOWN_AGENT_CARD_PATH]); the handler returns null for any other path. */
    @JvmStatic
    @JvmOverloads
    fun agentCardHandler(card: Any?, path: String? = null): PathHandler {
        val target = normalizePath(path ?: WELL_KNOWN_AGENT_CARD_PATH)
        val response = jsonResponse(card)
        return PathHandler { reqPath -> if (normalizePath(reqPath) == target) response else null }
    }

    /** Serve an AgentFacts document at [path] (null: [WELL_KNOWN_AGENT_FACTS_PATH]); the handler returns null for any other path. */
    @JvmStatic
    @JvmOverloads
    fun agentFactsHandler(facts: Any?, path: String? = null): PathHandler {
        val target = normalizePath(path ?: WELL_KNOWN_AGENT_FACTS_PATH)
        val response = jsonResponse(facts)
        return PathHandler { reqPath -> if (normalizePath(reqPath) == target) response else null }
    }

    // ---- 4. registry entry ----

    private fun wellKnownUrlFrom(serviceUrl: Any?, path: String): String? {
        if (serviceUrl !is String) return null
        return try {
            val u = WhatwgUrl.parse(serviceUrl) ?: return null
            val p = u.protocol
            if (!(p == "http:" || p == "https:" || p == "ws:" || p == "wss:" || p == "ftp:")) return null
            p + "//" + u.host + (if (u.port.isEmpty()) "" else ":" + u.port) + path
        } catch (e: RuntimeException) {
            null
        }
    }

    /**
     * Shape a registry entry from a signed card and an AgentFacts document (purely structural: it does NOT re-verify). Derives which advertised claim
     * names a third party attests and which are only self-asserted.
     */
    @JvmStatic
    fun toRegistryEntry(card: Any?, facts: Any?): Map<String, Any?> {
        val attestedSet = LinkedHashSet<String>()
        val atts = get(facts, "attestations")
        if (atts != null) {
            if (atts !is List<*> && atts !is String) throw IllegalStateException("TypeError: not iterable")
            if (atts is List<*>) for (a in atts) if (Js.truthy(a) && isObj(get(a, "attests"))) attestedSet.addAll(map(get(a, "attests")).keys)
        }
        val saO = get(facts, "selfAsserted")
        val selfOnly = ArrayList<Any?>()
        if (isObj(saO)) for (k in map(saO).keys) if (k !in attestedSet) selfOnly.add(k)
        val cardUrl = wellKnownUrlFrom(get(card, "url"), WELL_KNOWN_AGENT_CARD_PATH)
        val out = LinkedHashMap<String, Any?>()
        if (has(facts, "id")) out["id"] = get(facts, "id")
        if (has(card, "name")) out["name"] = get(card, "name")
        for (k in listOf("url", "version", "skills")) if (has(card, k)) out[k] = get(card, k)
        if (Js.truthy(get(card, "pcaPassport"))) out["passport"] = get(card, "pcaPassport")
        if (Js.truthy(get(card, "pcaProof"))) out["pcaProof"] = get(card, "pcaProof")
        out["card"] = card
        if (cardUrl != null) out["agentCardUrl"] = cardUrl
        out["facts"] = facts
        out["attestedClaims"] = ArrayList<Any?>(attestedSet)
        out["selfAssertedClaims"] = selfOnly
        return out
    }
}
