package net.atlasauth.pca.scim

import java.math.BigInteger
import java.util.Locale
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * SCIM 2.0 provisioning for Proof-Carrying Authority agents: the passport registry exposed as a SCIM `/Agents` resource server
 * ([scimHandler]) and outbound push-provisioning bodies for Microsoft Entra Agent ID and Okta.
 *
 * Resources, projections, requests and bodies are plain JSON values (Map / List / String / Boolean / [Json.Num] / null), mirroring the
 * reference package; a malformed write body is answered with a SCIM error response, never a partial write.
 * shortcut: PATCH object keys keep JSON order (a JavaScript object lists integer-like keys first), and list paging beyond 2^53 is not exact.
 */
@Suppress("UNCHECKED_CAST")
object Scim {
    const val AGENT_SCHEMA_URN = "urn:ietf:params:scim:schemas:atlas:2.0:Agent"
    const val LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    const val PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
    const val ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
    const val AGENT_RESOURCE_TYPE = "Agent"
    const val ENTRA_AGENT_EXTENSION_URN = "urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent"
    const val OKTA_AGENT_EXTENSION_URN = "urn:okta:scim:schemas:custom:1.0:Agent"
    private const val SCIM_CONTENT_TYPE = "application/scim+json"

    // ---- JavaScript-flavoured value readers ----

    private fun asRecord(v: Any?) = v as? Map<String, Any?>
    private fun asString(v: Any?) = v as? String
    private fun asBoolean(v: Any?): Boolean? = when (v) {
        is Boolean -> v
        "true" -> true
        "false" -> false
        else -> null
    }
    private fun asStringArray(v: Any?): List<String>? = if (v is List<*> && v.all { it is String }) v as List<String> else null

    /** A thrown value error carrying the SCIM `scimType`. */
    class ScimValueException(val scimType: String, detail: String) : RuntimeException(detail)

    // ---- Passport <-> SCIM mapping ----

    /** `new Date(ms).toISOString()` for years 0000-9999 (no java.time: Android API 24). */
    private fun isoAt(now: () -> Long): String {
        val ms = now()
        if (ms < -62167219200000L || ms > 253402300799999L) throw IllegalArgumentException("invalid time value") // shortcut: years 0000-9999 only
        val days = Math.floorDiv(ms, 86_400_000L)
        val rem = Math.floorMod(ms, 86_400_000L)
        // civil-from-days (H. Hinnant)
        val z = days + 719468
        val era = z / 146097
        val doe = z - era * 146097
        val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
        val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        val mp = (5 * doy + 2) / 153
        val d = doy - (153 * mp + 2) / 5 + 1
        val m = if (mp < 10) mp + 3 else mp - 9
        val y = yoe + era * 400 + if (m <= 2) 1 else 0
        return String.format(Locale.ROOT, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", y, m, d, rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000)
    }

    private fun trimTrailingSlash(s: String) = s.trimEnd('/')

    /** `encodeURIComponent`: throws on a lone surrogate like the JavaScript URIError. */
    internal fun encodeUriComponent(s: String): String {
        if (Json.hasLoneSurrogate(s)) throw IllegalArgumentException("URI malformed")
        val sb = StringBuilder()
        for (x in Json.utf8(s)) {
            val c = x.toInt() and 0xff
            if (c in 'A'.code..'Z'.code || c in 'a'.code..'z'.code || c in '0'.code..'9'.code || "-_.!~*'()".indexOf(c.toChar()) >= 0) sb.append(c.toChar())
            else sb.append('%').append("0123456789ABCDEF"[c shr 4]).append("0123456789ABCDEF"[c and 15])
        }
        return sb.toString()
    }

    /** Inputs for the SCIM `meta` block: any member may be null (defaults to the clock). */
    class MetaInput(var baseUrl: String? = null, var created: String? = null, var lastModified: String? = null, var now: (() -> Long)? = null) {
        companion object {
            /** From a JSON object {baseUrl?, created?, lastModified?}; `now` is given separately. */
            @JvmStatic
            fun of(m: Map<String, Any?>?, now: (() -> Long)?) = MetaInput(asString(m?.get("baseUrl")), asString(m?.get("created")), asString(m?.get("lastModified")), now)
        }
    }

    private fun buildMeta(id: String, resourceSansMeta: Map<String, Any?>, input: MetaInput): Map<String, Any?> {
        val now = input.now ?: { System.currentTimeMillis() }
        val location = (input.baseUrl?.let { trimTrailingSlash(it) } ?: "") + "/Agents/" + encodeUriComponent(id)
        return linkedMapOf(
            "resourceType" to AGENT_RESOURCE_TYPE, "created" to (input.created ?: isoAt(now)), "lastModified" to (input.lastModified ?: isoAt(now)),
            "location" to location, "version" to "W/\"" + Pca.hashCanonical(resourceSansMeta) + "\"",
        )
    }

    private fun present(m: Map<String, Any?>, k: String) = if (m.containsKey(k)) Js.template(m[k]) else "undefined"

    /** Project a passport and its governance attributes into a SCIM `Agent` resource (its content id is the immutable id). */
    @JvmStatic
    fun passportToScim(passport: Map<String, Any?>, proj: Map<String, Any?>, meta: MetaInput?): Map<String, Any?> {
        val base = LinkedHashMap<String, Any?>()
        base["schemas"] = arrayListOf<Any?>(AGENT_SCHEMA_URN)
        base["id"] = passport["id"]
        base["displayName"] = proj["displayName"] ?: (present(passport, "model_id") + " (" + present(passport, "operator") + ")")
        base["active"] = proj["active"] ?: true
        // the reference always writes owner: an absent one is undefined, which the version digest's canonicalize refuses
        if (!proj.containsKey("owner")) throw IllegalArgumentException("canonicalize: unsupported type undefined")
        base["owner"] = proj["owner"]
        base["capabilities"] = (proj["capabilities"] as? List<*>)?.let { ArrayList<Any?>(it) } ?: ArrayList<Any?>()
        base["passportRef"] = passport["id"]
        base["passport"] = passport
        if (proj.containsKey("externalId")) base["externalId"] = proj["externalId"]
        if (proj.containsKey("holder")) base["holder"] = proj["holder"]
        val out = LinkedHashMap<String, Any?>(base)
        out["meta"] = buildMeta(passport["id"].toString(), base, meta ?: MetaInput())
        return out
    }

    /** The passport identity to register plus the governance projection, distilled from a SCIM write body. */
    class ProvisioningRequest internal constructor(val identity: Map<String, Any?>, val projection: Map<String, Any?>)

    private val DIGESTS = listOf("weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement")

    private fun readIdentity(body: Map<String, Any?>): Map<String, Any?> {
        val nested = asRecord(body["passport"])
        if (nested != null) {
            val modelId = asString(nested["model_id"])
            val operator = asString(nested["operator"])
            if (modelId == null || operator == null) throw ScimValueException("invalidValue", "passport.model_id and passport.operator are required")
            val id = linkedMapOf<String, Any?>("model_id" to modelId, "operator" to operator, "hardware_rooted" to (asBoolean(nested["hardware_rooted"]) ?: false))
            val iat = nested["issued_at"]
            id["issued_at"] = if (Js.isNumber(iat)) iat else Json.Num("0")
            for (k in DIGESTS) asString(nested[k])?.let { id[k] = it }
            asBoolean(nested["weights_measured"])?.let { id["weights_measured"] = it }
            return id
        }
        val modelId = asString(body["model"]) ?: asString(body["model_id"])
        val operator = asString(body["operator"])
        if (modelId == null || operator == null) throw ScimValueException("invalidValue", "an Agent requires either a `passport` object or `model` + `operator`")
        return linkedMapOf("model_id" to modelId, "operator" to operator, "hardware_rooted" to (asBoolean(body["hardwareRooted"]) ?: false), "issued_at" to Json.Num("0"))
    }

    private fun readProjection(body: Map<String, Any?>): MutableMap<String, Any?> {
        val owner = asString(body["owner"]) ?: asString(body["operator"]) ?: asString(asRecord(body["passport"])?.get("operator")) ?: ""
        val proj = linkedMapOf<String, Any?>("owner" to owner)
        asString(body["displayName"])?.let { proj["displayName"] = it }
        asString(body["externalId"])?.let { proj["externalId"] = it }
        asBoolean(body["active"])?.let { proj["active"] = it }
        asStringArray(body["capabilities"])?.let { proj["capabilities"] = it }
        asString(body["holder"])?.let { proj["holder"] = it }
        return proj
    }

    /**
     * Distil a SCIM Agent write body (an untrusted value) into a [ProvisioningRequest]. Accepts the lossless nested-passport form and a
     * flat IdP form. Throws [ScimValueException] on a malformed body.
     */
    @JvmStatic
    fun scimToProvisioningRequest(value: Any?): ProvisioningRequest {
        val body = asRecord(value) ?: throw ScimValueException("invalidSyntax", "request body must be a JSON object")
        if (body.containsKey("schemas")) {
            val s = body["schemas"]
            if (!(s is List<*> && s.contains(AGENT_SCHEMA_URN))) throw ScimValueException("invalidValue", "schemas must include $AGENT_SCHEMA_URN")
        }
        return ProvisioningRequest(readIdentity(body), readProjection(body))
    }

    // ---- store ----

    /** A stored agent: its materialized SCIM resource plus the backing passport. */
    class StoredAgent(val resource: Map<String, Any?>, val passport: Map<String, Any?>)

    /** A read-only passport-registry view. */
    interface PassportRegistry {
        fun get(id: String): Map<String, Any?>?
        fun has(id: String): Boolean
        fun all(): List<Map<String, Any?>>
    }

    /** The passport registry over [passports], later entries replacing earlier ones by id (insertion order kept). */
    @JvmStatic
    fun buildRegistry(passports: List<Map<String, Any?>>): PassportRegistry {
        val byId = LinkedHashMap<String, Map<String, Any?>>()
        for (p in passports) byId[p["id"].toString()] = p
        return object : PassportRegistry {
            override fun get(id: String) = byId[id]
            override fun has(id: String) = byId.containsKey(id)
            override fun all() = ArrayList(byId.values)
        }
    }

    /** Fill `id` from the fingerprint of the identity fields. */
    @JvmStatic fun issuePassport(identity: Map<String, Any?>): Map<String, Any?> = Issue.issuePassport(identity)

    /** The content fingerprint of a passport identity. */
    @JvmStatic fun passportFingerprint(identity: Map<String, Any?>): String = Issue.passportFingerprint(identity)

    /** The persistence seam the SCIM server writes through. */
    interface AgentStore {
        fun all(): List<StoredAgent>
        fun get(id: String): StoredAgent?
        fun put(stored: StoredAgent)
        fun delete(id: String): Boolean
        fun registry(): PassportRegistry
    }

    /** The default in-memory store; insertion order is preserved for stable list output. */
    @JvmStatic
    @JvmOverloads
    fun createMemoryStore(seed: List<StoredAgent> = emptyList()): AgentStore {
        val byId = LinkedHashMap<String, StoredAgent>()
        for (s in seed) byId[s.resource["id"].toString()] = s
        return object : AgentStore {
            override fun all() = ArrayList(byId.values)
            override fun get(id: String) = byId[id]
            override fun put(stored: StoredAgent) { byId[stored.resource["id"].toString()] = stored }
            override fun delete(id: String) = byId.remove(id) != null
            override fun registry() = buildRegistry(byId.values.map { it.passport })
        }
    }

    // ---- envelopes ----

    /** A SCIM error body (`status` is a string; `scimType` is omitted when null). */
    @JvmStatic
    fun scimError(status: Int, detail: String, scimType: String?): Map<String, Any?> {
        val b = linkedMapOf<String, Any?>("schemas" to arrayListOf<Any?>(ERROR_SCHEMA), "status" to status.toString())
        if (scimType != null) b["scimType"] = scimType
        b["detail"] = detail
        return b
    }

    /** A SCIM ListResponse over an already-paginated page of resources. */
    @JvmStatic
    fun scimListResponse(resources: List<Map<String, Any?>>, totalResults: Long, startIndex: Long): Map<String, Any?> = scimListResponse(resources, totalResults, startIndex.toDouble())

    /** As above with a startIndex that is any JS number (a huge one stays in exponent form). */
    @JvmStatic
    fun scimListResponse(resources: List<Map<String, Any?>>, totalResults: Long, startIndex: Double): Map<String, Any?> = linkedMapOf(
        "schemas" to arrayListOf<Any?>(LIST_RESPONSE_SCHEMA), "totalResults" to Js.n(totalResults), "startIndex" to Js.jsNum(startIndex),
        "itemsPerPage" to Js.n(resources.size.toLong()), "Resources" to ArrayList<Any?>(resources),
    )

    // ---- filter ----

    private const val WS = "[\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]"
    private const val DOT = "[^\\n\\r\\u2028\\u2029]"
    private val FILTER = Regex(
        "^$WS*([A-Za-z0-9_]+)$WS+eq$WS+(?:\"((?:[^\"\\\\]++|\\\\$DOT)*+)\"|(true|false))$WS*$",
        RegexOption.IGNORE_CASE,
    )
    private val UNESCAPE = Regex("\\\\($DOT)")
    private val FILTERABLE = setOf("userName", "displayName", "externalId", "id", "active", "owner")

    /** A parsed `attr eq value` filter; `value` is a String or Boolean. */
    class EqFilter internal constructor(val attr: String, val value: Any)

    /** Parse the SCIM `attr eq "value"` / `attr eq true|false` subset. Throws [ScimValueException]. */
    @JvmStatic
    fun parseFilter(filter: Any?): EqFilter {
        val f = filter as? String ?: throw ScimValueException("invalidFilter", "filter must be a string")
        val m = FILTER.matchEntire(f) ?: throw ScimValueException("invalidFilter", "unsupported filter (only `attr eq \"value\"` is supported): $f")
        val attr = m.groupValues[1]
        if (attr !in FILTERABLE) throw ScimValueException("invalidFilter", "filter attribute not supported: $attr")
        m.groups[3]?.let { return EqFilter(attr, it.value.lowercase(Locale.ROOT) == "true") }
        return EqFilter(attr, UNESCAPE.replace(m.groups[2]?.value ?: "", "$1"))
    }

    private fun matchesFilter(agent: Map<String, Any?>, f: EqFilter): Boolean = when (f.attr) {
        "userName", "displayName" -> f.value == agent["displayName"]
        "externalId", "id", "owner", "active" -> f.value == agent[f.attr]
        else -> false
    }

    // ---- PATCH ----

    private val MUTABLE_PATHS = setOf("active", "displayName", "externalId", "owner", "capabilities", "holder")

    private class PatchOp(val op: String, val path: String?, val hasValue: Boolean, val value: Any?)

    private fun readPatchOps(value: Any?): List<PatchOp> {
        val body = asRecord(value) ?: throw ScimValueException("invalidSyntax", "PATCH body must be a JSON object")
        val ops = body["Operations"]
        if (ops !is List<*> || ops.isEmpty()) throw ScimValueException("invalidValue", "PATCH requires a non-empty Operations array")
        return ops.map { raw ->
            val o = asRecord(raw)
            val op = asString(o?.get("op"))?.lowercase(Locale.ROOT)
            if (op != "add" && op != "replace" && op != "remove") {
                throw ScimValueException("invalidValue", "unsupported PATCH op: " + if (o == null || !o.containsKey("op")) "undefined" else Js.template(o["op"]))
            }
            PatchOp(op, asString(o?.get("path")), o != null && o.containsKey("value"), o?.get("value"))
        }
    }

    private fun projectionOf(resource: Map<String, Any?>): MutableMap<String, Any?> {
        val proj = linkedMapOf<String, Any?>("owner" to resource["owner"], "active" to resource["active"], "capabilities" to ArrayList(resource["capabilities"] as List<*>))
        for (k in listOf("displayName", "externalId", "holder")) if (resource[k] != null) proj[k] = resource[k]
        return proj
    }

    private fun applyScalar(proj: MutableMap<String, Any?>, path: String, op: String, value: Any?) {
        if (path == "active") {
            proj["active"] = if (op == "remove") true else asBoolean(value) ?: throw ScimValueException("invalidValue", "`active` must be a boolean")
            return
        }
        if (path == "capabilities") {
            if (op == "remove") {
                proj["capabilities"] = ArrayList<Any?>()
                return
            }
            val arr = asStringArray(value) ?: throw ScimValueException("invalidValue", "`capabilities` must be a string array")
            val next = ArrayList<Any?>()
            if (op == "add") (proj["capabilities"] as? List<*>)?.let { next.addAll(it) }
            next.addAll(arr)
            proj["capabilities"] = next
            return
        }
        if (op == "remove") {
            if (path == "displayName" || path == "owner") throw ScimValueException("mutability", "`$path` cannot be removed")
            if (path == "externalId" || path == "holder") proj.remove(path)
            return
        }
        proj[path] = asString(value) ?: throw ScimValueException("invalidValue", "`$path` must be a string")
    }

    private fun applyPatchOp(proj: MutableMap<String, Any?>, op: PatchOp) {
        if (op.path == null) {
            if (op.op == "remove") throw ScimValueException("noTarget", "a `remove` op requires a `path`")
            val obj = asRecord(if (op.hasValue) op.value else null) ?: throw ScimValueException("invalidValue", "a pathless PATCH value must be an object")
            for (key in ArrayList(obj.keys)) {
                if (key !in MUTABLE_PATHS) throw ScimValueException("mutability", "attribute is immutable or unknown: $key")
                applyScalar(proj, key, "replace", obj[key])
            }
            return
        }
        if (op.path !in MUTABLE_PATHS) throw ScimValueException("mutability", "attribute is immutable or unknown: ${op.path}")
        applyScalar(proj, op.path, op.op, if (op.hasValue) op.value else null)
    }

    // ---- server ----

    /** The subset of an inbound HTTP request the handler needs, already routed under `/Agents`. */
    class ScimRequest @JvmOverloads constructor(var method: String? = null, var id: String? = null, var query: Map<String, Any?>? = null, var body: Any? = null)

    /** The handler's response: status, a JSON body (null when there is none) and headers. */
    class ScimResponse(val status: Int, val body: Any?, val headers: Map<String, String>) {
        /** `{status, body, headers}` as a JSON object. */
        fun toJson(): Map<String, Any?> {
            val m = linkedMapOf<String, Any?>("status" to Js.n(status.toLong()))
            if (body != null) m["body"] = body // an undefined body is dropped by JSON
            m["headers"] = LinkedHashMap<String, Any?>(headers)
            return m
        }
    }

    /** Authenticate and authorize a request; the handler admits it only on exactly `true` (a throw or any other value is a 401). */
    fun interface Authenticator { fun authenticate(req: ScimRequest): Any? }

    /** A SCIM handler: one request in, one response out. */
    fun interface ScimHandler { fun handle(req: ScimRequest): ScimResponse }

    class ScimHandlerOptions(
        var baseUrl: String? = null, var now: (() -> Long)? = null, var authenticate: Authenticator? = null, var allowUnauthenticated: Boolean = false,
    )

    private fun jsonResponse(status: Int, body: Any?, extra: Map<String, String>? = null): ScimResponse {
        val h = linkedMapOf("content-type" to SCIM_CONTENT_TYPE)
        if (extra != null) h.putAll(extra)
        return ScimResponse(status, body, h)
    }

    private fun errorResponse(status: Int, detail: String, scimType: String? = null) = jsonResponse(status, scimError(status, detail, scimType))

    private fun resourceResponse(status: Int, resource: Map<String, Any?>): ScimResponse {
        val meta = resource["meta"] as Map<String, Any?>
        return jsonResponse(status, resource, linkedMapOf("location" to meta["location"] as String, "etag" to meta["version"] as String))
    }

    private val TRIM = Regex("^$WS+|$WS+$")

    /** JavaScript `Number(v)` of a query value (string / number / null), as a double. */
    internal fun toNumber(v: Any?): Double {
        if (v == null) return 0.0
        Js.num(v)?.let { return it }
        if (v is Boolean) return if (v) 1.0 else 0.0
        if (v is List<*>) return toNumber(Js.template(v)) // Number([2]) is Number("2")
        if (v !is String) return Double.NaN
        val s = TRIM.replace(v, "")
        if (s.isEmpty()) return 0.0
        return try {
            when {
                s.matches(Regex("0[xX][0-9a-fA-F]+")) -> BigInteger(s.substring(2), 16).toDouble()
                s.matches(Regex("0[oO][0-7]+")) -> BigInteger(s.substring(2), 8).toDouble()
                s.matches(Regex("0[bB][01]+")) -> BigInteger(s.substring(2), 2).toDouble()
                s.matches(Regex("[+-]?Infinity")) -> if (s.startsWith("-")) Double.NEGATIVE_INFINITY else Double.POSITIVE_INFINITY
                s.matches(Regex("[+-]?([0-9]+\\.?[0-9]*|\\.[0-9]+)([eE][+-]?[0-9]+)?")) -> s.toDouble()
                else -> Double.NaN
            }
        } catch (e: NumberFormatException) {
            Double.NaN
        }
    }

    private fun parseIntParam(present: Boolean, v: Any?, fallback: Double): Double {
        if (!present) return fallback
        val n = toNumber(v)
        return if (!n.isNaN() && !n.isInfinite() && n == Math.floor(n)) n else fallback
    }

    private fun has(q: Map<String, Any?>?, k: String) = q != null && q.containsKey(k)

    /**
     * A framework-agnostic SCIM 2.0 `/Agents` handler over [store]: GET (list, eq filter, paging), GET by id, POST (register a passport),
     * PUT, PATCH (RFC 7644 operations) and DELETE. Requires `authenticate` unless `allowUnauthenticated` is set (throws
     * IllegalArgumentException otherwise).
     */
    @JvmStatic
    fun scimHandler(store: AgentStore, options: ScimHandlerOptions?): ScimHandler {
        val opt = options ?: ScimHandlerOptions()
        val authenticate = opt.authenticate
        if (authenticate == null && !opt.allowUnauthenticated) throw IllegalArgumentException("scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)")
        return ScimHandler { req ->
            val admitted = authenticate == null || try {
                authenticate.authenticate(req) == true
            } catch (e: Exception) {
                false
            }
            if (!admitted) {
                ScimResponse(401, scimError(401, "authentication required", null), linkedMapOf("content-type" to SCIM_CONTENT_TYPE, "www-authenticate" to "Bearer"))
            } else {
                val id = req.id
                when (val m = req.method) {
                    "GET" -> if (id == null) handleList(store, req.query) else handleGetOne(store, id)
                    "POST" -> if (id != null) errorResponse(405, "POST is not allowed on an individual Agent") else handleCreate(store, opt, req.body)
                    "PUT" -> if (id == null) errorResponse(405, "PUT requires an Agent id") else handleReplace(store, opt, id, req.body)
                    "PATCH" -> if (id == null) errorResponse(405, "PATCH requires an Agent id") else handlePatch(store, opt, id, req.body)
                    "DELETE" -> if (id == null) errorResponse(405, "DELETE requires an Agent id") else handleDelete(store, id)
                    else -> errorResponse(405, "method not allowed: ${m ?: "undefined"}")
                }
            }
        }
    }

    private fun metaInput(o: ScimHandlerOptions) = MetaInput(baseUrl = o.baseUrl, now = o.now)

    private fun handleList(store: AgentStore, query: Map<String, Any?>?): ScimResponse {
        var items = store.all().map { it.resource }
        val filter = query?.get("filter")
        if (has(query, "filter") && filter != "") {
            val parsed = try {
                parseFilter(filter)
            } catch (e: ScimValueException) {
                return errorResponse(400, e.message ?: "", e.scimType)
            }
            items = items.filter { matchesFilter(it, parsed) }
        }
        val total = items.size
        val startIndex = Math.max(1.0, parseIntParam(has(query, "startIndex"), query?.get("startIndex"), 1.0))
        val from = Math.min(startIndex - 1, total.toDouble())
        var to = total.toDouble()
        if (has(query, "count")) to = Math.min(from + Math.max(0.0, parseIntParam(true, query!!["count"], total.toDouble())), total.toDouble())
        val page = ArrayList(items.subList(from.toInt(), Math.max(from, to).toInt()))
        return jsonResponse(200, scimListResponse(page, total.toLong(), startIndex))
    }

    private fun handleCreate(store: AgentStore, o: ScimHandlerOptions, body: Any?): ScimResponse {
        val req = try {
            scimToProvisioningRequest(body)
        } catch (e: ScimValueException) {
            return errorResponse(400, e.message ?: "", e.scimType)
        }
        val passport = Issue.issuePassport(req.identity)
        val pid = passport["id"].toString()
        if (store.get(pid) != null) return errorResponse(409, "an agent with this attested identity already exists (id $pid)", "uniqueness")
        val resource = passportToScim(passport, req.projection, metaInput(o))
        store.put(StoredAgent(resource, passport))
        return resourceResponse(201, resource)
    }

    private fun rematerialize(o: ScimHandlerOptions, existing: StoredAgent, proj: Map<String, Any?>): Map<String, Any?> {
        val meta = metaInput(o)
        meta.created = (existing.resource["meta"] as Map<String, Any?>)["created"] as String?
        return passportToScim(existing.passport, proj, meta)
    }

    private fun handleReplace(store: AgentStore, o: ScimHandlerOptions, id: String, body: Any?): ScimResponse {
        val existing = store.get(id) ?: return errorResponse(404, "Agent $id not found")
        val body0 = asRecord(body) ?: return errorResponse(400, "request body must be a JSON object", "invalidSyntax")
        val proj = readProjection(body0)
        if (proj["owner"] == "") proj["owner"] = existing.resource["owner"]
        val resource = rematerialize(o, existing, proj)
        store.put(StoredAgent(resource, existing.passport))
        return resourceResponse(200, resource)
    }

    private fun handlePatch(store: AgentStore, o: ScimHandlerOptions, id: String, body: Any?): ScimResponse {
        val existing = store.get(id) ?: return errorResponse(404, "Agent $id not found")
        val proj = projectionOf(existing.resource)
        try {
            for (op in readPatchOps(body)) applyPatchOp(proj, op)
        } catch (e: ScimValueException) {
            return errorResponse(400, e.message ?: "", e.scimType)
        }
        val resource = rematerialize(o, existing, proj)
        store.put(StoredAgent(resource, existing.passport))
        return resourceResponse(200, resource)
    }

    private fun handleDelete(store: AgentStore, id: String): ScimResponse =
        if (!store.delete(id)) errorResponse(404, "Agent $id not found") else ScimResponse(204, null, LinkedHashMap())

    private fun handleGetOne(store: AgentStore, id: String): ScimResponse {
        val existing = store.get(id) ?: return errorResponse(404, "Agent $id not found")
        return resourceResponse(200, existing.resource)
    }

    // ---- push-provision adapters ----

    private fun extensionAttributes(agent: Map<String, Any?>): Map<String, Any?> {
        val passport = agent["passport"] as Map<String, Any?>
        val a = linkedMapOf(
            "owner" to agent["owner"], "model" to passport["model_id"], "operator" to passport["operator"], "hardwareRooted" to passport["hardware_rooted"],
            "capabilities" to ArrayList(agent["capabilities"] as List<*>), "passportRef" to agent["passportRef"],
        )
        if (agent["holder"] != null) a["holder"] = agent["holder"]
        return a
    }

    private fun orRef(agent: Map<String, Any?>) = agent["externalId"] ?: agent["passportRef"]

    /** The SCIM body pushed to Microsoft Entra Agent ID's provisioning endpoint. */
    @JvmStatic
    fun toEntraAgentPayload(agent: Map<String, Any?>): Map<String, Any?> = linkedMapOf(
        "schemas" to arrayListOf<Any?>(AGENT_SCHEMA_URN, ENTRA_AGENT_EXTENSION_URN), "externalId" to orRef(agent), "displayName" to agent["displayName"],
        "active" to agent["active"], ENTRA_AGENT_EXTENSION_URN to extensionAttributes(agent),
    )

    /** The SCIM body pushed to Okta: `userName` is the stable passport id; agent attributes sit under an Okta custom-app extension. */
    @JvmStatic
    fun toOktaScimPayload(agent: Map<String, Any?>): Map<String, Any?> = linkedMapOf(
        "schemas" to arrayListOf<Any?>(AGENT_SCHEMA_URN, OKTA_AGENT_EXTENSION_URN), "userName" to agent["passportRef"], "externalId" to orRef(agent),
        "displayName" to agent["displayName"], "active" to agent["active"], OKTA_AGENT_EXTENSION_URN to extensionAttributes(agent),
    )

    /** A fetch response: status plus a body reader that may throw (a non-JSON body becomes null). */
    interface FetchResponse {
        fun ok(): Boolean
        fun status(): Int
        fun json(): Any?
    }

    /** Minimal injectable HTTP POST. */
    fun interface FetchLike { fun post(url: String, headers: Map<String, String>, body: String): FetchResponse }

    /** Where and how to push an outbound provisioning body; `fetch` null uses OkHttp. */
    class PushTarget @JvmOverloads constructor(val endpoint: String, val token: String, val fetch: FetchLike? = null)

    /** The outcome of a push-provision call. */
    class PushResult internal constructor(val ok: Boolean, val status: Int, val body: Any?)

    private val client by lazy { OkHttpClient() }

    private fun defaultFetch() = FetchLike { url, headers, body ->
        val b = Request.Builder().url(url).post(body.toRequestBody(SCIM_CONTENT_TYPE.toMediaType()))
        for ((k, v) in headers) b.header(k, v)
        client.newCall(b.build()).execute().use { r ->
            val text = r.body?.string() ?: ""
            val ok = r.isSuccessful
            val status = r.code
            object : FetchResponse {
                override fun ok() = ok
                override fun status() = status
                override fun json(): Any? = Json.parseLenient(text)
            }
        }
    }

    /** POST an already-shaped provisioning payload to a directory endpoint (the body key order is canonical). */
    @JvmStatic
    fun pushProvision(payload: Map<String, Any?>, target: PushTarget): PushResult {
        val f = target.fetch ?: defaultFetch()
        val res = f.post(target.endpoint, linkedMapOf("authorization" to "Bearer ${target.token}", "content-type" to SCIM_CONTENT_TYPE), Js.stringify(payload)) // JSON.stringify: member order as built
        val body = try {
            res.json()
        } catch (e: Exception) {
            null
        }
        return PushResult(res.ok(), res.status(), body)
    }

    @JvmStatic fun pushToEntra(agent: Map<String, Any?>, target: PushTarget) = pushProvision(toEntraAgentPayload(agent), target)

    @JvmStatic fun pushToOkta(agent: Map<String, Any?>, target: PushTarget) = pushProvision(toOktaScimPayload(agent), target)
}
