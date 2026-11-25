package net.atlasauth.pca.testing

import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Facade
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * Testing kit for Proof-Carrying Authority: factories, fakes and assertion helpers so an integrator can test their PCA wiring
 * in process, with no backend and no network. [testAgent] mints a real agent with test defaults, [makePCActn] builds
 * real PCActns from it, and [fakeVerify] runs the real core verifier against them.
 *
 * Nothing here authorizes anything: `fakeVerify` stands in for the resource server by rooting the check at the PCActn's
 * own grant and accepting the PCActn's own audience by default, so a clean round trip verifies. It is the real verifier, not a
 * weakened one: tampering is caught exactly as in production. A grant lifted from the artifact is never trusted for a
 * post-quantum root (no pin exists), exactly as the reference refuses it.
 */
@Suppress("UNCHECKED_CAST")
object TestingKit {
    // ---- factories ----

    /** Overrides for [testAgent]; anything left null falls back to a test default. */
    class TestAgentOverrides {
        /** Connector to allowed actions. Default `{stripe: [refund]}`. */
        @JvmField var permissions: Map<String, Any?>? = null

        /** Per-action limits. Default `{refund: "$500/day"}`; pass an empty map for none. */
        @JvmField var limits: Map<String, Any?>? = null

        /** Plaintext goal (only its salted commitment goes in the grant). Default `test`. */
        @JvmField var goal: String? = null

        /** Default audience of every act. Default `ins_test`. */
        @JvmField var aud: String? = null

        /** The principal (human) key that roots and signs the grant; generated when null. */
        @JvmField var principal: Keys.SuiteKey? = null

        /** The agent (holder) key that signs PCActns; generated when null. */
        @JvmField var holder: Keys.SuiteKey? = null
    }

    /** A real agent handle with test defaults. */
    @JvmStatic
    @JvmOverloads
    fun testAgent(ov: TestAgentOverrides? = null): Facade.Handle {
        val o = ov ?: TestAgentOverrides()
        return Facade.agent(
            Facade.AgentOptions(
                o.principal ?: Keys.ed25519(Keys.edGenerate()), o.goal ?: "test",
                o.permissions ?: linkedMapOf<String, Any?>("stripe" to arrayListOf<Any?>("refund")),
                limits = o.limits ?: linkedMapOf<String, Any?>("refund" to "\$500/day"), holder = o.holder, aud = o.aud ?: "ins_test",
            ),
        )
    }

    /** The PCActn and its wire encoding. */
    class Made(@JvmField val pcactn: Map<String, Any?>, @JvmField val encoded: String)

    /** Build a PCActn for one action ([counter] auto-increments per holder when null; [now] is the clock in ms). */
    @JvmStatic
    @JvmOverloads
    fun makePCActn(a: Facade.Handle, verb: String, resource: String, params: Map<String, Any?>?, counter: Long? = null, now: Long? = null): Made {
        val r = a.act(verb, resource, params, Facade.ActOptions(counter = counter, now = now))
        return Made(r.pcactn, r.encoded)
    }

    // ---- fake verifier ----

    /** Options for [fakeVerify] / [expectVerifies] / [expectDenied]. */
    class FakeVerifyOptions {
        /** The verifier's own audience, honoured only when [audienceGiven]: null then opts out entirely. Unset: the PCActn's own aud. */
        @JvmField var audience: String? = null
        @JvmField var audienceGiven = false

        /** Clock (epoch ms); the wall clock when null. */
        @JvmField var now: Long? = null

        /** Root grant to verify against; the PCActn's own chain root when null. */
        @JvmField var grant: Map<String, Any?>? = null

        fun audience(a: String?): FakeVerifyOptions { audience = a; audienceGiven = true; return this }
        fun now(n: Long): FakeVerifyOptions { now = n; return this }
        fun grant(g: Map<String, Any?>): FakeVerifyOptions { grant = g; return this }
    }

    /** The verdict: `allow`, each check's pass/fail in the verifier's order, and the first failure's reason. */
    data class FakeVerifyResult(val allow: Boolean, val checks: Map<String, Boolean>, val reason: String?)

    /** `pcactn.cap_chain[0]` as JavaScript reads it; throws where JavaScript would throw or find nothing. */
    private fun liftGrant(pcactn: Any?): Any? {
        val empty = "fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant"
        if (pcactn !is Map<*, *>) throw IllegalArgumentException(empty)
        val chain = pcactn["cap_chain"]
        var first: Any? = null
        if (chain is List<*> && chain.isNotEmpty()) first = chain[0]
        else if (chain is String && chain.isNotEmpty()) first = chain.substring(0, 1)
        if (!Js.truthy(first)) throw IllegalArgumentException(empty)
        return first
    }

    private fun denied(check: String, why: String): FakeVerifyResult = FakeVerifyResult(false, linkedMapOf(check to false), "$check: $why")

    /**
     * Run the real core verifier against [pcactn], rooting the check at `opts.grant` or the PCActn's own chain root and
     * defaulting the audience to the PCActn's own. A lifted grant whose suite is not plain ed25519 is refused (the root key proves
     * nothing about who issued it without a verifier-side pin). Throws when there is no grant to root at.
     */
    @JvmStatic
    @JvmOverloads
    fun fakeVerify(pcactn: Any?, opts: FakeVerifyOptions? = null): FakeVerifyResult {
        val o = opts ?: FakeVerifyOptions()
        val grant = o.grant ?: liftGrant(pcactn)
        val lifted = o.grant == null
        val audience: String? = if (o.audienceGiven && o.audience != null) o.audience
        else {
            if (!o.audienceGiven && pcactn == null) throw IllegalArgumentException("fakeVerify: no PCActn")
            val aud = if (pcactn is Map<*, *>) pcactn["aud"] else null
            aud as? String // opt-out: the PCActn's own audience (a non-string one fails the wire check)
        }
        if (grant !is Map<*, *>) return denied("wire", "the grant is not an object")
        val g = grant as Map<String, Any?>
        if (lifted && g.containsKey("alg") && "ed25519" != g["alg"]) {
            return denied("chain", "root suite needs a verifier-side PQ pin; a grant lifted from the artifact is never trusted for it")
        }
        val now = o.now ?: System.currentTimeMillis()
        val v = Pca.verifyPcactn(pcactn, g, now, if (audience != null) Pca.Audience.Of(audience) else Pca.Audience.Unset, insecureSkipPlanRootCheck = true)
        return FakeVerifyResult(v.allow, LinkedHashMap(v.checks), v.reason)
    }

    private fun failing(r: FakeVerifyResult): String = r.checks.entries.filter { !it.value }.joinToString(", ") { it.key }

    /** Assert that [pcactn] verifies; throws an [IllegalStateException] naming the failing checks when it does not. */
    @JvmStatic
    @JvmOverloads
    fun expectVerifies(pcactn: Any?, opts: FakeVerifyOptions? = null): FakeVerifyResult {
        val r = fakeVerify(pcactn, opts)
        if (!r.allow) {
            throw IllegalStateException("expectVerifies: PCActn was denied. failing checks: [" + failing(r) + "]" + (if (!r.reason.isNullOrEmpty()) " — " + r.reason else ""))
        }
        return r
    }

    /** The inverse of [expectVerifies]: throws when [pcactn] unexpectedly verifies. */
    @JvmStatic
    @JvmOverloads
    fun expectDenied(pcactn: Any?, opts: FakeVerifyOptions? = null): FakeVerifyResult {
        val r = fakeVerify(pcactn, opts)
        if (r.allow) throw IllegalStateException("expectDenied: PCActn verified but was expected to be denied. checks: " + r.checks)
        return r
    }

    // ---- in-memory state store ----

    /** Per-holder replay/budget state; a structural stand-in for the state a resource server threads across actions. */
    class MemoryStateStore {
        private val m = ConcurrentHashMap<String, Map<String, Any?>>()

        /** The state stored under [key], or null. */
        fun get(key: String): Map<String, Any?>? = m[key]

        fun put(key: String, state: Map<String, Any?>) { m[key] = state }
    }

    /** An in-memory store; nothing persists beyond the process. */
    @JvmStatic
    fun memoryStateStore(): MemoryStateStore = MemoryStateStore()

    // ---- tampering ----

    private fun stringifyForm(v: Any?): Any? = when {
        v is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> for ((k, x) in v) out[k as String] = stringifyForm(x) }
        v is List<*> -> ArrayList<Any?>().also { out -> for (x in v) out.add(stringifyForm(x)) }
        IntentJs.num(v) != null -> { // JSON.stringify prints -0 as 0
            val n = IntentJs.normalize(if (v is Json.Num) v else Json.Num(v.toString())) as Json.Num
            if (n.raw == "-0") Json.Num("0") else n
        }
        else -> v
    }

    /**
     * Decode an encoded PCActn (strict JSON profile, size-capped), let [mutate] corrupt it in place, then re-decode and
     * re-encode it so a test can assert the corruption is caught. A change touching the signed body breaks the leaf signature.
     */
    @JvmStatic
    fun tamper(encoded: String, mutate: (MutableMap<String, Any?>) -> Unit): String {
        if (Pca.artifactTooLarge(encoded)) throw IllegalArgumentException(Pca.ARTIFACT_SIZE_REASON)
        val v = Json.parse(encoded)
        if (v !is Map<*, *>) throw IllegalArgumentException("decodePCActn: not an object")
        val rec = LinkedHashMap(v as Map<String, Any?>)
        mutate(rec)
        val text = Json.canonicalize(stringifyForm(rec))
        if (Pca.artifactTooLarge(text)) throw IllegalArgumentException(Pca.ARTIFACT_SIZE_REASON)
        val back = Json.parse(text)
        if (back !is Map<*, *>) throw IllegalArgumentException("decodePCActn: not an object")
        return Json.canonicalize(back)
    }

    // ---- adapter acceptance matrix (constants and the route mapping) ----

    const val ADAPTER_ACCEPTANCE_AUDIENCE = "payments-rs"

    private fun outcome(status: Int, ran: Boolean, bound: Boolean): Map<String, Any?> = linkedMapOf("status" to status, "handlerRan" to ran, "bound" to bound)

    /** The outcome every adapter must produce per scenario: status, whether the handler ran, whether the attached operation matches. */
    @JvmStatic
    fun adapterAcceptanceExpected(): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for (k in listOf("over_limit_predicate", "over_limit_max_spend", "body_differs", "other_operation", "escalate_unanswered", "missing_revocation", "missing_store")) {
            m[k] = outcome(403, false, false)
        }
        m["valid_first"] = outcome(200, true, true)
        m["replay_second"] = outcome(403, false, false)
        return m
    }

    private fun isSpecial(scheme: String): Boolean = scheme in setOf("http", "https", "ftp", "ws", "wss", "file")

    private val CTRL_EDGES = Regex("^[\\u0000-\\u0020]+|[\\u0000-\\u0020]+$")
    private val TAB_NL = Regex("[\\t\\n\\r]")
    private val SCHEME = Regex("^([A-Za-z][A-Za-z0-9+.\\-]*):")

    /**
     * The pathname of [url] resolved against a base origin, as a WHATWG URL parser yields it, for the shapes a request carries:
     * absolute and scheme-relative URLs with an authority, rooted and relative paths, dot segments, query and fragment. Only
     * a pathname equal to a route can match, so any other spelling needs no further normalisation. shortcut: percent-encoding of
     * the path is not reproduced (an encoded spelling never equals a route), upgrade if routes ever contain non-ASCII.
     */
    internal fun pathnameOf(url: String): String {
        val s = url.replace(CTRL_EDGES, "").replace(TAB_NL, "")
        var cut = s.length
        for (i in s.indices) if (s[i] == '?' || s[i] == '#') { cut = i; break }
        var rest = s.substring(0, cut)
        val sm = SCHEME.find(rest)
        val path: String
        if (sm != null) {
            val scheme = sm.groupValues[1].lowercase(Locale.ROOT)
            rest = rest.substring(sm.range.last + 1)
            if (!isSpecial(scheme)) {
                if (rest.startsWith("//")) {
                    val end = rest.indexOf('/', 2)
                    path = if (end < 0) "" else rest.substring(end)
                } else if (rest.startsWith("/")) path = rest
                else return rest // opaque path: never a route
            } else if (scheme == "file") {
                rest = rest.replace('\\', '/')
                if (rest.startsWith("//")) {
                    val end = rest.indexOf('/', 2)
                    path = if (end < 0) "/" else rest.substring(end)
                } else path = if (rest.startsWith("/")) rest else "/$rest"
            } else {
                rest = rest.replace('\\', '/')
                if (scheme == "http" && !rest.startsWith("//")) path = if (rest.startsWith("/")) rest else "/$rest" // same scheme as the base: relative
                else {
                    var slashes = 0
                    while (slashes < rest.length && rest[slashes] == '/') slashes++
                    rest = rest.substring(slashes)
                    val end = rest.indexOf('/')
                    if ((if (end < 0) rest else rest.substring(0, end)).isEmpty()) throw IllegalArgumentException("Invalid URL")
                    path = if (end < 0) "/" else rest.substring(end)
                }
            }
        } else {
            rest = rest.replace('\\', '/')
            if (rest.startsWith("//")) {
                var t = rest.substring(2)
                while (t.startsWith("/")) t = t.substring(1)
                val end = t.indexOf('/')
                if ((if (end < 0) t else t.substring(0, end)).isEmpty()) throw IllegalArgumentException("Invalid URL")
                path = if (end < 0) "/" else t.substring(end)
            } else path = if (rest.startsWith("/")) rest else "/$rest"
        }
        if (path.isEmpty()) return ""
        val out = ArrayList<String>()
        val segs = path.substring(1).split("/")
        for (i in segs.indices) {
            val seg = segs[i]
            val low = seg.lowercase(Locale.ROOT)
            val last = i == segs.size - 1
            if (low == ".." || low == ".%2e" || low == "%2e." || low == "%2e%2e") {
                if (out.isNotEmpty()) out.removeAt(out.size - 1)
                if (last) out.add("")
            } else if (low == "." || low == "%2e") {
                if (last) out.add("")
            } else out.add(seg)
        }
        return "/" + out.joinToString("/")
    }

    /**
     * The server's mapping from request to operation: a route table on method and path with the JSON body as params. Returns null for
     * an unknown route or a body that is not an object; otherwise `{verb, resource, params}`.
     */
    @JvmStatic
    fun acceptanceOperation(req: Map<String, Any?>): Map<String, Any?>? {
        val url = req["url"]
        val path = if (url is String) pathnameOf(url) else ""
        val key = Js.template(req["method"]).uppercase(Locale.ROOT) + " " + path
        val verb = when (key) {
            "POST /payments" -> "payments.send"
            "POST /refunds" -> "payments.refund"
            else -> return null
        }
        val body = req["body"]
        if (body !is Map<*, *>) return null
        return linkedMapOf("verb" to verb, "resource" to "payments", "params" to body)
    }
}
