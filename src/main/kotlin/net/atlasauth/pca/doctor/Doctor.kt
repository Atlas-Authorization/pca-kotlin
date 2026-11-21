package net.atlasauth.pca.doctor

import java.io.File
import java.net.URI
import java.util.concurrent.TimeUnit
import net.atlasauth.pca.verifier.Decide
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.Pq
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Checks a live PCA deployment's assumptions: clock skew, replay store, trusted-proxy settings, signature-suite policy, root-caveat
 * enforcement and the verifier's required checks. Every check returns a [CheckResult] (pass / warn / fail / skip, what was observed
 * and what to do); [runDoctor] merges them, [verdictOf] reduces them, [formatResults] prints them, and nothing printed carries a
 * credential ([scrubText]). Configuration is a plain JSON object (sections `url`, `clock`, `store`, `proxy`, `verifier`); checks
 * that cannot be observed from here say so instead of passing.
 */
object Doctor {
    // ---- results ----

    /** A deep copy of a config / result tree with absent (undefined) members dropped, the form the reference serialises. */
    fun json(v: Any?): Any? = Js.deepCopy(v)

    /** One check's result: `id`, `status`, `detail`, optional `remediation` and `observed`. */
    class CheckResult(val json: MutableMap<String, Any?>) {
        fun fix(remediation: String): CheckResult { json["remediation"] = remediation; return this }
        fun observed(o: Map<String, Any?>): CheckResult { json["observed"] = o; return this }
        fun id(): String = Js.str(json["id"])
        fun status(): String = Js.str(json["status"])
        fun detail(): String = Js.str(json["detail"])
        fun remediation(): String? { val r = json["remediation"]; return if (Js.truthy(r)) Js.str(r) else null }
        fun toJson(): Map<String, Any?> = json

        companion object {
            fun of(id: String, status: String, detail: String): CheckResult {
                val m = LinkedHashMap<String, Any?>()
                m["id"] = id
                m["status"] = status
                m["detail"] = detail
                return CheckResult(m)
            }

            @Suppress("UNCHECKED_CAST")
            fun fromJson(m: Map<String, Any?>): CheckResult = CheckResult(m as MutableMap<String, Any?>)
        }
    }

    // ---- scrub ----

    private const val S = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
    private val SCRUB_JWT = Regex("(?<![A-Za-z0-9_])eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*")
    private val SCRUB_AUTH = Regex("(?i)(?<![A-Za-z0-9_])(authorization[\"']?[$S]*[:=][$S]*)[^\\n\"']*")
    private val SCRUB_BEARER = Regex("(?i)(?<![A-Za-z0-9_])(Bearer|Basic|Token)[$S]+[A-Za-z0-9_.~+/=-]{6,}")
    private val SCRUB_URL = Regex("(?i)([a-z][a-z0-9+.-]*://)[^$S/@]*:[^$S/@]*@")
    private val SCRUB_PAIR = Regex(
        "(?i)(?<![A-Za-z0-9_])((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth|sslpassword)[\"']?[$S]*[:=][$S]*)(\"[^\"]*\"|'[^']*'|[^$S\"'&,;]+)",
    )
    private val SCRUB_LONG = Regex("[A-Za-z0-9_-]{40,}")

    /** Remove credentials from text the doctor prints: URL userinfo, `token=` / `password=` pairs, bearer credentials, JWTs and long token runs. */
    fun scrubText(text: Any?): String {
        var t = Js.str(text)
        t = SCRUB_JWT.replace(t, "[redacted]")
        t = SCRUB_AUTH.replace(t, "\$1[redacted]")
        t = SCRUB_BEARER.replace(t, "\$1 [redacted]")
        t = SCRUB_URL.replace(t, "\$1[redacted]@")
        t = SCRUB_PAIR.replace(t, "\$1[redacted]")
        t = SCRUB_LONG.replace(t, "[redacted]")
        return if (t.length > 600) t.substring(0, 600) + "..." else t
    }

    /** Scrub every string inside a JSON-like value (nesting deeper than 8 is left as it is, as the reference does). */
    fun scrubDeep(v: Any?): Any? = scrubDeep(v, 0)

    private fun scrubDeep(v: Any?, depth: Int): Any? {
        if (v is String) return scrubText(v)
        if (depth > 8 || v == null || !(v is Map<*, *> || v is List<*>)) return v
        if (v is List<*>) {
            val out = ArrayList<Any?>()
            for (x in v) out.add(scrubDeep(x, depth + 1))
            return out
        }
        val out = LinkedHashMap<String, Any?>()
        for ((k, x) in v as Map<*, *>) out[k as String] = scrubDeep(x, depth + 1)
        return out
    }

    // ---- fetch ----

    /** One HTTP response: the status and a header by lower-case name (null when absent). */
    interface Response {
        fun status(): Int
        fun header(lowerName: String): String?
    }

    /** The doctor's HTTP client: `method` is HEAD or GET; redirects are not followed. */
    fun interface Fetch {
        fun fetch(method: String, url: String, headers: Map<String, String>, timeoutMs: Long): Response
    }

    /** The default client over OkHttp (redirects are not followed). */
    class HttpFetch : Fetch {
        private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false).build()

        override fun fetch(method: String, url: String, headers: Map<String, String>, timeoutMs: Long): Response {
            val b = Request.Builder().url(url)
            for ((k, v) in headers) b.header(k, v)
            b.method(method, null)
            val c = client.newBuilder().callTimeout(timeoutMs, TimeUnit.MILLISECONDS).build()
            c.newCall(b.build()).execute().use { r ->
                val code = r.code
                val date = r.header("date")
                val rl = r.header("ratelimit-remaining")
                return object : Response {
                    override fun status(): Int = code
                    override fun header(lowerName: String): String? = if (lowerName == "date") date else if (lowerName == "ratelimit-remaining") rl else null
                }
            }
        }
    }

    // ---- clock ----

    const val DEFAULT_REFERENCE_URL = "https://www.google.com/generate_204"
    const val CLOCK_REMEDIATION =
        "Synchronise every verifier, issuer and replay-store host with NTP (chrony or systemd-timesyncd) and alert on drift. PCA tolerates at most 60 s between any two clocks (PCACTN_MAX_SKEW_MS); replay retention is exp + skew, so a clock outside that bound can free a nonce early or reject fresh actions."

    /** One reading of a server's clock relative to the local one: remote minus local (ms) and its uncertainty, or an error. */
    class DateReading internal constructor(val offsetMs: Double, val uncertaintyMs: Double, val error: String?) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            if (error != null) m["error"] = error else { m["offsetMs"] = offsetMs; m["uncertaintyMs"] = uncertaintyMs }
            return m
        }
    }

    /** One reading of the server's clock from its Date header (one-second resolution: +-0.5 s plus half the round trip). */
    fun readDate(url: String, fetch: Fetch, now: () -> Long, timeoutMs: Long): DateReading {
        val t0 = now().toDouble()
        val res = try {
            fetch.fetch("HEAD", url, LinkedHashMap(), timeoutMs)
        } catch (e: Exception) {
            return DateReading(0.0, 0.0, "request failed: " + e.message)
        }
        val t1 = now().toDouble()
        val date = res.header("date")
        val d = if (date == null) Double.NaN else Js.parseDate(date)
        if (d.isNaN() || d.isInfinite()) return DateReading(0.0, 0.0, if (date == null) "no Date header" else "unparseable Date header '$date'")
        return DateReading(d + 500 - (t0 + t1) / 2, 500 + (t1 - t0) / 2, null)
    }

    private fun signed(ms: Double): String = (if (ms >= 0) "+" else "-") + Js.toFixed1(Math.abs(ms) / 1000) + " s"

    /** Clock skew of the deployment against a reference (the Date headers of both, or this machine's clock). */
    fun checkClock(cfg: Map<String, Any?>, fetch: Fetch, now: (() -> Long)?): CheckResult {
        val clock: () -> Long = now ?: { System.currentTimeMillis() }
        val url = Js.g(cfg, "url")
        if (!Js.truthy(url)) return CheckResult.of("clock", "skip", "no deployment URL given (--url)")
        val clockCfg = Js.g(cfg, "clock")
        val max = Js.toNumber(Js.or(Js.g(clockCfg, "maxSkewMs"), Pca.MAX_SKEW_MS.toDouble()))
        val warnAt = max * Js.toNumber(Js.or(Js.g(clockCfg, "warnFraction"), 0.25))
        val timeout = Js.toNumber(Js.or(Js.g(clockCfg, "timeoutMs"), 10_000.0)).toLong()
        val dep = readDate(Js.str(url), fetch, clock, timeout)
        if (dep.error != null) {
            return CheckResult.of("clock", "warn", "cannot observe the deployment's clock at " + Js.str(url) + ": " + dep.error)
                .fix("Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. $CLOCK_REMEDIATION")
        }
        val refUrl = Js.str(Js.or(Js.g(clockCfg, "referenceUrl"), DEFAULT_REFERENCE_URL))
        var ref = DateReading(0.0, 0.0, null)
        var refName = "this machine's clock"
        var refNote = ""
        if (refUrl != "local") {
            val r = readDate(refUrl, fetch, clock, timeout)
            if (r.error != null) refNote = " (reference $refUrl unusable: ${r.error}; compared with this machine's clock instead)"
            else { ref = r; refName = refUrl }
        }
        val skew = dep.offsetMs - ref.offsetMs
        val unc = dep.uncertaintyMs + ref.uncertaintyMs
        val lower = Math.abs(skew) - unc
        val upper = Math.abs(skew) + unc
        // A skew, uncertainty or threshold that is not a number (NaN, an infinite clock reading) can show nothing: fail, never pass.
        val measurable = lower.isFinite() && upper.isFinite() && !max.isNaN() && !warnAt.isNaN()
        val status = if (!measurable) "fail" else if (lower > max) "fail" else if (Math.abs(skew) > warnAt || upper > max) "warn" else "pass"
        val detail = "deployment clock " + signed(skew) + " relative to " + refName + refNote + " (+-" + Js.toFixed1(unc / 1000) + " s: Date has 1 s resolution, plus round trips); " +
            "fail beyond " + Js.numStr(max / 1000) + " s, warn above " + Js.numStr(warnAt / 1000) + " s. The Date header is written by whatever answers the request (a CDN or proxy may set it)."
        val res = CheckResult.of("clock", status, detail)
        if (status != "pass") res.fix(CLOCK_REMEDIATION)
        val obs = LinkedHashMap<String, Any?>()
        obs["skewMs"] = skew
        obs["uncertaintyMs"] = unc
        obs["maxSkewMs"] = max
        obs["warnAtMs"] = warnAt
        obs["reference"] = refName
        return res.observed(obs)
    }

    // ---- proxy ----

    const val PROXY_REMEDIATION =
        "Set TRUSTED_PROXY_COUNT to exactly the number of reverse proxies in front of the API that APPEND to the trusted header (1 behind one load balancer / ingress; 0 when clients connect directly), and TRUSTED_PROXY_HEADER to the header they write. Too high lets a client pick its own rate-limit bucket with extra X-Forwarded-For entries; too low merges every client into the proxy's bucket."

    private fun failed(id: String, detail: String, remediation: String): CheckResult = CheckResult.of(id, "fail", detail).fix(remediation)

    /** The stated TRUSTED_PROXY_COUNT / TRUSTED_PROXY_HEADER against the stated number of appending proxies. */
    fun checkProxyConfig(cfg: Map<String, Any?>): CheckResult {
        val p = Js.g(cfg, "proxy")
        val n = Js.g(p, "trustedProxyCount")
        if (Js.isUndef(n)) return CheckResult.of("proxy.config", "skip", "TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)")
        val header = Js.or(Js.g(p, "header"), "x-forwarded-for")
        val hs = Js.str(header)
        val ns = Js.str(n)
        if (!Js.isInteger(n) || Js.num(n)!! < 0 || Js.isNegZero(n) || Js.num(n)!! > 16) return failed("proxy.config", "TRUSTED_PROXY_COUNT=$ns is not an integer in 0..16", PROXY_REMEDIATION)
        val nv = Js.num(n)!!
        if ("x-real-ip" == header && nv == 0.0) return failed("proxy.config", "TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)", PROXY_REMEDIATION)
        val hops = Js.g(p, "hops")
        if (Js.isUndef(hops)) {
            val r = CheckResult.of("proxy.config", if (nv == 0.0) "pass" else "warn", "TRUSTED_PROXY_COUNT=$ns ($hs); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared")
            return if (nv == 0.0) r else r.fix(PROXY_REMEDIATION)
        }
        val h = Js.toNumber(hops)
        val hp = Js.str(hops)
        if (nv > h) return failed("proxy.config", "TRUSTED_PROXY_COUNT=$ns is larger than the $hp proxies in front of the API: a client chooses its own address (and rate-limit bucket) with extra $hs entries", PROXY_REMEDIATION)
        if (nv < h) return CheckResult.of("proxy.config", "warn", "TRUSTED_PROXY_COUNT=$ns is smaller than the $hp proxies in front of the API: clients are keyed by a proxy's address and share its bucket").fix(PROXY_REMEDIATION)
        return CheckResult.of("proxy.config", "pass", "TRUSTED_PROXY_COUNT=$ns ($hs) matches the stated $hp appending proxies")
    }

    /** mulberry32: the seeded PRNG the reference vectors use (returns values in [0, 1)). */
    fun mulberry32(seed: Long): () -> Double {
        var a = seed.toInt()
        return {
            a += 0x6d2b79f5
            var t = a
            t = (t xor (t ushr 15)) * (t or 1)
            t = t xor (t + (t xor (t ushr 7)) * (t or 61))
            ((t xor (t ushr 14)).toLong() and 0xffffffffL) / 4294967296.0
        }
    }

    /** A random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client. */
    fun testNetIp(rand: (() -> Double)?): String {
        val r: () -> Double = rand ?: { Math.random() }
        val net = if (r() < 0.5) "198.51.100" else "203.0.113"
        return net + "." + (1 + Math.floor(r() * 254).toInt())
    }

    /** Forged values for all three forwarding headers at once (the server trusts at most one of them). */
    fun forgedHeaders(rand: (() -> Double)?): Map<String, String> {
        val r: () -> Double = rand ?: { Math.random() }
        val chain = ArrayList<String>()
        for (i in 0 until 17) chain.add(testNetIp(r))
        val fors = ArrayList<String>()
        for (ip in chain) fors.add("for=$ip")
        val m = LinkedHashMap<String, String>()
        m["x-forwarded-for"] = chain.joinToString(", ")
        m["forwarded"] = fors.joinToString(", ")
        m["x-real-ip"] = testNetIp(r)
        return m
    }

    private fun remaining(fetch: Fetch, url: String, headers: Map<String, String>, timeoutMs: Long): Double? {
        val r = fetch.fetch("GET", url, headers, timeoutMs)
        val v = r.header("ratelimit-remaining")
        val n = if (v == null) Double.NaN else Js.toNumber(v)
        return if (n.isNaN() || n.isInfinite()) null else n
    }

    /** `new URL(path, base).href` for the shapes a probe path takes (absolute URL, rooted path, relative path). */
    private fun resolveHref(path: String, base: String): String {
        try {
            var b = URI.create(base)
            if (b.scheme == null || b.host == null) throw IllegalArgumentException("Invalid URL")
            if (b.rawPath == null || b.rawPath.isEmpty()) b = b.resolve("/")
            return b.resolve(path).toString()
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid URL")
        }
    }

    /** Forged forwarding headers sent to a public rate-limited path: a forged request landing in a FRESH bucket means client-written entries are trusted. */
    fun checkProxyProbe(cfg: Map<String, Any?>, fetch: Fetch, rand: (() -> Double)?): CheckResult {
        val id = "proxy.probe"
        val url = Js.g(cfg, "url")
        if (!Js.truthy(url)) return CheckResult.of(id, "skip", "no deployment URL given (--url)")
        val proxy = Js.g(cfg, "proxy")
        if (Js.g(proxy, "probe") == false) return CheckResult.of(id, "skip", "disabled (--no-probe)")
        val target = resolveHref(Js.str(Js.or(Js.g(proxy, "probePath"), "/v1/pca/suites")), Js.str(url))
        val t = Js.toNumber(Js.or(Js.g(Js.g(cfg, "clock"), "timeoutMs"), 10_000.0)).toLong()
        val seq: List<Double?> = try {
            val r1 = remaining(fetch, target, LinkedHashMap(), t)
            val r2 = remaining(fetch, target, LinkedHashMap(), t)
            val r3 = remaining(fetch, target, forgedHeaders(rand), t)
            val r4 = remaining(fetch, target, LinkedHashMap(), t)
            listOf(r1, r2, r3, r4)
        } catch (e: Exception) {
            return CheckResult.of(id, "warn", "probe request to $target failed: " + e.message).fix("Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.")
        }
        val observed = LinkedHashMap<String, Any?>()
        observed["url"] = target
        observed["remaining"] = ArrayList<Any?>(seq)
        val a = seq[0]
        val b = seq[1]
        val f = seq[2]
        val c = seq[3]
        if (a == null || b == null || f == null || c == null) {
            return CheckResult.of(id, "skip", "not observable remotely: $target does not return a RateLimit-Remaining header on every response").observed(observed)
        }
        val sa = Js.numStr(a)
        val sb = Js.numStr(b)
        val sf = Js.numStr(f)
        val sc = Js.numStr(c)
        if (!(b < a && c < b)) {
            return CheckResult.of(id, "warn", "inconclusive: the plain requests' bucket did not drain monotonically ($sa, $sb, then $sc): a window rollover, a shared bucket or concurrent traffic. Re-run.").observed(observed)
        }
        if (f > b) {
            return CheckResult.of(id, "fail", "a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining $sf, while the plain requests' bucket was at $sb): the deployment trusts client-written forwarding entries")
                .fix(PROXY_REMEDIATION).observed(observed)
        }
        return CheckResult.of(id, "pass", "forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining $sa, $sb, forged $sf, $sc). A count that is too LOW is not observable from one client.").observed(observed)
    }

    // ---- suites ----

    const val SUITES_REMEDIATION =
        "Set the verifier's allowedSuites to exactly the suites your issuers sign with (names from SIG_SUITES), e.g. ['ed25519'] or ['hybrid-ed25519-ml-dsa-65']."
    const val PQ_REMEDIATION =
        "Never set allowUnboundPq. For pure-PQ or hybrid roots, configure pqPins (issuer Ed25519 identity -> PQ public key, from pqPinFor) or verify against your stored root grant (trustedRoot; requirePCA / verifyPCActnCore do this)."

    private val B64U = Regex("[A-Za-z0-9_-]+")
    private val ED25519_ID = Regex("[A-Za-z0-9_-]{43}")

    private fun isPq(alg: Any?): Boolean = alg is String && alg != "ed25519" && alg in Pq.REGISTERED_SUITES

    /** allowedSuites against the closed suite registry (the library's registered suite names, in registry order). */
    fun checkAllowedSuites(cfg: Map<String, Any?>, registry: List<String> = Pq.REGISTERED_SUITES): CheckResult {
        val id = "suites.allowed"
        val v = Js.g(cfg, "verifier")
        if (!Js.truthy(v)) return CheckResult.of(id, "skip", "no verifier configuration given (config verifier.*)")
        val list = Js.g(v, "allowedSuites")
        val known = registry.joinToString(", ")
        if (Js.isUndef(list)) {
            return CheckResult.of(id, "warn", "allowedSuites is unset: every registered suite is accepted (${registry.size}: $known)").fix(SUITES_REMEDIATION)
        }
        if (list !is List<*> || list.isEmpty()) {
            return CheckResult.of(id, "fail", "allowedSuites is empty or not a list: no PCActn can verify").fix(SUITES_REMEDIATION)
        }
        val unknown = ArrayList<String>()
        for (s in list) if (s !is String || s !in registry) unknown.add(Js.str(s))
        if (unknown.isNotEmpty()) {
            return CheckResult.of(id, "fail", "allowedSuites names suite(s) outside the registry: " + unknown.joinToString(", ") + " (known: $known)").fix(SUITES_REMEDIATION)
        }
        val names = ArrayList<String>()
        for (x in list) names.add(Js.str(x))
        return CheckResult.of(id, "pass", "allowedSuites = " + names.joinToString(", "))
    }

    /** allowUnboundPq / pqPins / trustedRoot sanity. */
    fun checkPqBinding(cfg: Map<String, Any?>): CheckResult {
        val id = "suites.pq-binding"
        val v = Js.g(cfg, "verifier")
        if (!Js.truthy(v)) return CheckResult.of(id, "skip", "no verifier configuration given (config verifier.*)")
        if (Js.g(v, "allowUnboundPq") == true) {
            return failed(id, "allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger and a pure-PQ hop can be signed by any key", PQ_REMEDIATION)
        }
        val pins = Js.g(v, "pqPins")
        if (!Js.isUndef(pins)) {
            if (!Js.truthy(pins) || pins !is Map<*, *>) return failed(id, "pqPins is not an object of { ed25519 identity: pq public key }", PQ_REMEDIATION)
            val bad = ArrayList<String>()
            for ((key, value) in pins) {
                val k = key as String
                if (!ED25519_ID.matches(k) || value !is String || !B64U.matches(value)) bad.add(k)
            }
            if (bad.isNotEmpty()) {
                return failed(id, "pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): " + bad.joinToString(", "), PQ_REMEDIATION)
            }
        }
        val allowed = Js.or(Js.g(v, "allowedSuites"), ArrayList<Any?>(Pq.REGISTERED_SUITES))
        if (allowed !is List<*>) throw IllegalStateException("allowedSuites is not a list")
        val pq = ArrayList<String>()
        for (s in allowed) if (isPq(s)) pq.add(s as String)
        if (pq.isEmpty()) return CheckResult.of(id, "pass", "no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)")
        val pinned = !Js.isUndef(pins) && !(pins as Map<*, *>).isEmpty()
        if (!pinned && Js.g(v, "trustedRoot") != true) {
            return CheckResult.of(
                id, "warn",
                "post-quantum suite(s) accepted (" + pq.joinToString(", ") + ") with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is refused (fail closed) or its PQ key is not pinned",
            ).fix(PQ_REMEDIATION)
        }
        return CheckResult.of(id, "pass", "PQ suites (" + pq.joinToString(", ") + ") are bound: " + (if (pinned) (pins as Map<*, *>).size.toString() + " pin(s)" else "stored trustedRoot") + "; allowUnboundPq off")
    }

    // ---- replay store remediation texts ----

    const val ATOMICITY_REMEDIATION =
        "Make consumeOnce / advance one atomic operation on the shared store, e.g. Postgres INSERT .. ON CONFLICT (key) DO UPDATE .. WHERE until < \$now RETURNING and UPDATE .. WHERE counter < \$n RETURNING, Redis SET key NX PX or a Lua compare-and-set; never read, then write. Then run the full kit: pca-store-conformance --adapter <your adapter>."
    const val DURABILITY_REMEDIATION =
        "Keep consumed keys and counters in a store with synchronous, persistent commits (Postgres synchronous_commit=on; Redis appendfsync always and maxmemory-policy noeviction), shared by every verifier instance. An in-memory store is only correct for a single process whose lifetime covers the action lifetime."

    // ---- root caveats and enforcement ----

    const val ROOT_CAVEAT_MIN_VERSION = "0.4.1"
    const val CAVEAT_REMEDIATION =
        "Upgrade @atlasauth/pca to >= 0.4.1 in the deployed application (root caveats outside the envelope are enforced from 0.4.1), redeploy, and re-run pca-doctor with --pca-dir pointing at the application."
    val DEFAULT_REQUIRED: List<String> = listOf("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")

    /** The decision of one probe: whether the payment was allowed, and the reasons given. */
    class Decision(val allowed: Boolean, val reasons: List<String>) {
        fun toJson(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["allowed"] = allowed
            m["reasons"] = ArrayList<Any?>(reasons)
            return m
        }
    }

    /** Decide a payment of `amount` USD under a root grant carrying `rootCaveat`, through the library under test. */
    fun interface Probe {
        fun decide(rootCaveat: Map<String, Any?>, amount: Double): Decision
    }

    /** The library under test: its version, where it was found, and how to probe it. */
    class LoadedPca(val version: String, val path: String, val probe: Probe)

    /**
     * Decide a payment of [amount] USD under a root grant carrying [rootCaveat], through THIS library's own policy VM: a fresh principal mints an
     * envelope grant, the root caveat is appended to its caveats outside the envelope, the task hop delegates to a fresh agent key and
     * [Decide.decide] answers. The native counterpart of probing a loaded module (the reference's `probeDecision`).
     */
    @JvmOverloads
    fun probeDecision(rootCaveat: Map<String, Any?>, amount: Double, now: Long = System.currentTimeMillis()): Decision {
        val ed = Keys.edGenerate()
        val principal = Keys.ed25519(ed)
        val pPub = ed.id()
        val envelope = linkedMapOf<String, Any?>(
            "predicates" to listOf(linkedMapOf<String, Any?>("verb" to "pay", "resource" to "invoice:*")),
            "caveats" to listOf(linkedMapOf<String, Any?>("type" to "expires", "at" to now + 3_600_000L)),
            "agent_binding" to LinkedHashMap<String, Any?>(), "risk_policy" to Issue.defaultRiskPolicy(),
        )
        val g0 = Issue.mintGrant(principal, pPub, null, envelope, "pca-doctor root caveat probe")
        val grant = Issue.mintRoot(principal, pPub, null, (g0.grant["caveats"] as List<*>) + listOf<Any?>(rootCaveat))
        val task = Issue.delegate(grant, Keys.edGenerate().id(), emptyList(), principal)
        val action = linkedMapOf<String, Any?>(
            "verb" to "pay", "resource" to "invoice:42", "reversibility_class" to "reversible",
            "params" to linkedMapOf<String, Any?>("amount" to Json.Num(java.math.BigDecimal.valueOf(amount).stripTrailingZeros().toPlainString()), "currency" to "usd"),
        )
        val d = Decide.decide(
            linkedMapOf(
                "grant" to grant, "chain" to listOf(grant, task), "action" to linkedMapOf<String, Any?>("action" to action),
                "risk" to linkedMapOf<String, Any?>("reversibility" to 1L, "blastRadius" to 0L, "confidence" to 1L, "semanticDistance" to 0L, "taint" to 0L),
                "budget" to linkedMapOf<String, Any?>("B" to 1_000_000_000L, "tau" to now, "asOf" to now), "now" to now,
            ),
        )
        val reasons = (d["reasons"] as? List<*>)?.map { Js.str(it) } ?: emptyList()
        return Decision(d["releaseGuardianShare"] == true, reasons)
    }

    /** A loader for [checkRootCaveats] that probes this very library: its own version and [probeDecision]. */
    @JvmOverloads
    fun nativeLoader(version: String, path: String = "native"): (String?) -> LoadedPca =
        { _ -> LoadedPca(version, path, Probe { caveat, amount -> probeDecision(caveat, amount) }) }

    /** -1 / 0 / 1 for a < b / = / > b over major.minor.patch (pre-release tags ignored); NaN parts compare as -1. */
    fun compareVersion(a: String, b: String): Int {
        val sep = Regex("[.+-]")
        val pa = a.split(sep)
        val pb = b.split(sep)
        for (i in 0 until 3) {
            var x = if (i < pa.size) Js.toNumber(pa[i]) else Double.NaN
            var y = if (i < pb.size) Js.toNumber(pb[i]) else Double.NaN
            if (x.isNaN() || x.isInfinite()) x = -1.0
            if (y.isNaN() || y.isInfinite()) y = -1.0
            if (x != y) return if (x < y) -1 else 1
        }
        return 0
    }

    private fun obj(vararg kv: Any?): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    private fun noLoader(@Suppress("UNUSED_PARAMETER") dir: String?): LoadedPca =
        throw IllegalStateException("no @atlasauth/pca loader is configured (the JVM cannot load the deployed library; supply a loader that probes it)")

    /** Root-caveat enforcement of the deployed library: version >= 0.4.1, and a probe (max_spend 100 denies 150 and allows 50; an unknown caveat type denies). */
    fun checkRootCaveats(cfg: Map<String, Any?>, loadPca: ((String?) -> LoadedPca)?): CheckResult {
        val id = "caveats.root"
        val dir = Js.g(Js.g(cfg, "verifier"), "pcaDir")
        val pcaDir: String? = if (Js.truthy(dir)) Js.str(dir) else null
        val pca = try {
            (loadPca ?: ::noLoader)(pcaDir)
        } catch (e: RuntimeException) {
            return CheckResult.of(id, "fail", "cannot load @atlasauth/pca" + (if (pcaDir != null) " from $pcaDir" else "") + ": " + e.message).fix(CAVEAT_REMEDIATION)
        }
        val where = "@atlasauth/pca ${pca.version} at ${pca.path}"
        if (compareVersion(pca.version, ROOT_CAVEAT_MIN_VERSION) < 0) {
            return CheckResult.of(id, "fail", "$where: root caveats outside the envelope are NOT enforced before $ROOT_CAVEAT_MIN_VERSION (legacy behaviour)").fix(CAVEAT_REMEDIATION)
        }
        val probes: List<Decision> = try {
            listOf(
                pca.probe.decide(obj("type", "max_spend", "usd", 100), 150.0),
                pca.probe.decide(obj("type", "max_spend", "usd", 100), 50.0),
                pca.probe.decide(obj("type", "pca-doctor-unknown-caveat"), 50.0),
            )
        } catch (e: Exception) {
            return CheckResult.of(id, "fail", "$where: the enforcement probe could not run: " + e.message).fix(CAVEAT_REMEDIATION)
        }
        val over = probes[0]
        val under = probes[1]
        val unknown = probes[2]
        val observed = obj("version", pca.version, "over", over.toJson(), "under", under.toJson(), "unknown", unknown.toJson())
        if (over.allowed || unknown.allowed) {
            return CheckResult.of(id, "fail", "$where: a root caveat was NOT enforced (" + (if (over.allowed) "max_spend 100 allowed a 150 payment" else "an unknown root caveat type was allowed") + ")")
                .fix(CAVEAT_REMEDIATION).observed(observed)
        }
        if (!under.allowed) {
            return CheckResult.of(id, "warn", "$where: inconclusive: the control payment within the root max_spend was denied too (" + under.reasons.joinToString("; ") + ")").observed(observed)
        }
        return CheckResult.of(id, "pass", "$where: root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)").observed(observed)
    }

    /** requirePCA must not run with insecureAllowUnenforced, and a custom require list should keep the defaults. */
    @Suppress("UNCHECKED_CAST")
    fun checkEnforcement(cfg: Map<String, Any?>): CheckResult {
        val id = "verifier.enforcement"
        val v = Js.g(cfg, "verifier")
        if (!Js.truthy(v)) return CheckResult.of(id, "skip", "no verifier configuration given (config verifier.*)")
        if (Js.g(v, "insecureAllowUnenforced") == true) {
            return failed(id, "requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny", "Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).")
        }
        val req = Js.g(v, "require")
        if (!Js.isUndef(req)) {
            if (req == null) throw NullPointerException("Cannot read properties of null (reading 'includes')")
            val missing = ArrayList<String>()
            for (c in DEFAULT_REQUIRED) {
                val has = when (req) {
                    is List<*> -> (req as List<Any?>).contains(c)
                    is String -> req.contains(c)
                    else -> throw IllegalStateException("require.includes is not a function")
                }
                if (!has) missing.add(c)
            }
            if (missing.isNotEmpty()) {
                return CheckResult.of(id, "warn", "the require list drops default check(s): " + missing.joinToString(", "))
                    .fix("Keep every default required check (" + DEFAULT_REQUIRED.joinToString(", ") + ") and add to it.")
            }
        }
        if (Js.truthy(req)) {
            if (req !is List<*>) throw IllegalStateException("require.join is not a function")
            val parts = ArrayList<String>()
            for (x in req) parts.add(if (Js.nullish(x)) "" else Js.str(x))
            return CheckResult.of(id, "pass", "require = " + parts.joinToString(", "))
        }
        return CheckResult.of(id, "pass", "default required checks; insecureAllowUnenforced off")
    }

    // ---- runDoctor ----

    val CHECK_GROUPS: List<String> = listOf("clock", "store", "proxy", "suites", "caveats")

    /** Collaborators of [runDoctor]; every member is optional (real HTTP, the wall clock, no library loader). */
    class DoctorDeps {
        var fetch: Fetch? = null
        var now: (() -> Long)? = null
        var loadPca: ((String?) -> LoadedPca)? = null
        var rand: (() -> Double)? = null
    }

    /** One check group that throws is a failed check, not a crashed run and not a skipped one. */
    private fun guarded(id: String, run: () -> List<CheckResult>): List<CheckResult> {
        return try {
            run()
        } catch (e: Exception) {
            listOf(
                CheckResult.of(id, "fail", "$id could not run: " + scrubText(e.message ?: e.toString()))
                    .fix("Fix the configuration or the dependency named above and run the doctor again."),
            )
        }
    }

    private fun one(r: CheckResult): List<CheckResult> = listOf(r)

    /** Numeric settings that would make a check meaningless (NaN, negative, zero where a duration is needed) are configuration errors. */
    fun configProblems(cfg: Map<String, Any?>): List<String> {
        val out = ArrayList<String>()
        val clock = Js.g(cfg, "clock")
        val store = Js.g(cfg, "store")
        val proxy = Js.g(cfg, "proxy")
        pos(out, "clock.maxSkewMs", Js.g(clock, "maxSkewMs"), false)
        pos(out, "clock.timeoutMs", Js.g(clock, "timeoutMs"), false)
        val wf = Js.g(clock, "warnFraction")
        if (!Js.isUndef(wf)) {
            val d = Js.num(wf)
            if (!(d != null && d > 0 && d <= 1)) out.add("clock.warnFraction must be a number in (0, 1]")
        }
        pos(out, "store.concurrency", Js.g(store, "concurrency"), true)
        pos(out, "store.rounds", Js.g(store, "rounds"), true)
        nonneg(out, "proxy.trustedProxyCount", Js.g(proxy, "trustedProxyCount"))
        nonneg(out, "proxy.hops", Js.g(proxy, "hops"))
        val url = Js.g(cfg, "url")
        if (!Js.isUndef(url)) {
            try {
                if (url !is String) throw IllegalArgumentException("not a URL")
                val u = URI.create(url)
                val scheme = u.scheme ?: throw IllegalArgumentException("not a URL")
                val sch = scheme.lowercase()
                if (sch == "https" || sch == "http") {
                    if (u.host == null) throw IllegalArgumentException("not a URL")
                } else out.add("url must be an http(s) URL")
            } catch (e: IllegalArgumentException) {
                out.add("url is not a valid URL")
            }
        }
        return out
    }

    private fun pos(out: MutableList<String>, name: String, v: Any?, integer: Boolean) {
        if (Js.isUndef(v)) return
        val d = Js.num(v)
        if (d == null || d.isNaN() || d.isInfinite() || d <= 0 || (integer && !Js.isInteger(v))) out.add(name + " must be a positive " + (if (integer) "integer" else "number"))
    }

    private fun nonneg(out: MutableList<String>, name: String, v: Any?) {
        if (Js.isUndef(v)) return
        if (!Js.isInteger(v) || Js.num(v)!! < 0 || Js.isNegZero(v)) out.add("$name must be a non-negative integer")
    }

    /** Run the selected check groups (all by default) and scrub everything they report. */
    @Suppress("UNCHECKED_CAST")
    fun runDoctor(cfg: Map<String, Any?>, only: List<String>?, deps: DoctorDeps?): List<CheckResult> {
        val d = deps ?: DoctorDeps()
        val sel = only ?: CHECK_GROUPS
        val problems = configProblems(cfg)
        if (problems.isNotEmpty()) {
            val out = ArrayList<CheckResult>()
            for (p in problems) out.add(CheckResult.of("config", "fail", scrubText("invalid configuration: $p")).fix("Correct the setting; no check was run."))
            return out
        }
        val fetch: Fetch = d.fetch ?: HttpFetch()
        val out = ArrayList<CheckResult>()
        if ("clock" in sel) out.addAll(guarded("clock") { one(checkClock(cfg, fetch, d.now)) })
        if ("store" in sel) out.addAll(guarded("store") { DoctorStore.checkStore(cfg) })
        if ("proxy" in sel) {
            out.addAll(guarded("proxy.config") { one(checkProxyConfig(cfg)) })
            out.addAll(guarded("proxy.probe") { one(checkProxyProbe(cfg, fetch, d.rand)) })
        }
        if ("suites" in sel) {
            out.addAll(guarded("suites.allowed") { one(checkAllowedSuites(cfg)) })
            out.addAll(guarded("suites.pq") { one(checkPqBinding(cfg)) })
        }
        if ("caveats" in sel) {
            out.addAll(guarded("caveats.root") { one(checkRootCaveats(cfg, d.loadPca)) })
            out.addAll(guarded("caveats.enforcement") { one(checkEnforcement(cfg)) })
        }
        val scrubbed = ArrayList<CheckResult>()
        for (r in out) scrubbed.add(CheckResult.fromJson(scrubDeep(r.json) as Map<String, Any?>))
        return scrubbed
    }

    /** fail if any check failed; warn if any warned (fail under strict); else pass. A run in which nothing was checked is a fail. */
    fun verdictOf(results: List<CheckResult>, strict: Boolean): String {
        var any = false
        var fail = false
        var warn = false
        for (r in results) {
            val s = r.status()
            if (s != "skip") any = true
            if (s == "fail") fail = true
            if (s == "warn") warn = true
        }
        if (!any) return "fail"
        if (fail) return "fail"
        if (warn) return if (strict) "fail" else "warn"
        return "pass"
    }

    fun formatResults(results: List<CheckResult>, target: String?, strict: Boolean): String {
        val lines = ArrayList<String>()
        lines.add("pca-doctor" + (if (target != null && target.isNotEmpty()) ": $target" else ""))
        for (r in results) {
            lines.add("  " + Js.padEnd(r.status().uppercase(), 4) + "  " + Js.padEnd(r.id(), 20) + " " + r.detail())
            val fx = r.remediation()
            if (fx != null) lines.add("  " + Js.padEnd("", 4) + "  " + Js.padEnd("", 20) + " fix: " + fx)
        }
        var anyChecked = false
        val n = IntArray(4)
        val names = arrayOf("pass", "warn", "fail", "skip")
        for (r in results) {
            if (r.status() != "skip") anyChecked = true
            for (i in 0 until 4) if (r.status() == names[i]) n[i]++
        }
        if (!anyChecked) lines.add("  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified")
        lines.add("Summary: ${n[0]} pass, ${n[1]} warn, ${n[2]} fail, ${n[3]} skip -> " + verdictOf(results, strict).uppercase())
        return lines.joinToString("\n")
    }

    // ---- configuration ----

    private val TRUTHY = Regex("(?i)1|true|yes|on")
    private val PROXY_HEADERS: List<String> = listOf("x-forwarded-for", "forwarded", "x-real-ip")

    private fun envInt(name: String, v: String?): Any {
        if (v == null || v.isEmpty()) return Js.UNDEF
        val n = Js.toNumber(v)
        if (n.isNaN() || n.isInfinite() || n != Math.rint(n) || n < 0 || (n == 0.0 && 1 / n < 0)) throw IllegalArgumentException("$name must be a non-negative integer")
        return n
    }

    private fun has(v: String?): Boolean = v != null && v.isNotEmpty()

    /** The deployment's own environment variable names (as the API and the guides use them). */
    fun configFromEnv(env: Map<String, String>): Map<String, Any?> {
        val c = LinkedHashMap<String, Any?>()
        if (has(env["PCA_DOCTOR_URL"])) c["url"] = env["PCA_DOCTOR_URL"]
        if (has(env["PCA_DOCTOR_REFERENCE_URL"])) c["clock"] = obj("referenceUrl", env["PCA_DOCTOR_REFERENCE_URL"])
        if (has(env["PCA_DOCTOR_STORE"])) c["store"] = obj("adapter", env["PCA_DOCTOR_STORE"])
        val proxy = LinkedHashMap<String, Any?>()
        if (env["TRUSTED_PROXY_COUNT"] != null) proxy["trustedProxyCount"] = envInt("TRUSTED_PROXY_COUNT", env["TRUSTED_PROXY_COUNT"])
        if (has(env["TRUSTED_PROXY_HEADER"])) {
            val h = env["TRUSTED_PROXY_HEADER"]!!.lowercase()
            if (h !in PROXY_HEADERS) throw IllegalArgumentException("TRUSTED_PROXY_HEADER must be one of " + PROXY_HEADERS.joinToString(", "))
            proxy["header"] = h
        }
        if (env["PCA_TRUSTED_PROXY_HOPS"] != null) proxy["hops"] = envInt("PCA_TRUSTED_PROXY_HOPS", env["PCA_TRUSTED_PROXY_HOPS"])
        if (proxy.isNotEmpty()) c["proxy"] = proxy
        val v = LinkedHashMap<String, Any?>()
        if (env["PCA_ALLOWED_SUITES"] != null) {
            val suites = ArrayList<Any?>()
            for (s in env["PCA_ALLOWED_SUITES"]!!.split(",")) { val t = Js.trim(s); if (t.isNotEmpty()) suites.add(t) }
            v["allowedSuites"] = suites
        }
        if (has(env["PCA_PQ_PINS"])) {
            val pins: Any? = try {
                Json.parseLenient(env["PCA_PQ_PINS"])
            } catch (e: RuntimeException) {
                throw IllegalArgumentException("PCA_PQ_PINS is not valid JSON") // never echo the value
            }
            var ok = pins is Map<*, *>
            if (ok) for (x in (pins as Map<*, *>).values) if (x !is String) ok = false
            if (!ok) throw IllegalArgumentException("PCA_PQ_PINS must be a JSON object of issuer -> public key strings")
            v["pqPins"] = pins
        }
        if (env["PCA_ALLOW_UNBOUND_PQ"] != null) v["allowUnboundPq"] = TRUTHY.matches(env["PCA_ALLOW_UNBOUND_PQ"]!!)
        if (v.isNotEmpty()) c["verifier"] = v
        return c
    }

    @Suppress("UNCHECKED_CAST")
    private fun spreadInto(into: MutableMap<String, Any?>, base: Any?) {
        if (base is Map<*, *>) into.putAll(base as Map<String, Any?>)
        else if (base is List<*>) { for (i in base.indices) into[i.toString()] = base[i] }
        else if (base is String) { for (i in base.indices) into[i.toString()] = base.substring(i, i + 1) }
    }

    /** Two-level merge: later sources win per field inside each section. */
    @Suppress("UNCHECKED_CAST")
    fun mergeConfig(cs: List<Map<String, Any?>>): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for (c in cs) {
            for ((k, v) in c) {
                if (k == "__proto__" || k == "constructor" || k == "prototype") throw IllegalArgumentException("config key \"$k\" is not allowed")
                if (v === Js.UNDEF) continue
                if (Js.truthy(v) && v is Map<*, *>) {
                    val merged = LinkedHashMap<String, Any?>()
                    val prev = out[k]
                    if (prev != null && prev !== Js.UNDEF) spreadInto(merged, prev)
                    merged.putAll(v as Map<String, Any?>)
                    out[k] = merged
                } else out[k] = v
            }
        }
        return out
    }

    /** A JSON file. Known limit: the reference also loads a JS module exporting the config; that has no JVM counterpart. */
    @Suppress("UNCHECKED_CAST")
    fun loadConfigFile(path: String): Map<String, Any?> {
        if (!path.endsWith(".json")) throw UnsupportedOperationException("only a .json config file can be loaded: $path")
        val v = Json.parseLenient(File(path).readText(Charsets.UTF_8))
        if (v !is Map<*, *>) throw IllegalArgumentException("config file is not a JSON object: $path")
        return v as Map<String, Any?>
    }

    // ---- CLI ----

    val USAGE: String = "pca-doctor [--url <deployment>] [options]\n\n" +
        "  --url URL              the live deployment (base URL of the API that verifies PCActns)\n" +
        "  --config FILE          JSON or JS config (see the pca-doctor guide); env and flags override it\n" +
        "  --store MODULE         replay-store adapter module (store conformance kit interface) for the atomicity / durability checks\n" +
        "  --store-option k=v     passed to the adapter factory (repeatable)\n" +
        "  --reference URL|local  clock reference (default https://www.google.com/generate_204)\n" +
        "  --max-skew-ms N        clock fail threshold (default 60000)\n" +
        "  --trusted-proxy-count N, --proxy-header H, --proxy-hops N   the deployment's proxy settings and the real hop count\n" +
        "  --pca-dir DIR          the deployed application's directory (its installed @atlasauth/pca is probed)\n" +
        "  --only a,b | --skip a,b   check groups: " + CHECK_GROUPS.joinToString(", ") + "\n" +
        "  --no-probe             do not send forged forwarding headers to the deployment\n" +
        "  --strict               warnings fail too\n" +
        "  --json                 machine-readable output\n\n" +
        "Env: PCA_DOCTOR_URL, PCA_DOCTOR_REFERENCE_URL, PCA_DOCTOR_STORE, TRUSTED_PROXY_COUNT, TRUSTED_PROXY_HEADER, PCA_TRUSTED_PROXY_HOPS,\n" +
        "     PCA_ALLOWED_SUITES (comma list), PCA_PQ_PINS (JSON), PCA_ALLOW_UNBOUND_PQ."

    private fun groups(flag: String, v: String?): List<String> {
        val g = ArrayList<String>()
        for (x in (v ?: "").split(",")) if (x.isNotEmpty()) g.add(x)
        val bad = ArrayList<String>()
        for (x in g) if (x !in CHECK_GROUPS) bad.add(x)
        if (bad.isNotEmpty() || g.isEmpty()) throw IllegalArgumentException("$flag: unknown check group(s) " + (if (bad.isEmpty()) "(none given)" else bad.joinToString(", ")))
        return g
    }

    private fun numArg(flag: String, v: String?): Double {
        val n = if (v == null || v.isEmpty()) Double.NaN else Js.toNumber(v)
        if (n.isNaN() || n.isInfinite()) throw IllegalArgumentException("$flag needs a number")
        return n
    }

    @Suppress("UNCHECKED_CAST")
    private fun sub(flags: MutableMap<String, Any?>, k: String): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        val cur = flags[k]
        if (cur is Map<*, *>) m.putAll(cur as Map<String, Any?>)
        flags[k] = m
        return m
    }

    /** The parsed command line: `flags` (a config), `only`, `json`, `strict`, `help` and an optional `config` path. */
    @Suppress("UNCHECKED_CAST")
    fun parseDoctorArgs(argv: List<String>): Map<String, Any?> {
        val flags = LinkedHashMap<String, Any?>()
        var only: List<String> = ArrayList(CHECK_GROUPS)
        var json = false
        var strict = false
        var help = false
        var config: String? = null
        var i = 0
        while (i < argv.size) {
            val k = argv[i]
            val nx: String? = if (i + 1 < argv.size) argv[i + 1] else null // next() consumes even when absent
            when (k) {
                "--url" -> { i++; flags["url"] = nx ?: Js.UNDEF }
                "--config" -> { i++; config = nx }
                "--store" -> { i++; sub(flags, "store")["adapter"] = nx ?: Js.UNDEF }
                "--store-option" -> {
                    i++
                    val kv = nx ?: ""
                    val eq = kv.indexOf('=')
                    if (eq < 1) throw IllegalArgumentException("--store-option needs k=v")
                    val st = sub(flags, "store")
                    val opts = LinkedHashMap<String, Any?>()
                    val cur = st["options"]
                    if (cur is Map<*, *>) opts.putAll(cur as Map<String, Any?>)
                    opts[kv.substring(0, eq)] = kv.substring(eq + 1)
                    st["options"] = opts
                }
                "--reference" -> { i++; sub(flags, "clock")["referenceUrl"] = nx ?: Js.UNDEF }
                "--max-skew-ms" -> { i++; sub(flags, "clock")["maxSkewMs"] = numArg(k, nx) }
                "--trusted-proxy-count" -> { i++; sub(flags, "proxy")["trustedProxyCount"] = numArg(k, nx) }
                "--proxy-header" -> {
                    i++
                    val h = (nx ?: "").lowercase()
                    if (h !in PROXY_HEADERS) throw IllegalArgumentException("--proxy-header must be x-forwarded-for, forwarded or x-real-ip")
                    sub(flags, "proxy")["header"] = h
                }
                "--proxy-hops" -> { i++; sub(flags, "proxy")["hops"] = numArg(k, nx) }
                "--no-probe" -> sub(flags, "proxy")["probe"] = false
                "--pca-dir" -> { i++; sub(flags, "verifier")["pcaDir"] = nx ?: Js.UNDEF }
                "--only" -> { i++; only = groups(k, nx) }
                "--skip" -> {
                    i++
                    val s = groups(k, nx)
                    val keep = ArrayList<String>()
                    for (g in only) if (g !in s) keep.add(g)
                    only = keep
                }
                "--strict" -> strict = true
                "--json" -> json = true
                "-h", "--help" -> help = true
                else -> throw IllegalArgumentException("unknown argument $k")
            }
            i++
        }
        val a = LinkedHashMap<String, Any?>()
        a["flags"] = flags
        a["only"] = ArrayList<Any?>(only)
        a["json"] = json
        a["strict"] = strict
        a["help"] = help
        if (config != null) a["config"] = config
        return a
    }

    /** Run the CLI: exit code 1 on any fail (and on warn under --strict), 2 on usage errors, else 0. */
    @Suppress("UNCHECKED_CAST")
    fun main(argv: List<String>, env: Map<String, String>, print: (String) -> Unit, printErr: (String) -> Unit, deps: DoctorDeps?): Int {
        val parsed: Pair<Map<String, Any?>, Map<String, Any?>>? = try {
            val pa = parseDoctorArgs(argv)
            if (pa["help"] == true) {
                null
            } else {
                val sources = ArrayList<Map<String, Any?>>()
                val cf = pa["config"] as String?
                sources.add(if (cf != null) loadConfigFile(cf) else LinkedHashMap<String, Any?>())
                sources.add(configFromEnv(env))
                sources.add(pa["flags"] as Map<String, Any?>)
                Pair(pa, mergeConfig(sources))
            }
        } catch (e: Exception) {
            printErr(scrubText(e.message) + "\n\n" + USAGE)
            return 2
        }
        if (parsed == null) {
            print(USAGE)
            return 0
        }
        val a = parsed.first
        val cfg = parsed.second
        val results = runDoctor(cfg, a["only"] as List<String>, deps)
        val strict = a["strict"] == true
        val verdict = verdictOf(results, strict)
        val url = Js.g(cfg, "url")
        if (a["json"] == true) {
            val rs = ArrayList<Any?>()
            for (r in results) rs.add(r.json)
            val doc = LinkedHashMap<String, Any?>()
            doc["target"] = if (Js.nullish(url)) null else url
            doc["verdict"] = verdict
            doc["results"] = rs
            print(Js.stringify(doc))
        } else {
            print(formatResults(results, if (Js.truthy(url)) Js.str(url) else null, strict))
        }
        return if (verdict == "fail") 1 else 0
    }

    /** Command-line entry. */
    @JvmStatic
    fun main(args: Array<String>) {
        val code = main(args.toList(), System.getenv(), { println(it) }, { System.err.println(it) }, null)
        System.exit(code)
    }
}
