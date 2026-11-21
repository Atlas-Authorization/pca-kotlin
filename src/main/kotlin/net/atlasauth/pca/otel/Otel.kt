package net.atlasauth.pca.otel

import java.util.regex.Pattern
import net.atlasauth.pca.jose.Js

/**
 * OpenTelemetry instrumentation for Proof-Carrying Authority: wrap a verification guard so every decision emits a span
 * (decision / tier / risk / verb / resource) and two metrics. The telemetry types are tiny structural interfaces that an
 * OpenTelemetry Span / Tracer / Counter / Histogram / Meter adapts to in a line each, so this package has no dependency on
 * OpenTelemetry. It observes and never decides: with no tracer and no meter the wrapper returns the guard's result unchanged.
 * Guard results and verdicts are JSON trees (Map / List / String / Boolean / Json.Num / null).
 */
object Otel {
    /** Minimal structural shape of an OpenTelemetry `Span`: only the methods this package touches. */
    interface SpanLike {
        /** [v] is a String, a number or a Boolean. */
        fun setAttribute(k: String, v: Any?)

        /** [message] is null when the status carries none. */
        fun setStatus(code: Int, message: String?)
        fun recordException(e: Throwable)
        fun end()
    }

    fun interface TracerLike { fun startSpan(name: String): SpanLike }

    fun interface CounterLike { fun add(n: Double, attrs: Map<String, Any?>) }

    fun interface HistogramLike { fun record(n: Double, attrs: Map<String, Any?>) }

    interface MeterLike {
        fun createCounter(name: String): CounterLike
        fun createHistogram(name: String): HistogramLike
    }

    /** OpenTelemetry `SpanStatusCode`: UNSET = 0, OK = 1, ERROR = 2, mirrored so the SDK is never imported. */
    const val STATUS_OK = 1
    const val STATUS_ERROR = 2

    private const val MAX_TEXT = 256

    // JavaScript whitespace (what \s matches), spelled out because the Java \s is ASCII only.
    private const val WS = " \\t\\n\\u000B\\f\\r\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"

    // \b before a word character, spelled out because the Java \b is Unicode-aware.
    private const val WB = "(?<![A-Za-z0-9_])"
    private val JWT = Pattern.compile(WB + "eyJ[\\w-]{5,}\\.[\\w-]{5,}\\.[\\w-]*")
    private val AUTH_HEADER = Pattern.compile(WB + "(authorization[\"']?[" + WS + "]*[:=][" + WS + "]*)[^\\n\"']*", Pattern.CASE_INSENSITIVE)
    private val SCHEME = Pattern.compile(WB + "(Bearer|Basic|Token)[" + WS + "]+[\\w.~+/=-]{6,}", Pattern.CASE_INSENSITIVE)
    private val URL_USERINFO = Pattern.compile("([a-z][a-z0-9+.-]*:\\/\\/)[^" + WS + "/@]*:[^" + WS + "/@]*@", Pattern.CASE_INSENSITIVE)
    private val KEYED = Pattern.compile(WB + "((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth)[\"']?[" + WS + "]*[:=][" + WS + "]*)(\"[^\"]*\"|'[^']*'|[^" + WS + "\"'&,;]+)", Pattern.CASE_INSENSITIVE)
    private val LONG_RUN = Pattern.compile("[A-Za-z0-9_-]{32,}")

    /**
     * Remove what looks like a credential from text bound for telemetry: JWTs, Bearer and Basic credentials, URL userinfo,
     * name=value pairs whose name is token, secret, password, key, signature, credential or authorization, and long unbroken
     * base64url or hex runs (32+ characters). The result is cut to 256 characters. A pattern list is a net, not a proof.
     */
    fun redactSecrets(text: String?): String {
        var t = text ?: "null"
        t = JWT.matcher(t).replaceAll("[redacted]")
        t = AUTH_HEADER.matcher(t).replaceAll("$1[redacted]")
        t = SCHEME.matcher(t).replaceAll("$1 [redacted]")
        t = URL_USERINFO.matcher(t).replaceAll("$1[redacted]@")
        val m = KEYED.matcher(t)
        val sb = StringBuilder()
        var last = 0
        while (m.find()) {
            val v = m.group(2)!!
            val q = if (v[0] == '"' || v[0] == '\'') v.substring(0, 1) else ""
            sb.append(t, last, m.start()).append(m.group(1)).append(q).append("[redacted]").append(q)
            last = m.end()
        }
        sb.append(t, last, t.length)
        t = sb.toString()
        t = LONG_RUN.matcher(t).replaceAll("[redacted]")
        return if (t.length > MAX_TEXT) t.substring(0, MAX_TEXT) + "..." else t
    }

    private fun g(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null

    /** `o?.[0]` over a JSON value: the first element of an array, the first character of a string, member "0" of an object. */
    private fun first(o: Any?): Any? = when (o) {
        is List<*> -> if (o.isEmpty()) null else o[0]
        is String -> if (o.isEmpty()) null else o.substring(0, 1)
        is Map<*, *> -> o["0"]
        else -> null
    }

    /** The first deny reason, if any (a string), used for the span's error message and the `pca.reason` attribute. */
    private fun firstReason(result: Any?): String? = first(g(g(result, "verdict"), "reasons")) as? String

    private fun finite(v: Any?): Double? {
        val d = Js.num(v)
        return if (d != null && !d.isNaN() && !d.isInfinite()) d else null
    }

    /**
     * Map a guard result to OpenTelemetry span attributes. Fields the verdict lacks are omitted; `pca.reason` is added on deny
     * only; anything but an explicit `ok: true` is reported as a deny.
     */
    @JvmOverloads fun pcaSpanAttributes(result: Any?, redact: ((String) -> String)? = null): Map<String, Any?> {
        val rd: (String) -> String = redact ?: { redactSecrets(it) }
        val attrs = LinkedHashMap<String, Any?>()
        val ok = g(result, "ok") == true
        attrs["pca.decision"] = if (ok) "allow" else "deny"
        val status = g(result, "status")
        if (finite(status) != null) attrs["pca.status"] = status
        val verdict = g(result, "verdict")
        val tier = g(g(verdict, "requiredThreshold"), "t")
        if (finite(tier) != null) attrs["pca.tier"] = tier
        val risk = g(verdict, "r")
        if (finite(risk) != null) attrs["pca.risk"] = risk
        val action = g(g(result, "pcactn"), "action")
        val verb = g(action, "verb")
        if (verb is String) attrs["pca.verb"] = rd(verb)
        val resource = g(action, "resource")
        if (resource is String) attrs["pca.resource"] = rd(resource)
        if (!ok) {
            val reason = firstReason(result)
            if (reason != null) attrs["pca.reason"] = rd(reason)
        }
        return attrs
    }

    /** The guard being observed: a request in, a result tree out (it may throw). */
    fun interface Guard<Req> { fun apply(req: Req): Any? }

    /** Options for [instrumentGuard]; leave tracer and meter null for a pure pass-through. */
    class InstrumentGuardOptions {
        var tracer: TracerLike? = null
        var meter: MeterLike? = null
        var spanName: String? = null

        /** Applied to every string that leaves in a span attribute, a status message or a recorded exception (default [redactSecrets]). */
        var redact: ((String) -> String)? = null
    }

    /** A fresh error handed to `recordException`: the original may carry credentials in its message, cause or stack. */
    class CleanError internal constructor(
        /** The original exception's simple class name when it is a plain word of at most 64 characters, else "Error". */
        val errorName: String,
        message: String,
    ) : RuntimeException(message, null, false, false) // no cause, no stack

    private fun safe(f: () -> Unit) {
        try { f() } catch (e: RuntimeException) { /* the decision is the guard's, not the exporter's */ }
    }

    private val NAME_OK = Regex("[A-Za-z0-9_]{1,64}")

    /**
     * Wrap a verification guard so each decision emits a span and metrics; the result is returned unchanged. A span named
     * `spanName` (default "pca.verify") is annotated with [pcaSpanAttributes], given OK status on allow and ERROR status
     * plus the first reason on deny, and always ended. When the guard throws, a redacted copy of the exception is recorded and the
     * original is re-thrown. A `pca.verifications` counter and a `pca.verify.risk` histogram are created once and fed per
     * decision. A tracer or meter that throws never changes what the guard decided.
     */
    @JvmOverloads fun <Req> instrumentGuard(guard: Guard<Req>, opts: InstrumentGuardOptions? = null): Guard<Req> {
        val tracer = opts?.tracer
        val meter = opts?.meter
        val spanName = opts?.spanName ?: "pca.verify"
        val counter = meter?.createCounter("pca.verifications")
        val histogram = meter?.createHistogram("pca.verify.risk")
        val redact: (String) -> String = opts?.redact ?: { redactSecrets(it) }

        return Guard { req ->
            var span: SpanLike? = null
            safe { if (tracer != null) span = tracer.startSpan(spanName) }
            try {
                val result = guard.apply(req)
                val sp = span
                if (sp != null) {
                    safe {
                        for ((k, v) in pcaSpanAttributes(result, redact)) sp.setAttribute(k, v)
                        val ok = g(result, "ok") == true
                        val reason = if (ok) null else firstReason(result)
                        if (ok) sp.setStatus(STATUS_OK, null)
                        else sp.setStatus(STATUS_ERROR, if (reason != null) redact(reason) else null)
                    }
                }
                val decision = if (g(result, "ok") == true) "allow" else "deny"
                safe {
                    if (counter != null) {
                        val a = LinkedHashMap<String, Any?>()
                        a["decision"] = decision
                        counter.add(1.0, a)
                    }
                }
                val risk = finite(g(g(result, "verdict"), "r"))
                if (histogram != null && risk != null) {
                    safe {
                        val a = LinkedHashMap<String, Any?>()
                        a["decision"] = decision
                        histogram.record(risk, a)
                    }
                }
                result
            } catch (e: Exception) {
                val sp = span
                if (sp != null) {
                    safe {
                        val simple = e.javaClass.simpleName
                        val name = if (NAME_OK.matches(simple)) simple else "Error"
                        val clean = CleanError(name, redact(e.message ?: ""))
                        sp.recordException(clean)
                        sp.setStatus(STATUS_ERROR, clean.message)
                    }
                }
                throw e
            } finally {
                val sp = span
                if (sp != null) safe { sp.end() }
            }
        }
    }
}
