package net.atlasauth.pca.otel

import java.util.Locale
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the OpenTelemetry attribute mapping, the secret redactor and the guard wrapper. */
@Suppress("UNCHECKED_CAST")
class OtelDiffTest {
    private val MOD = "ref-otel"

    private fun mode(m: Any?): ((String) -> String)? = when (m as String?) {
        null -> null
        "identity" -> ({ s: String -> s })
        "upper" -> ({ s: String -> s.uppercase(Locale.ROOT) })
        "brackets" -> ({ s: String -> "<$s>" })
        else -> throw IllegalArgumentException("mode $m")
    }

    private fun ev(ev: String): LinkedHashMap<String, Any?> { val m = LinkedHashMap<String, Any?>(); m["ev"] = ev; return m }

    @Test fun redactSecrets() = OracleCases.each(MOD, "redactSecrets") { a -> Otel.redactSecrets(a[0] as String?) }

    @Test fun pcaSpanAttributes() = OracleCases.each(MOD, "pcaSpanAttributes") { a -> Otel.pcaSpanAttributes(a[0], mode(a.getOrNull(1))) }

    @Test fun instrumentScenario() = OracleCases.each(MOD, "instrumentScenario") { a ->
        val spec = a[0] as Map<String, Any?>
        val events = ArrayList<Any?>()
        val tm = (spec["tracerMode"] as String?) ?: "ok"
        val mm = (spec["meterMode"] as String?) ?: "ok"
        val span = object : Otel.SpanLike {
            override fun setAttribute(k: String, v: Any?) {
                val e = ev("setAttribute"); e["k"] = k; e["v"] = v; events.add(e)
                if (tm == "attrThrows") throw RuntimeException("exporter boom")
            }
            override fun setStatus(code: Int, message: String?) {
                val e = ev("setStatus"); e["code"] = code; if (message != null) e["message"] = message; events.add(e)
                if (tm == "statusThrows") throw RuntimeException("exporter boom")
            }
            override fun recordException(e: Throwable) {
                val x = ev("recordException"); x["message"] = e.message; x["noStack"] = e.stackTrace.isEmpty(); events.add(x)
                if (tm == "recordThrows") throw RuntimeException("exporter boom")
            }
            override fun end() {
                events.add(ev("end"))
                if (tm == "endThrows") throw RuntimeException("exporter boom")
            }
        }
        val tracer = Otel.TracerLike { name ->
            val e = ev("startSpan"); e["name"] = name; events.add(e)
            if (tm == "startThrows") throw RuntimeException("exporter boom")
            span
        }
        val meter = object : Otel.MeterLike {
            override fun createCounter(name: String): Otel.CounterLike {
                val e = ev("createCounter"); e["name"] = name; events.add(e)
                if (mm == "createThrows") throw RuntimeException("exporter boom")
                return Otel.CounterLike { v, attrs ->
                    val x = ev("add"); x["v"] = v; x["a"] = attrs; events.add(x)
                    if (mm == "addThrows") throw RuntimeException("exporter boom")
                }
            }
            override fun createHistogram(name: String): Otel.HistogramLike {
                val e = ev("createHistogram"); e["name"] = name; events.add(e)
                return Otel.HistogramLike { v, attrs ->
                    val x = ev("record"); x["v"] = v; x["a"] = attrs; events.add(x)
                    if (mm == "recordThrows") throw RuntimeException("exporter boom")
                }
            }
        }
        val g = spec["guard"] as Map<String, Any?>
        val guard = Otel.Guard<String> { _ ->
            if (g["throws"] != null) throw RuntimeException(g["throws"] as String)
            g["result"]
        }
        val o = Otel.InstrumentGuardOptions()
        if (spec["tracer"] == true) o.tracer = tracer
        if (spec["meter"] == true) o.meter = meter
        o.spanName = spec["spanName"] as String?
        o.redact = mode(spec["redact"])
        val out = LinkedHashMap<String, Any?>()
        val wrapped: Otel.Guard<String> = try {
            Otel.instrumentGuard(guard, o)
        } catch (e: RuntimeException) {
            out["wrap"] = e.message
            out["events"] = events
            return@each out
        }
        var outcome = LinkedHashMap<String, Any?>()
        try { outcome["result"] = wrapped.apply("req") } catch (e: Exception) { outcome = LinkedHashMap(); outcome["threw"] = e.message }
        out["outcome"] = outcome
        out["events"] = events
        out
    }
}
