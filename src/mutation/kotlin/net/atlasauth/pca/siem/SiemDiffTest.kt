package net.atlasauth.pca.siem

import java.util.Collections
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Test

/** Replays the reference oracle over the SIEM event mapping, the credential scrubber and the sinks. */
@Suppress("UNCHECKED_CAST")
class SiemDiffTest {
    private val MOD = "ref-siem"

    private fun opts(a: List<Any?>): Map<String, Any?>? = if (a.size > 1) a[1] as Map<String, Any?>? else null
    private fun spec(a: List<Any?>): Map<String, Any?> = a[0] as Map<String, Any?>

    @Test fun toOcsfEvent() = OracleCases.each(MOD, "toOcsfEvent") { a -> Siem.toOcsfEvent(a[0], opts(a)) }

    @Test fun toCef() = OracleCases.each(MOD, "toCef") { a -> Siem.toCef(a[0], opts(a)) }

    @Test fun toEcs() = OracleCases.each(MOD, "toEcs") { a -> Siem.toEcs(a[0], opts(a)) }

    @Test fun formatDecision() = OracleCases.each(MOD, "formatDecision") { a -> Siem.formatDecision(a[0], a[1] as String?, a[2] as Map<String, Any?>?).toMap() }

    @Test fun scrubError() = OracleCases.each(MOD, "scrubError") { a -> Siem.scrubError(a[0] as String?) }

    @Test fun httpSinkScenario() = OracleCases.each(MOD, "httpSinkScenario") { a ->
        val s = spec(a)
        val mode = s["mode"] as String
        val format = s["format"] as String?
        val calls = Collections.synchronizedList(ArrayList<Map<String, Any?>>())
        val o = Siem.HttpSinkOptions(format)
        if (s["headers"] != null) {
            val h = LinkedHashMap<String, String>()
            for ((k, v) in s["headers"] as Map<String, Any?>) h[k] = v as String
            o.headers = h
        }
        o.contentType = s["contentType"] as String?
        o.name = s["name"] as String?
        if (s["timeoutMs"] != null) o.timeoutMs = Js.num(s["timeoutMs"])
        o.fetch = Siem.FetchLike { url, init ->
            val call = LinkedHashMap<String, Any?>()
            call["url"] = url
            call["method"] = init.method
            call["headers"] = LinkedHashMap<String, Any?>(init.headers)
            call["body"] = init.body
            calls.add(call)
            if (mode == "ok") return@FetchLike Siem.FetchLikeResponse(true, 200, null)
            if (mode.startsWith("st:")) {
                val p = mode.split(":", limit = 3)
                return@FetchLike Siem.FetchLikeResponse(false, p[1].toInt(), if (p.size > 2) p[2] else null)
            }
            if (mode.startsWith("throws:")) throw RuntimeException(mode.substring(7))
            Thread.sleep(500) // hang: outlive the sink's timeout
            Siem.FetchLikeResponse(true, 200, null)
        }
        val sink = Siem.httpSink(s["url"] as String, o)
        val events = (s["events"] as List<Any?>).map { Siem.formatDecision(it, format, null) }
        val out = LinkedHashMap<String, Any?>()
        val res = sink.deliver(events)
        out["name"] = sink.name()
        out["format"] = sink.format()
        out["result"] = res.toMap()
        if (calls.isNotEmpty()) out["request"] = calls[0]
        out
    }

    @Test fun consoleSinkScenario() = OracleCases.each(MOD, "consoleSinkScenario") { a ->
        val s = spec(a)
        val lines = ArrayList<Any?>()
        val throwsMsg = s["throws"] as String?
        val o = Siem.ConsoleSinkOptions()
        o.format = s["format"] as String?
        o.name = s["name"] as String?
        o.logger = { l -> if (throwsMsg != null) throw RuntimeException(throwsMsg); lines.add(l); Unit }
        val sink = Siem.consoleSink(o)
        val events = (s["records"] as List<Any?>).map { Siem.formatDecision(it, sink.format(), null) }
        val out = LinkedHashMap<String, Any?>()
        val res = sink.deliver(events)
        out["name"] = sink.name()
        out["format"] = sink.format()
        out["result"] = res.toMap()
        out["lines"] = lines
        out
    }

    @Test fun exportScenario() = OracleCases.each(MOD, "exportScenario") { a ->
        val s = spec(a)
        val mode = s["sinkMode"] as String
        val format = s["format"] as String?
        val errors = ArrayList<Any?>()
        val delivered = ArrayList<Any?>()
        val sink = object : Siem.SiemSink {
            override fun name(): String = "s1"
            override fun format(): String? = format
            override fun deliver(events: List<Siem.SiemEvent>): Siem.SinkResult {
                for (e in events) delivered.add(e.line)
                if (mode == "ok") return Siem.SinkResult.success()
                if (mode == "fail") return Siem.SinkResult.failure("collector said no token=abcdef123")
                if (mode == "failNoError") return Siem.SinkResult(false, null)
                throw RuntimeException("deliver exploded Bearer abcdefghij")
            }
        }
        val o = Siem.ExportOptions()
        o.serialize = s["serialize"] as Map<String, Any?>?
        val cbThrows = mode == "throwsOnError" || s["onErrorThrows"] == true
        o.onError = Siem.OnError { err, name, count ->
            val m = LinkedHashMap<String, Any?>()
            m["message"] = err.message
            m["sink"] = name
            m["count"] = count
            errors.add(m)
            if (cbThrows) throw RuntimeException("cb")
        }
        val out = LinkedHashMap<String, Any?>()
        out["result"] = Siem.exportBatch(s["records"] as List<Any?>, sink, o).toMap()
        out["errors"] = errors
        out["delivered"] = delivered
        out
    }

    @Test fun jsNumberText() {
        assertEquals("0", JsFmt.num(-0.0))
        assertEquals("1e+21", JsFmt.num(1e21))
        assertEquals("100000000000000000000", JsFmt.num(1e20))
        assertEquals("1.5e-7", JsFmt.num(1.5e-7))
        assertEquals("0.000001", JsFmt.num(1e-6))
        assertEquals("0.1", JsFmt.num(0.1))
        assertEquals("-12.5", JsFmt.num(-12.5))
        assertEquals("1800000000000", JsFmt.num(1_800_000_000_000.0))
    }
}
