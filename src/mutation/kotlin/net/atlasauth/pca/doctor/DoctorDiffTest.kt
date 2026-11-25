package net.atlasauth.pca.doctor

import net.atlasauth.pca.doctor.Doctor.CheckResult
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle for the deployment doctor (the oracle drives it through a fake fetch, a fake clock and a fake library table). */
@Suppress("UNCHECKED_CAST")
class DoctorDiffTest {
    private val MODULE = "ref-doctor"
    private val URL1 = "https://api.example.com"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun lng(o: Any?): Long = o.toString().toLong()

    /** The fake fetch + clock: each call pops the next response of its URL (the last repeats), advances the clock by rtt before answering. */
    private class Env(spec: Any?) {
        private val sp = spec as Map<String, Any?>
        var t: Long = sp["now"].toString().toLong()
        val responses: Map<String, Any?> = sp["responses"] as Map<String, Any?>
        val idx = HashMap<String, Int>()

        val fetch = Doctor.Fetch { _, url, _, _ ->
            val lst = responses[url] ?: throw Exception("no route $url")
            val rs = lst as List<Any?>
            val i = idx[url] ?: 0
            idx[url] = i + 1
            val r = rs[Math.min(i, rs.size - 1)] as Map<String, Any?>
            if (r["rtt"] != null) t += r["rtt"].toString().toLong()
            if (r["throw"] != null) throw Exception(r["throw"] as String)
            object : Doctor.Response {
                override fun status(): Int = 200
                override fun header(lowerName: String): String? = if (lowerName == "date") r["date"] as String? else if (lowerName == "ratelimit-remaining") r["rl"] as String? else null
            }
        }

        fun now(): Long = t
    }

    private fun allowed(a: Boolean, vararg reasons: String): Doctor.Decision = Doctor.Decision(a, ArrayList(reasons.toList()))

    /** The named fake library: behaviours enforce | ignore-max | ignore-unknown | deny-all | throws | nonarray-reasons | allow-all. */
    private fun loader(specO: Any?): (String?) -> Doctor.LoadedPca {
        val spec = m(specO)
        return { _ ->
            if (spec["throws"] != null) throw RuntimeException(spec["throws"] as String)
            val behavior = spec["behavior"] as String
            val p = Doctor.Probe { cav, amount ->
                when {
                    behavior == "throws" -> throw Exception("boom")
                    behavior == "allow-all" -> allowed(true)
                    behavior == "deny-all" -> allowed(false, "denied", "7")
                    behavior == "nonarray-reasons" -> allowed(false)
                    cav["type"] == "max_spend" ->
                        if (behavior == "ignore-max") allowed(true)
                        else if (amount <= cav["usd"].toString().toDouble()) allowed(true) else allowed(false, "over max_spend")
                    else -> if (behavior == "ignore-unknown") allowed(true) else allowed(false, "unknown caveat type")
                }
            }
            Doctor.LoadedPca(spec["version"] as String, spec["path"] as String, p)
        }
    }

    private fun results(o: Any?): List<CheckResult> = l(o).map { CheckResult.fromJson(m(it)) }
    private fun strEnv(o: Any?): Map<String, String> {
        val e = LinkedHashMap<String, String>()
        for ((k, v) in m(o)) e[k] = v as String
        return e
    }
    private fun strs(o: Any?): List<String> = l(o).map { it as String }
    private fun out(rs: List<CheckResult>): Any? = rs.map { it.toJson() }

    @Test fun consts() = OracleCases.each(MODULE, "consts") { _ ->
        val o = LinkedHashMap<String, Any?>()
        o["USAGE"] = Doctor.USAGE
        o["CHECK_GROUPS"] = ArrayList<Any?>(Doctor.CHECK_GROUPS)
        o["DEFAULT_REQUIRED"] = ArrayList<Any?>(Doctor.DEFAULT_REQUIRED)
        o["ROOT_CAVEAT_MIN_VERSION"] = Doctor.ROOT_CAVEAT_MIN_VERSION
        o["DEFAULT_REFERENCE_URL"] = Doctor.DEFAULT_REFERENCE_URL
        o["SUITES_REMEDIATION"] = Doctor.SUITES_REMEDIATION
        o["PQ_REMEDIATION"] = Doctor.PQ_REMEDIATION
        o["CLOCK_REMEDIATION"] = Doctor.CLOCK_REMEDIATION
        o["PROXY_REMEDIATION"] = Doctor.PROXY_REMEDIATION
        o["ATOMICITY_REMEDIATION"] = Doctor.ATOMICITY_REMEDIATION
        o["DURABILITY_REMEDIATION"] = Doctor.DURABILITY_REMEDIATION
        o["CAVEAT_REMEDIATION"] = Doctor.CAVEAT_REMEDIATION
        o
    }

    @Test fun scrubText() = OracleCases.each(MODULE, "scrubText") { a -> Doctor.scrubText(a[0]) }
    @Test fun scrubDeep() = OracleCases.each(MODULE, "scrubDeep") { a -> Doctor.scrubDeep(a[0]) }
    @Test fun checkAllowedSuites() = OracleCases.each(MODULE, "checkAllowedSuites") { a -> Doctor.checkAllowedSuites(m(a[0])).toJson() }
    @Test fun checkPqBinding() = OracleCases.each(MODULE, "checkPqBinding") { a -> Doctor.checkPqBinding(m(a[0])).toJson() }
    @Test fun checkProxyConfig() = OracleCases.each(MODULE, "checkProxyConfig") { a -> Doctor.checkProxyConfig(m(a[0])).toJson() }
    @Test fun testNetIp() = OracleCases.each(MODULE, "testNetIp") { a -> Doctor.testNetIp(Doctor.mulberry32(lng(a[0]))) }
    @Test fun forgedHeaders() = OracleCases.each(MODULE, "forgedHeaders") { a -> Doctor.forgedHeaders(Doctor.mulberry32(lng(a[0]))) }

    @Test fun checkClock() = OracleCases.each(MODULE, "checkClock") { a ->
        val e = Env(a[1])
        Doctor.checkClock(m(a[0]), e.fetch) { e.now() }.toJson()
    }

    @Test fun readDate() = OracleCases.each(MODULE, "readDate") { a ->
        val e = Env(a[1])
        Doctor.readDate(URL1, e.fetch, { e.now() }, 1000).toJson()
    }

    @Test fun checkProxyProbe() = OracleCases.each(MODULE, "checkProxyProbe") { a ->
        val e = Env(a[1])
        Doctor.checkProxyProbe(m(a[0]), e.fetch, Doctor.mulberry32(7)).toJson()
    }

    @Test fun compareVersion() = OracleCases.each(MODULE, "compareVersion") { a -> Doctor.compareVersion(a[0] as String, a[1] as String) }
    @Test fun checkRootCaveats() = OracleCases.each(MODULE, "checkRootCaveats") { a -> Doctor.checkRootCaveats(m(a[0]), loader(a[1])).toJson() }
    @Test fun checkEnforcement() = OracleCases.each(MODULE, "checkEnforcement") { a -> Doctor.checkEnforcement(m(a[0])).toJson() }
    @Test fun configProblems() = OracleCases.each(MODULE, "configProblems") { a -> ArrayList<Any?>(Doctor.configProblems(m(a[0]))) }
    @Test fun verdictOf() = OracleCases.each(MODULE, "verdictOf") { a -> Doctor.verdictOf(results(a[0]), a.size > 1 && a[1] == true) }

    @Test fun formatResults() = OracleCases.each(MODULE, "formatResults") { a -> Doctor.formatResults(results(a[0]), a[1] as String?, a[2] == true) }

    @Test fun configFromEnv() = OracleCases.each(MODULE, "configFromEnv") { a -> Doctor.json(Doctor.configFromEnv(strEnv(a[0]))) }

    @Test fun mergeConfig() = OracleCases.each(MODULE, "mergeConfig") { a -> Doctor.json(Doctor.mergeConfig(a.map { m(it) })) }

    @Test fun parseDoctorArgs() = OracleCases.each(MODULE, "parseDoctorArgs") { a -> Doctor.json(Doctor.parseDoctorArgs(strs(a[0]))) }

    @Test fun main() = OracleCases.each(MODULE, "main") { a ->
        val o = ArrayList<Any?>()
        val er = ArrayList<Any?>()
        val code = Doctor.main(strs(a[0]), strEnv(a[1]), { o.add(it) }, { er.add(it) }, null)
        val r = LinkedHashMap<String, Any?>()
        r["code"] = code
        r["out"] = o
        r["err"] = er
        r
    }

    @Test fun runDoctor() = OracleCases.each(MODULE, "runDoctor") { a ->
        val e = Env(a[2])
        val d = Doctor.DoctorDeps()
        d.fetch = e.fetch
        d.now = { e.now() }
        d.loadPca = loader(a[3])
        out(Doctor.runDoctor(m(a[0]), if (a[1] == null) null else strs(a[1]), d))
    }
}
