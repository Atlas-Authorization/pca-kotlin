package net.atlasauth.pca.research

import net.atlasauth.pca.verifier.Agent
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.BaseOracle
import net.atlasauth.pca.verifier.Facade
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.StoreJs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The research-tier pure modules (session, console with the immune read side, DLP, policy simulation, reputation evidence) against the reference. */
@Suppress("UNCHECKED_CAST")
class CoreResearchDiffTest {
    private val mod = "ref-core-research-java"

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun list(o: Any?): List<Any?> = o as List<Any?>

    private fun d(o: Any?): Double = StoreJs.dbl(o)!!

    private fun ed(label: Any?): Keys.EdKey = Keys.edFromSeed(OracleCases.seed("research/$label"))

    @Test fun dlp() {
        OracleCases.each(mod, "evaluateDlp") { a -> Dlp.evaluateDlp(map(a[0]), map(a[1])!!) }
        OracleCases.each(mod, "defaultDlpPolicy") { a -> Dlp.defaultDlpPolicy(map(a[0])!!) }
    }

    @Test fun immune() {
        OracleCases.each(mod, "assess") { a -> Immune.assess(a[0]) }
        OracleCases.each(mod, "validateImmuneState") { a -> Immune.validateImmuneState(a[0]) }
        OracleCases.each(mod, "observe") { a -> Immune.observe(map(a[0])!!, map(a[1])!!) }
        OracleCases.each(mod, "updateBaseline") { a -> Immune.updateBaseline(map(a[0])!!, d(a[1])) }
        OracleCases.each(mod, "baselineStd") { a -> StoreJs.num(Immune.baselineStd(map(a[0])!!)) }
    }

    @Test fun console() {
        OracleCases.each(mod, "buildConsole") { a -> Console.buildConsole(list(a[0])) }
        OracleCases.each(mod, "anomalies") { a -> Console.anomalies(Console.buildConsole(list(a[0]))) }
        OracleCases.each(mod, "eventFromPCActn") { a -> Console.eventFromPCActn(map(a[0])!!, a[1] as String?, if (a[2] == null) null else d(a[2])) }
        OracleCases.each(mod, "freezeAgent") { a -> Console.freezeAgent(map(a[0]), a[1]) }
        OracleCases.each(mod, "unfreezeAgent") { a -> Console.unfreezeAgent(map(a[0]), a[1]) }
        OracleCases.each(mod, "isFrozen") { a -> Console.isFrozen(a[0], a[1]) }
    }

    private fun agentOf(specO: Any?): Facade.Handle {
        val s = map(specO)!!
        return Agent.fromPrincipal(
            Facade.AgentOptions(
                Keys.ed25519(ed(s["principal"])), s["goal"] as String, map(s["permissions"])!!,
                holder = Keys.ed25519(ed(s["holder"])), goalSalt = s["goalSalt"] as String?, now = d(s["now"]).toLong(),
            ),
        )
    }

    private fun goalOf(h: Facade.Handle): String = Authorize.readEnvelope(h.grant)?.get("goal_commit") as? String ?: ""

    private fun <T> need(m: Map<String, T>, k: Any?): T = m[k as String] ?: throw IllegalStateException("unknown $k")

    @Test fun session() = OracleCases.each(mod, "session") { a ->
        val ags = HashMap<String, Facade.Handle>()
        val sess = HashMap<String, Session>()
        val out = ArrayList<Any?>()
        for (oo in a[0] as List<*>) {
            val op = oo as List<*>
            try {
                var v: Any? = null
                when (op[0] as String) {
                    "agent" -> { val h = agentOf(op[2]); ags[op[1] as String] = h; v = h.holder.ed!!.id() }
                    "start" -> { val s = Session.startSession(need(ags, op[2])); sess[op[1] as String] = s; v = s.goalCommit }
                    "mk" -> {
                        val ms = list(op[2]).map { need(ags, it) }
                        val goal = if (op[3] != null) op[3] as String else if (ms.isEmpty()) "" else goalOf(ms[0])
                        val s = Session(if (ms.isEmpty()) null else ms[0], ms, goal)
                        sess[op[1] as String] = s
                        v = s.goalCommit
                    }
                    "add" -> {
                        val child = if (op[3] == null) null else Keys.ed25519(ed(op[3]))
                        val cav = when (val c4 = op[4]) { // text spreads into its code points, as the reference's spread does
                            null -> null
                            is String -> c4.codePoints().toArray().map { String(Character.toChars(it)) }
                            else -> c4 as List<Any?>
                        }
                        val r = Session.addMember(need(sess, op[2]), child, cav)
                        sess[op[1] as String] = r.session
                        v = r.member.holder.ed!!.id()
                    }
                    "agents" -> v = ArrayList<Any?>(Session.sessionAgents(need(sess, op[1])))
                    "depth" -> v = Session.sessionDepth(need(sess, op[1]))
                    "shares" -> v = Session.sharesGoal(need(sess, op[1]))
                    "goal" -> v = need(sess, op[1]).goalCommit
                    "console" -> v = Session.sessionConsole(need(sess, op[1]), op[2] as List<Any?>)
                    else -> throw IllegalStateException("op")
                }
                out.add(v)
            } catch (t: Throwable) {
                out.add(linkedMapOf<String, Any?>("\$err" to "Error"))
            }
        }
        out
    }

    private fun compile(specO: Any?): Facade.CompiledPolicy {
        val s = map(specO)!!
        return Facade.compilePolicy(map(s["permissions"])!!, map(s["limits"]), null, s["budgetModel"] as String?, map(s["riskPolicy"]), d(s["now"]).toLong())
    }

    @Test fun policySim() {
        OracleCases.each(mod, "simulate") { a -> PolicySim.simulate(compile(a[0]), list(a[1]).map { map(it)!! }, null, if (a[2] == null) 0.0 else d(a[2])) }
        OracleCases.each(mod, "lintPolicy") { a -> PolicySim.lintPolicy(compile(a[0]), null) }
    }

    @Test fun reputationEvidence() = OracleCases.each(mod, "disputesFromSettlements") { a ->
        val guardian = if (a[1] == "@g") Keys.ed25519(ed("guardian")).ed!!.id() else a[1] as String
        val subjects = map(a[2])!!
        ReputationEvidence.disputesFromSettlements(list(a[0]), guardian, { id -> subjects[id] as? String }, if (a[3] == null) null else map(a[3]))
    }

    @Test fun everyFnIsReplayedAndTheTotalIsAsserted() {
        val fns = setOf(
            "evaluateDlp", "defaultDlpPolicy", "assess", "validateImmuneState", "observe", "updateBaseline", "baselineStd", "buildConsole", "anomalies",
            "eventFromPCActn", "freezeAgent", "unfreezeAgent", "isFrozen", "session", "simulate", "lintPolicy", "disputesFromSettlements",
        )
        assertEquals(fns, BaseOracle.fns("$mod.json.gz"))
        assertEquals(6188, fns.sumOf { OracleCases.of(mod, it).size })
    }

    @Test fun sessionAndFreezeBasics() {
        assertTrue("a malformed set fails closed", Console.isFrozen(null, "a"))
        var s = Console.freezeAgent(Console.emptyFreeze(), "b")
        s = Console.freezeAgent(s, "a")
        assertEquals(listOf("a", "b"), s["frozen"])
        assertTrue(Console.isFrozen(s, "a"))
        assertEquals(listOf("b"), Console.unfreezeAgent(s, "a")["frozen"])
    }
}
