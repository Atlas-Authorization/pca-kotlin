package net.atlasauth.pca.research

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.StoreJs

/**
 * The principal's live agent console, data layer: projects a stream of activity events into a per-agent view with a threat read (see [Immune])
 * and models the kill switch. Pure and offline: a projection over records you feed it. The "freeze" is a local kill-switch set a client or
 * gateway consults before dispatching; authoritative revocation is the transparency ledger's revocation epoch.
 *
 * An event is `{at, agent, verb, resource, outcome: auto|step_up|deny|executed, r?, taint?, digest?, goalCommit?}`.
 */
@Suppress("UNCHECKED_CAST")
object Console {
    private fun n(d: Double): Json.Num = StoreJs.num(d)
    private fun n(l: Long): Json.Num = StoreJs.num(l)
    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>
    private fun isNum(x: Any?): Boolean = IntentJs.num(x)?.let { !it.isNaN() } == true
    private fun d(x: Any?): Double = IntentJs.num(x)!!
    private fun cmp(x: Double): Int = if (x == 0.0 || x.isNaN()) 0 else if (x < 0) -1 else 1

    /** An activity event from a proof-carrying action and the verifier's outcome; [at] may be null (then the action's `iat`). */
    fun eventFromPCActn(p: Map<String, Any?>, outcome: String?, at: Double?): Map<String, Any?> {
        val chain = p["cap_chain"] as? List<Any?> ?: throw IllegalArgumentException("eventFromPCActn: cap_chain must be a list")
        val leaf = if (chain.isEmpty()) null else map(chain[chain.size - 1])
        val action = map(p["action"]) ?: throw IllegalArgumentException("eventFromPCActn: action must be an object")
        val e = LinkedHashMap<String, Any?>()
        if (at != null) e["at"] = n(at) else if (p.containsKey("iat")) e["at"] = p["iat"]
        e["agent"] = if (leaf != null && leaf["holder"] != null) leaf["holder"] else "unknown"
        if (action.containsKey("verb")) e["verb"] = action["verb"]
        if (action.containsKey("resource")) e["resource"] = action["resource"]
        e["outcome"] = outcome
        val rc = map(p["risk_claim"])
        if (rc != null && rc.containsKey("r")) e["r"] = rc["r"]
        val pv = map(p["provenance"])
        if (pv != null && pv.containsKey("taint_level")) e["taint"] = pv["taint_level"]
        e["digest"] = Pca.hashCanonical(p)
        return e
    }

    private fun usable(o: Any?): Boolean {
        val e = map(o) ?: return false
        return IntentJs.isFinite(e["at"]) && (e["agent"] as? String)?.isNotEmpty() == true
    }

    private fun total(actions: Long, autos: Long, stepUps: Long, denies: Long, executed: Long): Map<String, Any?> = linkedMapOf(
        "actions" to n(actions), "autos" to n(autos), "stepUps" to n(stepUps), "denies" to n(denies), "executed" to n(executed),
    )

    /**
     * Project events into the console view `{agents, totals, window: {from, to}, dropped}`, agents most threatened first (then most recently
     * seen). An event with no finite time or no agent id cannot be placed in a timeline or attributed: it is counted in `dropped`, not guessed.
     * A risk that is present but not a number is refused (throws) rather than summed as text.
     */
    fun buildConsole(all: List<Any?>): Map<String, Any?> {
        val events = all.filter { usable(it) }.map { map(it)!! }
        val dropped = (all.size - events.size).toLong()
        val byAgent = LinkedHashMap<String, MutableList<Map<String, Any?>>>()
        for (e in events) byAgent.getOrPut(e["agent"] as String) { ArrayList() }.add(e)

        val agents = ArrayList<Map<String, Any?>>()
        for ((agent, list) in byAgent) {
            val sorted = list.sortedWith { a, b -> cmp(d(a["at"]) - d(b["at"])) }
            var immune = Immune.initialState()
            var autos = 0L
            var stepUps = 0L
            var denies = 0L
            var executed = 0L
            var totalRisk = 0.0
            for (e in sorted) {
                val ro = e["r"]
                if (ro != null && !isNum(ro)) throw IllegalArgumentException("buildConsole: r must be a number")
                val r = if (ro == null) 0.0 else d(ro)
                totalRisk += r
                when (e["outcome"]) {
                    "auto" -> autos++
                    "step_up" -> stepUps++
                    "deny" -> denies++
                    "executed" -> executed++
                }
                immune = Immune.observe(
                    immune,
                    linkedMapOf("r" to n(r), "at" to e["at"], "stepUp" to (e["outcome"] == "step_up"), "denied" to (e["outcome"] == "deny")),
                )
            }
            agents.add(
                linkedMapOf(
                    "agent" to agent, "actions" to n(sorted.size.toLong()), "autos" to n(autos), "stepUps" to n(stepUps), "denies" to n(denies),
                    "executed" to n(executed), "totalRisk" to n(totalRisk), "firstSeen" to sorted[0]["at"], "lastSeen" to sorted[sorted.size - 1]["at"],
                    "threat" to Immune.assess(immune),
                ),
            )
        }
        val ordered = agents.sortedWith { x, y ->
            val ds = cmp(d(map(y["threat"])!!["score"]) - d(map(x["threat"])!!["score"]))
            if (ds != 0) ds else cmp(d(y["lastSeen"]) - d(x["lastSeen"]))
        }

        var ta = 0L
        var tau = 0L
        var ts = 0L
        var td = 0L
        var te = 0L
        for (a in ordered) {
            ta += d(a["actions"]).toLong()
            tau += d(a["autos"]).toLong()
            ts += d(a["stepUps"]).toLong()
            td += d(a["denies"]).toLong()
            te += d(a["executed"]).toLong()
        }
        var from = 0.0
        var to = 0.0
        if (events.isNotEmpty()) {
            from = Double.POSITIVE_INFINITY
            to = Double.NEGATIVE_INFINITY
            for (e in events) {
                from = Math.min(from, d(e["at"]))
                to = Math.max(to, d(e["at"]))
            }
        }
        return linkedMapOf(
            "agents" to ArrayList<Any?>(ordered), "totals" to total(ta, tau, ts, td, te),
            "window" to linkedMapOf("from" to n(from), "to" to n(to)), "dropped" to n(dropped),
        )
    }

    /** The agents whose current threat read is not calm (the console's "anomalies" panel). */
    fun anomalies(view: Map<String, Any?>): List<Any?> =
        (view["agents"] as List<Any?>).filter { map(map(it)!!["threat"])!!["level"] != "calm" }

    // ---- freeze (the kill switch) ----

    /** The empty freeze set `{frozen: []}`. */
    fun emptyFreeze(): Map<String, Any?> = linkedMapOf("frozen" to ArrayList<Any?>())

    private fun frozen(set: Map<String, Any?>?): List<Any?> =
        set?.get("frozen") as? List<Any?> ?: throw IllegalArgumentException("freeze set must be {frozen: [...]}")

    /** Freeze an agent: the set with the id added (sorted); the same set when it is already frozen. */
    fun freezeAgent(set: Map<String, Any?>?, agent: Any?): Map<String, Any?> {
        if (agent !is String || agent.isEmpty()) throw IllegalArgumentException("freezeAgent: agent must be a non-empty string")
        val raw = set?.get("frozen")
        if (raw is String) { // a string has `includes` (a substring test) and spreads into its code points
            if (raw.contains(agent)) return set!!
            val chars = ArrayList<String>()
            raw.codePoints().forEach { chars.add(String(Character.toChars(it))) }
            chars.add(agent)
            chars.sort()
            return linkedMapOf("frozen" to ArrayList<Any?>(chars))
        }
        val cur = frozen(set)
        if (cur.contains(agent)) return set!!
        val next = ArrayList<String>()
        for (o in cur) next.add(Js.str(o))
        next.add(agent)
        next.sort() // shortcut: UTF-16 order as in the reference; String.compareTo is the same order
        return linkedMapOf("frozen" to ArrayList<Any?>(next))
    }

    /** The set without the agent. */
    fun unfreezeAgent(set: Map<String, Any?>?, agent: Any?): Map<String, Any?> =
        linkedMapOf("frozen" to ArrayList<Any?>(frozen(set).filter { it != agent }))

    /** Whether an agent is frozen. Fails closed: an agent with no usable id, or a malformed set, counts as frozen. */
    fun isFrozen(set: Any?, agent: Any?): Boolean {
        if (agent !is String || agent.isEmpty()) return true
        val f = (set as? Map<*, *>)?.get("frozen") as? List<*> ?: return true
        return f.contains(agent)
    }
}
