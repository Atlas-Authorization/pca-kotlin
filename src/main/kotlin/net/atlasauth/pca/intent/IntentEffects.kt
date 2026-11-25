package net.atlasauth.pca.intent

import java.util.TreeSet
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Predicates

/**
 * Outcome verification: postconditions on observed effects. A postcondition is a set of conditions in the ordinary predicate
 * language over the requested action (`action.params.*`, `action.resource`) and the observed effect at `env.effect.*`,
 * evaluated by the one evaluator. A clause whose `ref` names an action parameter the action does not carry is not applicable
 * and is skipped. Results: ok, violated (a negative runtime observation), pending (the effect record lacks a field a clause reads).
 */
object IntentEffects {
    private fun leaf(field: String, op: String, ref: String?, value: Any?): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["field"] = "env.effect.$field"
        m["op"] = op
        if (ref != null) m["ref"] = ref else m["value"] = value
        return m
    }

    private fun pc(id: String, verb: String, description: String, vararg where: Any?): Map<String, Any?> =
        linkedMapOf("id" to id, "verb" to verb, "description" to description, "where" to ArrayList<Any?>(where.asList()))

    private val ZERO = Json.Num("0")

    /** Postconditions for the built-in connectors' state-changing verbs. */
    @JvmField
    val DEFAULT_POSTCONDITIONS: List<Map<String, Any?>> = java.util.Collections.unmodifiableList(listOf(
        pc("stripe.refund.amount", "stripe.refund", "the refunded amount is at most the requested amount", leaf("amount", "lte", "action.params.amount", null), leaf("amount", "gte", null, ZERO)),
        pc("stripe.refund.recipient", "stripe.refund", "the refund went to the requested recipient", leaf("recipient", "eq", "action.params.recipient", null)),
        pc("stripe.charge.amount", "stripe.charge", "the charged amount is at most the requested amount", leaf("amount", "lte", "action.params.amount", null), leaf("amount", "gte", null, ZERO)),
        pc("stripe.payout.amount", "stripe.payout", "the paid-out amount is at most the requested amount", leaf("amount", "lte", "action.params.amount", null), leaf("amount", "gte", null, ZERO)),
        pc("stripe.payout.recipient", "stripe.payout", "the payout went to the requested recipient", leaf("recipient", "eq", "action.params.recipient", null)),
        pc("gmail.send.to", "gmail.send", "the mail went only to the requested address", leaf("to", "eq", "action.params.to", null)),
        pc("slack.post_message.channel", "slack.post_message", "the message was posted in the requested channel", leaf("channel", "eq", "action.params.channel", null)),
        pc("files.write.path", "files.write", "the written path is the requested resource", leaf("path", "eq", "action.resource", null)),
        pc("files.delete.path", "files.delete", "the deleted path is the requested resource", leaf("path", "eq", "action.resource", null)),
        pc("github.merge_pr.repo", "github.merge_pr", "the merge landed in the requested repository", leaf("repo", "eq", "action.resource", null)),
        pc("calendar.create_event.hour", "calendar.create_event", "the event starts at the requested hour", leaf("hour", "eq", "env.hour", null)),
    ))

    private fun get(o: Any?, k: String): Any? = if (o is Map<*, *>) o[k] else null
    private fun has(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)

    private fun leaves(c: Any?, out: MutableList<Pair<String, String?>>) {
        if (c !is Map<*, *>) return
        if (has(c, "all_of") || has(c, "any_of") || has(c, "not")) {
            if (has(c, "all_of") && get(c, "all_of") is List<*>) for (x in get(c, "all_of") as List<*>) leaves(x, out)
            else if (has(c, "any_of") && get(c, "any_of") is List<*>) for (x in get(c, "any_of") as List<*>) leaves(x, out)
            else if (has(c, "not")) leaves(get(c, "not"), out)
            return
        }
        val f = get(c, "field")
        if (f is String) out.add(Pair(f, get(c, "ref") as? String))
    }

    /** Own-property walk of a dotted path: does a value exist there (undefined = not found)? */
    private fun defined(root: Any?, path: String): Boolean {
        var cur = root
        for (k in path.split(".")) {
            if (cur !is Map<*, *> || !cur.containsKey(k)) return false
            cur = cur[k]
        }
        return true
    }

    /** The evaluator's context for an action plus its observed effect. */
    fun effectContext(vs: VerbSpace, o: Outcome, effect: Map<String, Any?>?): MutableMap<String, Any?> {
        val a = IntentPolicy.outcomeToAction(vs, o)
        val action = LinkedHashMap<String, Any?>()
        action["verb"] = a["verb"]
        action["resource"] = a["resource"]
        action["params"] = IntentRuntime.jsonNums(a["params"])
        action["reversibility_class"] = vs.reversibility
        val ctx = LinkedHashMap<String, Any?>()
        ctx["action"] = action
        if (a["subject"] != null) ctx["subject"] = IntentRuntime.jsonNums(a["subject"])
        val env = LinkedHashMap<String, Any?>()
        if (a["env"] != null) env.putAll(IntentOmega.obj(IntentRuntime.jsonNums(a["env"])))
        env["effect"] = effect
        ctx["env"] = env
        return ctx
    }

    /** {status, violated, missing, checked, notApplicable}. */
    @JvmOverloads
    fun checkPostconditions(vs: VerbSpace, o: Outcome, effect: Map<String, Any?>?, pcs: List<*> = ArrayList<Any?>(DEFAULT_POSTCONDITIONS)): MutableMap<String, Any?> {
        val ctx = effectContext(vs, o, effect)
        val violated = ArrayList<Any?>()
        val checked = ArrayList<Any?>()
        val notApplicable = ArrayList<Any?>()
        val missing = ArrayList<String>()
        for (pc in pcs) {
            if (o.verb != get(pc, "verb")) continue
            val ls = ArrayList<Pair<String, String?>>()
            for (c in get(pc, "where") as List<*>) leaves(c, ls)
            if (ls.any { it.second != null && !it.second!!.startsWith("env.effect.") && !defined(ctx, it.second!!) }) {
                notApplicable.add(get(pc, "id"))
                continue
            }
            val need = LinkedHashSet<String>()
            for (l in ls) {
                if (l.first.startsWith("env.effect.")) need.add(l.first)
                val r = l.second
                if (r != null && r.isNotEmpty() && r.startsWith("env.effect.")) need.add(r)
            }
            val lacking = need.filter { !defined(ctx, it) }
            if (lacking.isNotEmpty()) {
                missing.addAll(lacking)
                continue
            }
            checked.add(get(pc, "id"))
            val pred = linkedMapOf<String, Any?>("verb" to o.verb, "resource" to "*", "where" to get(pc, "where"))
            if (!Predicates.evaluatePredicates(listOf(pred), ctx)) violated.add(get(pc, "id"))
        }
        val miss = ArrayList<Any?>(TreeSet(missing))
        val rep = LinkedHashMap<String, Any?>()
        rep["status"] = if (violated.isNotEmpty()) "violated" else if (miss.isNotEmpty()) "pending" else "ok"
        rep["violated"] = violated
        rep["missing"] = miss
        rep["checked"] = checked
        rep["notApplicable"] = notApplicable
        return rep
    }
}
