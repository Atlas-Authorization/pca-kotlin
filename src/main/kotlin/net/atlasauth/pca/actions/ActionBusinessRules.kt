package net.atlasauth.pca.actions

import java.util.Locale
import java.util.TimeZone
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.PcaDecision
import net.atlasauth.pca.verifier.Predicates

/**
 * A platform's own business rules for one action (amount ceilings per currency, approval thresholds, caller-scoped records, rate limits,
 * business hours, allowed recipients, required fields) compiled into tighten rules and count accumulators. Every compiled rule carries the
 * signal `escalate` or `deny`, so a rule can only lower a decision. Everything is a JSON tree (Map / List / String / Boolean /
 * Json.Num / null) so the results compare byte for byte with the reference. A time zone must be an IANA zone id known to the runtime
 * (shortcut: the reference's Intl also accepts a few offset spellings; those are refused here, which fails closed).
 */
@Suppress("UNCHECKED_CAST")
object ActionBusinessRules {
    val RULE_DAYS: List<String> = listOf("sun", "mon", "tue", "wed", "thu", "fri", "sat")
    val RATE_PERIODS: Map<String, Long> = mapOf("hour" to 3_600_000L, "day" to 86_400_000L)
    const val MAX_RULE_CURRENCIES = 32
    const val MAX_RULE_LIST = 64
    const val MAX_RULE_APPROVERS = 16
    const val MAX_RULE_EXAMPLES = 32
    const val BUSINESS_RULES_DOMAIN = "atlas-pca/action-business-rules/v1"
    const val RULES_REVIEW_DOMAIN = "atlas-pca/action-rules-review/v1"

    private val CCY_RE = Regex("[A-Z]{3}")
    private val NAME_RE = Regex("[a-z][a-z0-9_]{0,63}")
    private val HHMM_RE = Regex("([01][0-9]|2[0-3]):([0-5][0-9])")
    private val DOMAIN_RE = Regex("(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
    private val ADDRESS_RE = Regex("[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}")
    private val DEC_RE = Regex("(0|[1-9][0-9]{0,14})(?:\\.([0-9]{1,6}))?")
    private val AT_RE = Regex("([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")
    private val TZ_RE = Regex("[A-Za-z0-9_+\\-/]+")
    private val ID_STRIP_RE = Regex("[^a-z0-9_]")
    private val LIKE_ESC_RE = Regex("([\\\\*?])")
    private val RULE_KEYS = listOf("amount", "approval", "scope", "rate", "hours", "recipients", "required", "examples")
    private val DAY_NAMES = listOf("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")

    private fun isObj(v: Any?): Boolean = v is Map<*, *>
    private fun own(o: Any?, k: String): Boolean = o is Map<*, *> && o.containsKey(k)
    private fun undef(o: Any?, k: String): Boolean = !own(o, k)
    private fun fullMatch(p: Regex, v: Any?): Boolean = v is String && p.matches(v)
    private fun d0(o: Any?): Double = J.num(o)!!

    private fun closed(o: Map<String, Any?>, allowed: List<String>, at: String) {
        for (k in o.keys) if (k !in allowed) throw ActionKitError("bad_rules", "$at: unknown member '$k'")
    }

    private fun bad(msg: String): RuntimeException = ActionKitError("bad_rules", msg)

    private fun params(d: Map<String, Any?>): MutableMap<String, Any?> = J.m(d["params"])

    private fun sortedKeys(m: Map<String, Any?>): List<String> = m.keys.sorted()

    // ---- references and money ------------------------------------------------------------------------------------------------

    /** The parameter a reference names: `{name, p}`. Throws `bad_rules` when it resolves to none or to several. */
    fun resolveParamRef(d: Map<String, Any?>, r: Any?, at: String): Map<String, Any?> {
        if (!isObj(r)) throw bad("$at: name a parameter ({param} or {role})")
        val rm = J.m(r)
        val hasP = rm["param"] is String
        val hasR = rm["role"] is String
        if (hasP == hasR) throw bad("$at: give exactly one of param or role")
        val ps = params(d)
        if (hasP) {
            val name = rm["param"] as String
            if (!own(ps, name) || ps[name] == null) throw bad("$at: '${d["verb"]}' has no parameter '$name'")
            return J.obj("name", name, "p", ps[name])
        }
        val hits = ArrayList<String>()
        for (n in ps.keys) if (rm["role"] == J.get(ps[n], "role")) hits.add(n)
        hits.sort()
        if (hits.size != 1) throw bad("$at: '${d["verb"]}' has " + (if (hits.isEmpty()) "no" else "several") + " parameter" + (if (hits.isEmpty()) "" else "s") + " with role " + rm["role"])
        return J.obj("name", hits[0], "p", ps[hits[0]])
    }

    /** The money parameters of an action: `{amount, exp, ccy: {literal} | {param}}`. */
    fun moneyOf(d: Map<String, Any?>): Map<String, Any?> {
        val ps = params(d)
        val hits = ArrayList<String>()
        for (n in ps.keys) if ("money.amount" == J.get(ps[n], "role")) hits.add(n)
        hits.sort()
        if (hits.size != 1) throw bad("'${d["verb"]}' needs exactly one parameter with role money.amount for an amount or approval-above rule (has ${hits.size})")
        val name = hits[0]
        val p = J.m(ps[name])
        if ("integer" != p["type"]) throw bad("'${d["verb"]}': the money.amount parameter '$name' must be an integer")
        val u = p["unit"]
        if (u == null || "money" != J.get(u, "kind")) throw bad("'${d["verb"]}': the amount parameter '$name' declares no money unit (its currency)")
        val ccy = J.get(u, "ccy")
        if (ccy is String) return J.obj("amount", name, "exp", J.get(u, "exp"), "ccy", J.obj("literal", ccy))
        val from = J.get(ccy, "from") as String?
        if (from == null || !own(ps, from)) throw bad("'${d["verb"]}': the currency parameter '$from' does not exist")
        return J.obj("amount", name, "exp", J.get(u, "exp"), "ccy", J.obj("param", from))
    }

    private fun expOf(money: Map<String, Any?>): Int = d0(money["exp"]).toInt()

    private fun safeInt(v: Double): Boolean = v == Math.rint(v) && Math.abs(v) <= 9007199254740991.0

    /** Integer minor units of a money value under exponent `exp`. Throws `bad_rules` for a non-integer or over-precise value. */
    fun minorUnits(v: Any?, exp: Int, at: String): Long {
        val num = J.num(v)
        if (num != null) {
            if (!J.isInt(num) || num < 0) throw bad("$at: an amount is a non-negative integer of minor units, or a decimal string")
            return num.toLong()
        }
        if (v !is String) throw bad("$at: an amount is a number of minor units or a decimal string")
        val m = DEC_RE.matchEntire(v) ?: throw bad("$at: '$v' is not a decimal amount")
        val frac = m.groups[2]?.value ?: ""
        if (frac.length > exp) throw bad("$at: '$v' has more decimals than the currency's $exp")
        val padded = StringBuilder(frac)
        while (padded.length < exp) padded.append('0')
        val f = if (padded.isEmpty()) "0" else padded.toString()
        val n = m.groupValues[1].toDouble() * Math.pow(10.0, exp.toDouble()) + f.toDouble()
        if (!safeInt(n)) throw bad("$at: '$v' is too large")
        return n.toLong()
    }

    private fun mins(hhmm: String): Int = hhmm.substring(0, 2).toInt() * 60 + hhmm.substring(3, 5).toInt()

    private fun zoneOf(tz: String?): TimeZone? {
        if (tz == null || tz.isEmpty() || tz.length > 64 || !TZ_RE.matches(tz)) return null
        val ids = TimeZone.getAvailableIDs()
        if (ids.contains(tz)) return TimeZone.getTimeZone(tz)
        for (z in ids) if (z.equals(tz, ignoreCase = true)) return TimeZone.getTimeZone(z)
        return null
    }

    /** Is this a time zone the runtime knows (IANA name)? */
    fun knownTimeZone(tz: Any?): Boolean = tz is String && zoneOf(tz) != null

    /** Null iff `rules` is a well-formed rules block for `d`; the reason otherwise. */
    fun businessRulesError(d: Map<String, Any?>, rules: Any?): String? = try {
        validateRules(d, rules)
        null
    } catch (e: RuntimeException) {
        e.message
    }

    private fun ccyMap(d: Map<String, Any?>, m: Any?, at: String) {
        if (!isObj(m) || J.m(m).isEmpty() || J.m(m).size > MAX_RULE_CURRENCIES) throw bad("$at: a map of 1..$MAX_RULE_CURRENCIES currencies to amounts")
        val money = moneyOf(d)
        for ((k, v) in J.m(m)) {
            if (!CCY_RE.matches(k)) throw bad("$at: '$k' is not an ISO 4217 currency code")
            minorUnits(v, expOf(money), "$at.$k")
        }
    }

    private fun refOf(s: Map<String, Any?>): Map<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        if (own(s, "param")) r["param"] = s["param"]
        if (own(s, "role")) r["role"] = s["role"]
        return r
    }

    private fun distinct(xs: List<*>): Boolean = HashSet<Any?>(xs).size == xs.size

    private fun validateRules(d: Map<String, Any?>, rules: Any?) {
        if (!isObj(rules)) throw bad("rules must be an object")
        val r = J.m(rules)
        closed(r, RULE_KEYS, "rules")
        var n0 = 0
        for (k in r.keys) if (k != "examples") n0++
        if (n0 == 0) throw bad("rules: name at least one rule")
        if (own(r, "amount")) {
            if (!isObj(r["amount"])) throw bad("rules.amount must be {max: {CCY: amount}}")
            closed(J.m(r["amount"]), listOf("max"), "rules.amount")
            ccyMap(d, J.get(r["amount"], "max"), "rules.amount.max")
        }
        if (own(r, "approval")) {
            val a = r["approval"]
            if (!isObj(a)) throw bad("rules.approval must be an object")
            val ap = J.m(a)
            closed(ap, listOf("above", "always", "approvers", "group"), "rules.approval")
            if (own(ap, "always") && ap["always"] != true) throw bad("rules.approval.always is true or absent")
            if (undef(ap, "above") == undef(ap, "always")) throw bad("rules.approval: give exactly one of above or always")
            if (own(ap, "above")) ccyMap(d, ap["above"], "rules.approval.above")
            if (own(ap, "approvers") && (!J.isInt(ap["approvers"]) || d0(ap["approvers"]) < 1 || d0(ap["approvers"]) > MAX_RULE_APPROVERS)) throw bad("rules.approval.approvers is 1..$MAX_RULE_APPROVERS")
            if (own(ap, "group") && !fullMatch(NAME_RE, ap["group"])) throw bad("rules.approval.group is a lowercase name")
        }
        if (own(r, "scope")) {
            val sc = r["scope"]
            if (sc !is List<*> || sc.isEmpty() || sc.size > MAX_RULE_LIST) throw bad("rules.scope is a list of 1..$MAX_RULE_LIST bindings")
            var i = 0
            for (s0 in sc) {
                val at = "rules.scope[$i]"
                if (!isObj(s0)) throw bad("$at must be an object")
                val s = J.m(s0)
                closed(s, listOf("param", "role", "caller"), at)
                val p = resolveParamRef(d, refOf(s), at)["p"]
                val ty = J.get(p, "type")
                if ("string" != ty && "integer" != ty) throw bad("$at: the bound parameter must be a string or integer id")
                if (!fullMatch(NAME_RE, s["caller"])) throw bad("$at.caller is a lowercase attribute name of the caller")
                i++
            }
        }
        if (own(r, "rate")) {
            val rt = r["rate"]
            if (rt !is List<*> || rt.isEmpty() || rt.size > 4) throw bad("rules.rate is a list of 1..4 limits")
            var i = 0
            for (x0 in rt) {
                val at = "rules.rate[$i]"
                if (!isObj(x0)) throw bad("$at must be an object")
                val x = J.m(x0)
                closed(x, listOf("max", "per", "by"), at)
                if (!J.isInt(x["max"]) || d0(x["max"]) < 1 || d0(x["max"]) > 1_000_000) throw bad("$at.max is 1..1000000")
                if (!RATE_PERIODS.containsKey(J.jsStr(x["per"]))) throw bad("$at.per is hour or day")
                if (own(x, "by") && "principal" != x["by"] && "org" != x["by"]) throw bad("$at.by is principal or org")
                i++
            }
        }
        if (own(r, "hours")) {
            if (!isObj(r["hours"])) throw bad("rules.hours must be an object")
            val h = J.m(r["hours"])
            closed(h, listOf("days", "from", "to", "tz", "outside"), "rules.hours")
            val days = h["days"]
            var daysOk = days is List<*> && days.isNotEmpty() && distinct(days)
            if (daysOk) for (x in days as List<*>) if (x !is String || x !in RULE_DAYS) daysOk = false
            if (!daysOk) throw bad("rules.hours.days is a list of distinct days (" + RULE_DAYS.joinToString(", ") + ")")
            if (!fullMatch(HHMM_RE, h["from"]) || !fullMatch(HHMM_RE, h["to"])) throw bad("rules.hours.from and .to are HH:MM (24 h)")
            if (!knownTimeZone(h["tz"])) throw bad("rules.hours.tz '" + J.jsStr(h["tz"]) + "' is not a known IANA time zone")
            if (own(h, "outside") && "escalate" != h["outside"] && "deny" != h["outside"]) throw bad("rules.hours.outside is escalate or deny")
        }
        if (own(r, "recipients")) {
            if (!isObj(r["recipients"])) throw bad("rules.recipients must be an object")
            val x = J.m(r["recipients"])
            closed(x, listOf("param", "role", "domains", "addresses"), "rules.recipients")
            val res = resolveParamRef(d, refOf(x), "rules.recipients")
            val name = res["name"] as String
            val p = J.m(res["p"])
            val ty = p["type"]
            if ("array" == ty || "set" == ty) {
                if (own(p, "items") && "string" != p["items"]) throw bad("rules.recipients: '$name' must hold strings")
                if (!J.isInt(p["max_items"]) || d0(p["max_items"]) > MAX_RULE_LIST) throw bad("rules.recipients: the list parameter '$name' needs max_items <= $MAX_RULE_LIST so every entry can be checked")
            } else if ("string" != ty) throw bad("rules.recipients: '$name' must be a string or a bounded list of strings")
            if (undef(x, "domains") && undef(x, "addresses")) throw bad("rules.recipients: give domains and/or addresses")
            if (own(x, "domains") && !listOfRe(x["domains"], DOMAIN_RE)) throw bad("rules.recipients.domains is a list of lowercase domain names")
            if (own(x, "addresses") && !listOfRe(x["addresses"], ADDRESS_RE)) throw bad("rules.recipients.addresses is a list of lowercase email addresses")
        }
        if (own(r, "required")) {
            val rq = r["required"]
            if (rq !is List<*> || rq.isEmpty() || rq.size > MAX_RULE_LIST || !distinct(rq)) throw bad("rules.required is a list of distinct parameter names")
            for (n in rq) if (n !is String || !own(params(d), n)) throw bad("rules.required: '${d["verb"]}' has no parameter '${J.jsStr(n)}'")
        }
        if (own(r, "examples")) {
            val ex = r["examples"]
            if (ex !is List<*> || ex.size > MAX_RULE_EXAMPLES) throw bad("rules.examples is a list of at most $MAX_RULE_EXAMPLES")
            var i = 0
            for (e0 in ex) {
                val at = "rules.examples[$i]"
                if (!isObj(e0)) throw bad("$at must be an object")
                val e = J.m(e0)
                closed(e, listOf("params", "caller", "at", "recent", "expect"), at)
                if (!isObj(e["params"])) throw bad("$at.params must be an object")
                if (own(e, "caller") && !isObj(e["caller"])) throw bad("$at.caller must be an object")
                val atV = e["at"]
                if (own(e, "at") && (atV !is String || parseUtc(atV).isNaN())) throw bad("$at.at is an RFC 3339 UTC time (…Z)")
                if (own(e, "recent")) {
                    var ok = isObj(e["recent"])
                    if (ok) for (c in J.m(e["recent"]).values) if (!J.isInt(c) || d0(c) < 0) ok = false
                    if (!ok) throw bad("$at.recent maps rate indexes to counts")
                }
                if (!listOf("allow", "escalate", "deny").contains(e["expect"])) throw bad("$at.expect is allow, escalate or deny")
                i++
            }
        }
    }

    private fun listOfRe(v: Any?, re: Regex): Boolean {
        if (v !is List<*> || v.isEmpty() || v.size > MAX_RULE_LIST) return false
        for (x in v) if (!fullMatch(re, x)) return false
        return true
    }

    private fun daysFromCivil(y0: Int, m: Int, d: Int): Long {
        val y = (if (m <= 2) y0 - 1 else y0).toLong()
        val era = Math.floorDiv(y, 400L)
        val yoe = y - era * 400
        val doy = (153L * (m + (if (m > 2) -3 else 9)) + 2) / 5 + d - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }

    /** `Date.parse` of an RFC 3339 UTC time (`...Z`, whole seconds) as the reference engine reads it; NaN when it does not. */
    fun parseUtc(s: String): Double {
        val m = AT_RE.matchEntire(s) ?: return Double.NaN
        val g = m.groupValues
        val y = g[1].toInt()
        val mo = g[2].toInt()
        val dd = g[3].toInt()
        val h = g[4].toInt()
        val mi = g[5].toInt()
        val se = g[6].toInt()
        if (mo < 1 || mo > 12 || dd < 1 || dd > 31 || h > 24 || mi > 59 || se > 59 || (h == 24 && (mi != 0 || se != 0))) return Double.NaN
        val days = daysFromCivil(y, mo, 1) + (dd - 1)
        return (days * 86_400_000L + h * 3_600_000L + mi * 60_000L + se * 1000L).toDouble()
    }

    // ---- compiled form -----------------------------------------------------------------------------------------------------------

    /** Digest of a rules block (examples are tests, not rules). */
    fun businessRulesDigest(verb: String, rules: Map<String, Any?>): String {
        val body = LinkedHashMap<String, Any?>(rules)
        body.remove("examples")
        return Pca.hashCanonical(J.obj("d", BUSINESS_RULES_DOMAIN, "verb", verb, "rules", body))
    }

    private fun pp(n: String): String = "action.params.$n"

    private fun cond(field: String, op: String, value: Any?): Map<String, Any?> = J.obj("field", field, "op", op, "value", value)

    private fun ccyCond(m: Map<String, Any?>, c: String): Map<String, Any?>? {
        val ccy = J.m(m["ccy"])
        if (ccy.containsKey("param")) return cond(pp(ccy["param"] as String), "eq", c)
        return if (c == ccy["literal"]) null else cond("action.verb", "eq", "\u0000never")
    }

    private fun and(cs: List<Map<String, Any?>?>): Map<String, Any?> {
        val xs = ArrayList<Any?>()
        for (c in cs) if (c != null) xs.add(c)
        return if (xs.size == 1) J.m(xs[0]) else J.obj("all_of", xs)
    }

    private fun always(verb: Any?): Map<String, Any?> = cond("action.verb", "eq", verb)

    private fun ruleId(s: String): String {
        val r = ID_STRIP_RE.replace(s.lowercase(Locale.ROOT), "_")
        return if (r.length > 64) r.substring(0, 64) else r
    }

    private fun rule(id: String, `when`: Any?, signal: String, reason: String): Map<String, Any?> = J.obj("id", id, "when", `when`, "signal", signal, "reason", reason)

    private fun sortedStrings(xs: Any?): List<Any?> {
        val out = ArrayList<Any?>(J.a(xs))
        out.sortWith { a, b -> (a as String).compareTo(b as String) }
        return out
    }

    private fun listText(xs: List<String>): String = xs.joinToString(", ")

    /** Compile a rules block for `d`. Throws ActionKitError `bad_rules` for a malformed block. Deterministic. */
    fun compileBusinessRules(d: Map<String, Any?>, rules: Map<String, Any?>): Map<String, Any?> {
        validateRules(d, rules)
        val t = ArrayList<Any?>()
        val acc = ArrayList<Any?>()
        val verb = d["verb"]
        val out = J.obj("v", J.n(1), "verb", verb, "rules_digest", businessRulesDigest(verb as String, rules), "def_digest", Actions.defDigest(d), "tighten", t, "accumulators", acc)
        val approval = rules["approval"]
        val money: Map<String, Any?>? = if (own(rules, "amount") || (approval != null && own(approval, "above"))) moneyOf(d) else null
        val exp = if (money == null) 0 else expOf(money)
        if (own(rules, "amount")) {
            val maxes = J.m(J.get(rules["amount"], "max"))
            val listed = sortedKeys(maxes)
            val mm = money!!
            for (c in listed) {
                val max = minorUnits(maxes[c], exp, "rules.amount.max.$c")
                t.add(rule(ruleId("amount_max_$c"), and(listOf(ccyCond(mm, c), cond(pp(mm["amount"] as String), "gt", J.n(max)))), "deny", "the amount is above the " + formatMoney(max, c, exp) + " ceiling"))
            }
            val u = unlisted(money, listed, verb)
            if (u != null) t.add(rule("amount_currency", u, "deny", "only " + listText(listed) + " amounts are allowed"))
        }
        if (own(rules, "approval")) {
            val ap = J.m(approval)
            val need = J.obj("approvers", if (own(ap, "approvers")) ap["approvers"] else J.n(1))
            if (own(ap, "group")) need["group"] = ap["group"]
            out["approval"] = need
            if (ap["always"] == true) t.add(rule("approval_always", always(verb), "escalate", "this action always needs approval"))
            else {
                val above = J.m(ap["above"])
                val listed = sortedKeys(above)
                val mm = money!!
                for (c in listed) {
                    val x = minorUnits(above[c], exp, "rules.approval.above.$c")
                    t.add(rule(ruleId("approval_above_$c"), and(listOf(ccyCond(mm, c), cond(pp(mm["amount"] as String), "gt", J.n(x)))), "escalate", "amounts above " + formatMoney(x, c, exp) + " need approval"))
                }
                val u = unlisted(money, listed, verb)
                if (u != null) t.add(rule("approval_currency", u, "escalate", "amounts in a currency other than " + listText(listed) + " need approval"))
            }
        }
        if (own(rules, "scope")) {
            var i = 0
            for (s0 in J.a(rules["scope"])) {
                val s = J.m(s0)
                val name = resolveParamRef(d, refOf(s), "rules.scope[$i]")["name"] as String
                // `not eq`: an absent caller attribute or parameter is undecided, so the rule fires
                val eq = J.obj("field", pp(name), "op", "eq", "ref", "subject." + s["caller"])
                t.add(rule("scope_$i", J.obj("not", eq), "deny", name + " must be the caller's own " + s["caller"]))
                i++
            }
        }
        if (own(rules, "rate")) {
            var i = 0
            for (r0 in J.a(rules["rate"])) {
                val r = J.m(r0)
                val id = "rate_$i"
                val by = if (own(r, "by")) r["by"] as String else "principal"
                val per = J.jsStr(r["per"])
                acc.add(J.obj("id", id, "agg", "count", "sel", J.obj("verbs", J.list(verb)), "win", J.obj("kind", "sliding", "ms", J.n(RATE_PERIODS[per]!!)),
                    "key", null, "domain_max", r["max"], "cap", r["max"], "holder", J.obj("kind", "site_local"), "scope", by))
                t.add(rule(id, cond("env.acc.$id", "gte", r["max"]), "deny", "at most " + J.jsStr(r["max"]) + " per " + per + " per " + by))
                i++
            }
        }
        if (own(rules, "hours")) {
            val h = J.m(rules["hours"])
            val from = mins(h["from"] as String)
            val to = mins(h["to"] as String)
            val dows = ArrayList<Int>()
            for (x in J.a(h["days"])) dows.add(RULE_DAYS.indexOf(x as String))
            dows.sort()
            val dowsJ = ArrayList<Any?>()
            val nextJ = ArrayList<Any?>()
            for (x in dows) { dowsJ.add(J.n(x.toLong())); nextJ.add(J.n(((x + 1) % 7).toLong())) }
            val inTime: Any? = if (from < to) J.obj("all_of", J.list(cond("env.clock.min", "gte", J.n(from.toLong())), cond("env.clock.min", "lt", J.n(to.toLong()))))
                else J.obj("any_of", J.list(cond("env.clock.min", "gte", J.n(from.toLong())), cond("env.clock.min", "lt", J.n(to.toLong()))))
            val day: Any? = if (from < to) cond("env.clock.dow", "in", dowsJ)
                else J.obj("any_of", J.list(
                    J.obj("all_of", J.list(cond("env.clock.dow", "in", dowsJ), cond("env.clock.min", "gte", J.n(from.toLong())))),
                    J.obj("all_of", J.list(cond("env.clock.dow", "in", nextJ), cond("env.clock.min", "lt", J.n(to.toLong()))))))
            out["clock_tz"] = h["tz"]
            t.add(rule("hours", J.obj("not", J.obj("all_of", J.list(day, inTime))), if (own(h, "outside")) h["outside"] as String else "escalate", "outside " + hoursText(h)))
        }
        if (own(rules, "recipients")) {
            val x = J.m(rules["recipients"])
            val res = resolveParamRef(d, refOf(x), "rules.recipients")
            val name = res["name"] as String
            val p = J.m(res["p"])
            val ok: Any?
            if ("string" == p["type"]) ok = okAt(x, pp(name))
            else {
                val n = d0(p["max_items"]).toInt()
                val all = ArrayList<Any?>()
                for (i in 0 until n) all.add(J.obj("any_of", J.list(cond(pp("$name.$i"), "exists", false), okAt(x, pp("$name.$i")))))
                all.add(cond(pp("$name.$n"), "exists", false))
                ok = J.obj("all_of", all)
            }
            t.add(rule("recipients", J.obj("not", ok), "deny", name + " may only name " + recipientsText(x)))
        }
        if (own(rules, "required")) {
            var i = 0
            for (n0 in J.a(rules["required"])) {
                val n = n0 as String
                val missing: Any? = if ("string" == J.get(params(d)[n], "type")) J.obj("any_of", J.list(cond(pp(n), "exists", false), cond(pp(n), "eq", "")))
                    else cond(pp(n), "exists", false)
                t.add(rule("required_$i", missing, "deny", "$n is required"))
                i++
            }
        }
        for (r0 in t) {
            val r = J.m(r0)
            val rs = r["reason"] as String?
            if (rs != null && rs.length > 256) r["reason"] = rs.substring(0, 253) + "..."
        }
        return out
    }

    private fun unlisted(money: Map<String, Any?>?, listed: List<String>, verb: Any?): Map<String, Any?>? {
        if (money == null) return null
        val ccy = J.m(money["ccy"])
        if (ccy.containsKey("param")) return J.obj("not", cond(pp(ccy["param"] as String), "in", J.objs(listed)))
        return if (listed.contains(ccy["literal"])) null else always(verb)
    }

    private fun okAt(x: Map<String, Any?>, path: String): Any? {
        val any = ArrayList<Any?>()
        if (own(x, "domains")) for (dm in J.a(x["domains"])) any.add(cond(path, "like", "*@" + LIKE_ESC_RE.replace(dm as String) { "\\" + it.value }))
        if (own(x, "addresses")) any.add(cond(path, "in", sortedStrings(x["addresses"])))
        return J.obj("any_of", any)
    }

    // ---- evaluation --------------------------------------------------------------------------------------------------------------

    /** Day of week (0 = Sunday) and minute of day at `now` in `tz`, or null when it cannot be computed. */
    fun clockAt(now: Double, tz: String?): Map<String, Any?>? {
        try {
            if (now.isNaN() || now.isInfinite() || Math.abs(now) > 8.64e15) return null
            val z = zoneOf(tz) ?: return null
            val ms = now.toLong()
            val local = ms + z.getOffset(ms)
            val days = Math.floorDiv(local, 86_400_000L)
            val dow = Math.floorMod(days + 4, 7L)
            val min = Math.floorMod(local, 86_400_000L) / 60_000L
            return J.obj("dow", J.n(dow), "min", J.n(min))
        } catch (e: RuntimeException) {
            return null
        }
    }

    private fun nowOf(i: Map<String, Any?>): Double = J.num(i["now"]) ?: Double.NaN

    /** The predicate context the compiled rules are evaluated in. Verifier-computed `env` members only. */
    fun rulesContext(c: Map<String, Any?>, i: Map<String, Any?>): Map<String, Any?> {
        val env = LinkedHashMap<String, Any?>()
        if (own(c, "clock_tz")) {
            val k = clockAt(nowOf(i), c["clock_tz"] as String?)
            if (k != null) env["clock"] = k
        }
        val acc = LinkedHashMap<String, Any?>()
        val counts = i["counts"]
        for (a in J.a(c["accumulators"])) {
            val id = J.get(a, "id")
            val n = if (counts is Map<*, *>) counts[id] else null
            val nd = J.num(n)
            if (nd != null && safeInt(nd) && nd >= 0) acc[id as String] = n
        }
        env["acc"] = acc
        val resource = i["resource"]
        val action = J.obj("verb", c["verb"], "resource", resource ?: "", "params", i["params"])
        val subject = i["subject"]
        return J.obj("action", action, "subject", subject ?: LinkedHashMap<String, Any?>(), "env", env)
    }

    /** Evaluate compiled rules: `allow` unless a rule fires; a fired rule caps the decision at its signal. Never throws. */
    fun evaluateBusinessRules(c: Map<String, Any?>, i: Map<String, Any?>): Map<String, Any?> {
        try {
            val ctx = rulesContext(c, i)
            var decision = "allow"
            val reasons = ArrayList<Any?>()
            val fired = ArrayList<Any?>()
            var approval = false
            for (r0 in J.a(c["tighten"])) {
                val r = J.m(r0)
                if (Predicates.evaluateConditionTri(r["when"], ctx) == Predicates.Tri.FALSE) continue
                decision = PcaDecision.meet(decision, r["signal"] as String)
                fired.add(r["id"])
                reasons.add("${r["id"]}: " + (if (r["reason"] != null) r["reason"] else r["signal"]))
                if ("escalate" == r["signal"] && (r["id"] as String).startsWith("approval_")) approval = true
            }
            val out = J.obj("decision", decision, "reasons", reasons, "fired", fired)
            if (approval && c["approval"] != null) out["approval"] = c["approval"]
            return out
        } catch (e: RuntimeException) {
            return J.obj("decision", "deny", "reasons", J.list("rules: evaluation error (fail closed): " + e.message), "fired", ArrayList<Any?>())
        }
    }

    /** The decision with rules applied to a base decision: the meet, so rules never raise it. */
    fun withBusinessRules(base: String, verdict: Map<String, Any?>): String = PcaDecision.meet(base, verdict["decision"] as String)

    /** Run a rules block's examples: a list of `{index, expect, got, ok, why}`. */
    fun runRuleExamples(d: Map<String, Any?>, rules: Map<String, Any?>): List<Any?> {
        val c = compileBusinessRules(d, rules)
        val out = ArrayList<Any?>()
        if (!own(rules, "examples")) return out
        var index = 0
        for (e0 in J.a(rules["examples"])) {
            val e = J.m(e0)
            val counts = LinkedHashMap<String, Any?>()
            var k = 0
            for (a in J.a(c["accumulators"])) {
                val rec = e["recent"]
                val v = if (rec is Map<*, *>) rec[k.toString()] else null
                counts[J.get(a, "id") as String] = v ?: J.n(0)
                k++
            }
            val inp = J.obj("params", e["params"])
            if (e["caller"] != null) inp["subject"] = e["caller"]
            val now = if (own(e, "at") && e["at"] != null) parseUtc(e["at"] as String) else parseUtc("2026-01-07T15:00:00Z")
            inp["now"] = Json.Num(AttestUtil.jsNumString(now))
            inp["counts"] = counts
            val v = evaluateBusinessRules(c, inp)
            val ok = v["decision"] == e["expect"]
            val why = strs(v["reasons"]).joinToString("; ")
            out.add(J.obj("index", J.n(index.toLong()), "expect", e["expect"], "got", v["decision"], "ok", ok, "why", if (why.isEmpty()) "no rule fired" else why))
            index++
        }
        return out
    }

    private fun strs(xs: Any?): List<String> {
        val out = ArrayList<String>()
        for (x in J.a(xs)) out.add(x as String)
        return out
    }

    // ---- plain language ----------------------------------------------------------------------------------------------------------

    /** `12345` minor units of USD (exp 2) is "123.45 USD". Deterministic (no locale). */
    fun formatMoney(minor: Long, ccy: String, exp: Int): String {
        val s = StringBuilder(minor.toString())
        while (s.length < exp + 1) s.insert(0, '0')
        val str = s.toString()
        return (if (exp > 0) str.substring(0, str.length - exp) + "." + str.substring(str.length - exp) else str) + " " + ccy
    }

    private fun hoursText(h: Map<String, Any?>): String {
        val idx = ArrayList<Int>()
        for (x in J.a(h["days"])) idx.add(RULE_DAYS.indexOf(x as String))
        idx.sort()
        var run = idx.size > 2
        for (k in 1 until idx.size) if (idx[k] != idx[k - 1] + 1) run = false
        val days: String
        if (run) days = DAY_NAMES[idx[0]] + "-" + DAY_NAMES[idx[idx.size - 1]]
        else {
            val ns = ArrayList<String>()
            for (x in idx) ns.add(DAY_NAMES[x])
            days = ns.joinToString(", ")
        }
        return days + " " + h["from"] + "-" + h["to"] + " (" + h["tz"] + ")"
    }

    private fun recipientsText(x: Map<String, Any?>): String {
        val parts = ArrayList<String>()
        if (own(x, "domains")) for (dm in J.a(x["domains"])) parts.add("addresses at $dm")
        if (own(x, "addresses")) for (a in J.a(x["addresses"])) parts.add(a as String)
        return parts.joinToString(" or ")
    }

    private fun moneyList(mp: Map<String, Any?>, exp: Int): String {
        val out = ArrayList<String>()
        for (c in sortedKeys(mp)) out.add(formatMoney(minorUnits(mp[c], exp, c), c, exp))
        return out.joinToString(", ")
    }

    /** One plain sentence per rule. Throws `bad_rules` for a malformed block. */
    fun explainBusinessRules(d: Map<String, Any?>, rules: Map<String, Any?>): List<Any?> {
        validateRules(d, rules)
        val out = ArrayList<Any?>()
        val approval = rules["approval"]
        val m: Map<String, Any?>? = if (own(rules, "amount") || (approval != null && own(approval, "above"))) moneyOf(d) else null
        val exp = if (m == null) 0 else expOf(m)
        if (own(rules, "amount")) out.add("Refuses amounts above " + moneyList(J.m(J.get(rules["amount"], "max")), exp) + "; any other currency is refused.")
        if (approval != null) {
            val ap = J.m(approval)
            val n = if (own(ap, "approvers")) d0(ap["approvers"]) else 1.0
            val cnt = AttestUtil.jsNumString(n)
            val who = cnt + " approver" + (if (n == 1.0) "" else "s") + (if (own(ap, "group") && "" != ap["group"]) " from the " + ap["group"] + " group" else "")
            out.add(if (ap["always"] == true) "Always needs approval by $who." else "Needs approval by $who when the amount is above " + moneyList(J.m(ap["above"]), exp) + " (or in another currency).")
        }
        if (own(rules, "scope")) for (s0 in J.a(rules["scope"])) {
            val s = J.m(s0)
            val name = resolveParamRef(d, refOf(s), "rules.scope")["name"] as String
            out.add("Only the caller's own records: $name must be the caller's " + s["caller"] + ".")
        }
        if (own(rules, "rate")) for (r0 in J.a(rules["rate"])) {
            val r = J.m(r0)
            out.add("At most " + J.jsStr(r["max"]) + " per " + J.jsStr(r["per"]) + " per " + (if ("org" == r["by"]) "organisation" else "principal") + ".")
        }
        if (own(rules, "hours")) {
            val h = J.m(rules["hours"])
            out.add("Only " + hoursText(h) + "; outside those hours it " + (if ("deny" == h["outside"]) "is refused" else "needs approval") + ".")
        }
        if (own(rules, "recipients")) {
            val x = J.m(rules["recipients"])
            val name = resolveParamRef(d, refOf(x), "rules.recipients")["name"] as String
            out.add(name + " may only name " + recipientsText(x) + ".")
        }
        if (own(rules, "required")) out.add("Requires " + listText(strs(rules["required"])) + ".")
        return out
    }

    // ---- lint --------------------------------------------------------------------------------------------------------------------

    /** The rules lints (ids LR-*): `[id, severity, title]`. */
    val BUSINESS_RULE_LINTS: List<Array<String>> = listOf(
        arrayOf("LR-001", "error", "a rules block is malformed or names a parameter the action does not have"),
        arrayOf("LR-002", "error", "a contradiction: under the rules the action can never be allowed"),
        arrayOf("LR-003", "warning", "a rule that can never fire or that another rule already covers"),
        arrayOf("LR-004", "error", "a rules example does not decide as it expects"),
    )

    private fun finding(d: Map<String, Any?>, rule: String, severity: String, message: String): Map<String, Any?> =
        J.obj("rule", rule, "severity", severity, "verb", d["verb"], "message", message)

    private fun ccyJoin(xs: List<Any?>): String = xs.joinToString(", ") { J.jsStr(it) }

    private fun numStr(n: Any?): String = J.jsStr(n)

    /** Lint one action's rules. */
    fun lintBusinessRules(d: Map<String, Any?>, rules: Any?): List<Any?> {
        val out = ArrayList<Any?>()
        val e = businessRulesError(d, rules)
        if (e != null) { out.add(finding(d, "LR-001", "error", e)); return out }
        val r = J.m(rules)
        val approval = r["approval"]
        val ps = params(d)
        val above = approval != null && own(approval, "above")
        val m: Map<String, Any?>? = if (own(r, "amount") || above) moneyOf(d) else null
        val exp = if (m == null) 0 else expOf(m)
        val amt: Map<String, Any?>? = if (m == null) null else J.m(ps[m["amount"] as String])
        var ccyValues: List<Any?>? = null
        if (m != null) {
            val ccy = J.m(m["ccy"])
            ccyValues = if (ccy.containsKey("param")) (if (J.get(ps[ccy["param"] as String], "values") is List<*>) J.a(J.get(ps[ccy["param"] as String], "values")) else null) else J.list(ccy["literal"])
        }
        if (own(r, "amount") && m != null) {
            val maxes = J.m(J.get(r["amount"], "max"))
            val listed = ArrayList<String>(maxes.keys)
            if (ccyValues != null) {
                var any = false
                for (c in ccyValues) if (c is String && c in listed) any = true
                if (!any) out.add(finding(d, "LR-002", "error", "rules.amount: none of the action's currencies (" + ccyJoin(ccyValues) + ") has a ceiling, so every call is refused"))
            }
            for (c in listed) {
                val max = minorUnits(maxes[c], exp, c)
                if (ccyValues != null && !ccyValues.contains(c)) out.add(finding(d, "LR-003", "warning", "rules.amount.max.$c: the action never uses $c"))
                if (amt != null && own(amt, "min") && max < d0(amt["min"])) out.add(finding(d, "LR-002", "error", "rules.amount.max.$c: the ceiling " + formatMoney(max, c, exp) + " is below the parameter's minimum, so every $c call is refused"))
                if (amt != null && own(amt, "max") && max >= d0(amt["max"])) out.add(finding(d, "LR-003", "warning", "rules.amount.max.$c: the parameter's own maximum already bounds the amount below this ceiling"))
            }
        }
        if (above && m != null) {
            val ab = J.m(J.get(approval, "above"))
            val amount = if (own(r, "amount")) J.get(r["amount"], "max") else null
            for (c in ArrayList<String>(ab.keys)) {
                val x = minorUnits(ab[c], exp, c)
                val ceil = if (amount is Map<*, *>) amount[c] else null
                if (ceil != null && x >= minorUnits(ceil, exp, c)) out.add(finding(d, "LR-003", "warning", "rules.approval.above.$c: above the amount ceiling, so the approval can never be asked for"))
                if (own(r, "amount") && ceil == null) out.add(finding(d, "LR-003", "warning", "rules.approval.above.$c: $c has no ceiling, so it is always refused before an approval"))
            }
        }
        if (own(r, "hours")) {
            val h = J.m(r["hours"])
            if (h["from"] == h["to"]) out.add(finding(d, "LR-002", "error", "rules.hours: the window " + h["from"] + "-" + h["to"] + " is empty, so the action is " + (if ("deny" == h["outside"]) "always refused" else "always escalated")))
        }
        if (own(r, "required")) for (n in J.a(r["required"])) {
            val p = J.m(ps[n as String])
            if (p["required"] != false && "string" != p["type"]) out.add(finding(d, "LR-003", "warning", "rules.required: '$n' is already required by the definition"))
        }
        if (own(r, "rate")) {
            val seen = HashMap<String, Double>()
            for (x0 in J.a(r["rate"])) {
                val x = J.m(x0)
                val per = J.jsStr(x["per"])
                val by = if (own(x, "by")) x["by"] as String else "principal"
                val k = "$per|$by"
                val mx = d0(x["max"])
                if (seen.containsKey(k)) out.add(finding(d, "LR-003", "warning", "rules.rate: two limits per $per per $by; only the lower (" + AttestUtil.jsNumString(Math.min(seen[k]!!, mx)) + ") matters"))
                seen[k] = Math.min(seen[k] ?: Double.POSITIVE_INFINITY, mx)
            }
            val hh = seen["hour|principal"]
            val dd = seen["day|principal"]
            if (hh != null && dd != null && dd <= hh) out.add(finding(d, "LR-003", "warning", "rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires"))
        }
        try {
            for (x0 in runRuleExamples(d, r)) {
                val x = J.m(x0)
                if (x["ok"] != true) out.add(finding(d, "LR-004", "error", "rules.examples[" + numStr(x["index"]) + "]: expected " + x["expect"] + ", got " + x["got"] + " (" + x["why"] + ")"))
            }
        } catch (err: RuntimeException) {
            out.add(finding(d, "LR-001", "error", "" + err.message))
        }
        return out
    }

    // ---- semantic diff of rules --------------------------------------------------------------------------------------------------

    private enum class Rel { EQ, NARROW, WIDEN, INC }

    private fun relName(r: Rel): String = if (r == Rel.INC) "incomparable" else r.name.lowercase(Locale.ROOT)

    private fun setRel(a: Iterable<*>, b: Iterable<*>): Rel {
        val sa = HashSet<Any?>()
        val sb = HashSet<Any?>()
        for (x in a) sa.add(x)
        for (x in b) sb.add(x)
        val aInB = sb.containsAll(sa)
        val bInA = sa.containsAll(sb)
        return if (aInB && bInA) Rel.EQ else if (bInA) Rel.NARROW else if (aInB) Rel.WIDEN else Rel.INC
    }

    private fun numRel(a: Double, b: Double): Rel = if (a == b) Rel.EQ else if (b < a) Rel.NARROW else Rel.WIDEN

    private fun presence(o: Map<String, Any?>, n: Map<String, Any?>, k: String): Rel? {
        val a = undef(o, k)
        val b = undef(n, k)
        return if (a && b) Rel.EQ else if (a) Rel.NARROW else if (b) Rel.WIDEN else null
    }

    private fun combine(rs: List<Rel>): Rel {
        val inc = rs.contains(Rel.INC)
        val nar = rs.contains(Rel.NARROW)
        val wid = rs.contains(Rel.WIDEN)
        return if (inc || (nar && wid)) Rel.INC else if (wid) Rel.WIDEN else if (nar) Rel.NARROW else Rel.EQ
    }

    private fun flip(r: Rel): Rel = if (r == Rel.NARROW) Rel.WIDEN else if (r == Rel.WIDEN) Rel.NARROW else r

    private fun ccyMapRel(a: Any?, b: Any?, exp: Int): Rel {
        val ma = J.m(a)
        val mb = J.m(b)
        val rs = ArrayList<Rel>()
        rs.add(setRel(ma.keys, mb.keys))
        for (c in ma.keys) if (mb.containsKey(c)) rs.add(numRel(minorUnits(ma[c], exp, c).toDouble(), minorUnits(mb[c], exp, c).toDouble()))
        return combine(rs)
    }

    private fun minutesOfWeek(h: Map<String, Any?>): Set<Int> {
        val s = HashSet<Int>()
        val from = mins(h["from"] as String)
        val to = mins(h["to"] as String)
        for (day in J.a(h["days"])) {
            val base = RULE_DAYS.indexOf(day as String) * 1440
            if (from < to) {
                for (x in from until to) s.add(base + x)
            } else if (from > to) {
                for (x in from until 1440) s.add(base + x)
                for (x in 0 until to) s.add(((base + 1440) % 10080) + x)
            }
        }
        return s
    }

    private fun bestRates(rs: Any?): Map<String, Double> {
        val mp = HashMap<String, Double>()
        if (rs is List<*>) for (x0 in rs) {
            val x = J.m(x0)
            val k = J.jsStr(x["per"]) + "|" + (if (own(x, "by")) J.jsStr(x["by"]) else "principal")
            mp[k] = Math.min(mp[k] ?: Double.POSITIVE_INFINITY, d0(x["max"]))
        }
        return mp
    }

    private fun scopeKeys(sc: Any?): List<String> {
        val out = ArrayList<String>()
        if (sc is List<*>) for (s0 in sc) {
            val s = J.m(s0)
            out.add((if (s["param"] == null) "" else J.jsStr(s["param"])) + "|" + (if (s["role"] == null) "" else J.jsStr(s["role"])) + "|" + J.jsStr(s["caller"]))
        }
        return out
    }

    private fun listOrEmpty(x: Any?): List<Any?> = if (x is List<*>) J.a(x) else ArrayList<Any?>()

    private fun allowed(x: Map<String, Any?>): List<String> {
        val out = ArrayList<String>()
        for (dm in listOrEmpty(x["domains"])) out.add("@$dm")
        for (a in listOrEmpty(x["addresses"])) out.add(a as String)
        return out
    }

    private fun covered(x: String, set: List<String>): Boolean {
        if (set.contains(x)) return true
        if (x.startsWith("@")) return false
        val parts = x.split("@")
        return parts.size > 1 && set.contains("@" + parts[1])
    }

    /**
     * The semantic diff of two rules blocks of one action (either may be absent). `narrow` and `equal` can be published without
     * a reviewer; `widen` and `incomparable` need a reviewer's signed rules review. Returns `{class, reasons}`.
     */
    fun diffBusinessRules(d: Map<String, Any?>, prev: Map<String, Any?>?, next: Map<String, Any?>?): Map<String, Any?> {
        val rels = ArrayList<Pair<String, Rel>>()
        val o: Map<String, Any?> = prev ?: LinkedHashMap()
        val n: Map<String, Any?> = next ?: LinkedHashMap()
        val m: Map<String, Any?>? = if (own(o, "amount") || own(n, "amount") || (own(o, "approval") && own(o["approval"], "above")) || (own(n, "approval") && own(n["approval"], "above"))) moneyOf(d) else null
        val exp = if (m == null) 0 else expOf(m)

        var pr: Rel? = presence(o, n, "amount")
        rels.add(Pair("amount", pr ?: ccyMapRel(J.get(o["amount"], "max"), J.get(n["amount"], "max"), exp)))

        pr = presence(o, n, "approval")
        if (pr == null) {
            val a = J.m(o["approval"])
            val b = J.m(n["approval"])
            val rs = ArrayList<Rel>()
            val aa = a["always"] == true
            val ba = b["always"] == true
            if (aa && ba) rs.add(Rel.EQ)
            else if (aa) rs.add(Rel.WIDEN)
            else if (ba) rs.add(Rel.NARROW)
            else rs.add(ccyMapRel(a["above"], b["above"], exp))
            rs.add(numRel(-(if (own(a, "approvers")) d0(a["approvers"]) else 1.0), -(if (own(b, "approvers")) d0(b["approvers"]) else 1.0)))
            rs.add(if (a["group"] == b["group"]) Rel.EQ else Rel.INC)
            pr = combine(rs)
        }
        rels.add(Pair("approval", pr!!))

        rels.add(Pair("scope", flip(setRel(scopeKeys(o["scope"]), scopeKeys(n["scope"])))))

        val ra = bestRates(o["rate"])
        val rb = bestRates(n["rate"])
        val keys = HashSet<String>(ra.keys)
        keys.addAll(rb.keys)
        val rr = ArrayList<Rel>()
        for (k in keys) rr.add(if (!ra.containsKey(k)) Rel.NARROW else if (!rb.containsKey(k)) Rel.WIDEN else numRel(ra[k]!!, rb[k]!!))
        rels.add(Pair("rate", combine(rr)))

        pr = presence(o, n, "hours")
        if (pr == null) {
            val a = J.m(o["hours"])
            val b = J.m(n["hours"])
            if (a["tz"] != b["tz"]) pr = Rel.INC
            else {
                val sa = minutesOfWeek(a)
                val sb = minutesOfWeek(b)
                val inner = if (sa == sb) Rel.EQ else if (sa.containsAll(sb)) Rel.NARROW else if (sb.containsAll(sa)) Rel.WIDEN else Rel.INC
                val outside = numRel(if ("deny" == a["outside"]) 0.0 else 1.0, if ("deny" == b["outside"]) 0.0 else 1.0)
                pr = combine(listOf(inner, outside))
            }
        }
        rels.add(Pair("hours", pr!!))

        pr = presence(o, n, "recipients")
        if (pr == null) {
            val a = J.m(o["recipients"])
            val b = J.m(n["recipients"])
            if (a["param"] != b["param"] || a["role"] != b["role"]) pr = Rel.INC
            else {
                val allowedA = allowed(a)
                val allowedB = allowed(b)
                var bInA = true
                var aInB = true
                for (x in allowedB) if (!covered(x, allowedA)) bInA = false
                for (x in allowedA) if (!covered(x, allowedB)) aInB = false
                pr = if (bInA && aInB) Rel.EQ else if (bInA) Rel.NARROW else if (aInB) Rel.WIDEN else Rel.INC
            }
        }
        rels.add(Pair("recipients", pr!!))

        rels.add(Pair("required", flip(setRel(listOrEmpty(o["required"]), listOrEmpty(n["required"])))))

        val diffRels = ArrayList<Rel>()
        val reasonList = ArrayList<String>()
        for ((k, r) in rels) {
            if (r == Rel.EQ) continue
            diffRels.add(r)
            reasonList.add("rules." + k + ": " + relName(r))
        }
        reasonList.sort()
        val cls = combine(diffRels)
        return J.obj("class", if (cls == Rel.EQ) "equal" else if (cls == Rel.INC) "incomparable" else relName(cls), "reasons", ArrayList<Any?>(reasonList))
    }

    // ---- the reviewer's signature over a widened rules block --------------------------------------------------------------------

    /** The bytes a reviewer signs: the domain, a NUL, then the strict canonical body. */
    fun rulesReviewMessage(b: Map<String, Any?>): ByteArray {
        val body = J.obj("verb", b["verb"], "def_digest", b["def_digest"], "rules_digest", b["rules_digest"], "reviewer_kid", b["reviewer_kid"], "ts", b["ts"])
        return IntentJs.message(RULES_REVIEW_DOMAIN + "\u0000", body)
    }

    /** Sign a rules review (`verb, def_digest, rules_digest, reviewer_kid, ts`) with an Ed25519 seed. */
    fun signRulesReview(b: Map<String, Any?>, secret: ByteArray): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>(b)
        out["sig"] = Keys.b64u(Keys.edFromSeed(secret).sign(rulesReviewMessage(b)))
        return out
    }

    /**
     * Null iff `r` is a valid review of exactly these rules on exactly this def: digests match, the signer is pinned with the
     * `reviewer` role, the time is inside the key validity, the signature verifies. A reason otherwise. Never throws.
     */
    fun rulesReviewError(r: Any?, d: Map<String, Any?>, rules: Map<String, Any?>, pins: Any?): String? {
        try {
            if (pins == null) return "no reviewer keys are pinned"
            val pe = Actions.reviewerPinsError(pins)
            if (pe != null) return "bad pins: $pe"
            if (!isObj(r)) return "no rules review"
            val x = J.m(r)
            if (d["verb"] != x["verb"]) return "the rules review names another action"
            if (Actions.defDigest(d) != x["def_digest"]) return "the rules review covers another version of the action"
            if (businessRulesDigest(d["verb"] as String, rules) != x["rules_digest"]) return "the rules review covers other rules"
            if (x["sig"] !is String || x["reviewer_kid"] !is String || !J.isInt(x["ts"])) return "malformed rules review"
            var key: Map<String, Any?>? = null
            for (k in J.a(J.get(pins, "keys"))) if (x["reviewer_kid"] == J.get(k, "kid")) { key = J.m(k); break }
            if (key == null) return "no pinned key '" + x["reviewer_kid"] + "'"
            if (!J.a(key["roles"]).contains("reviewer")) return "key '" + key["kid"] + "' does not hold the reviewer role"
            val ts = d0(x["ts"])
            if ((own(key, "not_before") && ts < d0(key["not_before"])) || (own(key, "not_after") && ts > d0(key["not_after"]))) return "the review time is outside the key validity"
            val body = LinkedHashMap<String, Any?>(x)
            body.remove("sig")
            return if (Pca.verifyB64u(key["pk"] as? String, rulesReviewMessage(body), x["sig"] as String)) null else "the rules review signature is invalid"
        } catch (e: RuntimeException) {
            return "malformed rules review: " + e.message
        }
    }
}
