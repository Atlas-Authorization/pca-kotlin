package net.atlasauth.pca.ap2

import net.atlasauth.pca.ap2.Ap2Js.arr
import net.atlasauth.pca.ap2.Ap2Js.def
import net.atlasauth.pca.ap2.Ap2Js.get
import net.atlasauth.pca.ap2.Ap2Js.getU
import net.atlasauth.pca.ap2.Ap2Js.isArr
import net.atlasauth.pca.ap2.Ap2Js.isObj
import net.atlasauth.pca.ap2.Ap2Js.isStr
import net.atlasauth.pca.ap2.Ap2Js.sEq
import net.atlasauth.pca.ap2.Ap2Js.str
import net.atlasauth.pca.ap2.Ap2Js.truthy

/**
 * Evaluation of AP2 open-mandate constraints against a closed mandate / checkout.
 *
 * This follows the AP2 documentation's evaluation rules and is deliberately stricter than the official SDK in four places, each
 * a fail-closed choice: a line-item requirement whose `acceptable_items` is empty matches nothing; the maximal flow must equal
 * both the required and the carted quantity; a closed payment without `execution_date` is evaluated at the verification time;
 * `execution_date` bounds are compared as instants, not as strings.
 *
 * Mandates and contexts are parsed JSON (Map, List, String, Boolean, Json.Num, null). A usage context is
 * `{totalAmount, totalUses, lastUsedDate?}`: the minor-unit sum of previous closed payments, their count, and the epoch seconds
 * of the most recent one.
 */
@Suppress("UNCHECKED_CAST")
object Constraints {
    /** A usage context map ([lastUsedDate] may be null). */
    @JvmStatic
    @JvmOverloads
    fun context(totalAmount: Double, totalUses: Double, lastUsedDate: Double? = null): MutableMap<String, Any?> {
        val c = Ap2Js.m("totalAmount" to Ap2Js.n(totalAmount), "totalUses" to Ap2Js.n(totalUses))
        if (lastUsedDate != null) c["lastUsedDate"] = Ap2Js.n(lastUsedDate)
        return c
    }

    @JvmStatic
    fun merchantMatches(candidate: Any?, target: Any?): Boolean {
        val cid = get(candidate, "id")
        val tid = get(target, "id")
        if (truthy(cid) && truthy(tid)) return sEq(cid, tid)
        return truthy(get(candidate, "name")) && truthy(get(candidate, "website")) &&
            sEq(get(candidate, "name"), get(target, "name")) && sEq(get(candidate, "website"), get(target, "website"))
    }

    private fun sortKeys(v: Any?): Any? {
        if (v is List<*>) return v.map { sortKeys(it) }
        if (v is Map<*, *>) {
            val src = v as Map<String, Any?>
            val out = LinkedHashMap<String, Any?>()
            for (k in src.keys.sorted()) out[k] = sortKeys(src[k]) // UTF-16 code unit order, as Array.prototype.sort
            return out
        }
        return v
    }

    private fun sameJson(a: Any?, b: Any?): Boolean = Ap2Js.stringify(sortKeys(a)) == Ap2Js.stringify(sortKeys(b))

    private val RFC3339 = Regex("(\\d{4})-(\\d{2})-(\\d{2})(?:T(\\d{2}):(\\d{2}):(\\d{2})(?:\\.(\\d{1,9}))?(Z|([+-])(\\d{2}):(\\d{2})))?")

    // proleptic Gregorian civil calendar <-> days since 1970-01-01 (no java.time on Android API 24)
    internal fun daysFromCivil(y0: Long, m: Int, d: Int): Long {
        val y = if (m <= 2) y0 - 1 else y0
        val era = Math.floorDiv(y, 400L)
        val yoe = y - era * 400
        val doy = (153 * (m + (if (m > 2) -3 else 9)) + 2) / 5 + d - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }

    /** (year, month 1..12, day 1..31) of a day number. */
    internal fun civilFromDays(z0: Long): LongArray {
        val z = z0 + 719468
        val era = Math.floorDiv(z, 146097L)
        val doe = z - era * 146097
        val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
        val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        val mp = (5 * doy + 2) / 153
        val d = doy - (153 * mp + 2) / 5 + 1
        val m = if (mp < 10) mp + 3 else mp - 9
        return longArrayOf(if (m <= 2) yoe + era * 400 + 1 else yoe + era * 400, m, d)
    }

    private fun lengthOfMonth(y: Int, m: Int): Int = when (m) {
        2 -> if ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) 29 else 28
        4, 6, 9, 11 -> 30
        else -> 31
    }

    /**
     * Epoch ms of an RFC 3339 instant, or null. STRICT, and independent of the host: `YYYY-MM-DD` (UTC midnight) or
     * `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`, with every component in range (real calendar day, hour <= 23, no leap
     * second; the fraction is truncated to ms). An impossible day is refused rather than rolled over.
     */
    internal fun parseInstant(s: Any?): Double? {
        if (s !is String) return null
        val m = RFC3339.matchEntire(s) ?: return null
        val g = m.groupValues
        val y = g[1].toInt()
        val mo = g[2].toInt()
        val d = g[3].toInt()
        if (mo < 1 || mo > 12 || d < 1 || d > lengthOfMonth(y, mo)) return null
        val day = (daysFromCivil(y.toLong(), mo, d) * 86_400_000L).toDouble()
        if (m.groups[4] == null) return day
        val h = g[4].toInt()
        val mi = g[5].toInt()
        val se = g[6].toInt()
        if (h > 23 || mi > 59 || se > 59) return null
        var ms = 0.0
        if (m.groups[7] != null) {
            var f = g[7]
            if (f.length > 3) f = f.substring(0, 3)
            while (f.length < 3) f += "0"
            ms = f.toInt().toDouble()
        }
        var offset = 0.0
        if (g[8] != "Z") {
            val oh = g[10].toInt()
            val om = g[11].toInt()
            if (oh > 23 || om > 59) return null
            offset = (if (g[9] == "+") 1 else -1) * (oh * 60 + om) * 60_000.0
        }
        return day + ((h * 60 + mi) * 60 + se) * 1000.0 + ms - offset
    }

    /** Start (epoch ms, UTC) of the calendar period of [frequency] that contains [ms]; NaN for an unknown frequency. */
    internal fun periodStart(ms: Double, frequency: Any?): Double {
        if (ms.isNaN() || Math.abs(ms) > 8.64e15) return Double.NaN
        val day0 = 86_400_000L
        val t = ms.toLong()
        val dayNum = Math.floorDiv(t, day0)
        val day = dayNum * day0
        val monIdx = Math.floorMod(dayNum + 3, 7L) // Monday = 0 (1970-01-01 was a Thursday)
        val ymd = civilFromDays(dayNum)
        val year = ymd[0]
        val month = ymd[1].toInt()
        if (frequency !is String) return Double.NaN
        return when (frequency) {
            "ON_DEMAND" -> 0.0
            "DAILY" -> day.toDouble()
            "WEEKLY" -> (day - monIdx * day0).toDouble()
            "BIWEEKLY" -> {
                val weekStart = day - monIdx * day0
                val week2 = 14 * day0
                val epochMonday = -3 * day0
                (epochMonday + Math.floorDiv(weekStart - epochMonday, week2) * week2).toDouble()
            }
            "MONTHLY" -> (daysFromCivil(year, month, 1) * day0).toDouble()
            "QUARTERLY" -> (daysFromCivil(year, ((month - 1) / 3) * 3 + 1, 1) * day0).toDouble()
            "ANNUALLY" -> (daysFromCivil(year, 1, 1) * day0).toDouble()
            else -> Double.NaN
        }
    }

    /** Inputs of [checkPaymentConstraints]. */
    class PaymentCheckOptions @JvmOverloads constructor(
        /** `sd_hash` of the open checkout mandate this payment is chained to (for `payment.reference`). */
        var openCheckoutHash: String? = null,
        /** Usage state; required to evaluate `payment.budget` and recurrence limits / frequency. */
        var context: Map<String, Any?>? = null,
        /** Verification time, epoch seconds. */
        var now: Double = 0.0,
    )

    private fun d(o: Any?): Double = Ap2Js.num(o) ?: Double.NaN

    /** A usage context with a NaN, negative or fractional counter would make the cap comparisons fail open: refuse it. */
    private fun contextProblem(c: Map<String, Any?>): String? {
        if (!Ap2Js.isNonNegInt(c["totalAmount"]) || !Ap2Js.isNonNegInt(c["totalUses"]) || (c.containsKey("lastUsedDate") && !Ap2Js.isNonNegInt(c["lastUsedDate"]))) {
            return "mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate"
        }
        return null
    }

    private fun one(s: String): MutableList<String> = ArrayList<String>().also { it.add(s) }

    private fun evaluatePayment(c: Any?, closed: Map<String, Any?>, o: PaymentCheckOptions): List<String> {
        val amt = closed["payment_amount"]
        val type = get(c, "type")
        val v = ArrayList<String>()
        val t = type as? String ?: "\u0000"
        when (t) {
            "payment.amount_range" -> {
                if (!sEq(get(amt, "currency"), get(c, "currency"))) v.add("currency mismatch: expected " + str(getU(c, "currency")) + ", got " + str(getU(amt, "currency")))
                if (!d(get(amt, "amount")).isFinite()) v.add("amount " + str(getU(amt, "amount")) + " is not finite")
                if (def(c, "min") && !(d(get(amt, "amount")) >= d(get(c, "min")))) v.add("amount " + str(getU(amt, "amount")) + " below minimum " + str(get(c, "min")))
                if (!(d(get(amt, "amount")) <= d(get(c, "max")))) v.add("amount " + str(getU(amt, "amount")) + " exceeds maximum " + str(getU(c, "max")))
                return v
            }
            "payment.allowed_payees" -> {
                for (m in arr(get(c, "allowed"))) if (merchantMatches(m, closed["payee"])) return v
                return one("payee " + str(getU(closed["payee"], "name")) + " is not in the allowed list")
            }
            "payment.allowed_payment_instruments" -> {
                for (i in arr(get(c, "allowed"))) if (sEq(get(i, "id"), get(closed["payment_instrument"], "id"))) return v
                return one("payment instrument " + str(getU(closed["payment_instrument"], "id")) + " is not in the allowed list")
            }
            "payment.allowed_pisps" -> {
                val p = closed["pisp"]
                if (!truthy(p)) return one("missing PISP in the closed mandate")
                for (a in arr(get(c, "allowed"))) {
                    if (sEq(get(a, "legal_name"), get(p, "legal_name")) && sEq(get(a, "brand_name"), get(p, "brand_name")) && sEq(get(a, "domain_name"), get(p, "domain_name"))) return v
                }
                return one("PISP is not in the allowed list")
            }
            "payment.reference" -> {
                val h = o.openCheckoutHash
                if (h == null || h.isEmpty()) return one("openCheckoutHash is required to evaluate a payment.reference constraint")
                return if (sEq(h, get(c, "conditional_transaction_id"))) v else one("payment.reference does not match the open checkout mandate hash")
            }
            "payment.budget" -> {
                if (!sEq(get(amt, "currency"), get(c, "currency"))) return one("budget currency mismatch: expected " + str(getU(c, "currency")) + ", got " + str(getU(amt, "currency")))
                // The official SDK converts the budget with int(max * 100) for every currency; this check reads it the same way,
                // and the issuing side (ap2BudgetMax) chooses max so that this reading is never above the PCA cap.
                val ctx = o.context ?: return one("mandate context is required to evaluate a budget")
                val bad = contextProblem(ctx)
                if (bad != null) return one(bad)
                val scaled = d(get(c, "max")) * 100
                val maxMinor = Ap2Js.round(scaled)
                if (!(Math.abs(scaled - maxMinor) <= 1e-6)) return one("budget.max is not a whole number of minor units")
                val spend = d(ctx["totalAmount"]) + d(get(amt, "amount"))
                return if (!(spend.isFinite() && spend <= maxMinor)) {
                    one("cumulative spend " + str(Ap2Js.n(spend)) + " exceeds budget " + str(Ap2Js.n(maxMinor)) + " (past spend " + str(ctx["totalAmount"]) + ")")
                } else v
            }
            "payment.agent_recurrence" -> {
                // strict: an unknown frequency is a violation whether or not a last-used date exists
                val freq = get(c, "frequency")
                if (freq !is String || !Mandates.FREQUENCIES.contains(freq)) return one("unknown recurrence frequency")
                val ctx = o.context
                if (ctx != null) {
                    val bad = contextProblem(ctx)
                    if (bad != null) return one(bad)
                }
                if (def(c, "max_occurrences")) {
                    if (ctx == null) return one("mandate context is required to evaluate recurrence limits")
                    if (!(d(ctx["totalUses"]) < d(get(c, "max_occurrences")))) {
                        v.add("maximum occurrences exceeded: " + str(ctx["totalUses"]) + " >= " + str(get(c, "max_occurrences")))
                    }
                }
                if ("ON_DEMAND" != get(c, "frequency")) {
                    if (ctx == null) return one("mandate context is required to evaluate recurrence frequency")
                    if (ctx.containsKey("lastUsedDate")) {
                        val last = d(ctx["lastUsedDate"])
                        if (!(last * 1000 < periodStart(o.now * 1000, get(c, "frequency")))) v.add("already used in the current " + str(get(c, "frequency")) + " period")
                    }
                }
                return v
            }
            "payment.execution_date" -> {
                val atRaw: Double? = if (closed.containsKey("execution_date")) parseInstant(closed["execution_date"]) else o.now * 1000
                if (atRaw == null || !atRaw.isFinite()) return one("execution_date " + str(getU(closed, "execution_date")) + " is not a valid instant")
                val at: Double = atRaw
                for (key in arrayOf("not_before", "not_after")) {
                    if (!def(c, key)) continue
                    val before = key == "not_before"
                    val bound = get(c, key)
                    val b = parseInstant(bound)
                    if (b == null) v.add("$key " + str(bound) + " is not a valid instant")
                    else if (if (before) !(at >= b) else !(at <= b)) v.add("execution date is " + (if (before) "before" else "after") + " the allowed window ($key " + str(bound) + ")")
                }
                return v
            }
            else -> return one("unknown constraint type " + str(getU(c, "type")))
        }
    }

    /** Violations of the open payment mandate's constraints and pre-set claims by [closed] (empty = satisfied). */
    @JvmStatic
    fun checkPaymentConstraints(open: Map<String, Any?>, closed: Map<String, Any?>, o: PaymentCheckOptions): List<String> {
        val v = ArrayList<String>()
        if (open.containsKey("payee") && !merchantMatches(open["payee"], closed["payee"])) {
            v.add("pre-set payee mismatch: expected " + str(getU(open["payee"], "name")) + ", got " + str(getU(closed["payee"], "name")))
        }
        if (open.containsKey("payment_amount") && !sameJson(open["payment_amount"], getU(closed, "payment_amount"))) v.add("pre-set payment_amount mismatch")
        if (open.containsKey("payment_instrument") && !sameJson(open["payment_instrument"], getU(closed, "payment_instrument"))) v.add("pre-set payment_instrument mismatch")
        if (open.containsKey("pisp") && !sameJson(open["pisp"], getU(closed, "pisp"))) v.add("pre-set pisp mismatch")
        if (open.containsKey("execution_date") && !sEq(open["execution_date"], getU(closed, "execution_date"))) v.add("pre-set execution_date mismatch")

        val types = HashSet<Any?>()
        for (c in arr(open["constraints"])) types.add(get(c, "type"))
        if (types.contains("payment.agent_recurrence")) {
            if (!types.contains("payment.amount_range")) v.add("payment.agent_recurrence requires a payment.amount_range constraint")
            if (!types.contains("payment.budget")) v.add("payment.agent_recurrence requires a payment.budget constraint")
        }
        for (c in arr(open["constraints"])) v.addAll(evaluatePayment(c, closed, o))
        return v
    }

    // ---------------------------------------------------------------------------------------------
    // checkout side
    // ---------------------------------------------------------------------------------------------

    private val ISO_CCY = Regex("[A-Z]{3}")

    /**
     * Validate and project the checkout payload into the slice of the UCP Checkout object the constraints read
     * (`id, currency, line_items[{id, item{id,title,price}, quantity}], totals[{type,amount}], merchant?`); throws a descriptive
     * [Ap2Error] when malformed.
     */
    @JvmStatic
    fun projectCheckout(payload: Map<String, Any?>): MutableMap<String, Any?> {
        val id = payload["id"]
        if (id !is String || id.isEmpty()) throw bad("id is required")
        val currency = payload["currency"]
        if (currency !is String || !ISO_CCY.matches(currency)) throw bad("currency must be ISO 4217")
        if (!isArr(payload["line_items"]) || arr(payload["line_items"]).isEmpty()) throw bad("line_items must be a non-empty array")
        if (!isArr(payload["totals"])) throw bad("totals must be an array")
        val lineItems = ArrayList<Any?>()
        val src = arr(payload["line_items"])
        for (i in src.indices) {
            val li = src[i]
            if (!isObj(li) || !isStr(get(li, "id")) || !isObj(get(li, "item"))) throw bad("line_items[$i] is malformed")
            val item = get(li, "item")
            val price = get(item, "price")
            if (!isStr(get(item, "id")) || !isStr(get(item, "title")) || !Ap2Js.isSafeInteger(price) || Ap2Js.num(price)!! < 0 || Ap2Js.isNegZero(Ap2Js.num(price)!!)) {
                throw bad("line_items[$i].item needs id, title and integer minor-unit price")
            }
            val qty = get(li, "quantity")
            if (!Ap2Js.isSafeInteger(qty) || Ap2Js.num(qty)!! < 1) throw bad("line_items[$i].quantity must be a positive integer")
            lineItems.add(Ap2Js.m("id" to get(li, "id"), "item" to Ap2Js.m("id" to get(item, "id"), "title" to get(item, "title"), "price" to price), "quantity" to qty))
        }
        val totals = ArrayList<Any?>()
        val tsrc = arr(payload["totals"])
        for (i in tsrc.indices) {
            val t = tsrc[i]
            if (!isObj(t) || !isStr(get(t, "type")) || !Ap2Js.isSafeInteger(get(t, "amount")) || Ap2Js.isNegZero(Ap2Js.num(get(t, "amount"))!!)) throw bad("totals[$i] is malformed")
            totals.add(Ap2Js.m("type" to get(t, "type"), "amount" to get(t, "amount")))
        }
        var merchant: MutableMap<String, Any?>? = null
        if (payload.containsKey("merchant")) {
            val m = payload["merchant"]
            if (!isObj(m) || !isStr(get(m, "id")) || !isStr(get(m, "name"))) throw bad("merchant needs id and name")
            merchant = Ap2Js.m("id" to get(m, "id"), "name" to get(m, "name"))
            if (isStr(get(m, "website"))) merchant["website"] = get(m, "website")
        }
        val out = Ap2Js.m("id" to id, "currency" to currency, "line_items" to lineItems, "totals" to totals)
        if (merchant != null) out["merchant"] = merchant
        return out
    }

    private fun bad(m: String) = Ap2Error("checkout_jwt payload: $m")

    /** The checkout's single `total` entry in minor units (the number), or null if absent / ambiguous. */
    @JvmStatic
    fun checkoutTotal(checkout: Map<String, Any?>): Any? {
        var found: Any? = null
        var n = 0
        for (t in arr(checkout["totals"])) {
            if ("total" == get(t, "type")) {
                n++
                found = get(t, "amount")
            }
        }
        return if (n == 1) found else null
    }

    /**
     * Maximal-flow assignment of cart quantities to requirement slots (Edmonds-Karp on the bipartite graph of the
     * documentation): satisfied iff the flow equals both the required and the carted total.
     */
    private fun lineItemViolations(cart: List<Any?>, reqs: List<Any?>): List<String> {
        val qty = LinkedHashMap<Any?, Double>()
        for (li in cart) {
            val itemId = get(get(li, "item"), "id")
            qty[itemId] = (qty[itemId] ?: 0.0) + d(get(li, "quantity"))
        }
        val skus = ArrayList<Any?>(qty.keys)
        val s0 = 0
        val t0 = 1 + skus.size + reqs.size
        val cap = ArrayList<LinkedHashMap<Int, Double>>()
        for (i in 0..t0) cap.add(LinkedHashMap())
        val inf = 9007199254740991.0
        for (i in skus.indices) add(cap, s0, 1 + i, qty[skus[i]]!!)
        for (j in reqs.indices) {
            val r = reqs[j]
            add(cap, 1 + skus.size + j, t0, d(get(r, "quantity")))
            val ok = HashSet<Any?>()
            for (a in arr(get(r, "acceptable_items"))) ok.add(get(a, "id"))
            for (i in skus.indices) if (ok.contains(skus[i])) add(cap, 1 + i, 1 + skus.size + j, inf)
        }
        var flow = 0.0
        while (true) {
            val parent = LinkedHashMap<Int, Int>()
            parent[s0] = s0
            val queue = ArrayList<Int>()
            queue.add(s0)
            var h = 0
            while (h < queue.size && !parent.containsKey(t0)) {
                val u = queue[h]
                for ((k, c) in cap[u]) {
                    if (c > 0 && !parent.containsKey(k)) {
                        parent[k] = u
                        queue.add(k)
                    }
                }
                h++
            }
            if (!parent.containsKey(t0)) break
            var push = inf
            var v = t0
            while (v != s0) {
                val u = parent[v]!!
                push = Math.min(push, cap[u][v]!!)
                v = u
            }
            v = t0
            while (v != s0) {
                val u = parent[v]!!
                cap[u][v] = cap[u][v]!! - push
                cap[v][u] = cap[v][u]!! + push
                v = u
            }
            flow += push
        }
        var required = 0.0
        for (r in reqs) required += d(get(r, "quantity"))
        var carted = 0.0
        for (q in qty.values) carted += q
        if (flow == required && flow == carted) return ArrayList()
        return one("line items do not satisfy the constraint: assigned " + str(Ap2Js.n(flow)) + " of " + str(Ap2Js.n(required)) + " required and " + str(Ap2Js.n(carted)) + " carted units")
    }

    private fun add(cap: List<MutableMap<Int, Double>>, u: Int, v: Int, c: Double) {
        cap[u][v] = (cap[u][v] ?: 0.0) + c
        cap[v][u] = cap[v][u] ?: 0.0
    }

    private fun evaluateCheckout(c: Any?, checkout: Map<String, Any?>): List<String> {
        val type = get(c, "type")
        if ("checkout.allowed_merchants" == type) {
            val m = checkout["merchant"]
            if (!truthy(m)) return one("missing merchant in the checkout")
            for (a in arr(get(c, "allowed"))) if (merchantMatches(a, m)) return ArrayList()
            return one("merchant " + str(getU(m, "name")) + " is not in the allowed list")
        }
        if ("checkout.line_items" != type) return one("unknown constraint type " + str(getU(c, "type")))
        return if (arr(checkout["line_items"]).isEmpty()) one("empty cart does not satisfy a line_items constraint") else lineItemViolations(arr(checkout["line_items"]), arr(get(c, "items")))
    }

    /** Violations of the open checkout mandate's constraints by [checkout] (a [projectCheckout] result; empty = satisfied). */
    @JvmStatic
    fun checkCheckoutConstraints(open: Map<String, Any?>, checkout: Map<String, Any?>): List<String> {
        val out = ArrayList<String>()
        for (c in arr(open["constraints"])) out.addAll(evaluateCheckout(c, checkout))
        return out
    }
}
