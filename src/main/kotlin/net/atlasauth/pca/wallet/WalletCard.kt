package net.atlasauth.pca.wallet

import java.math.BigDecimal
import java.math.BigInteger
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.Catalog
import net.atlasauth.pca.verifier.Pca

/**
 * The trusted question card. Rendering belongs to the wallet and is deterministic: [renderCard] is a pure function of the
 * wallet's own outcome space, the cell coordinates, the verified site identity, the principal's own signed statement, schema
 * units, the friction tier and (for a clarification) a closed-enum reason. Its input has NO field for agent-authored text. Values
 * of the concrete action are shown only in fixed slots: numbers formatted by unit, and a string only when the outcome space names
 * it (otherwise only its last four letters or digits). The card's digest goes into the signed answer, so an auditor can re-render
 * the card and see exactly what the human saw.
 */
@Suppress("UNCHECKED_CAST")
object WalletCard {
    const val CARD_DOMAIN = "atlas-pca/intent-card/v2"

    /** The closed reason enum of an agent clarification, with the fixed label the card shows. */
    @JvmField val CLARIFY_REASONS: List<String> = listOf("ambiguous_parameter", "multiple_options", "price_changed", "constraint_conflict", "missing_value", "other")

    @JvmField val REASON_LABELS: Map<String, String> = mapOf(
        "ambiguous_parameter" to "Your agent found a detail your request did not settle.",
        "multiple_options" to "Your agent found several options that match.",
        "price_changed" to "Your agent found that a price changed.",
        "constraint_conflict" to "Your agent found that two parts of your request conflict.",
        "missing_value" to "Your agent needs a value your request did not give.",
        "other" to "Your agent needs a decision before it continues.",
    )

    // ---- text helpers ----

    private const val WS = "[ \\f\\n\\r\\t\\u000b\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]"
    private val CONTROL = Regex("[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u2028-\\u202e\\u2066-\\u2069]")
    private val WS_RUN = Regex("$WS+")
    private val WS_ENDS = Regex("^$WS+|$WS+$")

    /** Strip control characters, collapse whitespace, cap length. For the principal's own words and the site's name. */
    fun cleanText(s: String, max: Int): String {
        var t = CONTROL.replace(s, " ")
        t = WS_RUN.replace(t, " ")
        t = WS_ENDS.replace(t, "")
        return if (t.length <= max) t else t.substring(0, max - 1) + "…"
    }

    private val NOT_ALNUM = Regex("[^A-Za-z0-9]")

    /** The last four letters / digits of a string (all a card ever shows of a string the outcome space does not name). */
    fun last4(s: String): String {
        val t = NOT_ALNUM.replace(s, "")
        return (if (t.length > 4) t.substring(t.length - 4) else t).uppercase()
    }

    /** The JavaScript decimal text of an integral double (plain digits), else the shortest form. */
    internal fun jsNum(d: Double): String {
        if (d.isNaN()) return "NaN"
        if (d.isInfinite()) return if (d > 0) "Infinity" else "-Infinity"
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return BigDecimal(d).toBigInteger().toString()
        return BigDecimal(java.lang.Double.toString(d)).toPlainString()
    }

    private val DIGITS = Regex("\\d+")

    /** Thousands grouping with commas, independent of any locale. */
    private fun group(n: Double): String {
        val s = jsNum(n)
        if (!DIGITS.matches(s)) return s
        val sb = StringBuilder()
        for (i in s.indices) {
            if (i > 0 && (s.length - i) % 3 == 0) sb.append(',')
            sb.append(s[i])
        }
        return sb.toString()
    }

    private val CURRENCY_SYMBOL = mapOf("USD" to "$", "EUR" to "€", "GBP" to "£", "JPY" to "¥")

    private fun trunc(x: Double): Double = if (x < 0) Math.ceil(x) else Math.floor(x)

    private fun isMoney(unit: Any?): Boolean = unit is Map<*, *> && "money" == unit["kind"]

    /** JavaScript ToNumber of a JSON value (an absent member is undefined: NaN). */
    private fun toNum(present: Boolean, v: Any?): Double {
        if (!present) return Double.NaN
        return when (v) {
            null -> 0.0
            is Boolean -> if (v) 1.0 else 0.0
            is String -> { val t = v.trim(); if (t.isEmpty()) 0.0 else t.toDoubleOrNull() ?: Double.NaN }
            is List<*> -> toNum(true, Js.template(v))
            is Map<*, *> -> Double.NaN
            else -> Js.num(v) ?: Double.NaN
        }
    }

    /** `Math.max(0, Math.min(6, Math.floor(unit.exponent)))`: NaN stays NaN. */
    private fun exponentD(unit: Any?): Double {
        val m = unit as Map<*, *>
        val e = Math.floor(toNum(m.containsKey("exponent"), m["exponent"]))
        return if (e.isNaN()) e else Math.max(0.0, Math.min(6.0, e))
    }

    private fun exponentOf(unit: Any?): Int = exponentD(unit).let { if (it.isNaN()) 0 else it.toInt() }

    /** A number as the card shows it: grouped, with the currency symbol and minor-unit decimals for money. */
    fun formatNumber(x: Double, unit: Any?): String {
        if (isMoney(unit)) {
            val ed = exponentD(unit)
            val e = if (ed.isNaN()) 0 else ed.toInt()
            val neg = x < 0
            val a = Math.abs(trunc(x))
            val div = Math.pow(10.0, ed)
            val whole = group(Math.floor(a / div))
            var frac = ""
            if (ed > 0) {
                val f = jsNum(a % div)
                val pad = StringBuilder()
                for (i in f.length until e) pad.append('0')
                frac = ".$pad$f"
            }
            val um = unit as Map<*, *>
            val curText = if (um.containsKey("currency")) Js.template(um["currency"]) else "undefined" // a template literal / property key text
            val sym = CURRENCY_SYMBOL[curText] ?: "$curText "
            return (if (neg) "-" else "") + sym + whole + frac
        }
        return (if (x < 0) "-" else "") + group(Math.abs(trunc(x)))
    }

    private val ACC = Regex("env\\.acc\\.([A-Za-z0-9_.-]+)\\.post")
    private val WORLD = Regex("env\\.world\\.([A-Za-z0-9_.-]+)")
    private val MON = Regex("env\\.mon\\.([A-Za-z0-9_.-]+)\\.state")

    private fun spaced(s: String): String = s.replace('_', ' ').replace('.', ' ')

    internal fun dimLabel(path: String): String {
        ACC.matchEntire(path)?.let { return spaced(it.groupValues[1]) + " (running total for this task)" }
        WORLD.matchEntire(path)?.let { return spaced(it.groupValues[1]) + " (from a signed fact)" }
        MON.matchEntire(path)?.let { return "state of " + spaced(it.groupValues[1]) }
        return WalletOmega.labelOf(path)
    }

    private fun isProvPath(p: String): Boolean = p.startsWith("env.prov.")

    private fun numFact(d: Map<String, Any?>, ids: IntArray, unit: Any?, actionValue: Any?): String {
        val cells = WalletOmega.numCells(d)
        val lo = cells[ids[0]][0]
        val hi = cells[ids[ids.size - 1]][1]
        val dlo = WalletOmega.dlo(d)
        val dhi = WalletOmega.dhi(d)
        val range: String = if (lo == hi) "exactly " + formatNumber(lo, unit)
        else if (lo == dlo && hi == dhi) "any value"
        else if (hi == dhi) formatNumber(lo, unit) + " or more"
        else if (lo == dlo) "up to " + formatNumber(hi, unit)
        else formatNumber(lo, unit) + " – " + formatNumber(hi, unit)
        val ex = if (Js.isNumber(actionValue) && Wallet.isFinite(actionValue)) " (this action: " + formatNumber(Wallet.nv(actionValue), unit) + ")" else ""
        return range + ex
    }

    private fun catValueText(d: Map<String, Any?>, i: Int): String {
        val v = WalletOmega.value(d, i)
        if ("exact" == v["kind"]) return "\"" + cleanText(v["value"] as String, 64) + "\""
        if ("prefix" == v["kind"]) return "anything starting with \"" + cleanText(v["value"] as String, 64) + "\""
        return "a value not named in your request"
    }

    private fun catFact(d: Map<String, Any?>, ids: IntArray, actionValue: Any?): String {
        val parts = ids.map { catValueText(d, it) }
        val set = if (parts.size == 1) parts[0] else parts.dropLast(1).joinToString(", ") + " or " + (parts.lastOrNull() ?: "undefined")
        if (actionValue !is String) return set
        var named = false
        for (v in WalletOmega.values(d)) if ("exact" == (v as Map<*, *>)["kind"] && actionValue == v["value"]) named = true
        return set + " (this action: " + (if (named) "\"" + cleanText(actionValue, 64) + "\"" else "a value ending in \"" + last4(actionValue) + "\"") + ")"
    }

    private fun bannerFor(path: String, levels: List<String>): String? {
        val w = Wallet.worstProvenance(levels)
        val label = dimLabel(path)
        if (w == "web") return "This $label was suggested by content on a web page, not by you."
        if (w == "tool") return "This $label came from a tool result, not from you."
        if (w == "agent") return "This $label was chosen by your agent, not taken from your request or from the site."
        return null
    }

    private val PROV_SPLIT = Regex("[|,]")

    private fun provLevels(d: Map<String, Any?>, ids: IntArray): List<String> {
        val out = ArrayList<String>()
        for (i in ids) out.addAll(WalletBox.catLabel(d, i).split(PROV_SPLIT))
        return out
    }

    // ---- render ----

    private fun typedTarget(vs: Map<String, Any?>, action: Map<String, Any?>?, units: Any?): Map<String, Any?>? {
        if (action == null) return null
        val values = action["values"]
        val dims = ArrayList<Map<String, Any?>>()
        for (k in WalletOmega.dims(vs).indices) {
            val d = WalletOmega.dim(vs, k)
            if (!isProvPath(d["path"] as String)) dims.add(d)
        }
        var pick: Map<String, Any?>? = null
        var money: Map<String, Any?>? = null
        for (d in dims) {
            if ("num" == d["kind"] && Js.isNumber(Js.get(values, d["path"] as String))) {
                if (pick == null) pick = d
                if (money == null && isMoney(Js.get(units, d["path"] as String))) money = d
            }
        }
        if (money != null) pick = money
        if (pick != null) return Wallet.obj("path", pick["path"], "mode", "number", "prompt", "To allow it, type the " + dimLabel(pick["path"] as String) + " of this action shown above.")
        for (d in dims) {
            val v = Js.get(values, d["path"] as String)
            if ("cat" == d["kind"] && v is String && last4(v).length == 4)
                return Wallet.obj("path", d["path"], "mode", "last4", "prompt", "To allow it, type the last 4 letters or digits of the " + dimLabel(d["path"] as String) + ".")
        }
        return null
    }

    private fun answers(label: String): List<Any?> = arrayListOf(
        Wallet.obj("id", "no", "label", "No"),
        Wallet.obj("id", "partly", "label", "Partly…"),
        Wallet.obj("id", "yes", "label", label),
    )

    private fun answersFor(friction: Any?): List<Any?>? {
        if ("tap" == friction) return answers("Yes")
        if ("hold" == friction) return answers("Press and hold to allow")
        if ("typed" == friction) return answers("Yes, type the value to confirm")
        if ("device" == friction) return answers("Yes, confirm with your security key")
        return null
    }

    private fun revText(rev: Any?): String {
        if ("reversible" == rev) return "that can be undone"
        if ("rate_limited" == rev) return "that is rate-limited"
        if ("irreversible" == rev) return "that cannot be undone"
        return "undefined"
    }

    private fun refuse(reason: String?): Map<String, Any?> = Wallet.obj("ok", false, "reason", reason)

    /**
     * Render the card of a question: {ok:true, card} or {ok:false, reason}. [input] members: omega, verb, coords, site
     * {origin, name}, statementText?, reversibility?, units?, action? {verb, values}, friction, kind, reason?, locale?.
     */
    fun renderCard(input: Map<String, Any?>, catalog: Catalog = Catalog.DEFAULT): Map<String, Any?> {
        val locale = if (Wallet.defined(input, "locale") && input["locale"] != null) input["locale"] else "en"
        if ("en" != locale) return refuse("unsupported locale " + (if (input["locale"] == null) "null" else Js.template(input["locale"])))
        val kind = input["kind"]
        val reason = input["reason"]
        val hasReason = Wallet.defined(input, "reason")
        if ("clarification" == kind && !hasReason) return refuse("a clarification card needs a reason")
        if (hasReason && !(reason is String && CLARIFY_REASONS.contains(reason))) return refuse("unknown clarification reason")
        val omega = input["omega"] as Map<String, Any?>
        val verbRaw = input["verb"]
        if (verbRaw !is String) return refuse("verb " + (if (input.containsKey("verb")) Js.template(verbRaw) else "undefined") + " is not in the wallet's outcome space")
        val verb = verbRaw
        val r = WalletBox.resolveCoords(omega, verb, input["coords"] as Map<String, Any?>)
        if (!r.ok) return refuse(r.reason)
        val vs = r.vs!!
        val box = r.box!!
        val actionO = input["action"]
        val action = actionO as? Map<String, Any?>
        if (Js.truthy(actionO) && (action == null || verb != action["verb"])) return refuse("the action is for another verb")
        val site = input["site"] as Map<String, Any?>
        var siteName = cleanText(site["name"] as String, 64)
        if (siteName.isEmpty()) siteName = cleanText(site["origin"] as String, 64)
        val said = if (Wallet.defined(input, "statementText")) cleanText(input["statementText"] as String, 280) else ""
        val header: String = if ("clarification" == kind) {
            if (said.isNotEmpty()) "Your agent needs a decision for your request \"$said\"" else "Your agent needs a decision"
        } else {
            if (said.isNotEmpty()) "$siteName asks on behalf of your request \"$said\"" else "$siteName asks for your confirmation"
        }
        val spec = catalog.get(verb)
        val what: String = if (spec != null) {
            val desc = if (spec.description.endsWith(".")) spec.description.substring(0, spec.description.length - 1) else spec.description
            if (desc.isEmpty()) desc else desc.substring(0, 1).lowercase() + desc.substring(1)
        } else "the action \"" + cleanText(verb, 64) + "\" on " + siteName
        val rev = if (input["reversibility"] != null) input["reversibility"] else vs["reversibility"]
        val sentence = "Allow $what, " + revText(rev) + ", with:"
        val units = input["units"]
        val facts = ArrayList<Any?>()
        val banners = ArrayList<Any?>()
        val partial = ArrayList<Any?>()
        val avs = action?.get("values")
        for (k in WalletOmega.dims(vs).indices) {
            val d = WalletOmega.dim(vs, k)
            val ids = box[k]
            val path = d["path"] as String
            if (isProvPath(path)) {
                if ("cat" != d["kind"]) continue
                val b = bannerFor(path.substring("env.prov.".length), provLevels(d, ids))
                if (b != null) banners.add(b)
                continue
            }
            val av = Js.get(avs, path)
            if ("num" == d["kind"]) {
                facts.add(Wallet.obj("key", path, "label", dimLabel(path), "text", numFact(d, ids, Js.get(units, path), av)))
                val cells = WalletOmega.numCells(d)
                partial.add(Wallet.obj("path", path, "kind", "num", "lo", cells[ids[0]][0], "hi", cells[ids[ids.size - 1]][1]))
            } else {
                facts.add(Wallet.obj("key", path, "label", dimLabel(path), "text", catFact(d, ids, av)))
                val options = ArrayList<Any?>()
                for (i in ids) if ("exact" == WalletOmega.value(d, i)["kind"]) options.add(WalletOmega.value(d, i)["value"])
                if (options.size > 1) partial.add(Wallet.obj("path", path, "kind", "cat", "options", options))
            }
        }
        val friction = input["friction"]
        val typed = if (Wallet.frictionRank(friction) >= Wallet.frictionRank("typed")) typedTarget(vs, action, units) else null
        val body = LinkedHashMap<String, Any?>()
        body["v"] = Js.n(2)
        body["kind"] = kind
        body["verb"] = verb
        body["coords"] = Wallet.plain(input["coords"])
        body["locale"] = "en"
        body["site"] = Wallet.obj("origin", cleanText(site["origin"] as String, 256), "name", siteName)
        body["header"] = header
        if (hasReason) body["reason_label"] = REASON_LABELS[reason]
        body["sentence"] = sentence
        body["facts"] = facts
        body["banners"] = banners
        body["friction"] = friction
        val ans = answersFor(friction)
        if (ans != null) body["answers"] = ans
        if (typed != null) body["typed"] = typed
        body["partial"] = partial
        val card = LinkedHashMap<String, Any?>(body)
        card["rendered_digest"] = cardDigest(body)
        return Wallet.obj("ok", true, "card", card)
    }

    /** The content address of a card body (everything but rendered_digest). */
    fun cardDigest(body: Map<String, Any?>): String = Pca.hashCanonical(Wallet.obj("d", CARD_DOMAIN, "c", Wallet.plain(body)))

    /** Recompute a card's digest and compare: an auditor's check that the stored card is the one that was hashed. */
    fun cardDigestMatches(card: Map<String, Any?>): Boolean {
        val body = LinkedHashMap(card)
        val d = body.remove("rendered_digest")
        return cardDigest(body) == d
    }

    /** The plain text of a card, line by line (what a screen reader or a text channel shows). */
    fun cardText(card: Map<String, Any?>): String {
        val lines = ArrayList<String>()
        lines.add(card["header"] as String)
        if (Js.truthy(card["reason_label"])) lines.add(card["reason_label"] as String)
        lines.add(card["sentence"] as String)
        for (f in card["facts"] as List<Any?>) lines.add("- " + (f as Map<String, Any?>)["label"] + ": " + f["text"])
        for (b in card["banners"] as List<Any?>) lines.add(b as String)
        if (card["typed"] != null) lines.add((card["typed"] as Map<String, Any?>)["prompt"] as String)
        val `as` = ArrayList<String>()
        for (a in card["answers"] as List<Any?>) `as`.add("[" + (a as Map<String, Any?>)["label"] + "]")
        lines.add(`as`.joinToString(" "))
        return lines.joinToString("\n")
    }

    // ---- responses ----

    private fun inRange(x: Any?, lo: Double, hi: Double): Boolean {
        val v = Wallet.nv(x)
        return Wallet.isSafeInteger(x) && !Js.isNegZero(x) && v >= lo && v <= hi
    }

    /** Validate a "Partly..." answer against the card: a structured restriction of the shown ranges and values only. */
    fun partialError(card: Map<String, Any?>, p: Map<String, Any?>): String? {
        var slot: Map<String, Any?>? = null
        for (s in card["partial"] as List<Any?>) if ((s as Map<String, Any?>)["path"] == p["path"]) { slot = s; break }
        if (slot == null) return "the card has no field " + p["path"]
        if ("num" == slot["kind"]) {
            val lo = Wallet.nv(slot["lo"])
            val hi = Wallet.nv(slot["hi"])
            if (p.containsKey("upTo")) return if (inRange(p["upTo"], lo, hi) && Wallet.nv(p["upTo"]) < hi) null else "upTo must be an integer in [" + jsNum(lo) + ", " + jsNum(hi - 1) + "]"
            if (p.containsKey("from")) return if (inRange(p["from"], lo, hi) && Wallet.nv(p["from"]) > lo) null else "from must be an integer in [" + jsNum(lo + 1) + ", " + jsNum(hi) + "]"
            if (p.containsKey("except")) {
                val ex = p["except"] as List<Any?>
                var ok = ex.isNotEmpty()
                for (x in ex) if (!inRange(x, lo, hi)) ok = false
                return if (ok) null else "except values must be integers in [" + jsNum(lo) + ", " + jsNum(hi) + "]"
            }
            return "a numeric partly answer needs upTo, from or except"
        }
        if (!p.containsKey("notFor")) return "a categorical partly answer needs notFor"
        val vals = LinkedHashSet<Any?>(p["notFor"] as List<Any?>)
        val options = slot["options"] as List<Any?>
        var allShown = true
        for (v in vals) if (!options.contains(v)) allShown = false
        if (vals.isEmpty() || !allShown) return "notFor must name values shown on the card"
        if (vals.size == options.size) return "excluding every value is a \"No\""
        return null
    }

    private val TYPED_STRIP = Regex("(?:$WS|[,$€£¥])")
    private val CCY_PREFIX = Regex("^[A-Z]{3}", RegexOption.IGNORE_CASE)
    private val NUM_RE = Regex("(-?)(\\d+)(?:\\.(\\d+))?")

    /** Normalize what the human typed for comparison with the action value (digits for numbers, minor units for money). */
    fun normalizeTyped(input: String, mode: String, unit: Any?): String? {
        if (mode == "last4") {
            val t = NOT_ALNUM.replace(input, "").uppercase()
            return if (t.length == 4) t else null
        }
        var t = TYPED_STRIP.replace(input, "")
        t = CCY_PREFIX.replaceFirst(t, "")
        val m = NUM_RE.matchEntire(t) ?: return null
        val e = if (isMoney(unit)) exponentOf(unit) else 0
        val frac = m.groups[3]?.value ?: ""
        if (frac.length > e) return null
        val padded = StringBuilder(frac)
        while (padded.length < e) padded.append('0')
        val minor = BigInteger(m.groupValues[2]).multiply(BigInteger.TEN.pow(e)).add(if (frac.isEmpty()) BigInteger.ZERO else BigInteger(padded.toString()))
        return (if ("-" == m.groupValues[1] && minor.signum() != 0) "-" else "") + minor
    }

    /** The normalized value the human must type for this card and action (what a site or auditor recomputes); null when none. */
    fun expectedTyped(card: Map<String, Any?>, action: Map<String, Any?>): String? {
        val typed = card["typed"] ?: return null
        val v = Js.get(action["values"], (typed as Map<String, Any?>)["path"] as String)
        if ("last4" == typed["mode"]) return if (v is String && last4(v).length == 4) last4(v) else null
        return if (Js.isNumber(v) && Wallet.isSafeInteger(v) && !Js.isNegZero(v)) jsNum(Wallet.nv(v)) else null
    }
}
