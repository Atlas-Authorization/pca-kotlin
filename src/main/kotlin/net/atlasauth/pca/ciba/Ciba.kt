package net.atlasauth.pca.ciba

import java.io.ByteArrayOutputStream
import java.text.Normalizer
import java.util.Locale
import java.util.regex.Pattern
import net.atlasauth.pca.gnap.GnapJs as Js
import net.atlasauth.pca.jose.Uts46
import net.atlasauth.pca.verifier.Approval
import net.atlasauth.pca.verifier.Issue
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * A CIBA (OpenID Connect Client-Initiated Backchannel Authentication) on-ramp for PCA's step-up: a step-up request becomes a
 * backchannel authentication request (binding message, scope, expiry, interval) with risk-adaptive gating. Mirrors the reference
 * package's main module. A step-up is a JSON object with the reference's field names (`id`, `verb`, `resource`, `params`, `tier`,
 * `goalCommit`, `goal`, `render`, `renderDigest`); request options use the reference's option names (`expiresInSec`, `authReqId`,
 * `stepUpScope`, `loginHint`, `bindingMessage` = {maxChars, tokenOnly}, `interval`, `actsFor`). Every refusal throws
 * [IllegalArgumentException] (the reference's RangeError / TypeError). Nothing here authorises anything: the resource server's
 * verifier and the FROST cosigners remain the authority.
 *
 * The payee homograph checks use the platform's Unicode tables, so a character newer than the runtime's Unicode version reads as
 * unassigned and is refused. [asciiForm] encodes a word with UTS 46 ToASCII (ICU4J); a word it refuses is shown in its escaped form.
 */
@Suppress("UNCHECKED_CAST")
object Ciba {
    internal const val DEFAULT_EXPIRY_SEC = 300
    internal const val DEFAULT_INTERVAL_SEC = 5
    internal const val MIN_AUTH_REQ_ID_LEN = 22
    internal const val MAX_GOAL_CHARS = 100
    internal const val MAX_PAYEE_CHARS = 64
    internal val PAYEE_KEYS = listOf("payee", "to", "recipient", "beneficiary", "destination")
    private val DISPLAYED_PARAM_KEYS: Set<String> = linkedSetOf("amount", "currency") + PAYEE_KEYS

    private const val WS_CLASS = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
    private val FORGED_CLAUSE = Pattern.compile("because[$WS_CLASS]+you[$WS_CLASS]+asked", Pattern.CASE_INSENSITIVE)
    private val AUTH_REQ_ID = Pattern.compile("[A-Za-z0-9._-]+")
    private val IDENT = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,63}")
    private val PLAIN_AMOUNT = Pattern.compile("(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?")
    private val CURRENCY = Pattern.compile("[A-Za-z]{3}")
    private val WS_TWO = Pattern.compile("[$WS_CLASS]{2,}")
    private val DIGITS = Regex("[0-9]+")
    private val HEX_LABEL = Regex("0[xX][0-9a-fA-F]*")

    private fun range(m: String) = IllegalArgumentException(m)

    // ---- text helpers ----
    private fun cpLen(s: String) = s.codePointCount(0, s.length)

    private fun type(cp: Int): Int = Character.getType(cp)

    private inline fun eachCp(s: String, f: (Int) -> Unit) {
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            i += Character.charCount(cp)
            f(cp)
        }
    }

    /**
     * Make untrusted text safe for a one-line, plain-text approval prompt: control characters, line breaks and bidi / zero-width
     * formatting characters become spaces, runs of whitespace collapse.
     */
    internal fun plainText(value: String): String {
        val sb = StringBuilder()
        var inWs = false
        eachCp(value) { cp ->
            val t = type(cp)
            val space = t == Character.CONTROL.toInt() || t == Character.FORMAT.toInt() || cp == 0x2028 || cp == 0x2029 || Js.isWs(cp)
            if (space) { if (!inWs) sb.append(' '); inWs = true } else { sb.appendCodePoint(cp); inWs = false }
        }
        return Js.trim(sb.toString())
    }

    internal fun clip(value: String, max: Double): String {
        val n = cpLen(value)
        if (n <= max) return value
        val keep = max.toInt() - 1
        val end = value.offsetByCodePoints(0, maxOf(0, minOf(keep, n)))
        return value.substring(0, end) + "…"
    }

    private fun asciiPrintable(s: String, allowEmpty: Boolean): Boolean = if (s.isEmpty()) allowEmpty else s.all { it.code in 0x20..0x7e }

    private fun identifier(value: Any?, what: String): String {
        if (value !is String || !IDENT.matcher(value).matches())
            throw range("ciba: the step-up $what must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message")
        if (FORGED_CLAUSE.matcher(value).find()) throw range("ciba: the step-up $what contains an approval-explanation clause")
        return value
    }

    private fun undisplayable(cp: Int): Boolean {
        val t = type(cp)
        return t == Character.CONTROL.toInt() || t == Character.FORMAT.toInt() || t == Character.SURROGATE.toInt() || t == Character.PRIVATE_USE.toInt() ||
            t == Character.UNASSIGNED.toInt() || cp == 0x2028 || cp == 0x2029 || (cp in 0xfff9..0xfffd)
    }

    private fun isMark(cp: Int): Boolean {
        val t = type(cp)
        return t == Character.NON_SPACING_MARK.toInt() || t == Character.COMBINING_SPACING_MARK.toInt() || t == Character.ENCLOSING_MARK.toInt()
    }

    private fun anyCp(s: String, p: (Int) -> Boolean): Boolean {
        eachCp(s) { if (p(it)) return true }
        return false
    }

    private fun payeeText(value: Any?): String {
        if (value !is String) throw range("ciba: the payee must be a string (a nested value cannot be shown to the approver)")
        val t = Normalizer.normalize(value, Normalizer.Form.NFC)
        if (t.isEmpty() || Js.trim(t) != t || WS_TWO.matcher(t).find()) throw range("ciba: the payee must be non-empty without leading, trailing or repeated whitespace")
        if (anyCp(t) { undisplayable(it) } || t.indexOf('\r') >= 0 || t.indexOf('\n') >= 0 || t.indexOf('\t') >= 0)
            throw range("ciba: the payee contains control, bidirectional or invisible characters and cannot be displayed")
        if (t.indexOf('"') >= 0 || t.indexOf('\\') >= 0) throw range("ciba: the payee must not contain quote or backslash characters")
        if (cpLen(t) > MAX_PAYEE_CHARS) throw range("ciba: the payee is longer than $MAX_PAYEE_CHARS characters; refusing to truncate what the person approves")
        if (FORGED_CLAUSE.matcher(t).find()) throw range("ciba: the payee contains an approval-explanation clause")
        // Look-alikes: NFC already composed what can be composed, so a combining mark left is stacked or decorative; compatibility forms differ
        // from their plain look-alike under NFKC; a payee that mixes scripts is the classic homograph.
        if (anyCp(t) { isMark(it) }) throw range("ciba: the payee contains combining marks and cannot be shown unambiguously")
        if (Normalizer.normalize(t, Normalizer.Form.NFKC) != t) throw range("ciba: the payee contains compatibility/fullwidth characters that imitate plain ones")
        if (scriptsOf(t).size > 1) throw range("ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike")
        return t
    }

    /** Writing-system groups present in `t` (letters only; digits, punctuation and spaces are script-neutral). Character.UnicodeScript needs API 24. */
    internal fun scriptsOf(t: String): Set<String> {
        val found = LinkedHashSet<String>()
        eachCp(t) { cp ->
            if (Character.isLetter(cp)) {
                val g = when (Character.UnicodeScript.of(cp)) {
                    Character.UnicodeScript.LATIN -> "latin"
                    Character.UnicodeScript.CYRILLIC -> "cyrillic"
                    Character.UnicodeScript.GREEK -> "greek"
                    Character.UnicodeScript.ARMENIAN -> "armenian"
                    Character.UnicodeScript.HEBREW -> "hebrew"
                    Character.UnicodeScript.ARABIC -> "arabic"
                    Character.UnicodeScript.HAN, Character.UnicodeScript.HIRAGANA, Character.UnicodeScript.KATAKANA, Character.UnicodeScript.HANGUL,
                    Character.UnicodeScript.BOPOMOFO -> "cjk"
                    Character.UnicodeScript.DEVANAGARI, Character.UnicodeScript.BENGALI, Character.UnicodeScript.TAMIL, Character.UnicodeScript.THAI,
                    Character.UnicodeScript.GEORGIAN -> "indic-thai"
                    else -> null
                }
                found.add(g ?: ("other:" + String(Character.toChars(cp))))
            }
        }
        return found
    }

    // ---- ASCII form of a payee (UTS 46) ----
    private fun hex(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    private fun percentDecode(h: String): String {
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < h.length) {
            val c = h[i]
            if (c == '%' && i + 2 < h.length && hex(h[i + 1]) >= 0 && hex(h[i + 2]) >= 0) {
                out.write(hex(h[i + 1]) * 16 + hex(h[i + 2]))
                i += 3
                continue
            }
            val cp = h.codePointAt(i)
            i += Character.charCount(cp)
            val b = Json.utf8(String(Character.toChars(cp)))
            out.write(b, 0, b.size)
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    /**
     * `url.domainToASCII` (the host of `ws://<word>`): the word ends at the first `/ ? # \`, a valid `%XX` is decoded, then UTS 46 ToASCII
     * (ICU4J: non-transitional, CheckBidi, CheckJoiners, STD3 off, no hyphen or length checks) for a non-ASCII word, a
     * forbidden host character is refused, and a numeric last label (an IPv4 form) is refused; empty when the host cannot be encoded.
     */
    internal fun domainToAscii(w: String): String {
        var cut = w.length
        for (i in w.indices) { val c = w[i]; if (c == '/' || c == '?' || c == '#' || c == '\\') { cut = i; break } }
        val host = w.substring(0, cut)
        if (host.isEmpty()) return ""
        val decoded = percentDecode(host)
        val m = if (Uts46.needed(decoded)) Uts46.toAscii(decoded)?.lowercase(Locale.ROOT) ?: return "" else decoded.lowercase(Locale.ROOT)
        if (m.isEmpty()) return ""
        if (m.any { it.code <= 0x20 || it.code == 0x7f || "#%/:<>?@[\\]^|".indexOf(it) >= 0 }) return ""
        val labels = m.split(".")
        var last = labels.size - 1
        if (last > 0 && labels[last].isEmpty()) last--
        val l = labels[last]
        if (DIGITS.matches(l) || HEX_LABEL.matches(l)) return ""
        return m
    }

    /** Plain-ASCII rendering of a payee: itself when ASCII, else the punycode of each word (or braced code point escapes when IDNA refuses). */
    fun asciiForm(payee: String): String {
        if (asciiPrintable(payee, true)) return payee
        return payee.split(" ").joinToString(" ") { w ->
            if (asciiPrintable(w, true)) w
            else domainToAscii(w).ifEmpty {
                val sb = StringBuilder()
                eachCp(w) { cp -> if (cp > 0x7e) sb.append("\\u{").append(Integer.toHexString(cp)).append('}') else sb.appendCodePoint(cp) }
                sb.toString()
            }
        }
    }

    // ---- the canonical action ----
    /**
     * Build the canonical action from a step-up: `{verb, [amount, currency,] [payee,] resource}`. Fails loud: unknown params keys, a
     * nested or malformed amount, a missing currency or payee next to an amount, two different payee fields, and non-identifier verb /
     * resource all throw.
     */
    fun cibaActionFromStepUp(stepUp: Map<String, Any?>): Map<String, Any?> {
        val po = stepUp["params"] ?: LinkedHashMap<String, Any?>()
        if (po !is Map<*, *>) throw range("ciba: step-up params must be an object")
        val params = po as Map<String, Any?>
        val unknown = params.keys.filter { it !in DISPLAYED_PARAM_KEYS }
        if (unknown.isNotEmpty())
            throw range("ciba: step-up params field(s) ${unknown.joinToString(", ")} are not displayed in the approval message (displayable: amount, currency, " +
                PAYEE_KEYS.joinToString("/") + "); refusing so the person never approves a hidden field")
        val action = Issue.obj("verb" to identifier(stepUp["verb"], "verb"), "resource" to identifier(stepUp["resource"], "resource"))
        val payeeKeys = PAYEE_KEYS.filter { params[it] != null }
        if (payeeKeys.size > 1) throw range("ciba: more than one payee field (${payeeKeys.joinToString(", ")}) in params; the approver would see only one")
        if (params["amount"] != null) {
            val amt = params["amount"]
            val d = if (amt is Boolean) null else Js.num(amt)
            val text = if (d != null && !d.isNaN() && !d.isInfinite()) Js.jsNumber(d) else amt as? String ?: ""
            if (!PLAIN_AMOUNT.matcher(text).matches()) throw range("ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)")
            val cur = params["currency"]
            if (cur !is String || !CURRENCY.matcher(cur).matches()) throw range("ciba: the binding message needs a 3-letter currency code next to the amount")
            if (payeeKeys.isEmpty()) throw range("ciba: an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it")
            action["amount"] = text
            action["currency"] = cur.uppercase(Locale.ROOT)
        } else if (params["currency"] != null) {
            throw range("ciba: a currency without an amount cannot be displayed")
        }
        if (payeeKeys.size == 1) {
            val out = Issue.obj("verb" to action["verb"])
            if (action.containsKey("amount")) { out["amount"] = action["amount"]; out["currency"] = action["currency"] }
            out["payee"] = payeeText(params[payeeKeys[0]])
            out["resource"] = action["resource"]
            return out
        }
        return action
    }

    // ---- the binding message ----
    private fun bindingMessage(stepUp: Map<String, Any?>, actsFor: String, maxChars: Double?): String {
        val a = cibaActionFromStepUp(stepUp)
        val head = StringBuilder("Approve ").append(a["verb"])
        if (a.containsKey("amount")) head.append(' ').append(a["amount"]).append(' ').append(a["currency"])
        if (a.containsKey("payee")) {
            val p = a["payee"] as String
            head.append(" to \"").append(p).append('"')
            if (!asciiPrintable(p, true)) head.append(" [non-ASCII name; ASCII form: ").append(asciiForm(p)).append(']')
        }
        head.append(" on ").append(a["resource"])
        val limit = maxChars ?: Double.POSITIVE_INFINITY
        val h = head.toString()
        if (cpLen(h) > limit)
            throw range("ciba: the binding message needs ${cpLen(h)} characters but bindingMessage.maxChars is ${Js.jsNumber(maxChars!!)}; refusing to truncate what the person approves")
        var plainGoal = ""
        if (stepUp.containsKey("goal")) {
            val g = stepUp["goal"] as? String ?: throw range("ciba: the step-up goal must be a string")
            plainGoal = plainText(g).replace('\'', '′').replace('‘', '′').replace('’', '′')
        }
        val goalText: String? = if (plainGoal.isNotEmpty()) clip(plainGoal, MAX_GOAL_CHARS.toDouble())
        else {
            val gc = stepUp["goalCommit"] ?: throw range("ciba: the step-up goalCommit is required")
            val s = gc as? String ?: ""
            if (s.isNotEmpty()) "goal " + s.substring(0, minOf(10, s.length)) + "…" else null
        }
        if (goalText == null) return h
        val prefix = " — because you asked $actsFor to '"
        val room = limit - cpLen(h + prefix) - 1
        if (room >= cpLen(goalText)) return "$h$prefix$goalText'"
        if (room >= 8) return h + prefix + clip(goalText, room) + "'"
        return h
    }

    private val NON_TOKEN = Regex("[^A-Za-z0-9._-]+")
    private val DASHES = Regex("-{2,}")
    private val EDGES = Regex("^[-.]+|[-.]+$")

    private fun tokenise(value: String): String = value.replace(NON_TOKEN, "-").replace(DASHES, "-").replace(EDGES, "")

    private fun compactBindingMessage(stepUp: Map<String, Any?>, maxChars: Double): String {
        val a = cibaActionFromStepUp(stepUp)
        if (a.containsKey("payee") && !asciiPrintable(a["payee"] as String, false))
            throw range("ciba: tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)")
        val parts = arrayListOf("Approve", a["verb"] as String)
        if (a.containsKey("amount")) { parts.add(a["amount"] as String); parts.add(a["currency"] as String) }
        if (a.containsKey("payee")) { parts.add("to"); parts.add(a["payee"] as String) }
        parts.add(a["resource"] as String)
        val toks = parts.map { tokenise(it) }
        if (toks.any { it.isEmpty() }) throw range("ciba: tokenOnly binding message cannot represent the verb, payee or resource")
        val out = toks.joinToString("-")
        if (out.length > maxChars)
            throw range("ciba: the binding message needs ${out.length} characters but bindingMessage.maxChars is ${Js.jsNumber(maxChars)}; refusing to truncate what the person approves")
        return out
    }

    // ---- the request ----
    /**
     * Map a PCA step-up to a CIBA auth request: `{auth_req_id, binding_message, scope, requested_expiry, interval, [login_hint,] stepUpId,
     * tier, [authorization_details, render_digest]}`. Pure: derives a stable `auth_req_id` from the step-up id unless `opts.authReqId` is
     * given, renders the binding message, and carries the scope, expiry and poll interval.
     */
    fun toCibaAuthRequest(stepUp: Map<String, Any?>, opts: Map<String, Any?>?): Map<String, Any?> {
        val o: Map<String, Any?> = opts ?: emptyMap()
        var actsFor = "your agent"
        if (o.containsKey("actsFor")) {
            val af = o["actsFor"] as? String ?: throw range("ciba: actsFor must be a string")
            val pt = plainText(af)
            if (pt.isNotEmpty()) actsFor = clip(pt, 40.0)
        }
        val requestedExpiry = if (o.containsKey("expiresInSec")) o["expiresInSec"] else Json.Num(DEFAULT_EXPIRY_SEC.toString())
        if (!Js.isSafeInteger(requestedExpiry) || Js.num(requestedExpiry)!! <= 0)
            throw range("ciba: requested_expiry must be a positive integer number of seconds, got ${Js.str(requestedExpiry)}")
        val stepUpScope = "urn:atlas:pca:stepup:" + Js.str(Js.get(stepUp, "verb"))
        for (c in stepUpScope) {
            if (!(c.code == 0x21 || c.code in 0x23..0x5b || c.code in 0x5d..0x7e)) throw range("ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)")
        }
        val scope = if (o["stepUpScope"] == false) "openid" else "openid $stepUpScope"
        val interval = if (o.containsKey("interval")) o["interval"] else Json.Num(DEFAULT_INTERVAL_SEC.toString())
        if (!Js.isSafeInteger(interval) || Js.num(interval)!! <= 0)
            throw range("ciba: interval must be a positive integer number of seconds, got ${Js.str(interval)}")
        val idO = o["authReqId"]
        if (idO == null && !stepUp.containsKey("id")) throw range("ciba: the step-up has no id to derive the auth_req_id from")
        // a non-string authReqId is tested as its text and kept as given: `.length` is undefined, so the length bounds never refuse it
        val authReqId: Any = idO ?: Pca.hashCanonical(Issue.obj("d" to "atlas-pca/ciba/auth_req_id/v1", "stepUp" to stepUp["id"]))
        val idText = if (authReqId is String) authReqId else Js.str(authReqId)
        if (!AUTH_REQ_ID.matcher(idText).matches() || (authReqId is String && (idText.length < MIN_AUTH_REQ_ID_LEN || idText.length > 1024)))
            throw range("ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)")
        val bm = o["bindingMessage"] as? Map<String, Any?>
        val hasMax = bm != null && bm.containsKey("maxChars")
        val bmMax = if (hasMax) bm!!["maxChars"] else null
        if (hasMax && (!Js.isSafeInteger(bmMax) || Js.num(bmMax)!! < 1)) throw range("ciba: bindingMessage.maxChars must be a positive integer")
        val maxChars = if (hasMax && bmMax != null) Js.num(bmMax)!! else 50.0
        var words: String? = null
        val render = stepUp["render"]
        val renderDigest = stepUp["renderDigest"]
        if (stepUp.containsKey("render") || stepUp.containsKey("renderDigest")) {
            if (!stepUp.containsKey("render") || !stepUp.containsKey("renderDigest") || Approval.renderDigest(render) != renderDigest)
                throw range("ciba: the step-up render and its digest do not agree; refusing to send an approval that commits to something else")
            words = Approval.bindingWords(renderDigest)
        }
        val reserve = if (words == null) 0 else words.length + 14
        val tokenOnly = bm != null && bm["tokenOnly"] == true
        var bindingMessage = if (tokenOnly) compactBindingMessage(stepUp, maxChars - reserve)
        else bindingMessage(stepUp, actsFor, if (hasMax) Js.num(bmMax)!! - reserve else null)
        if (words != null) bindingMessage = if (tokenOnly) "$bindingMessage-match-$words" else "$bindingMessage [match code $words]"
        val out = Issue.obj("auth_req_id" to authReqId, "binding_message" to bindingMessage, "scope" to scope, "requested_expiry" to requestedExpiry, "interval" to interval)
        if (o.containsKey("loginHint")) out["login_hint"] = o["loginHint"]
        if (stepUp.containsKey("id")) out["stepUpId"] = stepUp["id"]
        if (stepUp.containsKey("tier")) out["tier"] = stepUp["tier"]
        if (stepUp.containsKey("render") && stepUp.containsKey("renderDigest")) {
            out["authorization_details"] = arrayListOf<Any?>(Issue.obj("type" to "pca_approval", "render" to render, "render_digest" to renderDigest))
            out["render_digest"] = renderDigest
        }
        return out
    }

    // ---- gating and the hand-off to the cosign ----
    /** The gate: does this review need a CIBA human-approval round-trip? Only a tier-3 step-up does (tier-2 is the guardian's auto-cosign). */
    fun requiresCiba(review: Any?): Boolean {
        if (review == null) throw IllegalArgumentException("ciba: review is null")
        if (Js.member(review, "kind") != "step_up") return false
        val req = Js.member(review, "request") ?: throw IllegalArgumentException("ciba: the step_up review has no request")
        return Js.num(Js.member(req, "tier")) == 3.0
    }

    private fun nz(x: Any?): Double = Js.num(x)?.takeIf { !it.isNaN() && !it.isInfinite() && it > 0 } ?: 0.0

    /**
     * Fold a settled CIBA decision into PCA's trust budget `{B, tau, asOf?}`: on `approve`, recharge (partial rho per cosign, or full with
     * `opts.full`); on anything else the budget is unchanged. Returns `{budget, cosigned}`. This is the BUDGET-level effect only: the
     * cryptographic cosign that authorises a tier-3 action is a FROST threshold signature verified by the resource server.
     */
    fun cibaDecisionToCosign(decision: Any?, budget: Map<String, Any?>, policy: Map<String, Any?>, now: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        if (decision != "approve") return Issue.obj("budget" to budget, "cosigned" to false)
        val full = opts != null && Js.truthy(opts["full"])
        val bMax = nz(policy["bMax"])
        val b = if (full) bMax else minOf(bMax, Js.num(budget["B"])!! + nz(policy["rho"]))
        return Issue.obj("budget" to Issue.obj("B" to b, "tau" to now, "asOf" to now), "cosigned" to true)
    }
}
