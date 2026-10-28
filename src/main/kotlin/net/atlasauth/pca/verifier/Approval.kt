package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets

/**
 * What you see is what you sign (track K7): a port of the TypeScript `approval-render.ts` (render shape, H(R), the approval
 * challenge, the speakable match code) and the pca-actions `approval-render.ts` + `approval-profiles.ts` (the canonical render of an
 * action, the PSD2 RTS Art. 5 linking view, the batch commitment). A render that cannot be made completely throws [ActionKitError]
 * rather than returning something partial.
 */
@Suppress("UNCHECKED_CAST")
object Approval {
    const val RENDER_DOMAIN = "atlas-pca/approval-render/v1"
    const val CHALLENGE_DOMAIN = "atlas-pca/approval-challenge/v1\u0000"
    const val BATCH_DOMAIN = "atlas-pca/approval-batch/v1"
    private const val ITEM_DOMAIN = "atlas-pca/approval-batch-item/v1"
    private const val PAYEE_DOMAIN = "atlas-pca/approval-payee/v1"
    private const val MAX_FIELDS = 64
    private const val MAX_DEPTH = 3
    private const val MAX_SAFE = 9007199254740991L

    val WORDS: List<String> = listOf(
        "able", "acid", "aged", "also", "area", "army", "atom", "aunt",
        "away", "baby", "back", "ball", "band", "bank", "base", "bath",
        "bear", "beat", "beef", "bell", "belt", "bend", "bird", "blue",
        "boat", "body", "bold", "bone", "book", "boot", "born", "both",
        "bowl", "bulb", "burn", "bush", "busy", "cafe", "cake", "calm",
        "camp", "card", "care", "cart", "case", "cash", "cast", "cave",
        "cell", "chat", "chef", "chip", "city", "clay", "clip", "club",
        "coal", "coat", "code", "coin", "cold", "cook", "cool", "cope",
        "copy", "cord", "core", "cost", "crew", "crop", "dark", "data",
        "date", "dawn", "deal", "dear", "deck", "deep", "deer", "desk",
        "dial", "dice", "diet", "dish", "dive", "door", "dose", "down",
        "draw", "drop", "drum", "duck", "dust", "duty", "each", "earn",
        "east", "easy", "edge", "echo", "else", "even", "ever", "exit",
        "face", "fact", "fair", "fall", "farm", "fast", "fate", "fern",
        "file", "fill", "film", "find", "fine", "fire", "firm", "fish",
        "five", "flag", "flat", "flow", "foam", "fold", "folk", "food",
        "foot", "fork", "form", "fort", "four", "free", "frog", "fuel",
        "full", "fund", "gain", "game", "gate", "gear", "gift", "girl",
        "glad", "glow", "goat", "gold", "golf", "good", "grab", "gray",
        "grid", "grip", "grow", "gulf", "hair", "half", "hall", "hand",
        "hard", "harp", "hawk", "head", "heat", "help", "herb", "hill",
        "hint", "hold", "hole", "home", "hood", "hook", "hope", "horn",
        "host", "hour", "huge", "hunt", "idea", "inch", "iron", "isle",
        "item", "jade", "jazz", "join", "joke", "jump", "jury", "just",
        "keen", "keep", "kind", "king", "kite", "knee", "knot", "lake",
        "lamp", "land", "lane", "last", "late", "lawn", "lead", "leaf",
        "lean", "left", "lens", "less", "lift", "lime", "line", "link",
        "lion", "list", "live", "load", "loan", "lock", "logo", "long",
        "loop", "lord", "loud", "love", "luck", "lung", "made", "mail",
        "main", "mask", "mass", "mate", "meal", "melt", "menu", "mild",
        "milk", "mind", "mint", "mole", "moon", "more", "moss", "move",
        "much", "nail", "navy", "neat", "neck", "nest", "news", "nice",
    )

    private fun n(v: Long): Any? = IntentJs.ofLong(v)
    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = linkedMapOf(*kv)
    private fun digestOk(v: Any?): Boolean = v is String && Pca.decodeB64uStrict(v, 32) != null
    private fun bounded(v: Any?, max: Int): Boolean = v is String && v.isNotEmpty() && v.toByteArray(StandardCharsets.UTF_8).size <= max
    private fun lone(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) i++
            else if (Character.isSurrogate(c)) return true
            i++
        }
        return false
    }

    private fun closed(o: Map<String, Any?>, required: List<String>, optional: List<String>): String? {
        for (k in o.keys) if (k !in required && k !in optional) return "unknown member '$k'"
        for (k in required) if (!o.containsKey(k)) return "missing member '$k'"
        return null
    }

    /** Null if [r] is a well-formed render (closed members, sorted unique ids, bounded), else the reason. */
    fun renderShapeError(r: Any?): String? {
        if (r !is Map<*, *>) return "render must be an object"
        val o = r as Map<String, Any?>
        closed(o, listOf("v", "kind", "verb", "def_digest", "unreviewed", "fields"), emptyList())?.let { return it }
        if (!(IntentJs.isInt(o["v"]) && IntentJs.num(o["v"]) == 1.0) || o["kind"] != "pca-approval-render") return "not a pca-approval-render v1"
        if (!bounded(o["verb"], 128)) return "verb must be a bounded string"
        if (!digestOk(o["def_digest"])) return "def_digest must be canonical base64url (32 bytes)"
        if (o["unreviewed"] !is Boolean) return "unreviewed must be a boolean"
        val fs = o["fields"]
        if (fs !is List<*> || fs.size > MAX_FIELDS) return "fields must be an array of at most $MAX_FIELDS"
        var prev: String? = null
        for (fo in fs) {
            if (fo !is Map<*, *>) return "a field must be an object"
            val f = fo as Map<String, Any?>
            closed(f, listOf("id", "class", "value"), listOf("unit"))?.let { return it }
            if (!bounded(f["id"], 192) || !bounded(f["class"], 128)) return "field id and class must be bounded strings"
            val id = f["id"] as String
            if (prev != null && prev >= id) return "fields must be sorted by id and unique"
            prev = id
            if (f.containsKey("unit")) {
                val uo = f["unit"]
                if (uo !is Map<*, *>) return "unit must be an object"
                val u = uo as Map<String, Any?>
                if (u["kind"] == "money") {
                    if (closed(u, listOf("kind", "ccy", "exp"), emptyList()) != null || !bounded(u["ccy"], 16) || !IntentJs.isInt(u["exp"]) ||
                        IntentJs.num(u["exp"])!! < 0 || IntentJs.num(u["exp"])!! > 18) return "a money unit needs ccy and exp"
                } else if (u["kind"] !is String || u["kind"] !in listOf("count", "bytes", "duration", "ratio") || closed(u, listOf("kind"), emptyList()) != null) return "unknown unit"
            }
        }
        return null
    }

    /** H(R). A malformed render throws (a digest is never made over a shapeless value). */
    fun renderDigest(render: Any?): String {
        val e = renderShapeError(render)
        require(e == null) { "approvalRenderDigest: $e" }
        return Pca.hashCanonical(obj("d" to RENDER_DOMAIN, "render" to render))
    }

    /** b64u(SHA-256(domain || action_digest || H(R))); both digests must be canonical 32-byte values. */
    fun challenge(actionDigest: Any?, renderDigest: Any?): String {
        val a = if (actionDigest is String) Pca.decodeB64uStrict(actionDigest, 32) else null
        val r = if (renderDigest is String) Pca.decodeB64uStrict(renderDigest, 32) else null
        require(a != null && r != null) { "approvalChallenge: both digests must be canonical 32-byte values" }
        return Pca.b64(Pca.sha(CHALLENGE_DOMAIN.toByteArray(StandardCharsets.UTF_8), a, r))
    }

    fun bindingWords(renderDigest: Any?): String {
        val r = if (renderDigest is String) Pca.decodeB64uStrict(renderDigest, 32) else null
        require(r != null) { "bindingWords: render digest must be a canonical 32-byte value" }
        return (0 until 6).joinToString("-") { WORDS[r[it].toInt() and 0xff] }
    }

    // ---- the render ------------------------------------------------------------------------------------------------------

    private fun flatten(out: MutableMap<String, Any?>, prefix: String, depth: Int, v: Any?) {
        if (v is Map<*, *> && depth < MAX_DEPTH && v.isNotEmpty()) {
            for ((k, x) in v as Map<String, Any?>) {
                if (k.contains(".")) throw ActionKitError("render_bad_params", "the parameter key '$k' contains a dot")
                flatten(out, if (prefix.isEmpty()) k else "$prefix.$k", depth + 1, x)
            }
        } else out[prefix] = v
    }

    private fun leafOk(v: Any?): Boolean = when (v) {
        is String -> !lone(v)
        is Boolean -> true
        is List<*> -> v.all { leafOk(it) }
        else -> IntentJs.isInt(v)
    }

    private fun valueOk(type: String, v: Any?): Boolean = when (type) {
        "integer", "duration" -> IntentJs.isInt(v)
        "boolean" -> v is Boolean
        "string", "date", "datetime", "object_ref" -> v is String && !lone(v)
        "set", "array" -> v is List<*> && leafOk(v)
        else -> false
    }

    /**
     * The canonical approval render of [def] for [params]. [confirmed]: whether the definition carries a valid signed confirmation
     * (the caller decides, as for `effective`); an unconfirmed render carries `unreviewed: true`.
     */
    fun render(def: Map<String, Any?>, params: Any?, confirmed: Boolean = false): Map<String, Any?> {
        if (params !is Map<*, *>) throw ActionKitError("render_bad_params", "params must be an object")
        val norm = Actions.normalize(def)
        val np = norm["params"] as Map<String, Any?>
        val flat = LinkedHashMap<String, Any?>()
        for ((k, v) in params as Map<String, Any?>) {
            if (k.contains(".")) throw ActionKitError("render_bad_params", "the parameter key '$k' contains a dot")
            flatten(flat, k, 1, v)
        }
        for (k in flat.keys) if (!np.containsKey(k)) throw ActionKitError("render_undeclared_param", "'$k' is not a parameter of ${norm["verb"]}")
        for ((k, p) in np) if ((p as Map<String, Any?>)["required"] == true && !flat.containsKey(k)) throw ActionKitError("render_missing_param", "required parameter '$k' of ${norm["verb"]} is missing")
        val fields = ArrayList<Any?>()
        for (id in flat.keys.sorted()) {
            val p = np[id] as Map<String, Any?>
            if (!valueOk(p["type"] as String, flat[id])) throw ActionKitError("render_bad_value", "'$id' is not a ${p["type"]} in the canonical domain")
            val f = obj("id" to id, "class" to (if (p.containsKey("role")) p["role"] else "param"), "value" to flat[id])
            val u = p["unit"]
            if (u is Map<*, *>) {
                val um = u as Map<String, Any?>
                if (um["kind"] == "money") {
                    val c = um["ccy"]
                    val ccy = if (c is String) c else if (c is Map<*, *>) flat[(c as Map<String, Any?>)["from"].toString()] else null
                    if (ccy !is String || ccy.isEmpty()) throw ActionKitError("render_unresolved_currency", "the currency of '$id' is not a string")
                    f["unit"] = obj("kind" to "money", "ccy" to ccy, "exp" to um["exp"])
                } else f["unit"] = obj("kind" to um["kind"])
            }
            fields.add(f)
        }
        return obj("v" to n(1), "kind" to "pca-approval-render", "verb" to norm["verb"], "def_digest" to Actions.defDigest(def), "unreviewed" to !confirmed, "fields" to fields)
    }

    // ---- PSD2 RTS Art. 5 -------------------------------------------------------------------------------------------------

    private fun unlinkable(m: String) = ActionKitError("psd2_unlinkable", m)

    /** The amount and the payee of a payment render (Art. 5(1)). */
    fun psd2Linking(r: Map<String, Any?>): Map<String, Any?> {
        if (r["unreviewed"] == true) throw unlinkable("an unreviewed definition cannot be a payment approval")
        val fs = (r["fields"] as List<Any?>).map { it as Map<String, Any?> }
        val amts = fs.filter { it["class"] == "money.amount" }
        val payees = fs.filter { it["class"] == "party.payee" }
        if (amts.size != 1) throw unlinkable("a payment approval needs exactly one money.amount parameter")
        val a = amts[0]
        val u = a["unit"]
        if (u !is Map<*, *> || (u as Map<String, Any?>)["kind"] != "money") throw unlinkable("the money.amount parameter has no money unit")
        if (!IntentJs.isInt(a["value"]) || IntentJs.num(a["value"])!! < 0) throw unlinkable("the amount must be a non-negative integer in minor units")
        if (payees.size != 1 || payees[0]["value"] !is String || (payees[0]["value"] as String).isEmpty()) throw unlinkable("a payment approval needs exactly one non-empty party.payee parameter")
        val um = u as Map<String, Any?>
        return obj("amount_minor" to a["value"], "currency" to um["ccy"], "exp" to um["exp"], "payee" to payees[0]["value"])
    }

    /** Minor units as the decimal string of the major unit, without floating point. */
    fun minorToDecimal(minor: Long, exp: Long): String {
        if (minor < 0 || exp < 0 || exp > 18) throw unlinkable("minor units must be a non-negative safe integer")
        val s = minor.toString()
        if (exp == 0L) return s
        val p = s.padStart(exp.toInt() + 1, '0')
        return p.substring(0, p.length - exp.toInt()) + "." + p.substring(p.length - exp.toInt())
    }

    /** One approval over N payments: per-currency totals, the payee set and every item (Art. 5(3)(b)). Items are `{action_digest, render}`. */
    fun batch(items: List<Any?>): Map<String, Any?> {
        if (items.isEmpty()) throw unlinkable("a batch needs at least one payment")
        val totals = java.util.TreeMap<String, LongArray>()
        val payees = java.util.TreeSet<String>()
        val leaves = ArrayList<Any?>()
        for (io in items) {
            val it = io as Map<String, Any?>
            val link = psd2Linking(it["render"] as Map<String, Any?>)
            val ccy = link["currency"] as String
            val exp = IntentJs.lng(link["exp"])
            val amt = IntentJs.lng(link["amount_minor"])
            val t = totals[ccy]
            if (t != null && t[0] != exp) throw unlinkable("currency $ccy appears with two exponents")
            val minor = (t?.get(1) ?: 0L) + amt
            if (minor > MAX_SAFE) throw unlinkable("the batch total exceeds the safe integer range")
            totals[ccy] = longArrayOf(exp, minor)
            payees.add(link["payee"] as String)
            leaves.add(obj("d" to ITEM_DOMAIN, "a" to it["action_digest"], "r" to renderDigest(it["render"])))
        }
        val tl = ArrayList<Any?>(totals.entries.map { obj("ccy" to it.key, "exp" to n(it.value[0]), "minor" to n(it.value[1])) })
        val pl = ArrayList<Any?>(payees.map { obj("d" to PAYEE_DOMAIN, "payee" to it) })
        val batch = obj("v" to n(1), "kind" to "pca-approval-batch", "n" to n(items.size.toLong()), "totals" to tl, "payees_root" to Pca.merkleRoot(pl), "items_root" to Pca.merkleRoot(leaves))
        val rd = Pca.hashCanonical(obj("d" to BATCH_DOMAIN, "batch" to batch))
        return obj("batch" to batch, "action_digest" to batch["items_root"], "render_digest" to rd, "challenge" to challenge(batch["items_root"], rd), "words" to bindingWords(rd))
    }
}
