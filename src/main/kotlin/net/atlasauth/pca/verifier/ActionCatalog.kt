package net.atlasauth.pca.verifier

/**
 * The connector action catalog over JSON action specs (catalog.ts): what the facade resolves a `permissions` shorthand against. A spec
 * is `{connector, action, verb, reversibility, blastRadius, description, amountField?, resource?, aliases?, traits?}`; members this
 * SDK does not know are carried as they are. This is data, not enforcement: the resource server's verifier stays authoritative.
 *
 * An unknown verb never passes as harmless: [resolveAction] answers it with the most cautious class ([uncataloguedSpec]). A host pins
 * the catalog it reviewed with [catalogDigest] / [assertCatalogPinned], and [extendCatalog] refuses an entry that would make an
 * existing verb less cautious. [Catalog] is the typed view of the same built-in rows.
 */
@Suppress("UNCHECKED_CAST")
object ActionCatalog {
    /** Rough blast-radius bands used by the built-in entries. */
    @JvmField
    val BLAST: Map<String, Double> =
        linkedMapOf("read" to 0.05, "reversibleWrite" to 0.2, "rateLimitedWrite" to 0.5, "irreversibleWrite" to 0.8, "moneyMovement" to 0.9)

    private val REVERSIBILITY_ORDER = listOf("reversible", "rate_limited", "irreversible")
    private val SPACE_OR_DOT = Regex("[\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff.]")
    private val NO_VERB = Any()

    private fun rec(x: Any?): Map<String, Any?>? = x as? Map<String, Any?>

    private fun json(s: Catalog.Spec): Map<String, Any?> {
        val o = linkedMapOf<String, Any?>(
            "connector" to s.connector, "action" to s.action, "verb" to s.verb, "reversibility" to s.reversibility, "blastRadius" to StoreJs.num(s.blastRadius),
        )
        if (s.amountField != null) o["amountField"] = s.amountField
        if (s.resource != null) o["resource"] = s.resource
        o["description"] = s.description
        if (s.aliases.isNotEmpty()) o["aliases"] = ArrayList<Any?>(s.aliases)
        o["traits"] = ArrayList<Any?>(s.traits)
        return o
    }

    /** The built-in action specs (the reference's 21 rows, generated from the reviewed action definitions). */
    @JvmField
    val BUILTIN_ACTIONS: List<Map<String, Any?>> = Catalog.BUILTIN.map { json(it) }

    /**
     * A checked action spec: `connector` and `action` are required (the connector without whitespace or a dot), `reversibility` is
     * `reversible` / `rate_limited` / `irreversible`, `blastRadius` is in [0, 1], `amountField` (when present) is a non-empty string.
     * `verb` defaults to `connector.action`; every other member is kept. Throws IllegalArgumentException on anything else.
     */
    fun defineAction(spec: Any?): Map<String, Any?> {
        val s = rec(spec)
        val connector = s?.get("connector") as? String
        val action = s?.get("action") as? String
        if (s == null || connector.isNullOrEmpty() || action.isNullOrEmpty()) throw IllegalArgumentException("defineAction: connector and action are required")
        if (SPACE_OR_DOT.containsMatchIn(connector)) throw IllegalArgumentException("defineAction: connector must not contain whitespace or a dot")
        if (s.containsKey("amountField") && (s["amountField"] as? String).isNullOrEmpty()) {
            throw IllegalArgumentException("defineAction: amountField must be a non-empty string")
        }
        if (s["reversibility"] !is String || s["reversibility"] as String !in REVERSIBILITY_ORDER) {
            throw IllegalArgumentException("defineAction: bad reversibility '${IntentRevocation.jsText(s["reversibility"], s.containsKey("reversibility"))}'")
        }
        val blast = IntentJs.num(s["blastRadius"])
        if (blast == null || !(blast >= 0 && blast <= 1)) throw IllegalArgumentException("defineAction: blastRadius must be in [0,1]")
        return LinkedHashMap(s).also { it["verb"] = s["verb"] ?: "$connector.$action" }
    }

    /** A catalog: action specs by verb, in the order the verbs first appeared (a later spec with the same verb replaces the earlier one in place). */
    class View internal constructor(actions: List<Any?>) {
        private val byVerb = LinkedHashMap<Any?, Map<String, Any?>>()

        init {
            for (a in actions) {
                val spec = a as? Map<String, Any?> ?: throw IllegalArgumentException("buildCatalog: an action is not an object")
                byVerb[if (spec.containsKey("verb")) spec["verb"] else NO_VERB] = spec
            }
        }

        /** The spec of a verb (`connector.action`), or null. */
        fun get(verb: Any?): Map<String, Any?>? = byVerb[verb]

        fun forConnector(connector: Any?): List<Map<String, Any?>> = byVerb.values.filter { it["connector"] == connector }

        fun all(): List<Map<String, Any?>> = ArrayList(byVerb.values)

        /** The exact verb `connector.action`, else the one action of `connector` that lists `action` as an alias (never a guess: two hits are none). */
        fun resolve(connector: Any?, action: Any?): Map<String, Any?>? {
            byVerb[IntentRevocation.jsText(connector, connector != null) + "." + IntentRevocation.jsText(action, action != null)]?.let { return it }
            val hits = byVerb.values.filter { it["connector"] == connector && (it["aliases"] as? List<Any?>)?.contains(action) == true }
            return if (hits.size == 1) hits[0] else null
        }
    }

    /** A catalog of `actions` (null = the built-in ones). The specs are taken as they are: check them with [defineAction] first. */
    @JvmOverloads
    fun buildCatalog(actions: List<Any?>? = null): View = View(actions ?: BUILTIN_ACTIONS)

    /** The catalog of the built-in actions. */
    @JvmField
    val DEFAULT_CATALOG: View = buildCatalog()

    /** The fail-closed spec of a verb no catalog knows: irreversible, blast radius 1. The connector is the text before the first dot, the action the rest (or the verb). */
    fun uncataloguedSpec(verb: String): Map<String, Any?> {
        val dot = verb.indexOf('.')
        val rest = if (dot < 0) "" else verb.substring(dot + 1)
        return linkedMapOf(
            "connector" to (if (dot < 0) verb else verb.substring(0, dot)), "action" to (if (rest.isEmpty()) verb else rest), "verb" to verb,
            "reversibility" to "irreversible", "blastRadius" to StoreJs.num(1L), "description" to "(uncatalogued) $verb",
        )
    }

    /** `{spec, catalogued}` for a verb: a catalogued verb returns its entry, any other the most cautious class. Never "no risk" for an unknown verb. */
    fun resolveAction(catalog: View, verb: String): Map<String, Any?> {
        val spec = catalog.get(verb)
        return if (spec != null) linkedMapOf("spec" to spec, "catalogued" to true) else linkedMapOf("spec" to uncataloguedSpec(verb), "catalogued" to false)
    }

    /** Content digest of a catalog (its specs sorted by verb, strict canonical JSON): pin it in config to detect drift. Throws on a spec that cannot be hashed. */
    fun catalogDigest(catalog: View): String = Pca.hashCanonical(
        catalog.all().sortedWith { a, b ->
            val x = a["verb"] as? String
            val y = b["verb"] as? String
            if (x == null || y == null) 0 else x.compareTo(y) // UTF-16 code unit order, as the reference compares
        },
    )

    /** Throws IllegalStateException unless the catalog matches the digest the host pinned. */
    fun assertCatalogPinned(catalog: View, expected: Any?) {
        if (catalogDigest(catalog) != expected) throw IllegalStateException("catalog does not match the pinned digest")
    }

    /**
     * The catalog with `extra` added. An extra spec may add a verb or make an existing one more cautious; it throws
     * IllegalArgumentException when it would lower an existing verb's reversibility class or blast radius.
     */
    fun extendCatalog(base: View, extra: List<Any?>): View {
        for (eO in extra) {
            val e = rec(eO) ?: throw IllegalArgumentException("extendCatalog: an action is not an object")
            val old = base.get(if (e.containsKey("verb")) e["verb"] else NO_VERB) ?: continue
            val lowerBlast = (IntentJs.num(e["blastRadius"]) ?: Double.NaN) < (IntentJs.num(old["blastRadius"]) ?: Double.NaN)
            if (REVERSIBILITY_ORDER.indexOf(e["reversibility"]) < REVERSIBILITY_ORDER.indexOf(old["reversibility"]) || lowerBlast) {
                throw IllegalArgumentException("extendCatalog: '${e["verb"]}' would be less cautious than the existing entry")
            }
        }
        return View(base.all() + extra)
    }
}
