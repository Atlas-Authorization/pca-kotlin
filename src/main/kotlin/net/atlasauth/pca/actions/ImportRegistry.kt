package net.atlasauth.pca.actions

/** The import registry's output side: the YAML an `import` writes. */
object ImportRegistry {
    /**
     * The YAML an import writes: `{ns, actions: a list of defs}` with each def written in full form. `rules` (verb to a business-rules
     * value; may be null) re-attaches each action's rules block (the loader keeps rules apart from the def), so a rewrite (confirm, sync) never
     * drops them. The text is byte for byte what the reference's YAML writer produces (see `YamlEmit`), ending in a newline.
     */
    @JvmStatic
    @JvmOverloads
    fun defsToYaml(ns: String, defs: List<Map<String, Any?>>, rules: Map<String, Any?>? = null): String {
        val actions = ArrayList<Any?>()
        for (d in defs) {
            val verb = d["verb"]
            if (rules != null && verb is String && rules.containsKey(verb)) {
                val withRules = LinkedHashMap(d)
                withRules["rules"] = rules[verb]
                actions.add(withRules)
            } else actions.add(d)
        }
        val doc = LinkedHashMap<String, Any?>()
        doc["ns"] = ns
        doc["actions"] = actions
        return YamlEmit.stringify(doc)
    }
}
