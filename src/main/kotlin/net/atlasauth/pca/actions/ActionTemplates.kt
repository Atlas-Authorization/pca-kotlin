package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Json

/**
 * Starter packs a platform can begin from: typical actions of five business types in the authoring YAML form, with custom traits and business rules (and
 * their examples). Every action is an AUTHORED draft: a template never confirms anything. The namespace is the platform's choice (verbs, resource types
 * and custom trait ids are derived from it). The text is the reference's, embedded verbatim with the namespace substituted.
 */
object ActionTemplates {
    private val NS_RE = Regex("[a-z][a-z0-9_]{0,31}")

    private fun all(): MutableList<Any?> = J.a(Json.parse(ActionData.join(ActionData.TEMPLATES)))

    /** The namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved `pca`. */
    private fun checkNs(ns: Any?): String {
        if (ns !is String || !NS_RE.matches(ns)) throw ActionKitError("bad_ns", "ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)")
        if ("pca" == ns) throw ActionKitError("bad_ns", "the namespace 'pca' is reserved for core traits")
        return ns
    }

    private fun subst(v: Any?, ns: String): Any? {
        if (v is String) return v.replace(ActionData.PLACEHOLDER_NS, ns)
        if (v is List<*>) {
            val out = ArrayList<Any?>()
            for (x in v) out.add(subst(x, ns))
            return out
        }
        if (v is Map<*, *>) {
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in v) out[k as String] = subst(x, ns)
            return out
        }
        return v
    }

    /** The starter templates, as `{id, title, description, ns}` (use [traits] and [yaml] for the namespace-bound parts). */
    fun starterTemplates(): MutableList<Any?> {
        val out = ArrayList<Any?>()
        for (t in all()) out.add(J.obj("id", J.get(t, "id"), "title", J.get(t, "title"), "description", J.get(t, "description"), "ns", J.get(t, "ns")))
        return out
    }

    /** The starter template with this id, or null. */
    fun starterTemplate(id: String?): MutableMap<String, Any?>? {
        for (t in starterTemplates()) if (J.get(t, "id") == id) return J.m(t)
        return null
    }

    private fun raw(id: String?): Any? {
        for (t in all()) if (J.get(t, "id") == id) return t
        throw ActionKitError("unknown_template", "no starter template '$id'")
    }

    /** The pack's custom traits under namespace `ns` (ids `<ns>.<name>`). */
    fun traits(id: String?, ns: Any?): MutableList<Any?> {
        val n = checkNs(ns)
        return J.a(subst(J.get(raw(id), "traits"), n))
    }

    /** The authoring YAML under namespace `ns`, with `rules:` blocks and their examples. */
    fun yaml(id: String?, ns: Any?): String {
        val n = checkNs(ns)
        return (J.get(raw(id), "yaml") as String).replace(ActionData.PLACEHOLDER_NS, n)
    }
}
