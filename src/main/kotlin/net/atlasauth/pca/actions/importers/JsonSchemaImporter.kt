package net.atlasauth.pca.actions.importers

import net.atlasauth.pca.actions.importers.ImportCommon.Draft
import net.atlasauth.pca.actions.importers.ImportCommon.addTodo
import net.atlasauth.pca.actions.importers.ImportCommon.clip
import net.atlasauth.pca.actions.importers.ImportCommon.emitDef
import net.atlasauth.pca.actions.importers.ImportCommon.finish
import net.atlasauth.pca.actions.importers.ImportCommon.flattenObject
import net.atlasauth.pca.actions.importers.ImportCommon.newBudget
import net.atlasauth.pca.actions.importers.ImportCommon.newCtx
import net.atlasauth.pca.actions.importers.ImportCommon.resolveSchema
import net.atlasauth.pca.verifier.ActionKitError

/** "I have a function signature": one JSON Schema plus a verb the caller gives, to one def. */
object JsonSchemaImporter {
    private val EFFECTS = listOf("read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign")

    /** `opts`: the common import options plus `verb` (required, in the namespace), `title`, `description`, `effects` (default update). */
    fun importJsonSchema(schema: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        val c = newCtx("jsonschema", schema, opts)
        val verbO = opts!!["verb"]
        val ns = opts["ns"] as String
        if (verbO !is String || !ImportCommon.VERB_RE.matches(verbO) || !verbO.startsWith("$ns.")) throw ActionKitError("bad_verb", "verb must be a valid verb in namespace '$ns'")
        val verb: String = verbO
        val effO: Any? = if (opts["effects"] == null) Jx.list("update") else opts["effects"]
        if (effO !is List<*> || Jx.a(effO).isEmpty() || !Jx.a(effO).all { it is String && EFFECTS.contains(it) }) throw ActionKitError("bad_effects", "effects must be 1+ known effects")
        val effects = ArrayList<String>()
        for (e in Jx.a(effO)) effects.add(e as String)
        if (schema !is Map<*, *>) throw ActionKitError("bad_source", "a JSON Schema must be an object")
        val bud = newBudget(c)
        val root = resolveSchema(schema, c, bud, verb)
        val params = LinkedHashMap<String, Any?>()
        if ("object" == root["type"] || root["properties"] is Map<*, *>) flattenObject(root, c, bud, verb, params)
        else addTodo(c, verb, "not_object", "the schema is not an object schema: the def has no parameters")
        val d = Draft()
        val parts = verb.split(".")
        d.name = parts.subList(1, parts.size).joinToString("_")
        d.verb = verb
        d.title = if (opts["title"] != null) opts["title"] else if (root["title"] is String) root["title"] else null
        d.description = if (opts["description"] != null) opts["description"] else clip(root["description"], 600)
        d.effects = effects
        d.scope = "one"
        d.params = params
        d.bindings = LinkedHashMap()
        emitDef(c, d)
        return finish(c)
    }
}
