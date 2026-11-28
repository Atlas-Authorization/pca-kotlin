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
import net.atlasauth.pca.actions.importers.ImportCommon.withTrait
import net.atlasauth.pca.verifier.ActionKitError

/**
 * MCP `tools/list` to drafts. The annotations are hints from the tool's own server and are untrusted: they can only add
 * restriction (destructive, network egress) or describe a harmless-looking shape; every output is `unreviewed`.
 */
object McpImporter {
    /** `tools/list` result `{tools: [...]}`, or the tool array itself. */
    fun importMcp(source: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        val c = newCtx("mcp", source, opts)
        val tools: List<Any?>? = if (source is List<*>) Jx.a(source) else if (source is Map<*, *> && Jx.m(source)["tools"] is List<*>) Jx.a(Jx.m(source)["tools"]) else null
        if (tools == null) throw ActionKitError("bad_source", "an MCP source is a tool array or a tools/list result {tools: [...]}")
        val seen = HashSet<String>()
        for (raw in tools) {
            if (raw !is Map<*, *> || Jx.m(raw)["name"] !is String || (Jx.m(raw)["name"] as String).isEmpty() || (Jx.m(raw)["name"] as String).length > 256) {
                addTodo(c, "(tool)", "skipped_op", "an entry without a usable name is skipped")
                continue
            }
            val t = Jx.m(raw)
            val name = t["name"] as String
            if (seen.contains(name)) { addTodo(c, name, "duplicate_tool", "a tool name listed twice; the first is kept"); continue }
            seen.add(name)
            c.root = t["inputSchema"]
            val bud = newBudget(c)
            val input = resolveSchema(t["inputSchema"], c, bud, "$name: inputSchema")
            val params = LinkedHashMap<String, Any?>()
            flattenObject(input, c, bud, name, params)
            val a: Map<String, Any?> = if (t["annotations"] is Map<*, *>) Jx.m(t["annotations"]) else LinkedHashMap()
            // readOnly claims safety, so it is honoured only when nothing contradicts it
            val read = a["readOnlyHint"] == true && a["destructiveHint"] != true
            val effects = if (read) listOf("read") else if (a["destructiveHint"] == true) listOf("update", "delete") else listOf("update")
            val d = Draft()
            d.name = name
            d.title = if (a["title"] is String && (a["title"] as String).isNotEmpty()) a["title"] else t["title"]
            d.description = t["description"]
            d.effects = ArrayList(effects)
            d.scope = "one"
            d.params = params
            if (a["idempotentHint"] == true) d.idempotency = Jx.obj("mode", "natural")
            if (a["openWorldHint"] == true) d.traits = withTrait(null, "pca.network_egress")
            d.bindings = Jx.obj("mcp", Jx.obj("tool", clip(name, 256)))
            emitDef(c, d)
        }
        return finish(c)
    }
}
