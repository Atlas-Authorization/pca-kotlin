package net.atlasauth.pca.actions.importers

import net.atlasauth.pca.actions.importers.ImportCommon.Budget
import net.atlasauth.pca.actions.importers.ImportCommon.Ctx
import net.atlasauth.pca.actions.importers.ImportCommon.Draft
import net.atlasauth.pca.actions.importers.ImportCommon.addTodo
import net.atlasauth.pca.actions.importers.ImportCommon.clip
import net.atlasauth.pca.actions.importers.ImportCommon.emitDef
import net.atlasauth.pca.actions.importers.ImportCommon.finish
import net.atlasauth.pca.actions.importers.ImportCommon.flattenObject
import net.atlasauth.pca.actions.importers.ImportCommon.newBudget
import net.atlasauth.pca.actions.importers.ImportCommon.newCtx
import net.atlasauth.pca.actions.importers.ImportCommon.paramSeg
import net.atlasauth.pca.actions.importers.ImportCommon.pointer
import net.atlasauth.pca.actions.importers.ImportCommon.resolveSchema
import net.atlasauth.pca.actions.importers.ImportCommon.verbOf
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Json

/**
 * AsyncAPI 2.x / 3.x to drafts. Sending to a channel is effect `send`, receiving is `read`; the message payload becomes the
 * params. A broker publish leaves the trust domain, so it stays `send` unless the channel carries the allow-listed `x-pca-internal: true`.
 */
object AsyncApiImporter {
    private val VERSION = Regex("^[23]\\.")

    private fun deref(c: Ctx, x: Any?, where: String, depth: Int = 0): Map<String, Any?>? {
        if (x !is Map<*, *>) return null
        val m = Jx.m(x)
        if (m["\$ref"] !is String) return m
        if (depth > c.lim.maxRefDepth) { addTodo(c, where, "ref_depth", "a reference chain is too deep"); return null }
        val t = pointer(c.root, m["\$ref"])
        if (t == null) { addTodo(c, where, "unresolved_ref", "reference '${clip(m["\$ref"], 120)}' does not resolve locally"); return null }
        return deref(c, t, where, depth + 1)
    }

    private fun payloadParams(c: Ctx, msgs: List<Any?>, where: String, params: MutableMap<String, Any?>, bud: Budget) {
        val resolved = ArrayList<Map<String, Any?>>()
        for (m in msgs) { val r = deref(c, m, where); if (r != null) resolved.add(r) }
        if (resolved.isEmpty()) return
        if (resolved.size > 1) addTodo(c, where, "message_variants", "${resolved.size} message variants: only the first is declared")
        val payload = Jx.getU(resolved[0], "payload")
        if (payload === Jx.UNDEF) return
        val s = resolveSchema(payload, c, bud, "$where: payload")
        if ("object" == s["type"] || s["properties"] is Map<*, *>) flattenObject(s, c, bud, where, params)
        else addTodo(c, where, "payload_shape", "the message payload is not an object schema; it is not declared")
    }

    private fun channelParams(c: Ctx, ch: Map<String, Any?>, where: String, params: MutableMap<String, Any?>) {
        val ps = deref(c, ch["parameters"], where) ?: return
        val names = ArrayList(ps.keys)
        names.sortWith { a, b -> Json.compareUtf8(a, b) }
        for (name in names) {
            val s = paramSeg(name)
            if (params.containsKey(s)) continue
            params[s] = Jx.obj("type", "string", "max_len", Jx.n(256))
        }
    }

    private fun emit(c: Ctx, source: Map<String, Any?>, ns: String, opName: String?, chName: String, ch: Map<String, Any?>, action: String, op: Map<String, Any?>, msgs: List<Any?>) {
        val where = action + " " + clip(chName, 100)
        val bud = newBudget(c)
        c.root = source
        val params = LinkedHashMap<String, Any?>()
        channelParams(c, ch, where, params)
        payloadParams(c, msgs, where, params, bud)
        val internal = c.ext.contains("x-pca-internal") && ch["x-pca-internal"] == true
        val d = Draft()
        d.name = opName ?: where
        d.noAlias = opName == null
        d.verb = if (opName == null) verbOf(ns, "$chName $action") else null
        d.title = if (op["summary"] is String) op["summary"] else null
        d.description = if (op["description"] is String) op["description"] else null
        d.effects = arrayListOf(if (action == "receive") "read" else if (internal) "create" else "send")
        d.scope = "one"
        d.params = params
        d.bindings = Jx.obj("asyncapi", Jx.obj("channel", clip(chName, 250), "op", action))
        emitDef(c, d)
    }

    fun importAsyncApi(source: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        val c = newCtx("asyncapi", source, opts)
        if (source !is Map<*, *> || Jx.m(source)["asyncapi"] !is String || !VERSION.containsMatchIn(Jx.m(source)["asyncapi"] as String))
            throw ActionKitError("bad_source", "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')")
        val src = Jx.m(source)
        val ns = opts!!["ns"] as String
        val v3 = (src["asyncapi"] as String).startsWith("3")
        val channels: Map<String, Any?> = if (src["channels"] is Map<*, *>) Jx.m(src["channels"]) else LinkedHashMap()
        if (v3) {
            val ops: Map<String, Any?> = if (src["operations"] is Map<*, *>) Jx.m(src["operations"]) else LinkedHashMap()
            val ids = ArrayList(ops.keys)
            ids.sortWith { a, b -> Json.compareUtf8(a, b) }
            for (id in ids) {
                val op = deref(c, ops[id], id)
                if (op == null || ("send" != op["action"] && "receive" != op["action"])) { addTodo(c, id, "skipped_op", "an operation without action send|receive is skipped"); continue }
                val chRef = deref(c, op["channel"], id) ?: continue
                val chName: String
                if (chRef["address"] is String) chName = chRef["address"] as String
                else if (op["channel"] is Map<*, *> && Jx.m(op["channel"])["\$ref"] is String) {
                    val p = (Jx.m(op["channel"])["\$ref"] as String).split("/")
                    chName = p[p.size - 1]
                } else chName = id
                val msgs: List<Any?>
                if (op["messages"] is List<*> && Jx.a(op["messages"]).isNotEmpty()) msgs = Jx.a(op["messages"])
                else if (chRef["messages"] is Map<*, *>) {
                    val cm = Jx.m(chRef["messages"])
                    val ks = ArrayList(cm.keys)
                    ks.sortWith { a, b -> Json.compareUtf8(a, b) }
                    val l = ArrayList<Any?>()
                    for (k in ks) l.add(cm[k])
                    msgs = l
                } else msgs = ArrayList()
                emit(c, src, ns, id, chName, chRef, op["action"] as String, op, msgs)
            }
        } else {
            val chNames = ArrayList(channels.keys)
            chNames.sortWith { a, b -> Json.compareUtf8(a, b) }
            for (chName in chNames) {
                val ch = deref(c, channels[chName], chName) ?: continue
                // 2.x: publish is what a client does to the channel (a send); subscribe is what a client receives
                for (ka in listOf(arrayOf("publish", "send"), arrayOf("subscribe", "receive"))) {
                    val op = deref(c, ch[ka[0]], chName) ?: continue
                    val m = deref(c, op["message"], chName)
                    val msgs: List<Any?> = if (m != null && m["oneOf"] is List<*>) Jx.a(m["oneOf"]) else if (m != null) Jx.list(m) else ArrayList()
                    val oid = if (op["operationId"] is String && (op["operationId"] as String).isNotEmpty()) op["operationId"] as String else null
                    emit(c, src, ns, oid, chName, ch, ka[1], op, msgs)
                }
            }
        }
        return finish(c)
    }
}
