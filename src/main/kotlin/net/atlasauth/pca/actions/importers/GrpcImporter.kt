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
import net.atlasauth.pca.actions.importers.ImportCommon.putProp
import net.atlasauth.pca.actions.importers.ImportCommon.withTrait
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json

/**
 * Protobuf services to drafts, from `.proto` text or a binary FileDescriptorSet. `service.method` becomes the verb;
 * `google.api.http` gives method and path; `idempotency_level` gives read / idempotent; field behavior refines params;
 * streaming methods get `pca.bulk`. Offline, bounded; the descriptor wire format is read by hand (no protobuf dependency).
 */
@Suppress("UNCHECKED_CAST")
object GrpcImporter {
    // ---- model ----

    class PField {
        @JvmField var name: String = ""
        @JvmField var type: String = ""
        @JvmField var scope: String = ""
        @JvmField var repeated: Boolean = false
        @JvmField var optional: Boolean = false
        @JvmField var map: Array<String>? = null
        @JvmField var behavior: MutableList<String> = ArrayList()
        internal fun toJson(): MutableMap<String, Any?> {
            val m = Jx.obj("name", name, "type", type, "scope", scope, "repeated", repeated, "optional", optional)
            val mp = map
            if (mp != null) m["map"] = Jx.list(mp[0], mp[1])
            m["behavior"] = ArrayList<Any?>(behavior)
            return m
        }
    }

    class PMsg {
        @JvmField var full: String = ""
        @JvmField var fields: MutableList<PField> = ArrayList()
        @JvmField var mapEntry: Boolean = false
    }

    class PEnum {
        @JvmField var full: String = ""
        @JvmField var values: MutableList<String> = ArrayList()
    }

    class PHttp {
        @JvmField var method: String? = null
        @JvmField var path: String? = null
        @JvmField var body: String? = null
    }

    class PMethod {
        @JvmField var name: String = ""
        @JvmField var input: String = ""
        @JvmField var output: String = ""
        @JvmField var scope: String = ""
        @JvmField var idem: String? = null
        @JvmField var cs: Boolean = false
        @JvmField var ss: Boolean = false
        @JvmField var http: PHttp? = null
    }

    class PService {
        @JvmField var full: String = ""
        @JvmField var name: String = ""
        @JvmField var methods: MutableList<PMethod> = ArrayList()
    }

    class ProtoModel {
        @JvmField val messages: MutableMap<String, PMsg> = LinkedHashMap()
        @JvmField val enums: MutableMap<String, PEnum> = LinkedHashMap()
        @JvmField val services: MutableList<PService> = ArrayList()

        /** `{messages: [[full, {...}]...], enums: [[full, [values]]...], services: [{...}]}`. */
        fun toJson(): MutableMap<String, Any?> {
            val ms = ArrayList<Any?>()
            for (m in messages.values) {
                val fs = ArrayList<Any?>()
                for (f in m.fields) fs.add(f.toJson())
                ms.add(Jx.list(m.full, Jx.obj("full", m.full, "fields", fs, "mapEntry", m.mapEntry)))
            }
            val es = ArrayList<Any?>()
            for (e in enums.values) es.add(Jx.list(e.full, ArrayList<Any?>(e.values)))
            val ss = ArrayList<Any?>()
            for (s in services) {
                val mm = ArrayList<Any?>()
                for (x in s.methods) {
                    val o = Jx.obj("name", x.name, "input", x.input, "output", x.output, "cs", x.cs, "ss", x.ss, "scope", x.scope)
                    val hx = x.http
                    if (hx != null) {
                        val h = Jx.obj("method", hx.method, "path", hx.path)
                        if (hx.body != null) h["body"] = hx.body
                        o["http"] = h
                    }
                    if (x.idem != null) o["idem"] = x.idem
                    mm.add(o)
                }
                ss.add(Jx.obj("full", s.full, "name", s.name, "methods", mm))
            }
            return Jx.obj("messages", ms, "enums", es, "services", ss)
        }
    }

    private val SCALAR_NAMES = setOf("double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes")

    // ---- .proto text ----

    private class Tok(@JvmField val t: String, @JvmField val v: String)

    private fun idStart(c: Char): Boolean = (c in 'A'..'Z') || (c in 'a'..'z') || c == '_' || c == '.'
    private fun idChar(c: Char): Boolean = idStart(c) || (c in '0'..'9')
    private fun numChar(c: Char): Boolean = c == '-' || c == '+' || c == '.' || (c in '0'..'9') || (c in 'A'..'Z') || (c in 'a'..'z')

    private fun lex(src: String, maxTokens: Int): List<Tok> {
        val out = ArrayList<Tok>()
        val n = src.length
        var i = 0
        while (i < n) {
            val ch = src[i]
            val push: Tok
            if (Jx.jsSpace(ch)) { i++; continue }
            if (src.startsWith("//", i)) { while (i < n && src[i] != '\n') i++; continue }
            if (src.startsWith("/*", i)) {
                val j = src.indexOf("*/", i + 2)
                if (j < 0) throw ActionKitError("bad_source", "unterminated comment in proto source")
                i = j + 2
                continue
            }
            if (ch == '"' || ch == '\'') {
                var j = i + 1
                val s = StringBuilder()
                while (j < n && src[j] != ch) {
                    if (src[j] == '\n') throw ActionKitError("bad_source", "unterminated string in proto source")
                    if (src[j] == '\\') { if (j + 1 < n) s.append(src[j + 1]); j += 2 } else s.append(src[j++])
                }
                if (j >= n) throw ActionKitError("bad_source", "unterminated string in proto source")
                push = Tok("str", s.toString())
                i = j + 1
            } else if (idStart(ch)) {
                var j = i + 1
                while (j < n && idChar(src[j])) j++
                push = Tok("id", src.substring(i, j))
                i = j
            } else if (ch == '-' || (ch in '0'..'9')) {
                var j = i + 1
                while (j < n && numChar(src[j])) j++
                push = Tok("num", src.substring(i, j))
                i = j
            } else if ("{}[]()<>=;,:".indexOf(ch) >= 0) { push = Tok("p", ch.toString()); i++ }
            else throw ActionKitError("bad_source", "unexpected character in proto source at offset $i")
            if (out.size >= maxTokens) throw ActionKitError("import_limit", "the proto source has too many tokens")
            out.add(push)
        }
        return out
    }

    private val UPPER_WORD = Regex("[A-Z_]+")
    private val HTTP_VERBS = listOf("get", "put", "post", "delete", "patch")

    private class PP(val toks: List<Tok>, val m: ProtoModel, val maxDepth: Int) {
        var i = 0
        var pkg = ""

        fun cur(): Tok? = if (i < toks.size) toks[i] else null
        fun isV(v: String): Boolean { val t = cur(); return t != null && "str" != t.t && t.v == v }
        fun eat(v: String): Boolean { if (isV(v)) { i++; return true }; return false }
        fun fail(msg: String): ActionKitError = ActionKitError("bad_source", "proto parse error: $msg near '${clip(cur()?.v ?: "<end>", 30)}'")
        fun expect(v: String) { if (!eat(v)) throw fail("expected '$v'") }
        fun id(): String { val t = cur(); if (t == null || "id" != t.t) throw fail("expected an identifier"); i++; return t.v }

        /** Skip to the matching close of an already-opened bracket. */
        fun skipTo(open: String, close: String) {
            var depth = 1
            while (depth > 0) {
                val t = if (i < toks.size) toks[i] else null
                i++
                if (t == null) throw fail("unterminated block")
                if ("p" == t.t) { if (t.v == open) depth++ else if (t.v == close) depth-- }
            }
        }

        fun skipStatement() {
            while (cur() != null && !isV(";")) {
                if (isV("{")) { i++; skipTo("{", "}"); return }
                i++
            }
            eat(";")
        }

        fun file() {
            while (cur() != null) {
                if (eat(";")) continue
                val kw = id()
                if (kw == "package") { pkg = id(); expect(";") }
                else if (kw == "message") message(pkg, 0)
                else if (kw == "enum") enumDef(pkg)
                else if (kw == "service") service()
                else if (kw == "extend") { id(); expect("{"); skipTo("{", "}") }
                else skipStatement()
            }
        }

        fun qual(scope: String, name: String): String = if (scope.isEmpty()) name else "$scope.$name"

        fun enumDef(scope: String) {
            val name = id()
            val full = qual(scope, name)
            expect("{")
            val values = ArrayList<String>()
            while (!isV("}")) {
                if (cur() == null) throw fail("unterminated enum")
                if (isV("option") || isV("reserved")) { skipStatement(); continue }
                values.add(id())
                skipStatement()
            }
            expect("}")
            val e = PEnum()
            e.full = full
            e.values = values
            m.enums[full] = e
        }

        /** Field options: collect `field_behavior` names; everything else is skipped. */
        fun fieldOptions(): MutableList<String> {
            val behavior = ArrayList<String>()
            if (!eat("[")) return behavior
            var depth = 1
            var inBehavior = false
            while (depth > 0) {
                val t = if (i < toks.size) toks[i] else null
                i++
                if (t == null) throw fail("unterminated field options")
                if ("p" == t.t) {
                    if (t.v == "[" || t.v == "{") depth++
                    else if (t.v == "]" || t.v == "}") depth--
                    else if (t.v == ",") inBehavior = false
                } else if ("id" == t.t) {
                    if (t.v.endsWith("field_behavior")) inBehavior = true
                    else if (inBehavior && UPPER_WORD.matches(t.v)) behavior.add(t.v)
                }
            }
            return behavior
        }

        fun field(msg: PMsg, full: String, label: String?, oneof: Boolean) {
            var repeated = "repeated" == label
            var type = id()
            var map: Array<String>? = null
            if (type == "map" && eat("<")) { val k = id(); expect(","); val v = id(); expect(">"); map = arrayOf(k, v); type = "map"; repeated = false }
            val fname = id()
            expect("=")
            i++ // field number
            val behavior = fieldOptions()
            expect(";")
            val f = PField()
            f.name = fname; f.type = type; f.scope = full; f.repeated = repeated; f.optional = "optional" == label || oneof; f.map = map; f.behavior = behavior
            msg.fields.add(f)
        }

        fun message(scope: String, depth: Int) {
            if (depth > maxDepth) throw ActionKitError("import_limit", "proto message nesting is too deep")
            val name = id()
            val full = qual(scope, name)
            val msg = PMsg()
            msg.full = full
            m.messages[full] = msg
            expect("{")
            while (!isV("}")) {
                val ct = cur() ?: throw fail("unterminated message")
                if (eat(";")) continue
                val kw = if ("id" == ct.t) ct.v else ""
                if (kw == "message") { i++; message(full, depth + 1); continue }
                if (kw == "enum") { i++; enumDef(full); continue }
                if (kw == "oneof") {
                    i++; id(); expect("{")
                    while (!isV("}")) {
                        if (cur() == null) throw fail("unterminated oneof")
                        if (isV("option")) { skipStatement(); continue }
                        field(msg, full, null, true)
                    }
                    expect("}")
                    continue
                }
                if (kw == "option" || kw == "reserved" || kw == "extensions") { skipStatement(); continue }
                if (kw == "extend") { i++; id(); expect("{"); skipTo("{", "}"); continue }
                if (kw == "group") { skipStatement(); continue }
                if (kw == "repeated" || kw == "optional" || kw == "required") { i++; field(msg, full, kw, false); continue }
                field(msg, full, null, false)
            }
            expect("}")
        }

        fun streamKw(): Boolean { val t = cur(); if (t != null && t.v == "stream" && "id" == t.t) { i++; return true }; return false }

        fun service() {
            val name = id()
            val full = qual(pkg, name)
            val svc = PService()
            svc.full = full
            svc.name = name
            expect("{")
            while (!isV("}")) {
                if (cur() == null) throw fail("unterminated service")
                if (eat(";")) continue
                val kw = id()
                if (kw != "rpc") { skipStatement(); continue }
                val mname = id()
                expect("(")
                val cs = streamKw()
                val input = id()
                expect(")")
                if (id() != "returns") throw fail("expected 'returns'")
                expect("(")
                val ss = streamKw()
                val output = id()
                expect(")")
                val me = PMethod()
                me.name = mname; me.input = input; me.output = output; me.cs = cs; me.ss = ss; me.scope = pkg
                if (eat("{")) {
                    while (!isV("}")) {
                        if (cur() == null) throw fail("unterminated rpc body")
                        if (!isV("option")) { skipStatement(); continue }
                        i++
                        val oname: String
                        if (eat("(")) { oname = id(); expect(")") } else oname = id()
                        expect("=")
                        if (isV("{")) {
                            i++
                            var depth = 1
                            while (depth > 0) {
                                val t = if (i < toks.size) toks[i] else null
                                i++
                                if (t == null) throw fail("unterminated option")
                                if ("p" == t.t) { if (t.v == "{") depth++ else if (t.v == "}") depth--; continue }
                                if (depth == 1 && oname.endsWith("http") && "id" == t.t && HTTP_VERBS.contains(t.v) && isV(":")) {
                                    i++
                                    val c1 = cur()
                                    val path = if (c1 != null && "str" == c1.t) c1.v else ""
                                    i++
                                    if (me.http == null) { val h = PHttp(); h.method = t.v.uppercase(); h.path = path; me.http = h }
                                } else if (depth == 1 && oname.endsWith("http") && "id" == t.t && t.v == "body" && isV(":")) {
                                    i++
                                    val c1 = cur()
                                    val h = me.http
                                    if (c1 != null && "str" == c1.t && h != null) h.body = c1.v
                                    i++
                                }
                            }
                            eat(";")
                        } else {
                            val v = cur()
                            i++
                            if (oname.endsWith("idempotency_level") && v != null) me.idem = v.v
                            eat(";")
                        }
                    }
                    expect("}")
                    eat(";")
                } else expect(";")
                svc.methods.add(me)
            }
            expect("}")
            m.services.add(svc)
        }
    }

    @JvmStatic
    fun parseProto(src: String): ProtoModel = parseProto(src, 2_000_000)

    @JvmStatic
    fun parseProto(src: String, maxTokens: Int): ProtoModel {
        val m = ProtoModel()
        PP(lex(src, maxTokens), m, 32).file()
        return m
    }

    // ---- binary descriptor set ----

    private class Reader(val b: ByteArray, var p: Int, val end: Int) {
        fun more(): Boolean = p < end

        fun varint(): Double {
            var r = 0.0
            var mul = 1.0
            for (k in 0 until 10) {
                if (p >= end) throw ActionKitError("bad_source", "truncated descriptor")
                val by = b[p++].toInt() and 0xff
                r += (by and 0x7f) * mul
                if ((by and 0x80) == 0) return r
                mul *= 128
            }
            throw ActionKitError("bad_source", "overlong varint in descriptor")
        }

        fun len(): Reader {
            val n = varint()
            if (n > end - p) throw ActionKitError("bad_source", "descriptor length exceeds the buffer")
            val r = Reader(b, p, p + n.toInt())
            p += n.toInt()
            return r
        }

        fun skip(wt: Double) {
            if (wt == 0.0) varint()
            else if (wt == 1.0) adv(8)
            else if (wt == 2.0) len()
            else if (wt == 5.0) adv(4)
            else throw ActionKitError("bad_source", "unsupported wire type ${AttestUtil.jsNumString(wt)} in descriptor")
        }

        fun adv(n: Int) { if (n > end - p) throw ActionKitError("bad_source", "truncated descriptor"); p += n }
        fun str(): String { val r = len(); return decodeUtf8(b, r.p, r.end) }
    }

    /** TextDecoder('utf-8') without fatal: maximal-subpart replacement, and a leading byte order mark is dropped. */
    internal fun decodeUtf8(b: ByteArray, from: Int, to: Int): String {
        val out = StringBuilder()
        var cp = 0
        var needed = 0
        var seen = 0
        var lower = 0x80
        var upper = 0xBF
        var i = from
        while (i < to) {
            val by = b[i].toInt() and 0xff
            if (needed == 0) {
                if (by <= 0x7F) out.append(by.toChar())
                else if (by in 0xC2..0xDF) { needed = 1; cp = by and 0x1F }
                else if (by in 0xE0..0xEF) { if (by == 0xE0) lower = 0xA0; if (by == 0xED) upper = 0x9F; needed = 2; cp = by and 0xF }
                else if (by in 0xF0..0xF4) { if (by == 0xF0) lower = 0x90; if (by == 0xF4) upper = 0x8F; needed = 3; cp = by and 7 }
                else out.append('�')
            } else {
                if (by < lower || by > upper) { cp = 0; needed = 0; seen = 0; lower = 0x80; upper = 0xBF; out.append('�'); continue }
                lower = 0x80; upper = 0xBF
                cp = (cp shl 6) or (by and 0x3F)
                if (++seen == needed) { out.appendCodePoint(cp); cp = 0; needed = 0; seen = 0 }
            }
            i++
        }
        if (needed != 0) out.append('�')
        return if (out.isNotEmpty() && out[0] == '﻿') out.substring(1) else out.toString()
    }

    private val FTYPES: Array<String?> = arrayOfNulls<String>(19).also {
        val names = arrayOf("double", "float", "int64", "uint64", "int32", "fixed64", "fixed32", "bool", "string")
        for (i in names.indices) it[i + 1] = names[i]
        it[12] = "bytes"; it[13] = "uint32"; it[15] = "sfixed32"; it[16] = "sfixed64"; it[17] = "sint32"; it[18] = "sint64"
    }

    private class Tag(@JvmField val f: Double, @JvmField val wt: Double)

    private fun tag(r: Reader): Tag { val t = r.varint(); return Tag(Math.floor(t / 8), t % 8) }

    private class FieldDesc {
        var name = ""
        var typeName = ""
        var type = 0.0
        var label = 1.0
        var proto3opt = false
        val behavior = ArrayList<Double>()
    }

    private fun readEnum(m: ProtoModel, r: Reader, scope: String) {
        var name = ""
        val values = ArrayList<String>()
        while (r.more()) {
            val g = tag(r)
            if (g.f == 1.0 && g.wt == 2.0) name = r.str()
            else if (g.f == 2.0 && g.wt == 2.0) {
                val v = r.len()
                while (v.more()) { val vg = tag(v); if (vg.f == 1.0 && vg.wt == 2.0) values.add(v.str()) else v.skip(vg.wt) }
            } else r.skip(g.wt)
        }
        val full = if (scope.isEmpty()) name else "$scope.$name"
        val e = PEnum()
        e.full = full
        e.values = values
        m.enums[full] = e
    }

    private fun behaviorName(b: Double): String = if (b == 2.0) "REQUIRED" else if (b == 3.0) "OUTPUT_ONLY" else if (b == 4.0) "INPUT_ONLY" else if (b == 5.0) "IMMUTABLE" else ""

    private fun readMsg(m: ProtoModel, r: Reader, scope: String, depth: Int) {
        if (depth > 32) throw ActionKitError("import_limit", "descriptor message nesting is too deep")
        var name = ""
        val fields = ArrayList<FieldDesc>()
        val nested = ArrayList<Reader>()
        val enums = ArrayList<Reader>()
        var mapEntry = false
        while (r.more()) {
            val g = tag(r)
            if (g.f == 1.0 && g.wt == 2.0) name = r.str()
            else if (g.f == 2.0 && g.wt == 2.0) {
                val fr = r.len()
                val fd = FieldDesc()
                while (fr.more()) {
                    val fg = tag(fr)
                    if (fg.f == 1.0 && fg.wt == 2.0) fd.name = fr.str()
                    else if (fg.f == 4.0 && fg.wt == 0.0) fd.label = fr.varint()
                    else if (fg.f == 5.0 && fg.wt == 0.0) fd.type = fr.varint()
                    else if (fg.f == 6.0 && fg.wt == 2.0) fd.typeName = fr.str()
                    else if (fg.f == 17.0 && fg.wt == 0.0) fd.proto3opt = fr.varint() == 1.0
                    else if (fg.f == 8.0 && fg.wt == 2.0) {
                        val o = fr.len()
                        while (o.more()) {
                            val og = tag(o)
                            if (og.f == 1052.0 && og.wt == 0.0) fd.behavior.add(o.varint())
                            else if (og.f == 1052.0 && og.wt == 2.0) { val pk = o.len(); while (pk.more()) fd.behavior.add(pk.varint()) }
                            else o.skip(og.wt)
                        }
                    } else fr.skip(fg.wt)
                }
                fields.add(fd)
            } else if (g.f == 3.0 && g.wt == 2.0) nested.add(r.len())
            else if (g.f == 4.0 && g.wt == 2.0) enums.add(r.len())
            else if (g.f == 7.0 && g.wt == 2.0) {
                val o = r.len()
                while (o.more()) { val og = tag(o); if (og.f == 7.0 && og.wt == 0.0) mapEntry = o.varint() == 1.0 else o.skip(og.wt) }
            } else r.skip(g.wt)
        }
        val full = if (scope.isEmpty()) name else "$scope.$name"
        val msg = PMsg()
        msg.full = full
        msg.mapEntry = mapEntry
        for (f in fields) {
            val pf = PField()
            pf.name = f.name; pf.scope = full; pf.repeated = f.label == 3.0; pf.optional = f.proto3opt
            pf.type = if (f.typeName.isNotEmpty()) f.typeName else (if (f.type >= 1 && f.type <= 18 && f.type == Math.rint(f.type) && FTYPES[f.type.toInt()] != null) FTYPES[f.type.toInt()]!! else "bytes")
            for (b in f.behavior) pf.behavior.add(behaviorName(b))
            msg.fields.add(pf)
        }
        m.messages[full] = msg
        for (n in nested) readMsg(m, n, full, depth + 1)
        for (e in enums) readEnum(m, e, full)
    }

    @JvmStatic
    fun parseDescriptorSet(bytes: ByteArray): ProtoModel {
        val m = ProtoModel()
        val top = Reader(bytes, 0, bytes.size)
        while (top.more()) {
            val g = tag(top)
            if (g.f != 1.0 || g.wt != 2.0) { top.skip(g.wt); continue }
            val fr = top.len()
            var pkg = ""
            val msgs = ArrayList<Reader>()
            val enums = ArrayList<Reader>()
            val svcs = ArrayList<Reader>()
            // package may follow the messages in the wire order: collect first, then resolve scopes
            while (fr.more()) {
                val fg = tag(fr)
                if (fg.f == 2.0 && fg.wt == 2.0) pkg = fr.str()
                else if (fg.f == 4.0 && fg.wt == 2.0) msgs.add(fr.len())
                else if (fg.f == 5.0 && fg.wt == 2.0) enums.add(fr.len())
                else if (fg.f == 6.0 && fg.wt == 2.0) svcs.add(fr.len())
                else fr.skip(fg.wt)
            }
            for (r in msgs) readMsg(m, r, pkg, 0)
            for (r in enums) readEnum(m, r, pkg)
            for (r in svcs) {
                var name = ""
                val methods = ArrayList<PMethod>()
                while (r.more()) {
                    val sg = tag(r)
                    if (sg.f == 1.0 && sg.wt == 2.0) name = r.str()
                    else if (sg.f == 2.0 && sg.wt == 2.0) {
                        val mr = r.len()
                        val me = PMethod()
                        me.scope = pkg
                        while (mr.more()) {
                            val mg = tag(mr)
                            if (mg.f == 1.0 && mg.wt == 2.0) me.name = mr.str()
                            else if (mg.f == 2.0 && mg.wt == 2.0) me.input = mr.str()
                            else if (mg.f == 3.0 && mg.wt == 2.0) me.output = mr.str()
                            else if (mg.f == 5.0 && mg.wt == 0.0) me.cs = mr.varint() == 1.0
                            else if (mg.f == 6.0 && mg.wt == 0.0) me.ss = mr.varint() == 1.0
                            else if (mg.f == 4.0 && mg.wt == 2.0) {
                                val o = mr.len()
                                while (o.more()) {
                                    val og = tag(o)
                                    if (og.f == 34.0 && og.wt == 0.0) { val lv = o.varint(); me.idem = if (lv == 1.0) "NO_SIDE_EFFECTS" else if (lv == 2.0) "IDEMPOTENT" else "IDEMPOTENCY_UNKNOWN" }
                                    else if (og.f == 72295728.0 && og.wt == 2.0) {
                                        val h = o.len()
                                        while (h.more()) {
                                            val hg = tag(h)
                                            val verb: String? = if (hg.f == 2.0) "GET" else if (hg.f == 3.0) "PUT" else if (hg.f == 4.0) "POST" else if (hg.f == 5.0) "DELETE" else if (hg.f == 6.0) "PATCH" else null
                                            if (verb != null && hg.wt == 2.0) {
                                                if (me.http == null) { val hh = PHttp(); hh.method = verb; hh.path = h.str(); me.http = hh } else h.str()
                                            } else if (hg.f == 7.0 && hg.wt == 2.0) { val bd = h.str(); val hh = me.http; if (hh != null) hh.body = bd }
                                            else h.skip(hg.wt)
                                        }
                                    } else o.skip(og.wt)
                                }
                            } else mr.skip(mg.wt)
                        }
                        methods.add(me)
                    } else r.skip(sg.wt)
                }
                val s = PService()
                s.full = if (pkg.isEmpty()) name else "$pkg.$name"
                s.name = name
                s.methods = methods
                m.services.add(s)
            }
        }
        return m
    }

    // ---- model to params ----

    private fun resolveName(m: ProtoModel, name: String, scope: String): String? {
        if (name.startsWith(".")) return name.substring(1)
        val parts: List<String> = if (scope.isEmpty()) emptyList() else scope.split(".")
        for (k in parts.size downTo 0) {
            val cand = StringBuilder()
            for (j in 0 until k) cand.append(parts[j]).append('.')
            cand.append(name)
            val cs = cand.toString()
            if (m.messages.containsKey(cs) || m.enums.containsKey(cs)) return cs
        }
        return if (m.messages.containsKey(name) || m.enums.containsKey(name)) name else null
    }

    private val WKT_STRING = setOf("google.protobuf.StringValue", "google.protobuf.BytesValue")
    private val WKT_INT = setOf("google.protobuf.Int32Value", "google.protobuf.Int64Value", "google.protobuf.UInt32Value", "google.protobuf.UInt64Value")

    private fun one(m: ProtoModel, type: String, scope: String, c: Ctx, stack: List<String>, where: String, budget: IntArray): MutableMap<String, Any?> {
        if (SCALAR_NAMES.contains(type)) {
            if (type.contains("int") || type.contains("fixed")) return Jx.obj("type", "integer", "format", "int64")
            if (type == "bool") return Jx.obj("type", "boolean")
            if (type == "string") return Jx.obj("type", "string")
            if (type == "bytes") return Jx.obj("type", "string")
            return Jx.obj("type", "number")
        }
        val abs: String? = if (type.startsWith(".")) type.substring(1) else null
        val eff = abs ?: type
        if ("google.protobuf.Timestamp" == abs || type == "google.protobuf.Timestamp") return Jx.obj("type", "string", "format", "date-time")
        if (WKT_STRING.contains(eff)) return Jx.obj("type", "string")
        if (WKT_INT.contains(eff)) return Jx.obj("type", "integer", "format", "int64")
        if (eff == "google.protobuf.BoolValue") return Jx.obj("type", "boolean")
        if (eff.startsWith("google.protobuf.")) return LinkedHashMap()
        val full = resolveName(m, type, scope)
        if (full == null) { addTodo(c, where, "unknown_type", "type '${clip(type, 60)}' is not defined in the proto source (declared string)"); return LinkedHashMap() }
        val en = m.enums[full]
        if (en != null) return Jx.obj("type", "string", "enum", ArrayList<Any?>(LinkedHashSet(en.values)))
        return msgSchema(m, full, c, stack, where, budget)
    }

    private fun fieldSchema(m: ProtoModel, f: PField, c: Ctx, stack: List<String>, where: String, budget: IntArray): MutableMap<String, Any?> {
        if (f.map != null) return Jx.obj("type", "object")
        val s = one(m, f.type, f.scope, c, stack, where, budget)
        return if (f.repeated) Jx.obj("type", "array", "items", s) else s
    }

    private fun msgSchema(m: ProtoModel, full: String, c: Ctx, stack: List<String>, where: String, budget: IntArray): MutableMap<String, Any?> {
        val msg = m.messages[full] ?: return LinkedHashMap()
        if (stack.contains(full)) { addTodo(c, where, "cyclic_ref", "message '${clip(full, 80)}' is recursive (declared string; refine or drop)"); return LinkedHashMap() }
        if (stack.size > c.lim.maxRefDepth || run { budget[0] -= 1; budget[0] <= 0 }) { addTodo(c, where, "ref_budget", "message expansion stopped at the bound (declared string; refine or drop)"); return LinkedHashMap() }
        val properties = LinkedHashMap<String, Any?>()
        val required = ArrayList<Any?>()
        val ns = ArrayList(stack)
        ns.add(full)
        for (f in msg.fields) {
            if (f.behavior.contains("OUTPUT_ONLY")) continue
            putProp(properties, f.name, fieldSchema(m, f, c, ns, where + "." + f.name, budget))
            if (f.behavior.contains("REQUIRED")) required.add(f.name)
        }
        return Jx.obj("type", "object", "properties", properties, "required", required)
    }

    @JvmStatic
    fun importGrpc(source: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        val c = newCtx("grpc", source, opts)
        val m: ProtoModel = if (source is String) parseProto(source)
        else if (source is ByteArray) parseDescriptorSet(source)
        else throw ActionKitError("bad_source", "a gRPC source is .proto text or a binary FileDescriptorSet")
        val svcs = ArrayList(m.services)
        svcs.sortWith { a, b -> Json.compareUtf8(a.full, b.full) }
        for (svc in svcs) {
            val ms = ArrayList(svc.methods)
            ms.sortWith { a, b -> Json.compareUtf8(a.name, b.name) }
            for (me in ms) {
                val where = svc.name + "/" + me.name
                c.root = null
                val bud: Budget = newBudget(c)
                val rn = resolveName(m, me.input, me.scope)
                val input = rn ?: (if (me.input.startsWith(".")) me.input.substring(1) else me.input)
                val schema = msgSchema(m, input, c, ArrayList(), where, intArrayOf(c.lim.maxRefNodes.toInt()))
                val params = LinkedHashMap<String, Any?>()
                if (schema["properties"] != null) flattenObject(schema, c, bud, where, params)
                else if (!m.messages.containsKey(input) && !input.startsWith("google.protobuf.")) addTodo(c, where, "unknown_type", "request type '${clip(me.input, 60)}' is not defined in the source (no parameters)")
                val hx = me.http
                val hm: String? = hx?.method
                val eff = if ("GET" == hm) "read" else if ("DELETE" == hm) "delete" else if ("POST" == hm) "create" else if ("PUT" == hm || "PATCH" == hm) "update" else if ("NO_SIDE_EFFECTS" == me.idem) "read" else "update"
                val natural = "NO_SIDE_EFFECTS" == me.idem || "IDEMPOTENT" == me.idem || "GET" == hm || "PUT" == hm || "DELETE" == hm
                var traits: List<String>? = null
                if (me.cs || me.ss) { traits = withTrait(traits, "pca.bulk"); addTodo(c, where, "streaming", "a streaming method: acts on many messages (pca.bulk added)") }
                val d = Draft()
                d.name = svc.name + " " + me.name
                d.title = camelSplit(me.name)
                d.effects = listOf(eff)
                d.scope = "one"
                d.params = params
                if (natural) d.idempotency = Jx.obj("mode", "natural")
                if (traits != null) d.traits = traits
                val b = Jx.obj("grpc", Jx.obj("service", clip(svc.full, 250), "method", clip(me.name, 250)))
                if (hx != null && hx.path != null && hx.path!!.isNotEmpty()) b["http"] = Jx.obj("method", hx.method, "path", clip(hx.path, 250))
                d.bindings = b
                emitDef(c, d)
            }
        }
        return finish(c)
    }

    private val CAMEL = Regex("([a-z0-9])([A-Z])")

    private fun camelSplit(s: String): String = CAMEL.replace(s, "\$1 \$2")
}
