package net.atlasauth.pca.actions.importers

import java.math.BigDecimal
import java.math.RoundingMode
import java.util.TreeSet
import net.atlasauth.pca.actions.ActionEffective
import net.atlasauth.pca.intent.IntentStats
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Json

/**
 * Measure the suggestion rules against a labeled corpus. Every corpus entry is turned into a source document of its own kind, run through the
 * REAL importer and the REAL suggestion engine, and the traits the system flags are compared with the labels. Precision and recall per trait,
 * with an exact Clopper-Pearson bound on each. These are heuristic numbers on a reviewed corpus, published as what they are, never as a safety
 * guarantee. Entries, reports and floors are JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object ImportEval {
    @JvmField val LABEL_SHORT: Map<String, String> = linkedMapOf(
        "money" to "money_moving", "destr" to "destructive", "comm" to "external_communication", "priv" to "privilege_change", "exp" to "data_export", "exec" to "code_execution",
        "cred" to "credential_access", "bulk" to "bulk", "pii" to "pii_access", "pub" to "public_exposure", "pers" to "persistence", "infra" to "infra_mutation", "cost" to "cost_incurring",
        "legal" to "legal_binding", "imp" to "impersonation", "egress" to "network_egress", "fin" to "financial_data_read", "reg" to "regulated_data", "sched" to "scheduled", "spawn" to "agent_spawning",
    )

    private fun splitList(s: String, sep: String): MutableList<Any?> {
        val out = ArrayList<Any?>()
        for (x in s.split(sep)) out.add(x)
        return out
    }

    private fun pad4(n: Int): String { val s = n.toString(); return "0".repeat(Math.max(0, 4 - s.length)) + s }

    /** The hand-labeled TSV: `kind, name, location, params, labels, description` per line. Throws on a short line or an unknown label. */
    fun parseHandTsv(text: String): List<Any?> {
        val out = ArrayList<Any?>()
        var n = 0
        for (line in text.split("\n")) {
            if (Jx.jsTrim(line).isEmpty() || line.startsWith("#")) continue
            val c = line.split("\t")
            if (c.size < 6) throw IllegalArgumentException("hand corpus line needs 6 columns: " + (if (line.length > 80) line.substring(0, 80) else line))
            val kind = c[0]
            val name = c[1]
            val loc = c[2]
            val params = c[3]
            val labels = c[4]
            val description = c[5]
            val e = LinkedHashMap<String, Any?>()
            e["id"] = "hand-" + pad4(++n)
            e["src"] = "hand"
            e["kind"] = kind
            e["name"] = name
            e["params"] = if (params == "-") ArrayList<Any?>() else splitList(params, ",")
            val ls = ArrayList<Any?>()
            if (labels != "-") for (l in splitList(labels, ",")) ls.add(if (LABEL_SHORT.containsKey(l)) LABEL_SHORT[l] else l)
            e["labels"] = ls
            e["description"] = description
            if (kind == "openapi") {
                val sp = loc.indexOf(' ')
                e["method"] = if (sp < 0) loc else loc.substring(0, sp)
                e["path"] = if (sp < 0) "" else loc.substring(sp + 1)
            }
            for (l in ls) if (!LABEL_SHORT.containsValue(l)) throw IllegalArgumentException("unknown label '$l' in $name")
            out.add(e)
        }
        return out
    }

    /** One JSON entry per non-blank line. */
    fun parseCorpusJsonl(text: String): List<Any?> {
        val out = ArrayList<Any?>()
        for (l in text.split("\n")) if (Jx.jsTrim(l).isNotEmpty()) out.add(Json.parseLenient(l))
        return out
    }

    // ---- entries to source documents ----

    private val SPEC_RE = Regex("^[^:]+:([a-z]+)(?::(.+))?\\z")
    private val TYPE_RE = Regex("^[^:]+:([a-z]+)")

    private fun schemaOf(spec: String): MutableMap<String, Any?> {
        val m = SPEC_RE.find(spec)
        var type: String? = null
        var format: String? = null
        if (m != null) { type = m.groupValues[1]; format = m.groups[2]?.value }
        if ("array" == type) return Jx.obj("type", "array", "items", Jx.obj("type", "string"))
        val o = Jx.obj("type", if ("number" == type) "number" else (type ?: "string"))
        if (format != null && format.isNotEmpty()) o["format"] = format
        return o
    }

    /** `spec.slice(0, spec.indexOf(':'))`: with no colon the slice drops the last character. */
    private fun pname(spec: String): String {
        val i = spec.indexOf(':')
        val end = if (i < 0) spec.length - 1 else i
        return if (end <= 0) "" else spec.substring(0, end)
    }

    private val READ_FIRST: Set<String> = linkedSetOf(
        "get", "list", "find", "search", "count", "describe", "show", "lookup", "check", "validate", "preview", "calculate", "estimate",
        "convert", "format", "compare", "summarize", "sort", "filter", "read", "fetch", "query", "view", "browse", "open",
    )
    private val FIRST_WORD = Regex("^[A-Za-z][a-z0-9]*")
    private val PLURAL = Regex("[a-z]+s?")
    private val PATH_PARAM = Regex("\\{([^}]+)\\}")

    private fun firstWord(n: String): String = (FIRST_WORD.find(n)?.value ?: n).lowercase()

    private fun strs(o: Any?): List<String> { val out = ArrayList<String>(); for (x in Jx.a(o)) out.add(x as String); return out }

    private fun openapiDoc(es: List<Map<String, Any?>>): Any? {
        val paths = LinkedHashMap<String, Any?>()
        for (e in es) {
            val method = (if (e["method"] != null) e["method"] as String else "get").lowercase()
            val body = listOf("post", "put", "patch").contains(method)
            val props = LinkedHashMap<String, Any?>()
            val ps = strs(e["params"])
            for (p in ps) ImportCommon.putProp(props, pname(p), schemaOf(p))
            val pathParams = ArrayList<Any?>()
            val ppNames = ArrayList<String>()
            for (pm in PATH_PARAM.findAll(if (e["path"] != null) e["path"] as String else "")) {
                ppNames.add(pm.groupValues[1])
                pathParams.add(Jx.obj("name", pm.groupValues[1], "in", "path", "required", true, "schema", Jx.obj("type", "string")))
            }
            val op = LinkedHashMap<String, Any?>()
            if (Jx.truthy(e["name"])) op["operationId"] = e["name"]
            if (Jx.truthy(e["description"])) op["summary"] = e["description"]
            val parameters = ArrayList<Any?>(pathParams)
            if (!body) for (p in ps) if (!ppNames.contains(pname(p))) parameters.add(Jx.obj("name", pname(p), "in", "query", "schema", schemaOf(p)))
            op["parameters"] = parameters
            if (body && ps.isNotEmpty()) {
                op["requestBody"] = Jx.obj("content", Jx.obj("application/json", Jx.obj("schema", Jx.obj("type", "object", "properties", props, "required", ArrayList<Any?>()))))
            }
            val path = e["path"] as String
            val item = Jx.m(paths.getOrPut(path) { LinkedHashMap<String, Any?>() })
            item[method] = op
        }
        return Jx.obj("openapi", "3.0.3", "info", Jx.obj("title", "corpus", "version", "1"), "paths", paths)
    }

    private fun gqlType(spec: String): String {
        val t = TYPE_RE.find(spec)?.groupValues?.get(1) ?: "string"
        return when (t) { "string" -> "String"; "integer" -> "Int"; "boolean" -> "Boolean"; "array" -> "[String]"; else -> "String" }
    }

    private fun graphqlSdl(es: List<Map<String, Any?>>): String {
        val q = ArrayList<String>()
        val m = ArrayList<String>()
        for (e in es) {
            val name = e["name"] as String
            val ps = strs(e["params"])
            var args = ""
            if (ps.isNotEmpty()) { val a = ArrayList<String>(); for (p in ps) a.add(pname(p) + ": " + gqlType(p)); args = "(" + a.joinToString(", ") + ")" }
            (if (READ_FIRST.contains(firstWord(name)) || PLURAL.matches(name)) q else m).add("  \"" + (e["description"] as String).replace("\"", "'") + "\"\n  " + name + args + ": String")
        }
        return (if (q.isEmpty()) "" else "type Query {\n" + q.joinToString("\n") + "\n}\n") + (if (m.isEmpty()) "" else "type Mutation {\n" + m.joinToString("\n") + "\n}\n")
    }

    private fun protoType(spec: String): String {
        val t = TYPE_RE.find(spec)?.groupValues?.get(1) ?: "string"
        return when (t) { "string" -> "string"; "integer" -> "int64"; "boolean" -> "bool"; "array" -> "repeated string"; else -> "string" }
    }

    private fun protoText(es: List<Map<String, Any?>>): String {
        val svcs = LinkedHashMap<String, MutableList<Map<String, Any?>>>()
        for (e in es) svcs.getOrPut((e["name"] as String).split("/")[0]) { ArrayList() }.add(e)
        val msgs = arrayListOf("message Empty {}")
        val out = ArrayList<String>()
        for ((svc, list) in svcs) {
            val rpcs = ArrayList<String>()
            for (e in list) {
                val parts = (e["name"] as String).split("/")
                val mname = if (parts.size > 1) parts[1] else "undefined"
                val ps = strs(e["params"])
                val fs = ArrayList<String>()
                for (i in ps.indices) fs.add("  " + protoType(ps[i]) + " " + pname(ps[i]) + " = " + (i + 1) + ";")
                msgs.add("message " + mname + "Request {\n" + fs.joinToString("\n") + "\n}")
                rpcs.add("  rpc $mname(${mname}Request) returns (Empty);")
            }
            out.add("service " + svc + " {\n" + rpcs.joinToString("\n") + "\n}")
        }
        return "syntax = \"proto3\";\npackage corpus;\n" + msgs.joinToString("\n") + "\n" + out.joinToString("\n") + "\n"
    }

    private fun asyncDoc(es: List<Map<String, Any?>>): Any? {
        val channels = LinkedHashMap<String, Any?>()
        for (e in es) {
            val props = LinkedHashMap<String, Any?>()
            for (p in strs(e["params"])) ImportCommon.putProp(props, pname(p), schemaOf(p))
            channels[e["name"] as String] = Jx.obj("publish", Jx.obj("summary", e["description"], "message", Jx.obj("payload", Jx.obj("type", "object", "properties", props))))
        }
        return Jx.obj("asyncapi", "2.6.0", "info", Jx.obj("title", "corpus", "version", "1"), "channels", channels)
    }

    private fun mcpDoc(es: List<Map<String, Any?>>): Any? {
        val out = ArrayList<Any?>()
        for (e in es) {
            val props = LinkedHashMap<String, Any?>()
            for (p in strs(e["params"])) ImportCommon.putProp(props, pname(p), schemaOf(p))
            out.add(Jx.obj("name", e["name"], "description", e["description"], "inputSchema", Jx.obj("type", "object", "properties", props)))
        }
        return out
    }

    private fun keyOf(e: Map<String, Any?>): String =
        if ("openapi" == e["kind"]) (if (e["method"] != null) Jx.jsStr(e["method"]).uppercase() else "GET") + " " + Jx.jsStr(e["path"]) else Jx.jsStr(e["name"])

    private fun defKey(d: Map<String, Any?>): String {
        val b = d["bindings"]
        val oa = Jx.get(b, "openapi")
        if (Jx.truthy(Jx.get(oa, "path"))) return Jx.jsStr(Jx.get(oa, "method")) + " " + Jx.jsStr(Jx.get(oa, "path"))
        if (Jx.get(oa, "operationId") != null) return Jx.jsStr(Jx.get(oa, "operationId"))
        if (Jx.get(Jx.get(b, "mcp"), "tool") != null) return Jx.jsStr(Jx.get(Jx.get(b, "mcp"), "tool"))
        if (Jx.get(Jx.get(b, "graphql"), "field") != null) return Jx.jsStr(Jx.get(Jx.get(b, "graphql"), "field"))
        val g = Jx.get(b, "grpc")
        if (Jx.truthy(g)) { val sv = Jx.jsStr(Jx.get(g, "service")).split("."); return sv[sv.size - 1] + "/" + Jx.jsStr(Jx.get(g, "method")) }
        if (Jx.get(Jx.get(b, "asyncapi"), "channel") != null) return Jx.jsStr(Jx.get(Jx.get(b, "asyncapi"), "channel"))
        return ""
    }

    /** Import every entry with the real importer of its kind. Returns `{defs: {id: def}, todo: n}` (an entry whose def was not emitted is absent). */
    fun importCorpus(entries: List<Any?>): Map<String, Any?> {
        val defs = LinkedHashMap<String, Any?>()
        var todo = 0L
        val groups = LinkedHashMap<String, MutableList<Map<String, Any?>>>()
        for (eo in entries) {
            val e = Jx.m(eo)
            val g = Jx.jsStr(e["kind"]) + "|" + (if (e["spec"] != null) Jx.jsStr(e["spec"]) else "")
            groups.getOrPut(g) { ArrayList() }.add(e)
        }
        val opts = Jx.obj("ns", "corpus", "limits", Jx.obj("max_ops", Jx.n(50_000), "max_nodes", Jx.n(20_000_000), "max_bytes", Jx.n(200_000_000)))
        for ((gk, es) in groups) {
            val kind = gk.split("|")[0]
            val src: Any? = if (kind == "openapi") openapiDoc(es) else if (kind == "mcp") mcpDoc(es) else if (kind == "graphql") graphqlSdl(es) else if (kind == "grpc") protoText(es) else asyncDoc(es)
            val r = ImportPipeline.importActions(kind, src, opts)
            todo += Jx.a(r["todo"]).size
            val byKey = LinkedHashMap<String, Any?>()
            for (d in Jx.a(r["defs"])) byKey[defKey(Jx.m(d))] = d
            for (e in es) { val d = byKey[keyOf(e)]; if (d != null) defs[e["id"] as String] = d }
        }
        return Jx.obj("defs", defs, "todo", Jx.n(todo))
    }

    // ---- scoring ----

    /** Deterministic split of the real corpus by specification: rules are tuned on `tune` specs only; `holdout` specs are never looked at when editing rules. */
    fun realSplit(spec: Any?): String {
        val s = if (spec == null) "" else Jx.jsStr(spec)
        var h = 2166136261L
        var i = 0
        while (i < s.length) {
            val code = s[i].code // charCodeAt(0) of the code point: its first UTF-16 unit
            i += Character.charCount(s.codePointAt(i))
            val x = h.toInt() xor code // ToInt32(h) ^ code
            h = (x * 16777619).toLong() and 0xFFFFFFFFL // Math.imul, then >>> 0
        }
        return if (((h ushr 7) % 2L) == 0L) "tune" else "holdout"
    }

    private fun sourceOf(e: Map<String, Any?>): String = if ("real" == e["src"]) "real/" + realSplit(e["spec"]) else Jx.jsStr(e["src"])

    private fun stat(trait: String, rows: List<BooleanArray>, alpha: Double): Map<String, Any?> {
        var tp = 0
        var fp = 0
        var fn = 0
        for (r in rows) { if (r[0] && r[1]) tp++ else if (r[1]) fp++ else if (r[0]) fn++ }
        val pos = tp + fn
        val pred = tp + fp
        val o = LinkedHashMap<String, Any?>()
        o["trait"] = trait
        o["positives"] = Jx.n(pos.toLong())
        o["predicted"] = Jx.n(pred.toLong())
        o["tp"] = Jx.n(tp.toLong())
        o["fp"] = Jx.n(fp.toLong())
        o["fn"] = Jx.n(fn.toLong())
        o["precision"] = if (pred == 0) null else tp.toDouble() / pred
        o["recall"] = if (pos == 0) null else tp.toDouble() / pos
        o["recall_lower"] = if (pos == 0) null else 1 - IntentStats.clopperPearsonUpper(fn.toDouble(), pos.toDouble(), alpha)
        // the exact bound costs O(n * k) big-integer products: affordable for recall (few misses), not for precision over thousands of flags
        o["precision_lower"] = if (pred == 0 || pred > 600) null else 1 - IntentStats.clopperPearsonUpper(fp.toDouble(), pred.toDouble(), alpha)
        return o
    }

    private fun strip(t: String): String = if (t.startsWith("pca.")) t.substring(4) else t

    private fun score(es: List<Map<String, Any?>>, pred: Map<String, Set<String>>, traitNames: List<String>, alpha: Double): MutableList<Any?> {
        val out = ArrayList<Any?>()
        for (t in traitNames) {
            val rows = ArrayList<BooleanArray>()
            for (e in es) {
                val p = pred[Jx.jsStr(e["id"])]
                rows.add(booleanArrayOf(Jx.a(e["labels"]).contains(t), p != null && p.contains(t)))
            }
            val s = stat(t, rows, alpha)
            if (Jx.num(s["positives"])!! > 0 || Jx.num(s["predicted"])!! > 0) out.add(s)
        }
        return out
    }

    /** `evalSuggest`: `rules` and `registry` default to the shipped ones; `alpha` to 0.05. */
    fun evalSuggest(entriesO: List<Any?>, rulesIn: Map<String, Any?>?, registryIn: Map<String, Map<String, Any?>>?, alphaIn: Double?): Map<String, Any?> {
        val rules = rulesIn ?: ImportRules.DEFAULT_RULES
        val registry = registryIn ?: Actions.CORE_REGISTRY
        val alpha = alphaIn ?: 0.05
        val entries = ArrayList<Map<String, Any?>>()
        for (e in entriesO) entries.add(Jx.m(e))
        val defs = Jx.m(importCorpus(entriesO)["defs"])
        val names = TreeSet<String>()
        for (t in registry.keys) if (t != "pca.unreviewed" && t != "pca.irreversible") names.add(strip(t))
        val traitNames = ArrayList(names)
        val flagged = LinkedHashMap<String, Set<String>>()
        val added = LinkedHashMap<String, Set<String>>()
        for (e in entries) {
            val d = defs[Jx.jsStr(e["id"])] ?: continue
            val s = ImportSuggest.suggestWithRules(Jx.m(d), rules, registry)
            val sd = ImportSuggest.applySuggestion(Jx.m(d), s, Jx.obj("rules", Jx.obj("version", rules["version"], "digest", "", "fired", s["fired"])))
            val fl = LinkedHashSet<String>()
            for (t in Actions.closure(registry, ActionEffective.hintTraits(sd))) if (t != "pca.unreviewed") fl.add(strip(t))
            flagged[Jx.jsStr(e["id"])] = fl
            val ad = LinkedHashSet<String>()
            for (t in Jx.a(s["traits"])) ad.add(strip(t as String))
            added[Jx.jsStr(e["id"])] = ad
        }
        val sources = TreeSet<String>()
        var anyReal = false
        for (e in entries) { sources.add(sourceOf(e)); if ("real" == e["src"]) anyReal = true }
        if (anyReal) sources.add("real")
        val bySource = LinkedHashMap<String, Any?>()
        for (s in sources) {
            val es = ArrayList<Map<String, Any?>>()
            for (e in entries) if (if (s == "real") "real" == e["src"] else sourceOf(e) == s) es.add(e)
            bySource[s] = Jx.obj("entries", Jx.n(es.size.toLong()), "flagged", score(es, flagged, traitNames, alpha))
        }
        val out = LinkedHashMap<String, Any?>()
        out["alpha"] = alpha
        out["entries"] = Jx.n(entries.size.toLong())
        out["mapped"] = Jx.n(defs.size.toLong())
        out["rules_version"] = rules["version"]
        out["flagged"] = score(entries, flagged, traitNames, alpha)
        out["suggested"] = score(entries, added, traitNames, alpha)
        out["by_source"] = bySource
        return out
    }

    private fun pct(x: Any?): String {
        if (x == null) return "-"
        val d = Jx.num(x)!! * 100
        return BigDecimal(d).setScale(1, RoundingMode.HALF_UP).toPlainString() + "%"
    }

    private fun table(stats: List<Any?>): String {
        val rows = arrayListOf("| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |", "|---|---:|---:|---:|---:|---:|---:|---:|")
        for (so in stats) {
            val s = Jx.m(so)
            rows.add(
                "| " + s["trait"] + " | " + Jx.jsStr(s["positives"]) + " | " + Jx.jsStr(s["predicted"]) + " | " + pct(s["recall"]) + " | " + pct(s["recall_lower"]) + " | " + pct(s["precision"]) + " | " +
                    Jx.jsStr(s["fn"]) + " | " + Jx.jsStr(s["fp"]) + " |",
            )
        }
        return rows.joinToString("\n")
    }

    fun renderEvalMarkdown(r: Map<String, Any?>): String {
        val parts = arrayListOf(
            "# Suggestion rules " + Jx.jsStr(r["rules_version"]) + ": measured on a labeled corpus",
            "",
            Jx.jsStr(r["entries"]) + " labeled operations (" + Jx.jsStr(r["mapped"]) + " imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = " + Jx.jsStr(r["alpha"]) + ".",
            "These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor.",
            "",
            "## What a reviewer is shown (importer facts plus suggestions)", "", table(Jx.a(r["flagged"])), "",
            "## What the suggestion rules added", "", table(Jx.a(r["suggested"])), "",
        )
        for ((k, v) in Jx.m(r["by_source"])) {
            parts.add("## Source: " + k + " (" + Jx.jsStr(Jx.get(v, "entries")) + " operations)")
            parts.add("")
            parts.add(table(Jx.a(Jx.get(v, "flagged"))))
            parts.add("")
        }
        return parts.joinToString("\n")
    }

    private fun findTrait(flagged: Any?, t: String): Any? {
        if (flagged !is List<*>) return null
        for (x in flagged) if (t == Jx.get(x, "trait")) return x
        return null
    }

    /** Empty when the report meets the floors; else one line per failure. */
    fun floorFailures(r: Map<String, Any?>, f: Map<String, Any?>): List<String> {
        val out = ArrayList<String>()
        val bySource = Jx.m(r["by_source"])
        val real = bySource["real/holdout"]
        val fr = Jx.m(f["real"])
        val minEntries = Jx.num(fr["min_entries"])!!
        if (real == null || Jx.num(Jx.get(real, "entries"))!! < minEntries)
            out.add("the real-spec hold-out has " + (if (real == null) "0" else Jx.jsStr(Jx.get(real, "entries"))) + " operations, fewer than the required " + Jx.jsStr(fr["min_entries"]))
        if (Jx.num(r["mapped"])!! < Jx.num(r["entries"])!!) out.add((Jx.num(r["entries"])!! - Jx.num(r["mapped"])!!).toLong().toString() + " corpus operations were not imported")
        for ((t, floorV) in Jx.m(fr["recall_lower"])) {
            val s = if (real == null) null else findTrait(Jx.get(real, "flagged"), t)
            val needO = Jx.m(fr["min_positives"])[t]
            val need = if (needO == null) "0" else Jx.jsStr(needO)
            val needN = if (needO == null) 0.0 else Jx.num(needO)!!
            if (s == null || Jx.num(Jx.get(s, "positives"))!! < needN) out.add(t + ": " + (if (s == null) "0" else Jx.jsStr(Jx.get(s, "positives"))) + " real labeled positives, fewer than the " + need + " the floor needs")
            else if (Jx.get(s, "recall_lower") == null || Jx.num(Jx.get(s, "recall_lower"))!! < Jx.num(floorV)!!)
                out.add(t + ": hold-out recall lower bound " + pct(Jx.get(s, "recall_lower")) + " is below the recorded floor " + pct(floorV))
        }
        val syn = bySource["syn"]
        for ((k, floorV) in Jx.m(Jx.m(f["regression"])["recall_lower"])) {
            val s = if (syn == null) null else findTrait(Jx.get(syn, "flagged"), k)
            if (s == null || Jx.get(s, "recall_lower") == null || Jx.num(Jx.get(s, "recall_lower"))!! < Jx.num(floorV)!!)
                out.add(k + ": regression-set recall lower bound " + pct(if (s == null) null else Jx.get(s, "recall_lower")) + " is below " + pct(floorV))
        }
        return out
    }
}
