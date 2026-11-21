package net.atlasauth.pca.intent

import java.util.TreeMap
import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.CatValue
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.VerbSpace
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json

/**
 * The outcome space from the site's signed action schema: one dimension per parameter whose effective sensitivity (after the wallet floor) is
 * material or critical, boolean / set / array parameters on their canonical projection path, closed-world default sets for silent parameters.
 * The schema, the slots, the policies and the confirmed values are JSON trees.
 */
@Suppress("UNCHECKED_CAST")
object IntentSchema {
    @JvmField val WALLET_FLOOR_PREFIXES: List<String> = listOf("money.", "party.", "contact.", "person.", "credential.")
    @JvmField val WALLET_FLOOR_EXACT: List<String> = listOf("text.message")
    private val REV = listOf("reversible", "rate_limited", "irreversible")

    /** The derived space with the wallet-floor overrides, the default-pinning slot constraints and the canonical-projection map. */
    class SchemaOmega internal constructor(
        @JvmField val omega: Omega,
        @JvmField val overrides: List<Map<String, Any?>>,
        @JvmField val defaults: List<Map<String, Any?>>,
        @JvmField val canonOf: Map<String, String>,
    )

    private fun lm() = LinkedHashMap<String, Any?>()

    private fun m(o: Any?): Map<String, Any?> = IntentOmega.obj(o)

    private fun strs(o: Any?, dflt: List<String>?): List<String>? {
        if (o == null) return dflt
        return IntentOmega.arr(o).map { it as String }
    }

    private fun utf8Cmp() = Comparator<String> { a, b -> Json.compareUtf8(a, b) }

    internal fun floorApplies(semantic: String, floor: Map<String, Any?>?): Boolean {
        val pre = strs(floor?.get("prefixes"), WALLET_FLOOR_PREFIXES)!!
        val ex = strs(floor?.get("exact"), WALLET_FLOOR_EXACT)!!
        if (ex.contains(semantic)) return true
        for (p in pre) if (semantic.startsWith(p)) return true
        return false
    }

    /** The wallet's effective sensitivity: a site `free` on a floored semantic type becomes `material`. */
    @JvmStatic
    fun effectiveSensitivity(d: Map<String, Any?>, floor: Map<String, Any?>?): String? =
        if ("free" == d["sensitivity"] && floorApplies(d["semantic"] as String, floor)) "material" else d["sensitivity"] as String?

    private fun maxRev(xs: List<Any?>): String {
        var a = "reversible"
        for (b in xs) if (REV.indexOf(b) > REV.indexOf(a)) a = b as String
        return a
    }

    /** The value-independent reversibility class of a verb declaration (the worst a value can map to). */
    @JvmStatic
    fun verbReversibility(v: Map<String, Any?>): String {
        val by = v["reversibility_by"]
        if (by == null) return if (v["reversibility"] != null) v["reversibility"] as String else if ("read" == v["kind"]) "reversible" else "irreversible"
        val b = m(by)
        val d = m(v["params"])[b["param"] as String?]
        val map = m(b["map"])
        val mapped = ArrayList<Any?>(map.values)
        var domain: List<String>? = null
        if (d != null) {
            val dm = m(d)
            if ("boolean" == dm["type"]) domain = listOf("true", "false")
            else if ("string" == dm["type"] && dm["values"] != null) domain = strs(dm["values"], null)
        }
        var covered = domain != null
        if (covered) for (x in domain!!) if (!map.containsKey(x)) covered = false
        val all = ArrayList<Any?>(mapped)
        if (!covered) all.add(if (b["default"] != null) b["default"] else "irreversible")
        return maxRev(if (covered) mapped else all)
    }

    /** Every override the wallet floor makes on the schema's verbs: [{verb, path, semantic, declared, effective}]. */
    @JvmStatic
    fun walletFloorOverrides(verbs: List<Any?>, floor: Map<String, Any?>?): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        for (vo in verbs) {
            val v = m(vo)
            val params = TreeMap<String, Any?>(utf8Cmp())
            params.putAll(m(v["params"]))
            for ((k, pv) in params) {
                val d = m(pv)
                val eff = effectiveSensitivity(d, floor)
                if (eff!! != d["sensitivity"]) {
                    val o = lm()
                    o["verb"] = v["verb"]; o["path"] = k; o["semantic"] = d["semantic"]; o["declared"] = d["sensitivity"]; o["effective"] = eff
                    out.add(o)
                }
            }
        }
        return out
    }

    private fun canonPath(paramPath: String): String = "env.canon." + paramPath.substring("action.params.".length)

    private fun usesCanon(d: Map<String, Any?>): Boolean {
        val t = d["type"]
        return "boolean" == t || "set" == t || "array" == t
    }

    /** The canonical text a value of a canon-projected parameter has. */
    @JvmStatic
    fun canonValue(d: Map<String, Any?>, x: Any?): String {
        if ("boolean" == d["type"]) return if (x == true) "true" else "false"
        val norm = IntentJs.normalize(x)
        if ("set" == d["type"]) {
            val l = IntentOmega.arr(norm).map { it as String }.sortedWith(utf8Cmp())
            return Json.canonicalizeStrict(ArrayList<Any?>(l))
        }
        return Json.canonicalizeStrict(norm)
    }

    private fun sortedUtf8(s: Collection<String>): List<String> = s.toList().sortedWith(utf8Cmp())

    /** Derive the space. `o`: schema {verbs}, verbs?, slots?, policies?, confirmed?, floor?, domains?. Throws on a malformed schema. */
    @JvmStatic
    fun deriveOmegaFromSchema(o: Map<String, Any?>): SchemaOmega {
        val schemaVerbs = IntentOmega.arr(m(o["schema"])["verbs"])
        val verbNames: List<String>
        if (o["verbs"] != null) verbNames = strs(o["verbs"], null)!!
        else {
            val set = LinkedHashSet<String>()
            for (v in schemaVerbs) if ("write" == m(v)["kind"]) set.add(m(v)["verb"] as String)
            if (o["slots"] != null && m(o["slots"])["verbs"] != null) set.addAll(strs(m(o["slots"])["verbs"], null)!!)
            verbNames = ArrayList(set)
        }
        val baseOpts = lm()
        baseOpts["policies"] = o["policies"] ?: ArrayList<Any?>()
        if (o["slots"] != null) baseOpts["slots"] = o["slots"]
        baseOpts["extraVerbs"] = ArrayList<Any?>(verbNames)
        val base = IntentDerive.deriveOmega(baseOpts)
        val floor = if (o["floor"] == null) null else m(o["floor"])
        val defaults = ArrayList<Map<String, Any?>>()
        val canonOf = LinkedHashMap<String, String>()
        val verbs = ArrayList<VerbSpace>()
        val sortedNames = verbNames.sortedWith(utf8Cmp())
        val confirmed = if (o["confirmed"] == null) LinkedHashMap<String, Any?>() else m(o["confirmed"])
        val domains = if (o["domains"] == null) LinkedHashMap<String, Any?>() else m(o["domains"])
        for (verb in sortedNames) {
            var decl: Map<String, Any?>? = null
            for (v in schemaVerbs) if (verb == m(v)["verb"]) { decl = m(v); break }
            if (decl == null) continue
            var lits: VerbSpace? = null
            for (v in base.verbs) if (v.verb == verb) { lits = v; break }
            val dims = ArrayList<Dim>()
            if (lits != null) for (d in lits.dims) if (!d.path.startsWith("action.params.")) dims.add(d)
            val params = TreeMap<String, Any?>(utf8Cmp())
            params.putAll(m(decl["params"]))
            for ((path, pv) in params) {
                val pd = m(pv)
                if ("free" == effectiveSensitivity(pd, floor)) continue
                var lit: Dim? = null
                if (lits != null) for (d in lits.dims) if (d.path == path) { lit = d; break }
                val silent = lit == null
                val defaultSet = ArrayList<Any?>()
                if (confirmed[path] != null) defaultSet.addAll(IntentOmega.arr(confirmed[path]))
                if (pd["principal_neutral_default"] == true && pd.containsKey("default")) defaultSet.add(pd["default"])
                if ("integer" == pd["type"]) {
                    val cuts = LinkedHashSet<Double>()
                    if (lit is NumDim) for (c in lit.cuts) cuts.add(c + 0.0)
                    for (x in defaultSet) if (IntentOmega.isNumber(x) && Math.abs(IntentOmega.dbl(x)) <= 9007199254740991.0 && IntentOmega.dbl(x) == Math.floor(IntentOmega.dbl(x))) cuts.add(IntentOmega.dbl(x) + 0.0)
                    val sorted = ArrayList(cuts)
                    sorted.sort()
                    val maxCut = if (sorted.isEmpty()) 0.0 else sorted[sorted.size - 1]
                    val dom = if (domains[path] == null) null else m(domains[path])
                    val lo = if (dom != null && dom["lo"] != null) IntentOmega.dbl(dom["lo"]) else if (pd["min"] != null) IntentOmega.dbl(pd["min"]) else Math.min(0.0, if (sorted.isEmpty()) 0.0 else sorted[0] - 1)
                    val hi = if (dom != null && dom["hi"] != null) IntentOmega.dbl(dom["hi"]) else if (pd["max"] != null) IntentOmega.dbl(pd["max"]) else Math.max(10.0, Math.max(2 * maxCut, maxCut + 10))
                    val kept = ArrayList<Double>()
                    for (c in sorted) if (c >= lo && c <= hi) kept.add(c)
                    dims.add(NumDim(path, lo, hi, IntentOmega.toArray(kept), if (lo >= 0) "loguniform" else "uniform"))
                    val nums = ArrayList<Double>()
                    for (x in defaultSet) if (IntentOmega.isNumber(x)) nums.add(IntentOmega.dbl(x))
                    if (silent && nums.size == 1) {
                        val c = lm()
                        c["verb"] = verb; c["path"] = path; c["min"] = nums[0]; c["max"] = nums[0]
                        defaults.add(c)
                    }
                    continue
                }
                val canon = usesCanon(pd)
                val dimPath = if (canon) canonPath(path) else path
                if (canon) canonOf[dimPath] = path
                val exacts = LinkedHashSet<String>()
                val prefixes = LinkedHashSet<String>()
                if (lit is CatDim) for (v in lit.values) { if (v.kind == "exact") exacts.add(v.value) else if (v.kind == "prefix") prefixes.add(v.value) }
                if ("string" == pd["type"] && pd["values"] != null) exacts.addAll(strs(pd["values"], null)!!)
                if ("boolean" == pd["type"]) { exacts.add("false"); exacts.add("true") }
                val defTexts = ArrayList<String>()
                for (x in defaultSet) defTexts.add(if (canon) canonValue(pd, x) else Js.template(x))
                exacts.addAll(defTexts)
                val values = ArrayList<CatValue>()
                for (s in sortedUtf8(exacts)) values.add(CatValue("exact", s))
                for (s in sortedUtf8(prefixes)) values.add(CatValue("prefix", s))
                values.add(CatValue("other", IntentOmega.OTHER))
                dims.add(CatDim(dimPath, values))
                if (silent && defTexts.isNotEmpty()) {
                    val c = lm()
                    c["verb"] = verb; c["path"] = dimPath; c["oneOf"] = ArrayList<Any?>(sortedUtf8(LinkedHashSet(defTexts)))
                    defaults.add(c)
                }
            }
            dims.sortWith(Comparator { a, b -> Json.compareUtf8(a.path, b.path) })
            verbs.add(VerbSpace(verb, verbReversibility(decl), 0.0, dims))
        }
        for (v in verbs) v.weight = 1.0 / (if (verbs.isEmpty()) 1 else verbs.size)
        val included = ArrayList<Any?>()
        for (v in schemaVerbs) if (verbNames.contains(m(v)["verb"])) included.add(v)
        return SchemaOmega(Omega(verbs, ArrayList(base.approximate)), walletFloorOverrides(included, floor), defaults, canonOf)
    }
}
