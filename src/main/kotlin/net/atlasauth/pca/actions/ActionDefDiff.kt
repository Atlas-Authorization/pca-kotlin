package net.atlasauth.pca.actions

import java.util.TreeMap
import java.util.TreeSet
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.AttestUtil

/**
 * The author-facing semantic diff of two versions of one def (equal | narrow | widen | incomparable, with the reasons) and the per-verb
 * diff of two packs. Conservative: anything it cannot show to be no wider is widening.
 */
object ActionDefDiff {
    private val SENSITIVITY = listOf("free", "material", "critical")
    private val PROVENANCE = listOf("first_party", "tool", "agent")
    private val SCOPE_RANK = mapOf("one" to 0, "set" to 1, "tenant" to 2, "global" to 3)

    private fun rr(rev: String): Int = ActionDiffSupport.revRank(rev)

    /** The diff of `b` against `a`: `{class, breaking, reasons}`. */
    @Suppress("UNCHECKED_CAST")
    fun diffDefs(a: Map<String, Any?>, b: Map<String, Any?>, reg: Map<String, Map<String, Any?>> = Actions.CORE_REGISTRY): MutableMap<String, Any?> {
        if (a["verb"] != b["verb"]) {
            return J.obj("class", "widen", "breaking", true, "reasons", J.list("verb renamed: removed + added (grants on the old verb do not follow)"))
        }
        val wide = ArrayList<String>()
        val narrow = ArrayList<String>()
        val incomp = ArrayList<String>()
        var breaking = false
        val na = Actions.normalize(a)
        val nb = Actions.normalize(b)
        val ea = J.m(J.m(ActionEffective.effective(a, reg, null))["hint"])
        val eb = J.m(J.m(ActionEffective.effective(b, reg, null))["hint"])
        val pa = J.m(ea["eff"])
        val pb = J.m(eb["eff"])
        if (!ActionEffective.leq(pa, pb)) wide.add("the effective profile is not at least the old one")
        else if (!ActionEffective.profileEq(pa, pb)) narrow.add("the effective profile rose")

        val fa = J.a(na["effects"])
        val fb = J.a(nb["effects"])
        for (e in fa) if (!fb.contains(e)) wide.add("effect $e removed")
        for (e in fb) if (!fa.contains(e)) narrow.add("effect $e added")
        val ta = J.a(na["traits"])
        val tb = J.a(nb["traits"])
        for (t in ta) if (!tb.contains(t)) wide.add("declared trait $t removed")
        for (t in tb) if (!ta.contains(t)) narrow.add("declared trait $t added")
        val pma = J.m(na["params"])
        val pmb = J.m(nb["params"])
        val ra = Actions.worstReversibility(na["reversibility"], pma as Map<String, Map<String, Any?>>)
        val rb = Actions.worstReversibility(nb["reversibility"], pmb as Map<String, Map<String, Any?>>)
        if (rr(rb) < rr(ra)) wide.add("reversibility lowered ($ra to $rb)")
        else if (rr(rb) > rr(ra)) narrow.add("reversibility raised ($ra to $rb)")
        val ba = J.num(J.get(na["blast"], "ppm"))!!.toLong()
        val bb = J.num(J.get(nb["blast"], "ppm"))!!.toLong()
        if (bb < ba) wide.add("blast lowered")
        else if (bb > ba) narrow.add("blast raised")
        val ia = if ("none" == J.get(na["idempotency"], "mode")) 0 else 1
        val ib = if ("none" == J.get(nb["idempotency"], "mode")) 0 else 1
        if (ib < ia) wide.add("idempotency loosened")
        else if (ib > ia) narrow.add("idempotency added")

        val resa = J.m(na["resource"])
        val resb = J.m(nb["resource"])
        if (resa["type"] != resb["type"]) incomp.add("resource type changed")
        val sa = SCOPE_RANK[resa["scope"] as String]!!
        val sb = SCOPE_RANK[resb["scope"] as String]!!
        if (sb > sa) wide.add("resource scope widened")
        else if (sb < sa) narrow.add("resource scope narrowed")
        val inOld = ActionIdPattern.idPatternContains(resa["id"], resb["id"])
        val inNew = ActionIdPattern.idPatternContains(resb["id"], resa["id"])
        if (!inOld) wide.add("the resource id pattern is not contained in the old one")
        else if (!inNew) narrow.add("the resource id pattern is narrower")

        for (k in pma.keys) {
            val x = J.m(pma[k])
            val y = pmb[k]
            if (y == null) { narrow.add("param $k removed"); breaking = true; continue }
            paramDiff(k, x, J.m(y), wide, narrow, incomp)
            if (x["required"] == false && J.get(y, "required") == true) breaking = true
        }
        for (k in pmb.keys) {
            if (pma.containsKey(k)) continue
            val req = J.get(pmb[k], "required")
            if (req == true || (req != null && req != false)) { narrow.add("required param $k added"); breaking = true }
            else wide.add("optional param $k added")
        }
        if ("confirmed" == J.get(a["review"], "state") && "confirmed" != J.get(b["review"], "state")) narrow.add("review state left confirmed")

        val cls = if (incomp.isNotEmpty() || (wide.isNotEmpty() && narrow.isNotEmpty())) "incomparable" else if (wide.isNotEmpty()) "widen" else if (narrow.isNotEmpty()) "narrow" else "equal"
        val cmpEq = cls == "equal" && Actions.defDigest(a) != Actions.defDigest(b)
        val reasons = ArrayList<String>()
        for (r in wide) reasons.add("widen: $r")
        for (r in narrow) reasons.add("narrow: $r")
        for (r in incomp) reasons.add("incomparable: $r")
        if (cmpEq) reasons.add("equal: only title or description changed")
        return J.obj("class", cls, "breaking", breaking, "reasons", J.objs(reasons))
    }

    private fun numText(v: Any?): String {
        val d = J.num(v)
        return if (v == null) "undefined" else if (d == null) v.toString() else AttestUtil.jsNumString(d)
    }

    private fun num(k: String, f: String, lowerIsWider: Boolean, x: Map<String, Any?>, y: Map<String, Any?>, wide: MutableList<String>, narrow: MutableList<String>) {
        val o = x[f]
        val n = y[f]
        val od = J.num(o)
        val nd = J.num(n)
        if (o == null && n == null) return
        if (od != null && nd != null && od == nd) return
        val ro = if (o == null) (if (lowerIsWider) Double.NEGATIVE_INFINITY else Double.POSITIVE_INFINITY) else od!!
        val rn = if (n == null) (if (lowerIsWider) Double.NEGATIVE_INFINITY else Double.POSITIVE_INFINITY) else nd!!
        val widerNew = if (lowerIsWider) rn < ro else rn > ro
        (if (widerNew) wide else narrow).add("param $k: $f ${numText(o)} to ${numText(n)}")
    }

    private fun pl(v: Any?): Int = if (v == null) PROVENANCE.size else ActionDiffSupport.indexIn(PROVENANCE, v)

    private fun sens(p: Map<String, Any?>): String = if (p["sensitivity"] is String) p["sensitivity"] as String else ActionDiffSupport.effectiveParamSensitivity(p)

    private fun floorRank(r: Any?): Int {
        if (r !is String) return 0
        val f = ActionDiffSupport.roleSensitivityFloor(r)
        return if (f == null) 0 else SENSITIVITY.indexOf(f)
    }

    private fun paramDiff(k: String, x: Map<String, Any?>, y: Map<String, Any?>, wide: MutableList<String>, narrow: MutableList<String>, incomp: MutableList<String>) {
        if (x["type"] != y["type"]) incomp.add("param $k: type changed")
        num(k, "min", true, x, y, wide, narrow); num(k, "max", false, x, y, wide, narrow); num(k, "max_len", false, x, y, wide, narrow)
        num(k, "max_items", false, x, y, wide, narrow); num(k, "min_items", true, x, y, wide, narrow)
        val ux = x["unit"]
        val uy = y["unit"]
        if (J.stringify(ux) != J.stringify(uy)) incomp.add("param $k: unit changed")
        val vo = x["values"]
        val vn = y["values"]
        if (vo != null || vn != null) {
            if (vo == null) narrow.add("param $k: values restricted")
            else if (vn == null) wide.add("param $k: values unrestricted")
            else {
                val added = ArrayList<String>()
                val removed = ArrayList<String>()
                for (v in J.a(vn)) if (!J.a(vo).contains(v)) added.add(v.toString())
                for (v in J.a(vo)) if (!J.a(vn).contains(v)) removed.add(v.toString())
                if (added.isNotEmpty()) wide.add("param $k: values added (${added.joinToString(", ")})")
                if (removed.isNotEmpty()) narrow.add("param $k: values removed (${removed.joinToString(", ")})")
            }
        }
        if (x["required"] == true && y["required"] == false) wide.add("param $k: required to optional")
        if (x["required"] == false && y["required"] == true) narrow.add("param $k: optional to required")
        if (pl(y["provenance_min"]) > pl(x["provenance_min"])) wide.add("param $k: provenance_min loosened")
        else if (pl(y["provenance_min"]) < pl(x["provenance_min"])) narrow.add("param $k: provenance_min tightened")
        val sx = SENSITIVITY.indexOf(sens(x))
        val sy = SENSITIVITY.indexOf(sens(y))
        if (sy < sx) wide.add("param $k: sensitivity lowered")
        else if (sy > sx) narrow.add("param $k: sensitivity raised")
        if (x["role"] != y["role"]) {
            val fx = floorRank(x["role"])
            val fy = floorRank(y["role"])
            if (fy < fx) wide.add("param $k: role changed to a lower-floor role")
            else if (fy > fx) narrow.add("param $k: role changed to a higher-floor role")
            else incomp.add("param $k: role changed")
        }
    }

    /** Per-verb diff of two sets of defs: `{verb, class, breaking, reasons}` (a removed verb is `removed`, a new one `added`). */
    fun diffPacks(olds: List<*>, news: List<*>, reg: Map<String, Map<String, Any?>> = Actions.CORE_REGISTRY): MutableList<Any?> {
        val o = TreeMap<String, Any?>()
        val n = TreeMap<String, Any?>()
        for (d in olds) o[J.get(d, "verb") as String] = d
        for (d in news) n[J.get(d, "verb") as String] = d
        val verbs = TreeSet<String>(o.keys)
        verbs.addAll(n.keys)
        val out = ArrayList<Any?>()
        for (v in verbs) {
            val x = o[v]
            val y = n[v]
            if (x == null) out.add(J.obj("verb", v, "class", "added", "breaking", false, "reasons", ArrayList<Any?>()))
            else if (y == null) out.add(J.obj("verb", v, "class", "removed", "breaking", true, "reasons", J.list("verb removed")))
            else {
                val d = diffDefs(J.m(x), J.m(y), reg)
                out.add(J.obj("verb", v, "class", d["class"], "breaking", d["breaking"], "reasons", d["reasons"]))
            }
        }
        return out
    }
}
