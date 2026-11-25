package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentOmega.CatDim
import net.atlasauth.pca.intent.IntentOmega.CatValue
import net.atlasauth.pca.intent.IntentOmega.Dim
import net.atlasauth.pca.intent.IntentOmega.NumDim
import net.atlasauth.pca.intent.IntentOmega.VerbSpace

/**
 * Regions: the part of the outcome space a cell question was about, written in value terms rather than cell indices, so an
 * observation keeps its meaning when the space is refined or lifted onto another organisation's space. Mapping onto a finer
 * space is exact; onto a non-refining one a "yes" claims only the cells wholly inside (inner) and a "no" widens to every
 * cell that meets the region (outer).
 */
object IntentRegion {
    /** One restricted dimension: numeric `lo..hi` or categorical (reference value list + the listed cell indices). */
    class RegionDim internal constructor(@JvmField val kind: String, @JvmField val lo: Double, @JvmField val hi: Double, @JvmField val values: List<CatValue>?, @JvmField val cells: List<Int>?) {
        fun toJson(): MutableMap<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["kind"] = kind
            if (kind == "num") {
                m["lo"] = lo
                m["hi"] = hi
            } else {
                m["values"] = values!!.map { IntentOmega.catValueJson(it) }.toMutableList()
                m["cells"] = ArrayList<Any?>(cells!!)
            }
            return m
        }

        companion object {
            @JvmStatic fun num(lo: Double, hi: Double): RegionDim = RegionDim("num", lo, hi, null, null)
            @JvmStatic fun cat(values: List<CatValue>, cells: List<Int>): RegionDim = RegionDim("cat", 0.0, 0.0, values, cells)

            @JvmStatic
            fun fromJson(o: Any?): RegionDim {
                val m = IntentOmega.obj(o)
                if ("num" == m["kind"]) return num(IntentOmega.dbl(m["lo"]), IntentOmega.dbl(m["hi"]))
                val vs = IntentOmega.arr(m["values"]).map { x -> CatValue(IntentOmega.obj(x)["kind"] as String, IntentOmega.obj(x)["value"] as String) }
                val cs = IntentOmega.arr(m["cells"]).map { IntentOmega.dbl(it).toInt() }
                return cat(vs, cs)
            }
        }
    }

    class Region(@JvmField val verb: String, @JvmField val dims: Map<String, RegionDim>) {
        fun toJson(): MutableMap<String, Any?> {
            val ds = LinkedHashMap<String, Any?>()
            for ((k, v) in dims) ds[k] = v.toJson()
            return linkedMapOf("verb" to verb, "dims" to ds)
        }

        companion object {
            @JvmStatic
            fun fromJson(o: Any?): Region {
                val m = IntentOmega.obj(o)
                val ds = LinkedHashMap<String, RegionDim>()
                for ((k, v) in IntentOmega.obj(m["dims"])) ds[k] = RegionDim.fromJson(v)
                return Region(m["verb"] as String, ds)
            }
        }
    }

    /** The value-space region of one cell. */
    fun regionOfCell(vs: VerbSpace, idx: IntArray): Region {
        val dims = LinkedHashMap<String, RegionDim>()
        for (k in vs.dims.indices) {
            val d = vs.dims[k]
            if (d is NumDim) {
                val c = IntentOmega.numCells(d)[idx[k]]
                dims[d.path] = RegionDim.num(c.lo, c.hi)
            } else dims[d.path] = RegionDim.cat(ArrayList((d as CatDim).values), arrayListOf(idx[k]))
        }
        return Region(vs.verb, dims)
    }

    /** Restrict one dimension: [part] is {lo, hi} for a numeric dimension, {cells} for a categorical one. */
    fun restrictRegion(r: Region, d: Dim, part: Map<String, Any?>): Region {
        val dims = LinkedHashMap(r.dims)
        if (d is NumDim && part.containsKey("lo")) dims[d.path] = RegionDim.num(IntentOmega.dbl(part["lo"]), IntentOmega.dbl(part["hi"]))
        else if (d is CatDim && part.containsKey("cells")) {
            val cs = IntentOmega.arr(part["cells"]).map { IntentOmega.dbl(it).toInt() }
            dims[d.path] = RegionDim.cat(ArrayList(d.values), cs)
        } else throw IllegalArgumentException("restrictRegion: part does not match the kind of " + d.path)
        return Region(r.verb, dims)
    }

    /** The cells of [d] covered by [rd]; [inner] = wholly inside, else meeting it. */
    fun dimCellsIn(d: Dim, rd: RegionDim?, inner: Boolean): List<Int> {
        val n = IntentOmega.cellCount(d)
        val all = (0 until n).toList()
        if (rd == null) return all
        val out = ArrayList<Int>()
        if (d is NumDim) {
            require(rd.kind == "num") { "region: " + d.path + " is numeric in the space but categorical in the region" }
            for (i in all) {
                val c = IntentOmega.numCells(d)[i]
                if (if (inner) c.lo >= rd.lo && c.hi <= rd.hi else c.hi >= rd.lo && c.lo <= rd.hi) out.add(i)
            }
            return out
        }
        require(rd.kind == "cat") { "region: " + d.path + " is categorical in the space but numeric in the region" }
        val ref = CatDim(d.path, rd.values!!)
        val inSet = HashSet(rd.cells!!)
        for (i in all) if (inSet.contains(IntentOmega.catCellOf(ref, IntentOmega.catRep(d as CatDim, i)))) out.add(i)
        return out
    }

    /** Flat cell indices covered by the region (row-major, last dimension fastest); throws on a dimension the verb space lacks. */
    fun regionCells(vs: VerbSpace, r: Region, inner: Boolean): List<Long> {
        require(r.verb == vs.verb) { "region: verb " + r.verb + " does not match " + vs.verb }
        for (p in r.dims.keys) require(vs.dims.any { it.path == p }) { "region: restricts $p, which the space has no dimension for" }
        val per = vs.dims.map { dimCellsIn(it, r.dims[it.path], inner) }
        for (x in per) if (x.isEmpty()) return ArrayList()
        var acc: List<Long> = listOf(0L)
        for (k in per.indices) {
            val size = IntentOmega.cellCount(vs.dims[k]).toLong()
            val next = ArrayList<Long>()
            for (f in acc) for (c in per[k]) next.add(f * size + c)
            acc = next
        }
        return acc
    }

    fun valueInRegionDim(path: String, rd: RegionDim, x: Any?): Boolean {
        if (rd.kind == "num") return x is Double && x >= rd.lo && x <= rd.hi
        return x is String && rd.cells!!.contains(IntentOmega.catCellOf(CatDim(path, rd.values!!), x))
    }
}
