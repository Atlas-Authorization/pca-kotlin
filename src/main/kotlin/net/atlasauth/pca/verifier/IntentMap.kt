package net.atlasauth.pca.verifier

/**
 * Rule 19 (Intent Layer v2 V15): the committed Intent Map and the Z0 disclosure (packages/pca/src/intent-map-commit.ts
 * `commitMap` / `decideMapDisclosure`). Every leaf is hashed with its own 32-byte salt and a per-kind tag
 * (`SHA-256(TAG_kind || r || strictCanonical(leaf))`), nodes with `TAG_NODE`, the tree has the RFC 9162 shape and
 * `map_commit = base64url(SHA-256(TAG_COMMIT || u64be(n) || root))`. The `map` check opens the action's header, cell and
 * metrics leaves against the commitment and recomputes the cell of the action. Never throws.
 */
object IntentMap {
    const val MAP_TAG_HEADER = "atlas-pca/intent-map/header/v1\u0000"
    const val MAP_TAG_CELL = "atlas-pca/intent-map/cell/v1\u0000"
    const val MAP_TAG_METRICS = "atlas-pca/intent-map/metrics/v1\u0000"
    const val MAP_TAG_LEARNER = "atlas-pca/intent-map/learner/v1\u0000"
    const val MAP_TAG_NODE = "atlas-pca/intent-map/node/v1\u0000"
    const val MAP_TAG_COMMIT = "atlas-pca/intent-map/commit/v1\u0000"
    /** The `intent_session.map_form` value that selects the committed form. */
    const val MAP_FORM_COMMIT = "commit"
    /** The OTHER value of a categorical dimension (U+22A5). */
    const val MAP_OTHER = "⊥"
    const val MAX_MAP_LEAVES = 1L shl 24
    const val MAX_VERB_CELLS = 1L shl 20
    const val MAX_MAP_DIMS = 16
    const val MAX_MAP_CUTS = 256
    const val MAX_MAP_VALUES = 256
    const val MAX_MAP_STRING_BYTES = 256
    internal val METRIC_FIELDS = listOf(
        "residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm",
        "fidelity_est_ppm", "entropy_mbits", "questions", "conflicts",
    )
    private val PATH_RE = Regex("action\\.params\\.[A-Za-z0-9_]{1,64}")

    /** The Z0 verdict: when `ok`, the action's cell indices, its `p_ppm` and the committed residual risk. */
    class Decision internal constructor(
        val ok: Boolean,
        val reason: String?,
        val cell: List<Long>?,
        val pPpm: Long,
        val residualRiskPpm: Long,
    ) {
        internal companion object {
            fun bad(reason: String) = Decision(false, reason, null, 0, 0)
        }
    }

    // ---- hashing ----
    internal fun tagOf(kind: String): String = when (kind) {
        "header" -> MAP_TAG_HEADER
        "cell" -> MAP_TAG_CELL
        "metrics" -> MAP_TAG_METRICS
        "learner" -> MAP_TAG_LEARNER
        else -> throw IllegalArgumentException("unknown leaf kind")
    }

    internal fun u64be(n0: Long): ByteArray {
        var n = n0
        val out = ByteArray(8)
        for (i in 7 downTo 0) { out[i] = (n and 0xff).toByte(); n = n ushr 8 }
        return out
    }

    /** SHA-256(TAG_kind || salt || strictCanonical(leaf)); throws on a leaf without a strict canonical form. */
    fun leafHash(kind: String, salt: ByteArray?, leaf: Any?): ByteArray {
        if (salt == null || salt.size != 32) throw IllegalArgumentException("mapLeafHash: the salt is 32 bytes")
        return Pca.sha(IntentJs.utf8(tagOf(kind)), salt, IntentJs.canonBytes(leaf))
    }

    internal fun nodeHash(l: ByteArray, r: ByteArray): ByteArray = Pca.sha(IntentJs.utf8(MAP_TAG_NODE), l, r)
    internal fun commitOf(size: Long, root: ByteArray): String = Pca.b64(Pca.sha(IntentJs.utf8(MAP_TAG_COMMIT), u64be(size), root))

    private fun split(n: Long): Long {
        var k = 1L
        while (k * 2 < n) k *= 2
        return k
    }

    private fun treeRoot(hs: List<ByteArray>): ByteArray {
        if (hs.size == 1) return hs[0]
        val k = split(hs.size.toLong()).toInt()
        return nodeHash(treeRoot(hs.subList(0, k)), treeRoot(hs.subList(k, hs.size)))
    }

    /** The `primitives.intent_map_commit` entry point: the commitment of a full leaf list `[{kind, salt, leaf}]`. */
    fun commitLeaves(leaves: Any?): String {
        val ls = IntentJs.normalize(leaves) as List<*>
        if (ls.isEmpty()) throw IllegalArgumentException("mapTree: empty")
        val hs = ls.map { leafHash(IntentJs.get(it, "kind") as String, Pca.decodeB64uStrict(IntentJs.get(it, "salt"), 32), IntentJs.get(it, "leaf")) }
        return commitOf(hs.size.toLong(), treeRoot(hs))
    }

    /** RFC 9162 §2.1.3.2 inclusion with this file's node hash: the root, or null when the path does not fit (index, size). */
    internal fun rootFromPath(index: Long, size: Long, leafHash: ByteArray, path: List<ByteArray>): ByteArray? {
        if (!(index >= 0 && index < size)) return null
        var fn = index
        var sn = size - 1
        var r = leafHash
        for (p in path) {
            if (sn == 0L) return null
            if (fn % 2 == 1L || fn == sn) {
                r = nodeHash(p, r)
                if (fn % 2 == 0L) while (fn % 2 == 0L && fn != 0L) { fn /= 2; sn /= 2 }
            } else {
                r = nodeHash(r, p)
            }
            fn /= 2
            sn /= 2
        }
        return if (sn == 0L) r else null
    }

    // ---- leaf shapes (closed and typed) ----
    private fun isStr(v: Any?, max: Int): Boolean = v is String && !Json.hasLoneSurrogate(v) && IntentJs.u8len(v) <= max
    private fun closed(o: Any?, allowed: List<String>, required: List<String>): Boolean {
        val m = o as Map<*, *>
        return m.keys.all { it in allowed } && required.all { m.containsKey(it) }
    }
    private fun isDimPath(p: Any?): Boolean = p == "action.resource" || (p is String && PATH_RE.matches(p))
    private fun lng(o: Any?): Long = IntentJs.lng(o)
    private fun num(o: Any?): Double = IntentJs.num(o)!!

    /** The cells of a numeric dimension as inclusive [lo, hi] ranges (empty ranges dropped). */
    internal fun numCells(d: Map<String, Any?>): List<LongArray> {
        val out = ArrayList<LongArray>()
        var cur = lng(d["lo"])
        for (co in d["cuts"] as List<*>) {
            val c = lng(co)
            if (cur <= c - 1) out.add(longArrayOf(cur, c - 1))
            out.add(longArrayOf(c, c))
            cur = c + 1
        }
        val hi = lng(d["hi"])
        if (cur <= hi) out.add(longArrayOf(cur, hi))
        return out
    }

    private fun dimCells(d: Map<String, Any?>): Long = if (d["kind"] == "num") numCells(d).size.toLong() else (d["values"] as List<*>).size.toLong()

    private fun dimError(dO: Any?, j: Int): String? {
        if (dO !is Map<*, *>) return "dims[$j] must be an object"
        val d = IntentJs.obj(dO)
        when (d["kind"]) {
            "num" -> {
                val ks = listOf("kind", "path", "lo", "hi", "cuts")
                if (!closed(d, ks, ks)) return "dims[$j] must be exactly {kind, path, lo, hi, cuts}"
                if (!isDimPath(d["path"]) || d["path"] == "action.resource") return "dims[$j].path must be action.params.<name>"
                if (!IntentJs.isInt(d["lo"]) || !IntentJs.isInt(d["hi"]) || num(d["lo"]) > num(d["hi"])) return "dims[$j] lo / hi must be safe integers with lo <= hi"
                val cuts = d["cuts"]
                if (cuts !is List<*> || cuts.size > MAX_MAP_CUTS) return "dims[$j].cuts must be an array of at most $MAX_MAP_CUTS"
                var prev = Double.NEGATIVE_INFINITY
                for (c in cuts) {
                    if (!IntentJs.isInt(c) || num(c) <= prev || num(c) < num(d["lo"]) || num(c) > num(d["hi"]))
                        return "dims[$j].cuts must be strictly increasing safe integers in [lo, hi]"
                    prev = num(c)
                }
                return null
            }
            "cat" -> {
                val ks = listOf("kind", "path", "values")
                if (!closed(d, ks, ks)) return "dims[$j] must be exactly {kind, path, values}"
                if (!isDimPath(d["path"])) return "dims[$j].path must be action.resource or action.params.<name>"
                val vs = d["values"]
                if (vs !is List<*> || vs.isEmpty() || vs.size > MAX_MAP_VALUES) return "dims[$j].values must be an array of 1..$MAX_MAP_VALUES"
                val seen = HashSet<String>()
                val vk = listOf("kind", "value")
                for (i in vs.indices) {
                    val v = vs[i]
                    if (v !is Map<*, *> || !closed(v, vk, vk)) return "dims[$j].values[$i] must be exactly {kind, value}"
                    val k = v["kind"]
                    val value = v["value"]
                    if (k != "exact" && k != "prefix" && k != "other") return "dims[$j].values[$i].kind must be exact, prefix or other"
                    if (!isStr(value, MAX_MAP_STRING_BYTES)) return "dims[$j].values[$i].value must be a string of at most $MAX_MAP_STRING_BYTES UTF-8 bytes"
                    val badOther = if (k == "other") i != vs.size - 1 || value != MAP_OTHER else k == "prefix" && (value as String).isEmpty()
                    if (badOther) return "dims[$j].values: exactly one other ('$MAP_OTHER'), last; prefixes non-empty"
                    if (!seen.add("$k:$value")) return "dims[$j].values must be distinct"
                }
                if (IntentJs.get(vs[vs.size - 1], "kind") != "other") return "dims[$j].values must end with the other value"
                return null
            }
            else -> return "dims[$j].kind must be num or cat"
        }
    }

    /** Shape of a header leaf (closed, typed; `cells` equals the product of the dimensions' cell counts). Null = well-formed. */
    fun headerError(h: Any?): String? {
        val ks = listOf("verb", "first", "cells", "dims")
        if (h !is Map<*, *> || !closed(h, ks, ks)) return "the header leaf must be exactly {verb, first, cells, dims}"
        val verb = h["verb"]
        if (!isStr(verb, 128) || (verb as String).isEmpty()) return "header.verb must be a non-empty string of at most 128 UTF-8 bytes"
        val first = h["first"]
        if (!IntentJs.isNonNeg(first) || num(first) >= MAX_MAP_LEAVES) return "header.first must be a leaf index"
        val cells = h["cells"]
        if (!IntentJs.isInt(cells) || num(cells) < 1 || num(cells) > MAX_VERB_CELLS) return "header.cells must be a safe integer in [1, $MAX_VERB_CELLS]"
        val dims = h["dims"]
        if (dims !is List<*> || dims.size > MAX_MAP_DIMS) return "header.dims must be an array of at most $MAX_MAP_DIMS"
        val paths = HashSet<Any?>()
        var n = 1L
        for (j in dims.indices) {
            val e = dimError(dims[j], j)
            if (e != null) return "header.$e"
            val d = IntentJs.obj(dims[j])
            if (!paths.add(d["path"])) return "header.dims paths must be distinct"
            n *= dimCells(d)
            if (n > MAX_VERB_CELLS) return "header: too many cells"
        }
        if (n.toDouble() != num(cells)) return "header.cells is not the product of the dimensions' cell counts"
        return null
    }

    fun cellError(c: Any?): String? {
        val ks = listOf("verb", "cell", "p_ppm", "in_grant")
        if (c !is Map<*, *> || !closed(c, ks, ks)) return "the cell leaf must be exactly {verb, cell, p_ppm, in_grant}"
        val verb = c["verb"]
        if (!isStr(verb, 128) || (verb as String).isEmpty()) return "cell.verb must be a non-empty string of at most 128 UTF-8 bytes"
        val cell = c["cell"]
        if (cell !is List<*> || cell.size > MAX_MAP_DIMS || !cell.all { IntentJs.isNonNeg(it) }) return "cell.cell must be an array of non-negative safe integers"
        val p = c["p_ppm"]
        if (!IntentJs.isNonNeg(p) || num(p) > 1_000_000) return "cell.p_ppm must be a safe integer in [0, 1000000]"
        if (c["in_grant"] !is Boolean) return "cell.in_grant must be a boolean"
        return null
    }

    fun metricsError(m: Any?): String? {
        val allowed = METRIC_FIELDS + "log2_vs_mbits"
        if (m !is Map<*, *> || !closed(m, allowed, METRIC_FIELDS)) return "the metrics leaf must be exactly {${METRIC_FIELDS.joinToString(", ")}, log2_vs_mbits?}"
        for (k in allowed) {
            if (k == "log2_vs_mbits" && !m.containsKey(k)) continue
            if (!IntentJs.isNonNeg(m[k])) return "metrics.$k must be a non-negative safe integer"
        }
        return null
    }

    fun learnerError(l: Any?): String? {
        val ks = listOf("learner_digest")
        if (l !is Map<*, *> || !closed(l, ks, ks)) return "the learner leaf must be exactly {learner_digest}"
        return if (IntentJs.b32(l["learner_digest"])) null else "learner.learner_digest must be canonical base64url (32 bytes)"
    }

    /** Cell of ω under a well-formed header: (indices, flat), or null when a value lies outside its dimension. */
    internal fun cellOf(header: Map<String, Any?>, resource: Any?, params: Any?): Pair<LongArray, Long>? {
        val dims = header["dims"] as List<*>
        val cell = LongArray(dims.size)
        var flat = 0L
        for (j in dims.indices) {
            val d = IntentJs.obj(dims[j])
            val path = d["path"] as String
            val name = path.removePrefix("action.params.")
            val present = path == "action.resource" || (params is Map<*, *> && params.containsKey(name))
            val x = if (path == "action.resource") resource else if (present) (params as Map<*, *>)[name] else null
            var i = -1L
            if (d["kind"] == "num") {
                if (present && IntentJs.isInt(x)) {
                    val v = num(x)
                    val cs = numCells(d)
                    for (k in cs.indices) if (v >= cs[k][0] && v <= cs[k][1]) { i = k.toLong(); break }
                }
            } else if (present && x is String && !Json.hasLoneSurrogate(x)) {
                val vs = d["values"] as List<*>
                var best = -1
                var bestLen = -1
                for (k in vs.indices) {
                    val vk = IntentJs.get(vs[k], "kind")
                    val vv = IntentJs.get(vs[k], "value") as String
                    if (vk == "exact" && vv == x) { best = k; bestLen = Int.MAX_VALUE; break }
                    if (vk == "prefix" && x.startsWith(vv) && vv.length > bestLen) { best = k; bestLen = vv.length }
                }
                i = if (best >= 0) best.toLong() else (vs.size - 1).toLong()
            }
            if (i < 0) return null
            cell[j] = i
            flat = flat * dimCells(d) + i
        }
        return cell to flat
    }

    private fun entryShape(e: Any?, what: String): String? {
        val ks = listOf("index", "salt", "leaf", "path")
        if (e !is Map<*, *> || !closed(e, ks, ks)) return "disclosure.$what must be exactly {index, salt, leaf, path}"
        if (!IntentJs.isNonNeg(e["index"])) return "disclosure.$what.index must be a non-negative safe integer"
        if (!IntentJs.b32(e["salt"])) return "disclosure.$what.salt must be canonical base64url (32 bytes)"
        val path = e["path"]
        if (path !is List<*> || path.size > 64 || !path.all { IntentJs.b32(it) }) return "disclosure.$what.path must be an array of 32-byte digests"
        return null
    }

    /** Shape of a Z0 disclosure (closed, typed). Null = well-formed. */
    fun disclosureError(d: Any?): String? {
        val ks = listOf("size", "header", "cell", "metrics")
        if (d !is Map<*, *> || !closed(d, ks, ks)) return "the disclosure must be exactly {size, header, cell, metrics}"
        val size = d["size"]
        if (!IntentJs.isInt(size) || num(size) < 4 || num(size) > MAX_MAP_LEAVES) return "disclosure.size must be a safe integer in [4, $MAX_MAP_LEAVES]"
        for (k in listOf("header", "cell", "metrics")) entryShape(d[k], k)?.let { return it }
        return headerError(IntentJs.get(d["header"], "leaf")) ?: cellError(IntentJs.get(d["cell"], "leaf")) ?: metricsError(IntentJs.get(d["metrics"], "leaf"))
    }

    /** Does the disclosed entry `e` (leaf kind `kind`) open `commit` in a tree of `size` leaves? */
    private fun opens(kind: String, e: Any?, size: Long, commit: String): Boolean = try {
        val h = leafHash(kind, Pca.decodeB64uStrict(IntentJs.get(e, "salt"), 32), IntentJs.get(e, "leaf"))
        val path = (IntentJs.get(e, "path") as List<*>).map { Pca.decodeB64uStrict(it, 32)!! }
        val root = rootFromPath(lng(IntentJs.get(e, "index")), size, h, path)
        root != null && commitOf(size, root) == commit
    } catch (x: RuntimeException) {
        false
    }

    /**
     * Z0, the `map` check (rule 19) over normalized values. `paramsPresent` false = params absent ({}); `eps` null = no ε.
     * First failure wins; never throws.
     */
    fun decide(mapCommit: Any?, action: Any?, paramsPresent: Boolean, params: Any?, disclosure: Any?, eps: Double?): Decision {
        try {
            val de = disclosureError(disclosure)
            if (de != null) return Decision.bad("map disclosure malformed: $de")
            if (!IntentJs.b32(mapCommit)) return Decision.bad("the PCActn carries no map commitment")
            val commit = mapCommit as String
            if (paramsPresent && params !is Map<*, *>) return Decision.bad("params must be an object")
            val ps: Any? = if (paramsPresent) params else LinkedHashMap<String, Any?>()
            if (Pca.paramsDigest(ps) != IntentJs.get(action, "params_digest")) return Decision.bad("the params do not hash to action.params_digest")
            val hd = IntentJs.get(disclosure, "header")
            val cd = IntentJs.get(disclosure, "cell")
            val md = IntentJs.get(disclosure, "metrics")
            val h = IntentJs.obj(IntentJs.get(hd, "leaf"))
            val size = lng(IntentJs.get(disclosure, "size"))
            val first = lng(h["first"])
            if (h["verb"] != IntentJs.get(action, "verb")) return Decision.bad("the disclosed header is not the action's verb")
            if (!(lng(IntentJs.get(hd, "index")) < first) || !(first + lng(h["cells"]) <= size - 2)) return Decision.bad("the disclosed header does not fit the committed layout")
            if (!opens("header", hd, size, commit)) return Decision.bad("the header leaf does not open the map commitment")
            if (!opens("cell", cd, size, commit)) return Decision.bad("the cell leaf does not open the map commitment")
            if (!opens("metrics", md, size, commit)) return Decision.bad("the metrics leaf does not open the map commitment")
            val w = cellOf(h, IntentJs.get(action, "resource"), ps) ?: return Decision.bad("the action's value lies outside the committed map's dimension")
            val c = IntentJs.obj(IntentJs.get(cd, "leaf"))
            val cc = c["cell"] as List<*>
            var same = lng(IntentJs.get(cd, "index")) == first + w.second && c["verb"] == h["verb"] && cc.size == w.first.size
            if (same) for (i in cc.indices) if (lng(cc[i]) != w.first[i]) same = false
            if (!same) return Decision.bad("the disclosed cell is not the action's cell")
            if (c["in_grant"] != true) return Decision.bad("the action's cell is outside the committed grant")
            if (lng(IntentJs.get(md, "index")) != size - 2) return Decision.bad("the disclosed metrics leaf is not at its committed position")
            val risk = lng(IntentJs.get(IntentJs.get(md, "leaf"), "residual_risk_ppm"))
            if (eps != null && !(risk <= eps)) return Decision.bad("the committed residual risk $risk ppm exceeds ε = ${eps.toLong()}")
            return Decision(true, null, w.first.toList(), lng(c["p_ppm"]), risk)
        } catch (e: RuntimeException) {
            return Decision.bad("map error (fail closed): " + e.javaClass.simpleName)
        }
    }

    /**
     * The `primitives.intent_map` entry point: `{map_commit, action, params?, disclosure, max_residual_risk_ppm?}` (params
     * absent = {}; ε absent = none).
     */
    fun decidePrimitive(input: Any?): Decision = try {
        val inp = IntentJs.obj(IntentJs.normalize(input))
        val epsPresent = inp.containsKey("max_residual_risk_ppm")
        val eps = if (epsPresent) IntentJs.num(inp["max_residual_risk_ppm"]) else null
        if (epsPresent && eps == null) Decision.bad("max_residual_risk_ppm must be a number")
        else decide(
            inp["map_commit"], if (inp.containsKey("action")) inp["action"] else LinkedHashMap<String, Any?>(),
            inp.containsKey("params"), inp["params"], inp["disclosure"], eps,
        )
    } catch (e: RuntimeException) {
        Decision.bad("map error (fail closed): " + e.javaClass.simpleName)
    }
}
