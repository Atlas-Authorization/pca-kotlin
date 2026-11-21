package net.atlasauth.pca.verifier

import java.text.Normalizer
import java.util.Locale
import net.atlasauth.pca.compliance.ComplianceJs

/**
 * Objective risk functional (objective-risk.ts). Every input of the heuristic r is a pure function of COMMITTED facts and of the CANONICAL
 * ACTION (verb + resource + params, canonicalized like the PCActn). Nothing the agent merely asserts (features, labels, scope, confidence)
 * is read. Agent and verifier recompute the same r; the grant commits the registry, graph, embedder and goal, and a mismatch fails closed
 * (r = 1). The output feeds the existing [Risk.riskScore].
 *
 * Digests here are SERVER-ONLY (the language verifiers never recompute them) and carry high-precision floats, so they use the LENIENT
 * canonical hash. Actions, registries' entries, scopes and results are JSON trees (maps, lists, strings, booleans, [Json.Num]).
 */
@Suppress("UNCHECKED_CAST")
object ObjectiveRisk {
    const val METRIC = "half-chord-v1"
    const val NATIVE_SCHEME = "pca-native-hash-ngram-v1"
    const val DEFAULT_MAX_PARAM_LEAVES = 256
    const val DEFAULT_EPSILON = 1.0 / 4096
    private const val MAX_SAFE = 9007199254740991.0

    /** The default native embedder configuration. */
    @JvmField
    val DEFAULT_NATIVE_CONFIG: Map<String, Any?> = linkedMapOf(
        "dims" to Json.Num("256"), "ngramMin" to Json.Num("2"), "ngramMax" to Json.Num("4"), "seed" to "pca-native-v1",
        "fieldWeights" to linkedMapOf("verb" to Json.Num("4"), "resource" to Json.Num("2"), "param" to Json.Num("1")),
    )

    private fun n(d: Double): Json.Num = StoreJs.num(d)
    private fun n(l: Long): Json.Num = StoreJs.num(l)
    private fun num(o: Any?): Double? = IntentJs.num(o)
    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>
    private fun obj(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = Issue.obj(*kv)
    private fun clamp01(x: Double): Double = if (x.isNaN() || x.isInfinite()) 1.0 else if (x < 0) 0.0 else if (x > 1) 1.0 else x
    private fun cmp(a: String, b: String): Int = a.compareTo(b) // UTF-16 code-unit order, as JavaScript `<`
    private fun hash(v: Any?): String = Pca.hashCanonicalLenient(v)
    private fun typeError(m: String) = IllegalArgumentException(m)

    /** JavaScript `Number(v)` of a possibly absent member. */
    private fun jsNum(m: Map<String, Any?>?, k: String): Double = if (m == null || !m.containsKey(k)) Double.NaN else ComplianceJs.toNumber(m[k])

    // ---- canonical action ----

    private fun isJsSpace(c: Char): Boolean =
        c in '\u0009'..'\u000D' || c == ' ' || c == ' ' || c == ' ' || c in ' '..' ' || c == ' ' || c == ' ' ||
            c == ' ' || c == ' ' || c == '　' || c == '﻿'

    /** JavaScript `String.prototype.trim`. */
    private fun jsTrim(s: String): String {
        var a = 0
        var b = s.length
        while (a < b && isJsSpace(s[a])) a++
        while (b > a && isJsSpace(s[b - 1])) b--
        return s.substring(a, b)
    }

    private fun nfc(s: String): String = Normalizer.normalize(s, Normalizer.Form.NFC)

    private fun normValue(v: Any?): Any? = when (v) {
        is String -> nfc(v)
        is List<*> -> v.map { normValue(it) }
        is Map<*, *> -> {
            val out = LinkedHashMap<String, Any?>()
            for ((k, x) in v) {
                val nk = nfc(k as String)
                if (out.containsKey(nk)) throw typeError("canonicalAction: duplicate key after NFC normalization")
                out[nk] = normValue(x)
            }
            out
        }
        else -> v
    }

    /**
     * Canonical form `{verb, resource, params}`: verb NFC, trimmed and lowercased, resource NFC and trimmed, all strings and keys inside params
     * NFC, params validated by the lenient canonical encoder. Throws IllegalArgumentException on anything without a stable encoding.
     */
    fun canonicalAction(a: Any?): Map<String, Any?> {
        val m = map(a)
        val v0 = m?.get("verb")
        val r0 = m?.get("resource")
        if (v0 !is String || r0 !is String) throw typeError("canonicalAction: verb/resource must be strings")
        val verb = jsTrim(nfc(v0)).lowercase(Locale.ROOT)
        val resource = jsTrim(nfc(r0))
        if (verb.isEmpty() || resource.isEmpty()) throw typeError("canonicalAction: empty verb/resource")
        val params = normValue(m["params"] ?: LinkedHashMap<String, Any?>())
        if (params !is Map<*, *>) throw typeError("canonicalAction: params must be an object")
        val c = obj("verb" to verb, "resource" to resource, "params" to params)
        Json.canonicalize(c) // validate
        return c
    }

    fun canonicalActionJson(c: Any?): String = Json.canonicalize(c)

    fun canonicalActionDigest(c: Any?): String = hash(c)

    // ---- 1. reversibility: a committed registry of verified inverses ----

    interface InverseRegistry {
        fun lookup(verb: String): Map<String, Any?>?

        /** Verifier ids whose verification counts; committed as part of the digest. */
        fun trustedVerifiers(): List<String>

        /** Canonical digest of ALL contents; the grant commits this. */
        fun digest(): String
    }

    class InMemoryInverseRegistry @JvmOverloads constructor(trustedVerifiers: List<String> = emptyList()) : InverseRegistry {
        private val m = LinkedHashMap<String, Map<String, Any?>>()
        private val trusted: List<String> = LinkedHashSet(trustedVerifiers).sortedWith { a, b -> cmp(a, b) }

        fun register(verb: String, e: Map<String, Any?>): InMemoryInverseRegistry {
            val copy = LinkedHashMap(e)
            val ver = e["verification"]
            if (ZkJs.truthy(ver)) copy["verification"] = LinkedHashMap(ver as Map<String, Any?>)
            m[verb] = copy
            return this
        }

        override fun lookup(verb: String): Map<String, Any?>? = m[verb]?.let { LinkedHashMap(it) }

        override fun trustedVerifiers(): List<String> = trusted

        override fun digest(): String {
            val entries = m.entries.sortedWith { a, b -> cmp(a.key, b.key) }.map { (verb, e) ->
                val row = obj("verb" to verb)
                if (e.containsKey("inverseKind")) row["inverseKind"] = e["inverseKind"]
                if (e.containsKey("fidelity")) row["fidelity"] = e["fidelity"]
                row["verification"] = e["verification"]
                row
            }
            return hash(obj("v" to n(1L), "trusted" to trusted, "entries" to entries))
        }
    }

    /**
     * Reversible iff the registry holds an inverse whose verification came from a TRUSTED verifier AND the inverse verb is itself authorized by
     * the capability: `{class, value, inverseKind?}` (reversible 1, compensable 0.5, irreversible 0). Inverses of inverses are not chased.
     */
    fun reversibility(action: Map<String, Any?>, registry: InverseRegistry, authorizedKinds: Set<String>): Map<String, Any?> {
        val e = registry.lookup(action["verb"] as String)
        val ver = e?.get("verification")
        val trusted = if (ZkJs.truthy(ver)) registry.trustedVerifiers().contains((ver as Map<String, Any?>)["verifierId"]) else false
        if (e == null || !trusted || !authorizedKinds.contains(e["inverseKind"])) return obj("class" to "irreversible", "value" to n(0L))
        return if (e["fidelity"] == "exact") obj("class" to "reversible", "value" to n(1L), "inverseKind" to e["inverseKind"])
        else obj("class" to "compensable", "value" to n(0.5), "inverseKind" to e["inverseKind"])
    }

    // ---- 2. blast radius: reachability over a committed resource graph ----

    /** Adjacency model with a content digest the grant commits. */
    class ResourceGraph {
        private val nodes = LinkedHashMap<String, Map<String, Any?>>()
        private val out = LinkedHashMap<String, MutableList<Map<String, Any?>>>()

        fun addNode(nd: Map<String, Any?>): ResourceGraph {
            val id = nd["id"] as String
            nodes[id] = nd
            if (!out.containsKey(id)) out[id] = ArrayList()
            return this
        }

        fun addEdge(e: Map<String, Any?>): ResourceGraph {
            if (!nodes.containsKey(e["from"]) || !nodes.containsKey(e["to"])) throw IllegalStateException("edge endpoints must exist")
            out[e["from"] as String]!!.add(e)
            return this
        }

        val size: Int get() = nodes.size

        fun node(id: String): Map<String, Any?>? = nodes[id]

        /** BFS reachable set (including [start]), edge-kind and depth restricted, sorted. */
        fun reachable(start: String, scope: Map<String, Any?>? = null): List<String> {
            if (!nodes.containsKey(start)) return emptyList()
            val kindsO = scope?.get("edgeKinds")
            val kinds: List<Any?>? = if (ZkJs.truthy(kindsO)) kindsO as List<Any?> else null
            val maxDepth = if (scope == null || scope["maxDepth"] == null) Double.POSITIVE_INFINITY else (num(scope["maxDepth"]) ?: Double.NaN)
            val seen = LinkedHashSet<String>()
            seen.add(start)
            var frontier: List<String> = listOf(start)
            var d = 0.0
            while (d < maxDepth && frontier.isNotEmpty()) {
                val next = ArrayList<String>()
                for (u in frontier) for (e in out[u] ?: emptyList<Map<String, Any?>>()) {
                    val to = e["to"] as String
                    if ((kinds == null || kinds.contains(e["kind"])) && !seen.contains(to)) { seen.add(to); next.add(to) }
                }
                frontier = next
                d++
            }
            return seen.sortedWith { a, b -> cmp(a, b) }
        }

        fun digest(): String {
            val nl = nodes.values.map { obj("id" to it["id"], "harm" to (it["harm"] ?: LinkedHashMap<String, Any?>())) }.sortedWith { a, b -> cmp(a["id"] as String, b["id"] as String) }
            val el = out.values.flatten().map { obj("from" to it["from"], "to" to it["to"], "kind" to it["kind"]) }.sortedWith { a, b ->
                cmp("${a["from"]}\u0000${a["to"]}\u0000${a["kind"]}", "${b["from"]}\u0000${b["to"]}\u0000${b["kind"]}")
            }
            return hash(obj("v" to n(1L), "n" to nl, "e" to el))
        }
    }

    /** `{count, reachable, normalized, harm}`: `count / |graph|` in [0,1]; an unknown resource is 1 (fail closed). */
    fun blastRadius(action: Map<String, Any?>, graph: ResourceGraph, scope: Map<String, Any?>? = null): Map<String, Any?> {
        val reachable = graph.reachable(action["resource"] as String, scope)
        if (reachable.isEmpty() || graph.size == 0) return obj("count" to n(0L), "reachable" to reachable, "normalized" to n(1L), "harm" to LinkedHashMap<String, Any?>())
        val harm = LinkedHashMap<String, Double>()
        for (id in reachable) {
            val h = map(graph.node(id)?.get("harm")) ?: continue
            for ((d, v) in h) {
                val x = num(v)
                if (x != null && !x.isNaN() && !x.isInfinite() && x > 0) harm[d] = (harm[d] ?: 0.0) + x
            }
        }
        val hm = LinkedHashMap<String, Any?>()
        for ((k, v) in harm) hm[k] = n(v)
        return obj("count" to n(reachable.size.toLong()), "reachable" to reachable, "normalized" to n(reachable.size.toDouble() / graph.size), "harm" to hm)
    }

    // ---- 3. committed embeddings ----

    /**
     * An embedder maps the CANONICAL ACTION to an integer vector; it never sees agent-supplied features. [modelId] is a committed identity (a
     * hash of [config] for native, of the descriptor for BYO). [embed] MUST return `dims` safe integers; it may throw, and what it returns is
     * validated by the callers.
     */
    interface Embedder {
        val modelId: String
        val config: Any?
        val dims: Double
        fun embed(action: Map<String, Any?>): Any?
    }

    class EmbeddingError(message: String) : RuntimeException(message)

    private fun maxComponent(dims: Double): Double = Math.floor(Math.sqrt(MAX_SAFE / (2 * Math.max(1.0, dims))))

    private fun isSafeInt(x: Double?): Boolean = x != null && !x.isNaN() && !x.isInfinite() && x == Math.rint(x) && Math.abs(x) <= MAX_SAFE

    /** The vector with negative zero normalised, or throws [EmbeddingError]: exactly [dims] safe integers within the dot-product range. */
    fun validateVector(v: Any?, dims: Double): List<Double> {
        if (v !is List<*> || v.size.toDouble() != dims) throw EmbeddingError("vector must have exactly ${AttestUtil.jsNumString(dims)} components")
        val lim = maxComponent(dims)
        val out = ArrayList<Double>()
        for (x in v) {
            val d = num(x)
            if (!isSafeInt(d)) throw EmbeddingError("vector components must be safe integers")
            if (Math.abs(d!!) > lim) throw EmbeddingError("vector component out of range")
            out.add(if (d == 0.0) 0.0 else d)
        }
        return out
    }

    private fun vec(v: List<Double>): List<Any?> = v.map { n(it) }

    private fun okInt(x: Any?, lo: Double, hi: Double): Boolean {
        val d = num(x)
        return isSafeInt(d) && d!! >= lo && d <= hi
    }

    private fun validateNativeConfig(c: Map<String, Any?>) {
        if (!okInt(c["dims"], 8.0, 65536.0)) throw RangeError("native config: dims must be an integer in [8, 65536]")
        if (!okInt(c["ngramMin"], 1.0, 8.0) || !okInt(c["ngramMax"], num(c["ngramMin"])!!, 8.0)) throw RangeError("native config: need 1 <= ngramMin <= ngramMax <= 8")
        if (c["seed"] !is String || (c["seed"] as String).isEmpty()) throw RangeError("native config: seed required")
        val fw = map(c["fieldWeights"]) ?: throw typeError("Cannot read properties of undefined (reading 'verb')")
        for (k in listOf("verb", "resource", "param")) if (!okInt(fw[k], 0.0, 1000.0)) throw RangeError("native config: fieldWeights.$k must be an integer in [0, 1000]")
        if (c.containsKey("maxParamLeaves") && !okInt(c["maxParamLeaves"], 1.0, 1_000_000.0)) throw RangeError("native config: maxParamLeaves must be an integer in [1, 1000000]")
        if (c.containsKey("paramMode") && c["paramMode"] != "leaves" && c["paramMode"] != "digest") throw RangeError("native config: paramMode must be 'leaves' or 'digest'")
    }

    /** `RangeError` of the reference: a refused configuration. */
    class RangeError(message: String) : RuntimeException(message)

    /** Flatten params to sorted `path=value` leaves (nested key order and array encoding are irrelevant). */
    private fun paramLeaves(v: Any?, path: String, out: MutableList<String>) {
        when (v) {
            is List<*> -> v.forEachIndexed { i, x -> paramLeaves(x, "$path[$i]", out) }
            is Map<*, *> -> for (k in v.keys.map { it as String }.sortedWith { a, b -> Json.compareUtf8(a, b) }) paramLeaves(v[k], if (path.isNotEmpty()) "$path.$k" else k, out)
            else -> out.add("$path=${Json.canonicalize(v)}")
        }
    }

    private val WORD_SPLIT = Regex("[^\\p{L}\\p{N}]+")

    private fun textFeatures(prefix: String, text: String, nmin: Int, nmax: Int): List<String> {
        val out = ArrayList<String>()
        val cps = ("\u0002$text\u0003").codePoints().toArray()
        for (g in nmin..nmax) {
            var i = 0
            while (i + g <= cps.size) {
                val sb = StringBuilder()
                for (j in i until i + g) sb.appendCodePoint(cps[j])
                out.add("${prefix}c$g:$sb")
                i++
            }
        }
        for (w in text.split(WORD_SPLIT)) if (w.isNotEmpty()) out.add("${prefix}w:${w.lowercase(Locale.ROOT)}")
        return out
    }

    /**
     * Native embedder: for each field (verb, resource, each param leaf) code-point n-grams and word tokens; each feature f is hashed as
     * SHA-256(seed 0x1F f): bucket = big-endian u32(h[0..4]) mod dims, sign = low bit of h[4]; the bucket accumulates +-fieldWeight.
     * [config] defaults to [DEFAULT_NATIVE_CONFIG]. Throws [RangeError] on a bad configuration.
     */
    @JvmOverloads
    fun nativeHashEmbedder(config: Map<String, Any?> = DEFAULT_NATIVE_CONFIG): Embedder {
        validateNativeConfig(config)
        val cfg = LinkedHashMap(config)
        cfg["fieldWeights"] = LinkedHashMap(map(config["fieldWeights"])!!)
        val committed = LinkedHashMap<String, Any?>()
        committed["scheme"] = NATIVE_SCHEME
        committed.putAll(cfg)
        val modelId0 = "native:" + hash(committed)
        val dims0 = num(cfg["dims"])!!.toInt()
        val nmin = num(cfg["ngramMin"])!!.toInt()
        val nmax = num(cfg["ngramMax"])!!.toInt()
        val fw = map(cfg["fieldWeights"])!!
        val wVerb = num(fw["verb"])!!.toLong()
        val wRes = num(fw["resource"])!!.toLong()
        val wParam = num(fw["param"])!!.toLong()
        val prefix = Json.utf8((cfg["seed"] as String) + "\u001f")
        return object : Embedder {
            override val modelId: String = modelId0
            override val config: Any? = committed
            override val dims: Double = dims0.toDouble()

            override fun embed(action: Map<String, Any?>): Any? {
                val v = LongArray(dims0)
                fun add(feat: String, w: Long) {
                    if (w == 0L) return
                    val h = Pca.sha(prefix, Json.utf8(feat))
                    val b = ((h[0].toLong() and 0xff) shl 24) or ((h[1].toLong() and 0xff) shl 16) or ((h[2].toLong() and 0xff) shl 8) or (h[3].toLong() and 0xff)
                    val bucket = (b % dims0).toInt()
                    v[bucket] += if ((h[4].toInt() and 1) == 0) w else -w
                }
                for (f in textFeatures("v:", action["verb"] as String, nmin, nmax)) add(f, wVerb)
                for (f in textFeatures("r:", action["resource"] as String, nmin, nmax)) add(f, wRes)
                val leaves = ArrayList<String>()
                paramLeaves(action["params"], "", leaves)
                // fail CLOSED on a param-stuffed action: more leaves than the cap never produce a (diluted) favorable embedding
                val cap = if (cfg.containsKey("maxParamLeaves")) num(cfg["maxParamLeaves"])!!.toInt() else DEFAULT_MAX_PARAM_LEAVES
                if (leaves.size > cap) throw EmbeddingError("param leaf count ${leaves.size} exceeds cap $cap")
                if (cfg["paramMode"] == "digest") {
                    add("p#:" + hash(obj("t" to "pca-objrisk-params-v1", "params" to action["params"])), wParam)
                } else {
                    for (leaf in leaves) for (f in textFeatures("p:", leaf, nmin, nmax)) add(f, wParam)
                }
                return v.map { n(it) }
            }
        }
    }

    // ---- BYO: a customer-supplied model that meets the determinism contract ----

    /** `"byo:" + hash(descriptor)`. */
    fun byoModelId(descriptor: Map<String, Any?>): String = "byo:" + hash(descriptor)

    /**
     * [infer] receives the canonical action JSON and returns the integer vector. If [claimedModelId] is given it must equal the descriptor hash.
     * Throws [RangeError] on a bad descriptor.
     */
    @JvmOverloads
    fun byoEmbedder(descriptor: Map<String, Any?>, infer: (String) -> Any?, claimedModelId: String? = null): Embedder {
        val dims0 = num(descriptor["dims"])
        if (!isSafeInt(dims0) || dims0!! < 1) throw RangeError("byo: dims must be a positive integer")
        val q = map(descriptor["quantization"]) ?: throw typeError("Cannot read properties of undefined (reading 'bits')")
        val bits = num(q["bits"])
        if (!isSafeInt(bits) || bits!! < 2 || bits > 31 || !(ComplianceJs.toNumber(q["scale"]) > 0)) throw RangeError("byo: invalid quantization") // `scale > 0` coerces ("1" is 1)
        if (descriptor["inputEncoding"] != "pca-canonical-action-json-v1") throw RangeError("byo: unsupported inputEncoding")
        val modelId0 = byoModelId(descriptor)
        if (claimedModelId != null && claimedModelId != modelId0) throw IllegalStateException("byo: modelId does not match the committed descriptor")
        val qmax = Math.pow(2.0, bits - 1) - 1
        return object : Embedder {
            override val modelId: String = modelId0
            override val config: Any? = descriptor
            override val dims: Double = dims0

            override fun embed(action: Map<String, Any?>): Any? {
                val v = validateVector(infer(canonicalActionJson(action)), dims0)
                for (x in v) if (Math.abs(x) > qmax) throw EmbeddingError("byo: component exceeds declared quantization range")
                return vec(v)
            }
        }
    }

    /** Run conformance cases `{action, vector}` shipped with a model; true iff all reproduce exactly. */
    fun conformanceCheck(e: Embedder, cases: List<Any?>): Boolean = try {
        cases.all { c ->
            val cm = c as Map<String, Any?>
            val v = e.embed(canonicalAction(cm["action"]))
            val want = cm["vector"] as List<Any?>
            v is List<*> && v.size == want.size && v.indices.all { i -> num(v[i]) != null && num(want[i]) != null && num(v[i])!! == num(want[i])!! }
        }
    } catch (t: Throwable) {
        if (!Contain.ok(t)) throw t
        false
    }

    // ---- goal commitment and distance ----

    private fun goalCommitInput(g: Map<String, Any?>): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for (k in listOf("embedderModelId", "config", "goalVector", "metric", "epsilon")) {
            if (!g.containsKey(k)) throw typeError("canonicalize: unsupported type undefined")
            m[k] = g[k]
        }
        return m
    }

    /** Embed the goal's CANONICAL action and bind it to this embedder: `{embedderModelId, config, goalVector, metric, epsilon, commit}`. */
    @JvmOverloads
    fun commitGoal(embedder: Embedder, goalAction: Any?, epsilon: Double = DEFAULT_EPSILON): Map<String, Any?> {
        if (!(epsilon > 0 && epsilon <= 1)) throw RangeError("epsilon must be in (0, 1]")
        val goalVector = validateVector(embedder.embed(canonicalAction(goalAction)), embedder.dims)
        val g = obj("embedderModelId" to embedder.modelId, "config" to embedder.config, "goalVector" to vec(goalVector), "metric" to METRIC, "epsilon" to n(epsilon))
        val out = LinkedHashMap(g)
        out["commit"] = hash(goalCommitInput(g))
        return out
    }

    /** `Checked<T>`: `{ok: true, value}` or `{ok: false, reason}`. */
    private fun fail(reason: String): Map<String, Any?> = obj("ok" to false, "reason" to reason)

    /** Verifies the commitment hashes AND is bound to exactly this embedder (id, config, dims): null when sound, else the first failing reason. */
    fun verifyGoalCommitment(goal: Any?, embedder: Embedder): String? {
        try {
            if (goal == null) return "Cannot read properties of null (reading 'metric')"
            val g = map(goal)
            if (g?.get("metric") != METRIC) return "unknown metric"
            val eps = jsNum(g, "epsilon")
            if (!(eps > 0 && eps <= 1)) return "bad epsilon"
            if (g["commit"] != hash(goalCommitInput(g))) return "goal commitment hash mismatch"
            if (g["embedderModelId"] != embedder.modelId) return "embedder modelId mismatch"
            if (hash(g["config"]) != hash(embedder.config)) return "embedder config mismatch"
            validateVector(g["goalVector"], embedder.dims)
            return null
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            return e.message ?: "invalid goal commitment"
        }
    }

    /** Integer vectors to `sin(theta/2) = sqrt((1-cos)/2)`, rounded up to the epsilon grid. Only IEEE `*`, `+`, `/` and `sqrt`, in this order. */
    @JvmOverloads
    fun vectorDistance(a: List<Any?>, b: List<Any?>, epsilon: Double = DEFAULT_EPSILON): Double {
        if (a.size != b.size) return 1.0
        var dot = 0.0
        var na = 0.0
        var nb = 0.0
        var same = true
        for (i in a.indices) {
            val x = num(a[i]) ?: Double.NaN
            val y = num(b[i]) ?: Double.NaN
            dot += x * y
            na += x * x
            nb += y * y
            if (x != y) same = false
        }
        if (na == 0.0 || nb == 0.0) return 1.0
        if (same) return 0.0
        val cos = Math.max(-1.0, Math.min(1.0, dot / Math.sqrt(na * nb)))
        val d = Math.sqrt((1 - cos) / 2)
        if (d < 1e-9) return 0.0 // float noise floor, far below epsilon
        return clamp01(Math.ceil(d / epsilon) * epsilon)
    }

    /** Distance to the committed goal: `{ok: true, value}`, or `{ok: false, reason}` on any commitment or embedding failure. */
    fun committedDistanceChecked(action: Map<String, Any?>, goal: Any?, embedder: Embedder): Map<String, Any?> {
        val bad = verifyGoalCommitment(goal, embedder)
        if (bad != null) return fail(bad)
        return try {
            val v = validateVector(embedder.embed(action), embedder.dims)
            val g = map(goal)!!
            obj("ok" to true, "value" to n(vectorDistance(vec(v), g["goalVector"] as List<Any?>, jsNum(g, "epsilon"))))
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            fail(e.message ?: "embedding failed")
        }
    }

    /** Convenience: accepts an agent submission, canonicalizes it, returns the distance (1 on any failure). */
    fun committedDistance(action: Any?, goal: Any?, embedder: Embedder): Double = try {
        val r = committedDistanceChecked(canonicalAction(action), goal, embedder)
        if (r["ok"] == true) num(r["value"])!! else 1.0
    } catch (e: Throwable) {
        if (!Contain.ok(e)) throw e
        1.0
    }

    // ---- 4. split-conformal calibration ----

    /**
     * `benignScores` = raw scores of acceptable actions, held out from tuning: calibrated r = 1 - (1 + #{s >= raw}) / (n + 1), non-decreasing in
     * raw. An empty set or non-finite raw gives 1.
     */
    fun calibrate(rawScore: Double, benignScores: List<Any?>): Double {
        val len = benignScores.size
        if (len == 0 || rawScore.isNaN() || rawScore.isInfinite()) return 1.0
        var ge = 0
        for (s in benignScores) if ((num(s) ?: Double.NaN) >= rawScore) ge++
        return 1 - (1.0 + ge) / (len + 1)
    }

    /** Split-conformal quantile (benign raw <= q with probability >= 1 - alpha): +Infinity when n is too small, null where the reference has no element. */
    fun conformalThreshold(benignScores: List<Any?>, alpha: Double): Double? {
        val len = benignScores.size
        val k = Math.ceil((len + 1) * (1 - alpha))
        if (len == 0 || k > len) return Double.POSITIVE_INFINITY
        val sorted = benignScores.map { num(it) ?: Double.NaN }.sortedWith { a, b -> val d = a - b; if (d < 0) -1 else if (d > 0) 1 else 0 }
        val idx = k - 1
        return if (idx.isNaN() || idx < 0 || idx >= sorted.size) null else sorted[idx.toInt()]
    }

    /** Digest of a calibration set, committed by the grant. */
    fun calibrationDigest(scores: List<Any?>): String {
        val sorted = scores.sortedWith { a, b -> val d = (num(a) ?: Double.NaN) - (num(b) ?: Double.NaN); if (d < 0) -1 else if (d > 0) 1 else 0 }
        return hash(obj("v" to n(1L), "scores" to sorted))
    }

    // ---- 5. harm currency ----

    /** `{units, normalized}`: the weighted saturating normalization of `units` over the denominations `{id, ceiling, weight}`, in [0,1]. */
    fun harmReport(units: Map<String, Any?>, denoms: List<Any?>): Map<String, Any?> {
        var numr = 0.0
        var den = 0.0
        for (dn in denoms) {
            val d = dn as Map<String, Any?>
            val weight = jsNum(d, "weight")
            val ceiling = jsNum(d, "ceiling")
            if (!(weight > 0) || !(ceiling > 0)) continue
            val id = d["id"]
            val key = if (id is String) id else IntentJs.num(id)?.let { AttestUtil.jsNumString(it) } ?: id.toString()
            val u = if (units.containsKey(key)) ComplianceJs.toNumber(units[key]) else 0.0
            numr += weight * Math.min(1.0, Math.max(0.0, u) / ceiling)
            den += weight
        }
        return obj("units" to units, "normalized" to n(if (den == 0.0) 1.0 else clamp01(numr / den)))
    }

    // ---- composition ----

    /** What [objectiveRisk] reads: the committed facts and the verifier's own measurements. */
    class ObjectiveRiskContext(
        val registry: InverseRegistry,
        val authorizedKinds: Set<String>,
        val graph: ResourceGraph,
        val scope: Map<String, Any?>?,
        val embedder: Embedder,
        val goal: Map<String, Any?>,
        /** `{registryDigest, graphDigest, calibrationDigest?}`: the digests the grant committed. */
        val commitments: Map<String, Any?>,
        val denominations: List<Any?>,
        val weights: Map<String, Any?>,
        /** L4 information-flow taint (verifier-computed). */
        val taint: Double,
        /** `ageSinceTouch(...)`. */
        val age: Double,
        /** Uncertainty from the separate attestation primitive in [0,1]; it can only RAISE r. */
        val attestedUncertainty: Double? = null,
        /** Committed benign raw scores; r becomes the conformal-calibrated value. */
        val calibration: List<Any?>? = null,
    )

    private fun worstInputs(): Map<String, Any?> = obj(
        "semanticDistance" to n(1L), "reversibility" to n(0L), "blastRadius" to n(1L), "taint" to n(1L), "confidence" to n(0L), "age" to n(1L),
    )

    private fun reject(reasons: List<String>): Map<String, Any?> = obj(
        "r" to n(1L), "valid" to false, "reasons" to ArrayList<Any?>(reasons), "raw" to n(1L), "inputs" to worstInputs(),
        "reversibility" to obj("class" to "irreversible", "value" to n(0L)),
        "blast" to obj("count" to n(0L), "reachable" to ArrayList<Any?>(), "normalized" to n(1L), "harm" to LinkedHashMap<String, Any?>()),
        "harm" to obj("units" to LinkedHashMap<String, Any?>(), "normalized" to n(1L)), "evidenceDigest" to "",
    )

    /**
     * Pure function of (canonical action, committed context). Any commitment mismatch (registry, graph, goal/embedder binding, calibration set)
     * or un-encodable action returns the fail-closed `r = 1` with `valid: false`. Blast input = max(count-normalized, harm-normalized). A graph
     * with a non-finite harm weight or a calibration set with a non-finite score cannot be digested: that throws (the reference does too).
     */
    fun objectiveRisk(submitted: Any?, ctx: ObjectiveRiskContext): Map<String, Any?> {
        val action: Map<String, Any?>
        try {
            action = canonicalAction(submitted)
        } catch (e: IllegalArgumentException) {
            return reject(listOf("action: ${e.message ?: "not canonicalizable"}"))
        }
        val reasons = ArrayList<String>()
        if (ctx.registry.digest() != ctx.commitments["registryDigest"]) reasons.add("registry digest does not match the committed digest")
        if (ctx.graph.digest() != ctx.commitments["graphDigest"]) reasons.add("graph digest does not match the committed digest")
        if (ctx.calibration != null) {
            if (!ctx.commitments.containsKey("calibrationDigest")) reasons.add("calibration set used without a committed digest")
            else if (calibrationDigest(ctx.calibration) != ctx.commitments["calibrationDigest"]) reasons.add("calibration digest does not match the committed digest")
        }
        val dist = committedDistanceChecked(action, ctx.goal, ctx.embedder)
        if (dist["ok"] != true) reasons.add("goal/embedder: ${dist["reason"]}")
        if (reasons.isNotEmpty()) return reject(reasons)

        val rev = reversibility(action, ctx.registry, ctx.authorizedKinds)
        val blast = blastRadius(action, ctx.graph, ctx.scope)
        val harm = harmReport(blast["harm"] as Map<String, Any?>, ctx.denominations)
        val uncertainty = clamp01(ctx.attestedUncertainty ?: 0.0)
        val blastIn = Math.max(
            num(blast["normalized"])!!,
            if (ctx.denominations.isNotEmpty() && (blast["harm"] as Map<*, *>).isNotEmpty()) num(harm["normalized"])!! else 0.0,
        )
        val inputs = obj(
            "semanticDistance" to dist["value"], "reversibility" to rev["value"], "blastRadius" to n(blastIn),
            "taint" to n(if (ctx.taint.isNaN() || ctx.taint.isInfinite()) 1.0 else ctx.taint), "confidence" to n(1 - uncertainty),
            "age" to n(if (ctx.age.isNaN() || ctx.age.isInfinite()) 1.0 else ctx.age),
        )
        val raw = Risk.riskScore(inputs, ctx.weights)
        val r = if (ctx.calibration != null) calibrate(raw, ctx.calibration) else raw
        val edgeKinds = ctx.scope?.get("edgeKinds")
        val evidenceDigest = hash(
            obj(
                "action" to canonicalActionDigest(action),
                "scope" to obj(
                    "edgeKinds" to (if (ZkJs.truthy(edgeKinds)) (edgeKinds as List<Any?>).sortedWith { a, b -> cmp(a as String, b as String) } else null),
                    "maxDepth" to ctx.scope?.get("maxDepth"),
                ),
                "authorized" to ctx.authorizedKinds.sortedWith { a, b -> cmp(a, b) },
                "registry" to ctx.commitments["registryDigest"], "graph" to ctx.commitments["graphDigest"], "goal" to ctx.goal["commit"],
                "calibration" to ctx.commitments["calibrationDigest"], "inputs" to inputs,
            ),
        )
        return obj(
            "r" to n(r), "valid" to true, "reasons" to ArrayList<Any?>(), "raw" to n(raw), "inputs" to inputs, "reversibility" to rev, "blast" to blast,
            "harm" to harm, "evidenceDigest" to evidenceDigest,
        )
    }

    // ---- dispute-game oracle ----

    /**
     * The objective oracle for the contestable dispute game: given a disputed input name and the frozen open-time snapshot, recompute that
     * input from the COMMITTED facts over the snapshot's canonical action. Never throws; a commitment mismatch or an un-encodable action gives
     * `{input, valid: false, reason}` (the dispute is indeterminate and slashes no one).
     */
    fun objectiveRiskOracle(ctx: ObjectiveRiskContext, input: Any?, snapshot: Any?): Map<String, Any?> {
        fun bad(reason: String) = obj("input" to input, "valid" to false, "reason" to reason)
        return try {
            val a = map(map(map(snapshot)?.get("action"))?.get("action"))
            if (a == null || a["verb"] !is String || a["resource"] !is String) return bad("snapshot action is missing a canonical verb/resource")
            val submitted = obj("verb" to a["verb"], "resource" to a["resource"], "params" to (a["params"].let { if (it is Map<*, *>) it else LinkedHashMap<String, Any?>() }))
            val res = objectiveRisk(submitted, ctx)
            if (res["valid"] != true) {
                val reasons = (res["reasons"] as List<Any?>).joinToString("; ")
                return bad(if (reasons.isEmpty()) "objective risk could not be reproduced" else reasons)
            }
            val inputs = res["inputs"] as Map<String, Any?>
            when (input) {
                "reversibility_class" -> obj("input" to input, "class" to (res["reversibility"] as Map<String, Any?>)["class"], "valid" to true)
                "reversibility" -> obj("input" to input, "value" to inputs["reversibility"], "valid" to true)
                "blastRadius" -> obj("input" to input, "value" to inputs["blastRadius"], "valid" to true)
                "semanticDistance" -> obj("input" to input, "value" to inputs["semanticDistance"], "valid" to true)
                else -> bad("unknown disputed input: ${if (input is String) input else IntentJs.num(input)?.let { AttestUtil.jsNumString(it) } ?: input.toString()}")
            }
        } catch (e: Throwable) {
            if (!Contain.ok(e)) throw e
            bad("objective oracle error (fail closed): ${e.message ?: "unknown"}")
        }
    }
}
