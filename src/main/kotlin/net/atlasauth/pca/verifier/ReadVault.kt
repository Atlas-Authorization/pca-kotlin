package net.atlasauth.pca.verifier

import java.security.SecureRandom
import net.atlasauth.pca.verifier.Workflow.ID_RE
import net.atlasauth.pca.verifier.Workflow.isB32
import net.atlasauth.pca.verifier.Workflow.isStr
import net.atlasauth.pca.verifier.Workflow.isUint
import net.atlasauth.pca.verifier.Workflow.obj
import net.atlasauth.pca.verifier.Workflow.onlyKeys
import net.atlasauth.pca.verifier.Workflow.sortedUnique
import net.atlasauth.pca.verifier.Workflow.verifyBody

/**
 * Tokenisation vault and aggregate read limits (K5 follow-up, C-315..C-319). Companion of [ReadSide]; mirrors packages/pca/src/read-vault.ts
 * check for check and replays packages/pca/conformance/vault-aggregate-vectors.json.
 *
 * VAULT. [redactReadWithVault] runs [ReadSide.redactRead] and records every `token` it minted (class, value, grant digest) in a [VaultStore];
 * [detokenize] returns the value only when the same signed, unexpired, pinned-principal grant lets the token's class reach the named sink
 * and the token was minted under THIS grant. Everything else denies.
 *
 * AGGREGATES. [aggregateRead] is a pure step over an explicit state `{spent_micro, queries, answered}`: it charges the epsilon budget,
 * refuses a group below k, and answers a repeated identical query from the state without charging again. With `dp: true` the answer gets
 * discrete Laplace noise from an INTEGER-EXACT sampler (Canonne-Kamath-Steinke) over SHA-256 blocks. Verification only: this SDK does not
 * sign grants. Total: nothing throws out of an entry point.
 */
object ReadVault {
    const val AGGREGATE_DOMAIN = "atlas-pca/aggregate-grant/v1\u0000"
    private const val AG_REF = "atlas-pca/aggregate-grant-ref/v1"
    private const val AG_Q = "atlas-pca/aggregate-query/v1"
    private const val AG_N = "atlas-pca/aggregate-noise/v1"
    private const val DP_STREAM = "atlas-pca/dp-stream/v1"
    private const val TWO48 = 1L shl 48
    private const val MAX_STEPS = 100_000

    // ---- vault ----

    /** What the vault remembers for one token. `value` is the original scalar (a parsed JSON string, boolean or number). */
    class VaultEntry(val cls: String, val value: Any?, val grant: String, val exp: Long)

    interface VaultStore {
        fun put(token: String, e: VaultEntry)
        fun get(token: String): VaultEntry?
    }

    class MemoryVault : VaultStore {
        private val m = HashMap<String, VaultEntry>()
        override fun put(token: String, e: VaultEntry) { synchronized(m) { m[token] = e } }
        override fun get(token: String): VaultEntry? = synchronized(m) { m[token] }
    }

    @JvmStatic
    fun memoryVault(): VaultStore = MemoryVault()

    /** [ReadSide.redactRead] that also records every token it minted in [store]. Never throws. */
    @JvmStatic
    fun redactReadWithVault(inp: ReadSide.ReadInput, store: VaultStore): ReadSide.ReadResult = try {
        val r = ReadSide.redactRead(inp)
        if (r.decision == "allow") {
            val g = obj(obj(inp.grant)!!["body"])!!
            val digest = ReadSide.readGrantDigest(g)
            val record = obj(inp.record)!!
            for ((path, f) in r.fields) {
                if (f.action == "masked" && f.kind == "token") {
                    store.put(r.view[path] as String, VaultEntry(f.cls, record[path], digest, Json.asLong(g["expires_at"])))
                }
            }
        }
        r
    } catch (e: Exception) {
        ReadSide.ReadResult("deny", "bad_request", emptyMap(), emptyMap(), emptyList(), emptyMap())
    }

    /** All members are parsed JSON values (or null) except [store]. */
    class DetokenizeInput(val grant: Any?, val principal: Any?, val now: Any?, val sink: Any?, val token: Any?, val store: VaultStore?)

    class DetokenizeResult(val decision: String, val code: String?, val value: Any?) {
        fun toMap(): Map<String, Any?> = linkedMapOf("decision" to decision, "code" to code, "value" to value)
    }

    private fun no(code: String) = DetokenizeResult("deny", code, null)

    /** Turn a token back into its value, only for a sink the grant allows that token's class to reach. Never throws. */
    @JvmStatic
    fun detokenize(inp: DetokenizeInput): DetokenizeResult = try {
        detok(inp)
    } catch (e: Exception) {
        no("bad_request")
    }

    private fun detok(inp: DetokenizeInput): DetokenizeResult {
        val store = inp.store
        if (store == null || !isB32(inp.principal) || !isUint(inp.now) || inp.token !is String || inp.sink !is String) return no("bad_request")
        val sg = obj(inp.grant)
        if (sg == null || !onlyKeys(sg, listOf("body", "sig")) || !ReadSide.validReadGrantBody(sg["body"])) return no("bad_grant")
        val body = obj(sg["body"])!!
        if (body["principal"] != inp.principal || !verifyBody(ReadSide.READ_GRANT_DOMAIN, body, inp.principal, sg["sig"])) return no("bad_signature")
        val now = Json.asLong(inp.now)
        if (now < Json.asLong(body["issued_at"])) return no("not_yet")
        if (now >= Json.asLong(body["expires_at"])) return no("expired")
        val e = store.get(inp.token)
        if (e == null || e.grant != ReadSide.readGrantDigest(body)) return no("unknown_token")
        if (now >= e.exp) return no("expired")
        val sinks = obj(body["sinks"])!!
        val rule = obj(sinks[inp.sink]) ?: return no("unknown_sink")
        if (strs(rule["allow"]).contains(e.cls)) return DetokenizeResult("allow", null, e.value)
        if (strs(rule["escalate"]).contains(e.cls)) return DetokenizeResult("escalate", "label_escalate", null)
        return no("label_flow")
    }

    private fun strs(o: Any?): List<String> = (o as List<*>).map { it as String }

    // ---- aggregates ----

    private val FN_RE = Regex("count|sum")

    private fun validRule(x: Any?): Boolean {
        val r = obj(x) ?: return false
        if (!onlyKeys(r, listOf("verb", "resource_prefix", "purposes", "fns", "min_group", "clamp", "epsilon_micro", "dp"))) return false
        if (!isStr(r["verb"], 128) || !isStr(r["resource_prefix"], 512) || !sortedUnique(r["purposes"], ID_RE, 16) || (r["purposes"] as List<*>).isEmpty() ||
            !sortedUnique(r["fns"], FN_RE, 2) || (r["fns"] as List<*>).isEmpty()) return false
        if (!isUint(r["min_group"]) || Json.asLong(r["min_group"]) < 1L || !isUint(r["clamp"]) || Json.asLong(r["clamp"]) > 1_000_000L ||
            !isUint(r["epsilon_micro"]) || Json.asLong(r["epsilon_micro"]) > 1_073_741_824L) return false
        val dp = r["dp"] as? Boolean ?: return false
        return !dp || Json.asLong(r["epsilon_micro"]) >= 1L
    }

    /** Shape of an aggregate grant body (no signature). */
    @JvmStatic
    fun validAggregateGrantBody(x: Any?): Boolean {
        val b = obj(x) ?: return false
        if (!onlyKeys(b, listOf("v", "id", "principal", "issued_at", "expires_at", "rules", "epsilon_budget_micro", "max_queries"))) return false
        if (!(Json.isSafeInt(b["v"]) && Json.asLong(b["v"]) == 1L)) return false
        val id = b["id"]
        if (id !is String || !ID_RE.matches(id) || !isB32(b["principal"]) || !isUint(b["issued_at"]) || !isUint(b["expires_at"])) return false
        val rules = b["rules"] as? List<*> ?: return false
        return rules.size in 1..16 && rules.all { validRule(it) } && isUint(b["epsilon_budget_micro"]) && isUint(b["max_queries"])
    }

    @JvmStatic
    fun aggregateGrantDigest(b: Any?): String = Pca.hashCanonical(linkedMapOf<String, Any?>("d" to AG_REF, "g" to b))

    /** The empty state `{spent_micro: 0, queries: 0, answered: {}}`. */
    @JvmStatic
    fun emptyAggregateState(): Map<String, Any?> = linkedMapOf("spent_micro" to 0L, "queries" to 0L, "answered" to LinkedHashMap<String, Any?>())

    /**
     * All members are parsed JSON values (or null). `values`: one integer per row (for `count` only the number of rows matters). `salt`: at least
     * 16 characters; with `noise = "seeded"` it (and the query digest) seeds the noise. `noise`: `"seeded"` is deterministic (vectors, tests,
     * reproducible audits); `"secure"` is the PRODUCTION setting: noise from the OS CSPRNG, so the answer is not reproducible. `state` is the
     * object [AggregateResult.state] returned last time (or [emptyAggregateState]).
     */
    class AggregateInput(
        val grant: Any?, val principal: Any?, val now: Any?, val verb: Any?, val resource: Any?, val purpose: Any?, val fn: Any?,
        val values: Any?, val salt: Any?, val noise: Any?, val state: Any?,
    )

    class AggregateResult(val decision: String, val code: String?, val value: Long?, val state: Any?, val chargedMicro: Long) {
        fun toMap(): Map<String, Any?> = linkedMapOf("decision" to decision, "code" to code, "value" to value, "state" to state, "charged_micro" to chargedMicro)
    }

    private fun clamp(v: Long, c: Long): Long = Math.max(-c, Math.min(c, v))

    /** Answer one aggregate under the grant, or refuse. The input state is never mutated. Never throws. */
    @JvmStatic
    fun aggregateRead(inp: AggregateInput): AggregateResult = try {
        aggregate(inp)
    } catch (e: Exception) {
        AggregateResult("deny", "bad_request", null, emptyAggregateState(), 0L)
    }

    private fun aggregate(inp: AggregateInput): AggregateResult {
        val st = obj(inp.state)
        val answered = obj(st?.get("answered"))
        if (st == null || !isUint(st["spent_micro"]) || !isUint(st["queries"]) || answered == null || !answered.values.all { Json.isSafeInt(it) })
            return AggregateResult("deny", "bad_request", null, emptyAggregateState(), 0L)
        fun keep(code: String) = AggregateResult("deny", code, null, st, 0L)
        if (!isB32(inp.principal) || !isUint(inp.now)) return keep("bad_request")
        val sg = obj(inp.grant)
        if (sg == null || !onlyKeys(sg, listOf("body", "sig")) || !validAggregateGrantBody(sg["body"])) return keep("bad_grant")
        val g = obj(sg["body"])!!
        if (g["principal"] != inp.principal || !verifyBody(AGGREGATE_DOMAIN, g, inp.principal, sg["sig"])) return keep("bad_signature")
        val now = Json.asLong(inp.now)
        if (now < Json.asLong(g["issued_at"])) return keep("not_yet")
        if (now >= Json.asLong(g["expires_at"])) return keep("expired")
        val verb = inp.verb
        val resource = inp.resource
        val purpose = inp.purpose
        val fn = inp.fn
        val salt = inp.salt
        val vals = inp.values as? List<*>
        if (!isStr(verb, 128) || !isStr(resource, 512) || purpose !is String || !ID_RE.matches(purpose) || (fn != "count" && fn != "sum") ||
            (inp.noise != "seeded" && inp.noise != "secure") || salt !is String || salt.length < 16 ||
            vals == null || vals.size > 1_000_000 || !vals.all { Json.isSafeInt(it) }) return keep("bad_request")
        verb as String
        resource as String
        fn as String
        val values = vals.map { Json.asLong(it) }
        val rule = (g["rules"] as List<*>).map { obj(it)!! }.find {
            it["verb"] == verb && resource.startsWith(it["resource_prefix"] as String) && purpose in strs(it["purposes"])
        }
        if (rule == null || fn !in strs(rule["fns"])) return keep("no_read_scope")
        if (values.size < Json.asLong(rule["min_group"])) return keep("group_too_small")
        val c = Json.asLong(rule["clamp"])
        val clampedSum = values.sumOf { clamp(it, c) }
        val qd = Pca.hashCanonical(
            linkedMapOf<String, Any?>(
                "d" to AG_Q, "g" to aggregateGrantDigest(g), "verb" to verb, "resource" to resource, "purpose" to purpose, "fn" to fn,
                "n" to values.size.toLong(), "s" to clampedSum,
            ),
        )
        val spent = Json.asLong(st["spent_micro"])
        val queries = Json.asLong(st["queries"])
        if (answered.containsKey(qd)) return AggregateResult("allow", null, Json.asLong(answered[qd]), st, 0L)
        if (queries + 1 > Json.asLong(g["max_queries"])) return keep("query_cap")
        val dp = rule["dp"] == true
        val eps = Json.asLong(rule["epsilon_micro"])
        val cost = if (dp) eps else 0L
        if (spent + cost > Json.asLong(g["epsilon_budget_micro"])) return keep("epsilon_exhausted")
        var exact = if (fn == "count") values.size.toLong() else clampedSum
        if (dp) {
            val sens = if (fn == "count") 1L else c
            val draws = if (inp.noise == "secure") secureDraws() else seededDraws(Pca.hashCanonical(linkedMapOf<String, Any?>("d" to AG_N, "salt" to salt, "q" to qd)))
            exact += discreteLaplace(draws, eps, sens * 1_000_000L)
        }
        val next = LinkedHashMap<String, Any?>(answered)
        next[qd] = exact
        return AggregateResult("allow", null, exact, linkedMapOf("spent_micro" to spent + cost, "queries" to queries + 1, "answered" to next), cost)
    }

    // ---- integer-exact discrete Laplace sampler (Canonne, Kamath, Steinke 2020, Alg. 1-2) ----
    // Integer arithmetic over a stream of 48-bit draws from SHA-256 blocks, so every language agrees byte for byte. All intermediate values
    // stay below 2^63, so signed 64-bit Long is exact. P[noise = x] is proportional to exp(-|x| * epsilon / sensitivity).

    /** A draw source. [uniform] throws [IllegalArgumentException] (the reference's RangeError) on a bad bound or no termination. */
    interface Draws {
        fun uniform(n: Long): Long
    }

    /** Block i is SHA-256 of the canonical `{d, seed, i}`; each block yields five 48-bit big-endian values (bytes 0-5, 6-11, ...), consumed in order. */
    class SeededDraws(private val seed: String) : Draws {
        private var block = 0L
        private val buf = LongArray(5)
        private var pos = 5

        private fun next48(): Long {
            if (pos == 5) {
                val bytes = Pca.decodeB64uStrict(Pca.hashCanonical(linkedMapOf<String, Any?>("d" to DP_STREAM, "seed" to seed, "i" to block++)), 32)!!
                for (k in 0 until 5) {
                    var v = 0L
                    for (j in 0 until 6) v = v * 256L + (bytes[k * 6 + j].toInt() and 0xff)
                    buf[k] = v
                }
                pos = 0
            }
            return buf[pos++]
        }

        override fun uniform(n: Long): Long {
            require(n >= 1L && n <= (1L shl 47)) { "uniform: bad bound" }
            val limit = TWO48 - (TWO48 % n)
            for (i in 0 until MAX_STEPS) {
                val r = next48()
                if (r < limit) return r % n
            }
            throw IllegalArgumentException("uniform: no draw")
        }
    }

    @JvmStatic
    fun seededDraws(seed: String): Draws = SeededDraws(seed)

    /** The PRODUCTION mode: a fresh 32-byte seed (base64url, unpadded) from the OS CSPRNG. Answers differ per call; a repeated query is still answered from the state. */
    @JvmStatic
    fun secureDraws(): Draws {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return SeededDraws(Pca.b64(bytes))
    }

    private fun bern(d: Draws, num: Long, den: Long): Boolean = d.uniform(den) < num

    /** Bernoulli(exp(-num/den)) for 0 <= num/den <= 1. */
    private fun bernExpSmall(d: Draws, num: Long, den: Long): Boolean {
        for (k in 1..MAX_STEPS) if (!bern(d, num, den * k)) return k % 2 == 1
        throw IllegalArgumentException("bernoulli: no termination")
    }

    /** Discrete Laplace with P[x] proportional to exp(-|x| s / t) (CKS Alg. 2: s is the rate numerator, t the scale denominator). */
    @JvmStatic
    fun discreteLaplace(d: Draws, s: Long, t: Long): Long {
        for (outer in 0 until MAX_STEPS) {
            val u = d.uniform(t)
            if (!bernExpSmall(d, u, t)) continue
            var v = 0L
            while (bernExpSmall(d, 1L, 1L)) if (++v > MAX_STEPS) throw IllegalArgumentException("laplace: no termination")
            val y = (u + t * v) / s
            val negative = d.uniform(2L) == 1L
            if (negative && y == 0L) continue
            return if (negative) -y else y
        }
        throw IllegalArgumentException("laplace: no sample")
    }
}
