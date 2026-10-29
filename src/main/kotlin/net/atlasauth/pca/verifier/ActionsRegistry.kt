package net.atlasauth.pca.verifier

/**
 * Action-kit registry layer (native port): signed evolution records, principal re-approvals, the grant pin decision, signed packs (with
 * shards), pack inclusion proofs, the rollback tracker and rule 22 over a whole v2 document. Natives verify signatures, digests and pins;
 * they do not recompute the semantic diff, so the tracker checks chain, version and signatures only. Pure and total: malformed input is a refusal.
 */
@Suppress("UNCHECKED_CAST")
object ActionsRegistry {
    private const val ACTION_PACK_KIND = "pca-action-pack"
    private val ON_NEW = listOf("deny", "escalate")
    private val EVOLUTION_CLASSES = listOf("equal", "narrow", "widen", "incomparable", "added", "removed")
    private const val EVOLUTION_RECORD_KIND = "pca-evolution-record"
    private const val REAPPROVAL_KIND = "pca-reapproval"
    private const val EVOLUTION_DOMAIN = "atlas-pca/action-evolution/v1\u0000"
    private const val EVOLUTION_DIFF_DOMAIN = "atlas-pca/action-evolution-diff/v1"
    private const val REAPPROVAL_DOMAIN = "atlas-pca/action-reapproval/v1\u0000"
    private const val MAX_EVOLUTION_STEPS = 32
    private const val MAX_ESC_TIER = 3
    private const val PACK_SIG_DOMAIN = "atlas-pca/action-pack/v1\u0000"
    private const val PACK_REF_DOMAIN = "atlas-pca/action-pack-ref/v1"
    private const val PACK_SHARD_DOMAIN = "atlas-pca/action-pack-shard/v1"
    private const val RULES_DIGEST_DOMAIN = "atlas-pca/action-rules/v1"
    private const val PACK_SHARD_KIND = "pca-action-pack-shard"
    private val STABILITIES = listOf("draft", "beta", "stable")
    private const val MAX_EVOLUTION_RECORDS = 65536

    private val B64U_43 = Regex("[A-Za-z0-9_-]{43}")
    private val NS_RE = Regex("[a-z0-9_]+(?:\\.[a-z0-9_]+){0,5}")
    private val VERB_RE = Regex("[a-z0-9_]+(?:\\.[a-z0-9_]+){1,5}")
    private val SEMVER_RE = Regex("(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})")
    private val SHARD_NAME_RE = Regex("[a-z0-9_]+(?:[.-][a-z0-9_]+){0,7}")
    private val CODES = listOf("schema_floor_forged", "schema_traits_forged", "unknown_trait", "traits_digest_mismatch", "bad_registry")

    private fun isObj(v: Any?) = v is Map<*, *>
    private fun sha(x: Any?) = x is String && B64U_43.matches(x)
    private fun is1(v: Any?) = v !is Boolean && IntentJs.isInt(v) && IntentJs.num(v) == 1.0
    private fun tier(x: Any?) = x !is Boolean && IntentJs.isInt(x) && IntentJs.num(x)!! in 0.0..MAX_ESC_TIER.toDouble()
    private fun closed(o: Map<*, *>, allowed: List<String>): String? {
        for (k in o.keys) if (k !in allowed) return "unknown member '$k'"
        return null
    }
    private fun m(x: Any?): Map<String, Any?> = x as Map<String, Any?>
    private fun withoutSig(x: Map<String, Any?>): Map<String, Any?> = LinkedHashMap(x).also { it.remove("sig") }

    // ---- evolution records -----------------------------------------------------------------------------------------------------

    fun evolutionRecordError(x: Any?, signed: Boolean = true): String? {
        if (!isObj(x)) return "evolution record must be an object"
        val r = m(x)
        closed(r, listOf("v", "kind", "ns", "verb", "from", "to", "class", "reasons") + (if (signed) listOf("sig") else listOf()))?.let { return "evolution record: $it" }
        if (!is1(r["v"]) || r["kind"] != EVOLUTION_RECORD_KIND) return "evolution record: bad v/kind"
        if (r["ns"] !is String || !NS_RE.matches(r["ns"] as String)) return "evolution record: bad ns"
        if (r["verb"] !is String || !VERB_RE.matches(r["verb"] as String)) return "evolution record: bad verb"
        if (r["from"] != null && !sha(r["from"])) return "evolution record: bad from"
        if (r["to"] != null && !sha(r["to"])) return "evolution record: bad to"
        val c = r["class"]
        if (c !is String || c !in EVOLUTION_CLASSES) return "evolution record: bad class"
        if ((c == "added") != (r["from"] == null) || (c == "removed") != (r["to"] == null)) return "evolution record: endpoints do not match the class"
        val rs = r["reasons"]
        if (rs !is List<*> || rs.size > 64 || rs.any { it !is String || it.length > 512 }) return "evolution record: bad reasons"
        if (signed) {
            val s = r["sig"]
            if (!isObj(s) || closed(s as Map<*, *>, listOf("alg", "kid", "value", "pq_value")) != null) return "evolution record: bad sig"
            val kid = s["kid"]
            if (kid !is String || kid.length !in 1..128 || s["value"] !is String || s["alg"] !is String) return "evolution record: bad sig"
            if (s.containsKey("pq_value") && s["pq_value"] !is String) return "evolution record: bad sig"
        }
        try { IntentJs.canonBytes(withoutSig(r)) } catch (e: RuntimeException) { return "evolution record: ${e.message}" }
        return null
    }

    /** Digest of ONE record's diff; throws when a member is absent (as the reference does). */
    fun evolutionDiffDigest(r: Map<String, Any?>): String {
        for (k in listOf("ns", "verb", "from", "to", "class", "reasons")) if (!r.containsKey(k)) throw IllegalArgumentException("missing $k")
        return Pca.hashCanonical(linkedMapOf("d" to EVOLUTION_DIFF_DOMAIN, "ns" to r["ns"], "verb" to r["verb"], "from" to r["from"], "to" to r["to"], "class" to r["class"], "reasons" to r["reasons"]))
    }

    /** Null = valid, else the reason. The suite comes from the pinned KEY entry. */
    fun verifyRegistrySig(domain: String, body: Any?, sig: Map<String, Any?>, keys: Any?): String? {
        try {
            if (keys !is List<*>) return "the registry keys must be an array"
            val key = keys.firstOrNull { isObj(it) && (it as Map<*, *>)["kid"] == sig["kid"] && it.containsKey("kid") }?.let { m(it) }
                ?: return "no registry key with kid '${sig["kid"]}'"
            if (key.containsKey("pq_pk") && key["pq_pk"] !is String) return "the registry key pq_pk must be a string"
            if (Pca.decodeB64uStrict(key["pk"], 32) == null) return "registry key pk is not canonical base64url (32 bytes)"
            val ka = IntentJs.suiteOf(key)
            if (ka == null || ka != IntentJs.suiteOf(sig)) return "sig.alg does not match the pinned key suite"
            val pk = key["pk"] as String
            val pin = if (key.containsKey("pq_pk")) IntentJs.pin(pk, key["pq_pk"]) else null
            if (!IntentJs.verifyPinnedSuite(ka, true, pk, key["pq_pk"], IntentJs.message(domain, body), sig["value"], sig["pq_value"], pin)) return "signature invalid"
            return null
        } catch (e: RuntimeException) {
            return "verification error: ${e.message}"
        }
    }

    /** Null = valid. */
    fun verifyEvolutionRecord(rec: Any?, keys: Any?): String? {
        evolutionRecordError(rec)?.let { return it }
        val r = m(rec)
        return verifyRegistrySig(EVOLUTION_DOMAIN, withoutSig(r), m(r["sig"]), keys)
    }

    fun reapprovalValid(r: Any?, grantId: Any?, issuer: Any?, verb: Any?, diff: Any?): Boolean = try {
        if (!isObj(r) || closed(r as Map<*, *>, listOf("v", "kind", "grant", "verb", "diff", "sig")) != null) false
        else if (!is1(r["v"]) || r["kind"] != REAPPROVAL_KIND || r["grant"] != grantId || r["verb"] != verb || r["diff"] != diff) false
        else {
            val s = r["sig"]
            if (!isObj(s) || closed(s as Map<*, *>, listOf("alg", "value")) != null || s["alg"] != "ed25519" || s["value"] !is String) false
            else IntentJs.verifyPinnedSuite("ed25519", true, issuer as? String, null, IntentJs.message(REAPPROVAL_DOMAIN, withoutSig(m(r))), s["value"], null, null)
        }
    } catch (e: RuntimeException) {
        false
    }

    // ---- the pin ---------------------------------------------------------------------------------------------------------------

    fun actionPinError(x: Any?): String? {
        if (!isObj(x)) return "actions must be an object"
        val p0 = m(x)
        closed(p0, listOf("pack", "defs", "on_new_action", "max_esc", "preauth_esc", "caveats"))?.let { return "actions: $it" }
        val p = p0["pack"]
        if (!isObj(p) || closed(p as Map<*, *>, listOf("ns", "root")) != null) return "actions.pack must be {ns, root}"
        if (p["ns"] !is String || !NS_RE.matches(p["ns"] as String)) return "actions.pack.ns is not a namespace"
        if (!sha(p["root"])) return "actions.pack.root must be a base64url digest"
        if (p0["on_new_action"] !is String || p0["on_new_action"] !in ON_NEW) return "actions.on_new_action must be 'deny' or 'escalate'"
        if (p0.containsKey("max_esc") && !tier(p0["max_esc"])) return "actions.max_esc must be an integer tier 0..3"
        if (p0.containsKey("preauth_esc") && !tier(p0["preauth_esc"])) return "actions.preauth_esc must be an integer tier 0..3"
        if (tier(p0["max_esc"]) && tier(p0["preauth_esc"]) && IntentJs.num(p0["preauth_esc"])!! > IntentJs.num(p0["max_esc"])!!) return "actions.preauth_esc exceeds actions.max_esc"
        if (p0.containsKey("caveats")) {
            val c = p0["caveats"]
            if (c !is List<*> || c.any { it !is String || it !in Actions.CAVEAT_KINDS } || c.toSet().size != c.size) return "actions.caveats must be distinct caveat kinds"
        }
        if (p0.containsKey("defs")) {
            val d = p0["defs"]
            if (!isObj(d)) return "actions.defs must be an object"
            for ((verb, dg) in d as Map<*, *>) {
                if (!VERB_RE.matches(verb as String)) return "actions.defs: '$verb' is not a verb"
                if (!sha(dg)) return "actions.defs.$verb must be a base64url digest"
            }
        }
        return null
    }

    private fun deny(code: String, reason: String, escalate: Boolean = false, needs: String? = null): Map<String, Any?> {
        val o = linkedMapOf<String, Any?>("ok" to false, "code" to code, "escalate" to escalate, "reason" to reason)
        if (needs != null) o["needs_reapproval"] = needs
        return o
    }

    private class Edge(val to: String, val blocked: String?)
    private class Parent(val from: String, val blocked: String?)

    /** Decide the pin for one verb: exact digest, pack root, or a chain of verified equal/narrow (or principal-approved) evolution steps. */
    fun decidePin(i: Map<String, Any?>): Map<String, Any?> {
        try {
            actionPinError(i["pin"])?.let { return deny("bad_pin", it) }
            val pin = m(i["pin"])
            val doc = i["doc"]
            val verb = i["verb"] as String
            val verbs = if (isObj(doc)) m(doc)["verbs"] else null
            val v = if (verbs is List<*>) verbs.firstOrNull { isObj(it) && (it as Map<*, *>).containsKey("verb") && it["verb"] == verb } else null
            if (v == null) return deny("unknown_verb", "the accepted schema does not declare '$verb'")
            val pack = m(pin["pack"])
            val pk = m(doc)["pack"]
            if (!isObj(pk) || !(pk as Map<*, *>).containsKey("ns") || pk["ns"] != pack["ns"]) return deny("pack_mismatch", "the schema does not come from the pinned pack '${pack["ns"]}'")
            if (!pin.containsKey("defs")) {
                return if (pk.containsKey("root") && pk["root"] == pack["root"]) linkedMapOf("ok" to true, "via" to "pack")
                else deny("pack_mismatch", "the pack root differs from the pinned root (the grant pins the pack as a whole)")
            }
            val defs = m(pin["defs"])
            if (!defs.containsKey(verb)) return deny("new_action", "the grant does not name '$verb' (on_new_action: ${pin["on_new_action"]})", pin["on_new_action"] == "escalate")
            val pinned = defs[verb] as String
            val presented = m(v)["def"]
            if (presented !is String) return deny("def_changed", "the schema verb carries no definition digest")
            if (presented == pinned) return linkedMapOf("ok" to true, "via" to "exact")
            val edges = HashMap<String, MutableList<Edge>>()
            val keys = i["keys"] ?: listOf<Any?>()
            val grant = m(i["grant"])
            for (r in (i["records"] as? List<*>) ?: listOf<Any?>()) {
                if (verifyEvolutionRecord(r, keys) != null) continue
                val rec = m(r)
                if (rec["ns"] != pack["ns"] || rec["verb"] != verb || rec["from"] == null || rec["to"] == null) continue
                val diff = evolutionDiffDigest(rec)
                val free = rec["class"] == "equal" || rec["class"] == "narrow"
                val approved = free || ((i["reapprovals"] as? List<*>) ?: listOf<Any?>()).any { reapprovalValid(it, grant["id"], grant["issuer"], verb, diff) }
                edges.getOrPut(rec["from"] as String) { ArrayList() }.add(Edge(rec["to"] as String, if (approved) null else diff))
            }
            fun search(usableOnly: Boolean): Map<String, Parent> {
                val parent = HashMap<String, Parent>()
                val seen = hashSetOf(pinned)
                var frontier = listOf(pinned)
                var step = 0
                while (step < MAX_EVOLUTION_STEPS && frontier.isNotEmpty() && presented !in parent) {
                    val next = ArrayList<String>()
                    for (f in frontier) for (e in edges[f] ?: listOf<Edge>()) {
                        if (e.to in seen || (usableOnly && e.blocked != null)) continue
                        seen.add(e.to)
                        parent[e.to] = Parent(f, e.blocked)
                        next.add(e.to)
                    }
                    frontier = next
                    step++
                }
                return parent
            }
            if (presented in search(true)) return linkedMapOf("ok" to true, "via" to "chain")
            val all = search(false)
            if (presented in all) {
                var first: String? = null
                var cur = presented
                while (cur != pinned) {
                    val p = all[cur]!!
                    if (p.blocked != null) first = p.blocked
                    cur = p.from
                }
                return deny("def_changed", "the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve", false, first)
            }
            return deny("def_changed", "the definition differs from the pinned digest and no signed evolution record chains to it")
        } catch (e: RuntimeException) {
            return deny("bad_pin", "pin evaluation error (fail closed): ${e.message}")
        }
    }

    // ---- signed packs ----------------------------------------------------------------------------------------------------------

    fun compareVersions(a: String, b: String): Int {
        val pa = SEMVER_RE.matchEntire(a)
        val pb = SEMVER_RE.matchEntire(b)
        if (pa == null || pb == null) throw ActionKitError("bad_version", "'${if (pa == null) a else b}' is not MAJOR.MINOR.PATCH")
        for (k in 1..3) {
            val d = pa.groupValues[k].toLong() - pb.groupValues[k].toLong()
            if (d != 0L) return if (d < 0) -1 else 1
        }
        return 0
    }

    fun rulesDigest(): String = Pca.hashCanonical(linkedMapOf("d" to RULES_DIGEST_DOMAIN, "prules" to Actions.PARAM_RULE_IDS, "caveats" to Actions.CAVEAT_KINDS, "context" to Actions.CONTEXT_KEYS))
    fun packDigest(p: Any?): String = Pca.hashCanonical(linkedMapOf("d" to PACK_REF_DOMAIN, "p" to p))
    fun shardDigest(s: Any?): String = Pca.hashCanonical(linkedMapOf("d" to PACK_SHARD_DOMAIN, "s" to s))

    private fun sortedUniqueDefsError(defs: List<*>): String? {
        for (i in defs.indices) {
            Actions.validateDef(defs[i])?.let { return "def $i: $it" }
            if (i > 0 && (m(defs[i - 1])["verb"] as String) >= (m(defs[i])["verb"] as String)) return "defs must be sorted by verb and unique (at '${m(defs[i])["verb"]}')"
        }
        return null
    }

    fun packShapeError(x: Any?, signed: Boolean = true): String? {
        try {
            if (!isObj(x)) return "pack must be an object"
            val p = m(x)
            closed(p, listOf("v", "kind", "ns", "version", "stability", "traits_digest", "roles_digest", "rules_digest", "root", "defs", "source", "prev", "evolution") + (if (signed) listOf("sig") else listOf()))?.let { return "pack: $it" }
            if (!is1(p["v"]) || p["kind"] != ACTION_PACK_KIND) return "pack: bad v/kind"
            if (p["ns"] !is String || !NS_RE.matches(p["ns"] as String)) return "pack: bad ns"
            if (p["version"] !is String || !SEMVER_RE.matches(p["version"] as String)) return "pack: version must be MAJOR.MINOR.PATCH"
            if (p["stability"] !is String || p["stability"] !in STABILITIES) return "pack: bad stability"
            for (k in listOf("traits_digest", "roles_digest", "rules_digest", "root")) if (!sha(p[k])) return "pack: $k must be a base64url digest"
            if (p["prev"] != null && !sha(p["prev"])) return "pack: bad prev"
            val s = p["source"]
            val sk = listOf("kind", "uri", "spec_digest", "licence", "licence_notes")
            if (!isObj(s) || closed(s as Map<*, *>, sk) != null) return "pack: source must be {kind, uri, spec_digest, licence, licence_notes}"
            for (k in sk) {
                val v = s[k]
                if (v !is String || (k != "licence_notes" && v.isEmpty()) || v.length > 2048) return "pack: source.$k is not a string of 1..2048 characters"
            }
            val d = p["defs"]
            if (d is List<*>) {
                if (d.isEmpty() || d.size > 4096) return "pack: inline defs must number 1..4096 (larger packs are sharded)"
                sortedUniqueDefsError(d)?.let { return "pack: $it" }
            } else {
                if (!isObj(d) || closed(d as Map<*, *>, listOf("shards")) != null || d["shards"] !is List<*> || (d["shards"] as List<*>).isEmpty() || (d["shards"] as List<*>).size > 4096) return "pack: defs must be a list of defs or {shards}"
                val names = HashSet<String>()
                for (r in d["shards"] as List<*>) {
                    if (!isObj(r) || closed(r as Map<*, *>, listOf("name", "digest", "uri")) != null) return "pack: bad shard ref"
                    val n = r["name"]
                    if (n !is String || !SHARD_NAME_RE.matches(n) || n in names) return "pack: shard names must be distinct simple names"
                    names.add(n)
                    val u = r["uri"]
                    if (!sha(r["digest"]) || u !is String || u.isEmpty() || u.length > 2048) return "pack: bad shard digest or uri"
                }
            }
            val ev = p["evolution"]
            if (ev !is List<*> || ev.size > MAX_EVOLUTION_RECORDS) return "pack: evolution must be a list of records"
            for (r in ev) evolutionRecordError(r)?.let { return "pack: $it" }
            if (signed) {
                val g = p["sig"]
                if (!isObj(g) || closed(g as Map<*, *>, listOf("alg", "kid", "value", "pq_value")) != null || g["kid"] !is String || g["value"] !is String || g["alg"] !is String) return "pack: bad sig"
            }
            Pca.hashCanonical(withoutSig(p))
            return null
        } catch (e: RuntimeException) {
            return "pack: ${e.message}"
        }
    }

    fun packDefs(pack: Map<String, Any?>, shards: Map<String, Any?>?): List<Map<String, Any?>> {
        val d = pack["defs"]
        if (d is List<*>) return d.map { m(it) }
        val all = ArrayList<Map<String, Any?>>()
        for (r0 in m(d)["shards"] as List<*>) {
            val r = m(r0)
            val s = shards?.get(r["name"] as String) ?: throw ActionKitError("missing_shard", "shard '${r["name"]}' was not supplied")
            if (shardDigest(s) != r["digest"]) throw ActionKitError("shard_digest_mismatch", "shard '${r["name"]}' does not match its digest")
            val sm = m(s)
            if (!is1(sm["v"]) || sm["kind"] != PACK_SHARD_KIND || sm["ns"] != pack["ns"] || sm["version"] != pack["version"] || sm["name"] != r["name"] || sm["defs"] !is List<*>)
                throw ActionKitError("bad_shard", "shard '${r["name"]}' is not a shard of this pack")
            (sm["defs"] as List<*>).forEach { all.add(m(it)) }
        }
        return all.sortedWith { a, b -> (a["verb"] as String).compareTo(b["verb"] as String) }
    }

    /** {ok:true, defs, digest} or {ok:false, reason}. Never throws. */
    fun verifyPack(pack: Any?, keys: Any?, shards: Map<String, Any?>? = null): Map<String, Any?> {
        fun fail(r: String) = linkedMapOf<String, Any?>("ok" to false, "reason" to r)
        try {
            packShapeError(pack)?.let { return fail(it) }
            val p = m(pack)
            verifyRegistrySig(PACK_SIG_DOMAIN, withoutSig(p), m(p["sig"]), keys)?.let { return fail("pack signature: $it") }
            if (p["traits_digest"] != Actions.traitsDigest(Actions.CORE_REGISTRY)) return fail("traits_digest does not match the trait registry")
            if (p["roles_digest"] != Actions.tablesDigest()) return fail("roles_digest does not match the vocabulary tables")
            if (p["rules_digest"] != rulesDigest()) return fail("rules_digest does not match the rule tables")
            val defs = try { packDefs(p, shards) } catch (e: ActionKitError) { return fail(e.message ?: "") }
            sortedUniqueDefsError(defs)?.let { return fail(it) }
            if (defs.isEmpty() || defs.size > 1_000_000) return fail("the pack lists no defs or too many")
            val digests = defs.map { Actions.defDigest(it) }
            if (Actions.packRoot(digests) != p["root"]) return fail("the Merkle root does not match the defs")
            val have = digests.toSet()
            for (r0 in p["evolution"] as List<*>) {
                val r = m(r0)
                verifyEvolutionRecord(r, keys)?.let { return fail("evolution record: $it") }
                if (r["ns"] != p["ns"]) return fail("evolution record of another namespace")
                if (r["to"] != null && r["to"] !in have) return fail("evolution record for '${r["verb"]}' names a definition that is not in the pack")
            }
            return linkedMapOf("ok" to true, "defs" to defs, "digest" to packDigest(p))
        } catch (e: RuntimeException) {
            return fail("pack verification error: ${e.message}")
        }
    }

    fun verifyPackProof(root: Any?, proof: Any?, digest: Any?): Boolean =
        root is String && digest is String && Actions.verifyPackProof(root, proof as? Map<String, Any?>, digest)

    /** The verifier's view of a registry: refuses rollback, fork and chain gap. The semantic diff of an upgrade is not recomputed natively. */
    class PackTracker(private val keys: Any?) {
        private val seen = HashMap<String, Pair<String, String>>()
        fun accept(pack: Any?, shards: Map<String, Any?>? = null): Map<String, Any?> {
            val v = verifyPack(pack, keys, shards)
            if (v["ok"] != true) return linkedMapOf("ok" to false, "code" to "bad_pack", "reason" to v["reason"])
            val p = m(pack)
            val ns = p["ns"] as String
            val ver = p["version"] as String
            val dg = v["digest"] as String
            val cur = seen[ns]
            if (cur == null) { seen[ns] = ver to dg; return linkedMapOf("ok" to true, "status" to "first") }
            if (cur.second == dg) return linkedMapOf("ok" to true, "status" to "same")
            val c = compareVersions(ver, cur.first)
            if (c < 0) return linkedMapOf("ok" to false, "code" to "rollback", "reason" to "older than the accepted version")
            if (c == 0) return linkedMapOf("ok" to false, "code" to "fork", "reason" to "two different packs claim one version")
            if (p["prev"] != cur.second) return linkedMapOf("ok" to false, "code" to "chain_gap", "reason" to "prev does not name the accepted pack")
            seen[ns] = ver to dg
            return linkedMapOf("ok" to true, "status" to "upgrade")
        }
    }

    // ---- rule 22 over a whole document -----------------------------------------------------------------------------------------

    /** `reviewers` are the verifier's pinned reviewer keys (see [Actions.reviewerPinsError]); absent = nothing is confirmed. */
    fun rule22Integrity(doc: Any?, reviewers: Any? = null): Map<String, Any?> {
        val e = Actions.schemaFloorError(m(doc), reviewers) ?: return linkedMapOf("ok" to true)
        return linkedMapOf("ok" to false, "code" to (CODES.firstOrNull { it in e } ?: "unknown"))
    }

    fun rule22Decide(doc: Any?, verb: String, grant: Map<String, Any?>, context: List<*>): String = try {
        val v = ((m(doc)["verbs"] as? List<*>) ?: listOf<Any?>()).firstOrNull { isObj(it) && (it as Map<*, *>)["verb"] == verb }
        if (v == null || Actions.profileError(m(v)["floors"]) != null) "deny"
        else Actions.floorDecision(
            linkedMapOf("caveats" to (grant["caveats"] as List<*>).filter { it is String && it in Actions.CAVEAT_KINDS }, "max_esc" to grant["max_esc"], "preauth_esc" to grant["preauth_esc"]),
            linkedMapOf("context" to context.filter { Actions.isContextKey(it) }), m(m(v)["floors"]),
        )
    } catch (e: RuntimeException) {
        "deny"
    }
}
