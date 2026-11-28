package net.atlasauth.pca.rag

import net.atlasauth.pca.policybridge.OpenFga
import net.atlasauth.pca.policybridge.PolicyBridge
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Pca

/**
 * FGA for RAG: retrieval-time, per-principal document filtering driven by the PCA policy evaluator (the pure core of the
 * TypeScript pca-rag package).
 *
 * FAIL CLOSED: a document is admitted only when a permit predicate cleanly matches one of its ACL entries (verb = relation,
 * resource = object) and no deny predicate matches. Anything unknown (no ACL, a malformed document, an incomplete policy
 * translation, an evaluator error) drops the document. Every decision is recorded ([Result.decision]), with a content
 * digest of the whole decision set.
 *
 * JSON values are the core's: Map, List, String, Boolean, numbers. A principal is a String id or a Map `{id, attributes?, env?}`.
 * A policy is a List of predicates, a Map `{openfga: {model, tuples}}`, a Map `{predicates, denies?, report?}` or an
 * already-compiled policy ([compilePolicy]).
 */
@Suppress("UNCHECKED_CAST")
object Rag {
    /** The admitted documents (candidate order) and the decision record (the proof trace). */
    class Result<D> internal constructor(@JvmField val documents: List<D>, @JvmField val decision: Map<String, Any?>)

    // ---- helpers ----

    private fun map(o: Any?): Map<String, Any?>? = o as? Map<String, Any?>

    private fun obj(vararg kv: Any?): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    private fun nonEmptyString(o: Any?): Boolean = o is String && o.isNotEmpty()

    // ---- documents and ACLs ----

    private fun isDocAcl(v: Any?): Boolean {
        val m = map(v)
        return m != null && nonEmptyString(m["relation"]) && nonEmptyString(m["object"])
    }

    private fun aclArray(acl: Any?): MutableList<Any?> {
        val out = ArrayList<Any?>()
        if (acl is List<*>) { for (a in acl) if (isDocAcl(a)) out.add(a) } else if (isDocAcl(acl)) out.add(acl)
        return out
    }

    /** A `relation:object` tag as an ACL entry; the split is at the FIRST colon, so an object id may contain colons. */
    private fun tagToAcl(tag: Any?): Map<String, Any?>? {
        if (tag !is String) return null
        val i = tag.indexOf(':')
        if (i <= 0 || i >= tag.length - 1) return null
        return obj("relation", tag.substring(0, i), "object", tag.substring(i + 1))
    }

    /** ACL entries from freeform `acl` (one entry or a list) and `tags` (`relation:object` strings) metadata. */
    @JvmStatic
    fun aclsFromMetadata(acl: Any?, tags: Any?): List<Any?> {
        val out = aclArray(acl)
        if (tags is List<*>) for (t in tags) tagToAcl(t)?.let { out.add(it) }
        return out
    }

    // ---- principal ----

    /**
     * The acting identity of a verified PCActn: its LEAF capability holder (map the key to your policy's identity with `opts.id`).
     * Throws on a PCActn with no capability chain, rather than producing an empty principal. [opts]: {id?, attributes?, env?}, may be null.
     */
    @JvmStatic
    fun principalFromPCActn(pcactn: Any?, opts: Map<String, Any?>?): Map<String, Any?> {
        val p = map(pcactn)
        val chain = p?.get("cap_chain")
        var holder: Any? = null
        if (chain is List<*> && chain.isNotEmpty()) holder = map(chain[chain.size - 1])?.get("holder")
        if (!nonEmptyString(holder)) throw IllegalArgumentException("principalFromPCActn: PCActn has no leaf capability holder")
        val out = LinkedHashMap<String, Any?>()
        out["id"] = opts?.get("id") ?: holder
        if (opts != null && opts.containsKey("attributes")) out["attributes"] = opts["attributes"]
        if (opts != null && opts.containsKey("env")) out["env"] = opts["env"]
        return out
    }

    private fun toPrincipal(p: Any?): Map<String, Any?>? = when (p) {
        is String -> obj("id", p)
        is Map<*, *> -> map(p)
        is List<*> -> LinkedHashMap() // a JavaScript array is an object with no id
        else -> null
    }

    // ---- policy compilation ----

    private fun incomplete(reason: String): Map<String, Any?> =
        obj("predicates", ArrayList<Any?>(), "denies", ArrayList<Any?>(), "incomplete", true, "incompleteReason", reason)

    /**
     * Compile any policy into `{predicates, denies, incomplete, incompleteReason?, report?}` (an already-compiled policy passes through).
     * A value that is not a policy, or a translation with errors, is INCOMPLETE: nothing is admitted.
     */
    @JvmStatic
    fun compilePolicy(policy: Any?): Map<String, Any?> {
        if (policy !is Map<*, *> && policy !is List<*>) return incomplete("no usable policy was supplied (fail closed)")
        if (policy is List<*>) return obj("predicates", policy, "denies", ArrayList<Any?>(), "incomplete", false)
        val p = map(policy)!!
        if (p["incomplete"] is Boolean) return p
        if (!p.containsKey("openfga") && p["predicates"] !is List<*>) return incomplete("the policy has no predicates and is not an OpenFGA policy (fail closed)")
        if (p.containsKey("openfga")) {
            val fga = map(p["openfga"])
            if (fga == null && p["openfga"] !is List<*>) return incomplete("the OpenFGA policy has no model (fail closed)")
            val f = fga ?: LinkedHashMap() // an array has no model or tuples
            val br = if (f.containsKey("tuples")) OpenFga.openfgaToPca(f["model"], f["tuples"]) else OpenFga.openfgaToPca(f["model"])
            val report = map(br["report"])
            return obj("predicates", br["predicates"], "denies", br["denies"], "report", report, "incomplete", hasErrors(report))
        }
        val denies = if (p["denies"] is List<*>) p["denies"] else ArrayList<Any?>()
        val out = obj("predicates", p["predicates"], "denies", denies)
        if (p.containsKey("report")) {
            val report = map(p["report"])
            if (report == null || report["errors"] == null) throw IllegalArgumentException("compilePolicy: report.errors is required") // the reference reads report.errors.length
            out["report"] = report
            out["incomplete"] = lengthPositive(report["errors"])
        } else out["incomplete"] = false
        return out
    }

    /** JavaScript `x.length > 0` for a JSON value that is not null. */
    private fun lengthPositive(x: Any?): Boolean = when (x) {
        is List<*> -> x.isNotEmpty()
        is String -> x.isNotEmpty()
        is Map<*, *> -> (x["length"] as? Json.Num)?.raw?.toDoubleOrNull()?.let { it > 0 } ?: false
        else -> false
    }

    private fun hasErrors(report: Map<String, Any?>?): Boolean = report != null && (report["errors"] as? List<*>)?.isNotEmpty() == true

    // ---- the filter ----

    private fun decideDocument(id: String, acls: List<Any?>, principal: Map<String, Any?>, compiled: Map<String, Any?>): Map<String, Any?> {
        if (compiled["incomplete"] == true) {
            val why = compiled["incompleteReason"]
            return obj("id", id, "allowed", false, "reason", if (why is String) why else "policy translation incomplete (fail closed)")
        }
        val pid = principal["id"]
        if (!nonEmptyString(pid)) return obj("id", id, "allowed", false, "reason", "no principal identity (fail closed)")
        if (acls.isEmpty()) return obj("id", id, "allowed", false, "reason", "no decidable ACL metadata (fail closed)")
        var last = "no relation grants access (fail closed)"
        val pol = obj("predicates", compiled["predicates"], "denies", compiled["denies"])
        for (a in acls) {
            val acl = map(a)!!
            val res: Map<String, Any?> = try {
                PolicyBridge.decide(pol, context(principal, acl))
            } catch (e: RuntimeException) {
                last = "evaluator error (fail closed)"
                continue
            } catch (e: StackOverflowError) {
                last = "evaluator error (fail closed)"
                continue
            }
            if (res["allowed"] == true) {
                val d = obj("id", id, "allowed", true, "via", acl, "reason", "granted: $pid has ${acl["relation"]} on ${acl["object"]}")
                if (res["matched"] != null) d["matched"] = res["matched"]
                return d
            }
            val r = res["reason"]
            if (r is String) last = r
        }
        return obj("id", id, "allowed", false, "reason", last)
    }

    /** The evaluation context for ONE ACL entry: the subject is the principal's attributes plus its id. */
    private fun context(principal: Map<String, Any?>, acl: Map<String, Any?>): Map<String, Any?> {
        val subject = LinkedHashMap<String, Any?>()
        when (val attrs = principal["attributes"]) {
            is Map<*, *> -> for ((k, v) in attrs) subject[k as String] = v
            is List<*> -> attrs.forEachIndexed { i, v -> subject[i.toString()] = v } // object spread of an array
            is String -> for (i in attrs.indices) subject[i.toString()] = attrs[i].toString()
            else -> {}
        }
        subject["id"] = principal["id"]
        val ctx = obj("action", obj("verb", acl["relation"], "resource", acl["object"]), "subject", subject)
        if (principal.containsKey("env")) ctx["env"] = principal["env"]
        return ctx
    }

    /**
     * The generic filter. [id] and [acls] read a candidate's id (null or empty: positional `doc#i`) and its ACL
     * entries (anything that is not a list or entry yields none); either throwing marks the document unreadable and drops it.
     */
    @JvmStatic
    fun <D> filter(principalInput: Any?, candidates: List<D>?, policy: Any?, id: (D, Int) -> Any?, acls: (D) -> Any?): Result<D> {
        val principal = toPrincipal(principalInput) ?: obj("id", "")
        val compiled = compilePolicy(policy)
        val list = candidates ?: emptyList()
        val documents = ArrayList<D>()
        val decisions = ArrayList<Any?>()
        val allowedIds = ArrayList<Any?>()
        val droppedIds = ArrayList<Any?>()
        val allowedIndexes = ArrayList<Any?>()
        val seen = LinkedHashSet<String>()
        for (i in list.indices) {
            val doc = list[i]
            val rawId: Any?
            val docAcls: List<Any?>
            try {
                rawId = id(doc, i)
                docAcls = aclArray(acls(doc))
            } catch (e: RuntimeException) {
                val fid = "doc#$i" // metadata that cannot even be read is unknown: fail closed
                decisions.add(obj("id", fid, "allowed", false, "reason", "unreadable document metadata (fail closed)"))
                droppedIds.add(fid)
                continue
            }
            var docId = if (nonEmptyString(rawId)) rawId as String else "doc#$i"
            if (docId in seen) docId = docId + "#dup" + i // two candidates with one id must stay distinguishable
            seen.add(docId)
            val d = decideDocument(docId, docAcls, principal, compiled)
            decisions.add(d)
            if (d["allowed"] == true) {
                documents.add(doc)
                allowedIds.add(docId)
                allowedIndexes.add(i.toLong())
            } else droppedIds.add(docId)
        }
        val pid = principal["id"]
        val base = obj(
            "principal", if (pid is String) pid else "", "considered", list.size.toLong(), "allowedIds", allowedIds,
            "allowedIndexes", allowedIndexes, "droppedIds", droppedIds, "policyIncomplete", compiled["incomplete"] == true,
        )
        val hashed = obj("v", 1L, "kind", "pca-rag/filter")
        hashed.putAll(base)
        val decision = LinkedHashMap(base)
        decision["decisions"] = decisions
        decision["digest"] = Pca.hashCanonical(hashed)
        if (compiled["report"] != null) decision["report"] = compiled["report"]
        return Result(documents, decision)
    }

    private fun nn(d: Any?): Map<*, *> {
        if (d == null) throw IllegalArgumentException("null document")
        return if (d is Map<*, *>) d else LinkedHashMap<Any?, Any?>()
    }

    /** Filter JSON documents (`{id, acl?, tags?}` maps) with the default readers. A null document is unreadable (dropped). */
    @JvmStatic
    fun filterDocuments(principal: Any?, candidates: List<Any?>?, policy: Any?): Result<Any?> =
        filter(principal, candidates, policy, { d, _ -> nn(d)["id"] }, { d -> aclsFromMetadata(nn(d)["acl"], nn(d)["tags"]) })
}
