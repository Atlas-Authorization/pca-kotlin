package net.atlasauth.pca.verifier

import java.security.MessageDigest

/**
 * Forbid-wins certificate check (security contract C-241) and linked policy templates (C-242, C-243): a port of
 * `certificateConsistent` in packages/pca/src/forbid-certificate.ts and of packages/pca/src/policy-link.ts (the TypeScript is
 * authoritative; same reason strings). Every function is total (never throws); anything malformed fails closed. Inputs are JSON
 * trees ([Json.parseLenient]).
 */
@Suppress("UNCHECKED_CAST")
object PolicyAuthoring {
    private const val TEMPLATE_SIG_DOMAIN = "atlas-pca/policy-template/v1\u0000"
    private const val TIGHTEN_SIG_DOMAIN = "atlas-pca/template-tighten/v1\u0000"
    private const val NAME_SOURCE = "^[a-z][a-z0-9_]{0,63}$"
    private val NAME_RE = Regex("[a-z][a-z0-9_]{0,63}")

    /** The outcome of [instantiateTemplate] / [resolveLink]: a policy, or the reason it was refused. */
    class Result(val policy: Map<String, Any?>?, val overlays: Int, val reason: String?)

    private fun isOne(v: Any?): Boolean = IntentJs.num(v) == 1.0
    private fun g(o: Any?, k: String): Any? = IntentJs.get(o, k)
    private fun nameOk(s: Any?): Boolean = s is String && NAME_RE.matches(s)

    // ---- forbid-wins certificate ----------------------------------------------------------------

    private class Row(val id: String, val kind: String, val value: String, val signer: String?)

    /** Whether the certificate's own table entails its decision, winner and shadowed list (no predicate evaluator needed). */
    fun forbidCertificateConsistent(cert: Any?, precedence: List<String> = emptyList()): Boolean {
        try {
            if (cert !is Map<*, *> || !isOne(g(cert, "v")) || g(cert, "kind") != "forbid-wins") return false
            val rows = g(cert, "clauses") as? List<*> ?: return false
            val winner = g(cert, "winner") as? Map<*, *> ?: return false
            val shadowed = g(cert, "shadowed") as? List<*> ?: return false
            if (winner["kind"] == "malformed") {
                return rows.isEmpty() && g(cert, "decision") == "deny" && winner.containsKey("id") && winner["id"] == null && shadowed.isEmpty()
            }
            val table = ArrayList<Row>()
            for (r in rows) {
                val id = g(r, "id") as? String ?: return false
                val kind = g(r, "kind") as? String ?: return false
                val value = g(r, "value") as? String ?: return false
                if (kind != "permit" && kind != "forbid" && kind != "escalate") return false
                if (value != "true" && value != "false" && value != "unknown") return false
                table.add(Row(id, kind, value, g(r, "signer") as? String))
            }
            fun rank(r: Row): Int {
                val i = if (r.signer == null) -1 else precedence.indexOf(r.signer)
                return if (i < 0) precedence.size else i // an unlisted (or absent) signer ranks last
            }
            fun hit(kind: String) = table.filter { it.kind == kind && it.value != "false" }
            // String.compareTo orders by UTF-16 code unit like JavaScript's `<`
            val forbids = hit("forbid").sortedWith(Comparator<Row> { a, b -> rank(a).compareTo(rank(b)).let { if (it != 0) it else a.id.compareTo(b.id) } })
            val permits = hit("permit")
            val escalates = hit("escalate")
            val win: Row?
            val decision: String
            val kind: String
            if (forbids.isNotEmpty()) { win = forbids[0]; decision = "deny"; kind = "forbid" }
            else if (permits.isEmpty()) { win = null; decision = "deny"; kind = "none" }
            else if (escalates.isNotEmpty()) { win = escalates[0]; decision = "escalate"; kind = "escalate" }
            else { win = permits[0]; decision = "allow"; kind = "permit" }
            val others = (forbids + permits + escalates).filter { it !== win }.map { it.id }
            val idOk = if (win == null) winner["id"] == null else winner["id"] == win.id
            return g(cert, "decision") == decision && winner["kind"] == kind && idOk && shadowed == others
        } catch (e: RuntimeException) {
            return false
        }
    }

    // ---- linked templates -------------------------------------------------------------------------

    private fun jsString(x: Any?): String = when (x) {
        null -> "null"
        is String -> x
        is Boolean, is Json.Num -> x.toString()
        else -> "object"
    }

    private fun scan(v: Any?, decl: Map<*, *>, used: MutableSet<String>): String? {
        if (v is List<*>) {
            for (x in v) scan(x, decl, used)?.let { return it }
            return null
        }
        if (v !is Map<*, *>) return null
        for (k in v.keys) if (k == "__proto__" || k == "constructor" || k == "prototype") return "body has the forbidden key '$k'"
        if (v.containsKey("\$slot")) {
            for (k in v.keys) if (k != "\$slot" && k != "pre" && k != "post") return "placeholder has unknown member '$k'"
            val name = v["\$slot"]
            if (name !is String || !decl.containsKey(name)) return "placeholder names undeclared slot '${jsString(name)}'"
            for (k in listOf("pre", "post")) if (v.containsKey(k) && v[k] !is String) return "placeholder $k must be a string"
            used.add(name)
            return null
        }
        for (k in v.keys) scan(v[k], decl, used)?.let { return it }
        return null
    }

    /** null for a well-formed template definition, else the first problem. */
    fun templateDefError(def: Any?): String? {
        if (def !is Map<*, *>) return "template must be an object"
        if (!isOne(g(def, "v")) || g(def, "kind") != "pca-policy-template") return "template v / kind mismatch"
        if (!nameOk(g(def, "id"))) return "template id must match $NAME_SOURCE"
        val ver = g(def, "version")
        if (ver !is String || ver.isEmpty() || ver.length > 64) return "template version must be a string of 1..64 characters"
        val slots = g(def, "slots") as? Map<*, *> ?: return "slots must be an object"
        if (slots.size > 32) return "more than 32 slots"
        for ((nk, s) in slots) {
            val n = nk as String
            if (!NAME_RE.matches(n)) return "slot name '$n' must match $NAME_SOURCE"
            if (s !is Map<*, *>) return "slot '$n' must be an object"
            val ty = s["type"]
            if (ty != "string" && ty != "integer" && ty != "set") return "slot '$n'.type must be string, integer or set"
            if (ty == "set" && s["values"] !is List<*>) return "set slot '$n' needs a closed values list"
            if (s.containsKey("values")) {
                val vl = s["values"]
                if (!(vl is List<*> && vl.size <= 64 && vl.all { it is String })) return "slot '$n'.values must be a list of strings"
            }
            if (ty == "integer") for (k in listOf("min", "max")) if (s.containsKey(k) && !IntentJs.isSafeInteger(s[k])) return "slot '$n'.$k must be a safe integer"
        }
        val body = g(def, "body")
        if (body !is Map<*, *> || g(body, "predicates") !is List<*>) return "body.predicates must be an array"
        if (body.containsKey("caveats") && body["caveats"] !is List<*>) return "body.caveats must be an array"
        val used = HashSet<String>()
        scan(body, slots, used)?.let { return it }
        for (n in slots.keys) if (!used.contains(n)) return "slot '$n' is declared but never used"
        return null
    }

    /** hashCanonical of the definition. */
    fun templateDigest(def: Any?): String = Pca.hashCanonical(def)

    private fun message(domain: String, digest: String): ByteArray =
        Pca.concat(IntentJs.utf8(domain), MessageDigest.getInstance("SHA-256").digest(IntentJs.utf8(digest)))

    /** Verify a signed template `{def, signer, sig}`: null when it verifies, else the reason. */
    fun verifyTemplate(t: Any?, trusted: List<String>): String? {
        try {
            templateDefError(g(t, "def"))?.let { return it }
            val signer = g(t, "signer")
            if (signer !is String || !trusted.contains(signer)) return "template signer is not trusted"
            if (!IntentJs.verifyEd(signer, message(TEMPLATE_SIG_DOMAIN, templateDigest(g(t, "def"))), g(t, "sig"))) return "bad template signature"
            return null
        } catch (e: RuntimeException) {
            return "template verification error (fail closed)"
        }
    }

    /** null for a well-formed tighten overlay: it may only add `where` conditions and caveats. */
    fun tightenOverlayError(o: Any?): String? {
        if (o !is Map<*, *>) return "overlay must be an object"
        if (!isOne(o["v"]) || o["kind"] != "pca-template-tighten") return "overlay v / kind mismatch"
        for (k in o.keys) if (k !in listOf("v", "kind", "template_id", "version_digest", "add_where", "add_caveats")) {
            return "overlay has unknown member '$k' (an overlay can only add where conditions and caveats)"
        }
        if (!nameOk(o["template_id"])) return "overlay template_id invalid"
        val vd = o["version_digest"]
        if (vd !is String || vd.isEmpty()) return "overlay version_digest invalid"
        if (o.containsKey("add_where") && !((o["add_where"] as? List<*>)?.all { it is Map<*, *> } ?: false)) return "overlay add_where must be a list of conditions"
        if (o.containsKey("add_caveats") && !((o["add_caveats"] as? List<*>)?.all { it is Map<*, *> && g(it, "type") is String } ?: false)) return "overlay add_caveats must be a list of caveats"
        return null
    }

    /** Verify a signed overlay `{overlay, signer, sig}`: null when it verifies, else the reason. */
    fun verifyTighten(t: Any?, trusted: List<String>): String? {
        try {
            tightenOverlayError(g(t, "overlay"))?.let { return it }
            val signer = g(t, "signer")
            if (signer !is String || !trusted.contains(signer)) return "overlay signer is not trusted"
            if (!IntentJs.verifyEd(signer, message(TIGHTEN_SIG_DOMAIN, Pca.hashCanonical(g(t, "overlay"))), g(t, "sig"))) return "bad overlay signature"
            return null
        } catch (e: RuntimeException) {
            return "overlay verification error (fail closed)"
        }
    }

    private fun slotValueError(name: String, d: Map<*, *>, v: Any?): String? {
        val values = (d["values"] as? List<*>)?.filterIsInstance<String>()
        when (d["type"]) {
            "string" -> {
                if (v !is String || v.isEmpty() || v.length > 256) return "slot '$name' must be a string of 1..256 characters"
                if (values != null && !values.contains(v)) return "slot '$name' is outside its closed value set"
            }
            "integer" -> {
                if (!IntentJs.isSafeInteger(v)) return "slot '$name' must be a safe integer"
                val n = IntentJs.lng(v)
                if (d.containsKey("min") && IntentJs.isSafeInteger(d["min"]) && n < IntentJs.lng(d["min"])) return "slot '$name' is below its minimum"
                if (d.containsKey("max") && IntentJs.isSafeInteger(d["max"]) && n > IntentJs.lng(d["max"])) return "slot '$name' is above its maximum"
            }
            else -> {
                if (!(v is List<*> && v.isNotEmpty() && v.size <= 64 && v.all { it is String })) return "slot '$name' must be a non-empty list of strings"
                if (v.toSet().size != v.size) return "slot '$name' has duplicate members"
                if (values != null && v.any { !values.contains(it) }) return "slot '$name' has a member outside its closed set"
            }
        }
        return null
    }

    private class Refusal(m: String) : RuntimeException(m, null, false, false)

    private fun fill(v: Any?, slots: Map<*, *>, key: String?): Any? {
        if (v is List<*>) return v.map { fill(it, slots, key) }
        if (v !is Map<*, *>) return v
        val name = v["\$slot"]
        if (name is String) {
            val value = slots[name]
            if (key == "verb" || key == "resource") {
                val items = if (value is List<*>) value else listOf(value)
                if (items.any { it is String && (it.contains("*") || it.startsWith("re:")) }) {
                    throw Refusal("slot '$name' would inject a wildcard or regex matcher into a verb or resource")
                }
            }
            val pre = v["pre"] as? String ?: ""
            val post = v["post"] as? String ?: ""
            if (pre.isEmpty() && post.isEmpty()) return value
            if (value !is String || value.contains("*") || value.contains("\u0000")) throw Refusal("slot '$name' cannot be spliced into a string (wildcard or non-string)")
            val out = pre + value + post
            if (pre.isEmpty() && out.startsWith("re:")) throw Refusal("slot '$name' would inject a regex matcher")
            return out
        }
        val m = LinkedHashMap<String, Any?>()
        for ((k, x) in v) m[k as String] = fill(x, slots, k)
        return m
    }

    private fun policyOf(predicates: Any?, caveats: Any?): Map<String, Any?> = linkedMapOf("predicates" to predicates, "caveats" to caveats)

    /**
     * Fill a template's slots. Refuses unfilled, extra, mistyped and out-of-domain slots and any slot value that would inject a
     * wildcard or a regex into a verb or resource. On success `policy` is `{predicates, caveats}`, else `reason`.
     */
    fun instantiateTemplate(def: Any?, slots: Any?): Result {
        try {
            templateDefError(def)?.let { return Result(null, 0, it) }
            if (slots !is Map<*, *>) return Result(null, 0, "slots must be an object")
            val decl = g(def, "slots") as Map<*, *>
            for (k in slots.keys) if (!decl.containsKey(k)) return Result(null, 0, "slot '$k' is not declared by the template")
            for ((nk, d) in decl) {
                val n = nk as String
                if (!slots.containsKey(n)) return Result(null, 0, "slot '$n' is not filled")
                slotValueError(n, d as Map<*, *>, slots[n])?.let { return Result(null, 0, it) }
            }
            val body = fill(g(def, "body"), slots, null) as Map<*, *>
            return Result(policyOf(body["predicates"], if (body.containsKey("caveats")) body["caveats"] else ArrayList<Any?>()), 0, null)
        } catch (r: Refusal) {
            return Result(null, 0, r.message)
        } catch (e: RuntimeException) {
            return Result(null, 0, "instantiation error (fail closed)")
        }
    }

    /** null for a well-formed reference `{template_id, version_digest, slots | bind_params_digest}`. */
    fun templateRefError(r: Any?): String? {
        if (r !is Map<*, *>) return "template_ref must be an object"
        for (k in r.keys) if (k != "template_id" && k != "version_digest" && k != "slots" && k != "bind_params_digest") return "template_ref has unknown member '$k'"
        if (!nameOk(r["template_id"])) return "template_ref.template_id invalid"
        val vd = r["version_digest"]
        if (vd !is String || vd.isEmpty() || IntentJs.utf8(vd).size > 128) return "template_ref.version_digest invalid"
        if (r.containsKey("slots") && r.containsKey("bind_params_digest")) return "template_ref has both slots and bind_params_digest"
        if (r.containsKey("bind_params_digest")) {
            val b = r["bind_params_digest"]
            return if (b is String && b.isNotEmpty() && IntentJs.utf8(b).size <= 128) null else "template_ref.bind_params_digest invalid"
        }
        if (r["slots"] !is Map<*, *>) return "template_ref.slots must be an object"
        return null
    }

    /** Rebuild the policy a reference denotes from a registry `{templates, overlays?, trusted, params?}`. */
    fun resolveLink(ref: Any?, reg: Any?): Result {
        try {
            templateRefError(ref)?.let { return Result(null, 0, it) }
            val trusted = (g(reg, "trusted") as? List<*>)?.filterIsInstance<String>() ?: emptyList()
            val digest = g(ref, "version_digest") as String
            val templates = g(reg, "templates") as? Map<*, *>
            if (templates == null || !templates.containsKey(digest)) return Result(null, 0, "template version is not in the registry")
            val t = templates[digest]
            verifyTemplate(t, trusted)?.let { return Result(null, 0, it) }
            val def = g(t, "def")
            if (templateDigest(def) != digest) return Result(null, 0, "registry entry does not match its digest")
            if (!IntentJs.jsonEquals(g(def, "id"), g(ref, "template_id"))) return Result(null, 0, "template id does not match the reference")
            var slots: Any? = g(ref, "slots")
            if (g(ref, "bind_params_digest") != null) {
                val bd = g(ref, "bind_params_digest") as String
                val params = g(reg, "params") as? Map<*, *>
                val bound = if (params != null && params.containsKey(bd)) params[bd] else null
                if (bound !is Map<*, *>) return Result(null, 0, "parameter object is not available")
                if (Pca.hashCanonical(bound) != bd) return Result(null, 0, "parameter object does not match bind_params_digest")
                slots = bound
            }
            val inst = instantiateTemplate(def, slots)
            val pol = inst.policy ?: return inst
            var predicates: List<Any?> = pol["predicates"] as List<Any?>
            var caveats: List<Any?> = pol["caveats"] as List<Any?>
            var applied = 0
            for (o in (g(reg, "overlays") as? List<*>) ?: emptyList<Any?>()) {
                val ov = g(o, "overlay")
                if (ov !is Map<*, *> || !IntentJs.jsonEquals(ov["version_digest"], g(ref, "version_digest")) || !IntentJs.jsonEquals(ov["template_id"], g(ref, "template_id"))) continue
                verifyTighten(o, trusted)?.let { return Result(null, 0, it) }
                val add = (ov["add_where"] as? List<Any?>) ?: emptyList()
                predicates = predicates.map { p ->
                    val m = LinkedHashMap<String, Any?>(p as Map<String, Any?>)
                    m["where"] = ((g(p, "where") as? List<Any?>) ?: emptyList()) + add
                    m
                }
                caveats = caveats + ((ov["add_caveats"] as? List<Any?>) ?: emptyList())
                applied++
            }
            return Result(policyOf(predicates, caveats), applied, null)
        } catch (e: RuntimeException) {
            return Result(null, 0, "link resolution error (fail closed)")
        }
    }
}
