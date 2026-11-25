package net.atlasauth.pca.actions

import java.util.Locale
import java.util.TreeMap
import java.util.regex.Pattern
import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca

/**
 * The build step of an authoring pipeline: from loaded defs to the unsigned schema, the pack, the policy cards, the ontology fragment, the MCP tool map and
 * generated TypeScript declarations, plus the signing and consistency checks of the pack. Every output is a pure function of the defs and the trait registry.
 */
@Suppress("UNCHECKED_CAST")
object ActionBuild {
    /** Domain of the pack signature; it differs from the schema's, so a signature of one is never valid for the other. */
    const val PACK_SIGN_DOMAIN = Actions.PACK_DIGEST_DOMAIN + "\u0000"
    private val IDENT_RE = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*")

    private fun byVerb(a: Any?, b: Any?): Int = (J.get(a, "verb") as String).compareTo(J.get(b, "verb") as String)

    /**
     * Build every output: `{schema, pack, cards, ontology, mcp: {tools}, types}`. `cfg`: `{ns, version, stability, site, aud}`. Throws on a pack
     * above the unsharded limit, a duplicate verb, or a unit conflict (never a partial build).
     */
    fun buildArtifacts(
        defsIn: List<*>,
        cfg: Map<String, Any?>,
        reg: Map<String, Map<String, Any?>>,
        attestationVerified: ((Map<String, Any?>) -> Boolean)?,
    ): MutableMap<String, Any?> {
        val defs = ArrayList<Any?>(defsIn)
        defs.sortWith { a, b -> byVerb(a, b) }
        if (defs.size > ActionPacks.MAX_PACK_DEFS) throw IllegalArgumentException("a pack above " + ActionPacks.MAX_PACK_DEFS + " defs must be sharded (" + defs.size + " given)")
        for (i in 1 until defs.size) if (J.get(defs[i], "verb") == J.get(defs[i - 1], "verb")) throw IllegalArgumentException("verb '" + J.get(defs[i], "verb") + "' appears twice")
        val digests = ArrayList<String>()
        for (d in defs) digests.add(Actions.defDigest(J.m(d)))
        val root = Actions.packRoot(digests)
        val meta = J.obj("site", cfg["site"], "aud", cfg["aud"], "version", cfg["version"], "pack", J.obj("ns", cfg["ns"], "version", cfg["version"], "root", root))
        val schema = ActionDerive.toSchemaDoc(defs, reg, meta, attestationVerified)
        val pack = J.obj(
            "v", J.n(1), "kind", "pca-action-pack", "ns", cfg["ns"], "version", cfg["version"], "stability", cfg["stability"],
            "traits_digest", Actions.traitsDigest(reg), "roles_digest", Actions.tablesDigest(), "rules_digest", ActionLint.lintRulesDigest(), "root", root,
            "defs", defs, "prev", null, "evolution", ArrayList<Any?>(),
        )
        val cards = ArrayList<Any?>()
        for (d in defs) cards.add(ActionDerive.cardOf(J.m(d), ActionEffective.effective(J.m(d), reg, attestationVerified), reg))
        val tools = LinkedHashMap<String, Any?>()
        for (d in defs) {
            val mcp = J.get(J.get(d, "bindings"), "mcp")
            if (mcp != null) tools[J.get(mcp, "tool") as String] = J.obj("verb", J.get(d, "verb"), "annotations", ActionDerive.mcpAnnotationsOf(J.m(d), ActionEffective.effective(J.m(d), reg, attestationVerified)))
        }
        return J.obj("schema", schema, "pack", pack, "cards", cards, "ontology", ActionDerive.toOntology(defs, reg, attestationVerified), "mcp", J.obj("tools", tools), "types", generateTypes(defs))
    }

    /** The tool-to-action map of the defs' MCP bindings: `(tool, args) -> {verb, resource}`, or null when the tool is unknown or the call does not bind. */
    fun toolActionMapOf(defs: List<*>): (String, Map<String, Any?>) -> Map<String, Any?>? {
        val m = LinkedHashMap<String, Map<String, Any?>>()
        for (d in defs) {
            val mcp = J.get(J.get(d, "bindings"), "mcp")
            if (mcp != null) m[J.get(mcp, "tool") as String] = J.m(d)
        }
        return { tool, args ->
            val d = m[tool]
            if (d == null) null
            else {
                val r = ActionDerive.operationOf(d, args)
                if (r["ok"] != true) null
                else J.obj("verb", J.get(r["op"], "verb"), "resource", J.get(r["op"], "resource"))
            }
        }
    }

    // ---- generated types ---------------------------------------------------------------------------------------------------------

    private fun pascal(s: String): String {
        val b = StringBuilder()
        for (x in s.split('.', '_')) b.append(if (x.isEmpty()) "" else x.substring(0, 1).uppercase(Locale.ROOT) + x.substring(1))
        return b.toString()
    }

    private fun key(k: String): String = if (IDENT_RE.matcher(k).matches()) k else J.stringify(k)

    private fun union(values: Any?): String {
        val out = ArrayList<String>()
        for (v in J.a(values)) out.add(J.stringify(v))
        return out.joinToString(" | ")
    }

    private fun tsType(p: Map<String, Any?>): String {
        val t = p["type"]
        if ("integer" == t || "duration" == t) return "number"
        if ("boolean" == t) return "boolean"
        if ("set" == t) {
            val u = if (p["values"] is List<*>) union(p["values"]) else ""
            return "Array<" + (if (u.isEmpty()) "string" else u) + ">"
        }
        if ("array" == t) return if ("integer" == p["items"]) "number[]" else "string[]"
        return if (p["values"] != null) union(p["values"]) else "string"
    }

    private class Node {
        var leaf: Map<String, Any?>? = null
        val kids = TreeMap<String, Node>()
    }

    private fun render(n: Node, indent: String): String {
        val lines = ArrayList<String>()
        for ((k, c) in n.kids) {
            val leaf = c.leaf
            if (leaf != null) lines.add(indent + key(k) + (if (false == leaf["required"]) "?" else "") + ": " + tsType(leaf) + ";")
            else lines.add(indent + key(k) + ": {\n" + render(c, "$indent  ") + "\n" + indent + "};")
        }
        return lines.joinToString("\n")
    }

    /** TypeScript declarations for typed call sites: one params interface per verb, `ActionParams` and `ActionVerb`. */
    fun generateTypes(defs: List<*>): String {
        val out = ArrayList<String>()
        out.add("// Generated by `pca actions build`. Do not edit.")
        out.add("")
        val names = ArrayList<String>()
        val sorted = ArrayList<Any?>(defs)
        sorted.sortWith { a, b -> byVerb(a, b) }
        for (d in sorted) {
            val root = Node()
            val ps = J.m(J.get(d, "params"))
            val pn = ArrayList<String>(ps.keys)
            pn.sort()
            for (name in pn) {
                var n = root
                val segs = name.split(".")
                for (i in segs.indices) {
                    n = n.kids.getOrPut(segs[i]) { Node() }
                    if (i == segs.size - 1) n.leaf = J.m(ps[name])
                }
            }
            val iface = pascal(J.get(d, "verb") as String) + "Params"
            names.add("  " + J.stringify(J.get(d, "verb")) + ": " + iface + ";")
            out.add("export interface $iface {")
            out.add(render(root, "  "))
            out.add("}")
            out.add("")
        }
        out.add("export interface ActionParams {")
        out.addAll(names)
        out.add("}")
        out.add("")
        out.add("export type ActionVerb = keyof ActionParams;")
        out.add("")
        return out.joinToString("\n")
    }

    // ---- pack signing and consistency ----------------------------------------------------------------------------------------------

    private fun packMessage(body: Map<String, Any?>): ByteArray {
        val dom = PACK_SIGN_DOMAIN.toByteArray(Charsets.UTF_8)
        val b = Json.canonicalizeStrict(body).toByteArray(Charsets.UTF_8)
        val out = ByteArray(dom.size + b.size)
        System.arraycopy(dom, 0, out, 0, dom.size)
        System.arraycopy(b, 0, out, dom.size, b.size)
        return out
    }

    private fun isOne(v: Any?): Boolean {
        val d = J.num(v)
        return d != null && d == 1.0
    }

    /** Null when the pack is internally consistent: every def valid and sorted-unique, the Merkle root and digests recomputed. */
    fun packConsistencyError(p: Any?, reg: Map<String, Map<String, Any?>>): String? {
        try {
            if (p !is Map<*, *>) return "the pack must be an object"
            val q = J.m(p)
            if ("pca-action-pack" != q["kind"] || !isOne(q["v"])) return "not a pca-action-pack v1"
            if (q["defs"] !is List<*> || J.a(q["defs"]).size > ActionPacks.MAX_PACK_DEFS) return "defs must be a list within the unsharded limit"
            val seen = HashSet<Any?>()
            val digests = ArrayList<String>()
            for (d in J.a(q["defs"])) {
                val e = Actions.validateDef(d)
                if (e != null) return "def " + (if (J.get(d, "verb") != null) J.jsStr(J.get(d, "verb")) else "?") + ": " + e
                if (!seen.add(J.get(d, "verb"))) return "verb '" + J.get(d, "verb") + "' is defined twice"
            }
            for (d in J.a(q["defs"])) digests.add(Actions.defDigest(J.m(d)))
            if (Actions.packRoot(digests) != q["root"]) return "the pack root does not match its defs"
            if (Actions.traitsDigest(reg) != q["traits_digest"]) return "traits_digest does not match the trait registry"
            return null
        } catch (e: RuntimeException) {
            return "malformed pack: " + e.message
        }
    }

    /** Sign a pack as the registry (Ed25519; the 32-byte seed). Refuses an inconsistent pack. */
    fun signPack(pack: Map<String, Any?>, kid: String, secret: ByteArray, reg: Map<String, Map<String, Any?>>): MutableMap<String, Any?> {
        val bad = packConsistencyError(pack, reg)
        if (bad != null) throw IllegalArgumentException("signPack: $bad")
        val body = LinkedHashMap<String, Any?>(pack)
        body.remove("sig")
        val sig = Keys.b64u(Keys.edFromSeed(secret).sign(packMessage(body)))
        val out = LinkedHashMap<String, Any?>(body)
        out["sig"] = J.obj("alg", "ed25519", "kid", kid, "value", sig)
        return out
    }

    /** The registry key entry for a signer: `{kid, alg, pk}`. */
    fun packKeyOf(kid: String, secret: ByteArray): MutableMap<String, Any?> = J.obj("kid", kid, "alg", "ed25519", "pk", Keys.edFromSeed(secret).id())

    /** Verify a signed pack against pinned registry keys: consistency, the key entry by kid, and the signature. Never throws. Returns `{ok}` or `{ok:false, reason}`. */
    fun verifyPack(pack: Any?, keys: Any?, reg: Map<String, Map<String, Any?>>): MutableMap<String, Any?> {
        try {
            val bad = packConsistencyError(pack, reg)
            if (bad != null) return J.obj("ok", false, "reason", bad)
            val body = LinkedHashMap<String, Any?>(J.m(pack))
            val sig = body.remove("sig")
            if (sig !is Map<*, *> || "ed25519" != J.get(sig, "alg") || J.get(sig, "kid") !is String || J.get(sig, "value") !is String) return J.obj("ok", false, "reason", "missing or malformed signature")
            var k: Any? = null
            for (x in J.a(keys)) if (J.get(sig, "kid") == J.get(x, "kid")) { k = x; break }
            if (k == null) return J.obj("ok", false, "reason", "no registry key with kid '" + J.get(sig, "kid") + "'")
            val pk = Pca.decodeB64uStrict(J.get(k, "pk"), 32)
            if ("ed25519" != J.get(k, "alg") || pk == null) return J.obj("ok", false, "reason", "the registry key entry is malformed")
            val sg = Pca.decodeB64uStrict(J.get(sig, "value"), 64)
            return if (sg != null && Pca.ed25519Strict(pk, packMessage(body), sg)) J.obj("ok", true) else J.obj("ok", false, "reason", "pack signature invalid")
        } catch (e: RuntimeException) {
            return J.obj("ok", false, "reason", "pack verification error: " + e.message)
        }
    }
}
