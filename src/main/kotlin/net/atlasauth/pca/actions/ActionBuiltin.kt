package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Json

/**
 * The built-in connector actions and the domain vocabularies as hand-reviewed action definitions (the `core` seed of the catalog packs), the legacy
 * tables they were reconciled from, and the derivation of a domain's ontology terms. The data is the reference's, embedded verbatim. Every call returns a
 * fresh tree the caller may modify. The built-ins are UNCONFIRMED until a release attestation is attached ([releasedBuiltinDefs]); this build carries
 * none, so they stay maximally dangerous when read here (the release signing step stays with the reference tooling, which holds the reviewer key).
 */
@Suppress("UNCHECKED_CAST")
object ActionBuiltin {
    val DOMAIN_NAMES: List<String> = listOf("payments", "email", "code_repos", "data_access", "calendar_travel")

    private fun parse(parts: Array<String>): Any? = Json.parse(ActionData.join(parts))

    /** The 21 built-in connector action definitions. */
    fun builtinDefs(): MutableList<Any?> = J.a(parse(ActionData.BUILTIN_DEFS))

    /** The defs the domain vocabularies add to the built-in pack. */
    fun domainDefs(): MutableList<Any?> = J.a(parse(ActionData.DOMAIN_DEFS))

    /** Every def the domain vocabularies and the connector catalog are built from: one pack, one alias namespace. */
    fun corePackDefs(): MutableList<Any?> {
        val all = builtinDefs()
        all.addAll(domainDefs())
        return all
    }

    /** What the old catalog said per built-in verb: `verb -> {reversibility, blastRadius}`. */
    fun legacyCatalog(): MutableMap<String, Any?> = J.m(parse(ActionData.LEGACY_CATALOG))

    /** What the old payments ontology said (effect class), for the verbs that exist in both models. */
    fun legacyOntologyEffect(): MutableMap<String, Any?> = J.m(parse(ActionData.LEGACY_ONTOLOGY_EFFECT))

    /** Every place the old models disagreed and how it was settled: a list of `{verb, field, was, now, reason}`. */
    fun resolutions(): MutableList<Any?> = J.a(parse(ActionData.RESOLUTIONS))

    /** The NL bindings per domain: `domain -> [{id, verb, resourceType, params, ccys?}]`. */
    fun domainVerbBindings(): MutableMap<String, Any?> = J.m(parse(ActionData.DOMAIN_VERBS))

    private fun defOf(pack: List<Any?>, verb: String): MutableMap<String, Any?> {
        for (d in pack) if (verb == J.get(d, "verb")) return J.m(d)
        throw IllegalStateException("domain binding names unknown def '$verb'")
    }

    private fun bindings(domain: String): MutableList<Any?> {
        val b = domainVerbBindings()[domain] ?: throw IllegalStateException("unknown domain '$domain'")
        return J.a(b)
    }

    /**
     * The `verbs` and `aliases` of a domain ontology, derived from the defs (effect class derived, parameter kinds from the def parameters,
     * a money parameter listing the domain's accepted currencies when the binding names them). Returns `{verbs, aliases}`.
     */
    fun domainVerbs(domain: String, reg: Map<String, Map<String, Any?>>?): Map<String, Any?> {
        val pack = corePackDefs()
        val bs = bindings(domain)
        val defs = ArrayList<Any?>()
        for (b in bs) defs.add(defOf(pack, J.get(b, "verb") as String))
        val onto = ActionDerive.toOntology(defs, reg ?: Actions.CORE_REGISTRY, null)
        val verbs = ArrayList<Any?>()
        val aliases = LinkedHashMap<String, Any?>()
        for (b in bs) {
            val d = defOf(pack, J.get(b, "verb") as String)
            val dal: List<Any?> = if (d["aliases"] is List<*>) J.a(d["aliases"]) else ArrayList()
            if (!dal.contains(J.get(b, "id"))) throw IllegalStateException("domain binding '${J.get(b, "id")}' is not an alias of '${J.get(b, "verb")}'")
            var ov: MutableMap<String, Any?>? = null
            for (v in J.a(onto["verbs"])) if (J.get(b, "verb") == J.get(v, "id")) { ov = J.m(v); break }
            val params = LinkedHashMap<String, Any?>()
            for ((k, name) in J.m(J.get(b, "params"))) {
                val p = J.m(ov!!["params"])[name as String]
                    ?: throw IllegalStateException("domain binding '${J.get(b, "id")}' surfaces unknown parameter '$name'")
                params[k] = if ("money" == J.get(p, "kind") && J.get(b, "ccys") != null) J.obj("kind", "money", "ccys", ArrayList(J.a(J.get(b, "ccys")))) else p
            }
            verbs.add(J.obj("id", J.get(b, "id"), "effect", ActionDerive.effectClass(d), "resource_type", J.get(b, "resourceType"), "params", params))
            for (a in dal) if (a != J.get(b, "id")) aliases[a as String] = J.get(b, "id")
        }
        return J.obj("verbs", verbs, "aliases", aliases)
    }

    /** The role map of a domain verb for the selector layer: `id -> role -> [NL parameter names carrying it]`. */
    fun domainRoles(domain: String): Map<String, Any?> {
        val pack = corePackDefs()
        val out = LinkedHashMap<String, Any?>()
        for (b in bindings(domain)) {
            val d = defOf(pack, J.get(b, "verb") as String)
            val roles = LinkedHashMap<String, Any?>()
            for ((k, name) in J.m(J.get(b, "params"))) {
                val r = J.get(J.m(d["params"])[name as String], "role")
                if (r != null) J.a(roles.getOrPut(r as String) { ArrayList<Any?>() }).add(k)
            }
            out[J.get(b, "id").toString()] = roles
        }
        return out
    }

    // ---- release attestation (none shipped in this build) -----------------------------------------------------------------------

    /** The release pins the built-in attestations verify against; null before the first release signing (always, in this build). */
    fun builtinReleasePins(): Any? = null

    /** The release pins and registry the built-in attestations verify against (`{pins, registry}`); null before the first release signing (always, in this build). */
    fun builtinReleaseCtx(reg: Map<String, Map<String, Any?>>? = null): Map<String, Any?>? {
        val pins = builtinReleasePins() ?: return null
        return linkedMapOf("pins" to pins, "registry" to (reg ?: Actions.CORE_REGISTRY))
    }

    /** The built-in defs with their release attestation attached where the package carries one (none: returned unchanged and unconfirmed). */
    fun releasedBuiltinDefs(defs: List<*>?): MutableList<Any?> = ArrayList<Any?>(defs ?: builtinDefs())

    /** The attestation check under which released built-ins count as confirmed; null without pinned release keys (nothing confirmed). */
    fun builtinReviewOpts(reg: Map<String, Map<String, Any?>>?): ((Map<String, Any?>) -> Boolean)? {
        val pins = builtinReleasePins()
        return if (pins == null) null else ActionUndoEngine.attestationVerifier(pins, reg ?: Actions.CORE_REGISTRY)
    }

    /**
     * Release step: confirm every built-in def (or [defs]) under the release reviewer key, each with its declared traits as the final set. The
     * secret is supplied by the caller and never stored; the result is the confirmed defs, the attestation of each at `review.attestation`.
     */
    fun signBuiltins(reg: Map<String, Map<String, Any?>>?, kid: String, secret: ByteArray, ts: Any?, defs: List<*>?): MutableList<Any?> {
        val out = ArrayList<Any?>()
        for (d in defs ?: builtinDefs()) {
            val def = J.m(d)
            val traits = java.util.TreeSet<String>()
            if (def["traits"] is List<*>) for (t in J.a(def["traits"])) traits.add(t as String)
            out.add(net.atlasauth.pca.actions.importers.ImportReview.confirmDef(def, reg ?: Actions.CORE_REGISTRY, kid, secret, null, ArrayList<Any?>(traits), null, ts))
        }
        return out
    }
}
