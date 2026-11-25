package net.atlasauth.pca.schema

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json

/**
 * JSON Schema (draft 2020-12) documents for the PCA wire types (the signed action, one capability hop, the discovery
 * document) plus a small dependency-free STRUCTURAL validator. The schemas describe structure only: a document that
 * passes is well-formed, never authorized. Schemas are plain JSON trees (maps and lists), the same shape the reference
 * publishes, so any generator or validator can consume them.
 */
object Schema {
    /** The outcome of [validate]: [valid] plus a readable error list (empty when valid). */
    data class ValidationResult(val valid: Boolean, val errors: List<String>) {
        fun toJson(): Map<String, Any?> = linkedMapOf("valid" to valid, "errors" to ArrayList<Any?>(errors))
    }

    private const val DRAFT = "https://json-schema.org/draft/2020-12/schema"
    private val ALGS = listOf("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")

    private fun o(vararg kv: Any?): MutableMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i < kv.size) { m[kv[i] as String] = kv[i + 1]; i += 2 }
        return m
    }

    private fun str() = o("type", "string")
    private fun ref(name: String) = o("\$ref", "#/\$defs/$name")
    private fun integer() = o("type", "integer")
    private fun arrOf(items: Any?) = o("type", "array", "items", items)
    private fun alg() = o("type", "string", "enum", ArrayList<Any?>(ALGS))
    private fun l(vararg xs: Any?): MutableList<Any?> = ArrayList(xs.toList())

    private fun caveatDef() = o("type", "object", "required", l("type"), "properties", o("type", str()), "additionalProperties", true)

    private fun capabilityDef() = o(
        "type", "object", "required", l("id", "issuer", "holder", "caveats", "body_digest", "sig"),
        "properties", o("id", str(), "issuer", str(), "holder", str(), "caveats", arrOf(ref("caveat")), "parent", str(),
            "body_digest", str(), "sig", str(), "alg", alg(), "pq_pk", str(), "pq_sig", str()),
        "additionalProperties", true,
    )

    private fun actionDef() = o(
        "type", "object", "required", l("verb", "resource", "params_digest", "reversibility_class"),
        "properties", o("verb", str(), "resource", str(), "params_digest", str(), "reversibility_class", str()), "additionalProperties", true,
    )

    private fun inclusionProofDef() = o(
        "type", "object", "required", l("index", "size", "path"),
        "properties", o("index", integer(), "size", integer(), "path", arrOf(o("type", "object", "additionalProperties", true))), "additionalProperties", true,
    )

    private fun planDef() = o(
        "type", "object", "required", l("root", "inclusion_proof", "node_id"),
        "properties", o("root", str(), "inclusion_proof", ref("inclusionProof"), "node_id", str(), "conditions_digest", str()), "additionalProperties", true,
    )

    private fun riskClaimDef() = o(
        "type", "object", "required", l("r", "inputs"),
        "properties", o("r", o("type", "number"), "inputs", o("type", "object", "additionalProperties", true)), "additionalProperties", true,
    )

    private fun attestationDef() = o(
        "type", "object", "required", l("quote_digest", "epoch", "model_id", "measurement", "operator"),
        "properties", o("quote_digest", str(), "epoch", integer(), "model_id", str(), "measurement", str(), "operator", str()), "additionalProperties", true,
    )

    private fun provenanceDef() = o(
        "type", "object", "required", l("causal_hash", "taint_level", "trusted_refs"),
        "properties", o("causal_hash", str(), "taint_level", o("type", "number"), "trusted_refs", arrOf(str())), "additionalProperties", true,
    )

    private fun freshnessDef() = o(
        "type", "object", "required", l("beacon_ref", "epoch", "accumulator_witness"),
        "properties", o("beacon_ref", str(), "epoch", integer(), "accumulator_witness", str()), "additionalProperties", true,
    )

    /** The signed action object (wire format v2). A fresh deep copy each call. */
    @JvmStatic
    fun pcactnSchema(): Map<String, Any?> {
        val props = o(
            "ver", integer(), "action", ref("action"),
            "grant_ref", str(), "cap_chain", o("type", "array", "minItems", Json.Num("1"), "items", ref("capability")),
            "plan", ref("plan"), "attestation", ref("attestation"), "provenance", ref("provenance"), "freshness", ref("freshness"),
            "counter", integer(), "risk_claim", ref("riskClaim"), "aud", str(), "iat", integer(), "exp", integer(), "nonce", str(),
            "caution", o("type", "number"), "rationale_commitment", str(), "progress_step", o("type", "object", "additionalProperties", true),
            "prohibition_evidence", o("type", l("object", "array")), "tool_binding", str(), "alg", alg(), "pq_pk", str(), "sig", str(), "pq_sig", str(),
            "threshold", o("type", "object", "additionalProperties", true),
            "zk_compliance", o("description", "Opaque zk-compliance proof; shape is verifier-defined."), "bond_ref", str(),
        )
        return o(
            "\$schema", DRAFT, "\$id", "https://atlasauth.net/schemas/pca/pcactn.schema.json", "title", "PCActn",
            "description", "Proof-Carrying Authority action object (spec §7, wire format v2).", "type", "object",
            "required", l("ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "aud", "iat", "exp", "sig"),
            "properties", props, "additionalProperties", true,
            "\$defs", o(
                "caveat", caveatDef(), "capability", capabilityDef(), "action", actionDef(), "inclusionProof", inclusionProofDef(), "plan", planDef(),
                "riskClaim", riskClaimDef(), "attestation", attestationDef(), "provenance", provenanceDef(), "freshness", freshnessDef(),
            ),
        )
    }

    /** One hop of a capability chain. */
    @JvmStatic
    fun capabilitySchema(): Map<String, Any?> {
        val m = o(
            "\$schema", DRAFT, "\$id", "https://atlasauth.net/schemas/pca/capability.schema.json", "title", "Capability",
            "description", "An attenuable capability chain hop (spec §5.2).",
        )
        m.putAll(capabilityDef())
        m["\$defs"] = o("caveat", caveatDef())
        return m
    }

    /** The resource-server discovery document. */
    @JvmStatic
    fun discoverySchema(): Map<String, Any?> = o(
        "\$schema", DRAFT, "\$id", "https://atlasauth.net/schemas/pca/discovery.schema.json", "title", "PcaDiscoveryDocument",
        "description", "The .well-known/pca-configuration discovery document (internet-wide integration).", "type", "object",
        "required", l("audience", "pca_versions", "signature_suites", "action_header"),
        "properties", o(
            "audience", str(), "pca_versions", arrOf(integer()), "signature_suites", arrOf(str()), "action_header", str(),
            "required_checks", arrOf(str()), "endpoints", ref("endpoints"), "trusted_roots", arrOf(str()), "metadata", o("type", "object", "additionalProperties", true),
        ),
        "additionalProperties", true,
        "\$defs", o(
            "endpoints", o(
                "type", "object",
                "properties", o("attestation_challenge", str(), "revocation_epoch", str(), "liveness_beacon", str(), "stepup", str(), "grant", str()),
                "additionalProperties", true,
            ),
        ),
    )

    /** Every published schema keyed by wire-type name. */
    @JvmStatic
    fun allSchemas(): Map<String, Any?> = o("PCActn", pcactnSchema(), "Capability", capabilitySchema(), "PcaDiscoveryDocument", discoverySchema())

    // ---- validator ----

    private fun isRecord(v: Any?): Boolean = v is Map<*, *>

    private fun num(v: Any?): Double? = IntentJs.num(v)

    private fun isIntegral(d: Double): Boolean = !d.isNaN() && !d.isInfinite() && d == Math.rint(d)

    private fun jsonTypeOf(v: Any?): String {
        if (v == null) return "null"
        if (v is List<*>) return "array"
        val d = num(v)
        if (d != null) return if (isIntegral(d)) "integer" else "number"
        if (v is Boolean) return "boolean"
        if (v is String) return "string"
        return "object"
    }

    private fun matchesType(expected: Any?, v: Any?): Boolean {
        if (expected !is String) return false
        val d = num(v)
        return when (expected) {
            "object" -> isRecord(v)
            "array" -> v is List<*>
            "string" -> v is String
            "number" -> d != null && !d.isNaN() && !d.isInfinite()
            "integer" -> d != null && isIntegral(d) && !IntentJs.isNegZero(d)
            "boolean" -> v is Boolean
            "null" -> v == null
            else -> false
        }
    }

    /** Resolve a local `#/...` pointer (own keys of objects only, no unescaping). */
    private fun resolveRef(root: Any?, ref: String): Map<*, *>? {
        if (!ref.startsWith("#/")) return null
        var cur: Any? = root
        for (token in ref.substring(2).split("/")) {
            if (cur !is Map<*, *> || !cur.containsKey(token)) return null
            cur = cur[token]
        }
        return cur as? Map<*, *>
    }

    private fun label(path: String): String = if (path.isEmpty()) "(root)" else path
    private fun join(path: String, key: String): String = if (path.isEmpty()) key else "$path.$key"

    /** JavaScript `JSON.stringify` of a scalar enum member. */
    private fun stringify(e: Any?): String {
        if (e == null) return "null"
        if (e is Boolean) return e.toString()
        if (e is String) return quote(e)
        val d = num(e)
        if (d != null) return stringifyNum(e, d)
        return "null"
    }

    private fun stringifyNum(e: Any, d: Double): String {
        if (d.isNaN() || d.isInfinite()) return "null"
        val s = (IntentJs.normalize(if (e is Json.Num) e else Json.Num(e.toString())) as Json.Num).raw
        return if (s == "-0") "0" else s
    }

    private fun quote(s: String): String {
        val b = StringBuilder("\"")
        for (i in s.indices) {
            val c = s[i]
            when (c) {
                '"' -> b.append("\\\"")
                '\\' -> b.append("\\\\")
                '\b' -> b.append("\\b")
                '\u000c' -> b.append("\\f")
                '\n' -> b.append("\\n")
                '\r' -> b.append("\\r")
                '\t' -> b.append("\\t")
                else -> {
                    val lone = if (Character.isHighSurrogate(c)) !(i + 1 < s.length && Character.isLowSurrogate(s[i + 1]))
                    else Character.isLowSurrogate(c) && !(i > 0 && Character.isHighSurrogate(s[i - 1]))
                    if (c.code < 0x20 || lone) b.append(String.format("\\u%04x", c.code)) else b.append(c)
                }
            }
        }
        return b.append('"').toString()
    }

    /** JavaScript `===` between a JSON scalar enum member and a value (containers never match). */
    private fun strictEq(e: Any?, v: Any?): Boolean {
        if (e == null || v == null) return e == null && v == null
        if (e is String || v is String) return e == v
        if (e is Boolean || v is Boolean) return e == v
        val x = num(e)
        val y = num(v)
        return x != null && y != null && x == y
    }

    private fun checkNode(schema: Map<*, *>, value: Any?, path: String, root: Any?, errors: MutableList<String>) {
        val r = schema["\$ref"]
        if (r is String) {
            val resolved = resolveRef(root, r)
            if (resolved == null) { errors.add(label(path) + ": unresolved \$ref '" + r + "'"); return }
            checkNode(resolved, value, path, root, errors)
            return
        }
        val type = schema["type"]
        if (type != null) {
            val types: List<Any?> = if (type is List<*>) type else listOf(type)
            var ok = false
            for (t in types) if (matchesType(t, value)) { ok = true; break }
            if (!ok) {
                errors.add(label(path) + ": expected type " + types.joinToString("|") { it?.toString() ?: "" } + ", got " + jsonTypeOf(value))
                return
            }
        }
        val en = schema["enum"]
        if (en is List<*>) {
            var found = false
            for (e in en) if (strictEq(e, value)) { found = true; break }
            if (!found) errors.add(label(path) + ": value is not one of [" + en.joinToString(", ") { stringify(it) } + "]")
        }
        if (isRecord(value)) {
            val rec = value as Map<*, *>
            val req = schema["required"]
            if (req is List<*>) {
                for (key in req) {
                    val k = key.toString()
                    if (!rec.containsKey(k)) errors.add(join(path, k) + ": missing required property '" + k + "'")
                }
            }
            val props = schema["properties"]
            if (props is Map<*, *>) {
                for ((k, v) in props) {
                    if (rec.containsKey(k) && v is Map<*, *>) checkNode(v, rec[k], join(path, k as String), root, errors)
                }
                if (schema["additionalProperties"] == false) {
                    for (key in rec.keys) if (!props.containsKey(key)) errors.add(join(path, key as String) + ": additional property not allowed")
                }
            }
        }
        val items = schema["items"]
        if (value is List<*> && items is Map<*, *>) {
            for (i in value.indices) checkNode(items, value[i], "$path[$i]", root, errors)
        }
    }

    /**
     * Structural check of [value] against [schema]: JSON type, required members, enum, and the same recursively
     * through properties, items and local `#/...` references. Not a full draft 2020-12 validator (no pattern, format,
     * oneOf/anyOf, bounds, remote refs): feed the schemas to a real validator for that.
     */
    @JvmStatic
    fun validate(schema: Map<String, Any?>, value: Any?): ValidationResult {
        val errors = ArrayList<String>()
        checkNode(schema, value, "", schema, errors)
        return ValidationResult(errors.isEmpty(), errors)
    }
}
