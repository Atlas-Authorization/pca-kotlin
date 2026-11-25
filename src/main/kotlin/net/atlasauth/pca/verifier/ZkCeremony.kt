package net.atlasauth.pca.verifier

/**
 * Trusted-setup bookkeeping for the Groth16 circuits (pure: no file or process access).
 *
 * A verifying key is only as trustworthy as the ceremony that made it. The answer is `multi-party` only when the caller supplies a
 * transcript, pins its SHA-256 (published out of band by the coordinator), the transcript is well-formed (two or more distinct
 * contributions chained from the initial key, a public random beacon applied last) and names exactly this verifying key. Everything
 * else is `single-party`. The cryptographic check of the contributions themselves is the ceremony tool's job; nothing here claims more
 * than the pinned transcript says.
 */
object ZkCeremony {
    private val H64 = Regex("[0-9a-f]{64}")
    private val VK_ID = Regex("vk_[0-9a-f]{64}")

    private fun h64(v: Any?): Boolean = H64.matches(ZkJs.string(v))

    /** Id of a verifying key: `vk_` + SHA-256 of its canonical JSON. A re-setup always yields a new id. */
    @JvmStatic
    fun vkId(vkey: Any?): String = "vk_" + ZkJs.hex(Pca.sha(Pca.canonBytes(vkey)))

    /**
     * What a verifying key was built from: `{circuit, sourceSha256, r1csSha256, vkId}` from `{circuit, sourceSha256, r1csSha256, vkey}`.
     * Throws on an empty circuit id or a hash that is not 64 lower-case hex characters.
     */
    @JvmStatic
    fun circuitProvenance(args: Map<String, Any?>): Map<String, Any?> {
        val circuit = ZkJs.get(args, "circuit")
        val source = ZkJs.get(args, "sourceSha256")
        val r1cs = ZkJs.get(args, "r1csSha256")
        if (!h64(source) || !h64(r1cs) || circuit == "") throw IllegalArgumentException("circuitProvenance: bad circuit id or hash")
        val out = LinkedHashMap<String, Any?>()
        if (circuit !== ZkJs.UNDEF) out["circuit"] = circuit
        out["sourceSha256"] = source
        out["r1csSha256"] = r1cs
        out["vkId"] = vkId(ZkJs.get(args, "vkey"))
        return out
    }

    /**
     * First reason `prov` does not describe the verifying key built from the expected sources and constraint system, or null. `expect`
     * is `{circuit, sourceSha256, r1csSha256?, vkey}`.
     */
    @JvmStatic
    fun checkCircuitProvenance(prov: Any?, expect: Map<String, Any?>): String? {
        if (prov !is Map<*, *> && prov !is List<*>) return "not a provenance record"
        if (!ZkJs.strictEq(ZkJs.get(prov, "circuit"), ZkJs.get(expect, "circuit"))) return "record is for another circuit"
        if (!ZkJs.strictEq(ZkJs.get(prov, "sourceSha256"), ZkJs.get(expect, "sourceSha256"))) return "circuit sources differ from the pinned version"
        val r1cs = ZkJs.get(prov, "r1csSha256")
        val wantR1cs = ZkJs.get(expect, "r1csSha256")
        if (r1cs !is String || !H64.matches(r1cs) || (wantR1cs !== ZkJs.UNDEF && !ZkJs.strictEq(r1cs, wantR1cs))) return "constraint system differs"
        if (!ZkJs.strictEq(ZkJs.get(prov, "vkId"), vkId(ZkJs.get(expect, "vkey")))) return "verifying key is not the recorded one"
        return null
    }

    /** SHA-256 (hex) of the canonical transcript. */
    @JvmStatic
    fun transcriptSha256(t: Any?): String = ZkJs.hex(Pca.sha(Pca.canonBytes(t)))

    /**
     * The first problem with a ceremony transcript, or null when it is well-formed. Fails closed on any odd shape. `minContributions`
     * raises the floor of 2; `r1csSha256` and `circuit` pin the constraint system and the circuit id.
     */
    @JvmStatic
    @JvmOverloads
    fun checkTranscript(t: Any?, minContributions: Double? = null, r1csSha256: String? = null, circuit: String? = null): String? =
        check(t, minContributions, r1csSha256 ?: ZkJs.UNDEF, circuit ?: ZkJs.UNDEF)

    private fun isIndex(v: Any?, i: Int): Boolean {
        val d = IntentJs.num(v) ?: return false
        return d == i.toDouble() && !IntentJs.isNegZero(d)
    }

    private fun check(t: Any?, minContributions: Double?, r1cs: Any?, circuit: Any?): String? {
        val version = IntentJs.num(ZkJs.get(t, "version"))
        if (t !is Map<*, *> || version == null || version != 1.0) return "not a version-1 transcript"
        val c = ZkJs.get(t, "circuit")
        if (c !is String || c.isEmpty()) return "no circuit id"
        if (circuit !== ZkJs.UNDEF && !ZkJs.strictEq(c, circuit)) return "transcript is for another circuit"
        val curve = ZkJs.get(t, "curve")
        if (curve != "bn128" && curve != "bls12-381") return "unknown curve"
        for (k in listOf("r1csSha256", "ptauSha256", "initZkeySha256")) if (!h64(ZkJs.get(t, k))) return "$k is not a SHA-256"
        if (r1cs !== ZkJs.UNDEF && !ZkJs.strictEq(ZkJs.get(t, "r1csSha256"), r1cs)) return "transcript is for a different constraint system"
        val own = ZkJs.get(t, "minContributions")
        val min = Math.max(Math.max(2.0, minContributions ?: 2.0), if (IntentJs.isSafeInteger(own)) IntentJs.num(own)!! else 2.0)
        val cs = ZkJs.get(t, "contributions")
        if (cs !is List<*> || cs.size < min) return "fewer than " + Json.jsNumberText(min) + " contributions"
        val names = HashSet<String>()
        val keys = HashSet<String>()
        var prev = ZkJs.get(t, "initZkeySha256")
        for ((i, x) in cs.withIndex()) {
            val name = ZkJs.get(x, "name")
            if (x !is Map<*, *> || !isIndex(ZkJs.get(x, "index"), i) || name !is String || name.isEmpty()) return "contribution $i is malformed"
            val zkey = ZkJs.get(x, "zkeySha256")
            if (!h64(zkey) || !ZkJs.strictEq(ZkJs.get(x, "prevZkeySha256"), prev)) return "contribution $i does not chain from the previous key"
            if (name in names || (zkey is String && zkey in keys)) return "contribution $i repeats a name or key"
            names.add(name)
            if (zkey is String) keys.add(zkey)
            prev = zkey
        }
        val b = ZkJs.get(t, "beacon")
        val exp = ZkJs.get(b, "iterationsExp")
        if (b !is Map<*, *> || !h64(ZkJs.get(b, "hashHex")) || !IntentJs.isSafeInteger(exp) || IntentJs.num(exp)!! < 10 || IntentJs.num(exp)!! > 63) return "no valid random beacon"
        if (!ZkJs.strictEq(ZkJs.get(b, "prevZkeySha256"), prev) || !h64(ZkJs.get(b, "zkeySha256"))) return "beacon is not applied after the last contribution"
        if (!ZkJs.strictEq(ZkJs.get(t, "finalZkeySha256"), ZkJs.get(b, "zkeySha256"))) return "final key is not the beacon output"
        val id = ZkJs.get(t, "vkId")
        if (id !is String || !VK_ID.matches(id)) return "no verifying-key id"
        return null
    }

    /**
     * `multi-party` only when `evidence.sha256` equals the transcript's hash, the transcript is well-formed (for the pinned
     * `evidence.r1csSha256` / `evidence.circuit` when given) and names `vkey`. Anything else, including an error, is `single-party`.
     * `evidence` is `{transcript, sha256, r1csSha256?, circuit?}`.
     */
    @JvmStatic
    @JvmOverloads
    fun ceremonyOf(vkey: Any?, evidence: Any? = null): String {
        try {
            if (!ZkJs.truthy(vkey) || !ZkJs.truthy(evidence)) return "single-party"
            val t = ZkJs.get(evidence, "transcript")
            if (check(t, null, ZkJs.get(evidence, "r1csSha256"), ZkJs.get(evidence, "circuit")) != null) return "single-party"
            if (!ZkJs.strictEq(transcriptSha256(t), ZkJs.get(evidence, "sha256")) || !ZkJs.strictEq(ZkJs.get(t, "vkId"), vkId(vkey))) return "single-party"
            return "multi-party"
        } catch (e: RuntimeException) {
            return "single-party"
        }
    }
}
