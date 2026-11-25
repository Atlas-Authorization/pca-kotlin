package net.atlasauth.pca.verifier

import java.math.BigInteger

/**
 * Zero-knowledge proof of compliance: the agent proves "this action is a valid derivation under the policy from the committed plan"
 * without revealing the policy, the plan or its reasoning to the resource server. Two realizations:
 *  - a Groth16 proof over a compliance circuit (`pca-compliance-v1`, the full Policy VM `pca-policyvm-v1` on BN254 and BLS12-381, the
 *    risk-bound `pca-policyvm-v2`). Everything except the pairing check is here: the envelope gate, the public-input derivation
 *    (binding tags, fixed-layout struct hashes, the deterministic action quantization) and the context pins. The pairing check and
 *    the prover come from a [Groth16Engine]; the optional pca-zk module registers the native one. Without an engine a proof is never
 *    reported invalid: verification throws [ZkBackendMissing].
 *  - the attested-VM equivalent: a trusted prover VM runs the Policy VM and signs a statement that carries only commitments.
 * In both, the verifier checks commitments only and never needs the plaintext policy or plan.
 */
@Suppress("UNCHECKED_CAST")
object Zk {
    private const val DOMAIN = "atlas-pca/zk-compliance/v1\u0000"

    /** `grantRef` of the binding a prover VM's hardware quote carries (see [proverKeyBinding]). */
    const val ZK_PROVER_BINDING_REF = "atlas-pca/zk-prover/v1"

    private fun table(vararg names: String): Map<String, Int> {
        val m = LinkedHashMap<String, Int>()
        for ((i, n) in names.withIndex()) m[n] = i
        return java.util.Collections.unmodifiableMap(m)
    }

    /** Public-signal layout of `pca-policyvm-v1` (circuit outputs, then the public inputs). */
    @JvmField val POLICYVM_PUBLIC_SIGNAL: Map<String, Int> =
        table("actionHi", "actionLo", "policyHi", "policyLo", "planHi", "planLo", "r", "t", "admit", "allow", "now", "blast", "delegationDepth", "recentCount", "allocChild")
    const val POLICYVM_PUBLIC_SIGNAL_COUNT = 15

    /** Public-signal layout of the risk-bound `pca-policyvm-v2`: the v1 statement plus the risk commitment halves. */
    @JvmField val POLICYVM_BOUND_PUBLIC_SIGNAL: Map<String, Int> = table(
        "actionHi", "actionLo", "policyHi", "policyLo", "planHi", "planLo", "r", "t", "admit", "riskHi", "riskLo", "allow", "now", "blast", "delegationDepth", "recentCount", "allocChild",
    )
    const val POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT = 17

    /** The risk magnitudes the v2 circuit commits to, in struct order. */
    @JvmField val POLICYVM_BOUND_RISK_FIELDS: List<String> = listOf("revScore", "taint", "conf", "age", "rFloorIn")

    /** The reversibility-class order the circuit's `reversibility` field and `revMax` caveat encode. */
    @JvmField val POLICYVM_REVERSIBILITY_ORDER: List<String> = listOf("reversible", "rate_limited", "irreversible")

    // Where the reference package keeps each artifact, relative to its root. Only the two Policy-VM verifying keys and the circuit
    // version table are bundled here ([policyVmVerificationKey], [policyVmBls12381VerificationKey], [circuitVersion]); the others
    // are build outputs a caller supplies.
    const val DEFAULT_VKEY_PATH = "circuits/build/verification_key.json"
    const val DEFAULT_WASM_PATH = "circuits/build/compliance_js/compliance.wasm"
    const val DEFAULT_ZKEY_PATH = "circuits/build/compliance_final.zkey"
    const val POLICYVM_VKEY_PATH = "circuits/policyvm_vkey.json"
    const val POLICYVM_SAMPLE_PROOF_PATH = "circuits/policyvm_sample_proof.json"
    const val POLICYVM_WASM_PATH = "circuits/build/policyvm_js/policyvm.wasm"
    const val POLICYVM_ZKEY_PATH = "circuits/build/policyvm_final.zkey"
    const val POLICYVM_BLS12381_VKEY_PATH = "circuits/policyvm_bls12381_vkey.json"
    const val POLICYVM_BLS12381_SAMPLE_PROOF_PATH = "circuits/policyvm_bls12381_sample_proof.json"
    const val POLICYVM_BOUND_VKEY_PATH = "circuits/build/policyvm_bound_vkey.json"
    const val POLICYVM_BOUND_SAMPLE_PROOF_PATH = "circuits/build/policyvm_bound_sample_proof.json"
    const val POLICYVM_BOUND_WASM_PATH = "circuits/build/policyvm_bound_js/policyvm_bound.wasm"
    const val POLICYVM_BOUND_ZKEY_PATH = "circuits/build/policyvm_bound_final.zkey"

    private val BN254_FR = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617")
    private val BN254_FQ = BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583")
    private val BLS12381_FQ = BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
    private val BLS12381_FR = BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
    private val U64_BOUND = BigInteger.ONE.shiftLeft(64)
    private val CANON_DEC = Regex("0|[1-9][0-9]*")
    private val DIGITS = Regex("[0-9]+")

    /** Pass as `expect` for "no context pins" (a null expectation is a refusal, not an absent one). */
    @JvmField val NO_EXPECT: Any = ZkJs.UNDEF

    /** A sha256 digest split into the circuit's two 128-bit big-endian halves (decimal strings). */
    class DigestHalves(val hi: String, val lo: String) {
        fun toMap(): Map<String, Any?> = linkedMapOf("hi" to hi, "lo" to lo)
    }

    // ---- commitments ----------------------------------------------------------------------------------------------------------

    /** Commitment to the policy: the grant's content address (its `id`, else the hash of the grant). */
    @JvmStatic
    fun policyCommitment(grant: Any?): String {
        val id = ZkJs.get(grant, "id")
        return if (id is String) id else Pca.hashCanonical(grant)
    }

    /** The policy commitment a resource server pins when it may not read the grant. */
    @JvmStatic
    fun pinnedPolicyCommitment(grant: Any?): String = policyCommitment(grant)

    /** Commitment to the action: the content address of the PCActn's action descriptor. */
    @JvmStatic
    fun actionCommitment(pcactn: Any?): String {
        val a = ZkJs.get(pcactn, "action")
        return Pca.hashCanonical(if (a === ZkJs.UNDEF) null else a)
    }

    /** The binding a prover VM puts in its hardware quote so the quote vouches for its key at this epoch and nonce. */
    @JvmStatic
    fun proverKeyBinding(proverPublicKey: String, epoch: Number, nonce: String): Map<String, Any?> =
        linkedMapOf("holderPub" to proverPublicKey, "grantRef" to ZK_PROVER_BINDING_REF, "epoch" to epoch, "nonce" to nonce)

    /**
     * A base64url commitment as a BN254 scalar-field element (decimal): the bytes, of any length, reduced mod r. This is the
     * circuit's public binding tag; prover and verifier derive it identically. Throws when the input is not canonical base64url.
     */
    @JvmStatic
    fun commitmentField(b64uCommit: String): String = BigInteger(1, Keys.unb64u(b64uCommit)).mod(BN254_FR).toString()

    // ---- the canonical Groth16 envelope gate ----------------------------------------------------------------------------------

    private fun canonDecBelow(v: Any?, bound: BigInteger): Boolean = v is String && v.length <= 120 && CANON_DEC.matches(v) && BigInteger(v) < bound

    private fun g1(a: Any?, fq: BigInteger): Boolean = a is List<*> && a.size == 3 && canonDecBelow(a[0], fq) && canonDecBelow(a[1], fq) && a[2] == "1"

    /**
     * True only for the one canonical Groth16 envelope of `curve` ("bn254", else BLS12-381): exactly the members snarkjs emits,
     * canonical decimal strings below the field modulus, z == 1. The same proof otherwise has many accepted encodings.
     */
    @JvmStatic
    fun isCanonicalGroth16Envelope(env: Any?, curve: String?): Boolean {
        if (env !is Map<*, *> || env.keys != setOf("system", "circuit", "proof", "publicSignals")) return false
        val bn = curve == "bn254"
        val fq = if (bn) BN254_FQ else BLS12381_FQ
        val fr = if (bn) BN254_FR else BLS12381_FR
        val ps = env["publicSignals"]
        if (ps !is List<*> || !ps.all { canonDecBelow(it, fr) }) return false
        val pr = env["proof"]
        if (pr !is Map<*, *> || pr.keys != setOf("pi_a", "pi_b", "pi_c", "protocol", "curve")) return false
        if (pr["protocol"] != "groth16" || pr["curve"] != (if (bn) "bn128" else "bls12381")) return false
        if (!g1(pr["pi_a"], fq) || !g1(pr["pi_c"], fq)) return false
        val b = pr["pi_b"]
        if (b !is List<*> || b.size != 3) return false
        for (i in 0..1) {
            val row = b[i]
            if (row !is List<*> || row.size != 2 || !canonDecBelow(row[0], fq) || !canonDecBelow(row[1], fq)) return false
        }
        val z = b[2]
        return z is List<*> && z.size == 2 && z[0] == "1" && z[1] == "0"
    }

    // ---- fixed-layout struct hashes -------------------------------------------------------------------------------------------

    /**
     * Serialize struct fields as the circuit does (each a 64-bit unsigned big-endian integer), sha256 them and split the digest into
     * the two 128-bit halves the circuit exposes. A field is a number, an integer string or a BigInteger; out of range throws.
     */
    @JvmStatic
    fun policyVmStructHash(fields: List<Any?>): DigestHalves {
        val bytes = ByteArray(fields.size * 8)
        for ((idx, f) in fields.withIndex()) {
            var v = ZkJs.bigInt(f)
            if (v.signum() < 0 || v >= U64_BOUND) throw IllegalArgumentException("policyVmStructHash: field out of uint64 range")
            for (b in 7 downTo 0) {
                bytes[idx * 8 + b] = v.toInt().toByte()
                v = v.shiftRight(8)
            }
        }
        val digest = Pca.sha(bytes)
        return DigestHalves(BigInteger(1, digest.copyOfRange(0, 16)).toString(), BigInteger(1, digest.copyOfRange(16, 32)).toString())
    }

    /** The risk commitment of `pca-policyvm-v2`: the struct hash of exactly the five risk magnitudes, in [POLICYVM_BOUND_RISK_FIELDS] order. */
    @JvmStatic
    fun policyVmRiskHash(fields: Any?): DigestHalves {
        if (fields !is List<*> || fields.size != POLICYVM_BOUND_RISK_FIELDS.size) throw IllegalArgumentException("policyVmRiskHash: need exactly 5 risk fields")
        return policyVmStructHash(fields as List<Any?>)
    }

    // ---- deterministic action -> quantized struct binding ---------------------------------------------------------------------

    /**
     * How verb / resource strings map to the circuit's uint64 codes. It must equal the map the prover used. A value absent from the
     * explicit maps is content-addressed unless [strictCatalog]; [paramScalarField] names the action param that is the `where` subject.
     */
    class QuantizeOpts(
        var verbCodes: Map<String, Any?>? = null,
        var resourceCodes: Map<String, Any?>? = null,
        var strictCatalog: Boolean = false,
        var paramScalarField: String? = null,
    )

    private fun contentAddressU64(domain: String, value: String): BigInteger =
        BigInteger(1, Pca.sha(Json.utf8("atlas-pca/policyvm-quantize/$domain:$value")).copyOfRange(0, 8))

    private fun toU64(v: Any?, what: String): BigInteger {
        val b = if (v is BigInteger) v else ZkJs.integerOf(v)
        if (b == null || b.signum() < 0 || b >= U64_BOUND) throw IllegalArgumentException("policyvm quantize: $what is not a uint64")
        return b
    }

    private fun codeFor(domain: String, value: Any?, map: Map<String, Any?>?, strict: Boolean): BigInteger {
        if (value !is String) throw IllegalArgumentException("policyvm quantize: $domain must be a string")
        if (map != null && map.containsKey(value)) return toU64(map[value], "$domain code")
        if (strict) throw IllegalArgumentException("policyvm quantize: $domain \"$value\" is not in the catalog (strict)")
        return contentAddressU64(domain, value)
    }

    // names every object answers to in the reference runtime: reading one as a param yields a non-number, which is refused
    private val INHERITED = setOf(
        "constructor", "toString", "valueOf", "toLocaleString", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "__proto__",
        "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__",
    )

    private fun paramScalarFrom(params: Any?, field: String?): BigInteger {
        if (field.isNullOrEmpty()) return BigInteger.ZERO
        val v = ZkJs.get(params, field)
        if (v === ZkJs.UNDEF) {
            if (params is Map<*, *> && field in INHERITED) throw IllegalArgumentException("policyvm quantize: paramScalar is not a non-negative integer")
            return BigInteger.ZERO
        }
        if (v == null) return BigInteger.ZERO
        if (v is BigInteger) return toU64(v, "paramScalar")
        val d = IntentJs.num(v)
        if (d != null) {
            if (ZkJs.integerOf(v) == null || d < 0 || IntentJs.isNegZero(d)) throw IllegalArgumentException("policyvm quantize: paramScalar must be a non-negative integer")
            return toU64(v, "paramScalar")
        }
        if (v is String && DIGITS.matches(v)) return toU64(BigInteger(v), "paramScalar")
        throw IllegalArgumentException("policyvm quantize: paramScalar is not a non-negative integer")
    }

    private fun reversibilityIndex(rc: Any?, what: String): BigInteger {
        val idx = if (rc is String) POLICYVM_REVERSIBILITY_ORDER.indexOf(rc) else -1
        if (idx < 0) throw IllegalArgumentException("policyvm quantize: unknown $what class \"" + ZkJs.string(rc) + "\"")
        return BigInteger.valueOf(idx.toLong())
    }

    /** What the reference reports when a quantizer is given `null` options (a TypeError reading `strictCatalog`). */
    private const val NULL_OPTS_MESSAGE = "Cannot read properties of null (reading 'strictCatalog')"

    /**
     * Quantize the live action `{verb, resource, reversibility_class?, params?}` to the circuit's 4-field struct: verb code, resource
     * code, reversibility-class index, param scalar. Throws (fail closed) on anything that cannot be quantized.
     */
    @JvmStatic
    @JvmOverloads
    fun quantizeActionStruct(action: Any?, options: QuantizeOpts? = QuantizeOpts()): List<BigInteger> {
        if (action !is Map<*, *>) throw IllegalArgumentException("policyvm quantize: action is missing")
        val opts = options ?: throw IllegalArgumentException(NULL_OPTS_MESSAGE)
        val verb = codeFor("verb", ZkJs.get(action, "verb"), opts.verbCodes, opts.strictCatalog)
        val resource = codeFor("resource", ZkJs.get(action, "resource"), opts.resourceCodes, opts.strictCatalog)
        val rc = ZkJs.get(action, "reversibility_class")
        val rev = reversibilityIndex(if (rc == null || rc === ZkJs.UNDEF) "reversible" else rc, "reversibility")
        return listOf(verb, resource, rev, paramScalarFrom(ZkJs.get(action, "params"), opts.paramScalarField))
    }

    /** Quantize the plan node `{verb, resource, semanticDist, planSalt}` to the circuit's 4-field plan struct. */
    @JvmStatic
    @JvmOverloads
    fun quantizePlanStruct(plan: Map<String, Any?>, options: QuantizeOpts? = QuantizeOpts()): List<BigInteger> = (options ?: throw IllegalArgumentException(NULL_OPTS_MESSAGE)).let { opts -> listOf(
        codeFor("verb", ZkJs.get(plan, "verb"), opts.verbCodes, opts.strictCatalog),
        codeFor("resource", ZkJs.get(plan, "resource"), opts.resourceCodes, opts.strictCatalog),
        toU64(ZkJs.get(plan, "semanticDist"), "semanticDist"),
        toU64(ZkJs.get(plan, "planSalt"), "planSalt"),
    ) }

    /**
     * Quantize the policy `{weights: {alpha..zeta}, theta1, theta2, kappa, budgetB, policyVerb, policyResource, policyParamBound,
     * expiresAt, notBefore, maxBlast, maxDepth, revMax, rateMax, allocParent}` to the circuit's 20-field policy struct.
     */
    @JvmStatic
    @JvmOverloads
    fun quantizePolicyStruct(policy: Map<String, Any?>, options: QuantizeOpts? = QuantizeOpts()): List<BigInteger> {
        val w = ZkJs.get(policy, "weights")
        if (w == null || w === ZkJs.UNDEF) throw IllegalArgumentException("policyvm quantize: policy weights are missing")
        val opts = options ?: throw IllegalArgumentException(NULL_OPTS_MESSAGE)
        return listOf(
            toU64(ZkJs.get(w, "alpha"), "wAlpha"),
            toU64(ZkJs.get(w, "beta"), "wBeta"),
            toU64(ZkJs.get(w, "gamma"), "wGamma"),
            toU64(ZkJs.get(w, "delta"), "wDelta"),
            toU64(ZkJs.get(w, "epsilon"), "wEpsilon"),
            toU64(ZkJs.get(w, "zeta"), "wZeta"),
            toU64(ZkJs.get(policy, "theta1"), "theta1"),
            toU64(ZkJs.get(policy, "theta2"), "theta2"),
            toU64(ZkJs.get(policy, "kappa"), "kappa"),
            toU64(ZkJs.get(policy, "budgetB"), "budgetB"),
            codeFor("verb", ZkJs.get(policy, "policyVerb"), opts.verbCodes, opts.strictCatalog),
            codeFor("resource", ZkJs.get(policy, "policyResource"), opts.resourceCodes, opts.strictCatalog),
            toU64(ZkJs.get(policy, "policyParamBound"), "policyParamBound"),
            toU64(ZkJs.get(policy, "expiresAt"), "expiresAt"),
            toU64(ZkJs.get(policy, "notBefore"), "notBefore"),
            toU64(ZkJs.get(policy, "maxBlast"), "maxBlast"),
            toU64(ZkJs.get(policy, "maxDepth"), "maxDepth"),
            reversibilityIndex(ZkJs.get(policy, "revMax"), "revMax"),
            toU64(ZkJs.get(policy, "rateMax"), "rateMax"),
            toU64(ZkJs.get(policy, "allocParent"), "allocParent"),
        )
    }

    /** `{action, plan?, policy?}` quantized: the action struct always, the plan and policy structs when given. */
    @JvmStatic
    @JvmOverloads
    fun quantizePolicyVmInputs(inp: Map<String, Any?>, opts: QuantizeOpts? = QuantizeOpts()): Map<String, List<BigInteger>> {
        val out = LinkedHashMap<String, List<BigInteger>>()
        out["action"] = quantizeActionStruct(ZkJs.get(inp, "action"), opts)
        val plan = ZkJs.get(inp, "plan")
        if (ZkJs.truthy(plan)) out["plan"] = quantizePlanStruct(plan as Map<String, Any?>, opts)
        val policy = ZkJs.get(inp, "policy")
        if (ZkJs.truthy(policy)) out["policy"] = quantizePolicyStruct(policy as Map<String, Any?>, opts)
        return out
    }

    /**
     * The circuit's action commitment recomputed from the live action. A resource server binds a Policy-VM proof to this action by
     * requiring the proof's `actionHi` / `actionLo` to equal these halves.
     */
    @JvmStatic
    @JvmOverloads
    fun policyVmCommitmentFromAction(action: Any?, opts: QuantizeOpts? = QuantizeOpts()): DigestHalves = policyVmStructHash(quantizeActionStruct(action, opts))

    // ---- public-signal decoding and context pins ------------------------------------------------------------------------------

    private fun halvesAt(ps: List<Any?>, layout: Map<String, Int>, hi: String, lo: String): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        if (layout.getValue(hi) < ps.size) m["hi"] = ps[layout.getValue(hi)]
        if (layout.getValue(lo) < ps.size) m["lo"] = ps[layout.getValue(lo)]
        return m
    }

    private fun decode(ps: List<Any?>, layout: Map<String, Int>, risk: Boolean): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        out["actionHash"] = halvesAt(ps, layout, "actionHi", "actionLo")
        out["policyHash"] = halvesAt(ps, layout, "policyHi", "policyLo")
        out["planHash"] = halvesAt(ps, layout, "planHi", "planLo")
        if (risk) out["riskHash"] = halvesAt(ps, layout, "riskHi", "riskLo")
        for (k in listOf("r", "t", "admit", "allow", "now", "blast", "delegationDepth", "recentCount", "allocChild")) {
            if (layout.getValue(k) < ps.size) out[k] = ps[layout.getValue(k)]
        }
        return out
    }

    /** The public signals of a v1 proof as the proven statement (hash halves, risk / threshold / admit, context); absent signals are left out. */
    @JvmStatic
    fun decodePolicyVmPublic(publicSignals: List<Any?>): Map<String, Any?> = decode(publicSignals, POLICYVM_PUBLIC_SIGNAL, false)

    /** The public signals of a v2 proof: the v1 statement plus `riskHash`. */
    @JvmStatic
    fun decodePolicyVmBoundPublic(publicSignals: List<Any?>): Map<String, Any?> = decode(publicSignals, POLICYVM_BOUND_PUBLIC_SIGNAL, true)

    private fun pinBigint(v: Any?): BigInteger? = try {
        if (v !is BigInteger && IntentJs.num(v) != null && !IntentJs.isSafeInteger(v)) null else ZkJs.bigInt(v)
    } catch (e: RuntimeException) {
        null
    }

    private fun signalMatchesPin(signal: Any?, pin: Any?): Boolean {
        if (signal !is String || !CANON_DEC.matches(signal)) return false
        val x = BigInteger(signal)
        if (pin == null) throw IllegalArgumentException("policyVmContextMatches: a pin must not be null")
        if (pin is Map<*, *> || pin is List<*>) {
            val lo = pinBigint(ZkJs.get(pin, "min"))
            val hi = pinBigint(ZkJs.get(pin, "max"))
            return lo != null && hi != null && lo <= hi && x >= lo && x <= hi
        }
        val want = pinBigint(pin)
        return want != null && x == want
    }

    /**
     * Do the public signals satisfy `expect`? `expect` is a map of pins (`now`, `blast`, `delegationDepth`, `recentCount`,
     * `allocChild`, `r`, `t`: an exact value or `{min, max}`; `requireAdmit`, `requireTier1`), or a function returning one (so `now`
     * can follow a live clock), or [NO_EXPECT]. Even with no pins a context signal that is not a canonical decimal below 2^64 is
     * refused: the circuit's comparators run on un-range-checked public inputs. `bound` selects the v2 layout.
     */
    @JvmStatic
    @JvmOverloads
    fun policyVmContextMatches(ps: List<Any?>, expect: Any? = ZkJs.UNDEF, bound: Boolean = false): Boolean {
        val layout = if (bound) POLICYVM_BOUND_PUBLIC_SIGNAL else POLICYVM_PUBLIC_SIGNAL
        for (k in listOf("now", "blast", "delegationDepth", "recentCount", "allocChild")) {
            val sig = ps.getOrNull(layout.getValue(k))
            if (sig !is String || !CANON_DEC.matches(sig) || BigInteger(sig) >= U64_BOUND) return false
        }
        if (expect === ZkJs.UNDEF) return true
        val e: Any? = if (expect is Function0<*>) {
            try {
                expect.invoke()
            } catch (x: RuntimeException) {
                return false
            }
        } else expect
        if (e !is Map<*, *> && e !is List<*>) return false
        for (k in listOf("now", "blast", "delegationDepth", "recentCount", "allocChild", "r", "t")) {
            val pin = ZkJs.get(e, k)
            if (pin !== ZkJs.UNDEF && !signalMatchesPin(ps.getOrNull(layout.getValue(k)), pin)) return false
        }
        if (ZkJs.truthy(ZkJs.get(e, "requireAdmit")) && ps.getOrNull(layout.getValue("admit")) != "1") return false
        if (ZkJs.truthy(ZkJs.get(e, "requireTier1")) && ps.getOrNull(layout.getValue("t")) != "1") return false
        return true
    }

    // ---- the Groth16 engine seam ----------------------------------------------------------------------------------------------

    /** The pairing check and the prover. The optional pca-zk module registers the native implementation. */
    interface Groth16Engine {
        /**
         * The Groth16 pairing check of `proof` for `publicSignals` under the verifying key `vkey` (all in the snarkjs JSON encoding),
         * with the acceptance rules of snarkjs `groth16.verify`. False for an invalid proof; an engine that cannot run must throw.
         */
        fun verify(vkey: Any?, publicSignals: List<Any?>, proof: Any?): Boolean

        /** Prove `input` with the circuit's witness calculator `wasm` and proving key `zkey`; `curve` is "bn128" or "bls12381". Returns `{proof, publicSignals}`. */
        fun prove(curve: String, wasm: ByteArray, zkey: ByteArray, input: Map<String, String>): Map<String, Any?>
    }

    const val NO_GROTH16_ENGINE_MESSAGE = "no Groth16 engine is registered (register one with Zk.registerGroth16, or use the pca-zk module)"

    /** No engine can answer the pairing question (none registered, or its library cannot run): never read as "the proof is invalid". */
    class ZkBackendMissing @JvmOverloads constructor(message: String = NO_GROTH16_ENGINE_MESSAGE) : IllegalStateException(message)

    @Volatile private var groth16: Groth16Engine? = null

    /** Install the Groth16 engine; nothing registers itself at load. */
    @JvmStatic
    fun registerGroth16(engine: Groth16Engine) { groth16 = engine }

    @JvmStatic
    fun unregisterGroth16() { groth16 = null }

    private fun engine(): Groth16Engine = groth16 ?: throw ZkBackendMissing()

    /** The bundled `pca-policyvm-v1` verifying key (BN254), as parsed JSON. */
    @JvmStatic
    fun policyVmVerificationKey(): Any? = ZkBundled.policyVmVkey

    /** The bundled `pca-policyvm-v1` verifying key on BLS12-381. */
    @JvmStatic
    fun policyVmBls12381VerificationKey(): Any? = ZkBundled.policyVmBls12381Vkey

    /** The committed version of a circuit id: `{circuit, sourceSha256, circom, circomlib}`; throws on an unknown id. */
    @JvmStatic
    fun circuitVersion(id: String): Map<String, Any?> {
        val sha = ZkBundled.CIRCUIT_SOURCES[id] ?: throw IllegalArgumentException("circuitVersion: unknown circuit " + Json.canonicalize(id))
        return linkedMapOf("circuit" to id, "sourceSha256" to sha, "circom" to ZkBundled.CIRCOM, "circomlib" to ZkBundled.CIRCOMLIB)
    }

    // ---- Policy-VM proof verification -----------------------------------------------------------------------------------------

    /** `verificationKey`: the snarkjs key JSON (null = the bundled key of the proof's curve). `expect`: see [policyVmContextMatches]. */
    open class VerifyOpts {
        var verificationKey: Any? = null
        var expect: Any? = ZkJs.UNDEF

        /** Pin the risk commitment ([policyVmRiskHash]); only a `pca-policyvm-v2` proof with these halves then passes. */
        var expectRiskHash: DigestHalves? = null
    }

    /**
     * Verify a full Policy-VM Groth16 proof envelope `{system, circuit, proof, publicSignals}` against the verifying key: a
     * well-formed canonical envelope of a known circuit and curve, allow == 1, the risk pin, the context pins, then the pairing
     * check. False on any malformed input. Throws [ZkBackendMissing] when no engine is registered, and when a v2 proof is given no key.
     */
    @JvmStatic
    @JvmOverloads
    fun verifyPolicyVmProof(env: Any?, opts: VerifyOpts = VerifyOpts()): Boolean {
        val circuit = ZkJs.get(env, "circuit")
        val bound = circuit == "pca-policyvm-v2"
        if (circuit != "pca-policyvm-v1" && !bound) return false
        val system = ZkJs.get(env, "system")
        val isBls = system == "groth16-bls12-381"
        if (system != "groth16-bn254" && !(isBls && !bound)) return false // the risk-bound circuit is BN254 only
        val layout = if (bound) POLICYVM_BOUND_PUBLIC_SIGNAL else POLICYVM_PUBLIC_SIGNAL
        val ps = ZkJs.get(env, "publicSignals")
        val proof = ZkJs.get(env, "proof")
        if (ps !is List<*> || ps.size != (if (bound) POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT else POLICYVM_PUBLIC_SIGNAL_COUNT) || proof == null || proof === ZkJs.UNDEF) return false
        if (ps[layout.getValue("allow")] != "1") return false
        val risk = opts.expectRiskHash
        if (risk != null) {
            if (!bound || ps[POLICYVM_BOUND_PUBLIC_SIGNAL.getValue("riskHi")] != risk.hi || ps[POLICYVM_BOUND_PUBLIC_SIGNAL.getValue("riskLo")] != risk.lo) return false
        }
        if (!isCanonicalGroth16Envelope(env, if (isBls) "bls12-381" else "bn254")) return false
        if (!policyVmContextMatches(ps as List<Any?>, opts.expect, bound)) return false
        var vkey = opts.verificationKey
        if (vkey == null) {
            if (bound) throw IllegalStateException("verifyPolicyVmProof: pca-policyvm-v2 has no bundled verifying key, pass verificationKey")
            vkey = if (isBls) ZkBundled.policyVmBls12381Vkey else ZkBundled.policyVmVkey
        }
        val e = engine()
        return try {
            e.verify(vkey, ps, proof)
        } catch (x: ZkBackendMissing) {
            throw x
        } catch (x: RuntimeException) {
            false
        }
    }

    // ---- SNARK backends -------------------------------------------------------------------------------------------------------

    /** A proof backend for [createZkVerifier]: it receives the opaque proof and only commitments as public inputs. */
    fun interface SnarkBackend {
        fun verify(proof: Any?, publicInputs: Map<String, Any?>, ctx: Any?): Boolean
    }

    /**
     * Backend options. `ceremony` is `{transcript, sha256}` for [verificationKey]: without it the backend reports
     * `ceremony: single-party`. The `expect*Hash` halves bind the proof's public struct hashes ([policyVmStructHash]).
     */
    class BackendOpts : VerifyOpts() {
        var ceremony: Map<String, Any?>? = null
        var expectActionHash: DigestHalves? = null
        var expectPolicyHash: DigestHalves? = null
        var expectPlanHash: DigestHalves? = null
    }

    private fun ceremonyLabel(o: BackendOpts, circuit: String): String {
        val c = o.ceremony
        val evidence = if (c == null) null else LinkedHashMap<String, Any?>(c).also { it["circuit"] = circuit }
        return ZkCeremony.ceremonyOf(o.verificationKey, evidence)
    }

    private fun halvesMatch(ps: List<*>, layout: Map<String, Int>, hi: String, lo: String, want: DigestHalves?): Boolean =
        want == null || (ps.getOrNull(layout.getValue(hi)) == want.hi && ps.getOrNull(layout.getValue(lo)) == want.lo)

    /**
     * The Groth16 backend of the first circuit (`pca-compliance-v1`, BN254): a well-formed envelope, allow == 1, the circuit's binding
     * tags equal to [commitmentField] of the resource server's own commitments, the canonical envelope, then the pairing check. It
     * has no bundled key: `verificationKey` is required. Label `groth16`.
     */
    @JvmStatic
    fun createGroth16SnarkBackend(opts: BackendOpts): SnarkBackend {
        val backend = object : SnarkBackend {
            override fun verify(proof: Any?, publicInputs: Map<String, Any?>, ctx: Any?): Boolean {
                if (proof !is Map<*, *>) return false
                if (proof["system"] != "groth16-bn254" || proof["circuit"] != "pca-compliance-v1") return false
                val ps = proof["publicSignals"]
                val g16 = proof["proof"]
                if (ps !is List<*> || ps.size != 7 || g16 == null) return false
                if (ps[6] != "1") return false
                if (ps[3] != commitmentField(publicInputs["policy_commit"] as String)) return false
                if (ps[4] != commitmentField(publicInputs["plan_commit"] as String)) return false
                if (ps[5] != commitmentField(publicInputs["action_commit"] as String)) return false
                if (!isCanonicalGroth16Envelope(proof, "bn254")) return false
                val vkey = opts.verificationKey ?: throw IllegalStateException("createGroth16SnarkBackend: pca-compliance-v1 has no bundled verifying key, pass verificationKey")
                return engine().verify(vkey, ps as List<Any?>, g16)
            }
        }
        return Assurance.setLabel(backend, "groth16", null, null, ceremonyLabel(opts, "pca-compliance-v1"))
    }

    private fun policyVmBackend(opts: BackendOpts, bls: Boolean): SnarkBackend {
        val backend = object : SnarkBackend {
            override fun verify(proof: Any?, publicInputs: Map<String, Any?>, ctx: Any?): Boolean {
                if (ZkJs.get(proof, "circuit") != "pca-policyvm-v1") return false
                val ps = ZkJs.get(proof, "publicSignals")
                if (ps is List<*>) {
                    val l = POLICYVM_PUBLIC_SIGNAL
                    if (!halvesMatch(ps, l, "actionHi", "actionLo", opts.expectActionHash) || !halvesMatch(ps, l, "policyHi", "policyLo", opts.expectPolicyHash) ||
                        !halvesMatch(ps, l, "planHi", "planLo", opts.expectPlanHash)
                    ) return false
                }
                val v = VerifyOpts()
                v.verificationKey = opts.verificationKey ?: (if (bls) ZkBundled.policyVmBls12381Vkey else ZkBundled.policyVmVkey)
                v.expect = opts.expect
                return verifyPolicyVmProof(proof, v)
            }
        }
        val ceremony = ceremonyLabel(opts, "pca-policyvm-v1")
        return if (opts.expectActionHash != null && opts.expectPolicyHash != null && opts.expectPlanHash != null) Assurance.setLabel(backend, "policyvm_snark", null, null, ceremony)
        else Assurance.setLabel(backend, "unknown", "policyvm-unbound", null, ceremony)
    }

    /**
     * A backend over the full Policy-VM circuit on BN254. It verifies the proof and allow == 1 and, when expected struct hashes are
     * given, binds the proof's public hash halves to them. Label `policyvm_snark` only with all three pinned; otherwise a valid proof
     * may be for another compliant action, and the label is `unknown` (`policyvm-unbound`).
     */
    @JvmStatic
    @JvmOverloads
    fun createPolicyVmSnarkBackend(opts: BackendOpts = BackendOpts()): SnarkBackend = policyVmBackend(opts, false)

    /** The BLS12-381 counterpart of [createPolicyVmSnarkBackend]: the same binding, the bundled BLS12-381 key by default. */
    @JvmStatic
    @JvmOverloads
    fun createPolicyVmSnarkBackendBls12381(opts: BackendOpts = BackendOpts()): SnarkBackend = policyVmBackend(opts, true)

    /**
     * A backend over the risk-bound circuit (`pca-policyvm-v2`, BN254): the checks of [createPolicyVmSnarkBackend] plus the risk
     * commitment. Label `policyvm_snark` only when all four commitments are pinned. There is no bundled key: pass `verificationKey`.
     */
    @JvmStatic
    fun createPolicyVmBoundSnarkBackend(opts: BackendOpts): SnarkBackend {
        val backend = object : SnarkBackend {
            override fun verify(proof: Any?, publicInputs: Map<String, Any?>, ctx: Any?): Boolean {
                val ps = ZkJs.get(proof, "publicSignals")
                if (ZkJs.get(proof, "circuit") != "pca-policyvm-v2" || ps !is List<*>) return false
                val l = POLICYVM_BOUND_PUBLIC_SIGNAL
                if (!halvesMatch(ps, l, "actionHi", "actionLo", opts.expectActionHash) || !halvesMatch(ps, l, "policyHi", "policyLo", opts.expectPolicyHash) ||
                    !halvesMatch(ps, l, "planHi", "planLo", opts.expectPlanHash) || !halvesMatch(ps, l, "riskHi", "riskLo", opts.expectRiskHash)
                ) return false
                val v = VerifyOpts()
                v.verificationKey = opts.verificationKey
                v.expect = opts.expect
                v.expectRiskHash = opts.expectRiskHash
                return verifyPolicyVmProof(proof, v)
            }
        }
        val ceremony = ceremonyLabel(opts, "pca-policyvm-v2")
        val pinned = opts.expectActionHash != null && opts.expectPolicyHash != null && opts.expectPlanHash != null && opts.expectRiskHash != null
        return if (pinned) Assurance.setLabel(backend, "policyvm_snark", null, null, ceremony) else Assurance.setLabel(backend, "unknown", "policyvm-unbound", null, ceremony)
    }

    // ---- the attested-VM statement and the verifier hook ----------------------------------------------------------------------

    private fun statementMessage(body: Map<String, Any?>): ByteArray = Pca.concat(Json.utf8(DOMAIN), Pca.canonBytes(body))

    /** The attested-VM prover: the stand-in for a SNARK prover. Its key is what a resource server lists in `trustedProverKeys`. */
    class AttestedComplianceProver internal constructor(private val key: Keys.EdKey) {
        /** The base64url public key the resource server registers. */
        val publicKey: String = key.id()

        /**
         * Run the Policy VM on `decideInput` and, only when it releases the guardian share, sign a statement that commits to the
         * action, the policy (the grant in `decideInput`) and the plan. Throws when the action is not compliant.
         */
        fun prove(pcactn: Any?, decideInput: Map<String, Any?>, issuedAt: Long, expiresAt: Long): Map<String, Any?> {
            val decision = Decide.decide(decideInput)
            if (decision["releaseGuardianShare"] != true) {
                val reasons = (decision["reasons"] as? List<*>)?.joinToString("; ") ?: ""
                throw IllegalArgumentException("createAttestedComplianceProver: action is not compliant, nothing to prove ($reasons)")
            }
            val root = ZkJs.get(ZkJs.get(pcactn, "plan"), "root")
            val body = LinkedHashMap<String, Any?>()
            body["v"] = 1L
            body["mode"] = "attested-vm"
            body["action_commit"] = actionCommitment(pcactn)
            body["policy_commit"] = policyCommitment(ZkJs.get(decideInput, "grant"))
            body["plan_commit"] = if (root is String) root else ""
            body["released"] = true
            body["r"] = decision["r"]
            body["issued_at"] = issuedAt
            body["expires_at"] = expiresAt
            body["prover"] = publicKey
            val out = LinkedHashMap(IntentJs.normalize(body) as Map<String, Any?>)
            out["sig"] = Keys.b64u(key.sign(statementMessage(out)))
            return out
        }
    }

    /** The attested-VM prover for an Ed25519 seed (the prover VM's key). */
    @JvmStatic
    fun createAttestedComplianceProver(attestorSeed: ByteArray): AttestedComplianceProver = AttestedComplianceProver(Keys.edFromSeed(attestorSeed))

    /** What a hardware check of the prover VM found: `bound` = the quote vouches for this prover key, `runtimeMeasurement` = the VM image. */
    class ProverHardwareResult(val ok: Boolean, val reason: String? = null, val bound: Boolean = false, val runtimeMeasurement: String? = null)

    /** Verifies the hardware quote of a prover VM for `proverPublicKey` against the `expected` binding ([proverKeyBinding]). */
    fun interface ProverHardwareVerifier {
        fun verify(proverPublicKey: String, ctx: Any?, nowMs: Double, expected: Map<String, Any?>): ProverHardwareResult?
    }

    /**
     * Binds the attested-VM prover key to hardware evidence. The verifier must carry a `hardware` or `multi_root` assurance label
     * ([Assurance.setLabel]); `measurements` is the non-empty allowlist of VM images; `expectedBinding` gives the binding the quote
     * must carry for a prover key (throwing denies).
     */
    class ProverAttestation(val hardwareVerifier: ProverHardwareVerifier, val measurements: List<String>, val expectedBinding: (String) -> Map<String, Any?>)

    class VerifierOpts {
        /** Public keys of the attested prover VMs trusted in attested-VM mode. */
        var trustedProverKeys: List<String> = emptyList()

        /** The expected policy commitments as bare hashes; null = derive the commitment from the verifier's grant. */
        var policyCommitments: List<String>? = null

        /** Delegate proof verification to a SNARK backend (the proof is then opaque to this hook). */
        var snarkBackend: SnarkBackend? = null

        /** Prover keys no longer trusted: a statement signed by one is denied even while still listed as trusted. */
        var revokedProverKeys: List<String>? = null

        /** Attested-VM mode only: require hardware evidence for the prover key. */
        var proverAttestation: ProverAttestation? = null

        /** Clock in epoch ms (default: the system clock). */
        var now: (() -> Double)? = null

        /** Allowed clock skew in ms for issued_at / expires_at (default 0; a non-finite or negative value is 0). */
        var clockSkewMs: Double? = null
    }

    /** The zk hook: [run] for the core verifier, [check] for a PCActn and grant in hand. Its configuration is fixed at construction. */
    class ZkVerifier internal constructor(o: VerifierOpts) : PcaCore.Hook {
        private val trusted: Set<String> = HashSet(o.trustedProverKeys)
        private val revoked: Set<String> = HashSet(o.revokedProverKeys ?: emptyList())
        private val expectedPolicy: Set<String>? = o.policyCommitments?.let { LinkedHashSet(it) }
        private val snarkBackend: SnarkBackend? = o.snarkBackend
        private val attestation: ProverAttestation? = if (o.snarkBackend != null) null else o.proverAttestation
        private val measurements: Set<String> = HashSet(attestation?.measurements ?: emptyList())
        private val clock: () -> Double = o.now ?: { System.currentTimeMillis().toDouble() }
        private val skew: Double = o.clockSkewMs.let { if (it == null || it.isNaN() || it.isInfinite()) 0.0 else Math.max(0.0, it) }

        private fun fail(reason: String): PcaCore.HookResult = PcaCore.HookResult.enforced(false, reason)

        override fun run(ctx: PcaCore.Ctx): PcaCore.HookResult = check(ctx.pcactn, ctx.grant, ctx)

        /** `{enforced: true, ok}` with the first reason on a failure; never throws (an error is a failure). */
        @JvmOverloads
        fun check(pcactn: Any?, grant: Any?, ctx: Any? = null): PcaCore.HookResult {
            try {
                val proof = ZkJs.get(pcactn, "zk_compliance")
                if (proof == null || proof === ZkJs.UNDEF) return fail("no zk_compliance proof present")
                val actionCommit = actionCommitment(pcactn)
                val root = ZkJs.get(ZkJs.get(pcactn, "plan"), "root")
                val planCommit = if (root is String) root else ""
                val wantPolicy: Set<String> = expectedPolicy ?: setOf(policyCommitment(grant))

                val backend = snarkBackend
                if (backend != null) {
                    val policyCommit = if (expectedPolicy != null && expectedPolicy.size == 1) expectedPolicy.first() else policyCommitment(grant)
                    val ok = backend.verify(proof, linkedMapOf("action_commit" to actionCommit, "policy_commit" to policyCommit, "plan_commit" to planCommit), ctx)
                    return if (ok) PcaCore.HookResult.enforced(true) else fail("snark backend rejected the proof")
                }

                val v = IntentJs.num(ZkJs.get(proof, "v"))
                if (v == null || v != 1.0 || ZkJs.get(proof, "mode") != "attested-vm") return fail("unrecognized compliance statement")
                if (ZkJs.get(proof, "released") != true) return fail("statement does not assert release")
                val prover = ZkJs.get(proof, "prover")
                if (prover !is String || prover !in trusted) return fail("prover key is not trusted")
                if (prover in revoked) return fail("prover key is revoked")

                val st = proof as Map<String, Any?>
                val sig = st["sig"]
                val body = LinkedHashMap(st)
                body.remove("sig")
                if (sig !is String || !Pca.verifyB64u(prover, statementMessage(body), sig)) return fail("compliance statement signature does not verify")

                val issued = ZkJs.finite(st["issued_at"])
                val expires = ZkJs.finite(st["expires_at"])
                if (issued == null || expires == null || expires < issued) return fail("malformed statement validity window")
                val nowMs = clock()
                if (!nowMs.isFinite()) return fail("compliance statement cannot be dated: the clock is not a finite number")
                if (nowMs + skew < issued) return fail("compliance statement not yet valid")
                if (nowMs - skew > expires) return fail("compliance statement expired")

                if (st["action_commit"] != actionCommit) return fail("statement does not bind to this action")
                if (st["plan_commit"] != planCommit) return fail("statement does not bind to this plan commitment")
                val policy = st["policy_commit"]
                if (policy !is String || policy !in wantPolicy) return fail("statement policy commitment is not an expected policy")

                // hardware binding of the prover key (last: the expensive check); anything but a bound, measured, allowlisted identity denies
                val pa = attestation
                if (pa != null) {
                    val hw = pa.hardwareVerifier.verify(prover, ctx, nowMs, pa.expectedBinding(prover))
                    if (hw == null || !hw.ok) return fail("prover hardware evidence invalid: " + (if (hw == null) "no result" else hw.reason ?: "no reason given"))
                    if (!hw.bound) return fail("prover hardware evidence does not bind the prover key")
                    val measured = hw.runtimeMeasurement ?: return fail("prover hardware evidence carries no measured identity")
                    if (measured !in measurements) return fail("prover VM measurement is not allowlisted")
                }
                return PcaCore.HookResult.enforced(true)
            } catch (e: RuntimeException) {
                return fail("zk verification error (fail closed): " + (e.message ?: "unknown"))
            }
        }
    }

    /**
     * Build the zk hook. The proof is carried in `pcactn.zk_compliance`. SNARK mode (a `snarkBackend`): the backend gets the three
     * commitments as public inputs. Attested-VM mode: the statement is well-formed, its prover is trusted and not revoked, its
     * signature verifies, it is fresh, and it commits to this action, this plan root and an expected policy. The hook's assurance
     * label is the backend's (`unknown` when it declares none), `attested_vm_hw` with hardware-bound prover keys, else `attested_vm`.
     */
    @JvmStatic
    fun createZkVerifier(opts: VerifierOpts): ZkVerifier {
        val backend = opts.snarkBackend
        val pa = if (backend != null) null else opts.proverAttestation
        var hw: Assurance.Label? = null
        if (pa != null) {
            hw = Assurance.labelOf(pa.hardwareVerifier)
            if (hw == null || (hw.level != "hardware" && hw.level != "multi_root")) throw IllegalArgumentException("createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label")
            if (pa.measurements.isEmpty() || pa.measurements.any { it.isEmpty() }) throw IllegalArgumentException("createZkVerifier: proverAttestation.measurements must be a non-empty allowlist")
        }
        val hook = ZkVerifier(opts)
        if (backend != null) {
            val l = Assurance.labelOf(backend)
            return if (l == null) Assurance.setLabel(hook, "unknown") else Assurance.setLabel(hook, l.level, l.vendor, l.awaitingAudit, l.ceremony)
        }
        return if (hw != null) Assurance.setLabel(hook, "attested_vm_hw", "hardware-bound:" + (hw.vendor ?: hw.level)) else Assurance.setLabel(hook, "attested_vm")
    }

    // ---- provers --------------------------------------------------------------------------------------------------------------

    private fun fullProve(curve: String, system: String, circuit: String, input: Map<String, String>, wasm: ByteArray, zkey: ByteArray): Map<String, Any?> {
        val r = engine().prove(curve, wasm, zkey, input)
        return linkedMapOf("system" to system, "circuit" to circuit, "proof" to r["proof"], "publicSignals" to r["publicSignals"])
    }

    private fun stringInputs(witness: Map<String, Any?>): Map<String, String> {
        val input = LinkedHashMap<String, String>()
        for ((k, v) in witness) input[k] = ZkJs.string(v)
        return input
    }

    /**
     * A Groth16 proof of the first circuit from the private witness `{verb, resource, planVerb, policySalt, planSalt, actionSalt,
     * risk, budget}` and the commitments to bind to (`action_commit`, `policy_commit`, `plan_commit`). `wasm` and `zkey` are the
     * circuit's witness calculator and proving key. A non-compliant witness cannot be proven (throws).
     */
    @JvmStatic
    fun proveGroth16Compliance(inp: Map<String, Any?>, wasm: ByteArray, zkey: ByteArray): Map<String, Any?> {
        val input = LinkedHashMap<String, String>()
        for (k in listOf("verb", "resource", "planVerb", "policySalt", "planSalt", "actionSalt", "risk", "budget")) input[k] = ZkJs.string(ZkJs.get(inp, k))
        input["shaPolicy"] = commitmentField(inp["policy_commit"] as String)
        input["shaPlan"] = commitmentField(inp["plan_commit"] as String)
        input["shaAction"] = commitmentField(inp["action_commit"] as String)
        input["allow"] = "1"
        return fullProve("bn128", "groth16-bn254", "pca-compliance-v1", input, wasm, zkey)
    }

    /** A full Policy-VM proof (`pca-policyvm-v1`, BN254) from the complete fixed-point witness. A denied action cannot be proven (throws). */
    @JvmStatic
    fun provePolicyVmCompliance(witness: Map<String, Any?>, wasm: ByteArray, zkey: ByteArray): Map<String, Any?> =
        fullProve("bn128", "groth16-bn254", "pca-policyvm-v1", stringInputs(witness), wasm, zkey)

    /** A risk-bound proof (`pca-policyvm-v2`, BN254); the same witness inputs as [provePolicyVmCompliance]. */
    @JvmStatic
    fun provePolicyVmBoundCompliance(witness: Map<String, Any?>, wasm: ByteArray, zkey: ByteArray): Map<String, Any?> =
        fullProve("bn128", "groth16-bn254", "pca-policyvm-v2", stringInputs(witness), wasm, zkey)
}
