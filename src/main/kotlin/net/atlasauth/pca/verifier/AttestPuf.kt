package net.atlasauth.pca.verifier

import java.security.MessageDigest

/**
 * The PUF (physical unclonable function) attestation root: an independent root whose identity is derived from a device's unclonable response (SRAM
 * start-up state, ring oscillators, a TPM endorsement key). This is the software layer that turns a noisy reading into a stable key and verifies it: a
 * fuzzy extractor (code-offset secure sketch over a repetition code with an HKDF-SHA256 strong extractor), a provider seam with a simulated PUF for tests and a
 * TPM-endorsement-key provider over an injected `tpm2-tools` runner, enrollment, the device attestor, an enrollment registry and the verifier.
 *
 * Honest scope: unclonability is a classical property of the device, a different axis from quantum resistance, though the derived key may carry an ML-DSA
 * suite so the identity is both. The root attests a device identity, never a silicon measurement of the loaded weights (`weights_measured: false`). The
 * simulated PUF is a pure function of a seed and is clonable: it is for tests only. A response is a byte array holding one 0 or 1 per bit.
 */
@Suppress("UNCHECKED_CAST")
object AttestPuf {
    const val PUF_EXTRACT_INFO = "atlas-pca/puf-extract/v1"
    const val PUF_ATTEST_DOMAIN = "atlas-pca/attest-puf/v1\u0000"
    const val PUF_KEY_BYTES = 32
    const val TPM_EK_PUF_DOMAIN = "atlas-pca/puf-tpm-ek/v1"
    private val PUF_SUITES = listOf("ed25519", "ml-dsa-65", "ml-dsa-87")
    private val PQ_PRIMS = setOf(Pq.Prim.ML_DSA_65, Pq.Prim.ML_DSA_87, Pq.Prim.SLH_DSA_SHA2_128F, Pq.Prim.SLH_DSA_SHA2_256S)

    private fun isInteger(o: Any?): Boolean {
        val d = IntentJs.num(o) ?: return false
        return !d.isNaN() && !d.isInfinite() && d == Math.floor(d)
    }

    private fun long(o: Any?): Long = IntentJs.num(o)!!.toLong()

    // ---- fuzzy extractor ----

    /** The per-block Hamming correction bound of a repetition code. */
    @JvmStatic fun repetitionCorrectionBound(rep: Double): Double = Math.floor((rep - 1) / 2)

    private fun assertBits(b: ByteArray, where: String) {
        for (x in b) if ((x.toInt() and 0xff) > 1) throw IllegalArgumentException("$where: response must be a 0/1 bit array")
    }

    private fun xorBits(a: ByteArray, b: ByteArray): ByteArray = ByteArray(a.size) { ((a[it].toInt() xor b[it].toInt()) and 1).toByte() }

    private fun repEncode(message: ByteArray, rep: Int): ByteArray {
        val out = ByteArray(message.size * rep)
        for (i in message.indices) {
            val bit = message[i]
            for (j in 0 until rep) out[i * rep + j] = bit
        }
        return out
    }

    private fun repDecode(code: ByteArray, rep: Int): ByteArray {
        val k = code.size / rep
        return ByteArray(k) { i ->
            var ones = 0
            for (j in 0 until rep) ones += code[i * rep + j].toInt() and 1
            if (ones * 2 > rep) 1 else 0 // strict majority: an even factor ties to 0, which is why the factor must be odd
        }
    }

    private fun packBits(bits: ByteArray): ByteArray {
        val out = ByteArray((bits.size + 7) / 8)
        for (i in bits.indices) if ((bits[i].toInt() and 1) != 0) out[i shr 3] = (out[i shr 3].toInt() or (1 shl (i and 7))).toByte()
        return out
    }

    private fun unpackBits(packed: ByteArray, n: Int): ByteArray = ByteArray(n) { ((packed[it shr 3].toInt() shr (it and 7)) and 1).toByte() }

    private fun extractKey(responseBits: ByteArray, salt: ByteArray): ByteArray =
        Entropy.hkdfSha256(packBits(responseBits), salt, PUF_EXTRACT_INFO.toByteArray(Charsets.UTF_8), PUF_KEY_BYTES)

    /** The key a response enrolls to and the public helper data `{sketch, salt, rep, messageBits, n}`. */
    class Enrolled(val key: ByteArray, val helper: Map<String, Any?>)

    /**
     * Enroll a response into a stable key and public helper data. `randomBytes(n)` supplies the random codeword message (n = messageBits; only each byte's
     * low bit is used) and then the 32-byte salt. The key depends only on the response, so any reading within the correction bound reproduces it.
     */
    @JvmStatic fun fuzzyEnroll(responseBits: ByteArray, rep: Any?, messageBits: Any?, randomBytes: (Int) -> ByteArray): Enrolled {
        if (!isInteger(rep) || IntentJs.num(rep)!! < 1 || IntentJs.num(rep)!! % 2 == 0.0) throw IllegalArgumentException("fuzzyEnroll: rep must be an odd positive integer")
        if (!isInteger(messageBits) || IntentJs.num(messageBits)!! < 1) throw IllegalArgumentException("fuzzyEnroll: messageBits must be a positive integer")
        val r = long(rep)
        val mb = long(messageBits)
        val n = r * mb
        if (responseBits.size.toLong() != n) throw IllegalArgumentException("fuzzyEnroll: response length ${responseBits.size} != rep*messageBits $n")
        assertBits(responseBits, "fuzzyEnroll")
        val mr = randomBytes(mb.toInt())
        val m = ByteArray(mb.toInt()) { ((mr.getOrElse(it) { 0 }).toInt() and 1).toByte() }
        val sketch = xorBits(repEncode(m, r.toInt()), responseBits) // C xor W
        val salt = randomBytes(32)
        val key = extractKey(responseBits, salt)
        val helper = linkedMapOf<String, Any?>("sketch" to Keys.b64u(packBits(sketch)), "salt" to Keys.b64u(salt), "rep" to r, "messageBits" to mb, "n" to n)
        return Enrolled(key, helper)
    }

    /**
     * Reproduce the key from a noisy response and the helper data: bit-identical within the per-block correction bound, a DIFFERENT key beyond it (the
     * signature then fails to verify). Throws on a structurally malformed helper or response.
     */
    @JvmStatic fun fuzzyReproduce(responseBits: ByteArray, helper: Any?): ByteArray {
        val h = helper as? Map<String, Any?>
        if (h == null || !isInteger(h["rep"]) || !isInteger(h["messageBits"]) || IntentJs.num(h["rep"])!! < 1 || IntentJs.num(h["rep"])!! % 2 == 0.0) {
            throw IllegalArgumentException("fuzzyReproduce: malformed helper params")
        }
        val rep = long(h["rep"])
        val mb = long(h["messageBits"])
        val n = rep * mb
        if (IntentJs.num(h["n"]) != n.toDouble()) throw IllegalArgumentException("fuzzyReproduce: helper.n inconsistent with rep*messageBits")
        if (responseBits.size.toLong() != n) throw IllegalArgumentException("fuzzyReproduce: response length ${responseBits.size} != $n")
        assertBits(responseBits, "fuzzyReproduce")
        val sk = h["sketch"]
        val sl = h["salt"]
        if (sk !is String || sl !is String) throw IllegalArgumentException("fuzzyReproduce: helper data missing sketch or salt")
        val packed = Pca.decodeB64uStrict(sk, -1)
        val salt = Pca.decodeB64uStrict(sl, -1)
        if (packed == null || salt == null) throw IllegalArgumentException("fuzzyReproduce: helper sketch or salt is not canonical base64url")
        if (packed.size.toLong() != (n + 7) / 8) throw IllegalArgumentException("fuzzyReproduce: helper sketch has the wrong length")
        if (salt.size != 32) throw IllegalArgumentException("fuzzyReproduce: helper salt has the wrong length")
        val sketchBits = unpackBits(packed, n.toInt())
        val mHat = repDecode(xorBits(responseBits, sketchBits), rep.toInt())
        val wRec = xorBits(repEncode(mHat, rep.toInt()), sketchBits)
        return extractKey(wRec, salt)
    }

    // ---- providers ----

    /** A source of PUF responses: a stable id and a (noisy) bit reading for a challenge. */
    interface PufProvider {
        val id: String
        fun response(challenge: ByteArray): ByteArray
    }

    private fun sha(vararg parts: ByteArray): ByteArray {
        val d = MessageDigest.getInstance("SHA-256")
        for (p in parts) d.update(p)
        return d.digest()
    }

    private fun counterBits(prefix: ByteArray, challenge: ByteArray, length: Int, minBlocks: Int): ByteArray {
        val nblocks = Math.max(minBlocks, ((length + 7) / 8 + 31) / 32)
        val stream = ByteArray(nblocks * 32)
        for (blk in 0 until nblocks) {
            val ctr = byteArrayOf((blk ushr 24).toByte(), (blk ushr 16).toByte(), (blk ushr 8).toByte(), blk.toByte())
            System.arraycopy(sha(prefix, challenge, ctr), 0, stream, blk * 32, 32)
        }
        return ByteArray(length) { ((stream[it shr 3].toInt() shr (it and 7)) and 1).toByte() }
    }

    /**
     * A deterministic simulated PUF, FOR TESTS ONLY: its response is a pure function of the seed and the challenge, so it is trivially clonable. `flip`
     * lists bit positions to toggle (out-of-range positions are ignored), to dial the Hamming distance; a different seed models a different device.
     */
    @JvmStatic @JvmOverloads
    fun createSimulatedPuf(id: String, seed: ByteArray, length: Int, flip: Collection<Number> = emptyList()): PufProvider {
        val flips = flip.map { it.toDouble() }.toSet()
        return object : PufProvider {
            override val id: String = id
            override fun response(challenge: ByteArray): ByteArray {
                val bits = counterBits(seed, challenge, length, 0)
                for (p in flips) if (p >= 0 && p < bits.size && p == Math.floor(p)) bits[p.toInt()] = (bits[p.toInt()].toInt() xor 1).toByte()
                return bits
            }
        }
    }

    /** The result of one `tpm2-tools` invocation. `error` is set when the tool could not be spawned at all. */
    class TpmCommandResult(val status: Int?, val stdout: ByteArray?, val stderr: String? = null, val error: String? = null)

    /** Runs `command` with `args`. It should not throw for a failed TPM or command: it returns a result so the provider fails closed. A null return is refused. */
    fun interface TpmCommandRunner {
        fun run(command: String, args: List<String>): TpmCommandResult?
    }

    /** The default runner: spawns the tool, 15 s timeout, 1 MiB of output; a spawn failure or non-zero exit becomes a result. */
    @JvmField val defaultTpmCommandRunner: TpmCommandRunner = TpmCommandRunner { command, args ->
        try {
            val p = ProcessBuilder(listOf(command) + args).redirectErrorStream(false).start()
            p.outputStream.close()
            val err = java.util.concurrent.CompletableFuture.supplyAsync { p.errorStream.readNBytes(1 shl 20) }
            val out = p.inputStream.readNBytes(1 shl 20)
            if (!p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly()
                TpmCommandResult(null, out, null, "$command: ETIMEDOUT")
            } else TpmCommandResult(p.exitValue(), out, String(err.get(), Charsets.UTF_8))
        } catch (e: java.io.IOException) {
            TpmCommandResult(null, ByteArray(0), e.message, "$command: ${e.javaClass.simpleName}")
        }
    }

    /**
     * A provider backed by a real TPM 2.0 endorsement key: each reading derives a stable, device-unique response from the EK public area (which is
     * non-exportable and unique to the chip), so the enrolled key cannot be reproduced on another machine. Fail closed: a tooling or TPM failure throws.
     * `id` and `length` (in bits, equal to the enrolled `rep * messageBits`) are required; `run` defaults to [defaultTpmCommandRunner]; `tool` defaults to
     * `tpm2_readpublic`; `ekHandle` to `0x81010001`; `args` overrides the whole argv; `minEkBytes` (default 64) rejects a truncated read.
     */
    class TpmEkPufProvider @JvmOverloads constructor(
        id: Any?, length: Any?, private val run: TpmCommandRunner? = null, tool: Any? = null, ekHandle: Any? = null, args: List<String>? = null, minEkBytes: Any? = null,
    ) : PufProvider {
        override val id: String
        private val length: Int
        private val tool: String
        private val argv: List<String>
        private val minEkBytes: Long

        init {
            if (id !is String || id.isEmpty()) throw IllegalArgumentException("TpmEkPufProvider: id must be a non-empty string")
            if (!isInteger(length) || IntentJs.num(length)!! < 1) throw IllegalArgumentException("TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)")
            if (minEkBytes != null && (!isInteger(minEkBytes) || IntentJs.num(minEkBytes)!! < 1)) throw IllegalArgumentException("TpmEkPufProvider: minEkBytes must be a positive integer")
            this.id = id
            this.length = long(length).toInt()
            this.tool = if (tool is String && tool.isNotEmpty()) tool else "tpm2_readpublic"
            val h = if (ekHandle is String && ekHandle.isNotEmpty()) ekHandle else "0x81010001"
            this.argv = args ?: listOf("-c", h, "-f", "der", "-o", "/dev/stdout", "-Q")
            this.minEkBytes = if (minEkBytes == null) 64 else long(minEkBytes)
        }

        /** Read the device-unique, stable EK public area (public material only), fail closed. */
        fun readEkPublic(): ByteArray {
            val res = try {
                (run ?: defaultTpmCommandRunner).run(tool, argv)
            } catch (e: RuntimeException) {
                throw IllegalStateException("TpmEkPufProvider: tpm2-tools invocation threw (fail closed): ${e.message ?: "unknown"}")
            } ?: throw IllegalStateException("TpmEkPufProvider: command runner returned no result (fail closed)")
            if (!res.error.isNullOrEmpty()) throw IllegalStateException("TpmEkPufProvider: tpm2-tools unavailable (fail closed): ${res.error}")
            if (res.status != 0) {
                throw IllegalStateException("TpmEkPufProvider: '$tool' exited with status ${res.status} (fail closed)" + if (!res.stderr.isNullOrEmpty()) ": ${res.stderr.trim()}" else "")
            }
            val ek = res.stdout
            if (ek == null || ek.size < minEkBytes) {
                throw IllegalStateException("TpmEkPufProvider: EK public too short (${ek?.size ?: 0} < $minEkBytes bytes) — TPM unavailable or wrong handle (fail closed)")
            }
            return ek
        }

        /** The stable response for `challenge`: HKDF over the EK public area (salt the domain, info the challenge), expanded to `length` bits. */
        override fun response(challenge: ByteArray): ByteArray {
            val ek = readEkPublic()
            val secret = Entropy.hkdfSha256(ek, TPM_EK_PUF_DOMAIN.toByteArray(Charsets.UTF_8), challenge, 32)
            return counterBits(secret, ByteArray(0), length, 1)
        }
    }

    // ---- derived signing key ----

    private fun assertPufSuite(alg: Any?): String {
        if (alg is String && alg in PUF_SUITES) return alg
        throw IllegalArgumentException("PUF root: unsupported derived suite '${ZkJs.string(alg)}' (use ed25519, ml-dsa-65 or ml-dsa-87)")
    }

    private fun signerFromSeed(alg: String, seed: ByteArray): Keys.SuiteKey = when (alg) {
        "ed25519" -> Keys.suite(alg, Keys.edFromSeed(seed), null)
        "ml-dsa-65" -> Keys.suite(alg, null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed))
        else -> Keys.suite(alg, null, Keys.pqFromSeed(Pq.Prim.ML_DSA_87, seed))
    }

    private fun publicKeyOf(k: Keys.SuiteKey): String = k.pqPk() ?: k.id()!!

    private fun statementMessage(body: Map<String, Any?>): ByteArray = IntentJs.message(PUF_ATTEST_DOMAIN, IntentJs.normalize(body))

    // ---- enrollment, attestor ----

    /**
     * Enroll a device: read its response under `challenge`, run the fuzzy extractor and derive the signing key. Returns the PUBLIC enrollment
     * `{providerId, challenge, alg, publicKey, helper, helperCommitment}`; the secret key never leaves this function. `alg` defaults to `ml-dsa-65`.
     */
    @JvmStatic @JvmOverloads
    fun enrollPuf(provider: PufProvider, challenge: ByteArray, rep: Any?, messageBits: Any?, alg: Any? = null, randomBytes: (Int) -> ByteArray): Map<String, Any?> {
        val suite = assertPufSuite(alg ?: "ml-dsa-65")
        val e = fuzzyEnroll(provider.response(challenge), rep, messageBits, randomBytes)
        val signer = signerFromSeed(suite, e.key)
        return linkedMapOf(
            "providerId" to provider.id, "challenge" to Keys.b64u(challenge), "alg" to suite, "publicKey" to publicKeyOf(signer), "helper" to e.helper,
            "helperCommitment" to Pca.hashCanonical(IntentJs.normalize(e.helper)),
        )
    }

    /** A device-side attestor: each [attest] reproduces the key from a fresh reading, so only the real device signs a statement that verifies. */
    class Attestor internal constructor(private val provider: PufProvider, private val enrollment: Map<String, Any?>, private val alg: String, private val challenge: ByteArray) {
        /** Sign `claims` (`measurement`, optional `weights_digest`, `holder_pub`, `grant_ref`, `epoch`, `nonce`). */
        fun attest(claims: Map<String, Any?>): Map<String, Any?> {
            val key = fuzzyReproduce(provider.response(challenge), enrollment["helper"])
            val signer = signerFromSeed(alg, key)
            val bind = LinkedHashMap<String, Any?>()
            for ((k, c) in listOf("holderPub" to "holder_pub", "grantRef" to "grant_ref", "epoch" to "epoch", "nonce" to "nonce")) if (claims.containsKey(c)) bind[k] = claims[c]
            val body = linkedMapOf<String, Any?>("provider_id" to provider.id)
            if (!claims.containsKey("measurement")) throw IllegalArgumentException("canonicalize: unsupported type undefined")
            body["measurement"] = claims["measurement"]
            body["binding"] = Attestation.attestationBindingB64u(bind)
            body["alg"] = alg
            if (claims.containsKey("weights_digest")) body["weights_digest"] = claims["weights_digest"]
            val sg = signer.sign(statementMessage(body))
            val out = LinkedHashMap(body)
            out["sig"] = sg.first
            if (sg.second != null) out["pq_sig"] = sg.second
            return out
        }
    }

    @JvmStatic fun createPufAttestor(provider: PufProvider, enrollment: Map<String, Any?>): Attestor {
        val alg = assertPufSuite(enrollment["alg"])
        val ch = enrollment["challenge"]
        val challenge = Pca.decodeB64uStrict(ch, -1) ?: throw IllegalArgumentException("not canonical base64url")
        return Attestor(provider, enrollment, alg, challenge)
    }

    /** An in-memory registry of enrolled identities by provider id (a later duplicate overwrites; a revoked id stays revoked, re-registering does not undo it). */
    class EnrollmentRegistry internal constructor(enrollments: Any?) {
        private val byId = HashMap<String, Map<String, Any?>>()
        private val revoked = HashSet<String>()

        init {
            if (enrollments is List<*>) for (e in enrollments) register(e)
        }

        fun register(e: Any?) {
            if (e is Map<*, *> && e["providerId"] is String) byId[e["providerId"] as String] = e as Map<String, Any?>
        }

        fun lookup(id: String): Map<String, Any?>? = if (id in revoked) null else byId[id]
        fun revoke(id: String) { revoked.add(id) }
        fun isRevoked(id: String): Boolean = id in revoked
    }

    @JvmStatic @JvmOverloads fun createPufEnrollmentRegistry(enrollments: Any? = emptyList<Any?>()): EnrollmentRegistry = EnrollmentRegistry(enrollments)

    // ---- verifier ----

    fun interface EnrollmentResolver {
        fun resolve(providerId: String, document: Any?, ctx: Any?): Map<String, Any?>?
    }

    fun interface EvidenceResolver {
        fun resolve(document: Any?, ctx: Any?): Any?
    }

    /** The verifier [createPufVerifier] builds: the hardware seam, labelled `software` / `puf`. */
    class Verifier internal constructor(
        private val measurements: List<Any?>,
        private val weights: List<Any?>?,
        private val requirePq: Boolean,
        private val resolveEnrollment: EnrollmentResolver,
        private val resolveEvidence: EvidenceResolver?,
        private val isRevoked: ((String) -> Boolean)?,
        private val derive: ((Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>)?,
    ) : Attestation.HardwareVerifier, Assurance.Labeled {
        override val assuranceLabel: Assurance.Label = Assurance.Label("software", "puf", null, null)

        private fun fail(reason: String): Map<String, Any?> = linkedMapOf("ok" to false, "reason" to reason)

        /**
         * `input` is `{document, ctx, nowMs, expected}`. In order: the statement; revocation; the enrolled identity and its expiry; the helper commitment;
         * the suite (equal to the enrolled one, post-quantum when required); the signature under the ENROLLED public key (never a key from the statement);
         * the binding; the measurement and weights allowlists. The first failure is the result; it never throws.
         */
        override fun verify(input: Map<String, Any?>): Any? {
            try {
                val res = resolveEvidence ?: return fail("no PUF evidence resolver configured (fail closed)")
                val st = res.resolve(input["document"], input["ctx"])
                if (st !is Map<*, *> || st["provider_id"] !is String || st["alg"] !is String) return fail("no PUF attestation statement for this action")
                st as Map<String, Any?>
                val pid = st["provider_id"] as String
                if (isRevoked != null && isRevoked.invoke(pid)) return fail("PUF enrollment for provider '$pid' is revoked")
                val enr = resolveEnrollment.resolve(pid, input["document"], input["ctx"]) ?: return fail("no PUF enrollment registered for provider '$pid'")
                if (enr.containsKey("notAfter") && !(IntentJs.num(input["nowMs"])?.let { it < net.atlasauth.pca.compliance.ComplianceJs.toNumber(enr["notAfter"]) } ?: false)) {
                    return fail("PUF enrollment has expired")
                }
                val commit = enr["helperCommitment"]
                if (commit !is String || commit != Pca.hashCanonical(IntentJs.normalize(enr["helper"]))) return fail("PUF enrollment helper commitment mismatch (helper tampered)")
                if (st["alg"] != enr["alg"]) return fail("PUF statement suite '${st["alg"]}' does not match the enrolled suite '${ZkJs.string(enr["alg"])}'")
                val suite = Pq.resolveSigAlg(st["alg"], true) ?: return fail("PUF statement declares an unknown signature alg '${st["alg"]}'")
                if (requirePq && suite.pq !in PQ_PRIMS) return fail("PQ required: PUF-derived suite '${suite.alg}' is classical")

                val body = LinkedHashMap(st)
                val sig = body.remove("sig")
                val pqSig = body.remove("pq_sig")
                val message = statementMessage(body)
                val enrolledKey = enr["publicKey"] as? String
                val pin = if (suite.needsPqPk) PinnedPq.resolve(null, null, trustedPk = enrolledKey) else null
                if (!Pq.verifySuite(suite.alg, true, enrolledKey, pin, message, sig, pqSig)) {
                    return fail("PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)")
                }

                if (!ZkJs.truthy(input["expected"])) return fail("no expected attestation binding supplied")
                val expected = try {
                    Keys.b64u(Attestation.attestationBinding(input["expected"]))
                } catch (e: RuntimeException) {
                    return fail("binding not constructible: ${e.message ?: "invalid"}")
                }
                if (st["binding"] != expected) return fail("PUF statement binding mismatch (holder/grant/epoch/nonce)")

                if (measurements.none { it == st["measurement"] }) return fail("measurement not in policy allowlist")
                if (weights != null && weights.isNotEmpty()) {
                    val w = st["weights_digest"]
                    if (w !is String || weights.none { it == w }) return fail("measured weights digest not in policy allowlist")
                }
                val measured = derive?.invoke(st, enr) ?: linkedMapOf<String, Any?>(
                    "model_id" to "", "weights_digest" to ((st["weights_digest"] as? String) ?: ""), "weights_measured" to false, "runtime_measurement" to st["measurement"], "operator" to "",
                )
                return linkedMapOf("ok" to true, "bound" to true, "measured" to measured, "hostAsserted" to linkedMapOf("provider_id" to pid, "suite" to suite.alg))
            } catch (e: RuntimeException) {
                return fail("puf verification error (fail closed): ${e.message ?: "unknown"}")
            }
        }
    }

    /**
     * Build the verifier from `opts` (`policy: {measurements (non-empty), weightsMeasurements?}`, `requirePq`), the enrolled-identity resolver (required), the
     * evidence seam (without it the verifier fails closed), an optional revocation check and an optional identity mapping (default: no model id, the statement's
     * weights digest, `weights_measured: false`). The allowlists are copied at construction.
     */
    @JvmStatic @JvmOverloads
    fun createPufVerifier(
        opts: Map<String, Any?>?, resolveEnrollment: EnrollmentResolver?, resolveEvidence: EvidenceResolver? = null, isRevoked: ((String) -> Boolean)? = null,
        derive: ((Map<String, Any?>, Map<String, Any?>) -> Map<String, Any?>)? = null,
    ): Verifier {
        val policy = opts?.get("policy") as? Map<String, Any?>
        val ms = (policy?.get("measurements") as? List<Any?>)?.toList()
        if (ms == null || ms.isEmpty()) throw IllegalArgumentException("createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
        if (resolveEnrollment == null) throw IllegalArgumentException("createPufVerifier: resolveEnrollment is required")
        return Verifier(ms, (policy["weightsMeasurements"] as? List<Any?>)?.toList(), opts["requirePq"] == true, resolveEnrollment, resolveEvidence, isRevoked, derive)
    }
}
