package net.atlasauth.pca.verifier

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * A complete self-made Sigstore world for the Kill05Sig* tests: DER writer, keys (generated once, at run time), a Fulcio-like CA
 * and leaf, a Rekor v1 log (SET, single-leaf inclusion proof, signed checkpoint) and bundle builders.
 */
@Suppress("UNCHECKED_CAST")
internal object Kill05SigKit {
    const val INTOTO = "application/vnd.in-toto+json"
    const val V03 = "application/vnd.dev.sigstore.bundle.v0.3+json"
    const val ROOT_MT = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
    const val SAN_URI = "https://github.com/o/r/.github/workflows/w.yml@refs/heads/main"
    const val ISSUER = "https://token.actions.githubusercontent.com"
    const val EKU_CS = "1.3.6.1.5.5.7.3.3"
    const val EKU_TS = "1.3.6.1.5.5.7.3.8"
    const val OID_SCT = "1.3.6.1.4.1.11129.2.4.2"
    const val ECDSA256 = "1.2.840.10045.4.3.2"
    const val SHA256 = "2.16.840.1.101.3.4.2.1"

    /** The signing (Rekor integrated) time 2025-01-01T01:00:00Z, in seconds. */
    const val IT = 1735693200L
    const val IT_RFC = "2025-01-01T01:00:00Z"
    const val DAY = 86_400_000L
    const val CA_NB = 1577836800000L // 2020-01-01
    const val CA_NA = 2208988800000L // 2040-01-01
    const val STATEMENT =
        "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"a.tgz\",\"digest\":{\"sha256\":\"aa\"}}]," +
            "\"predicateType\":\"https://slsa.dev/provenance/v1\",\"predicate\":{\"buildDefinition\":{\"buildType\":\"bt\"," +
            "\"externalParameters\":{}},\"runDetails\":{\"builder\":{\"id\":\"b\"}}}}"

    // ---- DER

    fun b(vararg v: Int): ByteArray = ByteArray(v.size) { v[it].toByte() }

    fun cat(vararg parts: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        for (p in parts) o.write(p, 0, p.size)
        return o.toByteArray()
    }

    fun tlv(tag: Int, vararg parts: ByteArray): ByteArray {
        val body = cat(*parts)
        val n = body.size
        val hdr = when {
            n < 0x80 -> b(tag, n)
            n < 0x100 -> b(tag, 0x81, n)
            n < 0x10000 -> b(tag, 0x82, n shr 8, n and 0xff)
            else -> b(tag, 0x83, n shr 16, (n shr 8) and 0xff, n and 0xff)
        }
        return cat(hdr, body)
    }

    fun seq(vararg p: ByteArray): ByteArray = tlv(0x30, *p)
    fun set(vararg p: ByteArray): ByteArray = tlv(0x31, *p)
    fun oct(v: ByteArray): ByteArray = tlv(0x04, v)
    fun oid(dotted: String): ByteArray = Kill05CertKit.oid(dotted)
    fun int(v: Long): ByteArray = tlv(0x02, BigInteger.valueOf(v).toByteArray())
    fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)
    fun u16(n: Int): ByteArray = b(n shr 8, n and 0xff)
    fun u64(v: Long): ByteArray = ByteBuffer.allocate(8).putLong(v).array()

    fun sha256(vararg p: ByteArray): ByteArray {
        val d = MessageDigest.getInstance("SHA-256")
        for (x in p) d.update(x)
        return d.digest()
    }

    fun std(x: ByteArray): String = Base64.getEncoder().encodeToString(x)
    fun hex(x: ByteArray): String = x.joinToString("") { String.format("%02x", it.toInt() and 0xff) }

    // ---- keys and certificates

    fun ec(curve: String = "secp256r1"): KeyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec(curve)) }.generateKeyPair()
    fun rsa(): KeyPair = KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.generateKeyPair()

    fun sign(k: PrivateKey, data: ByteArray, alg: String = "SHA256withECDSA"): ByteArray {
        val s = Signature.getInstance(alg)
        s.initSign(k)
        s.update(data)
        return s.sign()
    }

    fun utc(ms: Long): ByteArray =
        tlv(0x17, DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(ms)).toByteArray(Charsets.US_ASCII))

    fun name(cn: String): ByteArray = seq(set(seq(oid("2.5.4.3"), tlv(0x0c, utf8(cn)))))

    val ALG: ByteArray = seq(oid(ECDSA256))
    val RSA_ALG: ByteArray = seq(oid("1.2.840.113549.1.1.11"), tlv(0x05))

    fun ext(o: String, value: ByteArray, critical: Boolean = false): ByteArray =
        if (critical) seq(oid(o), tlv(0x01, b(0xff)), oct(value)) else seq(oid(o), oct(value))

    val CA_BC: ByteArray = ext("2.5.29.19", seq(tlv(0x01, b(0xff))), true)
    fun ku(unused: Int, bits: Int): ByteArray = ext("2.5.29.15", tlv(0x03, b(unused, bits)), true)
    val CA_KU: ByteArray = ku(1, 0x06) // keyCertSign + cRLSign
    fun eku(vararg o: String): ByteArray = ext("2.5.29.37", seq(*o.map { oid(it) }.toTypedArray()))
    fun san(vararg names: ByteArray): ByteArray = ext("2.5.29.17", seq(*names))
    fun uri(u: String): ByteArray = tlv(0x86, utf8(u))
    fun ski(id: ByteArray): ByteArray = ext("2.5.29.14", oct(id))
    fun aki(id: ByteArray): ByteArray = ext("2.5.29.35", seq(tlv(0x80, id)))
    fun fulcio(n: Int, value: ByteArray): ByteArray = ext("1.3.6.1.4.1.57264.1.$n", value)

    fun tbs(issuer: String, subject: String, pub: PublicKey, nb: Long, na: Long, exts: List<ByteArray>, alg: ByteArray = ALG): ByteArray {
        val parts = arrayListOf(tlv(0xa0, int(2)), int(7), alg, name(issuer), seq(utc(nb), utc(na)), name(subject), pub.encoded)
        if (exts.isNotEmpty()) parts.add(tlv(0xa3, seq(*exts.toTypedArray())))
        return seq(*parts.toTypedArray())
    }

    fun cert(tbs: ByteArray, signer: PrivateKey, alg: ByteArray = ALG, jca: String = "SHA256withECDSA"): ByteArray =
        seq(tbs, alg, tlv(0x03, b(0), sign(signer, tbs, jca)))

    /** A certificate the JDK parses but whose signature is junk (for the name / extension checks). */
    fun junk(tbs: ByteArray): ByteArray = seq(tbs, ALG, tlv(0x03, b(0, 1, 2)))

    fun x509(der: ByteArray): X509Certificate = Sigstore.x509(der)

    fun pem(der: ByteArray): String = "-----BEGIN CERTIFICATE-----\n" + std(der).chunked(64).joinToString("\n") + "\n-----END CERTIFICATE-----\n"

    // ---- the world: a Fulcio-like CA, a leaf, a Rekor v1 log

    val CA_KID: ByteArray = b(1, 2, 3, 4, 5, 6, 7, 8)
    val caKey: KeyPair by lazy { ec() }
    val logKey: KeyPair by lazy { ec() }
    val leafKey: KeyPair by lazy { ec() }
    val caDer: ByteArray by lazy { cert(tbs("Test CA", "Test CA", caKey.public, CA_NB, CA_NA, listOf(CA_BC, CA_KU, ski(CA_KID))), caKey.private) }
    val ca: X509Certificate by lazy { x509(caDer) }
    val logSpki: ByteArray by lazy { logKey.public.encoded }
    val logId: ByteArray by lazy { sha256(logSpki) }

    fun leafExts(issuerExt: ByteArray? = fulcio(1, utf8(ISSUER)), extra: List<ByteArray> = emptyList()): List<ByteArray> =
        listOfNotNull(aki(CA_KID), eku(EKU_CS), san(uri(SAN_URI)), issuerExt) + extra

    fun leafDer(exts: List<ByteArray> = leafExts(), pub: PublicKey = leafKey.public, nb: Long = IT * 1000 - DAY, na: Long = IT * 1000 + DAY): ByteArray =
        cert(tbs("Test CA", "leaf", pub, nb, na, exts), caKey.private)

    fun rootJson(caStart: String = "2020-01-01T00:00:00Z", caEnd: String? = null): MutableMap<String, Any?> {
        val caValid = linkedMapOf<String, Any?>("start" to caStart)
        if (caEnd != null) caValid["end"] = caEnd
        val pk = linkedMapOf<String, Any?>("rawBytes" to std(logSpki), "keyDetails" to "PKIX_ECDSA_P256_SHA_256", "validFor" to linkedMapOf<String, Any?>("start" to "2020-01-01T00:00:00Z"))
        val tlog = linkedMapOf<String, Any?>("baseUrl" to "https://rekor.example", "hashAlgorithm" to "SHA2_256", "publicKey" to pk, "logId" to linkedMapOf<String, Any?>("keyId" to std(logId)))
        val chain = linkedMapOf<String, Any?>("certificates" to listOf(linkedMapOf<String, Any?>("rawBytes" to std(caDer))))
        return linkedMapOf<String, Any?>(
            "mediaType" to ROOT_MT,
            "tlogs" to listOf(tlog),
            "certificateAuthorities" to listOf(linkedMapOf<String, Any?>("certChain" to chain, "validFor" to caValid)),
        )
    }

    fun roots(caStart: String = "2020-01-01T00:00:00Z", caEnd: String? = null): Sigstore.PinnedRoots = Sigstore.parseTrustedRoot(rootJson(caStart, caEnd))

    fun dsseBody(payloadSha: String, sigB64: String, pemB64: String): String =
        "{\"apiVersion\":\"0.0.1\",\"kind\":\"dsse\",\"spec\":{\"payloadHash\":{\"algorithm\":\"sha256\",\"value\":\"$payloadSha\"}," +
            "\"signatures\":[{\"signature\":\"$sigB64\",\"verifier\":\"$pemB64\"}]}}"

    fun intotoBody(payloadSha: String, sigB64: String, pemB64: String): String =
        "{\"apiVersion\":\"0.0.2\",\"kind\":\"intoto\",\"spec\":{\"content\":{\"envelope\":{\"payloadType\":\"$INTOTO\"," +
            "\"signatures\":[{\"sig\":\"${std(utf8(sigB64))}\",\"publicKey\":\"$pemB64\"}]},\"payloadHash\":{\"algorithm\":\"sha256\",\"value\":\"$payloadSha\"}}}}"

    /** A signed-note checkpoint over a one-leaf tree with root [root], signed by the log key. */
    fun checkpoint(root: ByteArray): String {
        val body = "rekor.example - 1\n1\n${std(root)}\n"
        return body + "\n— rekor.example " + std(cat(logId.copyOfRange(0, 4), sign(logKey.private, utf8(body)))) + "\n"
    }

    /**
     * A bundle (v0.3, DSSE, one Rekor v1 entry with SET and a one-leaf inclusion proof) the verifier accepts. [kind] "dsse" or
     * "intoto"; [body] replaces the entry body (given payload sha256 hex, envelope signature base64, base64 PEM of the leaf).
     */
    fun bundle(
        kind: String = "dsse",
        leaf: ByteArray? = null,
        payload: String = STATEMENT,
        body: ((String, String, String) -> String)? = null,
    ): MutableMap<String, Any?> {
        val leafDer = leaf ?: leafDer()
        val p = utf8(payload)
        val sig = sign(leafKey.private, Sigstore.dssePae(INTOTO, p))
        val dsseMk: (String, String, String) -> String = { a, s, c -> dsseBody(a, s, c) }
        val intotoMk: (String, String, String) -> String = { a, s, c -> intotoBody(a, s, c) }
        val mk = body ?: (if (kind == "dsse") dsseMk else intotoMk)
        val bodyBytes = utf8(mk(hex(sha256(p)), std(sig), std(utf8(pem(leafDer)))))
        val bodyB64 = std(bodyBytes)
        val setMsg = "{\"body\":\"$bodyB64\",\"integratedTime\":$IT,\"logID\":\"${hex(logId)}\",\"logIndex\":5}"
        val root = ProvenanceGate.rfc9162LeafHash(bodyBytes)
        val proof = linkedMapOf<String, Any?>(
            "logIndex" to "0", "rootHash" to std(root), "treeSize" to "1", "hashes" to mutableListOf<Any?>(),
            "checkpoint" to linkedMapOf<String, Any?>("envelope" to checkpoint(root)),
        )
        val entry = linkedMapOf<String, Any?>(
            "logIndex" to "5", "logId" to linkedMapOf<String, Any?>("keyId" to std(logId)),
            "kindVersion" to linkedMapOf<String, Any?>("kind" to kind, "version" to if (kind == "dsse") "0.0.1" else "0.0.2"),
            "integratedTime" to IT.toString(),
            "inclusionPromise" to linkedMapOf<String, Any?>("signedEntryTimestamp" to std(sign(logKey.private, utf8(setMsg)))),
            "inclusionProof" to proof,
            "canonicalizedBody" to bodyB64,
        )
        val vm = linkedMapOf<String, Any?>("certificate" to linkedMapOf<String, Any?>("rawBytes" to std(leafDer)), "tlogEntries" to mutableListOf<Any?>(entry))
        val env = linkedMapOf<String, Any?>("payload" to std(p), "payloadType" to INTOTO, "signatures" to mutableListOf<Any?>(linkedMapOf<String, Any?>("sig" to std(sig), "keyid" to "")))
        return linkedMapOf<String, Any?>("mediaType" to V03, "verificationMaterial" to vm, "dsseEnvelope" to env)
    }

    fun m(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>
    fun vm(b: Map<String, Any?>): MutableMap<String, Any?> = m(b["verificationMaterial"])
    fun entry(b: Map<String, Any?>): MutableMap<String, Any?> = m((vm(b)["tlogEntries"] as List<Any?>)[0])

    /** The `core` of [bundle] with the default leaf and statement. */
    fun expectedCore(): Map<String, Any?> = linkedMapOf<String, Any?>(
        "identity" to SAN_URI,
        "oidc_issuer" to ISSUER,
        "predicate_type" to "https://slsa.dev/provenance/v1",
        "subjects" to listOf(linkedMapOf<String, Any?>("alg" to "sha256", "digest" to "aa")),
        "signed_time" to IT,
        "rekor_log_index" to 5L,
        "rekor" to "v1",
        "timestamps" to linkedMapOf<String, Any?>("tsa" to 0L, "set" to true),
    )

    /** The message of the IllegalArgumentException [f] throws, or "OK" when it returns (any other exception fails the test). */
    fun err(f: () -> Any?): String = try {
        f()
        "OK"
    } catch (e: IllegalArgumentException) {
        "IAE:" + e.message
    }
}
