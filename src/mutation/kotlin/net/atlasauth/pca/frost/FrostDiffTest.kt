package net.atlasauth.pca.frost

import java.math.BigDecimal
import net.atlasauth.pca.frost.Frost.FrostCommitment
import net.atlasauth.pca.frost.Frost.FrostKeygenOpts
import net.atlasauth.pca.frost.Frost.FrostKeygenResult
import net.atlasauth.pca.frost.Frost.FrostNonces
import net.atlasauth.pca.frost.Frost.FrostParticipantShare
import net.atlasauth.pca.frost.Frost.FrostSignOpts
import net.atlasauth.pca.frost.Frost.FrostSignatureShare
import net.atlasauth.pca.frost.Frost.VerificationShare
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import org.junit.Test

/** Replays the reference FROST oracle (deterministic nonces, keys and messages) through the native implementation. */
@Suppress("UNCHECKED_CAST")
class FrostDiffTest {
    private val M = "ref-core-frost-java"

    private fun map(o: Any?): Map<String, Any?> = o as? Map<String, Any?> ?: throw IllegalArgumentException("expected object")
    private fun list(o: Any?): List<Any?> = o as? List<Any?> ?: throw IllegalArgumentException("expected array")

    private fun by(o: Any?): ByteArray {
        if (o is Map<*, *> && o.size == 1 && o["\$bytes"] is String) return Keys.unb64u(o["\$bytes"] as String)
        throw IllegalArgumentException("expected bytes")
    }

    private fun byOrNull(o: Any?): ByteArray? = if (o == null) null else by(o)

    /** A JSON number that is a whole number (the reference refuses anything else as an identifier / count). */
    private fun whole(o: Any?): Long {
        if (o !is Json.Num) throw IllegalArgumentException("expected number")
        val d = BigDecimal(o.raw)
        if (d.stripTrailingZeros().scale() > 0) throw IllegalArgumentException("expected integer")
        return d.toBigIntegerExact().toLong().also { if (BigDecimal(it).compareTo(d) != 0) throw IllegalArgumentException("out of range") }
    }

    private fun whole32(o: Any?): Int {
        val v = whole(o)
        if (v < Int.MIN_VALUE || v > Int.MAX_VALUE) throw IllegalArgumentException("out of range")
        return v.toInt()
    }

    private fun commitment(o: Any?): FrostCommitment { val m = map(o); return FrostCommitment(whole(m["identifier"]), by(m["hiding"]), by(m["binding"])) }

    private fun commitments(o: Any?): List<FrostCommitment>? = if (o == null) null else list(o).map { commitment(it) }

    private fun vshares(o: Any?): List<VerificationShare>? =
        if (o == null) null else list(o).map { val m = map(it); VerificationShare(whole(m["identifier"]), by(m["publicKey"])) }

    private fun sigShare(o: Any?): FrostSignatureShare { val m = map(o); return FrostSignatureShare(whole(m["identifier"]), by(m["sigShare"])) }

    private fun sigShares(o: Any?): List<FrostSignatureShare>? = if (o == null) null else list(o).map { sigShare(it) }

    private fun commitmentOut(c: FrostCommitment): Map<String, Any?> = linkedMapOf("identifier" to c.identifier, "hiding" to c.hiding, "binding" to c.binding)

    private fun keygenOut(kg: FrostKeygenResult): LinkedHashMap<String, Any?> {
        val shares = kg.participantShares.map { linkedMapOf<String, Any?>("identifier" to it.identifier, "share" to it.share, "publicKey" to it.publicKey) }
        return linkedMapOf("groupPublicKey" to kg.groupPublicKey, "participantShares" to shares, "groupCommitment" to ArrayList<Any?>(kg.groupCommitment))
    }

    private fun keygen(a: Map<String, Any?>): FrostKeygenResult {
        val o = FrostKeygenOpts()
        o.secret = byOrNull(a["secret"])
        if (a["coefficients"] != null) o.coefficients = list(a["coefficients"]).map { by(it) }
        if (a["identifiers"] != null) o.identifiers = list(a["identifiers"]).map { whole(it) }.toLongArray()
        return Frost.trustedDealerKeygen(whole32(a["t"]), whole32(a["n"]), o)
    }

    private fun signOpts(o: Any?): FrostSignOpts {
        val s = FrostSignOpts()
        if (o == null) return s
        val m = map(o)
        if (m["threshold"] != null) s.threshold = whole32(m["threshold"])
        s.verificationShare = byOrNull(m["verificationShare"])
        s.verificationShares = vshares(m["verificationShares"])
        return s
    }

    @Test fun genCorpusIsPresent() = net.atlasauth.pca.verifier.BaseOracle.requireGen(M)

    @Test fun scalar() = OracleCases.each(M, "scalar") { a -> Frost.scalarToBytes(Frost.bytesToScalar(by(a[0]))) }

    @Test fun isCanonicalScalar() = OracleCases.each(M, "isCanonicalScalar") { a -> a[0] != null && Frost.isCanonicalScalar(by(a[0])) }

    @Test fun hash() = OracleCases.each(M, "hash") { a ->
        val m = by(a[1])
        when (a[0] as String) {
            "H1" -> Frost.scalarToBytes(Frost.H1(m))
            "H2" -> Frost.scalarToBytes(Frost.H2(m))
            "H3" -> Frost.scalarToBytes(Frost.H3(m))
            "H4" -> Frost.H4(m)
            "H5" -> Frost.H5(m)
            else -> throw IllegalArgumentException("unknown hash")
        }
    }

    @Test fun decodeSafePoint() = OracleCases.each(M, "decodeSafePoint") { a -> Frost.decodeSafePoint(byOrNull(a[0])).toBytes() }

    @Test fun keygen() = OracleCases.each(M, "keygen") { a -> keygenOut(keygen(map(a[0]))) }

    @Test fun verifyingShare() = OracleCases.each(M, "verifyingShare") { a -> Frost.verifyingShare(by(a[0])) }

    @Test fun commit() = OracleCases.each(M, "commit") { a ->
        val c = Frost.commit(FrostParticipantShare(whole(a[0]), by(a[1]), ByteArray(32)), by(a[2]), by(a[3]))
        linkedMapOf("hidingNonce" to c.hidingNonce, "bindingNonce" to c.bindingNonce, "commitment" to commitmentOut(c.commitment))
    }

    @Test fun flow() = OracleCases.each(M, "flow") { a ->
        val inp = map(a[0])
        val kg = keygen(inp)
        val byId = LinkedHashMap<Long, FrostParticipantShare>()
        for (s in kg.participantShares) byId[s.identifier] = s
        val quorum = list(inp["signers"]).map { byId[whole(it)] ?: throw IllegalArgumentException("unknown signer") }
        val rnd = list(inp["randomness"])
        val commits = ArrayList<Frost.FrostCommitResult>()
        val cs = ArrayList<FrostCommitment>()
        val vss = ArrayList<VerificationShare>()
        for (i in quorum.indices) {
            val r = map(rnd[i])
            val c = Frost.commit(quorum[i], by(r["hr"]), by(r["br"]))
            commits.add(c)
            cs.add(c.commitment)
            vss.add(VerificationShare(quorum[i].identifier, quorum[i].publicKey))
        }
        val thr = if (inp["threshold"] == null) null else whole32(inp["threshold"])
        val msg = by(inp["message"])
        val shares = ArrayList<FrostSignatureShare>()
        for (i in quorum.indices) {
            val o = FrostSignOpts()
            o.threshold = thr
            o.verificationShare = quorum[i].publicKey
            o.verificationShares = vss
            shares.add(Frost.sign(quorum[i].identifier, quorum[i].share, kg.groupPublicKey, commits[i].nonces(), msg, cs, o))
        }
        val agg = Frost.aggregate(msg, cs, shares, kg.groupPublicKey, thr, vss)
        val out = keygenOut(kg)
        out["commitments"] = cs.map { commitmentOut(it) }
        out["sigShares"] = shares.map { linkedMapOf<String, Any?>("identifier" to it.identifier, "sigShare" to it.sigShare) }
        out["aggregate"] = agg
        out
    }

    @Test fun sign() = OracleCases.each(M, "sign") { a ->
        val id = whole(a[0])
        val share = by(a[1])
        val group = by(a[2])
        var nonces: FrostNonces? = null
        if (a[3] != null) { val n = map(a[3]); nonces = FrostNonces(byOrNull(n["hiding"]), byOrNull(n["binding"])) }
        if (nonces != null && (nonces.hiding == null || nonces.binding == null)) throw IllegalArgumentException("malformed nonces")
        val s = Frost.sign(id, share, group, nonces, by(a[4]), commitments(a[5]), signOpts(a[6]))
        linkedMapOf("identifier" to s.identifier, "sigShare" to s.sigShare)
    }

    @Test fun aggregate() = OracleCases.each(M, "aggregate") { a ->
        val o = map(a[4])
        val thr = if (o["threshold"] == null) null else whole32(o["threshold"])
        Frost.aggregate(by(a[0]), commitments(a[1]), sigShares(a[2]), byOrNull(a[3]), thr, vshares(o["verificationShares"]))
    }

    @Test fun verifySigShare() = OracleCases.each(M, "verifySigShare") { a ->
        try {
            val p = map(a[0])
            Frost.verifySigShare(
                whole(p["identifier"]), by(p["publicKey"]), commitment(p["commitment"]), sigShare(p["sigShare"]),
                commitments(p["signingCommitments"]), by(p["groupPublicKey"]), by(p["message"]),
            )
        } catch (e: RuntimeException) {
            false
        }
    }

    @Test fun cosign() = OracleCases.each(M, "cosign") { a ->
        val group = by(a[0])
        val msg = by(a[2])
        var quorum: List<FrostParticipantShare>? = null
        if (a[1] != null) quorum = list(a[1]).map { val m = map(it); FrostParticipantShare(whole(m["identifier"]), by(m["share"]), by(m["publicKey"])) }
        val o = map(a[3])
        val sig = Frost.cosign(group, quorum, msg, if (o["threshold"] == null) null else whole32(o["threshold"]))
        Pca.ed25519Strict(group, msg, sig)
    }
}
