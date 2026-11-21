package net.atlasauth.pca.frost

import java.math.BigInteger
import net.atlasauth.pca.frost.Frost.FrostCommitment
import net.atlasauth.pca.frost.Frost.FrostKeygenOpts
import net.atlasauth.pca.frost.Frost.FrostNonces
import net.atlasauth.pca.frost.Frost.FrostParticipantShare
import net.atlasauth.pca.frost.Frost.FrostSignatureShare
import net.atlasauth.pca.frost.Frost.VerificationShare
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RFC 9591 appendix E.1, FROST(Ed25519, SHA-512): the official test vectors (t = 2, n = 3, signers 1 and 3) reproduced byte for byte,
 * plus the one-shot nonce and tamper refusals.
 */
class FrostKatTest {
    private fun hex(h: String): ByteArray = ByteArray(h.length / 2) { i -> h.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    private fun toHex(b: ByteArray): String = b.joinToString("") { String.format("%02x", it.toInt() and 0xFF) }

    private val GROUP_SECRET = "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304"
    private val GROUP_PK = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"
    private val COEFF1 = "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204"
    private val MESSAGE = "74657374"
    private val AGGREGATE = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe" + "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"

    /** id, share, hidingRandomness, bindingRandomness, hidingNonce, bindingNonce, hidingCommitment, bindingCommitment, sigShare. */
    private val P = arrayOf(
        arrayOf(
            "1", "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509", "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec",
            "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501", "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407",
            "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301", "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
            "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932", "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603",
        ),
        arrayOf(
            "3", "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02", "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f",
            "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775", "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e",
            "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d", "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91",
            "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552", "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007",
        ),
    )

    private fun keygen() = Frost.trustedDealerKeygen(2, 3, FrostKeygenOpts().also {
        it.secret = hex(GROUP_SECRET)
        it.coefficients = listOf(hex(COEFF1))
        it.identifiers = longArrayOf(1, 2, 3)
    })

    private fun commitments(): List<FrostCommitment> = P.map { FrostCommitment(it[0].toLong(), hex(it[6]), hex(it[7])) }

    private fun nonces(p: Array<String>) = FrostNonces(hex(p[4]), hex(p[5]))

    @Test fun trustedDealerSplitMatchesRfc() {
        val kg = keygen()
        assertEquals(GROUP_PK, toHex(kg.groupPublicKey))
        assertEquals(P[0][1], toHex(kg.participantShares[0].share))
        assertEquals(P[1][1], toHex(kg.participantShares[2].share))
    }

    @Test fun roundOneNoncesAndCommitmentsMatchRfc() {
        for (p in P) {
            val c = Frost.commit(FrostParticipantShare(p[0].toLong(), hex(p[1]), ByteArray(32)), hex(p[2]), hex(p[3]))
            assertEquals(p[4], toHex(c.hidingNonce))
            assertEquals(p[5], toHex(c.bindingNonce))
            assertEquals(p[6], toHex(c.commitment.hiding))
            assertEquals(p[7], toHex(c.commitment.binding))
        }
    }

    @Test fun signatureSharesAndAggregateMatchRfc() {
        val group = hex(GROUP_PK)
        val msg = hex(MESSAGE)
        val cs = commitments()
        val shares = ArrayList<FrostSignatureShare>()
        val vss = ArrayList<VerificationShare>()
        for (p in P) {
            val s = Frost.sign(p[0].toLong(), hex(p[1]), group, nonces(p), msg, cs, null)
            assertEquals(p[8], toHex(s.sigShare))
            shares.add(s)
            vss.add(VerificationShare(p[0].toLong(), Frost.verifyingShare(hex(p[1]))))
        }
        val kg = keygen()
        for (i in 0 until 2) {
            assertTrue(Frost.verifySigShare(shares[i].identifier, kg.participantShares[if (i == 0) 0 else 2].publicKey, cs[i], shares[i], cs, group, msg))
        }
        val sig = Frost.aggregate(msg, cs, shares, group, null, vss)
        assertEquals(AGGREGATE, toHex(sig))
        assertTrue(Pca.ed25519Strict(group, msg, sig))

        // a tampered share is refused, and so is a share checked under the wrong verification share
        val bad = shares[0].sigShare.clone()
        bad[0] = (bad[0].toInt() xor 1).toByte()
        assertFalse(Frost.verifySigShare(1, vss[0].publicKey, cs[0], FrostSignatureShare(1, bad), cs, group, msg))
        assertFalse(Frost.verifySigShare(1, vss[1].publicKey, cs[0], shares[0], cs, group, msg))
        // z + L must not verify alongside z
        val z = BigInteger(1, shares[0].sigShare.reversedArray()).add(Frost.L)
        val zl32 = z.toByteArray().reversedArray().copyOf(32)
        assertFalse(Frost.isCanonicalScalar(zl32))
        assertFalse(Frost.verifySigShare(1, vss[0].publicKey, cs[0], FrostSignatureShare(1, zl32), cs, group, msg))
        assertThrows(IllegalArgumentException::class.java) { Frost.aggregate(msg, cs, listOf(shares[0], FrostSignatureShare(3, bad)), group, null, vss) }
        assertThrows(IllegalArgumentException::class.java) { Frost.aggregate(msg, cs, shares, group, null, null) }
        assertThrows(IllegalArgumentException::class.java) { Frost.aggregate(msg, cs, shares, group, 3, vss) }
    }

    /** Fresh, distinct randomness so the nonce registry of the RFC test is not touched. */
    @Test fun cosignRoundTripAndRefusals() {
        val kg = Frost.trustedDealerKeygen(2, 3, FrostKeygenOpts().also {
            it.secret = hex("0100000000000000000000000000000000000000000000000000000000000000")
            it.coefficients = listOf(hex("0200000000000000000000000000000000000000000000000000000000000000"))
        })
        val msg = "cosign".toByteArray()
        val sig = Frost.cosign(kg.groupPublicKey, kg.participantShares.subList(0, 2), msg, 2)
        assertTrue(Pca.ed25519Strict(kg.groupPublicKey, msg, sig))
        assertThrows(IllegalArgumentException::class.java) { Frost.cosign(kg.groupPublicKey, kg.participantShares.subList(0, 1), msg, 2) }
        assertThrows(IllegalArgumentException::class.java) { Frost.cosign(kg.groupPublicKey, emptyList(), msg, 2) }
        assertThrows(IllegalArgumentException::class.java) { Frost.cosign(kg.groupPublicKey, listOf(kg.participantShares[0], kg.participantShares[0]), msg, 2) }
    }

    @Test fun nonceIsOneShot() {
        val kg = keygen()
        val group = hex(GROUP_PK)
        val msg = "once".toByteArray()
        val p1 = kg.participantShares[0]
        val p2 = kg.participantShares[1]
        val r = hex("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
        val r2 = hex("b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2")
        val r3 = hex("c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3")
        val r4 = hex("d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4")
        val c1 = Frost.commit(p1, r, r2)
        val c2 = Frost.commit(p2, r3, r4)
        val cs = listOf(c1.commitment, c2.commitment)
        val n1 = c1.nonces()
        Frost.sign(p1.identifier, p1.share, group, n1, msg, cs, null)
        assertTrue(n1.hiding!!.contentEquals(ByteArray(32))) // zeroised
        assertThrows(IllegalArgumentException::class.java) { Frost.sign(p1.identifier, p1.share, group, n1, msg, cs, null) }
        // a fresh array carrying the same nonce value is refused through the commitment registry
        val again = Frost.commit(p1, r, r2).nonces()
        assertThrows(IllegalArgumentException::class.java) { Frost.sign(p1.identifier, p1.share, group, again, msg, cs, null) }
    }

    @Test fun pointDecodingIsStrict() {
        assertThrows(IllegalArgumentException::class.java) { Frost.decodeSafePoint(ByteArray(31)) }
        val identity = ByteArray(32)
        identity[0] = 1
        assertThrows(IllegalArgumentException::class.java) { Frost.decodeSafePoint(identity) } // small order
        val nonCanonicalY = hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") // y = p
        assertThrows(IllegalArgumentException::class.java) { Frost.decodeSafePoint(nonCanonicalY) }
        assertArrayEquals(hex(GROUP_PK), Frost.decodeSafePoint(hex(GROUP_PK)).toBytes())
    }
}
