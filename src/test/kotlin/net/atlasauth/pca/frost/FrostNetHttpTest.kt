package net.atlasauth.pca.frost

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** A 2-of-3 signing session where every signer is reached over loopback HTTP: the aggregate is an ordinary Ed25519 signature under the group key. */
@Suppress("UNCHECKED_CAST")
class FrostNetHttpTest {
    @Test fun twoOfThreeOverHttp() {
        val kg = Frost.trustedDealerKeygen(2, 3)
        val policy = Keys.edGenerate()
        val message = "transfer 10 USD to alice".toByteArray()
        val servers = ArrayList<FrostNetHttp.SignerHttpServer>()
        try {
            val transports = kg.participantShares.take(2).map { p ->
                val svc = FrostNet.GuardianSignerService(IntentJs.ofLong(p.identifier), p.share, kg.groupPublicKey, IntentJs.ofLong(2), policy.pub)
                val srv = FrostNetHttp.startSignerHttpServer(svc)
                servers.add(srv)
                FrostNetHttp.httpSignerTransport(srv.url, p.identifier)
            }
            val vs = kg.participantShares.take(2).map { linkedMapOf<String, Any?>("identifier" to IntentJs.ofLong(it.identifier), "publicKey" to it.publicKey) }
            val coord = FrostNet.NetworkCoordinator(kg.groupPublicKey, IntentJs.ofLong(2), transports, vs)
            val allow = FrostNet.issueAllowToken(policy.seed, linkedMapOf("message" to message, "groupPublicKey" to kg.groupPublicKey, "nonce" to "http-1"))
            val r = coord.sign(message, allow)
            assertTrue(Pca.ed25519Strict(kg.groupPublicKey, message, r.signature))
            assertEquals(listOf(1L, 2L), r.signers)
        } finally {
            servers.forEach { it.close() }
        }
    }
}
