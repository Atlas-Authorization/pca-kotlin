package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.l
import net.atlasauth.pca.verifier.KUtil.m
import net.atlasauth.pca.verifier.KUtil.mm
import java.security.SecureRandom
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Chains / shares signed under ML-DSA-65 and the hybrid suite (pins, trusted root, holder_pq binding) + Ed25519 re-signing helpers. */
class PqChainTest {
    companion object {
        fun pqKey(): AsymmetricCipherKeyPair {
            val g = MLDSAKeyPairGenerator(); g.init(MLDSAKeyGenerationParameters(SecureRandom(), MLDSAParameters.ml_dsa_65)); return g.generateKeyPair()
        }
        fun pk(k: AsymmetricCipherKeyPair): String = Pca.b64((k.public as MLDSAPublicKeyParameters).encoded)
        fun pqSign(k: AsymmetricCipherKeyPair, msg: ByteArray): String {
            val s = MLDSASigner(); s.init(true, k.private); s.update(msg, 0, msg.size); return Pca.b64(s.generateSignature())
        }
        @Suppress("UNCHECKED_CAST") private fun keys() = ReasonSnapshot.loadJson("keys.json")
        @Suppress("UNCHECKED_CAST") fun seed(name: String) = Pca.decodeB64uStrict((keys()[name] as Map<String, Any?>)["seed"], 32)!!
        @Suppress("UNCHECKED_CAST") fun pub(name: String) = (keys()[name] as Map<String, Any?>)["public"] as String
        fun edSign(name: String, msg: ByteArray): String {
            val sig = ByteArray(64); org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed(name), 0, msg, 0, msg.size, sig, 0); return Pca.b64(sig)
        }
        fun twoHopOf(name: String): List<Any?> = KUtil.ll(mm(KUtil.vec(name)["pcactn"])["cap_chain"])

        /** Ed25519-signed capability (signer key name), arbitrary issuer/holder values. */
        fun signedEd(issuer: Any?, holder: Any?, caveats: List<Any?>, parent: Any?, signer: String, @Suppress("UNUSED_PARAMETER") unused: String): Map<String, Any?> {
            val body = m("issuer" to issuer, "holder" to holder, "caveats" to caveats, "parent" to parent)
            val digest = Pca.hashCanonical(body)
            val msg = Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32)!!)
            val c = LinkedHashMap<String, Any?>()
            c["id"] = digest; c["issuer"] = issuer; c["holder"] = holder; c["caveats"] = caveats
            if (parent != null) c["parent"] = parent
            c["body_digest"] = digest; c["sig"] = edSign(signer, msg)
            return c
        }

        fun cap(issuer: String, holder: String, caveats: List<Any?>, parent: String?, signer: String, alg: String?, pqk: AsymmetricCipherKeyPair?, holderPq: String?): Map<String, Any?> {
            val c = LinkedHashMap<String, Any?>()
            c["issuer"] = issuer; c["holder"] = holder; c["caveats"] = caveats
            if (parent != null) c["parent"] = parent
            if (holderPq != null) c["holder_pq"] = holderPq
            if (alg != null) { c["alg"] = alg; c["pq_pk"] = pk(pqk!!) }
            val body: Map<String, Any?> = KUtil.priv(Pca, "signableHopBody", c)
            val digest = Pca.hashCanonical(body)
            val msg = Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32)!!)
            val out = LinkedHashMap(c); out["id"] = digest; out["body_digest"] = digest
            when (alg) {
                null -> out["sig"] = edSign(signer, msg)
                "ml-dsa-65" -> out["sig"] = pqSign(pqk!!, msg)
                else -> { out["sig"] = edSign(signer, msg); out["pq_sig"] = pqSign(pqk!!, msg) }
            }
            return out
        }
        fun refusal(alg: String) = "hop 0: root suite '$alg' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)"
    }

    @Test fun pqRoots() {
        val issuer = pub("principal"); val agent = pub("agent")
        for (alg in listOf("ml-dsa-65", "hybrid-ed25519-ml-dsa-65")) {
            val k = pqKey()
            val root = cap(issuer, agent, ArrayList(), null, "principal", alg, k, null)
            val chain = l(root); val pins = m(issuer to pk(k))
            assertEquals("$alg pinned", "", Pca.verifyChain(chain, issuer, true, null, pins, null))
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, null, root))
            // 0.4.2: trusted root AND a pin for the issuer must agree (the stored grant never overrides a disagreeing pin)
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, pins, root))
            assertEquals("hop 0: root suite '$alg': the server-side PQ pin for the root issuer (policy.pqPins) does not match the stored grant's pq_pk (fail closed)",
                Pca.verifyChain(chain, issuer, true, null, m(issuer to pk(pqKey())), root))
            assertEquals("", Pca.verifyChain(chain, "", false, null, pins, null))
            assertEquals(refusal(alg), Pca.verifyChain(chain, issuer, true, null))
            assertEquals(refusal(alg), Pca.verifyChain(chain, issuer, true, null, m(issuer to pk(pqKey())), null))
            assertEquals(refusal(alg), Pca.verifyChain(chain, issuer, true, null, m(agent to pk(k)), null))
            val other = cap(issuer, agent, l(m("type" to "x")), null, "principal", alg, k, null)
            assertEquals(refusal(alg), Pca.verifyChain(chain, issuer, true, null, null, other))
            val bad = LinkedHashMap(root); bad[if (alg == "ml-dsa-65") "sig" else "pq_sig"] = pqSign(pqKey(), byteArrayOf(1))
            assertEquals("hop 0: bad signature (not signed by expected key)", Pca.verifyChain(l(bad), issuer, true, null, pins, null))
            if (alg.startsWith("hybrid")) {
                val badEd = LinkedHashMap(root); badEd["sig"] = edSign("agent", byteArrayOf(1))
                assertEquals("hop 0: bad signature (not signed by expected key)", Pca.verifyChain(l(badEd), issuer, true, null, pins, null))
            }
            assertEquals("hop 0: signature suite is not allowed by this verifier's suite policy", Pca.verifyChain(chain, issuer, true, listOf("ed25519"), pins, null))
            assertEquals("", Pca.verifyChain(chain, issuer, true, listOf(alg), pins, null))
        }
    }

    @Test fun pqHops() {
        val issuer = pub("principal"); val agent = pub("agent"); val sub = pub("subagent")
        for (alg in listOf("ml-dsa-65", "hybrid-ed25519-ml-dsa-65")) {
            val hk = pqKey()
            val root = cap(issuer, agent, ArrayList(), null, "principal", null, null, Pca.holderPqCommitment(pk(hk)))
            val hop = cap(agent, sub, ArrayList(), Pca.capHash(root), "agent", alg, hk, null)
            val chain = l(root, hop)
            assertEquals("$alg bound hop", "", Pca.verifyChain(chain, issuer, true))
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, null, root))
            val evil = cap(agent, sub, ArrayList(), Pca.capHash(root), "agent", alg, pqKey(), null)
            assertEquals("hop 1: pq_pk does not match the signer's committed holder_pq (F-2)", Pca.verifyChain(l(root, evil), issuer, true))
            val bad = LinkedHashMap(hop); bad[if (alg == "ml-dsa-65") "sig" else "pq_sig"] = pqSign(hk, byteArrayOf(7))
            assertEquals("hop 1: bad signature (not signed by expected key)", Pca.verifyChain(l(root, bad), issuer, true))
            val root2 = cap(issuer, agent, ArrayList(), null, "principal", null, null, null)
            val hop2 = cap(agent, sub, ArrayList(), Pca.capHash(root2), "agent", alg, hk, null)
            assertTrue(Pca.verifyChain(l(root2, hop2), issuer, true).startsWith("hop 1: suite '$alg' needs a PQ key bound"))
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, m(agent to pk(hk)), null))
        }
    }

    @Test fun shares() {
        val k = pqKey(); val edPub = pub("agent")
        val set = l(m("publicKey" to edPub, "role" to "agent", "pq_pk" to pk(k)))
        val tm = byteArrayOf(4, 5, 6)
        val msg = Threshold.shareMessage("agent", tm, set, 3, "hybrid-ed25519-ml-dsa-65", true)
        val share = m("role" to "agent", "publicKey" to edPub, "alg" to "hybrid-ed25519-ml-dsa-65", "pq_pk" to pk(k), "sig" to edSign("agent", msg), "pq_sig" to pqSign(k, msg))
        assertTrue(Threshold.verifyShare("agent", tm, set, 3, share))
        fun v(f: (MutableMap<String, Any?>) -> Unit): Boolean { val s = LinkedHashMap(share); f(s); return Threshold.verifyShare("agent", tm, set, 3, s) }
        assertFalse(v { it.remove("pq_sig") }); assertFalse(v { it["sig"] = edSign("principal", msg) }); assertFalse(v { it["pq_pk"] = pk(pqKey()) }); assertTrue(v { it.remove("pq_pk") })
        assertFalse(v { it["publicKey"] = pub("principal") }); assertFalse(v { it.remove("alg") }); assertFalse(v { it["alg"] = "ed25519" })
        // pure ML-DSA share
        val msg2 = Threshold.shareMessage("agent", tm, set, 2, "ml-dsa-65", true)
        val sh2 = m("role" to "agent", "publicKey" to edPub, "alg" to "ml-dsa-65", "pq_pk" to pk(k), "sig" to pqSign(k, msg2))
        assertTrue(Threshold.verifyShare("agent", tm, set, 2, sh2))
        assertFalse(Threshold.verifyShare("agent", tm, set, 1, sh2)); assertFalse(Threshold.verifyShare("guardian", tm, set, 2, sh2))
        // R5-A1: the PQ key comes from the signer set, never from the share
        assertTrue(Threshold.verifyShare("agent", tm, set, 2, LinkedHashMap(sh2).also { it.remove("pq_pk") }))
        assertFalse(Threshold.verifyShare("agent", tm, set, 2, LinkedHashMap(sh2).also { it["pq_pk"] = pk(pqKey()) }))
        assertFalse(Threshold.verifyShare("agent", tm, l(m("publicKey" to edPub, "role" to "agent")), 2, sh2))
        assertFalse(Threshold.verifyShare("agent", tm, l(m("publicKey" to pub("principal"), "role" to "agent", "pq_pk" to pk(k))), 2, sh2))
        assertFalse(Threshold.verifyShare("agent", tm, l(m("publicKey" to edPub, "role" to "agent", "pq_pk" to pk(k)), m("publicKey" to pub("principal"), "role" to "agent")), 2, sh2))
        assertFalse(Threshold.verifyShare("agent", tm, l(m("publicKey" to edPub, "role" to "agent", "pq_pk" to pk(k)), m("publicKey" to edPub, "role" to "guardian")), 2, sh2))
        assertFalse(Threshold.verifyShare("agent", tm, set, 2, LinkedHashMap(sh2).also { it["role"] = "guardian" }))
        assertTrue(Threshold.verifyShare("agent", tm, set, 2, LinkedHashMap(sh2).also { it["role"] = "agent" }))
        assertFalse(Threshold.verifyShare("agent", tm, set, 2, LinkedHashMap(sh2).also { it["sig"] = "A".repeat(4412) }))
        assertFalse(java.util.Arrays.equals(Threshold.shareMessage("agent", tm, set, 2, null, false), msg2))
    }

    @Test fun explicitEd25519Share() {
        val edPub = pub("agent")
        val set = l(m("publicKey" to edPub, "role" to "agent"))
        val tm = byteArrayOf(8, 8)
        val msg = Threshold.shareMessage("agent", tm, set, 1, null, false)
        for (explicit in listOf(false, true)) {
            val sh = m("role" to "agent", "publicKey" to edPub, "sig" to edSign("agent", msg))
            if (explicit) sh["alg"] = "ed25519"
            assertTrue("explicit=$explicit", Threshold.verifyShare("agent", tm, set, 1, sh))
            // a pq_pk naming a key its role does not register is refused, any suite (d00dba73; this test was stale)
            sh["pq_pk"] = "ignored-for-ed25519"
            assertFalse(Threshold.verifyShare("agent", tm, set, 1, sh))
        }
        assertFalse(Threshold.verifyShare("agent", tm, set, 1, m("role" to "agent", "publicKey" to edPub, "alg" to "ed25519", "sig" to edSign("principal", msg))))
        assertFalse(Threshold.verifyShare("agent", tm, set, 1, m("role" to "agent", "publicKey" to edPub, "alg" to null, "sig" to edSign("agent", msg))))
    }
}
