package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Kotlin 0.5 mutation kills for [PolicyAuthoring.verifyLinkedPolicy] (group k5), from verifyLinkedPolicy of packages/pca/src/policy-link.ts:
 * a grant carrying a `template_ref` must hold exactly the predicates and caveats the reference instantiates (with the verified tighten
 * overlays applied), each refusal with its exact reason, and an envelope whose reads throw is a refusal, never an exception.
 */
@Suppress("UNCHECKED_CAST")
class Kill08K5PolicyLinkTest {
    private val kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val pub = Pca.b64(kp.public.encoded.copyOfRange(12, 44)) // X.509 SubjectPublicKeyInfo: 12-byte prefix + raw key

    private fun sign(domain: String, digest: String): String {
        val sg = java.security.Signature.getInstance("Ed25519")
        sg.initSign(kp.private)
        sg.update(Pca.concat(IntentJs.utf8(domain), java.security.MessageDigest.getInstance("SHA-256").digest(IntentJs.utf8(digest))))
        return Pca.b64(sg.sign())
    }

    /** JSON with ' for " (no apostrophes in these fixtures). */
    private fun q(s: String): Any? = Json.parseLenient(s.replace('\'', '"'))
    private fun mm(o: Any?) = o as MutableMap<String, Any?>

    private val defText =
        "{'v':1,'kind':'pca-policy-template','id':'tpl','version':'1'," +
            "'slots':{'acct':{'type':'string'},'n':{'type':'integer','min':1,'max':9}}," +
            "'body':{'predicates':[{'verb':'read','resource':{'\$slot':'acct','pre':'/a/'},'where':[{'field':'n','op':'lte','value':{'\$slot':'n'}}]}," +
            "{'verb':'read','resource':'/r'}]}}"
    private val def = mm(q(defText))
    private val digest = PolicyAuthoring.templateDigest(def)
    // an overlay adds its (here empty) `add_where` to EVERY predicate: each gains a `where`
    private val tightened = "[{'verb':'read','resource':'/a/x','where':[{'field':'n','op':'lte','value':3}]},{'verb':'read','resource':'/r','where':[]}]"
    private val predicates = "[{'verb':'read','resource':'/a/x','where':[{'field':'n','op':'lte','value':3}]},{'verb':'read','resource':'/r'}]"

    private fun entry(d: Any?) = linkedMapOf<String, Any?>("def" to d, "signer" to pub, "sig" to sign("atlas-pca/policy-template/v1\u0000", PolicyAuthoring.templateDigest(d)))
    private fun signedOverlay(o: Any?) = linkedMapOf<String, Any?>("overlay" to o, "signer" to pub, "sig" to sign("atlas-pca/template-tighten/v1\u0000", Pca.hashCanonical(o)))
    private fun ref() = linkedMapOf<String, Any?>("template_id" to "tpl", "version_digest" to digest, "slots" to q("{'acct':'x','n':3}"))
    private fun reg(vararg overlays: Any?): MutableMap<String, Any?> {
        val r = linkedMapOf<String, Any?>("templates" to mapOf(digest to entry(def)), "trusted" to listOf(pub))
        if (overlays.isNotEmpty()) r["overlays"] = overlays.toList()
        return r
    }

    private fun envelope(predicates: Any?, caveats: Any?, ref: Any? = ref()): MutableMap<String, Any?> =
        linkedMapOf("template_ref" to ref, "predicates" to predicates, "caveats" to caveats)

    private val differs = "grant policy differs from the linked template instantiation"

    @Test fun aGrantWithNoLinkIsNotChecked() {
        assertNull(PolicyAuthoring.verifyLinkedPolicy(linkedMapOf("predicates" to q(predicates), "caveats" to emptyList<Any?>()), reg()))
        assertNull(PolicyAuthoring.verifyLinkedPolicy(emptyMap(), null))
    }

    @Test fun aGrantThatHoldsExactlyTheInstantiationIsAccepted() {
        assertNull(PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), q("[]")), reg()))
        // member order of the objects does not matter (canonical hash), the order of the lists does
        val reordered = q("[{'resource':'/a/x','where':[{'value':3,'op':'lte','field':'n'}],'verb':'read'},{'resource':'/r','verb':'read'}]")
        assertNull(PolicyAuthoring.verifyLinkedPolicy(envelope(reordered, q("[]")), reg()))
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(q("[{'verb':'read','resource':'/r'},{'verb':'read','resource':'/a/x','where':[{'field':'n','op':'lte','value':3}]}]"), q("[]")), reg()))
    }

    @Test fun anyDifferenceFromTheInstantiationIsRefused() {
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), null), reg()))
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), q("[{'type':'rate','max':5}]")), reg()))
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(q("[{'verb':'read','resource':'/r'}]"), q("[]")), reg()))
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates.replace("3}", "4}")), q("[]")), reg()))
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(null, q("[]")), reg()))
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(q("[]"), q("[]")), reg()))
        val noPredicates = envelope(q(predicates), q("[]")).also { it.remove("predicates") }
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(noPredicates, reg()))
        val noCaveats = envelope(q(predicates), q("[]")).also { it.remove("caveats") }
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(noCaveats, reg()))
    }

    @Test fun theVerifiedTightenOverlaysArePartOfTheInstantiation() {
        val overlay = signedOverlay(q("{'v':1,'kind':'pca-template-tighten','template_id':'tpl','version_digest':'$digest','add_caveats':[{'type':'rate','max':5}]}"))
        val withCaveat = q("[{'type':'rate','max':5}]")
        assertNull(PolicyAuthoring.verifyLinkedPolicy(envelope(q(tightened), withCaveat), reg(overlay)))
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(q(tightened), q("[]")), reg(overlay)))
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), withCaveat), reg(overlay)))
        assertEquals(differs, PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), withCaveat), reg()))
        // an overlay that fails verification refuses with the resolver's reason
        val bad = linkedMapOf<String, Any?>("overlay" to overlay["overlay"], "signer" to pub, "sig" to "x")
        assertEquals("bad overlay signature", PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), withCaveat), reg(bad)))
    }

    @Test fun anUnresolvableLinkIsRefusedWithTheResolversReason() {
        assertEquals("template_ref must be an object", PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), q("[]"), ref = null), reg()))
        assertEquals("template_ref must be an object", PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), q("[]"), ref = "x"), reg()))
        assertEquals("template_ref has unknown member 'z'", PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), q("[]"), ref = ref().also { it["z"] = 1L }), reg()))
        assertEquals("template version is not in the registry", PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), q("[]")), emptyMap<String, Any?>()))
        assertEquals("template version is not in the registry", PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), q("[]")), null))
        assertEquals("slot 'n' is not filled", PolicyAuthoring.verifyLinkedPolicy(envelope(q(predicates), q("[]"), ref = ref().also { it["slots"] = q("{'acct':'x'}") }), reg()))
    }

    @Test fun anEnvelopeWhoseReadsThrowIsARefusalNotAnException() {
        val boom = object : LinkedHashMap<String, Any?>() {
            override fun get(key: String): Any? = throw IllegalStateException("boom")
        }
        boom["template_ref"] = ref()
        assertEquals("link verification error (fail closed)", PolicyAuthoring.verifyLinkedPolicy(boom, reg()))
    }
}
