package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The shared vectors for the forbid-wins certificate (table) and linked policy templates. */
@Suppress("UNCHECKED_CAST")
class PolicyAuthoringVectorsTest {
    private fun rows(o: Any?) = o as List<Map<String, Any?>>
    private fun strings(o: Any?) = (o as? List<*>)?.filterIsInstance<String>() ?: emptyList()

    @Test
    fun forbidCertificateTable() {
        val table = rows(ParityVectors.load("forbid-certificate-vectors.json")["table"])
        assertTrue(table.size >= 19)
        for (v in table) {
            val prec = strings((v["options"] as? Map<String, Any?>)?.get("precedence"))
            val want = (v["expect"] as Map<String, Any?>)["consistent"] == true
            assertEquals(v["name"].toString(), want, PolicyAuthoring.forbidCertificateConsistent(v["certificate"], prec))
        }
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(null))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent("x"))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(emptyMap<String, Any?>()))
    }

    @Test
    fun policyLinkVectors() {
        val doc = ParityVectors.load("policy-link-vectors.json")
        val tpl = doc["template"] as Map<String, Any?>
        val def = tpl["def"]
        assertEquals(tpl["digest"], PolicyAuthoring.templateDigest(def))
        for (v in rows(doc["def_errors"])) assertEquals(v["name"].toString(), v["expect"], PolicyAuthoring.templateDefError(v["def"]))
        val inst = rows(doc["instantiate"])
        assertTrue(inst.size >= 14)
        for (v in inst) {
            val r = PolicyAuthoring.instantiateTemplate(def, v["slots"])
            val x = v["expect"] as Map<String, Any?>
            if (x["ok"] == true) assertTrue("${v["name"]}: ${r.reason}", r.policy != null && IntentJs.jsonEquals(r.policy, x["policy"]))
            else { assertNull(v["name"].toString(), r.policy); assertEquals(v["name"].toString(), x["reason"], r.reason) }
        }
        for (v in rows(doc["verify"])) {
            val trusted = strings(v["trusted"])
            val r = if (v["kind"] == "template") PolicyAuthoring.verifyTemplate(v["signed"], trusted) else PolicyAuthoring.verifyTighten(v["signed"], trusted)
            val x = v["expect"] as Map<String, Any?>
            assertEquals(v["name"].toString(), x["ok"] == true, r == null)
            if (r != null) assertEquals(v["name"].toString(), x["reason"], r)
        }
        for (v in rows(doc["ref_errors"])) assertEquals(v["name"].toString(), v["expect"], PolicyAuthoring.templateRefError(v["ref"]))
        for (v in rows(doc["resolve"])) {
            val r = PolicyAuthoring.resolveLink(v["ref"], v["registry"])
            val x = v["expect"] as Map<String, Any?>
            if (x["ok"] == true) {
                assertTrue("${v["name"]}: ${r.reason}", r.policy != null && IntentJs.jsonEquals(r.policy, x["policy"]))
                assertEquals(v["name"].toString(), IntentJs.lng(x["overlays"]), r.overlays.toLong())
            } else { assertNull(v["name"].toString(), r.policy); assertEquals(v["name"].toString(), x["reason"], r.reason) }
        }
    }
}
