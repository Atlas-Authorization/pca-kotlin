package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Kill tests for PolicyClasses (k05 small group): every refusal reason exactly as packages/pca/src/policy-classes.ts words it. */
class Kill05SmallPolicyClassesTest {
    private fun n(s: String) = Json.Num(s)
    private fun pc(cls: Any?, rev: Any? = n("1"), digest: Any? = "d", decision: Any? = "allow"): LinkedHashMap<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["class"] = cls; m["revision"] = rev; m["digest"] = digest; m["decision"] = decision
        return m
    }
    private fun five(): ArrayList<Any?> = arrayListOf(pc("constitution"), pc("regulatory"), pc("org"), pc("blueprint"), pc("user"))

    @Test fun validationReasons() {
        assertNull(PolicyClasses.classVerdictsError(five()))
        assertEquals("more than 5 policy classes", PolicyClasses.classVerdictsError(five().also { it.add(pc("user")) }))
        assertEquals("policy classes must be an array", PolicyClasses.classVerdictsError("x"))
        assertEquals("policy_classes[2] must be an object", PolicyClasses.classVerdictsError(arrayListOf(pc("org"), pc("user"), n("1"))))
        assertEquals("policy_classes[1] has unknown member 'x'", PolicyClasses.classVerdictsError(arrayListOf(pc("org"), pc("user").also { it["x"] = 1 })))
        assertEquals("policy_classes[0].class is not a known class", PolicyClasses.classVerdictsError(arrayListOf(pc(n("5")))))
        assertEquals("policy_classes[1].class is not a known class", PolicyClasses.classVerdictsError(arrayListOf(pc("org"), pc("root"))))
        assertEquals("policy class 'org' appears twice", PolicyClasses.classVerdictsError(arrayListOf(pc("org"), pc("org"))))
        assertEquals("policy_classes[1].revision must be a non-negative safe integer", PolicyClasses.classVerdictsError(arrayListOf(pc("org"), pc("user", rev = n("-1")))))
        assertNull(PolicyClasses.classVerdictsError(arrayListOf(pc("org", digest = "d".repeat(128)))))
        assertEquals("policy_classes[0].digest invalid", PolicyClasses.classVerdictsError(arrayListOf(pc("org", digest = "d".repeat(129)))))
        assertEquals("policy_classes[0].digest invalid", PolicyClasses.classVerdictsError(arrayListOf(pc("org", digest = ""))))
        assertEquals("policy_classes[1].decision must be allow, escalate or deny", PolicyClasses.classVerdictsError(arrayListOf(pc("org"), pc("user", decision = "maybe"))))
    }

    @Test fun decideReportsTheValidationReason() {
        val r = PolicyClasses.decideClasses(arrayListOf(pc("org"), pc("user", decision = "maybe")))
        assertEquals("deny", r.decision)
        assertEquals("malformed policy classes: policy_classes[1].decision must be allow, escalate or deny", r.reason)
        val ok = PolicyClasses.decideClasses(arrayListOf(pc("user", decision = "escalate"), pc("org", decision = "deny"), pc("constitution")))
        assertEquals("deny", ok.decision)
        assertEquals(listOf("constitution", "org", "user"), ok.classes.map { it.cls })
        assertEquals(listOf("org"), ok.deniedBy)
        assertEquals(listOf("user"), ok.escalatedBy)
        assertNull(ok.reason)
    }

    @Test fun anEvaluationErrorFailsClosed() {
        // the list validates on its first pass and throws when decideClasses iterates it again
        val items = arrayListOf<Any?>(pc("org"))
        val flaky = object : ArrayList<Any?>(items) {
            var passes = 0
            override fun iterator(): MutableIterator<Any?> {
                if (passes++ > 0) throw IllegalStateException("second pass")
                return super.iterator()
            }
        }
        val r = PolicyClasses.decideClasses(flaky)
        assertEquals("deny", r.decision)
        assertEquals("evaluation error (fail closed)", r.reason)
        assertEquals(emptyList<Any?>(), r.classes)
        assertEquals(emptyList<String>(), r.deniedBy)
        assertEquals(emptyList<String>(), r.escalatedBy)
    }
}
