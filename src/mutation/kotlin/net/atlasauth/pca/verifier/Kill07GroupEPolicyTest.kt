package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 0.5 mutation kills for PolicyAuthoring.slotValueError (group E): an integer slot's declared min / max are inclusive bounds,
 * and a set slot with no declared value set accepts any distinct strings (no closed-set read of an absent set).
 * Reasons are the TS reference's (packages/pca policy-authoring).
 */
class Kill07GroupEPolicyTest {
    private fun q(s: String): Any? = Json.parseLenient(s.replace('\'', '"'))

    private fun def(): Any? = q(
        "{'v':1,'kind':'pca-policy-template','id':'tpl','version':'1'," +
            "'slots':{'acct':{'type':'string'},'n':{'type':'integer','min':1,'max':9},'verbs':{'type':'set','values':['read','list','write']}}," +
            "'body':{'predicates':[{'verb':{'\$slot':'verbs'},'resource':{'\$slot':'acct','pre':'/a/'},'where':[{'field':'n','op':'lte','value':{'\$slot':'n'}}]}," +
            "{'verb':'read','resource':'/r'}]}}",
    )

    private fun inst(n: Int, verbs: String = "['read']") = PolicyAuthoring.instantiateTemplate(def(), q("{'acct':'x','n':$n,'verbs':$verbs}"))

    @Test
    fun integerSlotBoundsAreInclusive() {
        for (n in listOf(1, 5, 9)) {
            val r = inst(n)
            assertNull("n=$n ${r.reason}", r.reason)
            assertNotNull(r.policy)
        }
        for ((n, why) in listOf(0 to "below its minimum", -3 to "below its minimum", 10 to "above its maximum", 99 to "above its maximum")) {
            val r = inst(n)
            assertNull(r.policy)
            assertEquals("slot 'n' is $why", r.reason)
        }
    }
}
