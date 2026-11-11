package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.KUtil.B32
import net.atlasauth.pca.verifier.KUtil.l
import net.atlasauth.pca.verifier.KUtil.m
import net.atlasauth.pca.verifier.KUtil.n
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * IntentSession.kt / IntentMap.kt survivors of full run 42070352941. A `listOf(...)` allow-list mutated one element larger
 * gains a null slot, so only a null member name tells it apart; the reference has no such input (JS keys are strings) and
 * rejects every member outside the list, which is the refusal pinned here. Reasons are the texts of intent-session.ts.
 */
class Kill05W5SessionMapTest {
    private fun root(vararg over: Pair<String, Any?>): LinkedHashMap<String, Any?> {
        val r = m(
            "v" to n("1"), "kind" to "pca-intent-session", "session" to B32, "principals" to l(m("key" to B32)), "intent_ref" to B32,
            "schema" to m("aud" to "a", "digest" to B32), "layers" to m("task" to m("map_digest" to B32)),
            "accumulators" to l(), "monitors" to l(), "question_uri" to "https://q", "expires_at" to n("1"), "signer" to B32, "sig" to "x",
        )
        for ((k, v) in over) r[k] = v
        return r
    }

    private val std = m("profile" to "p", "version" to n("1"), "digest" to B32)
    private fun withNull(vararg kv: Pair<String, Any?>): LinkedHashMap<Any?, Any?> {
        val r = linkedMapOf<Any?, Any?>(null to n("1"))
        for ((k, v) in kv) r[k] = v
        return r
    }

    private fun layers(vararg kv: Pair<String, Any?>): Pair<String, Any?> = "layers" to m("task" to m("map_digest" to B32), *kv)

    @Test fun baselineRootIsWellFormed() {
        assertNull(IntentSession.rootShapeError(root()))
        assertNull(IntentSession.rootShapeError(root(layers("std" to std, "org" to m("digest" to B32)))))
    }

    @Test fun allowListsRefuseANullMemberName() {
        assertEquals(
            "intent_session caveat: unknown member 'null'",
            IntentSession.caveatError(withNull("type" to "intent_session", "session" to B32, "seq" to n("0"), "root" to B32)),
        )
        assertEquals(
            "unknown field 'intent_session.acc[0].null'",
            IntentSession.validateWire(m("session" to B32, "root" to B32, "seq" to n("0"), "schema" to B32, "acc" to l(withNull("id" to "a", "post" to n("0"))))),
        )
        assertEquals(
            "principals entries are {key, alg?, pq_pk?} with a 32-byte key",
            IntentSession.rootShapeError(root("principals" to l(withNull("key" to B32)))),
        )
        assertEquals(
            "layers: unknown member 'null'",
            IntentSession.rootShapeError(root("layers" to withNull("task" to m("map_digest" to B32)))),
        )
        assertEquals(
            "revocation must be {epoch_uri, max_age_s, key, pq_pk?}",
            IntentSession.rootShapeError(root("revocation" to withNull("epoch_uri" to "https://e", "max_age_s" to n("1"), "key" to B32))),
        )
    }

    @Test fun closedRootMembersRefuseExtrasAtEachSite() {
        val schema = "schema must be {aud, digest}"
        assertEquals(schema, IntentSession.rootShapeError(root("schema" to m("aud" to "a", "digest" to B32, "x" to n("1")))))
        assertEquals(schema, IntentSession.rootShapeError(root("schema" to "a")))
        val task = "layers.task must be {map_digest}"
        assertEquals(task, IntentSession.rootShapeError(root("layers" to m("task" to m("map_digest" to B32, "x" to n("1"))))))
        assertEquals(task, IntentSession.rootShapeError(root("layers" to m("task" to l(B32)))))
        val stdErr = "layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)"
        assertEquals(stdErr, IntentSession.rootShapeError(root(layers("std" to m("profile" to "p", "version" to n("1"), "digest" to B32, "x" to n("1"))))))
        assertEquals(stdErr, IntentSession.rootShapeError(root(layers("std" to "p"))))
        val org = "layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)"
        assertEquals(org, IntentSession.rootShapeError(root(layers("org" to null))))
        assertEquals(org, IntentSession.rootShapeError(root(layers("org" to l(B32)))))
    }

    /** `paramsPresent` false means params = {} whatever the argument holds: the digest of {} passes, then the absent dimension refuses. */
    @Suppress("UNCHECKED_CAST")
    @Test fun absentParamsAreTheEmptyObject() {
        val inp = KillMapTest.args(KillMapTest.cases.first { it["name"] == "decide/ok" })[0] as Map<String, Any?>
        val action = LinkedHashMap(inp["action"] as Map<String, Any?>)
        action["params_digest"] = Pca.paramsDigest(LinkedHashMap<String, Any?>())
        val d = IntentMap.decide(inp["map_commit"], action, false, inp["params"], inp["disclosure"], null)
        assertEquals("the action's value lies outside the committed map's dimension", d.reason)
    }
}
