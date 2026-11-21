package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Kill tests for ActionsRegistry.kt (k05 group "Act"): member names the closed-object checks print, the diff digest's required members,
 * a body the strict canonicaliser refuses, the pin decision over a non-iterable record list and over a diamond of evolution steps (the
 * first blocked step on the path breadth-first search found), version messages, shard refs, and the pack size bounds.
 */
class Kill05ActActionsRegistryTest {
    private fun n(s: String) = Json.Num(s)
    private fun m(vararg kv: Pair<String, Any?>): LinkedHashMap<String, Any?> = linkedMapOf(*kv)
    private fun thrown(f: () -> Any?): Throwable? = try { f(); null } catch (t: Throwable) { t }
    private fun dg(s: String) = ActionsRegistry.shardDigest(s) // any 43-character base64url digest

    private val pub = IntentTestKit.pub("act-registry")
    private val keys = listOf(m("kid" to "rk", "pk" to pub))

    @Test fun aMemberNamedNullIsPrintedAsNull() {
        assertEquals("evolution record: unknown member 'null'", ActionsRegistry.evolutionRecordError(linkedMapOf<Any?, Any?>(null to n("1"))))
        assertEquals("actions: unknown member 'null'", ActionsRegistry.actionPinError(linkedMapOf<Any?, Any?>(null to n("1"))))
        assertEquals("pack: unknown member 'null'", ActionsRegistry.packShapeError(linkedMapOf<Any?, Any?>(null to n("1"))))
    }

    @Test fun theDiffDigestNeedsEveryMember() {
        val full = m("ns" to "acme", "verb" to "acme.thing.read", "from" to dg("a"), "to" to dg("b"), "class" to "widen", "reasons" to listOf<Any?>())
        ActionsRegistry.evolutionDiffDigest(full)
        for (k in listOf("ns", "verb", "from", "to", "class", "reasons")) {
            val e = thrown { ActionsRegistry.evolutionDiffDigest(LinkedHashMap(full).also { it.remove(k) }) }
            assertTrue("$k: $e", e is IllegalArgumentException && e.message == "missing $k")
        }
    }

    @Test fun aBodyTheStrictCanonicaliserRefuses() {
        val sig = m("alg" to "ed25519", "kid" to "rk", "value" to Pca.b64(ByteArray(64)))
        assertEquals("verification error: canonicalize: lone surrogate in string", ActionsRegistry.verifyRegistrySig("d\u0000", m("x" to "\uD800"), sig, keys))
        assertEquals("signature invalid", ActionsRegistry.verifyRegistrySig("d\u0000", m("x" to "y"), sig, keys))
        val r = m("v" to n("1"), "kind" to "pca-reapproval", "grant" to "g", "verb" to "\uD800", "diff" to "d", "sig" to m("alg" to "ed25519", "value" to Pca.b64(ByteArray(64))))
        assertFalse(ActionsRegistry.reapprovalValid(r, "g", pub, "\uD800", "d"))
    }

    // ---- the pin decision ----

    private val verb = "acme.thing.read"
    private fun pinInput(pinned: String, presented: String, vararg extra: Pair<String, Any?>): LinkedHashMap<String, Any?> = m(
        "pin" to m("pack" to m("ns" to "acme", "root" to dg("root")), "defs" to m(verb to pinned), "on_new_action" to "deny"),
        "doc" to m("pack" to m("ns" to "acme"), "verbs" to listOf(m("verb" to verb, "def" to presented))),
        "verb" to verb, "keys" to keys, "grant" to m("id" to "g", "issuer" to pub), *extra,
    )

    private fun record(from: String, to: String, cls: String): LinkedHashMap<String, Any?> {
        val r = m("v" to n("1"), "kind" to "pca-evolution-record", "ns" to "acme", "verb" to verb, "from" to from, "to" to to, "class" to cls, "reasons" to listOf<Any?>())
        val value = IntentTestKit.sign("act-registry", IntentJs.message("atlas-pca/action-evolution/v1\u0000", r))
        r["sig"] = m("alg" to "ed25519", "kid" to "rk", "value" to value)
        return r
    }

    @Test fun aRecordListThatIsNotIterableFailsClosed() {
        val out = ActionsRegistry.decidePin(pinInput(dg("P"), dg("C"), "records" to "x"))
        assertEquals(m("ok" to false, "code" to "bad_pin", "escalate" to false, "reason" to "pin evaluation error (fail closed): records is not iterable"), out)
    }

    @Test fun theFirstBlockedStepOnTheBreadthFirstPath() {
        val (p, a, b, c) = listOf(dg("P"), dg("A"), dg("B"), dg("C"))
        val pa = record(p, a, "widen")
        assertNull(ActionsRegistry.verifyEvolutionRecord(pa, keys))
        // P->A is reached first (blocked); B->A must not re-parent A; A->C is free
        val recs = listOf(pa, record(p, b, "equal"), record(b, a, "widen"), record(a, c, "narrow"))
        val out = ActionsRegistry.decidePin(pinInput(p, c, "records" to recs))
        assertEquals(
            m(
                "ok" to false, "code" to "def_changed", "escalate" to false,
                "reason" to "the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve",
                "needs_reapproval" to ActionsRegistry.evolutionDiffDigest(pa),
            ),
            out,
        )
        assertEquals(m("ok" to true, "via" to "chain"), ActionsRegistry.decidePin(pinInput(p, b, "records" to recs)))
    }

    @Test fun versionMessagesNameTheBadSide() {
        val e1 = thrown { ActionsRegistry.compareVersions("x", "1.0.0") }
        assertTrue("$e1", e1 is ActionKitError && e1.code == "bad_version" && e1.message == "'x' is not MAJOR.MINOR.PATCH")
        val e2 = thrown { ActionsRegistry.compareVersions("1.0.0", "y") }
        assertTrue("$e2", e2 is ActionKitError && e2.message == "'y' is not MAJOR.MINOR.PATCH")
    }

    // ---- packs ----

    private fun pack(shards: List<Any?>): LinkedHashMap<String, Any?> = m(
        "v" to n("1"), "kind" to "pca-action-pack", "ns" to "acme", "version" to "1.0.0", "stability" to "stable",
        "traits_digest" to Actions.traitsDigest(Actions.CORE_REGISTRY), "roles_digest" to Actions.tablesDigest(), "rules_digest" to ActionsRegistry.rulesDigest(),
        "root" to dg("root"), "prev" to null,
        "source" to m("kind" to "s", "uri" to "s", "spec_digest" to "s", "licence" to "s", "licence_notes" to ""),
        "defs" to m("shards" to shards), "evolution" to listOf<Any?>(),
    )

    private fun signed(p: LinkedHashMap<String, Any?>): LinkedHashMap<String, Any?> {
        val value = IntentTestKit.sign("act-registry", IntentJs.message("atlas-pca/action-pack/v1\u0000", p))
        p["sig"] = m("alg" to "ed25519", "kid" to "rk", "value" to value)
        return p
    }

    @Test fun shardRefUris() {
        fun ref(uri: Any?) = m("name" to "a", "digest" to dg("s"), "uri" to uri)
        assertNull(ActionsRegistry.packShapeError(signed(pack(listOf(ref("u"))))))
        assertEquals("pack: bad shard digest or uri", ActionsRegistry.packShapeError(signed(pack(listOf(ref(n("5")))))))
        assertEquals("pack: bad shard digest or uri", ActionsRegistry.packShapeError(signed(pack(listOf(ref(""))))))
        assertEquals("pack: bad shard digest or uri", ActionsRegistry.packShapeError(signed(pack(listOf(m("name" to "a", "digest" to "x", "uri" to "u"))))))
        assertEquals("pack: bad shard digest or uri", ActionsRegistry.packShapeError(signed(pack(listOf(m("name" to "a", "digest" to dg("s"), "uri" to "u".repeat(2049)))))))
        assertNull(ActionsRegistry.packShapeError(signed(pack(listOf(m("name" to "a", "digest" to dg("s"), "uri" to "u".repeat(2048)))))))
    }

    @Test fun aShardOfAnotherVersion() {
        fun shard(version: String) = m("v" to n("1"), "kind" to "pca-action-pack-shard", "ns" to "acme", "version" to version, "name" to "a", "defs" to listOf<Any?>())
        for ((version, ok) in listOf("1.0.0" to true, "2.0.0" to false)) {
            val s = shard(version)
            val p = pack(listOf(m("name" to "a", "digest" to ActionsRegistry.shardDigest(s), "uri" to "u")))
            val e = thrown { ActionsRegistry.packDefs(p, m("a" to s)) }
            if (ok) assertNull("$e", e)
            else assertTrue("$e", e is ActionKitError && e.code == "bad_shard" && e.message == "shard 'a' is not a shard of this pack")
        }
    }

    @Test fun aThrowInsidePackVerificationIsReportedWithItsMessage() {
        val p = signed(pack(listOf(m("name" to "a", "digest" to ActionsRegistry.shardDigest("x"), "uri" to "u"))))
        val out = ActionsRegistry.verifyPack(p, keys, m("a" to "x"))
        assertEquals(false, out["ok"])
        val r = out["reason"] as String
        assertTrue(r, r.startsWith("pack verification error: ") && r != "pack verification error: null")
        // the control: the same pack without its shard reaches the shard check by its own refusal
        assertEquals("shard 'a' was not supplied", ActionsRegistry.verifyPack(p, keys, m())["reason"])
    }

    @Test fun packSizeBounds() {
        for (k in listOf(-1, 0, 1_000_001, Int.MAX_VALUE)) assertFalse("$k", ActionsRegistry.packSizeOk(k))
        for (k in listOf(1, 2, 4096, 1_000_000)) assertTrue("$k", ActionsRegistry.packSizeOk(k))
    }

    @Test fun packProofArgumentsMustBeStrings() {
        assertFalse(ActionsRegistry.verifyPackProof(n("5"), m(), "x"))
        assertFalse(ActionsRegistry.verifyPackProof("r", m(), n("5")))
        assertFalse(ActionsRegistry.verifyPackProof("r", m(), "x"))
    }
}
