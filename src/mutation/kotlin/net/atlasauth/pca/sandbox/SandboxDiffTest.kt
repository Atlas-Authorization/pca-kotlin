package net.atlasauth.pca.sandbox

import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import net.atlasauth.pca.verifier.Pca
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the reference vectors of the sandbox package through the native port. */
@Suppress("UNCHECKED_CAST")
class SandboxDiffTest {
    private val M = "ref-sandbox"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun err(): Map<String, Any?> = linkedMapOf("\$err" to true)
    private fun bytes(o: Any?): ByteArray = Keys.unb64u(m(o)["\$bytes"] as String)
    private fun seedOf(label: String): ByteArray = OracleCases.seed(label)
    private fun arg(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null
    private fun idx(o: Any?): Long = IntentJs.num(o).let { if (it == null || it != Math.rint(it)) 0L else it.toLong() }

    /** What the reference's authorization result looks like for {allow, bind}: an operation bound to the digest of bind.params. */
    private fun result(allow: Boolean, bind: Any?): Authorize.Result {
        var op: Authorize.AuthorizedOperation? = null
        if (bind != null) {
            val b = m(bind)
            op = Authorize.AuthorizedOperation(b["verb"] as String, b["resource"] as String, Pca.hashCanonical(b["params"]), (b["id"] ?: "op") as String)
        }
        return Authorize.Result(allow, if (allow) 200 else 403, LinkedHashMap(), ArrayList(), null, operation = op)
    }

    /** The reference refuses an operation whose params are not an object (validOperation); the typed API cannot hold one. */
    private fun operation(o: Any?): Authorize.Operation {
        val op = m(o)
        if (op["params"] !is Map<*, *>) throw IllegalArgumentException("not_authorized: bad operation")
        return Authorize.Operation(op["verb"] as String, op["resource"] as String, m(op["params"]))
    }

    @Test fun consts() = OracleCases.each(M, "moduleConsts") {
        linkedMapOf(
            "IMPORT_MODULE" to Host.IMPORT_MODULE, "ALLOWED_IMPORTS" to Host.ALLOWED_IMPORTS, "USE_ERR" to Handles.USE_ERR,
            "GENESIS" to Receipts.GENESIS, "RUNTIME_CLASSES" to Receipts.RUNTIME_CLASSES, "DOMAIN" to RuntimeClaims.RUNTIME_CLAIM_DOMAIN,
        )
    }

    @Test fun satisfies() = OracleCases.each(M, "satisfiesRuntimeClass") { a -> Receipts.satisfiesRuntimeClass(a[0], a[1]) }

    @Test fun receiptLog() = OracleCases.each(M, "receiptLog") { a ->
        val spec = m(a[0])
        var t: Any? = 0L
        val signer: ((String) -> String)? = if (spec["sign"] == true) ({ d: String -> "sig:$d" }) else null
        val log = Receipts.ReceiptLog({ t }, signer)
        val outs = ArrayList<Any?>()
        for (s in l(spec["appends"])) {
            val st = m(s)
            t = st["t"]
            try { outs.add(log.append(st["rc"] as String, m(st["body"]))) } catch (e: RuntimeException) { outs.add(err()) }
        }
        outs
    }

    @Test fun receiptChain() = OracleCases.each(M, "verifyReceiptChain") { a ->
        val v: ((String, String) -> Boolean)? = if ("tag" == a[1]) ({ d: String, s: String -> s == "sig:$d" }) else null
        Receipts.verifyReceiptChain(a[0], v)
    }

    @Test fun policyFromNeeds() = OracleCases.each(M, "policyFromNeeds") { a -> Profiles.policyFromNeeds(a[0], arg(a, 1)) }

    @Test fun compilePolicy() = OracleCases.each(M, "compilePolicy") { a ->
        val spec = m(a[0])
        val items = ArrayList<Profiles.AuthorizedOp>()
        for (o in l(spec["items"])) {
            val it = m(o)
            items.add(Profiles.AuthorizedOp(result(it["allow"] == true, it["bind"]), operation(it["operation"])))
        }
        val needs = m(spec["needs"])
        Profiles.compilePolicy(items, { op -> needs[op.verb + " " + op.resource] }, spec["proxyPort"])
    }

    @Test fun profiles() {
        OracleCases.each(M, "seccompProfile") { a -> Profiles.seccompProfile(m(a[0])) }
        OracleCases.each(M, "landlockRuleset") { a -> Profiles.landlockRuleset(m(a[0])) }
        OracleCases.each(M, "macosProfile") { a -> Profiles.macosProfile(m(a[0])) }
        OracleCases.each(M, "confineArgs") { a -> Confine.confineArgs(m(a[0])) }
    }

    /**
     * These vectors predate the address check that classifies the parsed address: they read these loopback / unspecified / v4-mapped /
     * zoned / reserved spellings as public, and a non-string as a throw. The native check, like the current reference, calls all of them private.
     */
    private val STRICTER_PRIVATE = setOf("0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:0", "::ffff:7f00:1", "::ffff:0:0", "::1%eth0", "::127.0.0.1", "::ffff:1.2.3.4%x",
        "::2", "fec0::1", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:1.2.3.4", "f::")

    @Test fun privateAddress() {
        val bad = ArrayList<String>()
        for (c in OracleCases.of(M, "isPrivateAddress")) {
            val ip = l(c["args"])[0]
            if (ip !is String || ip in STRICTER_PRIVATE) {
                if (!Egress.isPrivateAddress(ip)) bad.add("${c["name"]} is not private")
            } else {
                OracleCases.diff(c, c["out"]) { a -> Egress.isPrivateAddress(a[0]) }?.let { bad.add(it) }
            }
        }
        assertTrue(bad.joinToString("\n"), bad.isEmpty())
        for (ip in listOf("0::1", "::FFFF:7F00:0001", "::7f00:1", "64:ff9b::7f00:1", "64:ff9b::10.0.0.1", "fe80::1%25eth0", "2606:4700::1111%eth0",
            "FE80::1", "fc::1", "1fff::1", "4000::1", "1::2::3", "::00001", "::01.2.3.4", "[::1]", " ::1")) assertTrue(ip, Egress.isPrivateAddress(ip))
        for (ip in listOf("2606:4700:0:0:0:0:0:1111", "2001:DB8::1", "::ffff:808:808", "::ffff:8.8.8.8", "64:ff9b::8.8.8.8", "2000::", "3fff::1", "8.8.8.8"))
            assertEquals(ip, false, Egress.isPrivateAddress(ip))
        assertTrue(Egress.isPrivateAddress(null))
    }

    @Test fun egress() = OracleCases.each(M, "egress") { a ->
        var t = 0.0
        val p = Egress.EgressPolicy({ t })
        val outs = ArrayList<Any?>()
        for (s in l(m(a[0])["steps"])) {
            val st = m(s)
            try {
                val op = st["op"] as String
                if (op == "now") { t = IntentJs.num(st["t"])!!; outs.add(null) }
                else if (op == "admit") {
                    val tmpl = st["template"]
                    val opts = if (st["opts"] == null) LinkedHashMap() else m(st["opts"])
                    p.admit(result(st["allow"] == true, st["bind"]), operation(st["operation"]), { _ ->
                        if (tmpl == null) null
                        else if (tmpl !is Map<*, *>) throw IllegalArgumentException("bad_template")
                        else m(tmpl)
                    }, opts["uses"], opts["expiresAt"])
                    outs.add("ok")
                } else {
                    val req = m(st["req"])
                    outs.add(p.claim(req["method"], req["url"], if (req["body"] == null) null else bytes(req["body"])))
                }
            } catch (e: RuntimeException) { outs.add(err()) }
        }
        outs
    }

    /** JSON.stringify of an operation: insertion order, compact, numbers as JavaScript prints them. */
    private fun js(v: Any?, sb: StringBuilder) {
        when (v) {
            null -> sb.append("null")
            is String -> sb.append(Json.canonicalize(v))
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, x) in v) {
                    if (!first) sb.append(',')
                    first = false
                    sb.append(Json.canonicalize(k)).append(':')
                    js(x, sb)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                var first = true
                for (x in v) {
                    if (!first) sb.append(',')
                    first = false
                    js(x, sb)
                }
                sb.append(']')
            }
            is Json.Num -> sb.append(v.raw)
            else -> sb.append(v)
        }
    }

    private val EXEC: Map<String, Handles.Executor> = linkedMapOf(
        "fs.read" to Handles.Executor { _, _, _ -> byteArrayOf(1, 2, 3) },
        "fs.echo" to Handles.Executor { verb, resource, params ->
            val sb = StringBuilder()
            js(IntentJs.normalize(linkedMapOf("verb" to verb, "resource" to resource, "params" to params)), sb)
            sb.toString().toByteArray(Charsets.UTF_8)
        },
        "fs.throw" to Handles.Executor { _, _, _ -> throw IllegalStateException("boom") },
        "fs.notbytes" to Handles.Executor { _, _, _ -> null },
    )

    @Test fun handles() = OracleCases.each(M, "handles") { a ->
        val spec = m(a[0])
        var t: Any? = 0L
        val log = Receipts.ReceiptLog({ t }, null)
        val table = Handles.HandleTable(spec["cls"] as String, log, EXEC) { IntentJs.num(t)!! }
        val outs = ArrayList<Any?>()
        for (s in l(spec["steps"])) {
            val st = m(s)
            try {
                when (st["op"] as String) {
                    "now" -> { t = st["t"]; outs.add(null) }
                    "mint" -> {
                        val bind: Any? = if (st.containsKey("bind")) st["bind"] else LinkedHashMap(m(st["operation"])).also { it["id"] = st["id"] ?: "op-h" }
                        val o = Handles.MintOptions()
                        val opts = if (st["opts"] == null) LinkedHashMap() else m(st["opts"])
                        o.uses = opts["uses"]
                        o.expiresAt = opts["expiresAt"]
                        o.requires = opts["requires"] as String?
                        val allow = st["allow"] == null || st["allow"] == true
                        outs.add(table.mint(result(allow, bind), operation(st["operation"]), o).toLong())
                    }
                    "attenuate" -> {
                        val n = if (st["narrower"] == null) LinkedHashMap() else m(st["narrower"])
                        outs.add(table.attenuate(idx(st["index"]), n["uses"], n["expiresAt"]).toLong())
                    }
                    "revoke" -> { table.revoke(idx(st["index"])); outs.add(null) }
                    "use" -> outs.add(table.use(idx(st["index"])).toMap())
                    "verbOf" -> outs.add(table.verbOf(idx(st["index"])))
                    else -> outs.add(table.size().toLong())
                }
            } catch (e: RuntimeException) { outs.add(err()) }
        }
        linkedMapOf("outs" to outs, "log" to log.entries())
    }

    @Test fun runtimeClaims() {
        OracleCases.each(M, "signRuntimeClaim") { a ->
            val k = a[0]
            val sk = if (k is String) seedOf(k) else ByteArray(IntentJs.num(m(k)["short"])!!.toInt())
            RuntimeClaims.signRuntimeClaim(sk, Keys.edFromSeed(seedOf(a[1] as String)).pub, m(a[2]))
        }
        OracleCases.each(M, "verifiedRuntimeClass") { a -> RuntimeClaims.verifiedRuntimeClass(a[0], a[1]) }
        OracleCases.each(M, "passportDigest") { a -> RuntimeClaims.passportDigest(a[0]) }
        OracleCases.each(M, "evidenceDigest") { a -> RuntimeClaims.evidenceDigest(a[0]) }
    }

    /** Negative times and empty or over-long digests are none even when correctly signed and trusted. */
    @Test fun runtimeClaimStrictForm() {
        val seed = seedOf("strict-attestor")
        val pub = Keys.edFromSeed(seed).pub
        fun run(over: Map<String, Any?>, tOver: Map<String, Any?>): String {
            val c = linkedMapOf<String, Any?>("class" to "os_confined", "passport_digest" to "pd", "evidence_digest" to "ev", "iat" to 0L, "exp" to 100L)
            c.putAll(over)
            val claim = RuntimeClaims.signRuntimeClaim(seed, pub, c)
            val t = linkedMapOf<String, Any?>(
                "pinnedAttestors" to listOf(claim["attestor"]), "passportDigest" to claim["passport_digest"],
                "verifiedEvidenceDigests" to listOf(claim["evidence_digest"]), "now" to 50L,
            )
            t.putAll(tOver)
            return RuntimeClaims.verifiedRuntimeClass(claim, t)
        }
        assertEquals("os_confined", run(emptyMap(), emptyMap()))
        assertEquals("negative iat", "none", run(mapOf("iat" to -5L), emptyMap()))
        assertEquals("negative times", "none", run(mapOf("iat" to -10L, "exp" to -1L), mapOf("now" to -5L)))
        assertEquals("negative now", "none", run(mapOf("iat" to -10L), mapOf("now" to -1L)))
        assertEquals("empty evidence digest", "none", run(mapOf("evidence_digest" to ""), emptyMap()))
        assertEquals("empty passport digest", "none", run(mapOf("passport_digest" to ""), emptyMap()))
        assertEquals("129-character evidence digest", "none", run(mapOf("evidence_digest" to "d".repeat(129)), emptyMap()))
        assertEquals("129-character passport digest", "none", run(mapOf("passport_digest" to "d".repeat(129)), emptyMap()))
        assertEquals("unsafe-integer now", "none", run(emptyMap(), mapOf("now" to 9007199254740992.0)))
        assertEquals("128 is the limit", "os_confined", run(mapOf("evidence_digest" to "d".repeat(128), "passport_digest" to "p".repeat(128)), emptyMap()))
    }

    @Test fun referenceModules() {
        OracleCases.each(M, "buildTool") { a -> ReferenceTool.buildTool(m(a[0])) }
        OracleCases.each(M, "buildProbeTool") { a -> ReferenceTool.buildProbeTool(arg(a, 0)) }
        OracleCases.each(M, "referenceComponentWat") { a -> ReferenceComponent.referenceComponentWat(if (a.isEmpty()) null else m(a[0])) }
    }

    @Test fun trustFromAttestationAdmitsOnlyBoundEvidence() {
        val doc = linkedMapOf<String, Any?>("format" to "x")
        val good = linkedMapOf<String, Any?>("ok" to true, "bound" to true)
        val unbound = linkedMapOf<String, Any?>("ok" to true, "bound" to false)
        val pinned = listOf("k")
        assertEquals(listOf(RuntimeClaims.evidenceDigest(doc)), RuntimeClaims.trustFromAttestation(doc, { good }, 5L, pinned, "p")["verifiedEvidenceDigests"])
        assertTrue((RuntimeClaims.trustFromAttestation(doc, { unbound }, 5L, pinned, "p")["verifiedEvidenceDigests"] as List<*>).isEmpty())
        assertTrue((RuntimeClaims.trustFromAttestation(doc, { throw IllegalStateException("x") }, 5L, pinned, "p")["verifiedEvidenceDigests"] as List<*>).isEmpty())
        assertTrue((RuntimeClaims.trustFromAttestation(doc, { "nope" }, 5L, pinned, "p")["verifiedEvidenceDigests"] as List<*>).isEmpty())
    }
}
