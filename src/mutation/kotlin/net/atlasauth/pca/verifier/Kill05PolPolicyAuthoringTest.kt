package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PCA 0.5 mutation kills for [PolicyAuthoring]: the differential against the TS reference (test-data/k05-policyauthoring.json.gz
 * from tools/pca-audit/k05-oracles/policyauthoring-oracle.mts, the same oracle the Java port replays) plus the fail-closed paths
 * no oracle case reaches (a map whose reads throw) and the parity fixes it found (String(x) of a non-string `$slot`, a falsy
 * registry entry, a non-list `overlays`, an absent winner id, UTF-16 lengths of the reference digests).
 * Exact reasons and exact policies; a reference refusal ending in "(fail closed)" (the reference threw on malformed input) only
 * requires a refusal; a forbid certificate whose table is not well typed only requires `false`.
 */
@Suppress("UNCHECKED_CAST")
class Kill05PolPolicyAuthoringTest {
    companion object {
        const val FILE = "k05-policyauthoring.json.gz"
        // raw lexemes (no normalize): the reference's JSON already spells numbers as String(n) does ('1e+21' in a reason)
        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn, normalize = false).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
        fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun strs(o: Any?): List<String> = (o as? List<*>)?.map { it as String } ?: emptyList()
        fun report(fn: String, bad: List<String>, n: Int) =
            assertTrue("$fn: ${bad.size}/$n mismatches:\n" + bad.take(60).joinToString("\n"), bad.isEmpty())
        fun j(s: String): Any? = Json.parseLenient(s)

        /** A map whose every read throws (the handlers' only way in: the JSON trees the verifier reads never throw). */
        val boom: Map<String, Any?> = object : java.util.AbstractMap<String, Any?>() {
            override val entries: MutableSet<MutableMap.MutableEntry<String, Any?>> get() = throw IllegalStateException("boom")
        }
    }

    private fun reasons(fn: String, f: (List<Any?>) -> String?) {
        val bad = ArrayList<String>()
        val cs = of(fn)
        for (c in cs) {
            val out = c["out"]
            val want = if (out is Map<*, *>) out["reason"] as String? else out as String?
            val got = try { f(args(c)) } catch (e: RuntimeException) { "threw $e" }
            if (want != null && want.endsWith("(fail closed)")) {
                if (got == null || got.startsWith("threw ")) bad.add("${c["name"]}: reference refused <$want>, got <$got>")
                continue
            }
            if (want != got) bad.add("${c["name"]}: want <$want> got <$got>")
        }
        report(fn, bad, cs.size)
    }

    @Test fun templateDef() = reasons("templateDef") { PolicyAuthoring.templateDefError(it[0]) }
    @Test fun tighten() = reasons("tighten") { PolicyAuthoring.tightenOverlayError(it[0]) }
    @Test fun templateRef() = reasons("templateRef") { PolicyAuthoring.templateRefError(it[0]) }
    @Test fun verifyTemplate() = reasons("verifyTemplate") { PolicyAuthoring.verifyTemplate(it[0], strs(it[1])) }
    @Test fun verifyTighten() = reasons("verifyTighten") { PolicyAuthoring.verifyTighten(it[0], strs(it[1])) }

    private fun results(fn: String, overlays: Boolean, f: (List<Any?>) -> PolicyAuthoring.Result) {
        val bad = ArrayList<String>()
        val cs = of(fn)
        for (c in cs) {
            val out = c["out"]
            val got = try {
                val r = f(args(c))
                var s = if (r.policy == null) "refused ${r.reason}"
                else (if (r.reason == null) "" else "reason with policy ") + Json.canonicalize(r.policy) + (if (overlays) " overlays ${r.overlays}" else "")
                if ((r.policy == null || !overlays) && r.overlays != 0) s += " overlays ${r.overlays}" // only resolve applies overlays
                s
            } catch (e: RuntimeException) { "threw $e" }
            val want: String
            if (IntentJs.get(out, "ok") == true) {
                want = Json.canonicalize(IntentJs.get(out, "policy")) + (if (overlays) " overlays ${Json.canonicalize(IntentJs.get(out, "overlays"))}" else "")
            } else {
                val reason = IntentJs.get(out, "reason") as String
                if (reason.endsWith("(fail closed)")) {
                    if (!got.startsWith("refused ") || got == "refused null") bad.add("${c["name"]}: reference refused <$reason>, got <$got>")
                    continue
                }
                want = "refused $reason"
            }
            if (want != got) bad.add("${c["name"]}: want <$want> got <$got>")
        }
        report(fn, bad, cs.size)
    }

    @Test fun instantiate() = results("instantiate", false) { PolicyAuthoring.instantiateTemplate(it[0], it[1]) }
    @Test fun resolve() = results("resolve", true) { PolicyAuthoring.resolveLink(it[0], it[1]) }

    @Test
    fun forbidCertificate() {
        val bad = ArrayList<String>()
        val cs = of("forbid")
        var typedTrue = 0
        var typedFalse = 0
        for (c in cs) {
            val out = c["out"]
            val ok = IntentJs.get(out, "ok") == true
            val typed = IntentJs.get(out, "typed") == true
            val got = try {
                PolicyAuthoring.forbidCertificateConsistent(args(c)[0], strs(args(c)[1]))
            } catch (e: RuntimeException) { bad.add("${c["name"]}: threw $e"); continue }
            val want = typed && ok // an ill-typed table is refused even where the reference's loose compare passes
            if (typed && ok) typedTrue++
            if (typed && !ok) typedFalse++
            if (got != want) bad.add("${c["name"]}: want $want got $got" + if (typed) "" else " (ill-typed)")
        }
        assertTrue("certificate corpus too thin: $typedTrue / $typedFalse", typedTrue > 1000 && typedFalse > 1000)
        report("forbid", bad, cs.size)
    }

    // ---- hand cases -----------------------------------------------------------------------------

    private fun cert(rows: String, decision: String, winner: String, shadowed: String) =
        j("{\"v\":1,\"kind\":\"forbid-wins\",\"clauses\":$rows,\"decision\":\"$decision\",\"winner\":$winner,\"shadowed\":$shadowed}")

    private fun row(id: String, kind: String, value: String, signer: String? = null) =
        "{\"id\":\"$id\",\"kind\":\"$kind\",\"value\":\"$value\"" + (if (signer == null) "" else ",\"signer\":$signer") + "}"

    @Test
    fun forbidWinnerAmongSignersAndShapes() {
        val org = listOf("org", "user")
        // the more authoritative signer wins over id order; an unsigned or unlisted signer ranks after every listed one
        val twoSigners = "[${row("a", "forbid", "true", "\"user\"")},${row("b", "forbid", "true", "\"org\"")}]"
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(cert(twoSigners, "deny", "{\"kind\":\"forbid\",\"id\":\"b\"}", "[\"a\"]"), org))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert(twoSigners, "deny", "{\"kind\":\"forbid\",\"id\":\"a\"}", "[\"b\"]"), org))
        val unsigned = "[${row("a", "forbid", "true")},${row("b", "forbid", "unknown", "\"org\"")}]"
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(cert(unsigned, "deny", "{\"kind\":\"forbid\",\"id\":\"b\"}", "[\"a\"]"), listOf("org")))
        val stranger = "[${row("a", "forbid", "true", "\"stranger\"")},${row("b", "forbid", "true", "\"org\"")}]"
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(cert(stranger, "deny", "{\"kind\":\"forbid\",\"id\":\"b\"}", "[\"a\"]"), listOf("org")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert(stranger, "deny", "{\"kind\":\"forbid\",\"id\":\"a\"}", "[\"b\"]"), listOf("org")))
        // a non-string signer is no signer (ranks last), never an error
        val numSigner = "[${row("a", "forbid", "true", "7")},${row("b", "forbid", "true", "\"org\"")}]"
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(cert(numSigner, "deny", "{\"kind\":\"forbid\",\"id\":\"b\"}", "[\"a\"]"), listOf("org")))
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(cert("[${row("a", "forbid", "true", "7")}]", "deny", "{\"kind\":\"forbid\",\"id\":\"a\"}", "[]")))
        // a default deny names the winner id as an explicit null: an absent id is not null
        val none = "[${row("a", "permit", "false")}]"
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(cert(none, "deny", "{\"kind\":\"none\",\"id\":null}", "[]")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert(none, "deny", "{\"kind\":\"none\"}", "[]")))
        // ill-typed tables / members
        val good = "[${row("a", "permit", "true")}]"
        val allow = "{\"kind\":\"permit\",\"id\":\"a\"}"
        assertTrue(PolicyAuthoring.forbidCertificateConsistent(cert(good, "allow", allow, "[]")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert("\"x\"", "allow", allow, "[]")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert(good, "allow", "\"x\"", "[]")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert(good, "allow", allow, "\"x\"")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert("[{\"kind\":\"permit\",\"value\":\"true\"}]", "deny", "{\"kind\":\"none\",\"id\":null}", "[]")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert("[{\"id\":5,\"kind\":\"permit\",\"value\":\"true\"}]", "allow", allow, "[]")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert("[{\"id\":\"a\",\"kind\":5,\"value\":\"true\"}]", "allow", allow, "[]")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert("[{\"id\":\"a\",\"kind\":\"permit\",\"value\":5}]", "allow", allow, "[]")))
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(cert("[5]", "allow", allow, "[]")))
        // a certificate whose reads throw is inconsistent (the handler), never an exception
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(boom))
    }

    private fun defWithSlotName(name: String) = j(
        "{\"v\":1,\"kind\":\"pca-policy-template\",\"id\":\"t\",\"version\":\"1\",\"slots\":{\"a\":{\"type\":\"string\"}}," +
            "\"body\":{\"predicates\":[{\"verb\":{\"\$slot\":$name}}]}}",
    )

    @Test
    fun undeclaredSlotNameIsJavaScriptString() {
        val cases = listOf(
            "5" to "5", "1.5" to "1.5", "1e+21" to "1e+21", "-0" to "0", "true" to "true", "false" to "false", "null" to "null", "\"zz\"" to "zz",
            "{}" to "[object Object]", "{\"a\":1}" to "[object Object]", "[]" to "", "[1,null,\"a\",{},[2,3]]" to "1,,a,[object Object],2,3",
        )
        for ((json, text) in cases) assertEquals(json, "placeholder names undeclared slot '$text'", PolicyAuthoring.templateDefError(defWithSlotName(json)))
    }

    @Test
    fun handlersAnswerTheirFailClosedReason() {
        assertEquals("template verification error (fail closed)", PolicyAuthoring.verifyTemplate(mapOf("def" to boom), emptyList()))
        assertEquals("overlay verification error (fail closed)", PolicyAuthoring.verifyTighten(mapOf("overlay" to boom), emptyList()))
        val inst = PolicyAuthoring.instantiateTemplate(boom, emptyMap<String, Any?>())
        assertNull(inst.policy)
        assertEquals(0, inst.overlays)
        assertEquals("instantiation error (fail closed)", inst.reason)
        val res = PolicyAuthoring.resolveLink(boom, emptyMap<String, Any?>())
        assertNull(res.policy)
        assertEquals(0, res.overlays)
        assertEquals("link resolution error (fail closed)", res.reason)
    }

    @Test
    fun referenceDigestLengthsCountUtf16Units() {
        fun ref(vd: String, bound: String? = null): Map<String, Any?> {
            val r = linkedMapOf<String, Any?>("template_id" to "t", "version_digest" to vd)
            if (bound == null) { r["slots"] = emptyMap<String, Any?>() } else { r["bind_params_digest"] = bound }
            return r
        }
        assertNull(PolicyAuthoring.templateRefError(ref("a".repeat(128))))
        assertEquals("template_ref.version_digest invalid", PolicyAuthoring.templateRefError(ref("a".repeat(129))))
        assertNull(PolicyAuthoring.templateRefError(ref("é".repeat(128)))) // 256 UTF-8 bytes, 128 code units
        assertEquals("template_ref.version_digest invalid", PolicyAuthoring.templateRefError(ref("")))
        assertNull(PolicyAuthoring.templateRefError(ref("d", "b".repeat(128))))
        assertNull(PolicyAuthoring.templateRefError(ref("d", "é".repeat(128))))
        assertEquals("template_ref.bind_params_digest invalid", PolicyAuthoring.templateRefError(ref("d", "b".repeat(129))))
        assertEquals("template_ref.bind_params_digest invalid", PolicyAuthoring.templateRefError(ref("d", "")))
    }

    @Test
    fun falsyRegistryEntryIsAbsent() {
        val ref = linkedMapOf<String, Any?>("template_id" to "t", "version_digest" to "d", "slots" to emptyMap<String, Any?>())
        for (t in listOf(null, false, "", Json.Num("0"), 0L)) {
            val r = PolicyAuthoring.resolveLink(ref, mapOf("templates" to mapOf("d" to t)))
            assertEquals("$t", "template version is not in the registry", r.reason)
            assertEquals(0, r.overlays)
        }
        // a truthy non-object entry reaches template verification
        for (t in listOf(true, "x", Json.Num("1"), emptyList<Any?>())) {
            assertEquals("$t", "template must be an object", PolicyAuthoring.resolveLink(ref, mapOf("templates" to mapOf("d" to t))).reason)
        }
    }

    @Test
    fun overlaysMemberMustBeAListOrAbsent() {
        val c = of("resolve").first { IntentJs.get(it["out"], "ok") == true && Json.canonicalize(IntentJs.get(it["out"], "overlays")) == "0" }
        val ref = args(c)[0]
        val want = Json.canonicalize(IntentJs.get(c["out"], "policy"))
        fun withOverlays(v: Any?) = LinkedHashMap(args(c)[1] as Map<String, Any?>).also { it["overlays"] = v }
        // absent, null and a string (the reference iterates its characters, none an overlay) apply nothing
        for (v in listOf(null, "abc", emptyList<Any?>())) {
            val r = PolicyAuthoring.resolveLink(ref, withOverlays(v))
            assertNotNull("$v: ${r.reason}", r.policy)
            assertEquals("$v", want, Json.canonicalize(r.policy))
            assertEquals(0, r.overlays)
        }
        // any other non-list is a refusal, never a silent skip
        for (v in listOf(Json.Num("5"), true, false, emptyMap<String, Any?>())) {
            val r = PolicyAuthoring.resolveLink(ref, withOverlays(v))
            assertNull("$v", r.policy)
            assertEquals("$v", "link resolution error (fail closed)", r.reason)
            assertEquals(0, r.overlays)
        }
    }

    // ---- signed fixtures (own key) ----------------------------------------------------------------

    private val kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val pub = Pca.b64(kp.public.encoded.copyOfRange(12, 44)) // X.509 SubjectPublicKeyInfo: 12-byte prefix + raw key

    private fun sign(domain: String, digest: String): String {
        val sg = java.security.Signature.getInstance("Ed25519")
        sg.initSign(kp.private)
        sg.update(Pca.concat(IntentJs.utf8(domain), java.security.MessageDigest.getInstance("SHA-256").digest(IntentJs.utf8(digest))))
        return Pca.b64(sg.sign())
    }

    /** JSON with ' for " (no apostrophes in these fixtures). */
    private fun q(s: String): Any? = j(s.replace('\'', '"'))
    private fun mm(o: Any?) = o as MutableMap<String, Any?>

    private val defText =
        "{'v':1,'kind':'pca-policy-template','id':'tpl','version':'1'," +
            "'slots':{'acct':{'type':'string'},'n':{'type':'integer','min':1,'max':9},'verbs':{'type':'set','values':['read','list']}}," +
            "'body':{'predicates':[{'verb':{'\$slot':'verbs'},'resource':{'\$slot':'acct','pre':'/a/'},'where':[{'field':'n','op':'lte','value':{'\$slot':'n'}}]}," +
            "{'verb':'read','resource':'/r'}]}}"
    private fun def(): MutableMap<String, Any?> = mm(q(defText))
    private val fillText = "{'acct':'x','n':3,'verbs':['read']}"
    private val p1 = "{'verb':['read'],'resource':'/a/x','where':[{'field':'n','op':'lte','value':3}]"

    private fun entry(d: Any?) = linkedMapOf<String, Any?>("def" to d, "signer" to pub, "sig" to sign("atlas-pca/policy-template/v1\u0000", PolicyAuthoring.templateDigest(d)))
    private fun overlay(digest: String, extra: String, tid: String = "tpl"): MutableMap<String, Any?> =
        mm(q("{'v':1,'kind':'pca-template-tighten','template_id':'$tid','version_digest':'$digest'$extra}"))
    private fun signedOverlay(o: Any?) = linkedMapOf<String, Any?>("overlay" to o, "signer" to pub, "sig" to sign("atlas-pca/template-tighten/v1\u0000", Pca.hashCanonical(o)))
    private fun ref(digest: String) = linkedMapOf<String, Any?>("template_id" to "tpl", "version_digest" to digest, "slots" to q(fillText))
    private fun reg(d: Any?, vararg overlays: Any?): MutableMap<String, Any?> {
        val r = linkedMapOf<String, Any?>("templates" to mapOf(PolicyAuthoring.templateDigest(d) to entry(d)), "trusted" to listOf(pub))
        if (overlays.isNotEmpty()) r["overlays"] = overlays.toList()
        return r
    }

    private fun okPolicy(r: PolicyAuthoring.Result, want: String, overlays: Int) {
        assertNotNull(r.reason, r.policy)
        assertNull(r.reason)
        assertEquals(Json.canonicalize(q(want)), Json.canonicalize(r.policy))
        assertEquals(overlays, r.overlays)
    }

    private fun refused(r: PolicyAuthoring.Result, reason: String) {
        assertNull(reason, r.policy)
        assertEquals(reason, r.reason)
        assertEquals(0, r.overlays)
    }

    @Test
    fun resolveAppliesOnlyMatchingVerifiedOverlays() {
        val d = def()
        val dg = PolicyAuthoring.templateDigest(d)
        val caveatsOnly = signedOverlay(overlay(dg, ",'add_caveats':[{'type':'rate','max':5}]"))
        val whereOnly = signedOverlay(overlay(dg, ",'add_where':[{'field':'m','op':'eq','value':'z'}]"))
        okPolicy(PolicyAuthoring.resolveLink(ref(dg), reg(d)), "{'predicates':[$p1},{'verb':'read','resource':'/r'}],'caveats':[]}", 0)
        okPolicy(PolicyAuthoring.resolveLink(ref(dg), reg(d, caveatsOnly)),
            "{'predicates':[$p1},{'verb':'read','resource':'/r','where':[]}],'caveats':[{'type':'rate','max':5}]}", 1)
        val w2 = "{'field':'m','op':'eq','value':'z'}"
        okPolicy(PolicyAuthoring.resolveLink(ref(dg), reg(d, whereOnly)),
            "{'predicates':[{'verb':['read'],'resource':'/a/x','where':[{'field':'n','op':'lte','value':3},$w2]},{'verb':'read','resource':'/r','where':[$w2]}],'caveats':[]}", 1)
        okPolicy(PolicyAuthoring.resolveLink(ref(dg), reg(d, caveatsOnly, whereOnly)),
            "{'predicates':[{'verb':['read'],'resource':'/a/x','where':[{'field':'n','op':'lte','value':3},$w2]},{'verb':'read','resource':'/r','where':[$w2]}],'caveats':[{'type':'rate','max':5}]}", 2)
        // another template's overlay under the same version digest, and entries that are no overlay, are skipped unverified
        val other = linkedMapOf<String, Any?>("overlay" to overlay(dg, "", "other"), "signer" to pub, "sig" to "x")
        val otherDigest = linkedMapOf<String, Any?>("overlay" to overlay("nope", ""), "signer" to pub, "sig" to "x")
        okPolicy(PolicyAuthoring.resolveLink(ref(dg), reg(d, other, otherDigest, Json.Num("5"), mapOf("overlay" to "x"), emptyMap<String, Any?>(), null)),
            "{'predicates':[$p1},{'verb':'read','resource':'/r'}],'caveats':[]}", 0)
        // a matching overlay that fails verification refuses
        refused(PolicyAuthoring.resolveLink(ref(dg), reg(d, linkedMapOf<String, Any?>("overlay" to overlay(dg, ""), "signer" to pub, "sig" to "x"))), "bad overlay signature")
    }

    @Test
    fun overlayNeverReplacesANonListWhere() {
        val d = def()
        mm(ll(mm(d["body"])["predicates"])[1])["where"] = "x"
        val dg = PolicyAuthoring.templateDigest(d)
        // no overlay: the template's own (malformed) where is kept as written
        okPolicy(PolicyAuthoring.resolveLink(ref(dg), reg(d)), "{'predicates':[$p1},{'verb':'read','resource':'/r','where':'x'}],'caveats':[]}", 0)
        refused(PolicyAuthoring.resolveLink(ref(dg), reg(d, signedOverlay(overlay(dg, ",'add_where':[{'field':'m','op':'eq','value':'z'}]")))),
            "template predicate where is not a list (fail closed)")
    }

    private fun ll(o: Any?) = o as MutableList<Any?>

    @Test
    fun registryShapes() {
        val d = def()
        val dg = PolicyAuthoring.templateDigest(d)
        for (bad in listOf<Any?>(null, emptyMap<String, Any?>(), mapOf("templates" to Json.Num("5")), mapOf("templates" to "x"), mapOf("templates" to emptyMap<String, Any?>())))
            refused(PolicyAuthoring.resolveLink(ref(dg), bad), "template version is not in the registry")
        // a non-list (or absent) trusted list trusts nobody
        for (t in listOf<Any?>("x", Json.Num("5"), null)) {
            val r = reg(d)
            if (t == null) { r.remove("trusted") } else { r["trusted"] = t }
            refused(PolicyAuthoring.resolveLink(ref(dg), r), "template signer is not trusted")
        }
        val r2 = reg(d)
        r2["trusted"] = listOf(Json.Num("1"), pub)
        okPolicy(PolicyAuthoring.resolveLink(ref(dg), r2), "{'predicates':[$p1},{'verb':'read','resource':'/r'}],'caveats':[]}", 0)
        // the digest must name the entry and the template id must match the reference
        val wrongId = ref(dg).also { it["template_id"] = "other" }
        refused(PolicyAuthoring.resolveLink(wrongId, reg(d)), "template id does not match the reference")
        val moved = linkedMapOf<String, Any?>("templates" to mapOf("elsewhere" to entry(d)), "trusted" to listOf(pub))
        refused(PolicyAuthoring.resolveLink(linkedMapOf<String, Any?>("template_id" to "tpl", "version_digest" to "elsewhere", "slots" to q(fillText)), moved),
            "registry entry does not match its digest")
    }

    @Test
    fun boundParameterObject() {
        val d = def()
        val dg = PolicyAuthoring.templateDigest(d)
        val params = q(fillText)
        val bd = Pca.hashCanonical(params)
        val bref = linkedMapOf<String, Any?>("template_id" to "tpl", "version_digest" to dg, "bind_params_digest" to bd)
        val r = reg(d)
        r["params"] = mapOf(bd to params)
        okPolicy(PolicyAuthoring.resolveLink(bref, r), "{'predicates':[$p1},{'verb':'read','resource':'/r'}],'caveats':[]}", 0)
        for (ps in listOf<Any?>(null, Json.Num("5"), "x", emptyMap<String, Any?>(), mapOf(bd to Json.Num("5")), mapOf(bd to null))) {
            val rr = reg(d)
            if (ps != null) rr["params"] = ps
            refused(PolicyAuthoring.resolveLink(bref, rr), "parameter object is not available")
        }
        val rr = reg(d)
        rr["params"] = mapOf(bd to q("{'acct':'y','n':3,'verbs':['read']}"))
        refused(PolicyAuthoring.resolveLink(bref, rr), "parameter object does not match bind_params_digest")
    }

    @Test
    fun signerChecks() {
        val d = def()
        val dg = PolicyAuthoring.templateDigest(d)
        val e = entry(d)
        assertNull(PolicyAuthoring.verifyTemplate(e, listOf(pub)))
        assertEquals("template signer is not trusted", PolicyAuthoring.verifyTemplate(e, emptyList()))
        assertEquals("template signer is not trusted", PolicyAuthoring.verifyTemplate(LinkedHashMap(e).also { it["signer"] = Json.Num("5") }, listOf(pub)))
        assertEquals("bad template signature", PolicyAuthoring.verifyTemplate(LinkedHashMap(e).also { it["sig"] = "x" }, listOf(pub)))
        assertEquals("template must be an object", PolicyAuthoring.verifyTemplate(LinkedHashMap(e).also { it["def"] = "x" }, listOf(pub)))
        val o = signedOverlay(overlay(dg, ",'add_where':[]"))
        assertNull(PolicyAuthoring.verifyTighten(o, listOf(pub)))
        assertEquals("overlay signer is not trusted", PolicyAuthoring.verifyTighten(o, emptyList()))
        assertEquals("overlay signer is not trusted", PolicyAuthoring.verifyTighten(LinkedHashMap(o).also { it["signer"] = Json.Num("5") }, listOf(pub)))
        assertEquals("bad overlay signature", PolicyAuthoring.verifyTighten(LinkedHashMap(o).also { it["sig"] = "x" }, listOf(pub)))
        assertEquals("overlay must be an object", PolicyAuthoring.verifyTighten(LinkedHashMap(o).also { it["overlay"] = "x" }, listOf(pub)))
    }

    // ---- shapes -----------------------------------------------------------------------------------

    private fun defErr(f: (MutableMap<String, Any?>) -> Unit): String? = PolicyAuthoring.templateDefError(def().also(f))
    private fun slots(d: MutableMap<String, Any?>) = mm(d["slots"])
    private fun body(d: MutableMap<String, Any?>) = mm(d["body"])
    private fun strList(n: Int): ArrayList<Any?> = ArrayList<Any?>((0 until n).map { "s$it" })

    @Test
    fun templateDefinitionShapes() {
        assertNull(defErr { })
        val ver = "template version must be a string of 1..64 characters"
        assertNull(defErr { it["version"] = "v".repeat(64) })
        assertEquals(ver, defErr { it["version"] = "v".repeat(65) })
        assertEquals(ver, defErr { it["version"] = "" })
        assertEquals(ver, defErr { it["version"] = Json.Num("1") })
        assertEquals(ver, defErr { it.remove("version") })
        val idErr = "template id must match ^[a-z][a-z0-9_]{0,63}$"
        assertEquals(idErr, defErr { it["id"] = Json.Num("5") })
        assertEquals(idErr, defErr { it.remove("id") })
        assertEquals("slots must be an object", defErr { it["slots"] = Json.Num("5") })
        assertEquals("slots must be an object", defErr { it.remove("slots") })
        assertEquals("slot 'acct' must be an object", defErr { slots(it)["acct"] = Json.Num("5") })
        assertEquals("slot 'acct' must be an object", defErr { slots(it)["acct"] = null })
        // closed value lists: up to 64 strings, empty allowed, on any slot type that carries one
        val vErr = "slot 'acct'.values must be a list of strings"
        assertNull(defErr { mm(slots(it)["acct"])["values"] = ArrayList<Any?>() })
        assertNull(defErr { mm(slots(it)["acct"])["values"] = strList(64) })
        assertEquals(vErr, defErr { mm(slots(it)["acct"])["values"] = strList(65) })
        assertEquals(vErr, defErr { mm(slots(it)["acct"])["values"] = Json.Num("5") })
        assertEquals(vErr, defErr { mm(slots(it)["acct"])["values"] = null })
        assertEquals(vErr, defErr { mm(slots(it)["acct"])["values"] = arrayListOf<Any?>(Json.Num("5")) })
        assertEquals(vErr, defErr { mm(slots(it)["acct"])["values"] = arrayListOf<Any?>("a", Json.Num("5")) })
        // 32 slots at most (each must be used)
        fun manySlots(n: Int): Map<String, Any?> {
            val d = def()
            val sl = LinkedHashMap<String, Any?>()
            val where = ArrayList<Any?>()
            for (i in 0 until n) {
                sl["s$i"] = q("{'type':'string'}")
                where.add(q("{'field':'f','op':'eq','value':{'\$slot':'s$i'}}"))
            }
            d["slots"] = sl
            d["body"] = mapOf("predicates" to listOf(mapOf("verb" to "v", "resource" to "r", "where" to where)))
            return d
        }
        assertNull(PolicyAuthoring.templateDefError(manySlots(32)))
        assertEquals("more than 32 slots", PolicyAuthoring.templateDefError(manySlots(33)))
        // body
        val pErr = "body.predicates must be an array"
        assertEquals(pErr, defErr { it["body"] = Json.Num("5") })
        assertEquals(pErr, defErr { it.remove("body") })
        assertEquals(pErr, defErr { body(it).remove("predicates") })
        // predicates not a list while every slot is still used (in caveats)
        assertEquals(pErr, defErr {
            body(it)["predicates"] = Json.Num("5")
            body(it)["caveats"] = q("[{'type':{'\$slot':'acct'}},{'type':{'\$slot':'n'}},{'type':{'\$slot':'verbs'}}]")
        })
        assertEquals("body.caveats must be an array", defErr { body(it)["caveats"] = Json.Num("5") })
        assertEquals("body.caveats must be an array", defErr { body(it)["caveats"] = null })
        assertNull(defErr { body(it)["caveats"] = ArrayList<Any?>() })
        // placeholder affixes must be strings
        for (k in listOf("pre", "post")) {
            for (bad in listOf<Any?>(Json.Num("5"), null, true)) {
                assertEquals("placeholder $k must be a string", defErr { mm(mm(ll(body(it)["predicates"])[0])["resource"])[k] = bad })
            }
        }
        assertNull(defErr { mm(mm(ll(body(it)["predicates"])[0])["resource"])["post"] = "/z" })
    }

    @Test
    fun overlayShapes() {
        fun ov(extra: String) = PolicyAuthoring.tightenOverlayError(overlay("d", extra))
        assertNull(ov(""))
        val w = "overlay add_where must be a list of conditions"
        assertNull(ov(",'add_where':[]"))
        assertNull(ov(",'add_where':[{}]"))
        assertNull(ov(",'add_where':[{},{'a':1}]"))
        for (bad in listOf("5", "null", "{}", "'x'", "[5]", "[{},5]", "[{},null]", "[[]]")) assertEquals(bad, w, ov(",'add_where':$bad"))
        val c = "overlay add_caveats must be a list of caveats"
        assertNull(ov(",'add_caveats':[]"))
        assertNull(ov(",'add_caveats':[{'type':'a'},{'type':'b','x':1}]"))
        for (bad in listOf("5", "null", "{}", "[5]", "[{}]", "[{'type':5}]", "[{'type':null}]", "[{'type':'a'},5]", "[{'type':'a'},{}]")) assertEquals(bad, c, ov(",'add_caveats':$bad"))
        val vd = "overlay version_digest invalid"
        for (bad in listOf<Any?>("", Json.Num("5"), null)) assertEquals("$bad", vd, PolicyAuthoring.tightenOverlayError(overlay("d", "").also { it["version_digest"] = bad }))
        assertEquals(vd, PolicyAuthoring.tightenOverlayError(overlay("d", "").also { it.remove("version_digest") }))
        assertEquals("overlay template_id invalid", PolicyAuthoring.tightenOverlayError(overlay("d", "").also { it["template_id"] = Json.Num("5") }))
        assertEquals("overlay has unknown member 'x' (an overlay can only add where conditions and caveats)", ov(",'x':1"))
        assertEquals("overlay must be an object", PolicyAuthoring.tightenOverlayError(null))
        assertEquals("overlay must be an object", PolicyAuthoring.tightenOverlayError("x"))
    }

    private fun inst(d: Any?, fill: String) = PolicyAuthoring.instantiateTemplate(d, q(fill))

    @Test
    fun fillAndSplice() {
        val all = "{'predicates':[$p1},{'verb':'read','resource':'/r'}],'caveats':[]}"
        okPolicy(inst(def(), fillText), all, 0)
        refused(PolicyAuthoring.instantiateTemplate(def(), "x"), "slots must be an object")
        refused(PolicyAuthoring.instantiateTemplate(def(), null), "slots must be an object")
        refused(PolicyAuthoring.instantiateTemplate("x", q(fillText)), "template must be an object")
        // string slot length 1..256; set slot non-empty, at most 64, strings only
        val sErr = "slot 'acct' must be a string of 1..256 characters"
        refused(inst(def(), "{'acct':'','n':3,'verbs':['read']}"), sErr)
        refused(inst(def(), "{'acct':'${"a".repeat(257)}','n':3,'verbs':['read']}"), sErr)
        okPolicy(inst(def(), "{'acct':'${"a".repeat(256)}','n':3,'verbs':['read']}"),
            "{'predicates':[{'verb':['read'],'resource':'/a/${"a".repeat(256)}','where':[{'field':'n','op':'lte','value':3}]},{'verb':'read','resource':'/r'}],'caveats':[]}", 0)
        val setErr = "slot 'verbs' must be a non-empty list of strings"
        for (bad in listOf("[]", "'read'", "[5]", "['read',5]", "['read',null]")) refused(inst(def(), "{'acct':'x','n':3,'verbs':$bad}"), setErr)
        refused(inst(def(), "{'acct':'x','n':3,'verbs':['read','read']}"), "slot 'verbs' has duplicate members")
        refused(inst(def(), "{'acct':'x','n':3,'verbs':['read','write']}"), "slot 'verbs' has a member outside its closed set")
        val big = def()
        mm(slots(big)["verbs"])["values"] = strList(64)
        refused(PolicyAuthoring.instantiateTemplate(big, mapOf("acct" to "x", "n" to Json.Num("3"), "verbs" to strList(65))), setErr)
        assertNotNull(PolicyAuthoring.instantiateTemplate(big, mapOf("acct" to "x", "n" to Json.Num("3"), "verbs" to strList(64))).policy)
        // a closed set may itself hold a wildcard or a regex: still never spliced into a verb
        val wild = def()
        mm(slots(wild)["verbs"])["values"] = arrayListOf<Any?>("read", "mail.*", "re:x")
        refused(inst(wild, "{'acct':'x','n':3,'verbs':['read','mail.*']}"), "slot 'verbs' would inject a wildcard or regex matcher into a verb or resource")
        refused(inst(wild, "{'acct':'x','n':3,'verbs':['re:x']}"), "slot 'verbs' would inject a wildcard or regex matcher into a verb or resource")
        // a regex prefix without a wildcard, straight into a resource (no affixes)
        val bare = def()
        mm(ll(body(bare)["predicates"])[0])["resource"] = q("{'\$slot':'acct'}")
        refused(inst(bare, "{'acct':'re:x','n':3,'verbs':['read']}"), "slot 'acct' would inject a wildcard or regex matcher into a verb or resource")
        okPolicy(inst(bare, "{'acct':'x:re','n':3,'verbs':['read']}"),
            "{'predicates':[{'verb':['read'],'resource':'x:re','where':[{'field':'n','op':'lte','value':3}]},{'verb':'read','resource':'/r'}],'caveats':[]}", 0)
        // a non-string slot in a resource is checked as no matcher (the evaluator refuses it later)
        val numRes = def()
        mm(ll(body(numRes)["predicates"])[1])["resource"] = q("{'\$slot':'n'}")
        okPolicy(inst(numRes, fillText), "{'predicates':[$p1},{'verb':'read','resource':3}],'caveats':[]}", 0)
        // splicing (outside verb / resource): one affix is enough; a wildcard, NUL or non-string value refuses
        fun spliced(placeholder: String, acctInResource: Boolean = false): MutableMap<String, Any?> {
            val d = def()
            val p0 = mm(ll(body(d)["predicates"])[0])
            mm(ll(p0["where"])[0])["value"] = q(placeholder)
            // the resource no longer reads acct: a resource slot is matcher-checked first (policy-link.ts matcherSafe), which would mask the splice checks
            if (!acctInResource) p0["resource"] = "/a/x"
            return d
        }
        fun where(v: String) = "{'predicates':[{'verb':['read'],'resource':'/a/x','where':[{'field':'n','op':'lte','value':$v}]},{'verb':'read','resource':'/r'}],'caveats':[]}"
        val acctPre = spliced("{'\$slot':'acct','pre':'p/'}")
        // acct is then used only in the spliced where value; the integer slot n is no longer used
        fun noN(d: MutableMap<String, Any?>) = d.also { slots(it).remove("n") }
        okPolicy(inst(noN(acctPre), "{'acct':'x','verbs':['read']}"), where("'p/x'"), 0)
        okPolicy(inst(noN(spliced("{'\$slot':'acct','post':'/z'}")), "{'acct':'x','verbs':['read']}"), where("'x/z'"), 0)
        okPolicy(inst(noN(spliced("{'\$slot':'acct','pre':'','post':''}")), "{'acct':'x','verbs':['read']}"), where("'x'"), 0)
        val cant = "slot 'acct' cannot be spliced into a string (wildcard or non-string)"
        // in an affixed resource the matcher check runs before the splice check (policy-link.ts fill order)
        refused(inst(def(), "{'acct':'a*b','n':3,'verbs':['read']}"), "slot 'acct' would inject a wildcard or regex matcher into a verb or resource")
        refused(inst(noN(spliced("{'\$slot':'acct','post':'/z'}")), "{'acct':'a*b','verbs':['read']}"), cant)
        refused(inst(noN(spliced("{'\$slot':'acct','post':'/z'}")), "{'acct':'a\\u0000b','verbs':['read']}"), cant)
        refused(inst(spliced("{'\$slot':'n','pre':'p'}", acctInResource = true), fillText), "slot 'n' cannot be spliced into a string (wildcard or non-string)")
        // a regex matcher: only when the value itself starts the string
        refused(inst(noN(spliced("{'\$slot':'acct','post':'/z'}")), "{'acct':'re:x','verbs':['read']}"), "slot 'acct' would inject a regex matcher")
        okPolicy(inst(noN(spliced("{'\$slot':'acct','pre':'p'}")), "{'acct':'re:x','verbs':['read']}"), where("'pre:x'"), 0)
        okPolicy(inst(noN(spliced("{'\$slot':'acct','pre':'re:'}")), "{'acct':'x','verbs':['read']}"), where("'re:x'"), 0)
    }
}
