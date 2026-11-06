package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * k05 survivors in ActionSchema: the v2 schema shape (parameter role / format / tags / provenance_min, floors, confirmation,
 * effects / traits / def, traits_digest / trait_defs / pack), the v1 / v2 switches, the v2 value types and formats, and the
 * String `when` dispatches (a name whose hashCode collides with a known one is still unknown). Reasons are the reference's
 * (packages/pca/src/action-schema.ts).
 */
@Suppress("UNCHECKED_CAST")
class Kill05SchemaActionSchemaTest {
    private val b32 = KUtil.B32
    private val b64 = KUtil.B64
    private fun j(s: String): Any? = IntentJs.normalize(Json.parseLenient(s))
    private fun mm(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>
    private fun ll(o: Any?): MutableList<Any?> = o as MutableList<Any?>
    private fun arr(xs: List<String>): String = xs.joinToString(",", "[", "]") { "\"$it\"" }

    private val floors = """{"risk":0,"rev":"reversible","blast_ppm":0,"esc":0,"caveats":[],"context":[],"prules":[]}"""
    private val head = """"kind":"pca-action-schema","site":"https://s.example","aud":"s.example","version":"1","units":{"usd_cents":{"kind":"money"}}"""
    private val px = """"params":{"action.params.x":{"type":"string","semantic":"s","sensitivity":"free"}}"""
    private val sig = """"sig":{"alg":"ed25519","kid":"k1","value":"AA"}"""
    private fun docV1(): MutableMap<String, Any?> = mm(j("""{"v":1,$head,"verbs":[{"verb":"a.b","kind":"write",$px}],$sig}"""))
    private fun docV2(): MutableMap<String, Any?> =
        mm(j("""{"v":2,$head,"verbs":[{"verb":"a.b","kind":"write",$px,"effects":["create","send"],"traits":["a.b","c.d"],"def":"$b32","floors":$floors}],$sig}"""))
    private fun doc(two: Boolean) = if (two) docV2() else docV1()
    private fun verb(d: MutableMap<String, Any?>): MutableMap<String, Any?> = mm(ll(d["verbs"])[0])
    private fun shape(d: Any?): String? = ActionSchema.shapeError(d)

    private fun withDoc(two: Boolean, members: String, drop: String? = null): String? {
        val d = doc(two)
        d.putAll(mm(j(members)))
        if (drop != null) d.remove(drop)
        return shape(d)
    }

    private fun withVerb(two: Boolean, members: String, drop: String? = null): String? {
        val d = doc(two)
        verb(d).putAll(mm(j(members)))
        if (drop != null) verb(d).remove(drop)
        return shape(d)
    }

    private fun withParam(two: Boolean, members: String, path: String = "action.params.x"): String? {
        val d = doc(two)
        val ps = mm(verb(d)["params"])
        val x = mm(ps.remove("action.params.x"))
        x.putAll(mm(j(members)))
        ps[path] = x
        return shape(d)
    }

    private val p = "verb 'a.b': action.params.x: "
    private val nineTags = listOf("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql")
    private fun traitIds(n: Int): List<String> = (0 until n).map { "a.t" + it.toString().padStart(3, '0') }

    @Test fun baseDocumentsAreWellFormed() {
        assertNull(shape(docV1()))
        assertNull(shape(docV2()))
        assertNull(ActionSchema.shapeError(docV1().also { it.remove("sig") }, false))
        assertNull(ActionSchema.shapeError(docV2().also { it.remove("sig") }, false))
        assertEquals("an unsigned schema must not carry sig", ActionSchema.shapeError(docV1(), false))
        assertEquals("an unsigned schema must not carry sig", ActionSchema.shapeError(docV2(), false))
    }

    @Test fun parameterPathsPerVersion() {
        assertEquals("verb 'a.b': parameter path 'action.params.a.b' is not action.params.<name>", withParam(false, "{}", "action.params.a.b"))
        assertNull(withParam(true, "{}", "action.params.a.b"))
        assertNull(withParam(true, "{}", "action.params.a.b.c"))
        assertEquals("verb 'a.b': parameter path 'action.params.a.b.c.d' is not action.params.<name>", withParam(true, "{}", "action.params.a.b.c.d"))
        assertEquals("verb 'a.b': parameter name 'action.params.a.__proto__' is reserved (__proto__ / constructor / prototype)", withParam(true, "{}", "action.params.a.__proto__"))
        assertEquals("verb 'a.b': parameter name 'action.params.constructor' is reserved (__proto__ / constructor / prototype)", withParam(false, "{}", "action.params.constructor"))
        assertEquals("verb 'a.b': parameter name 'action.params.prototype.b' is reserved (__proto__ / constructor / prototype)", withParam(true, "{}", "action.params.prototype.b"))
        val d = docV2()
        mm(verb(d)["params"])["action.params.x.y"] = j("""{"type":"string","semantic":"s","sensitivity":"free"}""")
        assertEquals("verb 'a.b': parameter 'action.params.x' is both a value and the parent of 'action.params.x.y'", shape(d))
    }

    @Test fun v2OnlyMembersAndTypes() {
        assertEquals(p + "unknown member 'role'", withParam(false, """{"role":"r"}"""))
        assertNull(withParam(true, """{"role":"r"}"""))
        assertEquals(p + "unknown type", withParam(false, """{"type":"datetime"}"""))
        for (t in listOf("datetime", "duration", "object_ref", "string", "integer", "boolean", "date")) assertNull(t, withParam(true, """{"type":"$t"}"""))
        assertEquals(p + "unknown type", withParam(true, """{"type":"nope"}"""))
        assertEquals(p + "unknown type", withParam(true, """{"type":5}"""))
        assertEquals(p + "unknown sensitivity", withParam(true, """{"sensitivity":5}"""))
        assertNull(withParam(true, """{"type":"duration","min":0,"max":10}"""))
        assertEquals(p + "min must be a safe integer on an integer parameter", withParam(false, """{"type":"string","min":0}"""))
    }

    @Test fun values() {
        assertEquals(p + "values must be 1..256 strings", withParam(true, """{"values":["a",5]}"""))
        assertEquals(p + "values must be 1..256 strings", withParam(true, """{"values":["a",""]}"""))
        assertEquals(p + "values must be 1..256 strings", withParam(true, """{"values":[]}"""))
        assertEquals(p + "values must be distinct", withParam(true, """{"values":["a","a"]}"""))
        assertNull(withParam(true, """{"values":["a","b"]}"""))
        assertNull(withParam(false, """{"values":["a"]}"""))
    }

    @Test fun role() {
        assertEquals(p + "role must be a non-empty string", withParam(true, """{"role":""}"""))
        assertEquals(p + "role must be a non-empty string", withParam(true, """{"role":5}"""))
        assertNull(withParam(true, """{"role":"${"r".repeat(128)}"}"""))
        assertEquals(p + "role must be a non-empty string", withParam(true, """{"role":"${"r".repeat(129)}"}"""))
    }

    @Test fun format() {
        val bad = p + "format must be a known format on a string parameter"
        assertNull(withParam(true, """{"format":"email"}"""))
        assertNull(withParam(true, """{"type":"object_ref","format":"uuid"}"""))
        assertNull(withParam(true, """{"format":"id:user.account"}"""))
        assertEquals(bad, withParam(true, """{"format":"nope"}"""))
        assertEquals(bad, withParam(true, """{"format":5}"""))
        assertEquals(bad, withParam(true, """{"type":"integer","format":"email"}"""))
        assertEquals(bad, withParam(true, """{"type":"set","values":["a"],"format":"email"}"""))
        assertEquals(p + "unknown member 'format'", withParam(false, """{"format":"email"}"""))
    }

    @Test fun tags() {
        val bad = p + "tags must be distinct known tags"
        assertNull(withParam(true, """{"tags":[]}"""))
        assertNull(withParam(true, """{"tags":["pii"]}"""))
        assertNull(withParam(true, """{"tags":${arr(nineTags)}}"""))
        assertEquals(bad, withParam(true, """{"tags":${arr(nineTags + "pii")}}"""))
        assertEquals(bad, withParam(true, """{"tags":["pii","pii"]}"""))
        assertEquals(bad, withParam(true, """{"tags":["nope"]}"""))
        assertEquals(bad, withParam(true, """{"tags":["pii","nope"]}"""))
        assertEquals(bad, withParam(true, """{"tags":[5]}"""))
        assertEquals(bad, withParam(true, """{"tags":"pii"}"""))
        assertEquals(p + "unknown member 'tags'", withParam(false, """{"tags":[]}"""))
    }

    @Test fun provenanceMin() {
        for (v in listOf("first_party", "tool", "agent")) assertNull(withParam(true, """{"provenance_min":"$v"}"""))
        assertEquals(p + "unknown provenance_min", withParam(true, """{"provenance_min":"nope"}"""))
        assertEquals(p + "unknown provenance_min", withParam(true, """{"provenance_min":5}"""))
    }

    private fun fl(members: String, drop: String? = null): String? {
        val f = mm(j(floors))
        f.putAll(mm(j(members)))
        if (drop != null) f.remove(drop)
        return ActionSchema.schemaFloorsError(f)
    }

    @Test fun floorsShape() {
        assertNull(fl("{}"))
        assertEquals("floors must be an object", ActionSchema.schemaFloorsError(null))
        assertEquals("floors must be an object", ActionSchema.schemaFloorsError(ArrayList<Any?>()))
        assertEquals("floors: unknown member 'x'", fl("""{"x":1}"""))
        val rangeMsg = "floors.risk and floors.esc must be integers in 0..3"
        for (k in listOf("risk", "esc")) {
            for (ok in listOf("0", "1", "3")) assertNull("$k=$ok", fl("""{"$k":$ok}"""))
            for (bad in listOf("-1", "4", "1.5", "\"0\"", "null")) assertEquals("$k=$bad", rangeMsg, fl("""{"$k":$bad}"""))
            assertEquals(rangeMsg, fl("{}", k))
        }
        for (r in listOf("reversible", "rate_limited", "irreversible")) assertNull(fl("""{"rev":"$r"}"""))
        assertEquals("floors.rev is not a reversibility class", fl("""{"rev":"nope"}"""))
        assertEquals("floors.rev is not a reversibility class", fl("""{"rev":5}"""))
        for (ok in listOf("0", "1", "1000000")) assertNull(fl("""{"blast_ppm":$ok}"""))
        for (bad in listOf("-1", "1000001", "0.5")) assertEquals("floors.blast_ppm must be an integer in 0..1000000", fl("""{"blast_ppm":$bad}"""))
    }

    @Test fun floorsLists() {
        assertNull(fl("""{"caveats":["amount_cap","window"],"context":["approval_ref","session_taint_max:web"],"prules":["array_bounded","secret_not_logged"]}"""))
        for (name in listOf("caveats", "context", "prules")) {
            val known = "floors.$name must be an array of known entries"
            assertEquals(known, fl("""{"$name":"x"}"""))
            assertEquals(known, fl("""{"$name":[5]}"""))
            assertEquals(known, fl("""{"$name":["nope"]}"""))
            assertEquals(known, fl("{}", name))
        }
        assertEquals("floors.caveats must be an array of known entries", fl("""{"caveats":["dry_run_first"]}"""))
        assertEquals("floors.context must be an array of known entries", fl("""{"context":["amount_cap"]}"""))
        assertEquals("floors.context must be an array of known entries", fl("""{"context":["session_taint_max:"]}"""))
        assertEquals("floors.context must be an array of known entries", fl("""{"context":["session_taint_max:WEB"]}"""))
        assertEquals("floors.prules must be an array of known entries", fl("""{"prules":["window"]}"""))
        assertEquals("floors.caveats must be sorted and distinct", fl("""{"caveats":["window","amount_cap"]}"""))
        assertEquals("floors.caveats must be sorted and distinct", fl("""{"caveats":["window","window"]}"""))
        assertEquals("floors.context must be sorted and distinct", fl("""{"context":["session_taint_max:web","approval_ref"]}"""))
        assertEquals("floors.prules must be sorted and distinct", fl("""{"prules":["secret_not_logged","array_bounded"]}"""))
        // the 64-entry bound is checked before the order: 65 entries are not "known", 64 duplicates are "not sorted"
        assertEquals("floors.caveats must be an array of known entries", fl("""{"caveats":${arr(List(65) { "amount_cap" })}}"""))
        assertEquals("floors.caveats must be sorted and distinct", fl("""{"caveats":${arr(List(64) { "amount_cap" })}}"""))
        assertEquals("verb 'a.b': floors must be an object", withVerb(true, """{"floors":5}"""))
        assertEquals("verb 'a.b': floors must be an object", withVerb(true, "{}", "floors"))
        assertEquals("verb 'a.b': floors.rev is not a reversibility class", withVerb(true, """{"floors":${floors.replace("reversible", "nope")}}"""))
    }

    private val conf = """{"def_digest":"$b32","traits_digest":"$b32","facts_digest":"$b32","final_traits":["a.b","c.d"],"dismissed":[{"trait":"e.f","reason":"r"}],"reviewer_kid":"k","ts":0,"sig":"$b64"}"""

    private fun cf(members: String, drop: String? = null): String? {
        val c = mm(j(conf))
        c.putAll(mm(j(members)))
        if (drop != null) c.remove(drop)
        return ActionSchema.confirmationShapeError(c)
    }

    @Test fun confirmationShape() {
        assertNull(cf("{}"))
        assertEquals("confirmation must be an object", ActionSchema.confirmationShapeError(null))
        assertEquals("confirmation must be an object", ActionSchema.confirmationShapeError(ArrayList<Any?>()))
        assertEquals("confirmation: unknown member 'x'", cf("""{"x":1}"""))
        val dig = "confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests"
        for (k in listOf("def_digest", "traits_digest", "facts_digest")) {
            assertEquals(k, dig, cf("""{"$k":"AA"}"""))
            assertEquals(k, dig, cf("{}", k))
        }
        assertEquals("confirmation: sig must be a canonical base64url 64-byte signature", cf("""{"sig":"$b32"}"""))
        assertEquals("confirmation: sig must be a canonical base64url 64-byte signature", cf("{}", "sig"))
    }

    @Test fun confirmationFinalTraits() {
        val ids = "confirmation: final_traits must be trait ids"
        for (bad in listOf("\"x\"", "[\"A.b\"]", "[5]", "[\"ab\"]", "null")) assertEquals(bad, ids, cf("""{"final_traits":$bad}"""))
        assertNull(cf("""{"final_traits":[]}"""))
        assertNull(cf("""{"final_traits":${arr(traitIds(64))}}"""))
        assertEquals(ids, cf("""{"final_traits":${arr(traitIds(65))}}"""))
        assertEquals("confirmation: final_traits must be sorted and distinct", cf("""{"final_traits":["c.d","a.b"]}"""))
        assertEquals("confirmation: final_traits must be sorted and distinct", cf("""{"final_traits":["a.b","a.b"]}"""))
    }

    @Test fun confirmationDismissed() {
        val arrMsg = "confirmation: dismissed must be an array"
        val entry = "confirmation: dismissed entries must be {trait, reason}"
        val one = """{"trait":"e.f","reason":"r"}"""
        assertEquals(arrMsg, cf("""{"dismissed":"x"}"""))
        assertEquals(arrMsg, cf("{}", "dismissed"))
        assertNull(cf("""{"dismissed":[]}"""))
        assertNull(cf("""{"dismissed":${List(64) { one }.joinToString(",", "[", "]")}}"""))
        assertEquals(arrMsg, cf("""{"dismissed":${List(65) { one }.joinToString(",", "[", "]")}}"""))
        assertNull(cf("""{"dismissed":[{"reason":"r","trait":"e.f"}]}"""))
        assertNull(cf("""{"dismissed":[{"trait":"e.f","reason":"${"r".repeat(256)}"}]}"""))
        for (bad in listOf(
            """{"trait":"e.f"}""", """{"trait":"e.f","reason":"r","x":1}""", """{"x":1,"trait":"e.f","reason":"r"}""", """{"trait":5,"reason":"r"}""",
            """{"trait":"E.f","reason":"r"}""", """{"trait":"e.f","reason":""}""", """{"trait":"e.f","reason":"${"r".repeat(257)}"}""", "\"x\"", "{}",
        )) assertEquals(bad, entry, cf("""{"dismissed":[$bad]}"""))
    }

    @Test fun confirmationKidAndTs() {
        val kid = "confirmation: reviewer_kid must be a non-empty string"
        assertEquals(kid, cf("""{"reviewer_kid":""}"""))
        assertEquals(kid, cf("""{"reviewer_kid":5}"""))
        assertNull(cf("""{"reviewer_kid":"${"k".repeat(128)}"}"""))
        assertEquals(kid, cf("""{"reviewer_kid":"${"k".repeat(129)}"}"""))
        val ts = "confirmation: ts must be a non-negative safe integer"
        for (bad in listOf("-1", "1.5", "\"0\"", "9007199254740992")) assertEquals(bad, ts, cf("""{"ts":$bad}"""))
        assertNull(cf("""{"ts":9007199254740991}"""))
        assertEquals("verb 'a.b': confirmation must be an object", withVerb(true, """{"confirmation":5}"""))
        assertEquals("verb 'a.b': confirmation: ts must be a non-negative safe integer", withVerb(true, """{"confirmation":${conf.replace("\"ts\":0", "\"ts\":-1")}}"""))
        assertNull(withVerb(true, """{"confirmation":$conf}"""))
    }

    @Test fun verbEffectsKindTraitsDef() {
        assertEquals("verb entry: unknown member 'traits'", withVerb(false, """{"traits":[]}"""))
        val eff = "verb 'a.b': effects must be 1..12 known effects"
        assertEquals(eff, withVerb(true, "{}", "effects"))
        for (bad in listOf("[]", "[\"nope\"]", "[5]", "\"read\"", arr(List(13) { "read" }))) assertEquals(bad, eff, withVerb(true, """{"effects":$bad}"""))
        val all12 = listOf("create", "delete", "exec", "export", "pay", "privilege", "provision", "publish", "read", "send", "sign", "update")
        assertNull(withVerb(true, """{"effects":${arr(all12)}}"""))
        assertEquals("verb 'a.b': effects must be sorted and distinct", withVerb(true, """{"effects":["send","create"]}"""))
        assertEquals("verb 'a.b': effects must be sorted and distinct", withVerb(true, """{"effects":["create","create"]}"""))
        assertEquals("verb 'a.b': effects must be sorted and distinct", withVerb(true, """{"effects":${arr(List(12) { "read" })}}"""))
        val kind = "verb 'a.b': kind read must hold exactly when every effect is read"
        assertEquals(kind, withVerb(true, """{"kind":"read","effects":["create"]}"""))
        assertEquals(kind, withVerb(true, """{"kind":"read","effects":["create","read"]}"""))
        assertEquals(kind, withVerb(true, """{"kind":"write","effects":["read"]}"""))
        assertNull(withVerb(true, """{"kind":"read","effects":["read"]}"""))
        val tr = "verb 'a.b': traits must be trait ids"
        assertEquals(tr, withVerb(true, "{}", "traits"))
        for (bad in listOf("[\"A\"]", "[5]", "\"a.b\"", "[\"a.b\",\"B.c\"]", arr(traitIds(65)))) assertEquals(bad, tr, withVerb(true, """{"traits":$bad}"""))
        assertNull(withVerb(true, """{"traits":[]}"""))
        assertNull(withVerb(true, """{"traits":${arr(traitIds(64))}}"""))
        assertEquals("verb 'a.b': traits must be sorted and distinct", withVerb(true, """{"traits":["c.d","a.b"]}"""))
        assertEquals("verb 'a.b': traits must be sorted and distinct", withVerb(true, """{"traits":["a.b","a.b"]}"""))
        assertEquals("verb 'a.b': def must be a canonical base64url SHA-256 digest", withVerb(true, """{"def":"AA"}"""))
        assertEquals("verb 'a.b': def must be a canonical base64url SHA-256 digest", withVerb(true, "{}", "def"))
    }

    @Test fun harmEffectsReturnsPerVersion() {
        assertEquals("verb 'a.b': harm must be an object", withVerb(true, """{"harm":"x"}"""))
        assertEquals("verb 'a.b': returns must be an object", withVerb(true, """{"returns":"x"}"""))
        assertNull(withVerb(true, """{"harm":{},"returns":{}}"""))
        assertEquals("verb 'a.b': harm must be an object", withVerb(false, """{"harm":"x"}"""))
        assertEquals("verb 'a.b': effects must be an object", withVerb(false, """{"effects":"x"}"""))
        assertEquals("verb 'a.b': returns must be an object", withVerb(false, """{"returns":"x"}"""))
        assertNull(withVerb(false, """{"harm":{},"effects":{},"returns":{}}"""))
    }

    @Test fun documentV2Members() {
        assertEquals("traits_digest must be a canonical base64url SHA-256 digest", withDoc(true, """{"traits_digest":"AA"}"""))
        assertNull(withDoc(true, """{"traits_digest":"$b32"}"""))
        assertEquals("unknown member 'traits_digest'", withDoc(false, """{"traits_digest":"$b32"}"""))
        val td = "trait_defs must be an array of up to 64 objects"
        assertEquals(td, withDoc(true, """{"trait_defs":"x"}"""))
        assertEquals(td, withDoc(true, """{"trait_defs":[1]}"""))
        assertEquals(td, withDoc(true, """{"trait_defs":[{},1]}"""))
        assertNull(withDoc(true, """{"trait_defs":[]}"""))
        assertNull(withDoc(true, """{"trait_defs":${List(64) { "{}" }.joinToString(",", "[", "]")}}"""))
        assertEquals(td, withDoc(true, """{"trait_defs":${List(65) { "{}" }.joinToString(",", "[", "]")}}"""))
        val pk = "pack must be {ns, version, root}"
        assertNull(withDoc(true, """{"pack":{"ns":"n","root":"$b32","version":"1"}}"""))
        assertNull(withDoc(true, """{"pack":{"version":"${"v".repeat(128)}","ns":"${"n".repeat(64)}","root":"$b32"}}"""))
        for (bad in listOf(
            "\"x\"", """{"ns":"n","version":"1"}""", """{"ns":"n","root":"$b32"}""", """{"root":"$b32","version":"1"}""",
            """{"ns":"n","root":"$b32","version":"1","x":1}""", """{"ns":"","root":"$b32","version":"1"}""", """{"ns":"${"n".repeat(65)}","root":"$b32","version":"1"}""",
            """{"ns":"n","root":"$b32","version":""}""", """{"ns":"n","root":"$b32","version":"${"v".repeat(129)}"}""", """{"ns":"n","root":"AA","version":"1"}""",
            """{"ns":5,"root":"$b32","version":"1"}""",
        )) assertEquals(bad, pk, withDoc(true, """{"pack":$bad}"""))
    }

    private fun pv(d: String, x: Any?): Pair<String, String>? = ActionSchema.paramValueViolation(mm(j(d)), x)
    private fun n(s: String) = Json.Num(s)

    @Test fun v2ValueTypes() {
        val ref = """{"type":"object_ref"}"""
        assertNull(pv(ref, "id-1"))
        for (bad in listOf<Any?>("", n("5"), "a\uD800", null)) assertEquals("$bad", "bad_type" to "expected a non-empty id string", pv(ref, bad))
        assertNull(pv("""{"type":"object_ref","max_len":3}""", "abc"))
        assertEquals("out_of_domain" to "longer than the declared max_len", pv("""{"type":"object_ref","max_len":3}""", "abcd"))
        assertEquals("out_of_domain" to "not a valid uuid", pv("""{"type":"object_ref","format":"uuid"}""", "x"))
        assertNull(pv("""{"type":"object_ref","format":"uuid"}""", listOf("123e4567", "e89b", "12d3", "a456", "426614174000").joinToString("-")))
        assertEquals("out_of_domain" to "not a valid email", pv("""{"type":"string","format":"email"}""", "x"))
        assertNull(pv("""{"type":"string","format":"email"}""", "a@b.co"))
        val dt = """{"type":"datetime"}"""
        assertNull(pv(dt, "2024-02-29T23:59:59.123Z"))
        assertNull(pv(dt, "2023-12-31T00:00:00Z"))
        assertEquals("out_of_domain" to "not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z", pv(dt, "2023-02-29T00:00:00Z"))
        assertEquals("out_of_domain" to "not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z", pv(dt, "2023-01-01T24:00:00Z"))
        assertEquals("bad_type" to "expected an RFC 3339 UTC string", pv(dt, n("5")))
        val du = """{"type":"duration"}"""
        assertNull(pv(du, n("0")))
        assertNull(pv(du, n("1")))
        assertEquals("out_of_domain" to "a duration is not negative", pv(du, n("-1")))
        assertEquals("bad_type" to "expected a safe integer (milliseconds)", pv(du, n("1.5")))
        assertEquals("bad_type" to "expected a safe integer (milliseconds)", pv(du, "1"))
        assertEquals("out_of_domain" to "below min", pv("""{"type":"duration","min":5}""", n("4")))
        assertNull(pv("""{"type":"duration","min":5,"max":5}""", n("5")))
        assertEquals("out_of_domain" to "above max", pv("""{"type":"duration","max":5}""", n("6")))
    }

    /** Each pair has equal String.hashCode(): the `when` must still compare the whole name. */
    private val typeTwins = listOf(
        "string" to "tUring", "object_ref" to "pCject_ref", "datetime" to "eBtetime", "duration" to "eVration", "integer" to "jOteger",
        "boolean" to "cPolean", "date" to "eBte", "set" to "tFt", "array" to "bSray",
    )
    private val formatTwins = listOf(
        "email" to "fNail", "url" to "vSl", "uri_https" to "vSi_https", "uuid" to "vVid", "iban" to "jCan", "phone_e164" to "qIone_e164",
        "cidr" to "dJdr", "iso_country" to "jTo_country", "iso_currency" to "jTo_currency", "semver" to "tFmver", "sha256" to "tIa256",
    )

    @Test fun hashCollidingNamesAreUnknown() {
        for ((name, twin) in typeTwins) {
            assertEquals(name, name.hashCode(), twin.hashCode())
            assertEquals(twin, "bad_type" to "unknown declared type", pv("""{"type":"$twin"}""", "x"))
            assertEquals(twin, "bad_type" to "unknown declared type", pv("""{"type":"$twin"}""", n("1")))
        }
        for ((name, twin) in formatTwins) {
            assertEquals(name, name.hashCode(), twin.hashCode())
            assertNull(twin, ActionSchema.formatCheck(twin))
            assertNotNull(name, ActionSchema.formatCheck(name))
            assertEquals(p + "format must be a known format on a string parameter", withParam(true, """{"format":"$twin"}"""))
        }
    }

    private fun fmt(f: String, s: String): Boolean = ActionSchema.formatCheck(f)!!(s)

    @Test fun formats() {
        val email254 = "a".repeat(64) + "@" + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61)
        val cases = listOf(
            Triple("email", "a@b.co", true), Triple("email", "a@b", false), Triple("email", email254, true), Triple("email", email254 + "d", false),
            Triple("url", "https://x.y/p", true), Triple("url", "x", false),
            Triple("uri_https", "https://x", true), Triple("uri_https", "http://x", false),
            Triple("uuid", listOf("123e4567", "e89b", "12d3", "a456", "426614174000").joinToString("-"), true), Triple("uuid", listOf("123E4567", "E89B", "12D3", "A456", "426614174000").joinToString("-"), false),
            Triple("iban", "GB93AAAA1234567890", true), Triple("iban", "GB94AAAA1234567890", false), Triple("iban", "x", false), Triple("iban", "GB82WEST12345698765432", true),
            Triple("phone_e164", "+14155552671", true), Triple("phone_e164", "14155552671", false),
            Triple("cidr", "10.0.0.0/8", true), Triple("cidr", "255.255.255.255/32", true), Triple("cidr", "0.0.0.0/0", true), Triple("cidr", "256.0.0.0/8", false),
            Triple("cidr", "1.2.3.4/33", false), Triple("cidr", "01.2.3.4/8", false), Triple("cidr", "1.2.3.4/08", false), Triple("cidr", "1.2.3.256/8", false),
            Triple("cidr", "::1/128", true), Triple("cidr", "::1/0", true), Triple("cidr", "::1/129", false), Triple("cidr", "1:2/64", false),
            Triple("cidr", ":::/64", false), Triple("cidr", "::1/012", false), Triple("cidr", "1:2:3/64", true), Triple("cidr", "x", false),
            Triple("iso_country", "US", true), Triple("iso_country", "us", false), Triple("iso_currency", "USD", true), Triple("iso_currency", "US", false),
            Triple("semver", "1.2.3-rc.1+b", true), Triple("semver", "01.2.3", false),
            Triple("sha256", "0".repeat(64), true), Triple("sha256", "0".repeat(63), false),
            Triple("id:user", "abc", true), Triple("id:user", "", false), Triple("id:user", "a b", false),
        )
        for ((f, s, want) in cases) assertEquals("$f '$s'", want, fmt(f, s))
        assertNull(ActionSchema.formatCheck("id:"))
    }
}
