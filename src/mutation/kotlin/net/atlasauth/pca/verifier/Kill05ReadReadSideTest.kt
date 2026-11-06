package net.atlasauth.pca.verifier

import net.atlasauth.pca.verifier.IntentTestKit.jl
import net.atlasauth.pca.verifier.IntentTestKit.jm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 0.5 mutation kills for ReadSide.kt: a differential test against the TS reference (packages/pca/src/readside.ts) over the shared
 * k05 read-side oracle (test-data/k05-readside.json.gz, from tools/pca-audit/k05-oracles/readside-oracle.mts), plus Kotlin-only
 * edges the oracle cannot reach: the result getters, the fail-closed catch paths (a hostile Map), the shape of a read receipt
 * checked member by member, and every boundary of the redaction modes on grants signed at runtime.
 */
@Suppress("UNCHECKED_CAST")
class Kill05ReadReadSideTest {
    companion object {
        const val FILE = "k05-readside.json.gz"
        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
        fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun isThrow(o: Any?) = o is Map<*, *> && o.containsKey("\$throws")
        fun show(o: Any?): String = if (isThrow(o)) "THROWS" else Json.canonicalize(o)

        /** One case per reference call; [f] returns the native result (or throws), [skip] names cases with no native counterpart. */
        fun diff(fn: String, skip: (Map<String, Any?>) -> Boolean = { false }, f: (List<Any?>) -> Any?) {
            val bad = ArrayList<String>()
            var ran = 0
            for (c in of(fn)) {
                if (skip(c)) continue
                ran++
                val want = show(c["out"])
                val got = try { Json.canonicalize(f(args(c))) } catch (t: Throwable) { "THROWS" }
                if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
            }
            assertTrue("$fn: every case skipped", ran > 0)
            assertTrue("${bad.size} divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
        }

        fun readIn(g: Any?, a: List<Any?>) = ReadSide.ReadInput(g, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9])

        fun chainMap(c: ReadSide.ChainResult): Map<String, Any?> =
            if (c.labels != null) linkedMapOf("labels" to c.labels) else linkedMapOf("code" to c.code, "at" to c.at.toLong())
    }

    /** A grant whose members cannot be read: every entry point must fail closed instead of throwing. */
    class Boom : LinkedHashMap<String, Any?>() {
        init {
            put("body", null)
            put("sig", null)
        }

        override fun get(key: String): Any? = throw IllegalStateException("boom")
    }

    // ---- the differential ----

    @Test fun validReadGrantBody() = diff("validReadGrantBody") { ReadSide.validReadGrantBody(it[0]) }

    @Test fun redactRead() = diff("redactRead") { ReadSide.redactRead(readIn(it[0], it.subList(1, 11))).toMap() }

    // the native rsSigner parameter is a String (checkSink passes it only after isB32): a non-string signer has no native call
    @Test fun readChainLabels() = diff("readChainLabels", { args(it)[1] !is String }) {
        chainMap(ReadSide.readChainLabels(it[0], it[1] as String, it[2] as String, Json.asLong(it[3])))
    }

    @Test fun checkSink() = diff("checkSink") { ReadSide.checkSink(ReadSide.SinkInput(it[0], it[1], it[2], it[3], it[4], it[5])).toMap() }

    @Test fun digests() {
        diff("readGrantDigest") { ReadSide.readGrantDigest(it[0]) }
        diff("readReceiptRef") { ReadSide.readReceiptRef(it[0]) }
    }

    // ---- grants and receipts signed at runtime ----

    private val label = "k05-read-principal"
    private val p = IntentTestKit.pub(label)
    private val other = IntentTestKit.pub("k05-read-other")
    private val rsLabel = "k05-read-rs"
    private val rs = IntentTestKit.pub(rsLabel)
    private val vd = Pca.b64(ByteArray(32))
    private val salt = "0123456789abcdef"

    private fun entry(vararg over: Any?): LinkedHashMap<String, Any?> {
        val e = jm(
            "verb", "customers.get", "resource_prefix", "customers/", "purposes", jl("support"),
            "modes", jm("fin", "bucket:100", "gone", "drop", "pii", "last4", "pub", "show", "ref", "token", "sec", "hash"), "default_mode", "drop",
        )
        for (i in over.indices step 2) e[over[i] as String] = over[i + 1]
        return e
    }

    private fun body(vararg over: Any?): LinkedHashMap<String, Any?> {
        val b = jm(
            "v", 1L, "id", "rg-1", "principal", p, "issued_at", 1000L, "expires_at", 2000L, "reads", jl(entry()), "caps", jm(),
            "sinks", jm("payments", jm("allow", jl("pub", "ref"), "escalate", jl("pii")), "email", jm("allow", jl(), "escalate", jl())),
        )
        for (i in over.indices step 2) b[over[i] as String] = over[i + 1]
        return b
    }

    private fun grant(b: Map<String, Any?> = body(), signer: String = label) =
        jm("body", b, "sig", IntentTestKit.sign(signer, IntentJs.message(ReadSide.READ_GRANT_DOMAIN, b)))

    private val schemaFields = jm("a_pub", "pub", "b_pii", "pii", "c_fin", "fin", "d_ref", "ref", "e_sec", "sec", "f_gone", "gone", "g_other", "other")

    private fun schema(required: List<Any?> = jl()) = jm("fields", schemaFields, "required", ArrayList(required))

    private fun read(
        g: Any? = grant(), record: Any? = jm("a_pub", "hi"), schema: Any? = schema(), tighten: Any? = jm(), counts: Any? = jm(),
        now: Any? = 1500L, principal: Any? = p, verb: Any? = "customers.get", resource: Any? = "customers/1", purpose: Any? = "support",
        salt: Any? = this.salt,
    ) = ReadSide.redactRead(ReadSide.ReadInput(g, principal, now, verb, resource, purpose, schema, record, tighten, salt, counts))

    private fun code(r: ReadSide.ReadResult) = "${r.decision}/${r.code}"

    @Test
    fun gradingTheGrant() {
        assertEquals("allow/null", code(read()))
        assertEquals("deny/bad_request", code(read(principal = "x")))
        assertEquals("deny/bad_request", code(read(now = -1L)))
        assertEquals("deny/bad_grant", code(read(g = null)))
        assertEquals("deny/bad_grant", code(read(g = jm("body", body(), "sig", "x", "extra", 1L))))
        assertEquals("deny/bad_grant", code(read(g = grant(body("reads", jl())))))
        assertEquals("deny/bad_signature", code(read(g = grant(body("principal", other), "k05-read-other"))))
        assertEquals("deny/bad_signature", code(read(g = jm("body", body(), "sig", Pca.b64(ByteArray(64))))))
        assertEquals("deny/not_yet", code(read(now = 999L)))
        assertEquals("allow/null", code(read(now = 1000L)))
        assertEquals("allow/null", code(read(now = 1999L)))
        assertEquals("deny/expired", code(read(now = 2000L)))
    }

    @Test
    fun theRequestItself() {
        val prefix = "customers/"
        assertEquals("allow/null", code(read(verb = "v".repeat(128), g = grant(body("reads", jl(entry("verb", "v".repeat(128))))))))
        assertEquals("deny/bad_request", code(read(verb = "v".repeat(129))))
        assertEquals("deny/bad_request", code(read(verb = "")))
        assertEquals("allow/null", code(read(resource = prefix + "r".repeat(512 - prefix.length))))
        assertEquals("deny/bad_request", code(read(resource = prefix + "r".repeat(513 - prefix.length))))
        assertEquals("deny/bad_request", code(read(purpose = "bad purpose")))
        assertEquals("deny/bad_request", code(read(purpose = Json.Num("5"))))
        assertEquals("deny/bad_request", code(read(purpose = null)))
        assertEquals("deny/bad_request", code(read(salt = "s".repeat(15))))
        assertEquals("allow/null", code(read(salt = "s".repeat(16))))
        assertEquals("deny/bad_request", code(read(salt = Json.Num("1234567890123456"))))
    }

    @Test
    fun theSchemaRecordTightenAndCounts() {
        val bad = "deny/bad_request"
        assertEquals(bad, code(read(schema = "x")))
        assertEquals(bad, code(read(schema = jm("fields", "x", "required", jl()))))
        assertEquals(bad, code(read(schema = jm("fields", jm("a_pub", "pub", "b c", "pub"), "required", jl()))))
        assertEquals(bad, code(read(schema = jm("fields", jm("a_pub", "pub", "b", Json.Num("5")), "required", jl()))))
        assertEquals(bad, code(read(schema = jm("fields", jm("a_pub", "pub", "b", "Pub"), "required", jl()))))
        assertEquals(bad, code(read(schema = jm("fields", schemaFields, "required", "a_pub"))))
        assertEquals(bad, code(read(schema = schema(jl("a_pub", "nope")))))
        assertEquals(bad, code(read(schema = schema(jl("a_pub", Json.Num("5"))))))
        assertEquals("allow/null", code(read(schema = schema(jl("a_pub")))))
        // an empty schema classifies nothing: every field is dropped as unclassified, and nothing is required
        val empty = read(schema = jm("fields", jm(), "required", jl()), record = jm("x", "y"))
        assertEquals("allow/null", code(empty))
        assertEquals(Json.canonicalize(jm("class", "unclassified", "action", "dropped", "kind", null, "vd", empty.fields["x"]!!.vd)), Json.canonicalize(empty.fields["x"]!!.toMap()))
        assertEquals(emptyList<String>(), empty.labels)

        assertEquals(bad, code(read(record = "x")))
        assertEquals(bad, code(read(record = jm("a_pub", jl("x")))))
        assertEquals(bad, code(read(record = jm("a b", "x"))))
        assertEquals(bad, code(read(tighten = "x")))
        assertEquals(bad, code(read(tighten = jm("pub", "hash", "BAD", "hash"))))
        assertEquals(bad, code(read(tighten = jm("pub", "hash", "sec", "loud"))))
        assertEquals(bad, code(read(tighten = jm("pub", "hash", "sec", Json.Num("5")))))
        assertEquals("allow/null", code(read(tighten = jm("pub", "hash", "sec", "drop"))))
        assertEquals(bad, code(read(counts = "x")))
        assertEquals(bad, code(read(counts = jm("pub", 1L, "BAD", 1L))))
        assertEquals(bad, code(read(counts = jm("pub", 1L, "sec", -1L))))
        assertEquals(bad, code(read(counts = jm("pub", 1L, "sec", "1"))))
        assertEquals("allow/null", code(read(counts = jm("pub", 1L, "sec", 0L))))
    }

    @Test
    fun theScopeOfTheRead() {
        val counts = jm("pub", 3L)
        for (r in listOf(read(verb = "customers.list", counts = counts), read(resource = "orders/1", counts = counts), read(purpose = "billing", counts = counts))) {
            assertEquals("deny/no_read_scope", code(r))
            assertEquals(Json.canonicalize(counts), Json.canonicalize(r.counts))
            assertTrue(r.view.isEmpty() && r.fields.isEmpty() && r.labels.isEmpty())
        }
        // the second entry is found when the first does not match
        val two = grant(body("reads", jl(entry("verb", "customers.list"), entry())))
        assertEquals("allow/null", code(read(g = two)))
    }

    @Test
    fun everyModeAndItsEdges() {
        val r = read(
            record = jm(
                "a_pub", "hi", "b_pii", "123-45-6789", "c_fin", 12345L, "d_ref", "c_77", "e_sec", "s", "f_gone", "x", "g_other", "o", "h_unc", "u",
            ),
        )
        assertEquals("allow/null", code(r))
        assertEquals("hi", r.view["a_pub"])
        assertEquals("****6789", r.view["b_pii"])
        assertEquals(Json.Num("12300"), r.view["c_fin"])
        assertTrue((r.view["d_ref"] as String).matches(Regex("tok_[A-Za-z0-9_-]{22}")))
        assertEquals(43, (r.view["e_sec"] as String).length)
        assertFalse(r.view.containsKey("f_gone") || r.view.containsKey("g_other") || r.view.containsKey("h_unc"))
        fun f(k: String) = r.fields[k]!!.let { listOf(it.cls, it.action, it.kind) }
        assertEquals(listOf("pub", "shown", null), f("a_pub"))
        assertEquals(listOf("pii", "masked", "last4"), f("b_pii"))
        assertEquals(listOf("fin", "masked", "bucket"), f("c_fin"))
        assertEquals(listOf("ref", "masked", "token"), f("d_ref"))
        assertEquals(listOf("sec", "masked", "hash"), f("e_sec"))
        assertEquals(listOf("gone", "dropped", null), f("f_gone"))
        assertEquals(listOf("other", "dropped", null), f("g_other"))
        assertEquals(listOf("unclassified", "dropped", null), f("h_unc"))
        for (v in r.fields.values) assertEquals(43, v.vd.length)
        assertEquals(listOf("fin", "pii", "pub", "ref", "sec"), r.labels)
        assertEquals(Json.canonicalize(jm("fin", 1L, "pii", 1L, "pub", 1L, "ref", 1L, "sec", 1L)), Json.canonicalize(r.counts))
        assertNull(r.code)
        assertEquals("allow", r.decision)

        // last4: more than four code points, all in the BMP; a number is dropped
        fun last4(v: Any?) = read(record = jm("b_pii", v)).view["b_pii"]
        assertEquals("****bcde", last4("abcde"))
        assertNull(last4("abcd"))
        assertEquals("****abcd", last4("￿abcd"))
        assertNull(last4("😀abcd"))
        assertNull(last4("ab😀cdef"))
        assertNull(last4(Json.Num("123456")))
        assertNull(last4(true))
        // bucket: a non-negative integer only
        fun bucket(v: Any?) = read(record = jm("c_fin", v)).view["c_fin"]
        assertEquals(Json.Num("0"), bucket(0L))
        assertEquals(Json.Num("0"), bucket(99L))
        assertEquals(Json.Num("100"), bucket(100L))
        assertNull(bucket(-1L))
        assertNull(bucket("100"))
        assertNull(bucket(false))
    }

    @Test
    fun tightenOnlyEverTightens() {
        val rec = jm("a_pub", "hi", "e_sec", "s", "c_fin", 12345L)
        val r = read(record = rec, tighten = jm("pub", "hash", "sec", "show", "fin", "bucket:1000"))
        assertEquals(listOf("pub", "masked", "hash"), r.fields["a_pub"]!!.let { listOf(it.cls, it.action, it.kind) })
        assertEquals("hash", r.fields["e_sec"]!!.kind)
        // the same rank (bucket:1000 vs bucket:100) is not stricter: the grant's mode stays
        assertEquals(Json.Num("12300"), r.view["c_fin"])
        assertEquals("dropped", read(record = rec, tighten = jm("fin", "drop")).fields["c_fin"]!!.action)
        assertEquals("tok_", (read(record = rec, tighten = jm("fin", "token")).view["c_fin"] as String).substring(0, 4))
    }

    @Test
    fun capsAndRequiredFields() {
        val capped = grant(body("caps", jm("pii", 2L)))
        val rec = jm("b_pii", "123-45-6789")
        assertEquals("allow/null", code(read(g = capped, record = rec, counts = jm("pii", 1L))))
        val over = read(g = capped, record = rec, counts = jm("pii", 2L, "pub", 9L))
        assertEquals("deny/read_cap", code(over))
        assertEquals(Json.canonicalize(jm("pii", 2L, "pub", 9L)), Json.canonicalize(over.counts))
        // a class without a cap is never capped
        assertEquals("allow/null", code(read(g = capped, record = jm("a_pub", "x"), counts = jm("pub", 9_000_000L))))
        val esc = read(record = jm("a_pub", "x", "f_gone", "y"), schema = schema(jl("f_gone")), counts = jm("pub", 4L))
        assertEquals("escalate/required_dropped", code(esc))
        assertEquals(Json.canonicalize(jm("pub", 4L)), Json.canonicalize(esc.counts))
        assertEquals("allow/null", code(read(record = jm("a_pub", "x"), schema = schema(jl("a_pub")))))
        // a required field the record does not carry is dropped too
        assertEquals("escalate/required_dropped", code(read(record = jm("a_pub", "x"), schema = schema(jl("a_pub", "b_pii")))))
    }

    @Test
    fun grantShapeEdges() {
        assertTrue(ReadSide.validReadGrantBody(body()))
        assertTrue(ReadSide.validReadGrantBody(body("caps", jm(), "sinks", jm())))
        assertTrue(ReadSide.validReadGrantBody(body("reads", jl(entry("modes", jm())))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(entry("modes", jm("pub", "show", "Bad", "show"))))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(entry("modes", jm("pub", "show", "sec", "loud"))))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(entry("modes", jm("pub", "show", "sec", Json.Num("5")))))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(entry("default_mode", "loud")))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(entry("default_mode", null)))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(entry(), "x"))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(entry("modes", "x")))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(entry("purposes", jl())))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(jm("verb", "v")))))
        val m32 = jm()
        for (i in 0 until 32) m32["c$i"] = "show"
        assertTrue(ReadSide.validReadGrantBody(body("reads", jl(entry("modes", m32)))))
        val m33 = LinkedHashMap(m32).also { it["c32"] = "show" }
        assertFalse(ReadSide.validReadGrantBody(body("reads", jl(entry("modes", m33)))))
        assertTrue(ReadSide.validReadGrantBody(body("reads", ArrayList<Any?>(List(32) { entry() }))))
        assertFalse(ReadSide.validReadGrantBody(body("reads", ArrayList<Any?>(List(33) { entry() }))))
        val c32 = jm()
        for (i in 0 until 32) c32["c$i"] = 1L
        assertTrue(ReadSide.validReadGrantBody(body("caps", c32)))
        assertFalse(ReadSide.validReadGrantBody(body("caps", LinkedHashMap(c32).also { it["c32"] = 1L })))
        assertFalse(ReadSide.validReadGrantBody(body("caps", jm("a", 1L, "B", 1L))))
        assertFalse(ReadSide.validReadGrantBody(body("caps", jm("a", 1L, "b", -1L))))
        val s16 = jm()
        for (i in 0 until 16) s16["s$i"] = jm("allow", jl(), "escalate", jl())
        assertTrue(ReadSide.validReadGrantBody(body("sinks", s16)))
        assertFalse(ReadSide.validReadGrantBody(body("sinks", LinkedHashMap(s16).also { it["s16"] = jm("allow", jl(), "escalate", jl()) })))
        fun sink(rule: Any?) = ReadSide.validReadGrantBody(body("sinks", jm("ok", jm("allow", jl(), "escalate", jl()), "s", rule)))
        assertTrue(sink(jm("allow", jl("a", "b"), "escalate", jl("c"))))
        assertFalse(sink(jm("allow", jl("a", "b"), "escalate", jl("b"))))
        assertFalse(sink(jm("allow", jl("b", "a"), "escalate", jl())))
        assertFalse(sink(jm("allow", jl(), "escalate", jl("A"))))
        assertFalse(sink(jm("allow", jl())))
        assertFalse(sink("x"))
        assertFalse(sink(jm("allow", ArrayList<Any?>(List(17) { "l$it" }.sorted()), "escalate", jl())))
        assertTrue(sink(jm("allow", ArrayList<Any?>(List(16) { "l$it" }.sorted()), "escalate", ArrayList<Any?>(List(16) { "m$it" }.sorted()))))
        assertFalse(sink(jm("allow", jl(), "escalate", ArrayList<Any?>(List(17) { "m$it" }.sorted()))))
        assertFalse(ReadSide.validReadGrantBody(body("sinks", jm("bad sink", jm("allow", jl(), "escalate", jl())))))
        assertFalse(ReadSide.validReadGrantBody(body("v", 2L)))
        assertFalse(ReadSide.validReadGrantBody(body("id", Json.Num("5"))))
        assertFalse(ReadSide.validReadGrantBody(body("id", "bad id")))
        assertFalse(ReadSide.validReadGrantBody(body("principal", "x")))
        assertFalse(ReadSide.validReadGrantBody(body("issued_at", -1L)))
        assertFalse(ReadSide.validReadGrantBody(body("expires_at", "1")))
        assertFalse(ReadSide.validReadGrantBody(body("reads", "x")))
        assertFalse(ReadSide.validReadGrantBody(body("caps", "x")))
        assertFalse(ReadSide.validReadGrantBody(body("sinks", "x")))
        assertFalse(ReadSide.validReadGrantBody(body().also { it["extra"] = 1L }))
        assertFalse(ReadSide.validReadGrantBody("x"))
    }

    // ---- receipts, chains and sinks ----

    private fun fld(cls: String, action: String, kind: String? = null) = jm("class", cls, "action", action, "kind", kind, "vd", vd)

    private fun receipt(
        g: Map<String, Any?>, seq: Long, prev: Map<String, Any?>?, fields: Map<String, Any?>, labels: List<String>, issuedAt: Long = 1500L,
        signer: String = rsLabel,
    ): LinkedHashMap<String, Any?> {
        val r = jm(
            "v", 1L, "grant", ReadSide.readGrantDigest(g), "verb", "customers.get", "resource", "customers/1", "purpose", "support", "seq", seq,
            "prev", prev?.let { ReadSide.readReceiptRef(it) }, "fields", fields, "labels", ArrayList<Any?>(labels), "issued_at", issuedAt,
            "signer", IntentTestKit.pub(signer),
        )
        r["sig"] = IntentTestKit.sign(signer, IntentJs.message(ReadSide.READ_RECEIPT_DOMAIN, r))
        return r
    }

    private val b = body()
    private val digest = ReadSide.readGrantDigest(b)

    private fun chain(vararg labelSets: List<String>): List<Any?> {
        val out = ArrayList<Any?>()
        var prev: Map<String, Any?>? = null
        for ((i, ls) in labelSets.withIndex()) {
            val fields = jm()
            for ((j, l) in ls.withIndex()) fields["f$j"] = fld(l, "shown")
            fields["z"] = fld("zzz", "dropped")
            val r = receipt(b, i.toLong(), prev, fields, ls)
            out.add(r)
            prev = r
        }
        return out
    }

    private fun labels(rec: Any?, now: Long = 1500L) = chainMap(ReadSide.readChainLabels(rec, rs, digest, now))

    private fun badAt(i: Int) = linkedMapOf<String, Any?>("code" to "bad_receipt", "at" to i.toLong())

    @Test
    fun readChains() {
        assertEquals(linkedMapOf<String, Any?>("labels" to listOf<String>()), labels(jl()))
        assertEquals(badAt(0), labels("x"))
        assertEquals(badAt(0), labels(jm()))
        val c = chain(listOf("pub"), listOf("pii", "pub"), listOf())
        assertEquals(linkedMapOf<String, Any?>("labels" to listOf("pii", "pub")), labels(c))
        val r = ReadSide.readChainLabels(c, rs, digest, 1500L)
        assertEquals(listOf("pii", "pub"), r.labels)
        assertNull(r.code)
        assertEquals(0, r.at)
        // issued exactly now is fine, a moment later is not
        assertEquals(badAt(0), labels(c, 1499L))
        // the second receipt is the offender: at = 1
        val bad = ReadSide.readChainLabels(listOf(c[0], c[2]), rs, digest, 1500L)
        assertEquals("bad_receipt", bad.code)
        assertNull(bad.labels)
        assertEquals(1, bad.at)
        assertEquals(badAt(1), labels(listOf(c[0], "x")))
        // a receipt signed by another key, for another grant, out of order, or with a broken prev link
        assertEquals(badAt(0), labels(listOf(receipt(b, 0L, null, jm(), listOf(), signer = "k05-read-other"))))
        assertEquals(badAt(0), labels(listOf(receipt(body("id", "rg-2"), 0L, null, jm(), listOf()))))
        assertEquals(badAt(0), labels(listOf(c[1])))
        val r0 = c[0] as Map<String, Any?>
        assertEquals(badAt(1), labels(listOf(r0, receipt(b, 1L, c[1] as Map<String, Any?>, jm(), listOf()))))
        assertEquals(linkedMapOf<String, Any?>("labels" to listOf("pub")), labels(listOf(r0, receipt(b, 1L, r0, jm(), listOf()))))
        // a forged signature, and a receipt whose labels understate (or overstate) its shown fields
        assertEquals(badAt(0), labels(listOf(LinkedHashMap(r0).also { it["sig"] = Pca.b64(ByteArray(64)) })))
        assertEquals(badAt(0), labels(listOf(receipt(b, 0L, null, jm("a", fld("pii", "masked", "last4")), listOf()))))
        assertEquals(badAt(0), labels(listOf(receipt(b, 0L, null, jm("a", fld("pii", "dropped")), listOf("pii")))))
        assertEquals(
            linkedMapOf<String, Any?>("labels" to listOf("pii")),
            labels(listOf(receipt(b, 0L, null, jm("a", fld("pii", "masked", "last4"), "b", fld("pii", "shown"), "u", fld("unclassified", "dropped")), listOf("pii")))),
        )
        // a field that is not an object, or with a non-string or unknown class, is a bad receipt (never a throw)
        assertEquals(badAt(0), labels(listOf(receipt(b, 0L, null, jm("a", "x"), listOf()))))
        assertEquals(badAt(0), labels(listOf(receipt(b, 0L, null, jm("a", jm("class", Json.Num("5"), "action", "shown", "kind", null, "vd", vd)), listOf()))))
        assertEquals(badAt(0), labels(listOf(receipt(b, 0L, null, jm("a", fld("BAD", "dropped")), listOf()))))
    }

    private fun validReceipt(r: Any?): Boolean = KUtil.priv(ReadSide, "validReadReceipt", r)

    @Test
    fun receiptShape() {
        val ok = chain(listOf("pub"))[0] as Map<String, Any?>
        fun w(vararg kv: Any?): Map<String, Any?> = LinkedHashMap(ok).also { for (i in kv.indices step 2) it[kv[i] as String] = kv[i + 1] }
        assertTrue(validReceipt(ok))
        assertFalse(validReceipt("x"))
        assertFalse(validReceipt(LinkedHashMap(ok).also { it.remove("sig") }))
        assertFalse(validReceipt(w("v", 2L)))
        assertFalse(validReceipt(w("v", "1")))
        assertFalse(validReceipt(w("grant", "x")))
        assertFalse(validReceipt(w("verb", "")))
        assertTrue(validReceipt(w("verb", "v".repeat(128))))
        assertFalse(validReceipt(w("verb", "v".repeat(129))))
        assertTrue(validReceipt(w("resource", "r".repeat(512))))
        assertFalse(validReceipt(w("resource", "r".repeat(513))))
        assertFalse(validReceipt(w("purpose", "bad purpose")))
        assertFalse(validReceipt(w("purpose", Json.Num("5"))))
        assertFalse(validReceipt(w("seq", -1L)))
        assertFalse(validReceipt(w("seq", "0")))
        assertFalse(validReceipt(w("prev", "x")))
        assertFalse(validReceipt(w("prev", vd)))
        assertTrue(validReceipt(w("seq", 1L, "prev", vd)))
        assertFalse(validReceipt(w("seq", 1L, "prev", null)))
        assertFalse(validReceipt(w("issued_at", -1L)))
        assertFalse(validReceipt(w("signer", "x")))
        assertFalse(validReceipt(w("sig", Json.Num("5"))))
        assertFalse(validReceipt(w("sig", null)))
        assertFalse(validReceipt(w("labels", jl("pub", "pii"))))
        assertFalse(validReceipt(w("labels", "pub")))
        assertTrue(validReceipt(w("labels", ArrayList<Any?>(List(32) { "l%02d".format(it) }))))
        assertFalse(validReceipt(w("labels", ArrayList<Any?>(List(33) { "l%02d".format(it) }))))
        assertFalse(validReceipt(w("fields", "x")))
        assertTrue(validReceipt(w("fields", jm())))
        val f64 = jm()
        for (i in 0 until 64) f64["f$i"] = fld("pub", "shown")
        assertTrue(validReceipt(w("fields", f64)))
        assertFalse(validReceipt(w("fields", LinkedHashMap(f64).also { it["f64"] = fld("pub", "shown") })))
        fun field(f: Any?) = validReceipt(w("fields", jm("ok", fld("pub", "shown"), "f", f)))
        assertTrue(field(fld("unclassified", "dropped")))
        assertTrue(field(fld("pub", "masked", "hash")))
        assertTrue(field(fld("pub", "dropped")))
        assertFalse(field(fld("pub", "hidden")))
        assertFalse(field(fld("Pub", "shown")))
        assertFalse(field(jm("class", null, "action", "shown", "kind", null, "vd", vd)))
        assertFalse(field(jm("class", "pub", "action", "shown", "kind", Json.Num("5"), "vd", vd)))
        assertFalse(field(jm("class", "pub", "action", "shown", "kind", null, "vd", "x")))
        assertFalse(field(jm("class", "pub", "action", "shown", "kind", null)))
        assertFalse(field(jm("class", "pub", "action", "shown", "kind", null, "vd", vd, "x", 1L)))
        assertFalse(field("x"))
        assertFalse(validReceipt(w("fields", jm("bad key", fld("pub", "shown")))))
    }

    private fun sink(sink: Any?, receipts: Any?, g: Any? = grant(b), signer: Any? = rs, now: Any? = 1500L, principal: Any? = p) =
        ReadSide.checkSink(ReadSide.SinkInput(g, principal, signer, now, sink, receipts))

    @Test
    fun sinks() {
        fun s(r: ReadSide.SinkResult) = Json.canonicalize(r.toMap())
        fun res(d: String, c: String?, l: List<String>) = Json.canonicalize(linkedMapOf("decision" to d, "code" to c, "labels" to l))
        assertEquals(res("allow", null, listOf()), s(sink("payments", jl())))
        assertEquals(res("allow", null, listOf("pub")), s(sink("payments", chain(listOf("pub")))))
        assertEquals(res("allow", null, listOf("pub", "ref")), s(sink("payments", chain(listOf("pub"), listOf("ref")))))
        assertEquals(res("escalate", "label_escalate", listOf("pii")), s(sink("payments", chain(listOf("pii")))))
        assertEquals(res("escalate", "label_escalate", listOf("pii", "pub")), s(sink("payments", chain(listOf("pub"), listOf("pii")))))
        assertEquals(res("deny", "label_flow", listOf("pii", "sec")), s(sink("payments", chain(listOf("pii", "sec")))))
        assertEquals(res("deny", "label_flow", listOf("pub")), s(sink("email", chain(listOf("pub")))))
        assertEquals(res("deny", "unknown_sink", listOf()), s(sink("fax", jl())))
        assertEquals(res("deny", "bad_request", listOf()), s(sink(Json.Num("5"), jl())))
        assertEquals(res("deny", "bad_request", listOf()), s(sink("payments", jl(), signer = "x")))
        assertEquals(res("deny", "bad_request", listOf()), s(sink("payments", jl(), signer = Json.Num("5"))))
        assertEquals(res("deny", "bad_receipt", listOf()), s(sink("payments", "x")))
        assertEquals(res("deny", "bad_receipt", listOf()), s(sink("payments", chain(listOf("pub")), now = 1499L)))
        assertEquals(res("deny", "bad_request", listOf()), s(sink("payments", jl(), principal = "x")))
        assertEquals(res("deny", "bad_request", listOf()), s(sink("payments", jl(), now = -1L)))
        assertEquals(res("deny", "bad_grant", listOf()), s(sink("payments", jl(), g = null)))
        assertEquals(res("deny", "bad_signature", listOf()), s(sink("payments", jl(), g = grant(b, "k05-read-other"))))
        assertEquals(res("deny", "not_yet", listOf()), s(sink("payments", jl(), now = 999L)))
        assertEquals(res("deny", "expired", listOf()), s(sink("payments", jl(), now = 2000L)))
        val esc = sink("payments", chain(listOf("pii")))
        assertEquals("escalate", esc.decision)
        assertEquals("label_escalate", esc.code)
        assertEquals(listOf("pii"), esc.labels)
        val ok = sink("payments", jl())
        assertNull(ok.code)
        assertEquals(listOf<String>(), ok.labels)
    }

    // ---- the fail-closed catch paths ----

    @Test
    fun aHostileGrantFailsClosed() {
        val r = read(g = Boom())
        assertEquals("deny", r.decision)
        assertEquals("bad_request", r.code)
        assertTrue(r.view.isEmpty() && r.fields.isEmpty() && r.labels.isEmpty() && r.counts.isEmpty())
        val s = sink("payments", jl(), g = Boom())
        assertEquals("deny", s.decision)
        assertEquals("bad_request", s.code)
        assertTrue(s.labels.isEmpty())
    }

    @Test
    fun resultGetters() {
        val r = read(record = jm("a_pub", "hi", "b_pii", "123-45-6789"), counts = jm("pub", 2L))
        assertEquals("allow", r.decision)
        assertNull(r.code)
        assertEquals(listOf("pii", "pub"), r.labels)
        assertEquals(Json.canonicalize(jm("pii", 1L, "pub", 3L)), Json.canonicalize(r.counts))
        val f = r.fields["b_pii"]!!
        assertEquals("pii", f.cls)
        assertEquals("masked", f.action)
        assertEquals("last4", f.kind)
        assertEquals(f.vd, (f.toMap())["vd"])
        assertEquals(43, f.vd.length)
        val d = read(verb = "nope.get", counts = jm("pub", 2L))
        assertEquals("no_read_scope", d.code)
        assertEquals(Json.canonicalize(jm("pub", 2L)), Json.canonicalize(d.counts))
    }
}
