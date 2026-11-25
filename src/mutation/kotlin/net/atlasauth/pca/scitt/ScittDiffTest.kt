package net.atlasauth.pca.scitt

import java.io.File
import java.math.BigDecimal
import java.math.BigInteger
import net.atlasauth.pca.scitt.Scitt.CoseAlg
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Replays the TypeScript-reference vectors of the SCITT package (CBOR, RFC 9162, COSE statements and receipts, services, file store). */
@Suppress("UNCHECKED_CAST")
class ScittDiffTest {
    private val m = "ref-scitt"

    @get:Rule val tmp = TemporaryFolder()

    private var counter = 0

    // ---- argument shaping ----

    private fun map(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun list(o: Any?): List<Any?> = o as List<Any?>

    private fun bytes(o: Any?): ByteArray = Keys.unb64u(map(o)["\$bytes"] as String)

    private fun byteList(o: Any?): List<ByteArray> = list(o).map { bytes(it) }

    private fun safe(o: Any?) = Json.isSafeInt(o)

    private fun lng(o: Any?) = Json.asLong(o)

    /** A JSON number as the CBOR model value: Long for an exact safe integer, else Double (which the codec refuses). */
    private fun num(n: Json.Num): Any {
        val raw = n.raw
        try {
            val d = BigDecimal(raw)
            if (d.signum() == 0 && raw.startsWith("-")) return -0.0
            val i = d.toBigIntegerExact()
            if (i.abs() <= BigInteger.valueOf(Cbor.MAX_SAFE)) return i.toLong()
        } catch (e: ArithmeticException) {
            // not an exact integer
        } catch (e: NumberFormatException) {
            // not an exact integer
        }
        return raw.toDouble()
    }

    private fun fromCj(v: Any?): Any? {
        if (v is Json.Num) return num(v)
        if (v is List<*>) return v.map { fromCj(it) }
        if (v is Map<*, *>) {
            val mm = map(v)
            if (mm.containsKey("\$bytes")) return bytes(mm)
            if (mm.containsKey("\$map")) {
                val out = LinkedHashMap<Any?, Any?>()
                for (e in list(mm["\$map"])) {
                    val kv = list(e)
                    val key = fromCj(kv[0]).let { if (it is Double && it == 0.0) 0L else it } // a Map key -0 is +0 (SameValueZero)
                    out[key] = fromCj(kv[1]) // like a JavaScript Map: a repeated key keeps its slot, the last value wins
                }
                return out
            }
            if (mm.containsKey("\$tag")) {
                val t = fromCj(mm["\$tag"])
                if (t !is Long) throw IllegalArgumentException("cbor: bad tag")
                return Cbor.Tag(t, fromCj(mm["v"]))
            }
        }
        return v
    }

    private fun toCj(v: Any?): Any? = when (v) {
        is Map<*, *> -> linkedMapOf<String, Any?>("\$map" to v.entries.map { listOf(it.key, toCj(it.value)) })
        is Cbor.Tag -> linkedMapOf<String, Any?>("\$tag" to v.tag, "v" to toCj(v.value))
        is List<*> -> v.map { toCj(it) }
        else -> v
    }

    private fun priv(spec: Any?): ScittPrivateKey {
        val s = map(spec)
        if ("EdDSA" == s["alg"]) return Scitt.ed25519PrivateKey(Keys.unb64u(s["seed"] as String))
        return Scitt.es256PrivateKey(Keys.unb64u(s["d"] as String))
    }

    private fun pub(spec: Any?): ScittPublicKey {
        val s = map(spec)
        if ("EdDSA" == s["alg"]) return Scitt.ed25519PublicKey(Keys.unb64u(s["pub"] as String))
        return Scitt.es256PublicKey(Keys.unb64u(s["x"] as String), Keys.unb64u(s["y"] as String))
    }

    private fun alg(o: Any?) = CoseAlg.valueOf(o as String)

    private fun sOpts(o: Any?): Scitt.SignStatementOpts {
        val s = map(o)
        val out = Scitt.SignStatementOpts(alg(s["alg"]), priv(s["key"]), s["issuer"] as String?)
        if (s.containsKey("subject")) out.subject(s["subject"] as String?)
        if (s.containsKey("contentType")) out.contentType(s["contentType"] as String?)
        return out
    }

    private fun rOpts(o: Any?): Scitt.ReceiptSignerOpts {
        val s = map(o)
        return Scitt.ReceiptSignerOpts(alg(s["alg"]), priv(s["key"]), s["issuer"] as String?)
    }

    private fun vOpts(o: Any?): Scitt.VerifyReceiptOpts {
        val out = Scitt.VerifyReceiptOpts()
        if (o !is Map<*, *>) return out
        val mm = map(o)
        out.treeRoot = mm["treeRoot"] as String?
        if (mm["verificationKey"] != null) out.verificationKey = pub(mm["verificationKey"])
        if (mm["statementKey"] != null) out.statementKey = pub(mm["statementKey"])
        out.allowHighS = mm["allowHighS"] == true
        return out
    }

    private fun highS(a: List<Any?>) = a.size > 2 && a[2] is Map<*, *> && map(a[2])["allowHighS"] == true

    // ---- CBOR ----

    @Test fun cborEncode() = OracleCases.each(m, "cborEncode") { a -> Cbor.encode(fromCj(a[0])) }

    @Test fun cborDecode() = OracleCases.each(m, "cborDecode") { a -> toCj(Cbor.decode(bytes(a[0]))) }

    // ---- RFC 9162 ----

    @Test fun emptyRoot() = OracleCases.each(m, "emptyRoot") { Rfc9162.emptyRoot() }

    @Test fun leafHash() = OracleCases.each(m, "leafHash") { a -> Rfc9162.leafHash(bytes(a[0])) }

    @Test fun nodeHash() = OracleCases.each(m, "nodeHash") { a -> Rfc9162.nodeHash(bytes(a[0]), bytes(a[1])) }

    @Test fun treeHash() = OracleCases.each(m, "treeHash") { a -> Rfc9162.treeHash(byteList(a[0])) }

    @Test fun inclusionPath() = OracleCases.each(m, "inclusionPath") { a ->
        if (!safe(a[1])) throw IllegalArgumentException("rfc9162: leaf index out of range")
        Rfc9162.inclusionPath(byteList(a[0]), lng(a[1]))
    }

    @Test fun rootFromInclusionPath() = OracleCases.each(m, "rootFromInclusionPath") { a ->
        if (!safe(a[1]) || !safe(a[2])) null else Rfc9162.rootFromInclusionPath(bytes(a[0]), lng(a[1]), lng(a[2]), byteList(a[3]))
    }

    @Test fun verifyInclusionPath() = OracleCases.each(m, "verifyInclusionPath") { a ->
        safe(a[1]) && safe(a[2]) && Rfc9162.verifyInclusionPath(bytes(a[0]), lng(a[1]), lng(a[2]), byteList(a[3]), bytes(a[4]))
    }

    @Test fun consistencyPath() = OracleCases.each(m, "consistencyPath") { a ->
        if (!safe(a[1])) throw IllegalArgumentException("rfc9162: consistency size out of range")
        Rfc9162.consistencyPath(byteList(a[0]), lng(a[1]))
    }

    @Test fun verifyConsistencyPath() = OracleCases.each(m, "verifyConsistencyPath") { a ->
        safe(a[0]) && safe(a[1]) && Rfc9162.verifyConsistencyPath(lng(a[0]), lng(a[1]), bytes(a[2]), bytes(a[3]), byteList(a[4]))
    }

    // ---- proofs, statements, receipts ----

    @Test fun siblingSides() = OracleCases.each(m, "siblingSides") { a -> Scitt.siblingSides(lng(a[0]), lng(a[1])) }

    @Test fun encodeInclusionProof() = OracleCases.each(m, "encodeInclusionProof") { a -> Scitt.encodeInclusionProof(map(a[0])) }

    @Test fun decodeInclusionProof() = OracleCases.each(m, "decodeInclusionProof") { a -> Scitt.decodeInclusionProof(bytes(a[0])) }

    @Test fun signStatement() = OracleCases.each(m, "signStatement") { a -> Scitt.signStatement(a[0], sOpts(a[1])) }

    @Test fun decodeCoseSign1() = OracleCases.each(m, "decodeCoseSign1") { a ->
        val c = Scitt.decodeCoseSign1(bytes(a[0]))
        linkedMapOf<String, Any?>(
            "protectedBytes" to c.protectedBytes,
            "protectedMap" to toCj(c.protectedMap),
            "unprotected" to toCj(c.unprotected),
            "payload" to c.payload,
            "signature" to c.signature,
        )
    }

    @Test fun checkStatement() = OracleCases.each(m, "checkStatement") { a -> Scitt.checkStatement(bytes(a[0]), pub(a[1]), highS(a)).toMap() }

    @Test fun verifyStatement() = OracleCases.each(m, "verifyStatement") { a -> Scitt.verifyStatement(bytes(a[0]), pub(a[1]), highS(a)) }

    @Test fun statementPayload() = OracleCases.each(m, "statementPayload") { a -> Scitt.statementPayload(bytes(a[0])) }

    @Test fun statementLeaf() = OracleCases.each(m, "statementLeaf") { a -> Scitt.statementLeaf(bytes(a[0])) }

    @Test fun buildReceipt() = OracleCases.each(m, "buildReceipt") { a -> Scitt.buildReceipt(a[0] as String, map(a[1]), rOpts(a[2])) }

    @Test fun verifyReceipt() = OracleCases.each(m, "verifyReceipt") { a -> Scitt.verifyReceipt(bytes(a[0]), bytes(a[1]), vOpts(a[2])) }

    @Test fun verifyConsistencyProof() = OracleCases.each(m, "verifyConsistencyProof") { a ->
        Scitt.verifyConsistencyProof(bytes(a[0]), a[1] as String?, a[2] as String?)
    }

    @Test fun constants() = OracleCases.each(m, "constants") {
        linkedMapOf<String, Any?>(
            "COSE_SIGN1_TAG" to Scitt.COSE_SIGN1_TAG,
            "HDR_ALG" to Scitt.HDR_ALG,
            "HDR_CONTENT_TYPE" to Scitt.HDR_CONTENT_TYPE,
            "HDR_CWT_CLAIMS" to Scitt.HDR_CWT_CLAIMS,
            "CWT_ISS" to Scitt.CWT_ISS,
            "CWT_SUB" to Scitt.CWT_SUB,
            "HDR_VDS" to Scitt.HDR_VDS,
            "HDR_VDS_PROOFS" to Scitt.HDR_VDS_PROOFS,
            "VDS_RFC9162_SHA256" to Scitt.VDS_RFC9162_SHA256,
            "PROOF_TYPE_INCLUSION" to Scitt.PROOF_TYPE_INCLUSION,
            "DEFAULT_CONTENT_TYPE" to Scitt.DEFAULT_CONTENT_TYPE,
        )
    }

    // ---- ES256 (signatures are RFC 6979 deterministic here, but the oracle compares outcomes only) ----

    @Test fun es256SignVerify() = OracleCases.each(m, "es256SignVerify") { a ->
        val key = map(a[0])
        val st = Scitt.signStatement(a[1], Scitt.SignStatementOpts(CoseAlg.ES256, priv(key), a[2] as String?))
        val c = Scitt.decodeCoseSign1(st)
        val s = BigInteger(1, c.signature.copyOfRange(32, 64))
        linkedMapOf<String, Any?>(
            "check" to Scitt.checkStatement(st, Scitt.es256PublicKey(Keys.unb64u(key["x"] as String), Keys.unb64u(key["y"] as String))).toMap(),
            "payload" to Scitt.statementPayload(st),
            "lowS" to (s <= BigInteger("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8", 16)),
            "protectedBytes" to c.protectedBytes,
        )
    }

    @Test fun es256Receipt() = OracleCases.each(m, "es256Receipt") { a ->
        val key = map(a[0])
        val n = lng(a[1]).toInt()
        val index = lng(a[2]).toInt()
        val edPriv = priv(a[3])
        val edPub = Scitt.ed25519PublicKey(Keys.edFromSeed(Keys.unb64u(map(a[3])["seed"] as String)).pub)
        val ts = TransparencyService(Scitt.ReceiptSignerOpts(CoseAlg.ES256, priv(key), "ts"))
        val sts = ArrayList<ByteArray>()
        for (i in 0 until n) {
            val payload = linkedMapOf<String, Any?>("i" to Json.Num(i.toString()))
            sts.add(ts.appendAndReceipt(payload, Scitt.SignStatementOpts(CoseAlg.EdDSA, edPriv, "iss")).statement!!)
        }
        val tsPub = Scitt.es256PublicKey(Keys.unb64u(key["x"] as String), Keys.unb64u(key["y"] as String))
        val r = ts.getReceipt(index.toLong())
        val out = LinkedHashMap<String, Any?>()
        var o = Scitt.VerifyReceiptOpts().also { it.verificationKey = tsPub }
        out["key"] = Scitt.verifyReceipt(r.receipt, sts[index], o)
        o = Scitt.VerifyReceiptOpts().also { it.treeRoot = r.root }
        out["root"] = Scitt.verifyReceipt(r.receipt, sts[index], o)
        o = Scitt.VerifyReceiptOpts().also { it.verificationKey = tsPub; it.treeRoot = r.root; it.statementKey = edPub }
        out["both"] = Scitt.verifyReceipt(r.receipt, sts[index], o)
        o = Scitt.VerifyReceiptOpts().also { it.verificationKey = pub(a[4]) }
        out["wrongKey"] = Scitt.verifyReceipt(r.receipt, sts[index], o)
        o = Scitt.VerifyReceiptOpts().also { it.verificationKey = tsPub }
        val other = if ((index + 1) % n < sts.size) sts[(index + 1) % n] else ByteArray(3)
        out["otherStatement"] = Scitt.verifyReceipt(r.receipt, other, o)
        out["none"] = Scitt.verifyReceipt(r.receipt, sts[index], Scitt.VerifyReceiptOpts())
        out
    }

    // ---- services over the log ----

    /** A store that misbehaves the way the oracle's fault spec says. */
    private inner class FaultStore(private val f: Map<String, Any?>) : ScittLogStore {
        private val inner = MemoryScittLogStore()

        private fun at(spec: Any?, l: Long, i: Long) = spec != null && lng(list(spec)[0]) == l && lng(list(spec)[1]) == i

        override fun size(): Long = if (f["negSize"] == true) -1 else inner.size()

        override fun getEntry(index: Long) = inner.getEntry(index)

        override fun getNode(level: Long, index: Long): ByteArray? {
            if (at(f["dropNode"], level, index)) return null
            if (at(f["shortNode"], level, index)) return ByteArray(31)
            return inner.getNode(level, index)
        }

        override fun append(expectedSize: Long, entry: ByteArray, nodes: List<ScittLogStore.StoredNode>): Boolean =
            f["stale"] != true && inner.append(expectedSize, entry, nodes)
    }

    private fun idx(o: Any?, durable: Boolean): Long {
        if (!safe(o)) {
            if (durable) throw ScittLogError("out_of_range", "index out of range")
            throw IllegalArgumentException("index out of range")
        }
        return lng(o)
    }

    @Test fun service() = OracleCases.each(m, "service") { a ->
        val spec = map(a[0])
        val durable = "durable" == spec["kind"]
        val signer = Scitt.ReceiptSignerOpts(CoseAlg.EdDSA, priv(spec["key"]), spec["issuer"] as String?)
        var mem: TransparencyService? = null
        var dur: DurableTransparencyService? = null
        if (durable) dur = DurableTransparencyService(if (spec.containsKey("storeFault")) FaultStore(map(spec["storeFault"])) else MemoryScittLogStore(), signer)
        else mem = TransparencyService(signer)
        val res = ArrayList<Any?>()
        for (oo in list(spec["ops"])) {
            val op = map(oo)
            val r = LinkedHashMap<String, Any?>()
            try {
                val v: Any? = when (op["op"] as String) {
                    "append" -> {
                        val so = Scitt.SignStatementOpts(CoseAlg.EdDSA, priv(spec["stmtKey"]), "https://issuer.example")
                        if (op.containsKey("subject")) so.subject(op["subject"] as String?)
                        if (op.containsKey("contentType")) so.contentType(op["contentType"] as String?)
                        (if (durable) dur!!.appendAndReceipt(op["payload"], so) else mem!!.appendAndReceipt(op["payload"], so)).toMap()
                    }
                    "register" -> (if (durable) dur!!.register(bytes(op["statement"])) else mem!!.register(bytes(op["statement"]))).toMap()
                    "receipt" -> (if (durable) dur!!.getReceipt(idx(op["i"], true)) else mem!!.getReceipt(idx(op["i"], false))).toMap()
                    "consistency" -> (if (durable) dur!!.consistencyProof(idx(op["m"], true)) else mem!!.consistencyProof(idx(op["m"], false))).toMap()
                    "entry" -> {
                        if (!durable) throw IllegalStateException("no such method")
                        dur!!.getEntry(idx(op["i"], true))
                    }
                    "snapshot" -> {
                        if (durable) throw IllegalStateException("no such method")
                        mem!!.snapshot()
                    }
                    "root" -> if (durable) dur!!.root() else mem!!.root()
                    "size" -> if (durable) dur!!.size() else mem!!.size()
                    else -> throw IllegalStateException("op")
                }
                r["ok"] = v
            } catch (e: ScittLogError) {
                r["err"] = e.code
            } catch (e: RuntimeException) {
                r["err"] = true
            }
            res.add(r)
        }
        res
    }

    // ---- file store ----

    private fun file(prefix: String) = File(tmp.root, prefix + (counter++) + ".log")

    @Test fun fileStoreBytes() = OracleCases.each(m, "fileStoreBytes") { a ->
        val p = file("f")
        FileScittLogStore.open(p).use { s ->
            for (oo in list(a[0])) {
                val op = map(oo)
                try {
                    val nodes = ArrayList<ScittLogStore.StoredNode>()
                    for (no in list(op["nodes"])) {
                        val nl = list(no)
                        nodes.add(ScittLogStore.StoredNode(lng(nl[0]), lng(nl[1]), Keys.unb64u(nl[2] as String)))
                    }
                    s.append(lng(op["expected"]), bytes(op["entry"]), nodes)
                } catch (e: ScittLogError) {
                    // a malformed node is refused before anything is written
                }
            }
        }
        p.readBytes()
    }

    @Test fun fileStoreOpen() = OracleCases.each(m, "fileStoreOpen") { a ->
        val p = file("o")
        p.writeBytes(bytes(a[0]))
        FileScittLogStore.open(p).use { s ->
            val entries = ArrayList<Any?>()
            val nodes0 = ArrayList<Any?>()
            val size = s.size()
            var i = 0L
            while (i < size) {
                entries.add(s.getEntry(i))
                nodes0.add(s.getNode(0, i))
                i++
            }
            linkedMapOf<String, Any?>("size" to size, "entries" to entries, "nodes0" to nodes0, "after" to p.readBytes())
        }
    }

    @Test fun checkScittLogStore() = OracleCases.each(m, "checkScittLogStore") { a ->
        if ("memory" == a[0]) DurableTransparencyService.checkScittLogStore { MemoryScittLogStore() }
        else DurableTransparencyService.checkScittLogStore { FileScittLogStore.open(file("c")) }
    }

    // ---- plain tests the oracle cannot cover ----

    @Test fun fileStoreSurvivesReopen() {
        val p = file("reopen")
        val signer = Scitt.ReceiptSignerOpts(CoseAlg.EdDSA, Scitt.ed25519PrivateKey(ByteArray(32)), "ts")
        val root = FileScittLogStore.open(p).use { s ->
            val svc = DurableTransparencyService(s, signer)
            val payload = linkedMapOf<String, Any?>("a" to Json.Num("1"))
            for (i in 0 until 5) svc.appendAndReceipt(payload, Scitt.SignStatementOpts(CoseAlg.EdDSA, Scitt.ed25519PrivateKey(ByteArray(32)), "iss"))
            svc.root()
        }
        FileScittLogStore.open(p).use { s ->
            val svc = DurableTransparencyService(s, signer)
            assertEquals(5L, svc.size())
            assertEquals(root, svc.root())
            assertTrue(Scitt.verifyReceipt(svc.getReceipt(3).receipt, svc.getEntry(3), Scitt.VerifyReceiptOpts().also { it.treeRoot = root }))
        }
    }
}
