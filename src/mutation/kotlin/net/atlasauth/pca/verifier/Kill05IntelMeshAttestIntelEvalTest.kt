package net.atlasauth.pca.verifier

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Intel TDX collateral evaluation: TCB status helpers, the TCB info levels, the QE identity, the wire collateral. */
class Kill05IntelMeshAttestIntelEvalTest {
    private fun <T> p(name: String, vararg a: Any?): T = KUtil.priv(AttestIntel, name, *a)
    private fun f(o: Any?, n: String): Any? = o!!.javaClass.getDeclaredField(n).also { it.isAccessible = true }.get(o)
    private fun num(v: Int) = Json.Num(v.toString())

    /** Date.parse refuses an impossible zone offset (attest-intel-collateral.ts:260-261): never read as another instant. */
    @Test fun collateralDatesRefuseImpossibleOffsets() {
        for (s in listOf("2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00-24:00", "2026-01-01T00:00:00+00:60")) assertEquals(s, null, p<Long?>("jsDateParse", s))
        assertEquals(1767229200000L, p<Long?>("jsDateParse", "2026-01-01T02:00:00+01:00"))
        assertEquals(1767225600000L, p<Long?>("jsDateParse", "2026-01-01"))
    }

    @Test fun statuses() {
        assertEquals("UpToDate", p<String?>("asTcbStatus", "UpToDate"))
        assertEquals("Revoked", p<String?>("asTcbStatus", "Revoked"))
        assertNull(p<String?>("asTcbStatus", "Fine"))
        assertNull(p<String?>("asTcbStatus", num(1)))
        assertNull(p<String?>("asTcbStatus", null))
        assertEquals("OutOfDate", p<String>("worstStatus", "UpToDate", "OutOfDate"))
        assertEquals("OutOfDate", p<String>("worstStatus", "OutOfDate", "UpToDate"))
        assertEquals("Revoked", p<String>("worstStatus", "Revoked", "OutOfDate"))
        // equal rank keeps the first
        assertEquals("X", p<String>("worstStatus", "X", "Y"))
    }

    private fun comps(n: Int, v: Any?): ArrayList<Any?> = ArrayList<Any?>((0 until n).map { KUtil.m("svn" to v) })

    @Test fun svnLists() {
        assertEquals(List(16) { 3.0 }, p<List<Double>?>("svnList", comps(16, num(3))))
        assertNull(p<List<Double>?>("svnList", "x"))
        assertNull(p<List<Double>?>("svnList", comps(15, num(3))))
        assertNull(p<List<Double>?>("svnList", comps(16, "3")))
        val one = comps(16, num(3))
        one[5] = num(3)
        assertNull(p<List<Double>?>("svnList", one))
    }

    @Test fun hexFields() {
        assertArrayEquals(byteArrayOf(0xab.toByte(), 0xcd.toByte()), p<ByteArray?>("hexBytesN", "abCD", 2))
        assertNull(p<ByteArray?>("hexBytesN", num(1), 2))
        assertNull(p<ByteArray?>("hexBytesN", null, 2))
        assertNull(p<ByteArray?>("hexBytesN", "abc", 2))
        assertNull(p<ByteArray?>("hexBytesN", "abcdef", 2))
        assertNull(p<ByteArray?>("hexBytesN", "zzzz", 2))
    }

    @Test fun advisories() {
        assertEquals(listOf("A", "B"), p<List<String>>("advisoryList", KUtil.m("advisoryIDs" to KUtil.l("A", num(1), "B"))))
        assertEquals(emptyList<String>(), p<List<String>>("advisoryList", KUtil.m("advisoryIDs" to "A")))
        assertEquals(emptyList<String>(), p<List<String>>("advisoryList", KUtil.m()))
    }

    private fun isv(v: Any?, st: String): Map<String, Any?> =
        KUtil.m("tcb" to (if (v == null) KUtil.m() else KUtil.m("isvsvn" to v)), "tcbStatus" to st)

    @Test fun levelLookup() {
        val levels = KUtil.l("x", KUtil.m("tcb" to "x"), isv(null, "A"), isv(num(5), "B"), isv(num(3), "C"))
        assertEquals("C", p<Map<String, Any?>?>("findLevel", levels, 4.0)!!["tcbStatus"])
        assertEquals("B", p<Map<String, Any?>?>("findLevel", levels, 5.0)!!["tcbStatus"])
        assertNull(p<Map<String, Any?>?>("findLevel", levels, 2.0))
        assertNull(p<Map<String, Any?>?>("findLevel", "x", 9.0))
    }

    // ---- evaluateTcb ----

    private fun svns(v: Int): ArrayList<Any?> = comps(16, num(v))
    private fun svnsHi01(): ArrayList<Any?> = ArrayList<Any?>((0 until 16).map { KUtil.m("svn" to num(if (it < 2) 200 else 0)) })

    private fun level(sgx: Any?, tdx: Any?, pce: Any?, status: String, vararg adv: String): Map<String, Any?> =
        KUtil.m("tcb" to KUtil.m("sgxtcbcomponents" to sgx, "tdxtcbcomponents" to tdx, "pcesvn" to pce), "tcbStatus" to status, "advisoryIDs" to ArrayList<Any?>(adv.toList()))

    private fun module(mr: Any?, attr: Any?, mask: Any?): Map<String, Any?> = KUtil.m("mrsigner" to mr, "attributes" to attr, "attributesMask" to mask)

    private val goodModule = module("00".repeat(48), "0000000000000000", "ffffffffffffffff")

    private fun info(vararg levels: Any?): MutableMap<String, Any?> = KUtil.m("tdxModule" to goodModule, "tcbLevels" to ArrayList<Any?>(levels.toList()))

    private fun tee(svn0: Int, minor: Int): ByteArray = ByteArray(16) { 5.toByte() }.also { it[0] = svn0.toByte(); it[1] = minor.toByte() }

    /** "platform|module|advisories", or the error. PCK SGX SVNs are all 5, the PCESVN 10. */
    private fun ev(info: Map<String, Any?>, tee: ByteArray): String {
        val r = p<Any>("evaluateTcb", info, ByteArray(16) { 5.toByte() }, 10, tee, ByteArray(48), ByteArray(8))
        val err = f(r, "err") as String
        return if (err != "") err else "${f(r, "platform")}|${f(r, "module")}|${f(r, "advisories")}"
    }

    @Test fun tcbLevels() {
        val t0 = tee(3, 0)
        assertEquals("SWHardeningNeeded|UpToDate|[A, B]",
            ev(info(level(svns(6), svns(0), num(1), "UpToDate"), level(svns(5), svns(0), num(10), "SWHardeningNeeded", "B", "A")), t0))
        assertEquals("TCB info has no tcbLevels", ev(KUtil.m("tdxModule" to goodModule, "tcbLevels" to "x"), t0))
        assertEquals("TCB info has no tcbLevels", ev(KUtil.m("tdxModule" to goodModule), t0))
        val one = KUtil.l(level(svns(5), svns(0), num(10), "UpToDate"))
        for (m in listOf(
            module("00", "0000000000000000", "ffffffffffffffff"),
            module("00".repeat(48), num(0), "ffffffffffffffff"),
            module("00".repeat(48), "0000000000000000", "zzzzzzzzzzzzzzzz"),
        )) assertEquals("TDX module identity fields malformed", ev(KUtil.m("tdxModule" to m, "tcbLevels" to one), t0))
        assertEquals("malformed TCB level", ev(info("x"), t0))
        assertEquals("malformed TCB level", ev(info(KUtil.m("tcb" to "x", "tcbStatus" to "UpToDate")), t0))
        val comp = "malformed TCB level components"
        assertEquals(comp, ev(info(level("x", svns(0), num(10), "UpToDate")), t0))
        assertEquals(comp, ev(info(level(svns(5), comps(15, num(0)), num(10), "UpToDate")), t0))
        assertEquals(comp, ev(info(level(svns(5), svns(0), null, "UpToDate")), t0))

        // minor 0: every TDX component (0 and 1 included) is compared
        assertEquals("platform TCB is below every level in the TCB info", ev(info(level(svns(5), svnsHi01(), num(10), "UpToDate")), t0))

        // minor > 0: the module identity TDX_<minor> applies and TDX components 0 and 1 are skipped
        val ident = KUtil.m(
            "id" to "TDX_01", "mrsigner" to "00".repeat(48), "attributes" to "0000000000000000", "attributesMask" to "ffffffffffffffff",
            "tcbLevels" to KUtil.l(KUtil.m("tcb" to KUtil.m("isvsvn" to num(0)), "tcbStatus" to "OutOfDate", "advisoryIDs" to KUtil.l("M"))),
        )
        val withIds = KUtil.m(
            "tdxModuleIdentities" to KUtil.l("junk", KUtil.m("id" to "TDX_02"), ident),
            "tcbLevels" to KUtil.l(level(svns(5), svnsHi01(), num(10), "UpToDate", "P")),
        )
        assertEquals("UpToDate|OutOfDate|[M, P]", ev(withIds, tee(3, 1)))
        assertEquals("TDX module identity TDX_03 not present in TCB info", ev(info(level(svns(5), svns(0), num(10), "UpToDate")), tee(3, 3)))
    }

    // ---- evaluateQe ----

    private fun qeId(): MutableMap<String, Any?> = KUtil.m(
        "id" to "TD_QE", "version" to num(2), "miscselect" to "00000000", "miscselectMask" to "ffffffff",
        "attributes" to "00".repeat(16), "attributesMask" to "ff".repeat(16), "mrsigner" to "00".repeat(32), "isvprodid" to num(258),
        "tcbLevels" to KUtil.l(KUtil.m("tcb" to KUtil.m("isvsvn" to num(4)), "tcbStatus" to "SWHardeningNeeded", "advisoryIDs" to KUtil.l("Q"))),
    )

    /** ISVPRODID 258 (0x0102, little-endian), ISVSVN 4. */
    private fun qeRep(): ByteArray = ByteArray(384).also {
        it[256] = 2
        it[257] = 1
        it[258] = 4
    }

    private fun eq(id: Map<String, Any?>, qe: ByteArray): String {
        val r = p<Any>("evaluateQe", id, qe)
        val e = f(r, "err") as String
        return if (e != "") e else "${f(r, "status")}|${f(r, "advisories")}"
    }

    @Test fun qeIdentity() {
        assertEquals("SWHardeningNeeded|[Q]", eq(qeId(), qeRep()))
        assertEquals("QE report has wrong length", eq(qeId(), qeRep().copyOf(383)))
        assertEquals("QE MISCSELECT does not match the QE identity", eq(qeId(), qeRep().also { it[16] = 1 }))
        assertEquals("QE ISVPRODID does not match the QE identity", eq(qeId(), qeRep().also { it[257] = 0 }))
        for (key in listOf("miscselect", "miscselectMask", "attributes", "attributesMask", "mrsigner", "isvprodid")) {
            assertEquals(key, "QE identity fields malformed", eq(qeId().also { it.remove(key) }, qeRep()))
        }
    }

    @Test fun wireCollateral() {
        val c = AttestIntel.collateralFromWire(KUtil.m("tcbInfoJson" to num(5), "qeIdentityJson" to "q", "pckCrlDer" to "AQI="))
        assertEquals("", c.tcbInfoJson)
        assertEquals("q", c.qeIdentityJson)
        assertEquals("", c.tcbInfoChain)
        assertArrayEquals(byteArrayOf(1, 2), c.pckCrl)
        assertEquals(0, c.rootCrl.size)
        val d = AttestIntel.collateralFromWire(KUtil.m("rootCrlDer" to "AQI="))
        assertArrayEquals(byteArrayOf(1, 2), d.rootCrl)
        assertEquals(0, d.pckCrl.size)
    }

    private fun tdxSvns(f: (Int) -> Int): ArrayList<Any?> = ArrayList<Any?>((0 until 16).map { KUtil.m("svn" to num(f(it))) })

    private fun withModule(tdx: ArrayList<Any?>): Map<String, Any?> = KUtil.m(
        "tdxModuleIdentities" to KUtil.l(KUtil.m(
            "id" to "TDX_01", "mrsigner" to "00".repeat(48), "attributes" to "0000000000000000", "attributesMask" to "ffffffffffffffff",
            "tcbLevels" to KUtil.l(KUtil.m("tcb" to KUtil.m("isvsvn" to num(0)), "tcbStatus" to "UpToDate")),
        )),
        "tcbLevels" to KUtil.l(level(svns(5), tdx, num(10), "UpToDate")),
    )

    @Test fun tdxComponentsComparedFromTheRightIndex() {
        val below = "platform TCB is below every level in the TCB info"
        // minor 0: component 0 (the TEE SVN, 3 here) is compared
        assertEquals(below, ev(info(level(svns(5), tdxSvns { if (it == 0) 4 else 0 }, num(10), "UpToDate")), tee(3, 0)))
        assertEquals("UpToDate|UpToDate|[]", ev(info(level(svns(5), tdxSvns { if (it == 0) 3 else 0 }, num(10), "UpToDate")), tee(3, 0)))
        // minor > 0: components 0 and 1 are skipped, component 2 (5 here) is compared
        assertEquals(below, ev(withModule(tdxSvns { if (it < 2) 200 else if (it == 2) 6 else 0 }), tee(3, 1)))
        assertEquals("UpToDate|UpToDate|[]", ev(withModule(tdxSvns { if (it < 2) 200 else if (it == 2) 5 else 0 }), tee(3, 1)))
    }

    @Test fun moduleIdentitiesThatAreNotAListAreAbsent() {
        for (bad in listOf<Any?>("x", num(1), KUtil.m("id" to "TDX_01"))) {
            val i = info(level(svns(5), svns(0), num(10), "UpToDate"))
            i["tdxModuleIdentities"] = bad
            assertEquals("TDX module identity TDX_01 not present in TCB info", ev(i, tee(3, 1)))
        }
    }

    @Test fun qeIsvsvnIsLittleEndian16() {
        val id = qeId()
        id["tcbLevels"] = KUtil.l(
            KUtil.m("tcb" to KUtil.m("isvsvn" to num(516)), "tcbStatus" to "OutOfDate"),
            KUtil.m("tcb" to KUtil.m("isvsvn" to num(260)), "tcbStatus" to "UpToDate"),
            KUtil.m("tcb" to KUtil.m("isvsvn" to num(4)), "tcbStatus" to "SWHardeningNeeded"),
        )
        // ISVSVN bytes 258..259 = 04 01: 0x0104 = 260
        assertEquals("UpToDate|[]", eq(id, qeRep().also { it[259] = 1 }))
        assertEquals("SWHardeningNeeded|[]", eq(id, qeRep()))
        // 0x0204 = 516
        assertEquals("OutOfDate|[]", eq(id, qeRep().also { it[259] = 2 }))
    }
}
