package net.atlasauth.pca.verifier

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.GZIPInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Differential against the TS reference for the agent mesh: test-data/k05-mesh.json.gz from
 * tools/pca-audit/k05-oracles/mesh-oracle.mts. fn -> Kotlin:
 *   verifyMeshProof(p, t)            Mesh.verifyMeshProof            ok + reason + hop exact ("chain:" refusals by prefix: the
 *                                                                     chain verifier words its own detail, as MeshVectorsTest)
 *   checkHeadAdvance(prev, next, pf) Mesh.checkHeadAdvance (private)  "" <-> null, else the exact reason
 *   verifyLedgerConsistency(a, b, pf) Ledger.verifyConsistency       exact boolean
 *   verifyNonMembership(root, nm, id) Revocation.verifyNonMembership exact boolean; also Mesh.nonMembership (private, the
 *                                                                     expanded {size, lo?, hi?} form the mesh verifier uses)
 *   effectiveAuthority(cs)           Mesh.effective (private)         {error} exact, else every member exact
 * An empty previous head (size 0, root '') advancing is pinned by emptyHeadAdvances ('' is checked as EMPTY_TREE_ROOT).
 */
class K05MeshDiffTest {
    companion object {
        const val FILE = "k05-mesh.json.gz"
        fun of(fn: String): List<Map<String, Any?>> = K05Oracle.cases(FILE, fn, false).also { assertFalse("no oracle cases for $fn", it.isEmpty()) }
        @Suppress("UNCHECKED_CAST") fun args(c: Map<String, Any?>) = c["args"] as List<Any?>
        fun report(bad: List<String>, n: Int) = assertTrue("${bad.size}/$n divergent case(s):\n" + bad.take(40).joinToString("\n"), bad.isEmpty())
    }

    @Test fun verifyMeshProof() {
        val bad = ArrayList<String>()
        val cs = of("verifyMeshProof")
        for (c in cs) {
            val a = args(c)
            val o = c["out"] as Map<*, *>
            val wantOk = o["ok"] == true
            val wantReason = o["reason"] as? String ?: ""
            val wantHop = if (o.containsKey("hop")) IntentJs.lng(o["hop"]).toInt() else -1
            val v = try { Mesh.verifyMeshProof(a[0], a[1]) } catch (t: Throwable) { bad.add("${c["name"]}: THROWS $t"); continue }
            val reasonOk = if (wantReason.startsWith("chain:")) v.reason.startsWith("chain:") else v.reason == wantReason
            if (v.ok != wantOk || !reasonOk || v.hop != wantHop) bad.add("${c["name"]}\n  want: $wantOk|$wantReason|$wantHop\n  got:  ${v.ok}|${v.reason}|${v.hop}")
        }
        report(bad, cs.size)
    }

    @Test fun checkHeadAdvance() {
        val bad = ArrayList<String>()
        val cs = of("checkHeadAdvance")
        for (c in cs) {
            val a = args(c)
            val want = c["out"] as String?
            val got = try { KUtil.priv<String>(Mesh, "checkHeadAdvance", a[0], a[1], a.getOrNull(2)).ifEmpty { null } } catch (t: Throwable) { "THROWS $t" }
            if (want != got) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad, cs.size)
    }

    @Test fun verifyLedgerConsistency() {
        val bad = ArrayList<String>()
        val cs = of("verifyLedgerConsistency")
        for (c in cs) {
            val a = args(c)
            val got = try { Ledger.verifyConsistency(a[0], a[1], a[2]) } catch (t: Throwable) { "THROWS $t" }
            if (c["out"] != got) bad.add("${c["name"]}\n  want: ${c["out"]}\n  got:  $got")
        }
        report(bad, cs.size)
    }

    @Test fun verifyNonMembership() {
        val bad = ArrayList<String>()
        val cs = of("verifyNonMembership")
        for (c in cs) {
            val a = args(c)
            val root = a[0] as String; val id = a[2] as String
            val got = try { Revocation.verifyNonMembership(root, a[1], id) } catch (t: Throwable) { "THROWS $t" }
            if (c["out"] != got) bad.add("${c["name"]} (Revocation)\n  want: ${c["out"]}\n  got:  $got")
            if (a[1] is Map<*, *>) {
                val m = try { KUtil.priv<Boolean>(Mesh, "nonMembership", root, a[1], id) } catch (t: Throwable) { "THROWS $t" }
                if (c["out"] != m) bad.add("${c["name"]} (Mesh)\n  want: ${c["out"]}\n  got:  $m")
            }
        }
        report(bad, cs.size)
    }

    private fun authority(): Any {
        val k = Class.forName("net.atlasauth.pca.verifier.Mesh\$Authority")
        return k.getDeclaredConstructor().also { it.isAccessible = true }.newInstance()
    }
    private fun field(o: Any, n: String): Any? = o.javaClass.getDeclaredField(n).also { it.isAccessible = true }.get(o)

    @Test fun effectiveAuthority() {
        val bad = ArrayList<String>()
        val cs = of("effectiveAuthority")
        for (c in cs) {
            val want = c["out"] as Map<*, *>
            val got: Any? = try {
                val e = authority()
                val why = KUtil.priv<String>(Mesh, "effective", args(c)[0], e)
                if (why != "") mapOf("error" to why) else {
                    val r = LinkedHashMap<String, Any?>()
                    r["prefixes"] = field(e, "prefixes")
                    if (field(e, "hasAct") == true) r["actions"] = field(e, "actions")
                    if (field(e, "hasAmount") == true) r["maxAmount"] = field(e, "maxAmount")
                    if (field(e, "hasExp") == true) r["expiresAt"] = field(e, "expiresAt")
                    if (field(e, "hasAud") == true) r["audience"] = field(e, "audience")
                    if (field(e, "hasHops") == true) r["maxHops"] = field(e, "maxHops")
                    r
                }
            } catch (t: Throwable) { "THROWS $t" }
            if (!IntentJs.jsonEquals(want, got)) bad.add("${c["name"]}\n  want: $want\n  got:  $got")
        }
        report(bad, cs.size)
    }

    /** a head pinned at size 0 (root '') advances: '' is checked as the RFC 9162 empty-tree root; a non-vacuous or mis-sized proof is refused. */
    @Suppress("UNCHECKED_CAST")
    @Test fun emptyHeadAdvances() {
        val j = Json.parseLenient("{\"e\":{\"domain\":\"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A\",\"size\":0,\"root\":\"\",\"rev_root\":\"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8\",\"rev_size\":0,\"timestamp\":1800000000000},\"n\":{\"domain\":\"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A\",\"size\":3,\"root\":\"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow\",\"rev_root\":\"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8\",\"rev_size\":0,\"timestamp\":1800000000000},\"ok\":{\"oldSize\":0,\"newSize\":3,\"path\":[]},\"path\":{\"oldSize\":0,\"newSize\":3,\"path\":[\"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow\"]},\"old1\":{\"oldSize\":1,\"newSize\":3,\"path\":[]}}") as Map<String, Any?>
        fun adv(pf: Any?) = KUtil.priv<String>(Mesh, "checkHeadAdvance", j["e"], j["n"], pf)
        assertEquals("", adv(j["ok"]))
        assertEquals("consistency proof required for a larger head", adv(null))
        assertEquals("head is not consistent with the previous head (fork or rewrite)", adv(j["path"]))
        assertEquals("consistency proof required for a larger head", adv(j["old1"]))
    }
}
