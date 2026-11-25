package net.atlasauth.pca.abe

import java.io.File
import java.math.BigInteger
import net.atlasauth.pca.verifier.Json
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import supranational.blst.P1
import supranational.blst.P2

/** FAME group elements against an independent implementation (py_ecc): setup, keygen and encrypt with fixed scalars, byte for byte. */
@Suppress("UNCHECKED_CAST")
class FamePyeccTest {
    private fun map(o: Any?) = o as Map<String, Any?>

    private fun unhex(s: Any?): BigInteger = BigInteger(s as String, 16)

    private fun scalars(list: Any?): Array<BigInteger> = (list as List<Any?>).map { unhex(it) }.toTypedArray()

    private fun hex(b: ByteArray): String = String.format("%0" + (2 * b.size) + "x", BigInteger(1, b))

    private fun hex1(p: Array<P1>): List<String> = p.map { hex(it.compress()) }

    private fun hex2(p: Array<P2>): List<String> = p.map { hex(it.compress()) }

    @Test fun matchesPyEcc() {
        val doc = map(Json.parseLenient(File("test-data/fame-pyecc/fame-pyecc.json").readText()))
        for (co in doc["cases"] as List<Any?>) {
            val c = map(co)
            val name = c["name"] as String
            val n = AbePolicy.normalize(c["policy"])
            val tree = n.tree
            assertNotNull(name, tree)
            val attrs = (c["attrs"] as List<Any?>).map { it as String }
            val s = map(c["scalars"])
            val ms = Fame.setup(scalars(s["a"]), scalars(s["b"]), scalars(s["d"]))
            val key = Fame.keygen(ms.msk, attrs, scalars(s["r"]), scalars(s["sigma"]).toList(), unhex(s["sigmaPrime"]))
            val e = Fame.encrypt(ms.mpk, tree!!, scalars(s["s"]))
            assertEquals("$name h", c["h"].toString(), listOf(hex(ms.mpk.h1.compress()), hex(ms.mpk.h2.compress())).toString())
            assertEquals("$name mskg", c["mskg"].toString(), hex1(ms.msk.g).toString())
            assertEquals("$name k0", c["k0"].toString(), hex2(key.k0).toString())
            assertEquals("$name kp", c["kp"].toString(), hex1(key.kp).toString())
            for ((attr, want) in map(c["key"])) assertEquals("$name key $attr", want.toString(), hex1(key.attrs[attr]!!).toString())
            assertEquals("$name ct0", c["ct0"].toString(), hex2(e.ct.ct0).toString())
            assertEquals("$name rows", (c["rows"] as List<Any?>).map { it.toString() }, e.ct.rows.map { hex1(it).toString() })
            // the reference decrypted these with the attribute set it was issued; so must the native
            val dec = Fame.decrypt(key, tree, e.ct)
            if (AbePolicy.satisfies(tree, attrs.toSet())) assertArrayEquals("$name decrypt", e.k, dec)
        }
    }
}
