package net.atlasauth.pca.abe

import java.math.BigInteger
import net.atlasauth.pca.aggsig.Oracle
import net.atlasauth.pca.aggsig.Oracle.bytes
import net.atlasauth.pca.aggsig.Oracle.bytesList
import net.atlasauth.pca.pairing.Bls12
import net.atlasauth.pca.pairing.Gt
import org.junit.Test
import supranational.blst.P1
import supranational.blst.P2

/** Replays the TypeScript-reference corpus (test-data/ref-abe.json.gz) through the native FAME port. */
@Suppress("UNCHECKED_CAST")
class AbeDiffTest {
    private val m = "ref-abe"

    private fun map(o: Any?) = o as Map<String, Any?>

    private fun unhex(s: Any?): BigInteger = BigInteger(s as String, 16)

    private fun scalars(list: Any?): Array<BigInteger> = (list as List<Any?>).map { unhex(it) }.toTypedArray()

    private fun strings(list: Any?): List<String> = (list as List<Any?>).map { it as String }

    private fun g1s(p: Array<P1>): List<Any?> = p.map { it.compress() }

    private fun g2s(p: Array<P2>): List<Any?> = p.map { it.compress() }

    @Test fun genCorpusIsPresent() {
        val p = Oracle.genFile(m).toPath()
        val msg = "secret oracle corpus missing: $p (generate with gen-secret-corpus.sh or set PCA_SECRET_CORPUS_DIR)"
        val ci = System.getenv("CI")
        if (ci == "true" || ci == "1") org.junit.Assert.assertTrue(msg, java.nio.file.Files.exists(p)) else org.junit.Assume.assumeTrue(msg, java.nio.file.Files.exists(p))
    }

    @Test fun fame() = Oracle.each(m, "fame") { a ->
        val n = AbePolicy.normalize(a[0])
        val tree = n.tree ?: throw IllegalArgumentException(n.reason)
        val attrs = strings(a[1])
        val s = map(a[2])
        val ms = Fame.setup(scalars(s["a"]), scalars(s["b"]), scalars(s["d"]))
        val key = Fame.keygen(ms.msk, attrs, scalars(s["r"]), scalars(s["sigma"]).toList(), unhex(s["sigmaPrime"]))
        val e = Fame.encrypt(ms.mpk, tree, scalars(s["s"]))
        val dec = Fame.decrypt(key, tree, e.ct)
        linkedMapOf<String, Any?>(
            "h" to listOf(ms.mpk.h1.compress(), ms.mpk.h2.compress()),
            "t" to listOf(ms.mpk.t1, ms.mpk.t2),
            "mskg" to g1s(ms.msk.g),
            "k0" to g2s(key.k0),
            "kp" to g1s(key.kp),
            "key" to key.attrs.mapValuesTo(LinkedHashMap()) { g1s(it.value) },
            "ct0" to g2s(e.ct.ct0),
            "rows" to e.ct.rows.map { g1s(it) },
            "k" to e.k,
            "dec" to dec,
        )
    }

    @Test fun gtIsElement() = Oracle.each(m, "gtIsElement") { a -> Gt.isElement(bytes(a[0])) }
    @Test fun gtPow() = Oracle.each(m, "gtPow") { a -> Gt.pow(bytes(a[0]), unhex(a[1])) }
    @Test fun gtMul() = Oracle.each(m, "gtMul") { a -> Gt.mul(bytes(a[0]), bytes(a[1])) }

    @Test fun pairingProduct() = Oracle.each(m, "pairingProduct") { a ->
        Gt.pairingProduct(bytesList(a[0]).map { Bls12.decodeG1(it) }, bytesList(a[1]).map { Bls12.decodeG2(it) })
    }

    @Test fun normalizePolicy() = Oracle.each(m, "normalizePolicy") { a -> AbePolicy.normalize(a[0]).toJson() }
    @Test fun satisfies() = Oracle.each(m, "satisfies") { a -> AbePolicy.satisfies(map(a[0]), strings(a[1]).toSet()) }
    @Test fun policyAttributes() = Oracle.each(m, "policyAttributes") { a -> AbePolicy.policyAttributes(map(a[0])) }
    @Test fun parseCiphertext() = Oracle.each(m, "parseCiphertext") { a -> Abe.parseCiphertext(a[0]) }
    @Test fun decrypt() = Oracle.each(m, "decrypt") { a -> Abe.decrypt(a[0], a[1]) }
    @Test fun decryptText() = Oracle.each(m, "decryptText") { a -> Abe.decryptText(a[0], a[1]) }
    @Test fun decryptWithCapability() = Oracle.each(m, "decryptWithCapability") { a -> Abe.decryptWithCapability(a[0], a[1]) }

    @Test fun encryptAccepts() = Oracle.each(m, "encryptAccepts") { a ->
        Abe.encryptForPolicy(a[0], a[1], "x")
        true
    }

    @Test fun keygenForAttributes() = Oracle.each(m, "keygenForAttributes") { a ->
        map(Abe.keygenForAttributes(a[0], strings(a[1]))["attrs"]).keys.toList()
    }

    @Test fun keygenForCapability() = Oracle.each(m, "keygenForCapability") { a ->
        val k = Abe.keygenForCapability(a[0], map(a[1]), strings(a[2]), map(a[3]))
        linkedMapOf("holder" to k["holder"], "attrs" to map(k["attrs"]).keys.toList())
    }

    @Test fun capabilityAttributes() = Oracle.each(m, "capabilityAttributes") { a ->
        Abe.capabilityAttributes(map(a[0]), map(a[1])).toSortedSet().toList()
    }
}
