package net.atlasauth.pca.verifier

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.bouncycastle.math.ec.rfc8032.Ed25519

/** Shared builders of the Intent Layer v2 kill tests: JSON trees, deterministic keys `sha256("atlas-pca-conformance/" + label)`. */
object IntentTestKit {
    fun jm(vararg kv: Any?): LinkedHashMap<String, Any?> {
        val r = LinkedHashMap<String, Any?>()
        var i = 0
        while (i < kv.size) { r[kv[i] as String] = kv[i + 1]; i += 2 }
        return r
    }
    fun jl(vararg xs: Any?): ArrayList<Any?> = ArrayList(xs.toList())
    @Suppress("UNCHECKED_CAST") fun mm(o: Any?): MutableMap<String, Any?> = o as MutableMap<String, Any?>
    @Suppress("UNCHECKED_CAST") fun ml(o: Any?): MutableList<Any?> = o as MutableList<Any?>
    fun seed(label: String): ByteArray = MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/$label".toByteArray(StandardCharsets.UTF_8))
    fun pub(label: String): String { val pk = ByteArray(32); Ed25519.generatePublicKey(seed(label), 0, pk, 0); return Pca.b64(pk) }
    fun sign(label: String, msg: ByteArray): String { val sig = ByteArray(64); Ed25519.sign(seed(label), 0, msg, 0, msg.size, sig, 0); return Pca.b64(sig) }
    fun b64seed(label: String): String = Pca.b64(seed(label))
    @Suppress("UNCHECKED_CAST") fun norm(o: Any?): Map<String, Any?> = IntentJs.normalize(o) as Map<String, Any?>
}
