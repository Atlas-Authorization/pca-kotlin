package net.atlasauth.pca.bbs

import java.math.BigInteger
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.util.TreeSet
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys

/**
 * PCA layer: a capability as a multi-message BBS credential with selective disclosure. The message vector is
 * `iss`, `sub`, then one message per caveat named `cav:<i>:<type>` whose value is the strict-canonical JSON
 * of the caveat; each message's octets are `utf8(name) || 0x00 || utf8(value)`. Credentials, attributes and
 * presentations are JSON maps with the same member names as the TypeScript types.
 */
@Suppress("UNCHECKED_CAST")
object BbsCredential {
    /** UTF-8 with U+FFFD for an unpaired surrogate (what a JavaScript TextEncoder produces). */
    private fun utf8(s: String): ByteArray {
        val b = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE)
            .replaceWith(byteArrayOf(0xEF.toByte(), 0xBF.toByte(), 0xBD.toByte())).encode(CharBuffer.wrap(s))
        val out = ByteArray(b.remaining())
        b.get(out)
        return out
    }

    internal fun encodeAttribute(name: Any?, value: Any?): ByteArray {
        if (name !is String || value !is String) throw IllegalArgumentException("attribute name and value must be strings")
        if (name.indexOf('\u0000') >= 0) throw IllegalArgumentException("attribute name must not contain NUL")
        val n = utf8(name)
        val v = utf8(value)
        val out = ByteArray(n.size + 1 + v.size)
        System.arraycopy(n, 0, out, 0, n.size)
        System.arraycopy(v, 0, out, n.size + 1, v.size)
        return out
    }

    private fun asMap(o: Any?): Map<String, Any?> {
        if (o !is Map<*, *>) throw IllegalArgumentException("not an object")
        return o as Map<String, Any?>
    }

    private fun asList(o: Any?): List<Any?> {
        if (o !is List<*>) throw IllegalArgumentException("not an array")
        return o as List<Any?>
    }

    private fun encode(attr: Any?): ByteArray {
        val a = asMap(attr)
        return encodeAttribute(a["name"], a["value"])
    }

    private fun encodeAll(attrs: Any?): List<ByteArray> = asList(attrs).map { encode(it) }

    private fun attr(index: Int, name: String, value: Any?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["index"] = Json.Num(index.toString())
        m["name"] = name
        m["value"] = value
        return m
    }

    /** The ordered attribute vector for a capability: issuer, holder, then each caveat. */
    fun capabilityAttributes(capability: Map<String, Any?>): List<Map<String, Any?>> {
        val attrs = ArrayList<Map<String, Any?>>()
        attrs.add(attr(0, "iss", capability["issuer"]))
        attrs.add(attr(1, "sub", capability["holder"]))
        val cs = capability["caveats"]
        if (cs is List<*>) {
            for (i in cs.indices) {
                val cv = asMap(cs[i])
                attrs.add(attr(i + 2, "cav:" + i + ":" + cv["type"], Json.canonicalizeStrict(cv)))
            }
        }
        return attrs
    }

    /** Sign a capability's attributes as a BBS credential; `header` is optional application context (null = empty). */
    fun issueCapabilityCredential(capability: Map<String, Any?>, sk: BigInteger, pk: ByteArray, header: ByteArray?): Map<String, Any?> {
        val attributes = capabilityAttributes(capability)
        val hdr = header ?: ByteArray(0)
        val signature = Bbs.sign(sk, pk, hdr, encodeAll(attributes))
        val cred = LinkedHashMap<String, Any?>()
        cred["issuerPublicKey"] = Keys.b64u(pk)
        cred["header"] = Keys.b64u(hdr)
        cred["attributes"] = attributes
        cred["signature"] = Keys.b64u(signature)
        return cred
    }

    /** Verify a whole credential against its issuer key (every attribute). Never throws. */
    fun verifyCredential(cred: Map<String, Any?>): Boolean {
        val pk: ByteArray
        val header: ByteArray
        val signature: ByteArray
        try {
            pk = Keys.unb64u(cred["issuerPublicKey"] as String)
            header = Keys.unb64u(cred["header"] as String)
            signature = Keys.unb64u(cred["signature"] as String)
        } catch (e: RuntimeException) {
            return false
        }
        return try {
            Bbs.verify(pk, signature, header, encodeAll(cred["attributes"]))
        } catch (e: RuntimeException) {
            false
        }
    }

    private fun indexOf(attr: Any?): Int {
        val i = asMap(attr)["index"]
        val d = if (i is Json.Num) i.raw.toDouble() else Double.NaN
        if (d != Math.rint(d) || d.isInfinite() || Math.abs(d) > Int.MAX_VALUE) throw IllegalArgumentException("attribute index is not an integer")
        return d.toInt()
    }

    /** Selective-disclosure presentation revealing only the named attributes; `presentationHeader` binds it to a context (null = empty). The proof is randomized. */
    fun presentCredential(cred: Map<String, Any?>, disclose: List<String>, presentationHeader: ByteArray?): Map<String, Any?> {
        val pk = Keys.unb64u(cred["issuerPublicKey"] as String)
        val header = Keys.unb64u(cred["header"] as String)
        val signature = Keys.unb64u(cred["signature"] as String)
        val ph = presentationHeader ?: ByteArray(0)
        val wanted = TreeSet(disclose)
        val messages = encodeAll(cred["attributes"])
        val idx = ArrayList<Int>()
        val disclosed = ArrayList<Any?>()
        for (a in asList(cred["attributes"])) {
            val n = asMap(a)["name"]
            if (n is String && wanted.contains(n)) {
                idx.add(indexOf(a))
                disclosed.add(a)
            }
        }
        val missing = ArrayList<String>()
        for (w in wanted) {
            if (disclosed.none { w == asMap(it)["name"] }) missing.add(w)
        }
        if (missing.isNotEmpty()) throw IllegalArgumentException("presentCredential: unknown attribute(s): " + missing.joinToString(", "))
        val proof = Bbs.proofGen(pk, signature, header, ph, messages, idx)
        val pres = LinkedHashMap<String, Any?>()
        pres["issuerPublicKey"] = cred["issuerPublicKey"]
        pres["header"] = cred["header"]
        pres["presentationHeader"] = Keys.b64u(ph)
        pres["messageCount"] = Json.Num(asList(cred["attributes"]).size.toString())
        pres["disclosed"] = disclosed
        pres["proof"] = Keys.b64u(proof)
        return pres
    }

    /**
     * Check a presentation. `pk`, `disclosed` and `presentationHeader` default (when null) to the values the presentation
     * carries; pass them to assert the verifier's own expectations. Never throws.
     */
    fun verifyPresentation(pres: Map<String, Any?>, pk: ByteArray?, disclosed: List<Map<String, Any?>>?, presentationHeader: ByteArray?): Boolean {
        val pkb: ByteArray
        val header: ByteArray
        val proof: ByteArray
        try {
            pkb = pk ?: Keys.unb64u(pres["issuerPublicKey"] as String)
            header = Keys.unb64u(pres["header"] as String)
            proof = Keys.unb64u(pres["proof"] as String)
        } catch (e: RuntimeException) {
            return false
        }
        if (pk != null && Keys.b64u(pk) != pres["issuerPublicKey"]) return false
        val ph: ByteArray
        if (presentationHeader != null) {
            ph = presentationHeader
        } else {
            try {
                ph = Keys.unb64u(pres["presentationHeader"] as String)
            } catch (e: RuntimeException) {
                return false
            }
        }
        if (presentationHeader != null && presentationHeader.isNotEmpty() && Keys.b64u(ph) != pres["presentationHeader"]) return false
        return try {
            verifyInner(pres, pkb, header, proof, ph, disclosed)
        } catch (e: RuntimeException) {
            false
        }
    }

    private fun key(x: Any?): String {
        val a = asMap(x)
        return indexOf(x).toString() + "\u0000" + a["name"] + "\u0000" + a["value"]
    }

    private fun sameDisclosure(a: List<Any?>, b: List<Any?>): Boolean {
        if (a.size != b.size) return false
        return a.map { key(it) }.sorted() == b.map { key(it) }.sorted()
    }

    private fun verifyInner(pres: Map<String, Any?>, pk: ByteArray, header: ByteArray, proof: ByteArray, ph: ByteArray, optsDisclosed: List<Map<String, Any?>>?): Boolean {
        val disclosed: List<Any?> = optsDisclosed ?: asList(pres["disclosed"])
        if (optsDisclosed != null && !sameDisclosure(optsDisclosed, asList(pres["disclosed"]))) return false
        for (o in disclosed) indexOf(o) // an attribute without an integer index fails closed
        val ordered = disclosed.sortedBy { indexOf(it) }
        val msgs = ordered.map { encode(it) }
        val idx = ordered.map { indexOf(it) }
        val mc = pres["messageCount"]
        val count = if (mc is Json.Num) mc.raw.toDouble() else Double.NaN
        for (i in idx) if (i >= count || i < 0) return false
        return Bbs.proofVerify(pk, proof, header, ph, msgs, idx)
    }
}
