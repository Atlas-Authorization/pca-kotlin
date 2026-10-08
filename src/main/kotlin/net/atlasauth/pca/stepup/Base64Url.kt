package net.atlasauth.pca.stepup

/** Unpadded base64url (RFC 4648 section 5). Pure Kotlin so it behaves the same on JVM tests and Android. */
internal object Base64Url {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val REVERSE = IntArray(128) { -1 }.also { r -> ALPHABET.forEachIndexed { i, c -> r[c.code] = i } }

    fun encode(data: ByteArray): String {
        val sb = StringBuilder((data.size * 4 + 2) / 3)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xff
            val b1 = if (i + 1 < data.size) data[i + 1].toInt() and 0xff else 0
            val b2 = if (i + 2 < data.size) data[i + 2].toInt() and 0xff else 0
            sb.append(ALPHABET[b0 shr 2])
            sb.append(ALPHABET[((b0 and 3) shl 4) or (b1 shr 4)])
            if (i + 1 < data.size) sb.append(ALPHABET[((b1 and 15) shl 2) or (b2 shr 6)])
            if (i + 2 < data.size) sb.append(ALPHABET[b2 and 63])
            i += 3
        }
        return sb.toString()
    }

    /** Null for malformed input (padding tolerated). */
    fun decode(input: String): ByteArray? {
        val s = input.trimEnd('=')
        if (s.length % 4 == 1) return null
        val out = ArrayList<Byte>(s.length * 3 / 4)
        var buf = 0
        var bits = 0
        for (ch in s) {
            val v = if (ch.code < 128) REVERSE[ch.code] else -1
            if (v < 0) return null
            buf = (buf shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.add(((buf shr bits) and 0xff).toByte())
                buf = buf and ((1 shl bits) - 1)
            }
        }
        return out.toByteArray()
    }
}
