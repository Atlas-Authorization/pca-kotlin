package net.atlasauth.pca.ratchet

import net.atlasauth.pca.frost.Frost
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.fail
import org.junit.Test

/** Point validation is fail-closed whatever libsodium build answers its validity query: B + T (T of order 2) is mixed-order and must be refused. */
class EdwardsMixedOrderTest {
    private fun filled(first: Int, mid: Int, last: Int) = ByteArray(32) { mid.toByte() }.also { it[0] = first.toByte(); it[31] = last.toByte() }

    private val base = filled(0x58, 0x66, 0x66)
    private val t2 = filled(0xEC, 0xFF, 0x7F) // (0, -1), order 2
    private val nonCanon = filled(0xEE, 0xFF, 0x7F) // y = p + 1

    @Test
    fun decodeSafePointRefusesTorsion() {
        val mixed = EdwardsPoint.fromBytes(base).add(EdwardsPoint.fromBytes(t2)).toBytes()
        assertArrayEquals(base, Frost.decodeSafePoint(base).toBytes())
        val neg = base.clone().also { it[31] = (it[31].toInt() or 0x80).toByte() }
        assertArrayEquals(neg, Frost.decodeSafePoint(neg).toBytes())
        val identity = ByteArray(32).also { it[0] = 1 }
        for (bad in listOf(mixed, t2, identity, ByteArray(32), nonCanon)) {
            try { Frost.decodeSafePoint(bad); fail("accepted") } catch (e: IllegalArgumentException) { }
        }
    }
}
