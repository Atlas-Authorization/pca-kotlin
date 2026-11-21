package net.atlasauth.pca.scitt

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * A file-backed [ScittLogStore]: one append-only file of checksummed transactions (entry plus its new subtree hashes), fsynced
 * before [append] returns, so a crash leaves either the whole transaction or none of it. A torn final record is discarded on
 * open; corruption anywhere else throws `store_corrupt`. SINGLE PROCESS: it does not lock the file, so run one writer per
 * directory (use a database-backed store for a fleet). The file format is byte-identical to the TypeScript reference.
 */
class FileScittLogStore private constructor(private val file: RandomAccessFile) : ScittLogStore, AutoCloseable {
    private class Off(val at: Long, val len: Int)

    private val nodes = HashMap<String, ByteArray>()
    private val offsets = ArrayList<Off>()
    private var end = 0L

    @Synchronized override fun close() {
        file.close()
    }

    private fun read(at: Long, len: Long): ByteArray {
        val b = ByteArray(len.toInt())
        var got = 0
        file.seek(at)
        while (got < len) {
            val n = file.read(b, got, len.toInt() - got)
            if (n <= 0) break
            got += n
        }
        return if (got.toLong() == len) b else b.copyOf(got)
    }

    private fun load() {
        val total = file.length()
        var pos = 0L
        while (pos < total) {
            val head = read(pos, 4)
            val len = if (head.size == 4) u32(head, 0) else -1L
            val recEnd = pos + 4 + len + 32
            if (len < 6 || recEnd > total) {
                discardTail(pos, recEnd > total)
                return
            }
            val payload = read(pos + 4, len)
            val sum = read(pos + 4 + len, 32)
            if (!MessageDigest.isEqual(sha256(payload), sum)) {
                discardTail(pos, recEnd == total)
                return
            }
            val entryLen = u32(payload, 0)
            var p = 4 + entryLen
            if (p + 2 > len) throw ScittLogError("store_corrupt", "a log record has an inconsistent length")
            val count = ByteBuffer.wrap(payload).getShort(p.toInt()).toInt() and 0xffff
            p += 2
            if (p + count.toLong() * 40 != len) throw ScittLogError("store_corrupt", "a log record has an inconsistent length")
            offsets.add(Off(pos + 8, entryLen.toInt()))
            for (i in 0 until count) {
                val ip = p.toInt()
                nodes["${payload[ip].toInt() and 0xff}:${u32(payload, ip + 1)}"] = payload.copyOfRange(ip + 8, ip + 40)
                p += 40
            }
            pos = recEnd
        }
        end = pos
    }

    private fun discardTail(pos: Long, isTail: Boolean) {
        if (!isTail) throw ScittLogError("store_corrupt", "the log file is corrupt at offset $pos")
        file.setLength(pos)
        file.fd.sync()
        end = pos
    }

    @Synchronized override fun size(): Long = offsets.size.toLong()

    @Synchronized override fun getEntry(index: Long): ByteArray? {
        if (index < 0 || index >= offsets.size) return null
        val o = offsets[index.toInt()]
        return read(o.at, o.len.toLong())
    }

    @Synchronized override fun getNode(level: Long, index: Long): ByteArray? = nodes["$level:$index"]?.clone()

    @Synchronized override fun append(expectedSize: Long, entry: ByteArray, nodes: List<ScittLogStore.StoredNode>): Boolean {
        if (offsets.size.toLong() != expectedSize) return false
        for (n in nodes) {
            if (n.level < 0 || n.level > 255 || n.index < 0 || n.index > 0xffffffffL || n.hash.size != 32) {
                throw ScittLogError("store_corrupt", "a subtree node is malformed")
            }
        }
        val payload = ByteBuffer.allocate(4 + entry.size + 2 + nodes.size * 40)
        payload.putInt(entry.size)
        payload.put(entry)
        payload.putShort(nodes.size.toShort())
        for (n in nodes) {
            payload.put(n.level.toByte())
            payload.putInt(n.index.toInt())
            payload.put(ByteArray(3))
            payload.put(n.hash)
        }
        val pl = payload.array()
        val rec = ByteBuffer.allocate(4 + pl.size + 32)
        rec.putInt(pl.size)
        rec.put(pl)
        rec.put(sha256(pl))
        file.seek(end)
        file.write(rec.array())
        file.fd.sync()
        offsets.add(Off(end + 8, entry.size))
        for (n in nodes) this.nodes["${n.level}:${n.index}"] = n.hash.clone()
        end += rec.capacity()
        return true
    }

    companion object {
        /** Open (creating if absent) the log file at [path] and rebuild the index. */
        @JvmStatic
        fun open(path: File): FileScittLogStore {
            val s = FileScittLogStore(RandomAccessFile(path, "rw"))
            try {
                s.load()
            } catch (e: RuntimeException) {
                s.close()
                throw e
            } catch (e: IOException) {
                s.close()
                throw e
            }
            return s
        }

        private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

        private fun u32(b: ByteArray, at: Int): Long = ByteBuffer.wrap(b).getInt(at).toLong() and 0xffffffffL
    }
}
