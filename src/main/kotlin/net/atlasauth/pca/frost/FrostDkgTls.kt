package net.atlasauth.pca.frost

/**
 * The framing and the identity rule of the mutual-TLS DKG channel. In this SDK the TLS socket is an INJECTED transport (a deployment brings its own TLS stack and
 * certificate management): this carries what the protocol depends on, not a TLS stack. One TLS 1.3 connection per pair of participants, mutually authenticated by
 * pinned certificate: each side trusts exactly the other participants' certificates, and the peer's certificate fingerprint maps to its participant id, so the
 * sender identity the DKG driver sees comes from the handshake and never from message content. The higher-numbered party dials the lower-numbered one. Frames are a
 * 4-byte big-endian length then the message; the length is checked against [FrostDkgChannel.DKG_MAX_MESSAGE_BYTES] before any allocation.
 */
object FrostDkgTls {
    /** One frame: the 4-byte big-endian length of `payload`, then `payload`. */
    @JvmStatic
    fun encodeFrame(payload: ByteArray): ByteArray {
        val f = ByteArray(4 + payload.size)
        f[0] = (payload.size ushr 24).toByte()
        f[1] = (payload.size ushr 16).toByte()
        f[2] = (payload.size ushr 8).toByte()
        f[3] = payload.size.toByte()
        System.arraycopy(payload, 0, f, 4, payload.size)
        return f
    }

    /** What a stream of chunks yielded: the whole frames accepted, `oversize` when a length exceeded the cap (the stream is then dead), and the bytes still buffered. */
    class Decoded(val accepted: List<ByteArray>, val error: String?, val buffered: Int)

    /**
     * The incremental frame reader of one link. [feed] takes the next chunk and returns the frames it completed; once a frame announces more than
     * [FrostDkgChannel.DKG_MAX_MESSAGE_BYTES] the reader is dead ([error] is `oversize`): nothing is allocated for it and later chunks are ignored.
     */
    class FrameDecoder {
        private var buf = ByteArray(0)
        private var off = 0
        var error: String? = null
            private set
        val buffered: Int get() = buf.size - off

        fun feed(chunk: ByteArray): List<ByteArray> {
            val out = ArrayList<ByteArray>()
            if (error != null) return out
            buf = buf.copyOfRange(off, buf.size) + chunk
            off = 0
            while (true) {
                if (buf.size - off < 4) break
                val len = ((buf[off].toLong() and 0xff) shl 24) or ((buf[off + 1].toLong() and 0xff) shl 16) or ((buf[off + 2].toLong() and 0xff) shl 8) or (buf[off + 3].toLong() and 0xff)
                if (len > FrostDkgChannel.DKG_MAX_MESSAGE_BYTES) {
                    error = "oversize"
                    break
                }
                if (buf.size - off < 4 + len) break
                out.add(buf.copyOfRange(off + 4, off + 4 + len.toInt()))
                off += 4 + len.toInt()
            }
            return out
        }
    }

    /** Run a [FrameDecoder] over `chunks`. */
    @JvmStatic
    fun decodeFrames(chunks: List<ByteArray>): Decoded {
        val d = FrameDecoder()
        val accepted = ArrayList<ByteArray>()
        for (c in chunks) {
            if (d.error != null) break
            accepted.addAll(d.feed(c))
        }
        return Decoded(accepted, d.error, d.buffered)
    }

    /**
     * The identity rule for an INBOUND connection: accept only a peer whose certificate verified against the pinned set (`authorized`) and maps to a participant id
     * (`peerId`), that is supposed to dial this node (a HIGHER id) and has no link yet (`alreadyLinked`). Anything else is refused before any DKG byte is read.
     */
    @JvmStatic
    fun acceptInbound(self: Long, authorized: Boolean, peerId: Long?, alreadyLinked: Boolean): Boolean = authorized && peerId != null && peerId >= self && !alreadyLinked

    /**
     * A [DkgChannel] over injected authenticated links: `write(peer, frame)` sends one frame to an authenticated peer (a failure throws), and the transport hands every
     * chunk read from a peer's link to [FramedChannel.onData] (and tells it when a link ends). The sender identity of every message is the link it arrived on.
     */
    class FramedChannel(override val self: Long, sessionId: ByteArray, override val peers: List<Long>, private val write: (Long, ByteArray) -> Unit) : DkgChannel {
        private val sid = sessionId
        private val inbox = FrostDkgChannel.DkgInbox(sessionId, peers)
        private val decoders = HashMap<Long, FrameDecoder>()

        /** Feed a chunk read from the authenticated link of `peer`. Returns false once the link is dead (an oversize frame): the transport must close it. */
        fun onData(peer: Long, chunk: ByteArray): Boolean {
            val d = decoders.getOrPut(peer) { FrameDecoder() }
            for (m in d.feed(chunk)) inbox.accept(peer, m)
            if (d.error != null) {
                inbox.fail(peer, DkgChannelError("oversize", peer, "frame exceeds the cap"))
                return false
            }
            return true
        }

        /** The link to `peer` ended. */
        fun onLinkClosed(peer: Long) = inbox.peerGone(peer)

        private fun send1(to: Long, kind: String, body: Any?) {
            val payload = FrostDkgChannel.encodeDkgMessage(sid, kind, body)
            write(to, encodeFrame(payload))
        }

        override fun broadcast(kind: String, body: Any?) { for (p in peers) send1(p, kind, body) }

        override fun send(to: Long, kind: String, body: Any?) {
            if (to !in peers) throw DkgChannelError("identity", to, "not a connected peer")
            send1(to, kind, body)
        }

        override fun collect(kind: String, from: List<Long>, timeoutMs: Double): Map<Long, Any?> = inbox.collect(kind, from, timeoutMs)

        override fun close() = inbox.close()
    }
}
