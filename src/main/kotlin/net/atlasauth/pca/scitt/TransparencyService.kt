package net.atlasauth.pca.scitt

import net.atlasauth.pca.verifier.Keys

/**
 * In-memory reference log (it recomputes the Merkle tree on every registration and loses everything on restart): use it to produce
 * receipts for tests and demos, never as a production transparency service. The production log is
 * [DurableTransparencyService] over a [ScittLogStore].
 */
class TransparencyService(private val signer: Scitt.ReceiptSignerOpts) {
    private val statements = ArrayList<ByteArray>()
    private val leafHashes = ArrayList<ByteArray>()

    /** Current number of registered statements. */
    @Synchronized fun size(): Long = statements.size.toLong()

    /** The current Merkle tree root (b64u); the empty-log root for an empty service. */
    @Synchronized fun root(): String = Keys.b64u(Rfc9162.treeHash(leafHashes))

    /** The statement leaves (b64u of each Signed Statement) currently in the log, in order. */
    @Synchronized fun snapshot(): List<String> = statements.map { Keys.b64u(it) }

    private fun receiptFor(index: Int): DurableTransparencyService.Registration {
        val root = Rfc9162.treeHash(leafHashes)
        val proof = Scitt.inclusionProofMap(index.toLong(), leafHashes.size.toLong(), Rfc9162.inclusionPath(leafHashes, index.toLong()))
        val r = Keys.b64u(root)
        return DurableTransparencyService.Registration(index.toLong(), Scitt.buildReceipt(r, proof, signer), r, null)
    }

    /** Register an already-signed Signed Statement; append it and return a signed inclusion receipt. */
    @Synchronized fun register(statement: ByteArray): DurableTransparencyService.Registration {
        val cose = Scitt.decodeCoseSign1(statement)
        if (cose.payload == null) throw IllegalArgumentException("scitt: cannot register a statement with a detached payload")
        val index = statements.size
        statements.add(statement.clone())
        leafHashes.add(Rfc9162.leafHash(statement))
        return receiptFor(index)
    }

    /** Sign [payload] as a Signed Statement, register it, and return the statement plus its receipt. */
    @Synchronized fun appendAndReceipt(payload: Any?, stmt: Scitt.SignStatementOpts): DurableTransparencyService.Registration {
        val statement = Scitt.signStatement(payload, stmt)
        val r = register(statement)
        return DurableTransparencyService.Registration(r.index, r.receipt, r.root, statement)
    }

    /** Re-issue a receipt for an already-registered statement, against the CURRENT ledger root. */
    @Synchronized fun getReceipt(index: Long): DurableTransparencyService.Registration {
        if (index < 0 || index >= statements.size) throw IndexOutOfBoundsException("getReceipt: index out of range")
        return receiptFor(index.toInt())
    }

    /** An RFC 9162 consistency proof that the log at [oldSize] entries is a prefix of the current log. */
    @Synchronized fun consistencyProof(oldSize: Long): Scitt.ConsistencyProofResult {
        if (oldSize < 1 || oldSize > statements.size) throw IndexOutOfBoundsException("consistencyProof: size out of range")
        val path = Rfc9162.consistencyPath(leafHashes, oldSize)
        return Scitt.ConsistencyProofResult(
            oldSize, statements.size.toLong(), Keys.b64u(Rfc9162.treeHash(leafHashes.subList(0, oldSize.toInt()))), root(),
            Cbor.encode(listOf(oldSize, statements.size.toLong(), ArrayList<Any?>(path))),
        )
    }

    companion object {
        /** Register a Signed Statement into a Transparency Service (RFC 9943 register-signed-statement). */
        @JvmStatic
        fun registerStatement(statement: ByteArray, service: TransparencyService) = service.register(statement)
    }
}
