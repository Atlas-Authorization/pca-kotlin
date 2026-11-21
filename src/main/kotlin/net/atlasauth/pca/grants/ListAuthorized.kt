package net.atlasauth.pca.grants

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.Pca
import net.atlasauth.pca.verifier.ListAuthorized as ListVerify

/**
 * "Which objects of this type may this agent touch?" Authority = capability AND relationship: the capability (`permits`) decides and a
 * relation source can only NARROW. Every page is charged to a read accumulator (scanned and returned objects), pages are bound by a signed
 * cursor and the result carries a signed receipt. Verification of receipts and cursors is [ListVerify].
 */
object ListAuthorized {
    const val MAX_PAGE_LIMIT = 500

    /** One page of candidate objects; [next] null or empty ends the scan. */
    class CandidatePage(val objects: List<String>, val next: String?)

    fun interface CandidateSource {
        @Throws(Exception::class)
        fun page(type: String, cursor: String?, limit: Int): CandidatePage
    }

    interface RelationSource {
        /** May [subject] have [relation] on [obj]? Only ever narrows. */
        @Throws(Exception::class)
        fun check(subject: String, relation: String, obj: String): Boolean

        /** Whether [listObjects] is implemented. */
        fun supportsListObjects(): Boolean = false

        @Throws(Exception::class)
        fun listObjects(subject: String, relation: String, type: String, cursor: String?, limit: Int): CandidatePage =
            throw UnsupportedOperationException("listObjects")
    }

    /** Adapt a relation source's list-objects into a candidate source for one subject + relation. */
    @JvmStatic
    fun candidatesFromRelation(rel: RelationSource, subject: String, relation: String): CandidateSource {
        require(rel.supportsListObjects()) { "candidatesFromRelation: the relation source has no listObjects" }
        return CandidateSource { type, cursor, limit -> rel.listObjects(subject, relation, type, cursor, limit) }
    }

    /** Charges reads against a budget keyed by (subject, type). False when the charge would exceed the cap. */
    fun interface ReadAccumulator {
        @Throws(Exception::class)
        fun charge(key: String, units: Long, now: Long): Boolean
    }

    /** Reference accumulator: `cap` units per `windowMs` fixed window per key. */
    class WindowReadAccumulator(private val cap: Long, private val windowMs: Long) : ReadAccumulator {
        private val used = HashMap<String, LongArray>()

        @Synchronized
        override fun charge(key: String, units: Long, now: Long): Boolean {
            val e = used[key]
            val cur = if (e == null || now - e[0] >= windowMs) longArrayOf(now, 0) else e
            if (cur[1] + units > cap) return false
            cur[1] += units
            used[key] = cur
            return true
        }
    }

    @JvmStatic
    fun objectsDigest(objects: List<Any?>): String = ListVerify.objectsDigest(objects)

    @JvmStatic
    fun verifyListReceipt(r: Any?, signer: String, objects: List<Any?>?): Boolean = ListVerify.verifyReceipt(r, signer, objects)

    class ListError(
        /** read_budget_exhausted | bad_cursor | bad_limit */
        val code: String,
        message: String,
    ) : RuntimeException(message)

    /** Arguments of [listAuthorized]; fields mirror the reference. */
    class Args(
        val subject: String,
        val resourceType: String,
        /** The capability: true iff the grant permits the object. */
        val permits: (String) -> Boolean,
        val candidates: CandidateSource,
        val filterId: String,
        val policyDigest: String,
        val freshAtDigest: String,
        val limit: Long,
        val reads: ReadAccumulator,
        val now: Long,
        val signingSecret: Keys.EdKey,
        val relationSource: RelationSource? = null,
        /** The relation name; null when no relation filter is used. */
        val relation: String? = null,
        val cursor: String? = null,
        /** Max candidates scanned per call; null means 4x limit. At most 1000 either way. */
        val maxScan: Long? = null,
    )

    /** `{objects, next_cursor?, receipt}`. */
    class Result(val objects: List<String>, val nextCursor: String?, val receipt: Map<String, Any?>) {
        fun toMap(): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            m["objects"] = ArrayList<Any?>(objects)
            if (nextCursor != null) m["next_cursor"] = nextCursor
            m["receipt"] = receipt
            return m
        }
    }

    private fun bindInputs(a: Args): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["subject"] = a.subject
        m["resourceType"] = a.resourceType
        m["filterId"] = a.filterId
        m["policyDigest"] = a.policyDigest
        if (a.relation != null) {
            val r = LinkedHashMap<String, Any?>()
            r["relation"] = a.relation
            m["relation"] = r
        }
        m["limit"] = a.limit
        return m
    }

    /** What a cursor is bound to: `{subject, resourceType, filterId, policyDigest, relation?: {relation}, limit}`. */
    @JvmStatic
    fun listBind(a: Map<String, Any?>): String = ListVerify.listBind(a)

    /** Verify a page cursor (never throws); [bind] null skips the binding check. */
    @JvmStatic
    fun verifyListCursor(tok: Any?, signer: String, bind: Map<String, Any?>?): ListVerify.Cursor = ListVerify.verifyCursor(tok, signer, bind)

    private fun encCursor(inner: String?, skip: Long, bind: String, signer: String, secret: Keys.EdKey): String {
        // Member order is the reference's JSON.stringify order (v, inner?, skip, bind, signer); the signature covers the canonical form.
        val c = LinkedHashMap<String, Any?>()
        c["v"] = 1L
        if (inner != null) c["inner"] = inner
        c["skip"] = skip
        c["bind"] = bind
        c["signer"] = signer
        val sb = StringBuilder("{\"v\":1")
        if (inner != null) sb.append(",\"inner\":").append(Json.canonicalize(inner))
        sb.append(",\"skip\":").append(skip).append(",\"bind\":").append(Json.canonicalize(bind)).append(",\"signer\":").append(Json.canonicalize(signer)).append('}')
        return Keys.b64u(Json.utf8(sb.toString())) + "." + GrantSigning.signBody(ListVerify.LIST_CURSOR_DOMAIN, c, secret)
    }

    @JvmStatic
    @Throws(Exception::class)
    fun listAuthorized(a: Args): Result {
        if (a.limit < 1 || a.limit > MAX_PAGE_LIMIT) throw ListError("bad_limit", "limit must be 1..$MAX_PAGE_LIMIT")
        val limit = a.limit.toInt()
        val signer = GrantSigning.signerOf(a.signingSecret)
        val bi = bindInputs(a)
        val bind = ListVerify.listBind(bi)
        var inner: String? = null
        var skipIn = 0L
        if (a.cursor != null) {
            val c = ListVerify.verifyCursor(a.cursor, signer, bi)
            if (!c.ok) throw ListError("bad_cursor", if (c.reason == "bind") "subject, type, filter, policy or limit changed between pages" else "the page cursor is malformed, forged or from another signer")
            inner = c.inner
            skipIn = IntentJs.lng(c.skip)
        }
        val maxScan = minOf(a.maxScan ?: (a.limit * 4), 1000L)
        val kk = LinkedHashMap<String, Any?>()
        kk["s"] = a.subject
        kk["t"] = a.resourceType
        val key = Pca.hashCanonical(kk)
        val out = ArrayList<String>()
        var scanned = 0L
        var pageStart = inner
        var skip = skipIn
        var haveResume = false
        var resumeInner: String? = null
        var resumeSkip = 0L
        while (true) {
            val pg = a.candidates.page(a.resourceType, pageStart, limit)
            val objs = if (pg.objects.size > limit) pg.objects.subList(0, limit) else pg.objects
            // Charge what was SCANNED before anything is returned: enumeration by filter-heavy scans is the attack.
            if (!a.reads.charge(key, maxOf(objs.size - skip, 1L), a.now)) throw ListError("read_budget_exhausted", "the read budget for this subject and type is exhausted")
            var i = minOf(skip, Int.MAX_VALUE.toLong()).toInt()
            while (i < objs.size && out.size < limit) {
                scanned++
                val o = objs[i]
                i++
                if (!a.permits(o)) continue
                if (a.relation != null && !a.relationSource!!.check(a.subject, a.relation, o)) continue
                out.add(o)
            }
            if (i < objs.size) {
                haveResume = true
                resumeInner = pageStart
                resumeSkip = i.toLong()
                break
            }
            if (pg.next.isNullOrEmpty() || objs.isEmpty()) break
            pageStart = pg.next
            skip = 0
            if (out.size >= limit || scanned >= maxScan) {
                haveResume = true
                resumeInner = pg.next
                resumeSkip = 0
                break
            }
        }
        val receipt = LinkedHashMap<String, Any?>()
        receipt["v"] = 1L
        receipt["subject"] = a.subject
        receipt["resource_type"] = a.resourceType
        receipt["policy_digest"] = a.policyDigest
        receipt["fresh_at"] = a.freshAtDigest
        receipt["filter_digest"] = a.filterId
        receipt["count"] = out.size.toLong()
        receipt["objects_digest"] = ListVerify.objectsDigest(out)
        receipt["issued_at"] = a.now
        receipt["signer"] = signer
        val signed = LinkedHashMap<String, Any?>(receipt)
        signed["sig"] = GrantSigning.signBody(ListVerify.LIST_RECEIPT_DOMAIN, receipt, a.signingSecret)
        val next = if (haveResume) encCursor(resumeInner, resumeSkip, bind, signer, a.signingSecret) else null
        return Result(out, next, signed)
    }
}
