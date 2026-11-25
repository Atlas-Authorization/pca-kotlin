package net.atlasauth.pca.wallet

import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Question delivery over approval-channel transports. A delivery only tells the principal's device that a question is waiting and
 * hands it the SIGNED question. It never carries a rendered card, agent text, the map, or p. A site question carries the
 * site-signed intent_required body exactly as received (the device re-verifies it and renders the card itself); a
 * wallet-originated question (an agent clarification) carries only its session and question id; text surfaces (email, SMS, push)
 * use one fixed template. Notices and deliveries are maps; a delivery is {kind, questionId, payload, delivered, status?, reason?}.
 */
@Suppress("UNCHECKED_CAST")
object WalletDelivery {
    private fun truthyString(o: Any?): Boolean = o is String && o.isNotEmpty()

    /**
     * A notice for a site-signed question. [keys] are the site's discovery keys, [site] the verified origin, [now] the clock;
     * [inboxUrl] may be null. Throws when the signature or expiry does not verify (nothing unsigned leaves).
     */
    fun siteQuestionNotice(ir: Map<String, Any?>, keys: Any?, site: Any?, now: Any?, inboxUrl: Any?): Map<String, Any?> {
        val bad = WalletBridge.verifyIntentRequired(ir, keys, now)
        if (bad != null) throw IllegalArgumentException("siteQuestionNotice: $bad")
        val n = Wallet.obj("type", "pca.intent.question", "session", ir["session"], "question_id", ir["question_id"], "site", site,
            "friction", ir["friction"], "expires_at", ir["expires_at"], "intent_required", ir)
        if (truthyString(inboxUrl)) n["inbox_url"] = inboxUrl
        return n
    }

    /** A notice for a wallet-originated question (clarification): ids only. */
    fun clarificationNotice(session: Any?, questionId: Any?, inboxUrl: Any?): Map<String, Any?> {
        val n = Wallet.obj("type", "pca.intent.clarification", "session", session, "question_id", questionId)
        if (truthyString(inboxUrl)) n["inbox_url"] = inboxUrl
        return n
    }

    /** A channel that delivers a notice: its kind, whether it is configured, and the delivery attempt. */
    interface QuestionChannel {
        fun kind(): String

        fun enabled(): Boolean

        fun notify(notice: Map<String, Any?>): Map<String, Any?>
    }

    /** The result of the webhook transport: whether the response was 2xx and its status. */
    class TransportResult(@JvmField val ok: Boolean, @JvmField val status: Int)

    /** The webhook transport: POST [body] with [headers] to [url]. */
    fun interface Transport {
        @Throws(Exception::class)
        fun post(url: String, headers: Map<String, String>, body: String): TransportResult
    }

    /** The default transport over OkHttp. */
    fun defaultTransport(): Transport {
        val client = OkHttpClient()
        return Transport { url, headers, body ->
            val b = Request.Builder().url(url).post(body.toRequestBody("application/json".toMediaType()))
            for ((k, v) in headers) b.header(k, v)
            client.newCall(b.build()).execute().use { r -> TransportResult(r.code in 200..299, r.code) }
        }
    }

    private fun delivery(kind: String, questionId: Any?, payload: Any?): LinkedHashMap<String, Any?> =
        Wallet.obj("kind", kind, "questionId", questionId, "payload", payload)

    /** Webhook delivery (the principal's own wallet push endpoint): the JSON notice, signed question included. */
    fun questionWebhookChannel(url: String?, extraHeaders: Map<String, String>?, transport: Transport?): QuestionChannel {
        val enabled = url != null && url.isNotEmpty()
        val tr = transport ?: defaultTransport()
        val headers = LinkedHashMap<String, String>()
        headers["content-type"] = "application/json"
        if (extraHeaders != null) headers.putAll(extraHeaders)
        return object : QuestionChannel {
            override fun kind(): String = "webhook"

            override fun enabled(): Boolean = enabled

            override fun notify(notice: Map<String, Any?>): Map<String, Any?> {
                val d = delivery("webhook", notice["question_id"], notice)
                if (!enabled) { d["delivered"] = false; d["reason"] = "webhook channel not configured"; return d }
                try {
                    val res = tr.post(url!!, headers, jsonStringify(notice))
                    d["delivered"] = res.ok
                    d["status"] = res.status.toLong()
                    if (!res.ok) d["reason"] = "webhook returned " + res.status
                    return d
                } catch (err: Exception) {
                    d["delivered"] = false
                    d["reason"] = err.message ?: ""
                    return d
                }
            }
        }
    }

    /** `encodeURIComponent`. */
    fun encodeUriComponent(s: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if ((c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || "-_.!~*'()".indexOf(c) >= 0) { sb.append(c); i++; continue }
            val cp: Int
            if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { cp = Character.toCodePoint(c, s[i + 1]); i++ }
            else if (Character.isSurrogate(c)) throw IllegalArgumentException("URI malformed")
            else cp = c.code
            for (x in Json.utf8(String(Character.toChars(cp)))) sb.append('%').append(String.format("%02X", x.toInt() and 0xff))
            i++
        }
        return sb.toString()
    }

    /** The fixed text of a text-surface notice: {subject, text}. */
    fun questionText(notice: Map<String, Any?>, siteName: String): Map<String, Any?> {
        val question = "pca.intent.question" == notice["type"]
        val clean = WalletCard.cleanText(siteName, 64)
        val who = if (question) (if (clean.isEmpty()) "A site" else clean) else "Your agent"
        val subject = if (question) "$who has a question about your request" else "$who needs a decision about your request"
        val inbox = notice["inbox_url"]
        var link: String? = null
        if (truthyString(inbox)) link = (inbox as String) + (if (inbox.contains("?")) "&" else "?") + "question=" + encodeUriComponent(Js.template(notice["question_id"]))
        return Wallet.obj("subject", subject, "text", subject + "\n\n" + (if (link != null) "Open your wallet to answer: $link" else "Open your wallet to answer."))
    }

    /** The email / SMS / push sender port: gets {subject, text}. */
    fun interface TextSender {
        @Throws(Exception::class)
        fun send(body: Map<String, Any?>)
    }

    /** Email / SMS / push delivery through a sender port (fixed text only); [send] may be null (disabled). */
    fun questionTextChannel(kind: String, send: TextSender?, siteName: String): QuestionChannel {
        val enabled = send != null
        return object : QuestionChannel {
            override fun kind(): String = kind

            override fun enabled(): Boolean = enabled

            override fun notify(notice: Map<String, Any?>): Map<String, Any?> {
                val body = questionText(notice, siteName)
                val d = delivery(kind, notice["question_id"], body)
                if (!enabled) { d["delivered"] = false; d["reason"] = "$kind channel not configured"; return d }
                try {
                    send!!.send(body)
                    d["delivered"] = true
                    return d
                } catch (err: Exception) {
                    d["delivered"] = false
                    d["reason"] = err.message ?: ""
                    return d
                }
            }
        }
    }

    /** Fan a notice out to every enabled channel (disabled channels are skipped). */
    fun notifyAll(channels: List<QuestionChannel>, notice: Map<String, Any?>): List<Map<String, Any?>> {
        val out = ArrayList<Map<String, Any?>>()
        for (c in channels) if (c.enabled()) out.add(c.notify(notice))
        return out
    }

    // ---- JSON.stringify ----

    /** `JSON.stringify` of a parsed value: insertion-ordered members, numbers as JavaScript prints them (`-0` as 0). */
    fun jsonStringify(v: Any?): String {
        val sb = StringBuilder()
        ser(sb, v)
        return sb.toString()
    }

    private fun ser(sb: StringBuilder, v: Any?) {
        if (v == null) sb.append("null")
        else if (v is String) sb.append(WalletBox.jsonString(v))
        else if (v is Boolean) sb.append(v)
        else if (v is Map<*, *>) {
            sb.append('{')
            var first = true
            for ((k, x) in v) {
                if (!first) sb.append(',')
                first = false
                sb.append(WalletBox.jsonString(k as String)).append(':')
                ser(sb, x)
            }
            sb.append('}')
        } else if (v is List<*>) {
            sb.append('[')
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                ser(sb, x)
            }
            sb.append(']')
        } else if (Js.isNumber(v)) {
            val d = Js.num(v)!!
            if (d.isNaN() || d.isInfinite()) sb.append("null")
            else if (d == 0.0) sb.append('0')
            else sb.append((IntentJs.normalize(if (v is Json.Num) v else Json.Num(v.toString())) as Json.Num).raw)
        } else sb.append("null")
    }
}
