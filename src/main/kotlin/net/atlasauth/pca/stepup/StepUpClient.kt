package net.atlasauth.pca.stepup

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/**
 * Lists, approves and denies PCA step-ups from the principal's phone.
 *
 *  - [dashboardUrl] + a dashboard bearer token (a `dsk_` service key or console session token)
 *    serve `GET/POST .../pca/stepups` (list, deny). Deny requires an owner/admin role.
 *  - [instanceUrl] (the Atlas instance host the agent talks to) serves the public,
 *    self-authenticating `POST /v1/pca/stepups/:id/cosign`; the device signature is the credential.
 */
class StepUpClient(
    dashboardUrl: String,
    instanceUrl: String,
    private val accountId: String,
    private val instanceId: String,
    val key: PrincipalDeviceKey,
    private val token: suspend () -> String,
    private val http: OkHttpClient = OkHttpClient(),
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val dashboard: HttpUrl = dashboardUrl.toHttpUrl()
    private val instance: HttpUrl = instanceUrl.toHttpUrl()
    private val jsonType = "application/json".toMediaType()

    /** Pending, not-yet-expired step-ups. */
    suspend fun pending(): List<PendingStepUp> {
        val url = dashboard.newBuilder()
            .addPathSegments("v1/dashboard/accounts/$accountId/instances/$instanceId/pca/stepups")
            .addQueryParameter("status", "pending").build()
        val body = call(Request.Builder().url(url).header("Authorization", "Bearer ${token()}").get().build()).second
        val list = try {
            Json.parseToJsonElement(body).jsonObject["stepups"]!!.jsonArray
        } catch (e: Exception) {
            throw StepUpError.Transport("Unreadable step-up list.", e)
        }
        val t = now()
        return list.mapNotNull { el ->
            try {
                val o = el.jsonObject
                val exp = parseIso(o.str("expires_at"))
                if (exp <= t) return@mapNotNull null
                val action = o["action"]!!.jsonObject
                PendingStepUp(
                    id = o.str("id"), grantRef = o.str("grant_ref"),
                    actionVerb = action.str("verb"), actionResource = action.str("resource"),
                    requiredT = o["required_t"]!!.jsonPrimitive.int,
                    thresholdMessageB64u = o.str("threshold_message"), expiresAt = exp,
                )
            } catch (e: Exception) {
                throw StepUpError.Transport("Unreadable step-up entry.", e)
            }
        }
    }

    /**
     * Sign the step-up's threshold message with the device key and submit it.
     * Throws [StepUpError.PrincipalMismatch] (server 403) when this key is not the grant's principal.
     */
    suspend fun approve(stepUp: PendingStepUp): ApproveResult {
        val message = Base64Url.decode(stepUp.thresholdMessageB64u) ?: throw StepUpError.InvalidThresholdMessage()
        val payload = JsonObject(
            mapOf(
                "role" to JsonPrimitive("principal"),
                "publicKey" to JsonPrimitive(key.publicKey()),
                "sig" to JsonPrimitive(key.sign(message)),
            ),
        ).toString()
        val url = instance.newBuilder().addPathSegments("v1/pca/stepups/${stepUp.id}/cosign").build()
        val (status, body) = call(Request.Builder().url(url).post(payload.toRequestBody(jsonType)).build())
        val obj = runCatching { Json.parseToJsonElement(body).jsonObject }.getOrNull()
        // 200 + allow:true = anchored; 202 = more roles still required.
        return ApproveResult(
            status = obj?.get("status")?.jsonPrimitive?.contentOrNull ?: "",
            anchored = obj?.get("allow")?.jsonPrimitive?.booleanOrNull ?: false,
            httpStatus = status,
        )
    }

    /** Deny a pending step-up (dashboard endpoint; audited; owner/admin). */
    suspend fun deny(stepUp: PendingStepUp, reason: String? = null) {
        val url = dashboard.newBuilder()
            .addPathSegments("v1/dashboard/accounts/$accountId/instances/$instanceId/pca/stepups/${stepUp.id}/deny").build()
        val payload = JsonObject(if (reason == null) emptyMap() else mapOf("reason" to JsonPrimitive(reason))).toString()
        call(Request.Builder().url(url).header("Authorization", "Bearer ${token()}").post(payload.toRequestBody(jsonType)).build())
    }

    // ---- transport ----

    private suspend fun call(req: Request): Pair<Int, String> = withContext(Dispatchers.IO) {
        try {
            http.newCall(req).execute().use { resp ->
                val body = resp.body?.string().orEmpty()
                if (!resp.isSuccessful) throw httpError(resp.code, body)
                resp.code to body
            }
        } catch (e: IOException) {
            throw StepUpError.Transport(e.message ?: "Network error.", e)
        }
    }

    private fun httpError(status: Int, body: String): StepUpError {
        // Section 9.1 envelope: { errors: [{ code, message }] }
        val message = runCatching {
            Json.parseToJsonElement(body).jsonObject["errors"]!!.jsonArray[0].jsonObject.str("message")
        }.getOrDefault("The request failed.")
        return if (status == 403) StepUpError.PrincipalMismatch(message) else StepUpError.Api(status, message)
    }

    private fun JsonObject.str(k: String): String = this[k]!!.jsonPrimitive.content

    private fun parseIso(s: String): Long {
        // "2026-10-06T18:00:00.123Z" (fractional part optional, always UTC from the API).
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
        val base = fmt.parse(s.substring(0, 19))!!.time
        val frac = Regex("""\.(\d+)""").find(s)?.groupValues?.get(1)?.padEnd(3, '0')?.take(3)?.toLong() ?: 0L
        return base + frac
    }
}
