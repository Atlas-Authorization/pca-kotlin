package net.atlasauth.pca.actions.importers

import java.util.concurrent.TimeUnit
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import net.atlasauth.pca.verifier.ActionKitError
import net.atlasauth.pca.verifier.Json

/**
 * Model adapters for `--suggest model`: a pinned model id on a named provider, the API key read from the environment at call time
 * (never a flag, never printed, never stored, never put in an error). The request is exactly the names-and-types prompt of
 * [ImportModel]; the answer is parsed against the closed trait vocabulary there. The transport is injectable.
 */
@Suppress("UNCHECKED_CAST")
object ImportProviders {
    @JvmField val PROVIDERS: List<String> = listOf("anthropic", "openai")

    private val MODEL_RE = Regex("[A-Za-z0-9._:/-]{1,128}")

    /** What a transport answers: status, and the parsed JSON body on demand. */
    interface FetchResponse {
        fun ok(): Boolean
        fun status(): Int
        fun json(): Any?
    }

    /** One POST: url, headers, JSON body text, timeout. */
    fun interface FetchLike {
        fun fetch(url: String, headers: Map<String, String>, body: String, timeoutMs: Long): FetchResponse
    }

    /** The provider, the pinned model and the key (kept out of [toString] and [toMap]). */
    class ModelEnvConfig internal constructor(@JvmField val provider: String, @JvmField val model: String, internal val apiKey: String) {
        fun toMap(): Map<String, Any?> = Jx.obj("provider", provider, "model", model)
        override fun toString(): String = "$provider:$model"
    }

    private fun keyEnv(provider: String): String = if (provider == "anthropic") "ANTHROPIC_API_KEY" else "OPENAI_API_KEY"
    private fun urlOf(provider: String): String = if (provider == "anthropic") "https://api.anthropic.com/v1/messages" else "https://api.openai.com/v1/chat/completions"

    private fun first(a: Any?, b: Any?): Any? = a ?: b

    /**
     * Read the model assist configuration. `model` and `provider` come from flags or ATLAS_PCA_SUGGEST_MODEL /
     * ATLAS_PCA_SUGGEST_PROVIDER; the model must be named explicitly (a pinned id). The key comes only from the provider's env var.
     */
    fun modelConfigFromEnv(env: Map<String, Any?>, flags: Map<String, Any?>?): ModelEnvConfig {
        val fl: Map<String, Any?> = flags ?: LinkedHashMap()
        val provider = first(fl["provider"], first(env["ATLAS_PCA_SUGGEST_PROVIDER"], "anthropic"))
        if (provider !is String || !PROVIDERS.contains(provider)) throw ActionKitError("bad_model_config", "unknown provider (one of " + PROVIDERS.joinToString(", ") + ")")
        val model = first(fl["model"], env["ATLAS_PCA_SUGGEST_MODEL"])
        if (!Jx.truthy(model) || !MODEL_RE.matches(Jx.jsStr(model))) throw ActionKitError("bad_model_config", "--model <pinned model id> (or ATLAS_PCA_SUGGEST_MODEL) is required")
        val key = env[keyEnv(provider)]
        if (!Jx.truthy(key)) throw ActionKitError("bad_model_config", keyEnv(provider) + " is not set")
        return ModelEnvConfig(provider, Jx.jsStr(model), Jx.jsStr(key))
    }

    private val client by lazy { OkHttpClient() }

    /** A transport over OkHttp. */
    fun httpFetch(): FetchLike = FetchLike { url, headers, body, timeoutMs ->
        val c = client.newBuilder().callTimeout(timeoutMs, TimeUnit.MILLISECONDS).build()
        val b = Request.Builder().url(url).post(body.toRequestBody("application/json".toMediaType()))
        for ((k, v) in headers) b.header(k, v)
        c.newCall(b.build()).execute().use { r ->
            val code = r.code
            val text = r.body?.string() ?: ""
            object : FetchResponse {
                override fun ok(): Boolean = code in 200..299
                override fun status(): Int = code
                override fun json(): Any? = Json.parseLenient(text)
            }
        }
    }

    fun providerAdapter(cfg: ModelEnvConfig, fetch: FetchLike): ModelAdapter = providerAdapter(cfg, fetch, 30_000)

    /** A ModelAdapter for the provider. Errors carry the HTTP status only: never the key, the request or the response body. */
    fun providerAdapter(cfg: ModelEnvConfig, fetch: FetchLike, timeoutMs: Long): ModelAdapter = object : ModelAdapter {
        override fun id(): String = cfg.provider + ":" + cfg.model
        override fun version(): String? = null

        override fun complete(req: Map<String, Any?>): String? {
            val headers = LinkedHashMap<String, String>()
            headers["content-type"] = "application/json"
            val body: Any?
            if (cfg.provider == "anthropic") {
                headers["x-api-key"] = cfg.apiKey
                headers["anthropic-version"] = "2023-06-01"
                body = Jx.obj(
                    "model", cfg.model, "max_tokens", Jx.n(512), "temperature", req["temperature"], "system", req["system"],
                    "messages", Jx.list(Jx.obj("role", "user", "content", req["user"])),
                )
            } else {
                headers["authorization"] = "Bearer " + cfg.apiKey
                body = Jx.obj(
                    "model", cfg.model, "max_tokens", Jx.n(512), "temperature", req["temperature"],
                    "messages", Jx.list(Jx.obj("role", "system", "content", req["system"]), Jx.obj("role", "user", "content", req["user"])),
                )
            }
            val res: FetchResponse = try {
                fetch.fetch(urlOf(cfg.provider), headers, Jx.stringify(body), timeoutMs)
            } catch (e: Exception) {
                throw RuntimeException(cfg.provider + " request failed")
            }
            if (!res.ok()) throw RuntimeException(cfg.provider + " returned HTTP " + res.status())
            val j = res.json()
            // a body that is JSON null has no member to read: the reference's TypeError text is the refusal
            if (j == null) throw RuntimeException("Cannot read properties of null (reading '" + (if (cfg.provider == "anthropic") "content" else "choices") + "')")
            var text: Any? = null
            if (cfg.provider == "anthropic") {
                val content = Jx.get(j, "content")
                if (content is List<*>) for (c in content) if ("text" == Jx.get(c, "type")) { text = Jx.get(c, "text"); break }
            } else {
                val choices = Jx.get(j, "choices")
                text = if (choices is List<*> && choices.isNotEmpty()) Jx.get(Jx.get(choices[0], "message"), "content") else null
            }
            if (text !is String) throw RuntimeException(cfg.provider + " returned no text")
            return text
        }
    }
}
