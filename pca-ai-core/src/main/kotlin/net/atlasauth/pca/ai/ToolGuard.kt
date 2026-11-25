package net.atlasauth.pca.ai

import net.atlasauth.pca.verifier.Json

/** The shared guard behind every AI-stack adapter: map the tool call to an action, build the proof, run the tool under it. Deny fails closed. */
object ToolGuard {
    /** Which PCA action a tool call is. */
    data class Action(val verb: String, val resource: String)

    /** Map a tool call to an action; null declines (the call is then refused: there is no proof to carry). */
    fun interface ToolMapping {
        fun map(tool: String, args: Map<String, Any?>): Action?
    }

    /** The tool body, run only with a proof in hand. */
    fun interface Body<R> {
        @Throws(Exception::class)
        fun run(args: Map<String, Any?>, proof: Proof): R
    }

    /** Parse a tool call's JSON arguments (null, empty or whitespace: `{}`). Anything but a JSON object is refused. */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    fun parseArguments(raw: String?): Map<String, Any?> {
        if (raw == null || raw.trim().isEmpty()) return LinkedHashMap()
        val v = try {
            Json.parse(raw.trim())
        } catch (e: RuntimeException) {
            throw PcaDenied("tool arguments are not valid JSON: ${e.message}", null, null, e)
        }
        if (v !is Map<*, *>) throw PcaDenied("tool arguments must be a JSON object", null, null)
        return v as Map<String, Any?>
    }

    /** Map the call and build its proof; throws [PcaDenied] (the body never runs then). */
    @JvmStatic
    fun prove(prover: Prover, map: ToolMapping, name: String, args: Map<String, Any?>): Proof {
        val a = map.map(name, args) ?: throw PcaDenied("no PCActn for unmapped tool \"$name\" (the mapping declined)", null, null)
        return try {
            prover.prove(a.verb, a.resource, args)
        } catch (d: PcaDenied) {
            throw d
        } catch (e: RuntimeException) {
            throw PcaDenied("proof could not be built: ${e.message}", a.verb, a.resource, e)
        }
    }

    /**
     * Run [body] for the call `name(args)`. Throws [PcaDenied] when the mapping declines, the proof cannot be built or the
     * local pre-check denies; the body never runs then. The body's result is recorded as untrusted tool output.
     */
    @JvmStatic
    fun <R> run(prover: Prover, map: ToolMapping, name: String, args: Map<String, Any?>, body: Body<R>): R {
        val proof = prove(prover, map, name, args)
        val out = try {
            body.run(args, proof)
        } catch (e: RuntimeException) {
            throw e
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }
        prover.tool(name, out)
        return out
    }

    /** [run] for a suspending body (Kotlin coroutines: Koog and friends). Cancellation propagates untouched. */
    suspend fun <R> runSuspending(prover: Prover, map: ToolMapping, name: String, args: Map<String, Any?>, body: suspend (Map<String, Any?>, Proof) -> R): R {
        val proof = prove(prover, map, name, args)
        val out = body(args, proof)
        prover.tool(name, out)
        return out
    }

    /** [run] for JSON-string arguments (what model tool calls carry) and a String result. */
    @JvmStatic
    fun runJson(prover: Prover, map: ToolMapping, name: String, argsJson: String?, body: (Map<String, Any?>, Proof) -> String): String =
        run(prover, map, name, parseArguments(argsJson)) { a, p -> body(a, p) }

    /** A tool result as the string a model turn carries (canonical JSON; a null result carries the proof instead, as the TypeScript adapters do). */
    @JvmStatic
    fun content(result: Any?, proof: Proof): String =
        if (result == null) Json.canonicalize(linkedMapOf<String, Any?>("pca" to proof.encoded)) else Json.canonicalize(result)
}
