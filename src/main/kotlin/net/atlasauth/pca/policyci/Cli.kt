package net.atlasauth.pca.policyci

import java.io.File
import java.io.IOException
import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.Json

/**
 * The command line of the policy-safety gate.
 *
 * ```
 * pca-policy-ci <files...> [--max-severity error|warn|info] [--format text|github] [--quiet] [--schema file] [--lint-rules-pin file]
 * pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
 * pca-policy-ci test <policy.json> <tests.json> [--require-digest]
 * pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]
 * ```
 *
 * Each file is a JSON policy (envelope, grant, compiled policy, `{predicates, caveats}`) or a JSON array treated as a delegation chain.
 * Exits non-zero when a finding reaches `--max-severity` (default `error`); 2 is unusable input.
 */
object Cli {
    private val SEVERITIES = listOf("error", "warn", "info")

    private fun isSeverity(x: String): Boolean = SEVERITIES.contains(x)

    /** Parse the gate's own arguments: `{args: {files, maxSeverity, format, quiet, help, schema?, lintRulesPin?}}` or `{error}`. */
    fun parseArgs(argv: List<String?>): Map<String, Any?> {
        val files = ArrayList<Any?>()
        var maxSeverity = "error"
        var format = "text"
        var schema: String? = null
        var lintRulesPin: String? = null
        var quiet = false
        var help = false
        val sevMsg = "--max-severity expects one of " + SEVERITIES.joinToString("|")

        var i = 0
        while (i < argv.size) {
            val a = argv[i]
            if (a == null) { i++; continue }
            if (a == "--help" || a == "-h") {
                help = true
            } else if (a == "--quiet" || a == "-q") {
                quiet = true
            } else if (a == "--lint-rules-pin") {
                i++
                val v = if (i < argv.size) argv[i] else null
                if (v == null || v.startsWith("-")) return PcJs.obj("error", "--lint-rules-pin expects a file")
                lintRulesPin = v
            } else if (a == "--max-severity") {
                i++
                val v = if (i < argv.size) argv[i] else null
                if (v == null || !isSeverity(v)) return PcJs.obj("error", sevMsg)
                maxSeverity = v
            } else if (a.startsWith("--max-severity=")) {
                val v = a.substring("--max-severity=".length)
                if (!isSeverity(v)) return PcJs.obj("error", sevMsg)
                maxSeverity = v
            } else if (a == "--schema") {
                i++
                val v = if (i < argv.size) argv[i] else null
                if (v == null) return PcJs.obj("error", "--schema expects a file")
                schema = v
            } else if (a.startsWith("--schema=")) {
                schema = a.substring("--schema=".length)
            } else if (a == "--format") {
                i++
                val v = if (i < argv.size) argv[i] else null
                if (v == null || (v != "text" && v != "github")) return PcJs.obj("error", "--format expects 'text' or 'github'")
                format = v
            } else if (a.startsWith("--format=")) {
                val v = a.substring("--format=".length)
                if (v != "text" && v != "github") return PcJs.obj("error", "--format expects 'text' or 'github'")
                format = v
            } else if (a.startsWith("-")) {
                return PcJs.obj("error", "unknown option '$a'")
            } else {
                files.add(a)
            }
            i++
        }
        val args = PcJs.obj("files", files, "maxSeverity", maxSeverity, "format", format, "quiet", quiet, "help", help)
        if (schema != null) args["schema"] = schema
        if (lintRulesPin != null) args["lintRulesPin"] = lintRulesPin
        return PcJs.obj("args", args)
    }

    private val HELP = "pca-policy-ci — statically catch unsafe PCA policies before they ship.\n\n" +
        "Usage:\n" +
        "  pca-policy-ci <files...> [options]\n" +
        "  pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]\n" +
        "  pca-policy-ci test <policy.json> <tests.json> [--require-digest]\n" +
        "  pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]\n\n" +
        "Options:\n" +
        "  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)\n" +
        "  --format <text|github>            Output format (default: text; 'github' = workflow annotations)\n" +
        "  --schema <file>                   Also check each policy against this signed action schema (JSON)\n" +
        "  --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>\n" +
        "  --quiet, -q                       Only print findings and the summary line\n" +
        "  --help, -h                        Show this help\n\n" +
        "Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array\n" +
        "treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity."

    /** The usage text. */
    fun help(): String = HELP

    private fun message(e: Throwable): String = if (e is StackOverflowError) "Maximum call stack size exceeded" else e.message.toString()

    private fun readText(file: String): String = String(File(file).readBytes(), Charsets.UTF_8)

    /** Pair(true, document) or Pair(false, message). */
    private fun readJson(file: String): Pair<Boolean, Any?> = try {
        Pair(true, Json.parseLenient(readText(file)))
    } catch (e: IOException) {
        Pair(false, file + ": " + message(e))
    } catch (e: RuntimeException) {
        Pair(false, file + ": " + message(e))
    } catch (e: StackOverflowError) {
        Pair(false, file + ": " + message(e))
    }

    private fun lintFile(file: String, hasSchema: Boolean, schema: Any?, validator: Rules.SchemaValidator): List<Any?> {
        val text: String = try {
            readText(file)
        } catch (e: IOException) {
            return finding("cannot read file: " + message(e))
        } catch (e: RuntimeException) {
            return finding("cannot read file: " + message(e))
        }
        val doc: Any? = try {
            Json.parseLenient(text)
        } catch (e: RuntimeException) {
            return finding("invalid JSON: " + message(e))
        } catch (e: StackOverflowError) {
            return finding("invalid JSON: " + message(e))
        }
        val opts = LinkedHashMap<String, Any?>()
        if (hasSchema) opts["schema"] = schema
        return PolicyCi.lint(doc, opts, validator)
    }

    private fun finding(message: String): List<Any?> = arrayListOf<Any?>(PcJs.obj("rule", "malformed-policy", "severity", "error", "message", message))

    private fun ghLevel(sev: String): String = if (sev == "error") "error" else if (sev == "warn") "warning" else "notice"

    private fun textTag(sev: String): String = if (sev == "error") "ERROR" else if (sev == "warn") "WARN " else "INFO "

    @Suppress("UNCHECKED_CAST")
    private fun printText(results: List<Any?>, quiet: Boolean, write: (String) -> Unit) {
        for (r in results) {
            if (!quiet) write("\n" + PcJs.get(r, "label") + ":")
            val findings = PcJs.get(r, "findings") as List<Any?>
            if (findings.isEmpty()) {
                if (!quiet) write("  (clean)")
                continue
            }
            for (f in findings) {
                val where = PcJs.get(f, "where")
                val loc = if (where != null) " [" + PcJs.str(where) + "]" else ""
                write("  " + textTag(PcJs.get(f, "severity") as String) + " " + PcJs.get(f, "rule") + loc + ": " + PcJs.get(f, "message"))
            }
        }
    }

    private fun escapeGh(s: String): String = s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    /** Workflow-command property values must also escape `:` and `,`, or a file name can add properties or end the command. */
    private fun escapeGhProp(s: String): String = escapeGh(s).replace(":", "%3A").replace(",", "%2C")

    @Suppress("UNCHECKED_CAST")
    private fun printGithub(results: List<Any?>, write: (String) -> Unit) {
        for (r in results) {
            for (f in PcJs.get(r, "findings") as List<Any?>) {
                val props = "file=" + escapeGhProp(PcJs.get(r, "label") as String) + ",title=" + escapeGhProp(PcJs.get(f, "rule") as String)
                val where = PcJs.get(f, "where")
                val loc = if (where != null) PcJs.str(where) + ": " else ""
                write("::" + ghLevel(PcJs.get(f, "severity") as String) + " " + props + "::" + escapeGh(loc + PcJs.get(f, "message")))
            }
        }
    }

    private val DECIMAL = java.util.regex.Pattern.compile("[+-]?(?:[0-9]+\\.?[0-9]*|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?")

    /** `Number(v)` of a trimmed non-empty flag value when it is finite, else null (JavaScript's grammar, including 0x / 0o / 0b). */
    private fun flagNum(flags: Map<String, Any?>, k: String): Double? {
        val v = flags[k]
        if (v !is String) return null
        val s = PcJs.trim(v)
        if (s.isEmpty()) return null
        var d = 0.0
        try {
            if (s.length > 2 && s[0] == '0' && "xXoObB".indexOf(s[1]) >= 0) {
                val radix = if ("xX".indexOf(s[1]) >= 0) 16 else if ("oO".indexOf(s[1]) >= 0) 8 else 2
                d = java.math.BigInteger(s.substring(2), radix).toDouble()
                if (s[2] == '-' || s[2] == '+') return null
            } else if (DECIMAL.matcher(s).matches()) {
                d = s.toDouble()
            } else {
                return null
            }
        } catch (e: NumberFormatException) {
            return null
        }
        return if (d.isNaN() || d.isInfinite()) null else d
    }

    private fun numJson(d: Double): Any = Json.Num(AttestUtil.jsNumString(d))

    /** `diff`, `test` and `coverage`: two files and flags. Unknown or malformed flags are a usage error (exit 2). */
    @Suppress("UNCHECKED_CAST")
    private fun runAuthoring(cmd: String, rest: List<String>, write: (String) -> Unit, backend: Authoring.Backend): Int {
        val files = ArrayList<String>()
        val flags = LinkedHashMap<String, Any?>()
        val valued = setOf("--verb", "--amount-field", "--window-secs", "--max-exposure-increase", "--min-clauses", "--min-boundaries", "--min-mutation", "--max-survivors")
        val bools = setOf("--allow-widen", "--integer", "--require-digest")
        var i = 0
        while (i < rest.size) {
            val a = rest[i]
            if (valued.contains(a)) {
                i++
                if (i >= rest.size) { write("$a expects a value"); return 2 }
                flags[a] = rest[i]
            } else if (bools.contains(a)) {
                flags[a] = true
            } else if (a.startsWith("-")) {
                write("unknown option '$a'")
                return 2
            } else {
                files.add(a)
            }
            i++
        }
        for ((k, v) in flags) {
            if (valued.contains(k) && k != "--verb" && k != "--amount-field" && flagNum(flags, k) == null) {
                write("$k expects a number, got '$v'")
                return 2
            }
        }
        if (files.size != 2) {
            write("error: $cmd takes exactly two files")
            write(HELP)
            return 2
        }
        val a = readJson(files[0])
        if (!a.first) { write(a.second as String); return 2 }
        val b = readJson(files[1])
        if (!b.first) { write(b.second as String); return 2 }
        val r: Map<String, Any?>
        if (cmd == "diff") {
            val o = LinkedHashMap<String, Any?>()
            o["allowWiden"] = flags.containsKey("--allow-widen")
            if (flags["--verb"] is String) o["verb"] = flags["--verb"]
            if (flags["--amount-field"] is String) o["amountField"] = flags["--amount-field"]
            o["integer"] = flags.containsKey("--integer")
            flagNum(flags, "--window-secs")?.let { o["windowSecs"] = numJson(it) }
            flagNum(flags, "--max-exposure-increase")?.let { o["maxExposureIncrease"] = numJson(it) }
            r = Authoring.diffCommand(a.second, b.second, o)
        } else if (cmd == "test") {
            r = Authoring.testCommand(a.second, b.second, PcJs.obj("requireDigest", flags.containsKey("--require-digest")), backend)
        } else {
            val o = LinkedHashMap<String, Any?>()
            flagNum(flags, "--min-clauses")?.let { o["minClauses"] = numJson(it) }
            flagNum(flags, "--min-boundaries")?.let { o["minBoundaries"] = numJson(it) }
            flagNum(flags, "--min-mutation")?.let { o["minMutation"] = numJson(it) }
            flagNum(flags, "--max-survivors")?.let { o["maxSurvivors"] = numJson(it) }
            r = Authoring.coverageCommand(a.second, b.second, o, backend)
        }
        for (l in r["lines"] as List<Any?>) write(l as String)
        return Math.round(PcJs.num(r["exitCode"])!!).toInt()
    }

    /**
     * Run the CLI; [write] receives each output line. [validator] checks policies against `--schema`; [backend] runs `test` and `coverage`.
     * Either may be null when that analyzer part is not available: the command then refuses (a rule that cannot run is a finding; a
     * missing backend is exit code 2). Returns the process exit code.
     */
    @Suppress("UNCHECKED_CAST")
    fun run(
        argv: List<String>,
        write: (String) -> Unit,
        validator: Rules.SchemaValidator? = PolicyCi.ANALYZER_SCHEMA_VALIDATOR,
        backend: Authoring.Backend? = Authoring.ANALYZER_BACKEND,
    ): Int {
        if (argv.isNotEmpty() && (argv[0] == "diff" || argv[0] == "test" || argv[0] == "coverage")) {
            return runAuthoring(argv[0], argv.subList(1, argv.size), write, backend ?: Authoring.ANALYZER_BACKEND)
        }
        val parsed = parseArgs(argv)
        if (parsed.containsKey("error")) {
            write(parsed["error"] as String)
            write(HELP)
            return 2
        }
        val args = parsed["args"] as Map<String, Any?>
        val files = args["files"] as List<Any?>
        if (args["help"] == true) {
            write(HELP)
            return 0
        }
        var pinFailed = false
        if (args["lintRulesPin"] != null) {
            var r: Map<String, Any?>
            try {
                r = PolicyCi.checkLintRulesPin(readText(args["lintRulesPin"] as String))
            } catch (e: IOException) {
                r = PcJs.obj("ok", false, "message", "cannot read the lint rules pin: " + message(e))
            } catch (e: RuntimeException) {
                r = PcJs.obj("ok", false, "message", "cannot read the lint rules pin: " + message(e))
            }
            write((if (r["ok"] == true) "PASS" else "FAIL") + " — " + r["message"])
            pinFailed = r["ok"] != true
            if (files.isEmpty()) return if (pinFailed) 1 else 0
        }
        if (files.isEmpty()) {
            write("error: no policy files given")
            write(HELP)
            return 2
        }

        var hasSchema = false
        var schema: Any? = null
        if (args["schema"] != null) {
            val s = readJson(args["schema"] as String)
            if (!s.first) { write(s.second as String); return 2 }
            hasSchema = true
            schema = s.second
        }
        val v = validator ?: PolicyCi.ANALYZER_SCHEMA_VALIDATOR
        val results = ArrayList<Any?>()
        for (file in files) results.add(PcJs.obj("label", file, "findings", lintFile(file as String, hasSchema, schema, v)))
        val summary = PolicyCi.summarize(results, PcJs.obj("maxSeverity", args["maxSeverity"]))

        if ("github" == args["format"]) printGithub(results, write)
        else printText(results, args["quiet"] == true, write)

        if (summary["reason"] != null) write("error: " + summary["reason"])
        val c = summary["counts"] as Map<String, Any?>
        write(
            "\n" + (if (summary["ok"] == true) "PASS" else "FAIL") + " — " + PcJs.str(c["error"]) + " error(s), " + PcJs.str(c["warn"]) + " warning(s), " + PcJs.str(c["info"]) +
                " info across " + results.size + " policy/policies (fail threshold: " + summary["maxSeverity"] + ")",
        )
        val code = Math.round(PcJs.num(summary["exitCode"])!!).toInt()
        return if (pinFailed) Math.max(1, code) else code
    }
}
