package net.atlasauth.pca.storeconformance

import net.atlasauth.pca.doctor.Js
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.PcaStateConformance

/**
 * `pca-store-conformance --adapter <class|builtin:name> [options]`.
 * Exit codes: 0 pass, 1 a contract violation was found, 3 unresolved (no violation, but not every key could be decided), 2 usage / adapter error.
 */
object Cli {
    /** The tests of the reference's pca-state profile (the store behind the real authorize path). */
    internal val ALL_PCA_STATE_TESTS: List<String> =
        listOf("claim-burst", "claim-concurrent", "claim-durability", "one-instance", "instances", "processes", "crash-after-claim", "retry-after-timeout")

    val USAGE: String = "pca-store-conformance --adapter <module|builtin:name> [options]\n\n" +
        "  --adapter <path>        module exporting a store adapter (default export, 'adapter' or 'createAdapter(options)')\n" +
        "                          or builtin:in-memory | builtin:durable-file | builtin:bad-* (reference adapters)\n" +
        "  --option k=v            passed to the adapter factory (repeatable)\n" +
        "  --tests a,b             subset of: " + Kit.ALL_TESTS.joinToString(", ") + " (default all)\n" +
        "  --clients N             concurrent clients (default 16)\n" +
        "  --duration MS           concurrent run length (default 2000)\n" +
        "  --rounds N              same-key burst rounds (default 20)\n" +
        "  --revisit-keys N        retention run size (default 500)\n" +
        "  --processes N           crash test: client processes alive at once (default 3)\n" +
        "  --kill-every MS         crash test: SIGKILL one client process this often (default 400)\n" +
        "  --budget N              search states per key before it is UNRESOLVED (default 200000)\n" +
        "  --values N              advance tests: counter values are drawn from [0, N) (default 20)\n" +
        "  --seed N                workload PRNG seed, to reproduce a run (default random)\n" +
        "  --json                  print the report as JSON\n" +
        "  --profile pca-state     test the store behind requirePCA instead (a module exporting createPcaStateAdapter(options),\n" +
        "                          or builtin:in-memory | builtin:durable-file | builtin:bad-*); --tests then takes a subset of:\n" +
        "                          " + ALL_PCA_STATE_TESTS.joinToString(", ") + "\n" +
        "                          (--rounds = race rounds, default 10; --clients = copies per round, default 16; --processes)\n\n" +
        "Exit: 0 pass, 1 violation found, 3 unresolved, 2 usage or adapter error."

    private fun num(flag: String, v: String?): Double {
        val n = if (v == null) Double.NaN else Js.toNumber(v)
        if (v == null || n.isNaN() || n.isInfinite() || n < 0) throw IllegalArgumentException("$flag needs a non-negative number")
        return n
    }

    private fun splitCommas(s: String): List<String> {
        val out = ArrayList<String>()
        for (x in s.split(",")) if (x.isNotEmpty()) out.add(x)
        return out
    }

    /**
     * The parsed command line as JSON: `options`, `json`, `help`, `conf` (clients, durationMs, rounds, revisitKeys, budget, values,
     * seed, tests) and, when given, `adapter`, `profile`, `pcaStateTests`, `processes`, `killEveryMs`.
     */
    @Suppress("UNCHECKED_CAST")
    fun parseCli(argv: List<String>): Map<String, Any?> {
        val a = LinkedHashMap<String, Any?>()
        val options = LinkedHashMap<String, Any?>()
        val conf = LinkedHashMap<String, Any?>()
        a["options"] = options
        a["json"] = false
        a["help"] = false
        a["conf"] = conf
        var rawTests: List<String>? = null
        var i = 0
        while (i < argv.size) {
            val f = argv[i]
            val nx: String? = if (i + 1 < argv.size) argv[i + 1] else null
            when (f) {
                "--adapter" -> { i++; a["adapter"] = nx ?: Js.UNDEF }
                "--option" -> {
                    i++
                    val kv = nx ?: ""
                    val eq = kv.indexOf('=')
                    if (eq < 1) throw IllegalArgumentException("--option needs k=v")
                    options[kv.substring(0, eq)] = kv.substring(eq + 1)
                }
                "--tests" -> { i++; rawTests = splitCommas(nx ?: "") }
                "--profile" -> {
                    i++
                    if ("pca-state" != nx) throw IllegalArgumentException("--profile: unknown profile " + (nx ?: "undefined") + " (known: pca-state)")
                    a["profile"] = nx
                }
                "--clients" -> { i++; conf["clients"] = num(f, nx) }
                "--duration" -> { i++; conf["durationMs"] = num(f, nx) }
                "--rounds" -> { i++; conf["rounds"] = num(f, nx) }
                "--revisit-keys" -> { i++; conf["revisitKeys"] = num(f, nx) }
                "--processes" -> { i++; a["processes"] = num(f, nx) }
                "--kill-every" -> { i++; a["killEveryMs"] = num(f, nx) }
                "--budget" -> { i++; conf["budget"] = num(f, nx) }
                "--values" -> {
                    i++
                    val n = num(f, nx)
                    if (n != Math.rint(n) || n < 1) throw IllegalArgumentException("--values needs a positive integer")
                    conf["values"] = n
                }
                "--seed" -> {
                    i++
                    val n = num(f, nx)
                    if (n != Math.rint(n)) throw IllegalArgumentException("--seed needs a non-negative integer")
                    conf["seed"] = n
                }
                "--json" -> a["json"] = true
                "-h", "--help" -> a["help"] = true
                else -> throw IllegalArgumentException("unknown argument $f")
            }
            i++
        }
        val rt = rawTests
        if (rt != null) {
            val pcaState = "pca-state" == a["profile"]
            val known = if (pcaState) ALL_PCA_STATE_TESTS else Kit.ALL_TESTS
            val bad = ArrayList<String>()
            for (x in rt) if (x !in known) bad.add(x)
            if (bad.isNotEmpty() || rt.isEmpty()) {
                throw IllegalArgumentException("--tests: unknown test(s) " + (if (bad.isEmpty()) "(none given)" else bad.joinToString(", ")))
            }
            if (pcaState) a["pcaStateTests"] = ArrayList<Any?>(rt) else conf["tests"] = ArrayList<Any?>(rt)
        }
        return Js.deepCopy(a) as Map<String, Any?>
    }

    private fun asInt(o: Any?): Int? = if (o == null) null else Js.toNumber(o).toInt()

    /** Runs the CLI and returns the exit code; [print] / [printErr] are injectable. */
    @Suppress("UNCHECKED_CAST")
    fun main(argv: List<String>, print: (String) -> Unit, printErr: (String) -> Unit): Int {
        val args = try {
            parseCli(argv)
        } catch (e: RuntimeException) {
            printErr(e.message + "\n\n" + USAGE)
            return 2
        }
        if (args["help"] == true) {
            print(USAGE)
            return 0
        }
        val spec = args["adapter"] as String?
        if (spec == null) {
            printErr("--adapter is required\n\n$USAGE")
            return 2
        }
        val options = LinkedHashMap<String, String>()
        for ((k, v) in args["options"] as Map<String, Any?>) options[k] = v as String
        if ("pca-state" == args["profile"]) return pcaState(spec, options, args, print, printErr)
        val adapter = try {
            Reference.loadAdapter(spec, options)
        } catch (e: Exception) {
            printErr("cannot load adapter: " + e.message)
            return 2
        }
        try {
            val conf = args["conf"] as Map<String, Any?>
            val o = Runner.ConformanceOptions()
            o.clients = asInt(conf["clients"])
            if (conf["durationMs"] != null) o.durationMs = Js.toNumber(conf["durationMs"])
            o.rounds = asInt(conf["rounds"])
            o.revisitKeys = asInt(conf["revisitKeys"])
            o.values = asInt(conf["values"])
            if (conf["seed"] != null) o.seed = Js.toNumber(conf["seed"]).toLong()
            if (conf["budget"] != null) o.check.budget = Js.toNumber(conf["budget"])
            if (conf["tests"] != null) {
                val ts = ArrayList<String>()
                for (t in conf["tests"] as List<Any?>) ts.add(t as String)
                o.tests = ts
            }
            val crash = Crash.CrashOptions()
            crash.adapters = { adapter } // every client process opens its own clients on the one shared backend
            crash.processes = asInt(args["processes"])
            crash.killEveryMs = asInt(args["killEveryMs"])
            o.crash = crash
            val r = Runner.runConformance(adapter, o)
            print(if (args["json"] == true) r.json() else r.format())
            return if (r.status == "pass") 0 else if (r.status == "fail") 1 else 3
        } catch (e: Exception) {
            printErr("conformance run failed: " + e.message)
            return 2
        } finally {
            try { adapter.teardown() } catch (ignored: Exception) { /* best effort */ }
        }
    }

    /** The pca-state profile: `builtin:in-memory` or a class implementing [PcaStateConformance.Adapter] (or a factory `(Map<String, String>) -> Adapter`). */
    @Suppress("UNCHECKED_CAST")
    private fun pcaState(spec: String, options: Map<String, String>, args: Map<String, Any?>, print: (String) -> Unit, printErr: (String) -> Unit): Int {
        val adapter: PcaStateConformance.Adapter = try {
            if (spec == "builtin:in-memory") {
                val store = Authorize.MemoryStateStore()
                object : PcaStateConformance.Adapter {
                    override val name: String get() = "in-memory"
                    override fun open(): Authorize.StateStore = store
                }
            } else if (spec.startsWith("builtin:")) {
                throw IllegalArgumentException("unknown built-in adapter '" + spec.substring("builtin:".length) + "' for the pca-state profile (known: in-memory)")
            } else {
                val inst = Class.forName(spec).getDeclaredConstructor().newInstance()
                val made = if (inst is Function1<*, *>) (inst as (Map<String, String>) -> Any?)(options) else inst
                made as? PcaStateConformance.Adapter ?: throw IllegalArgumentException("$spec: does not name a pca-state adapter")
            }
        } catch (e: Exception) {
            printErr("cannot load adapter: " + e.message)
            return 2
        }
        try {
            val conf = args["conf"] as Map<String, Any?>
            val d = PcaStateConformance.Options()
            val o = PcaStateConformance.Options(
                rounds = asInt(conf["rounds"]) ?: d.rounds, copies = asInt(conf["clients"]) ?: d.copies, instances = d.instances,
                processes = asInt(args["processes"]) ?: d.processes, worker = null,
            )
            val r = PcaStateConformance.run(adapter, o)
            val keep = args["pcaStateTests"] as List<Any?>?
            if (keep != null) r.results.removeAll { it.test !in keep }
            if (args["json"] == true) {
                val rs = ArrayList<Any?>()
                for (t in r.results) rs.add(linkedMapOf("test" to t.test, "status" to t.status, "note" to t.note))
                print(net.atlasauth.pca.verifier.Json.canonicalize(linkedMapOf("name" to r.name, "ok" to r.ok, "results" to rs)))
            } else print(r.render())
            return if (r.ok) 0 else if (r.failures().isEmpty()) 3 else 1
        } catch (e: Exception) {
            printErr("conformance run failed: " + e.message)
            return 2
        } finally {
            try { adapter.teardown() } catch (ignored: Exception) { /* best effort */ }
        }
    }
}
