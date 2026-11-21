package net.atlasauth.pca.sandbox

import java.util.TreeSet
import net.atlasauth.pca.jose.Js
import net.atlasauth.pca.jose.JsTypeError
import net.atlasauth.pca.verifier.Authorize

/**
 * Compile the OS policy from what was actually authorized, and generate the seccomp, Landlock and macOS (SBPL) profiles from it.
 * Policies and profiles are JSON trees (maps and lists); the output is byte-identical to the reference's canonical form.
 */
@Suppress("UNCHECKED_CAST")
object Profiles {
    /** One authorized operation: the authorization result and the operation it must allow exactly. */
    class AuthorizedOp(@JvmField val result: Authorize.Result, @JvmField val operation: Authorize.Operation)

    // Absolute, normalized, and only characters that need no escaping in a seccomp/Landlock/SBPL string. Refuse, never escape.
    private val PATH_RE = Regex("/[A-Za-z0-9._+@=,:~ /-]*")
    private val HOST_RE = Regex("[a-z0-9]([a-z0-9.-]*[a-z0-9])?")

    private fun checkPath(p: Any?): String {
        if (p !is String) throw IllegalArgumentException("bad_path")
        if (!PATH_RE.matches(p) || p.contains("//") || (p.length > 1 && p.endsWith("/"))) throw IllegalArgumentException("bad_path")
        for (seg in p.split("/")) if (seg == "." || seg == "..") throw IllegalArgumentException("bad_path")
        return p
    }

    /** `for (const x of v ?? [])`: a list iterates; null and the empty string are empty; anything else throws. */
    private fun iter(v: Any?): List<Any?> = when {
        v == null -> emptyList()
        v is List<*> -> v
        v is String && v.isEmpty() -> emptyList()
        else -> throw JsTypeError("not iterable")
    }

    private fun strMember(o: Any?, k: String): String = if (Js.own(o, k)) Js.template(Js.get(o, k)) else "undefined"

    private fun isInteger(o: Any?): Boolean = Js.isInteger(o)

    private fun inPortRange(o: Any?): Boolean = Js.num(o)!!.let { it >= 1 && it <= 65535 }

    /**
     * Compile the OS policy from what was actually authorized: only operations that `isAuthorizedFor` allows contribute,
     * so a denied or unrelated operation widens nothing. [needsOf] maps an operation to its needs (a JSON object) or null.
     */
    @JvmStatic
    fun compilePolicy(items: List<AuthorizedOp>, needsOf: (Authorize.Operation) -> Any?, proxyPort: Any?): Map<String, Any?> {
        val needs = ArrayList<Any?>()
        for (it in items) {
            if (!Authorize.isAuthorizedFor(it.result, it.operation)) throw IllegalArgumentException("not_authorized: result does not allow exactly this operation")
            val n = needsOf(it.operation)
            if (n != null) needs.add(n)
        }
        return policyFromNeeds(needs, proxyPort)
    }

    /** The pure core of [compilePolicy]: validate, merge, sort. [proxyPort] null means no proxy. */
    @JvmStatic
    fun policyFromNeeds(needs: Any?, proxyPort: Any?): Map<String, Any?> {
        if (needs !is List<*>) throw JsTypeError("needs is not iterable")
        val read = TreeSet<String>(); val write = TreeSet<String>(); val exec = TreeSet<String>(); val hosts = TreeSet<String>()
        for (n in needs) {
            for (f in iter(Js.member(n, "fs"))) {
                val p = checkPath(Js.member(f, "path"))
                val mode = Js.get(f, "mode")
                if ("x" == mode) exec.add(p)
                else if ("r" == mode || "rw" == mode) {
                    read.add(p)
                    if ("rw" == mode) write.add(p)
                } else throw IllegalArgumentException("bad_mode")
            }
            for (h in iter(Js.member(n, "net"))) {
                val port = Js.member(h, "port")
                if (!HOST_RE.matches(strMember(h, "host")) || !isInteger(port) || !inPortRange(port)) throw IllegalArgumentException("bad_net_need")
                hosts.add(strMember(h, "host") + ":" + Js.num(port)!!.toLong())
            }
        }
        if (hosts.isNotEmpty() && proxyPort == null) throw IllegalArgumentException("net_needs_proxy: network access exists only through the egress proxy; pass its port")
        if (proxyPort != null && (!isInteger(proxyPort) || !inPortRange(proxyPort))) throw IllegalArgumentException("bad_proxy_port")
        val fs = linkedMapOf<String, Any?>("read" to ArrayList<Any?>(read), "write" to ArrayList<Any?>(write), "exec" to ArrayList<Any?>(exec))
        val net = LinkedHashMap<String, Any?>()
        net["proxy"] = if (proxyPort == null) null else linkedMapOf<String, Any?>("host" to "127.0.0.1", "port" to Js.num(proxyPort)!!.toLong())
        net["hosts"] = ArrayList<Any?>(hosts)
        return linkedMapOf("v" to 1L, "fs" to fs, "net" to net)
    }

    // ---- profiles ----

    private val BASE = listOf("read", "write", "close", "fstat", "newfstatat", "statx", "lseek", "mmap", "mprotect", "munmap", "mremap", "brk", "madvise", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "pread64", "pwrite64", "readv", "writev", "openat", "getdents64", "fcntl", "getcwd", "readlink", "readlinkat", "dup", "dup3", "pipe2", "poll", "ppoll", "epoll_create1", "epoll_ctl", "epoll_pwait", "eventfd2", "futex", "set_tid_address", "set_robust_list", "rseq", "arch_prctl", "prlimit64", "sched_yield", "nanosleep", "clock_nanosleep", "clock_gettime", "gettimeofday", "getrandom", "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid", "uname", "tgkill", "exit", "exit_group").sorted()
    private val NET = listOf("connect", "getsockopt", "setsockopt", "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown").sorted()
    private val EXEC = listOf("execve", "execveat")

    private fun rule(names: List<String>, args: Any?): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        m["names"] = ArrayList<Any?>(names)
        m["action"] = "SCMP_ACT_ALLOW"
        if (args != null) m["args"] = args
        return m
    }

    private fun obj(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun proxyOf(p: Map<String, Any?>): Any? = obj(p["net"])["proxy"]

    /** Docker/OCI-format seccomp profile: deny by default; network syscalls only with a proxy; `socket` only for AF_INET/AF_INET6; exec only when the grant names a binary. */
    @JvmStatic
    fun seccompProfile(p: Map<String, Any?>): Map<String, Any?> {
        val syscalls = ArrayList<Any?>()
        syscalls.add(rule(BASE, null))
        if (proxyOf(p) != null) {
            syscalls.add(rule(NET, null))
            for (d in longArrayOf(2, 10)) {
                val a = linkedMapOf<String, Any?>("index" to 0L, "value" to d, "op" to "SCMP_CMP_EQ")
                syscalls.add(rule(listOf("socket"), arrayListOf<Any?>(a)))
            }
        }
        if ((obj(p["fs"])["exec"] as List<*>).isNotEmpty()) syscalls.add(rule(EXEC, null))
        val arch = ArrayList<Any?>()
        for (a in listOf("SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64")) arch.add(linkedMapOf<String, Any?>("architecture" to a, "subArchitectures" to ArrayList<Any?>()))
        return linkedMapOf("defaultAction" to "SCMP_ACT_ERRNO", "defaultErrnoRet" to 1L, "archMap" to arch, "syscalls" to syscalls)
    }

    private fun prefixed(prefix: String, xs: Collection<String>): List<String> = xs.map { prefix + it }

    /** Landlock ruleset (kernel UAPI access-right names; network rules need ABI 4). Handle every right, allow only what the grant names. */
    @JvmStatic
    fun landlockRuleset(p: Map<String, Any?>): Map<String, Any?> {
        val handledFs = prefixed("LANDLOCK_ACCESS_FS_", listOf("EXECUTE", "WRITE_FILE", "READ_FILE", "READ_DIR", "REMOVE_DIR", "REMOVE_FILE", "MAKE_CHAR", "MAKE_DIR", "MAKE_REG", "MAKE_SOCK", "MAKE_FIFO", "MAKE_BLOCK", "MAKE_SYM", "REFER", "TRUNCATE"))
        val fsP = obj(p["fs"])
        val read = fsP["read"] as List<*>; val write = fsP["write"] as List<*>; val exec = fsP["exec"] as List<*>
        val paths = TreeSet<String>()
        for (x in read) paths.add(x as String)
        for (x in write) paths.add(x as String)
        for (x in exec) paths.add(x as String)
        val fs = ArrayList<Any?>()
        for (path in paths) {
            val acc = LinkedHashSet<String>()
            if (exec.contains(path)) acc.addAll(listOf("EXECUTE", "READ_FILE")) // execve opens the binary for reading
            if (read.contains(path)) acc.addAll(listOf("READ_FILE", "READ_DIR"))
            if (write.contains(path)) acc.addAll(listOf("WRITE_FILE", "TRUNCATE", "MAKE_REG", "MAKE_DIR", "REMOVE_FILE", "REMOVE_DIR"))
            fs.add(linkedMapOf<String, Any?>("path" to path, "access" to ArrayList<Any?>(prefixed("LANDLOCK_ACCESS_FS_", acc))))
        }
        val net = ArrayList<Any?>()
        val proxy = proxyOf(p)
        if (proxy != null) net.add(linkedMapOf<String, Any?>("port" to obj(proxy)["port"], "access" to arrayListOf<Any?>("LANDLOCK_ACCESS_NET_CONNECT_TCP")))
        return linkedMapOf(
            "v" to 1L, "abi_min" to 4L,
            "handled_access_fs" to ArrayList<Any?>(handledFs),
            "handled_access_net" to arrayListOf<Any?>("LANDLOCK_ACCESS_NET_BIND_TCP", "LANDLOCK_ACCESS_NET_CONNECT_TCP"),
            "rules" to linkedMapOf<String, Any?>("fs" to fs, "net" to net),
        )
    }

    /** macOS sandbox profile (SBPL for sandbox-exec(1)): deny by default; the base lines are what a dynamically linked binary needs to start. */
    @JvmStatic
    fun macosProfile(p: Map<String, Any?>): String {
        val lines = arrayListOf(
            "(version 1)", "(deny default)", "(allow sysctl-read)", "(allow process-fork)", "(allow mach-lookup)", "(allow file-read-metadata)",
            "(allow file-read* (literal \"/\") (literal \"/dev/null\") (literal \"/dev/urandom\") (subpath \"/usr/lib\") (subpath \"/System/Library\") (subpath \"/private/var/db/dyld\") (subpath \"/System/Volumes/Preboot/Cryptexes\"))",
        )
        val fs = obj(p["fs"])
        for (x in fs["exec"] as List<*>) {
            lines.add("(allow process-exec (literal \"$x\"))")
            lines.add("(allow file-read* (literal \"$x\"))")
        }
        for (r in fs["read"] as List<*>) lines.add("(allow file-read* (subpath \"$r\"))")
        for (w in fs["write"] as List<*>) lines.add("(allow file-write* (subpath \"$w\"))")
        val proxy = proxyOf(p)
        if (proxy != null) lines.add("(allow network-outbound (remote tcp \"localhost:" + Js.template(obj(proxy)["port"]) + "\"))")
        return lines.joinToString("\n") + "\n"
    }
}
