package net.atlasauth.pca.sandbox

import net.atlasauth.pca.jose.Js

/** Flatten the generated seccomp and Landlock profiles into the flags of a reference confinement helper (it never reads a second source of truth). */
@Suppress("UNCHECKED_CAST")
object Confine {
    private fun shortName(n: Any?): String = (n as String).replaceFirst(Regex("^LANDLOCK_ACCESS_"), "")

    private fun joinShort(xs: List<*>): String = xs.joinToString(",") { shortName(it) }

    /** JavaScript String(n) of a number or string member. */
    private fun jsStr(o: Any?): String = Js.template(o)

    /** The helper's flags for a policy; run as `<helper> <flags> -- <command>`. */
    @JvmStatic
    fun confineArgs(policy: Map<String, Any?>): List<String> {
        val ll = Profiles.landlockRuleset(policy)
        val sc = Profiles.seccompProfile(policy)
        val rules = ll["rules"] as Map<String, Any?>
        val netRules = rules["net"] as List<Any?>
        val args = ArrayList<String>()
        args.add("--fs-handled")
        args.add(joinShort(ll["handled_access_fs"] as List<*>))
        if (netRules.isNotEmpty() || (policy["net"] as Map<String, Any?>)["proxy"] != null) {
            args.add("--net-handled")
            args.add(joinShort(ll["handled_access_net"] as List<*>))
        }
        for (r in rules["fs"] as List<*>) {
            val m = r as Map<String, Any?>
            args.add("--fs")
            args.add(m["path"].toString() + ":" + joinShort(m["access"] as List<*>))
        }
        for (r in netRules) {
            val m = r as Map<String, Any?>
            args.add("--net")
            args.add(jsStr(m["port"]) + ":" + joinShort(m["access"] as List<*>))
        }
        syscallFlags(args, sc)
        return args
    }

    /** The syscall flags, appended after the filesystem and network flags in the reference's order. */
    private fun syscallFlags(out: MutableList<String>, sc: Map<String, Any?>) {
        for (s in sc["syscalls"] as List<*>) {
            val m = s as Map<String, Any?>
            val names = m["names"] as List<*>
            if (m["args"] != null) {
                for (a in m["args"] as List<*>) {
                    val am = a as Map<String, Any?>
                    for (n in names) {
                        out.add("--allow-arg")
                        out.add(n.toString() + ":" + jsStr(am["index"]) + ":" + jsStr(am["value"]))
                    }
                }
            } else for (n in names) {
                out.add("--allow")
                out.add(n as String)
            }
        }
    }
}
