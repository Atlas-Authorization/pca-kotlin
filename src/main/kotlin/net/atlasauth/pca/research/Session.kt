package net.atlasauth.pca.research

import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Facade
import net.atlasauth.pca.verifier.Keys

/**
 * A multi-agent session, the delegation-tree "team" view: a root agent plus the sub-agents it delegates to all share ONE signed goal; the
 * session groups them so a principal sees the whole team under a goal and the console can be scoped to it. Pure.
 *
 * [members] is the root first, then each added sub-agent, in delegation order; [goalCommit] the shared signed goal commitment (from the
 * root grant), "" when the grant carries none.
 */
class Session(val root: Facade.Handle?, members: List<Facade.Handle>, val goalCommit: String) {
    val members: List<Facade.Handle> = ArrayList(members)

    /** What [addMember] returns: the grown session and the new member. */
    class Added internal constructor(val session: Session, val member: Facade.Handle)

    companion object {
        /** Deepest delegation chain a session accepts. */
        const val SESSION_MAX_DEPTH = 32

        private fun goalOf(h: Facade.Handle): String = Authorize.readEnvelope(h.grant)?.get("goal_commit") as? String ?: ""

        /** Start a session from a root agent. */
        @JvmStatic
        fun startSession(root: Facade.Handle): Session = Session(root, listOf(root), goalOf(root))

        /** Add a sub-agent: one attenuated delegation hop under the session's current leaf. Throws past [SESSION_MAX_DEPTH] hops. */
        @JvmStatic
        @JvmOverloads
        fun addMember(session: Session, child: Keys.SuiteKey? = null, addedCaveats: List<Any?>? = null): Added {
            if (session.members.size > SESSION_MAX_DEPTH) throw IllegalArgumentException("addMember: a session is limited to $SESSION_MAX_DEPTH delegation hops")
            val parent = session.members[session.members.size - 1]
            val member = parent.subAgent(child, addedCaveats ?: emptyList())
            return Added(Session(session.root, session.members + member, session.goalCommit), member)
        }

        /** The holder ids (b64u public keys) of every agent in the session. */
        @JvmStatic
        fun sessionAgents(session: Session): List<String> = session.members.map { it.holder.ed!!.id() }

        /** A console view scoped to just this session's agents. */
        @JvmStatic
        @Suppress("UNCHECKED_CAST")
        fun sessionConsole(session: Session, events: List<Any?>): Map<String, Any?> {
            val ids = sessionAgents(session).toSet()
            val mine = ArrayList<Any?>()
            for (e in events) {
                if (e == null) throw IllegalArgumentException("sessionConsole: an event must not be null")
                val m = e as? Map<String, Any?>
                if (m != null && m["agent"] is String && ids.contains(m["agent"])) mine.add(e)
            }
            return Console.buildConsole(mine)
        }

        /**
         * True iff every member shares the root's goal commitment (a well-formed team). A root without a readable envelope has no goal commitment
         * (""), and members that all lack one do not "share a goal": false.
         */
        @JvmStatic
        fun sharesGoal(session: Session): Boolean {
            if (session.goalCommit.isEmpty()) return false
            return session.members.all { goalOf(it) == session.goalCommit }
        }

        /** Depth of the delegation tree (0 = root only). */
        @JvmStatic
        fun sessionDepth(session: Session): Int = session.members.size - 1
    }
}
