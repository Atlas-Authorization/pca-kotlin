package net.atlasauth.pca.goal.kernel

/** The goal IR of the proved compiler (types, ontology, action and history), as immutable values with structural equality. */

internal sealed class GUnit {
    data class Money(val ccy: String) : GUnit()
    object Count : GUnit()
    object Duration : GUnit()
    object Instant : GUnit()
    object Bytes : GUnit()
    object Ratio : GUnit()
}

internal data class GQ(val u: GUnit, val n: Long)

internal sealed class GAtom {
    data class AQ(val q: GQ) : GAtom()
    data class AS(val s: String) : GAtom()
}

internal sealed class GV {
    data class VQ(val q: GQ) : GV()
    data class VS(val s: String) : GV()
    data class VSet(val items: List<GAtom>) : GV()
}

internal sealed class GTy {
    data class TyQ(val u: GUnit) : GTy()
    object TyS : GTy()
}

internal sealed class GTerm {
    data class Param(val path: String, val ty: GTy) : GTerm()
    data class Lit(val v: GV) : GTerm()
    data class HistAgg(val bid: String, val u: GUnit) : GTerm()
}

/** Declaration order is the tape index (350 + ordinal). */
internal enum class GOp { Eq, Ne, Lt, Lte, Gt, Gte, In, Nin }

internal sealed class GCond {
    object CTrue : GCond()
    data class Cmp(val op: GOp, val l: GTerm, val r: GTerm) : GCond()
    data class And(val a: GCond, val b: GCond) : GCond()
    data class Or(val a: GCond, val b: GCond) : GCond()
    data class Not(val c: GCond) : GCond()
}

internal sealed class ResPart {
    data class PartExact(val id: String) : ResPart()
    data class PartOneOf(val ids: List<String>) : ResPart()
    data class PartRelated(val rel: String, val anchor: String) : ResPart()
}

internal sealed class ResSel {
    data class Exact(val id: String) : ResSel()
    data class OneOf(val ids: List<String>) : ResSel()
    data class Related(val rel: String, val anchor: String) : ResSel()
    data class AnyRes(val reason: String) : ResSel()
    data class AllOf(val parts: List<ResPart>) : ResSel()
}

internal data class GGrant(val gid: String, val verb: String, val res: ResSel, val cond: GCond)

internal sealed class ProhTarget {
    data class PVerb(val verb: String) : ProhTarget()
    data class PEffect(val cls: String) : ProhTarget()
}

internal data class GProhibit(val pid: String, val target: ProhTarget, val res: ResSel, val cond: GCond)

/** Declaration order is the tape index (400 + ordinal). */
internal enum class GAgg { Count, Sum, Max, Distinct }

internal sealed class GSel {
    data class SelGids(val gids: List<String>) : GSel()
    data class SelEffect(val cls: String) : GSel()
}

internal sealed class GWindow {
    object WTask : GWindow()
    data class WSliding(val ms: Long) : GWindow()
    data class WPeriod(val ms: Long, val t0: Long) : GWindow()
    object WLifetime : GWindow()
}

internal sealed class GScope {
    object SSession : GScope()
    object SPrincipal : GScope()
    object SOrg : GScope()
    data class SFleet(val agents: List<String>) : GScope()
}

internal enum class OnExceed { Deny, Escalate }

internal data class BCore(val agg: GAgg, val value: GTerm, val key: String, val window: GWindow, val scope: GScope, val cap: GQ, val onExceed: OnExceed)

internal data class GBound(val bid: String, val sel: GSel, val core: BCore)

internal data class GValidity(val notBefore: Long, val notAfter: Long, val maxIdle: Long)

internal data class GDeleg(val maxDepth: Long, val narrowOnly: Boolean, val mayTouch: List<String>)

internal data class GHole(val hid: String, val q: String, val domain: List<String>, val affects: List<String>, val global: Boolean)

internal data class GGoal(
    val v: Long, val principal: String, val ontDigest: String, val nlDigest: String, val sources: List<String>,
    val grants: List<GGrant>, val prohibits: List<GProhibit>, val bounds: List<GBound>, val validity: GValidity,
    val deleg: GDeleg, val escalateOn: List<GCond>, val wildcardAck: List<String>, val holes: List<GHole>,
)

internal data class ParamDecl(val path: String, val ty: GTy)
internal data class VerbDecl(val verb: String, val cls: String, val params: List<ParamDecl>)
internal data class RelDecl(val rel: String, val anchor: String, val members: List<String>)
internal data class GOntology(val verbs: List<VerbDecl>, val rels: List<RelDecl>)

internal data class GAct(
    val verb: String, val res: String, val params: Map<String, GV>, val t: Long,
    val sess: String, val prin: String, val org: String, val agent: String, val depth: Long,
)

internal data class GAdm(val gid: String, val act: GAct)
internal data class GHist(val adms: List<GAdm>, val last: Long, val aggs: Map<String, GQ>)

/** A tape token: keyword, exact integer, exact string. */
internal sealed class Tok {
    data class Kw(val k: Long) : Tok()
    data class I(val i: Long) : Tok()
    data class S(val s: String) : Tok()
}
