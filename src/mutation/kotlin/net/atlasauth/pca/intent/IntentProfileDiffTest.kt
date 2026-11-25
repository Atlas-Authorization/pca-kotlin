package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of portable, revocable intent profiles. */
class IntentProfileDiffTest {
    private val m = "ref-intent-profile"

    private fun map(o: Any?): Map<String, Any?> = IntentOmega.obj(o)

    @Test fun signIntentProfile() = OracleCases.each(m, "signIntentProfile") { a -> IntentProfile.signIntentProfile(map(a[0]), Keys.unb64u(a[1] as String)) }

    @Test fun intentProfileShapeError() = OracleCases.each(m, "intentProfileShapeError") { a ->
        val o = if (a.size > 1) a[1] else null
        val signed = o !is Map<*, *> || false != o["signed"]
        IntentProfile.intentProfileShapeError(a[0], signed)
    }

    @Test fun verifyIntentProfile() = OracleCases.each(m, "verifyIntentProfile") { a -> IntentProfile.verifyIntentProfile(a[0]) }

    @Test fun intentProfileDigest() = OracleCases.each(m, "intentProfileDigest") { a -> IntentProfile.intentProfileDigest(a[0]) }

    @Test fun verifyProfileSuccession() = OracleCases.each(m, "verifyProfileSuccession") { a -> IntentProfile.verifyProfileSuccession(a[0], a[1]) }

    @Test fun profileApplies() = OracleCases.each(m, "profileApplies") { a -> IntentProfile.profileApplies(map(a[0]), map(a[1])) }

    @Test fun standingAdmits() = OracleCases.each(m, "standingAdmits") { a -> IntentProfile.standingAdmits(map(a[0]), map(a[1]), map(a[2])) }

    @Test fun standingPermits() = OracleCases.each(m, "standingPermits") { a -> IntentProfile.standingPermits(map(a[0]), map(a[1]), map(a[2])) }

    @Test fun profileVetoCells() = OracleCases.each(m, "profileVetoCells") { a -> IntentProfile.profileVetoCells(map(a[0]), IntentOmega.omegaFromJson(a[1])) }

    @Test fun profileCeiling() = OracleCases.each(m, "profileCeiling") { a ->
        IntentProfile.profileCeiling(map(a[0]), map(a[1]))(IntentOmega.verbSpaceFromJson(a[2]), IntentOmega.outcomeFromJson(a[3]))
    }

    @Test fun profileUsable() = OracleCases.each(m, "profileUsable") { a -> IntentProfile.profileUsable(map(a[0]), map(a[1])) }
}
