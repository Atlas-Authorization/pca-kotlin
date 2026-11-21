package net.atlasauth.pca.compliance

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the TypeScript-reference vectors of the compliance evidence package (audit events, control mappings, reports, renderers). */
class ComplianceDiffTest {
    private val m = "ref-compliance"

    private fun at(a: List<Any?>, i: Int): Any? = if (i < a.size) a[i] else null

    @Test fun toAuditEvent() = OracleCases.each(m, "toAuditEvent") { a -> Compliance.toAuditEvent(at(a, 0)) }

    @Test fun controlMappings() = OracleCases.each(m, "controlMappings") { a ->
        if (a.isEmpty()) Compliance.controlMappings() else Compliance.controlMappings(a[0])
    }

    @Test fun constants() = OracleCases.each(m, "constants") { _ ->
        linkedMapOf<String, Any?>("COMPLIANCE_FRAMEWORKS" to Compliance.COMPLIANCE_FRAMEWORKS, "CONTROL_MAPPINGS" to Compliance.CONTROL_MAPPINGS)
    }

    @Test fun toComplianceReport() = OracleCases.each(m, "toComplianceReport") { a -> Compliance.toComplianceReport(at(a, 0), at(a, 1)) }

    @Test fun renderJson() = OracleCases.each(m, "renderJson") { a -> Compliance.renderJson(at(a, 0)) }

    @Test fun renderMarkdown() = OracleCases.each(m, "renderMarkdown") { a -> Compliance.renderMarkdown(at(a, 0)) }

    @Test fun frameworkReport() = OracleCases.each(m, "frameworkReport") { a -> Compliance.frameworkReport(at(a, 0), at(a, 1), at(a, 2)) }

    @Test fun frameworkReportToMarkdown() = OracleCases.each(m, "frameworkReportToMarkdown") { a -> Compliance.frameworkReportToMarkdown(at(a, 0)) }
}
