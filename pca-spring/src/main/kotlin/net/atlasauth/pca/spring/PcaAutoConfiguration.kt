package net.atlasauth.pca.spring

import jakarta.servlet.DispatcherType
import net.atlasauth.pca.guard.PcaExecutorConfig
import net.atlasauth.pca.guard.PcaGuardConfig
import net.atlasauth.pca.verifier.Authorize
import net.atlasauth.pca.verifier.Pca
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean

/**
 * `atlas.pca.*` properties. Nothing is enforced until `atlas.pca.enabled=true`; once enabled, a missing component refuses every
 * request (403 `authorize_config`), it never turns enforcement off.
 *
 *  - `enabled`        register the [PcaFilter] (default false: the integration is opt-in)
 *  - `audience`       this resource server's id; the PCActn's signed `aud` must equal it
 *  - `signature-only` the explicit opt-in to verify the signature only; cannot be combined with an `Authorize.AuthorizeOptions` bean
 *  - `url-patterns`   the URL patterns the filter covers (default `/*`)
 *  - `order`          the filter order (default 0)
 */
@ConfigurationProperties(prefix = "atlas.pca")
class PcaProperties {
    var enabled: Boolean = false
    var audience: String? = null
    var signatureOnly: Boolean = false
    var urlPatterns: List<String> = listOf("/*")
    var order: Int = 0
}

/**
 * Wires the guard from beans: a [PcaGrantResolver], an `Authorize.AuthorizeOptions` (replay store, revocation check, ...), an
 * optional [PcaOperationMapper], an optional [PcaWorkflowStepMapper] (K5 workflow step; the gate itself is `AuthorizeOptions.workflow`), an optional [PcaExecutorConfig] (run-once execution; the filter only) and an optional `Pca.IntentPolicy` and `java.time.Clock`. Define your own `PcaGuardConfig`, `PcaFilter` or
 * `PcaInterceptor` bean to replace the matching default. The interceptor bean is not registered with MVC for you: add it to a
 * `WebMvcConfigurer` where you want header-only guarding.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "atlas.pca", name = ["enabled"], havingValue = "true")
@EnableConfigurationProperties(PcaProperties::class)
class PcaAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean(PcaGuardConfig::class)
    fun pcaGuardConfig(
        props: PcaProperties,
        resolver: ObjectProvider<PcaGrantResolver>,
        authorize: ObjectProvider<Authorize.AuthorizeOptions>,
        intentPolicy: ObjectProvider<Pca.IntentPolicy>,
        clock: ObjectProvider<java.time.Clock>,
        executor: ObjectProvider<PcaExecutorConfig>,
    ): PcaGuardConfig {
        val c = clock.getIfAvailable()
        val now: () -> Long = if (c == null) ({ System.currentTimeMillis() }) else ({ c.millis() })
        val r = resolver.getIfAvailable()
        val fn: ((String) -> Map<String, Any?>?)? = if (r == null) null else (fun(ref: String): Map<String, Any?>? = r.resolve(ref))
        return PcaGuardConfig(
            props.audience,
            fn,
            authorize.getIfAvailable(),
            intentPolicy.getIfAvailable(),
            props.signatureOnly,
            now,
            executor.getIfAvailable(),
        )
    }

    @Bean
    @ConditionalOnMissingBean(PcaFilter::class)
    fun pcaFilter(config: PcaGuardConfig, mapper: ObjectProvider<PcaOperationMapper>, workflow: ObjectProvider<PcaWorkflowStepMapper>): PcaFilter =
        PcaFilter(config, if (config.signatureOnly) null else mapper.getIfAvailable(), workflow.getIfAvailable())

    @Bean
    fun pcaFilterRegistration(filter: PcaFilter, props: PcaProperties): FilterRegistrationBean<PcaFilter> {
        val reg = FilterRegistrationBean(filter)
        reg.setUrlPatterns(props.urlPatterns)
        reg.order = props.order
        reg.setDispatcherTypes(DispatcherType.REQUEST)
        return reg
    }

    @Bean
    @ConditionalOnMissingBean(PcaInterceptor::class)
    fun pcaInterceptor(config: PcaGuardConfig, mapper: ObjectProvider<PcaOperationMapper>, workflow: ObjectProvider<PcaWorkflowStepMapper>): PcaInterceptor =
        PcaInterceptor(config, if (config.signatureOnly) null else mapper.getIfAvailable(), workflow.getIfAvailable())
}
