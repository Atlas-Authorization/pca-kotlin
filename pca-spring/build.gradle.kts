plugins {
    alias(libs.plugins.kotlin.jvm)
}

// Spring (Boot 3 / jakarta) integration for PCA: a servlet filter, a HandlerInterceptor and an auto-configuration. A pure-JVM
// module: the core verifier is compiled in from the shared source directory, so the core library keeps no Spring dependency.
group = "net.atlasauth"
version = "0.5.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions.jvmTarget = "17"
}

kotlin {
    sourceSets["main"].kotlin.srcDir("../src/main/kotlin/net/atlasauth/pca/verifier")
    sourceSets["main"].kotlin.srcDir("../guard-common")
    sourceSets["test"].kotlin.srcDir("../guard-common-test")
}

dependencies {
    // versions of the Spring artifacts come from the Boot BOM
    implementation(platform(libs.spring.boot.dependencies))
    testImplementation(platform(libs.spring.boot.dependencies))

    compileOnly(libs.jakarta.servlet.api)
    api("org.springframework:spring-webmvc")
    api("org.springframework.boot:spring-boot-autoconfigure")
    implementation(libs.bouncycastle)

    testImplementation(libs.jakarta.servlet.api)
    testImplementation("org.springframework:spring-test")
    testImplementation("org.springframework.boot:spring-boot-test")
    testImplementation(libs.junit)
}

tasks.test {
    maxHeapSize = "2g"
    jvmArgs("-Xss16m")
}
