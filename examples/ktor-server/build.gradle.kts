plugins {
    kotlin("jvm") version "1.9.24"
    application
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin { jvmToolchain(17) }

application {
    mainClass.set("example.MainKt")
}

dependencies {
    implementation("net.atlasauth:pca-ktor")
    implementation("io.ktor:ktor-server-netty:2.3.12")
    runtimeOnly("ch.qos.logback:logback-classic:1.4.14")

    testImplementation("io.ktor:ktor-server-test-host:2.3.12")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    testImplementation("junit:junit:4.13.2")
}

tasks.test {
    maxHeapSize = "1g"
    jvmArgs("-Xss16m")
}
