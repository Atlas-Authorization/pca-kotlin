#!/usr/bin/env python3
"""gradle-module-pom.py <module>: write pom.xml in the current directory (a Gradle-only module of the Kotlin SDK) so PIT can mutate it.
Same sources and dependencies as the module's build.gradle.kts (Maven does not read Gradle module metadata, hence the -jvm artifacts).
The compiler is the one the core pom runs on JDK 23 (2.0.21) with -language-version 1.9, i.e. the K1 front end Gradle's Kotlin 1.9.24 uses: K2 rejects ToolGuardTest.kt:91 (lambda inference), and 1.9.24 itself is unproven on JDK 23."""
import sys

V = "../src/main/kotlin/net/atlasauth/pca/"
AI = "../pca-ai-core/src/main/kotlin"
CL = [V + d for d in ("analyzer", "compliance", "durable", "events", "evidence", "explain", "gnap", "intent", "jose", "payments", "research", "scitt", "verifier", "wallet", "webauthn")]
OK = ("com.squareup.okhttp3", "okhttp", "4.12.0", "")
ICU = ("com.ibm.icu", "icu4j", "78.3", "")
BC = ("org.bouncycastle", "bcprov-jdk18on", "1.80", "")
CO = ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.8.1", "")
MODS = {
    "pca-ai-core": (CL, [BC, OK, ICU]),
    "pca-koog": ([*CL, AI], [BC, OK, ICU, CO, ("ai.koog", "koog-agents-jvm", "0.5.0", "")]),
    "pca-langchain4j": ([*CL, V + "policybridge", V + "rag", AI], [BC, OK, ICU, ("dev.langchain4j", "langchain4j", "1.0.0", "")]),
    "pca-openai": ([*CL, AI], [BC, OK, ICU, ("com.aallam.openai", "openai-client-jvm", "3.8.2", ""), ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.8.1", "test")]),
}
dirs, deps = MODS[sys.argv[1]]
deps = deps + [("junit", "junit", "4.13.2", "test")]
dep = "".join(f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version>{f'<scope>{s}</scope>' if s else ''}</dependency>\n    " for g, a, v, s in deps)
src = "".join(f"<sourceDir>${{project.basedir}}/{d}</sourceDir>" for d in ["src/main/kotlin"] + dirs)
open("pom.xml", "w").write(f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>net.atlasauth</groupId><artifactId>{sys.argv[1]}-mutation</artifactId><version>0</version>
  <!-- -Xskip-metadata-version-check: koog 0.5 pulls AWS SDK jars built with Kotlin 2.2 metadata, which 2.0.21 refuses to read otherwise -->
  <properties><project.build.sourceEncoding>UTF-8</project.build.sourceEncoding><kotlin.version>2.0.21</kotlin.version></properties>
  <dependencies>
    <dependency><groupId>org.jetbrains.kotlin</groupId><artifactId>kotlin-stdlib</artifactId><version>${{kotlin.version}}</version></dependency>
    {dep}</dependencies>
  <build>
    <sourceDirectory>src/main/kotlin</sourceDirectory>
    <testSourceDirectory>src/test/kotlin</testSourceDirectory>
    <plugins>
      <plugin>
        <groupId>org.jetbrains.kotlin</groupId><artifactId>kotlin-maven-plugin</artifactId><version>${{kotlin.version}}</version>
        <configuration><jvmTarget>17</jvmTarget><languageVersion>1.9</languageVersion><args><arg>-Xskip-metadata-version-check</arg></args></configuration>
        <executions>
          <execution><id>compile</id><phase>compile</phase><goals><goal>compile</goal></goals><configuration><sourceDirs>{src}</sourceDirs></configuration></execution>
          <execution><id>test-compile</id><phase>test-compile</phase><goals><goal>test-compile</goal></goals><configuration><sourceDirs><sourceDir>${{project.basedir}}/src/test/kotlin</sourceDir></sourceDirs></configuration></execution>
        </executions>
      </plugin>
      <plugin><artifactId>maven-surefire-plugin</artifactId><version>3.2.5</version><configuration><argLine>-Xss16m</argLine></configuration></plugin>
    </plugins>
  </build>
</project>
""")
