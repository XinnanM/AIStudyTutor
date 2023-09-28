plugins {
    // use Gradle Libs Error Suppressor
    // if your IntelliJ mark this syntax error
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    id("com.abx.build.java-conventions")
}

dependencies {

    implementation(project(":model"))
    implementation("org.springframework.boot:spring-boot-starter-security")

    annotationProcessor("org.immutables:value:2.9.3")
    compileOnly("org.immutables:value:2.9.3")
}