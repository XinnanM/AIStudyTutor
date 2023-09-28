plugins {
    // use Gradle Libs Error Suppressor
    // if your IntelliJ mark this syntax error
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    id("com.abx.build.java-conventions")
}

dependencies {
    implementation(project(mapOf("path" to ":model")))
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")

    runtimeOnly("org.postgresql:postgresql")
}