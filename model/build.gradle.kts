plugins {
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    id("com.abx.build.java-conventions")
    id("org.flywaydb.flyway") version "7.15.0"
}

dependencies {

    implementation("javax.validation:validation-api:2.0.1.Final")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")

    runtimeOnly("org.postgresql:postgresql")
}


flyway {
    url = "jdbc:postgresql://localhost:5432/ai_study_tutor"
    user = "postgres"
    password = "postgres"
    schemas = arrayOf("ai_study_tutor")
}