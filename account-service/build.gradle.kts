plugins {
    // use Gradle Libs Error Suppressor
    // if your IntelliJ mark this syntax error
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)

    id("org.flywaydb.flyway") version "7.15.0"
    id("com.abx.build.java-conventions")
}

dependencies {

    implementation("javax.validation:validation-api:2.0.1.Final")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("io.jsonwebtoken:jjwt-api:0.11.5")

    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.11.5")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.11.5")
    runtimeOnly("org.postgresql:postgresql")
}


 flyway {
     url = "jdbc:postgresql://localhost:5432/account_service"
     user = "postgres"
     password = "postgres"
     schemas = arrayOf("account_service")
 }