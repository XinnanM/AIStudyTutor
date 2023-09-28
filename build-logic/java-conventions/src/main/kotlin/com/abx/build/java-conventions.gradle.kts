package com.abx.build

plugins {
    java
}

repositories {
    mavenCentral()
}

plugins.apply("com.abx.build.checkstyle")
plugins.apply("com.abx.build.java-formatter")


dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
