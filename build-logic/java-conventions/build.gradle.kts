plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
}

dependencies {
    implementation(project(":checkstyle"))
    implementation(project(":java-formatter"))
}
