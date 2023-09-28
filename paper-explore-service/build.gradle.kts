plugins {
    // use Gradle Libs Error Suppressor
    // if your IntelliJ mark this syntax error
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    id("com.abx.build.java-conventions")
}

dependencies {
}