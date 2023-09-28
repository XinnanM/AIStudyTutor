plugins {
    // use Gradle Libs Error Suppressor
    // if your IntelliJ mark this syntax error
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    id("com.abx.build.java-conventions")
}


dependencies {

    implementation(project(":model"))
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.1")
    implementation("com.theokanning.openai-gpt3-java:api:0.12.0")


    annotationProcessor("org.immutables:value:2.9.3")
    compileOnly("org.immutables:value:2.9.3")

}