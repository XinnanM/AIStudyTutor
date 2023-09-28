package com.abx.build

plugins {
    id("com.diffplug.spotless")
}

repositories {
    mavenCentral()
}


spotless {
    isEnforceCheck = false
    java {
        palantirJavaFormat("2.28.0")
        targetExclude("**/build/generated/**")
    }
}