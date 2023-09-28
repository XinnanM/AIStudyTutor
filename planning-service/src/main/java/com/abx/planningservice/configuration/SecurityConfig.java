package com.abx.planningservice.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain configureSecurity(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests() //
                .anyRequest()
                .permitAll()
                .and()
                .csrf()
                .disable()
                .cors()
                .disable()
                .build();
    }
}
