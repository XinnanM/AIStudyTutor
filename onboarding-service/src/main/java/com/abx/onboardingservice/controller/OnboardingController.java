package com.abx.onboardingservice.controller;

import com.abx.onboardingservice.dto.PlanInitializationDto;
import com.abx.onboardingservice.dto.SettingsDto;
import com.abx.onboardingservice.service.OnboardingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OnboardingController {

    // bean injection

    private final OnboardingService onboardingService;

    public OnboardingController(OnboardingService onboardingService) {
        this.onboardingService = onboardingService;
    }

    @PostMapping
    public ResponseEntity<Boolean> onboardStudent(@RequestBody PlanInitializationDto planInitializationDto) {

        // TODO: validation

        boolean resp = onboardingService.onboardStudent(planInitializationDto);

        return ResponseEntity.ok(resp);
    }

    @PostMapping
    public ResponseEntity<Boolean> initializeSettings(@RequestBody SettingsDto settingsDto) {
        // TODO: validation

        // TODO: save in database

        return ResponseEntity.ok(true);
    }
}
