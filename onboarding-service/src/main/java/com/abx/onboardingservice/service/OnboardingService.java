package com.abx.onboardingservice.service;

import com.abx.model.model.LanguageEntity;
import com.abx.model.repository.LanguageRepository;
import com.abx.onboardingservice.dto.PlanInitializationDto;
import com.abx.onboardingservice.dto.SettingsDto;
import org.springframework.stereotype.Service;

@Service
public class OnboardingService {

    // import gpt-service
    private final LanguageRepository languageRepository;

    public OnboardingService(LanguageRepository languageRepository) {
        this.languageRepository = languageRepository;
    }

    public boolean onboardStudent(PlanInitializationDto planInitializationDto) {
        // TODO: save to database
        // TODO: call gpt-service

        return true;
    }

    public boolean initializeSettings(SettingsDto settingsDto) {
        // TODO:save in database
        LanguageEntity languageEntity = new LanguageEntity();
        languageRepository.save(languageEntity);
        return true;
    }
}
