package com.abx.onboardingservice.dto;

public class SettingsDto {
    private String preferredLanguage;
    private String preferredStudyStyle;

    public String getPreferredLanguage() {
        return preferredLanguage;
    }

    public void setPreferredLanguage(String preferredLanguage) {
        this.preferredLanguage = preferredLanguage;
    }

    public String getPreferredStudyStyle() {
        return preferredStudyStyle;
    }

    public void setPreferredStudyStyle(String preferredStudyStyle) {
        this.preferredStudyStyle = preferredStudyStyle;
    }
}
