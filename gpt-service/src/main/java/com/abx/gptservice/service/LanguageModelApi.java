package com.abx.gptservice.service;

import com.abx.model.model.PlanEntity;

public interface LanguageModelApi {

    String initializePlan(PlanEntity planEntity);
}
