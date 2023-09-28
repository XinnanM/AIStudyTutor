package com.abx.planningservice.service;

import com.abx.model.model.PlanEntity;
import com.abx.planningservice.dto.PlanInfoDto;
import org.springframework.stereotype.Service;

@Service
public class PlanningService {

    public PlanEntity generatePlan(PlanInfoDto planInfoDto) {
        // TODO: add gpt-service

        var planEntity = new PlanEntity();
        planEntity.setStudyTopic(planInfoDto.studyTopic());
        return planEntity;
    }
}
