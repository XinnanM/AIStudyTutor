package com.abx.gptservice.dto;

import com.abx.model.model.PlanEntity;
import org.immutables.value.Value;

@Value.Immutable
public interface PlanDto {

    String studyTopic();

    default PlanEntity toEntity() {
        PlanEntity planEntity = new PlanEntity();
        planEntity.setStudyTopic(studyTopic());
        return planEntity;
    }
}
