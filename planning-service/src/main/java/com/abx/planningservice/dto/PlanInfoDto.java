package com.abx.planningservice.dto;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.immutables.value.Value;

@Value.Immutable
@JsonSerialize(as = ImmutablePlanInfoDto.class)
@JsonDeserialize(as = ImmutablePlanInfoDto.class)
public interface PlanInfoDto {

    String planName();

    String studyTopic();

    // TODO: add the rest of the info
}
