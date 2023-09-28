package com.abx.planningservice.service;

import com.abx.planningservice.dto.ImmutablePlanInfoDto;
import com.abx.planningservice.dto.PlanInfoDto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class PlanningServiceTest {

    // use @Mock for any dependencies

    private PlanningService planningService;

    @BeforeEach
    public void before() {
        planningService = new PlanningService();
    }

    @Test
    public void testGeneratePlan_returnPlanEntity() {
        String studyTopic = "test";
        PlanInfoDto planInfoDto = ImmutablePlanInfoDto.builder()
                .planName("test name")
                .studyTopic(studyTopic)
                .build();
        var res = planningService.generatePlan(planInfoDto);

        Assertions.assertEquals(studyTopic, res.getStudyTopic());
    }
}
