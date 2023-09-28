package com.abx.planningservice.controller;

import com.abx.model.model.PlanEntity;
import com.abx.planningservice.dto.PlanInfoDto;
import com.abx.planningservice.service.PlanningService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PlanningServiceController {

    private final PlanningService planningService;

    public PlanningServiceController(PlanningService planningService) {
        this.planningService = planningService;
    }

    @PostMapping("/generate-plan")
    public ResponseEntity<PlanEntity> generatePlan(@RequestBody PlanInfoDto planInfoDto) {

        // TODO: Validation
        // return ResponseEntity.badRequest()

        // generate plan
        PlanEntity planEntity = planningService.generatePlan(planInfoDto);
        return ResponseEntity.ok(planEntity);
    }

    // TODO:
    // 1. track progress
    // 2. get progress
    // 3. resume study
    // 4. get plan/lesson
}
