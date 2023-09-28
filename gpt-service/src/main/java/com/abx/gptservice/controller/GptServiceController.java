package com.abx.gptservice.controller;

import com.abx.gptservice.dto.InitializePlanResponseDto;
import com.abx.gptservice.dto.PlanDto;
import com.abx.gptservice.service.LanguageModelApi;
import com.abx.gptservice.util.GptResponseParser;
import com.abx.model.model.PlanEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GptServiceController {

    private final LanguageModelApi languageModelApi;

    public GptServiceController(LanguageModelApi languageModelApi) {
        this.languageModelApi = languageModelApi;
    }

    @PostMapping("/initialize-study-plan")
    public ResponseEntity<InitializePlanResponseDto> initStudyPlan(@RequestBody PlanDto planDto) {

        // TODO: validation
        // TODO: check communication with ChatGPT
        PlanEntity planEntity = planDto.toEntity();
        String result = languageModelApi.initializePlan(planEntity);

        var resp = GptResponseParser.parseInitializationResponse(result);

        // return ResponseEntity.badRequest();
        return ResponseEntity.ok(resp);
    }
}
