package com.abx.planningservice.controller;

import static org.mockito.Mockito.when;

import com.abx.model.model.PlanEntity;
import com.abx.planningservice.configuration.SecurityConfig;
import com.abx.planningservice.service.PlanningService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@WebMvcTest(PlanningServiceController.class)
@ContextConfiguration(classes = SecurityConfig.class)
@ComponentScan(basePackages = "com.abx.planningservice.controller")
public class PlanningServiceControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private PlanningService planningService;

    @Test
    public void testGeneratePlanApi() throws Exception {
        String studyTopic = "test-topic";
        String expectedResult = String.format("{\"studyTopic\": \"%s\"}", studyTopic);
        String payload = "{\n" + "    \"planName\": \"test plan\",\n" + "    \"studyTopic\": \"test topic 2\"\n" + "}";

        PlanEntity planEntity = new PlanEntity();
        planEntity.setStudyTopic(studyTopic);

        when(planningService.generatePlan(ArgumentMatchers.any())).thenReturn(planEntity);

        this.mockMvc
                .perform(MockMvcRequestBuilders.post("/generate-plan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().json(expectedResult));
    }
}
