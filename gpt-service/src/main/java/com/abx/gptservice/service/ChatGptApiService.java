package com.abx.gptservice.service;

import com.abx.model.model.PlanEntity;
import org.springframework.stereotype.Service;

@Service
public class ChatGptApiService implements LanguageModelApi {

    @Override
    public String initializePlan(PlanEntity planEntity) {
        // TODO: ChatGPT Java client

        // predefine query
        // question -> output the response with the following format
        // output in json with the following format
        //  {
        //   name :xxx
        //   study plan: xxx
        //  }
        //
        return null;
    }
}
