package com.abx.gptservice.dto;

import org.immutables.value.Value;

@Value.Immutable
public interface InitializePlanResponseDto {
    String planUuid();

    String planName();
}
