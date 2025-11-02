package com.webapp.backend_nexora.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AIResultDto {
    private String jobId;
    private double aiScore;
    private double confidence;
    private Map<String, Object> explanation;
    private String summary;
}
