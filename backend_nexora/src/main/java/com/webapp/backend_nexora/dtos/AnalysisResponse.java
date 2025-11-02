package com.webapp.backend_nexora.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AnalysisResponse {
    private String jobId;
    private String fileName;
    private String sha256;
    private String mime;
    private double aiScore;
    private double finalScore;
    private String riskLevel;
    private String summary;
}
