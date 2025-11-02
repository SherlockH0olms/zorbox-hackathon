package com.webapp.backend_nexora.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SandboxResultDto {
    private String jobId;
    private String filename;
    private String sha256;
    private String mime;
    private List<String> yaraHits;
    private List<String> macros;
    private List<String> behaviors;
    private double entropyScore;
    private double ruleScore;
    private String riskLevel;
}
