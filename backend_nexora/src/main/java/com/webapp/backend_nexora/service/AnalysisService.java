package com.webapp.backend_nexora.service;

import com.webapp.backend_nexora.client.AIClient;
import com.webapp.backend_nexora.client.SandboxClient;
import com.webapp.backend_nexora.dtos.AIResultDto;
import com.webapp.backend_nexora.dtos.AnalysisRequest;
import com.webapp.backend_nexora.dtos.AnalysisResponse;
import com.webapp.backend_nexora.dtos.SandboxResultDto;
import com.webapp.backend_nexora.entity.AnalysisJob;
import com.webapp.backend_nexora.repository.AnalysisJobRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AnalysisService {
    private final FileValidationService fileValidationService;
    private final SandboxClient sandboxClient;
    private final AIClient aiClient;
    private final AggregatorService aggregatorService;
    private final AnalysisJobRepo jobRepo;

    public AnalysisResponse analyze(AnalysisRequest request) {
        SandboxResultDto sandboxResult;
        String jobId = UUID.randomUUID().toString();

        if (request.getFile() != null && !request.getFile().isEmpty()) {
            fileValidationService.validate(request.getFile(), request.getPassword());
            sandboxResult = sandboxClient.analyzeFile(request.getFile(), request.getPassword());
        } else if (request.getUrl() != null && !request.getUrl().isBlank()) {
            sandboxResult = sandboxClient.analyzeUrl(request.getUrl());
        } else {
            throw new IllegalArgumentException("Neither file nor URL provided");
        }

        sandboxResult.setJobId(jobId);

        AIResultDto aiResult = aiClient.analyzeWithAI(sandboxResult);
        AnalysisResponse response = aggregatorService.aggregate(sandboxResult, aiResult);

        jobRepo.save(AnalysisJob.builder()
                .jobId(jobId)
                .fileName(response.getFileName())
                .sha256(response.getSha256())
                .mime(response.getMime())
                .ruleScore(sandboxResult.getRuleScore())
                .aiScore(aiResult.getAiScore())
                .finalScore(response.getFinalScore())
                .riskLevel(response.getRiskLevel())
                .summary(response.getSummary())
                .build());

        return response;
    }
}
