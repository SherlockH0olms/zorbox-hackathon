package com.webapp.backend_nexora.service;
import com.webapp.backend_nexora.dtos.AIResultDto;
import com.webapp.backend_nexora.dtos.AnalysisResponse;
import com.webapp.backend_nexora.dtos.SandboxResultDto;
import org.springframework.stereotype.Service;

@Service
public class AggregatorService {
    public AnalysisResponse aggregate(SandboxResultDto sandbox, AIResultDto ai) {
        double finalScore = 0.6 * sandbox.getRuleScore() + 0.4 * ai.getAiScore();
        String risk = getRiskLevel(finalScore);

        return AnalysisResponse.builder()
                .jobId(sandbox.getJobId())
                .fileName(sandbox.getFilename())
                .sha256(sandbox.getSha256())
                .mime(sandbox.getMime())
                .aiScore(ai.getAiScore())
                .finalScore(finalScore)
                .riskLevel(risk)
                .summary(ai.getSummary())
                .build();
    }

    private String getRiskLevel(double score) {
        if (score < 30) return "Low";
        if (score < 60) return "Medium";
        if (score < 80) return "High";
        return "Critical";
    }
}
