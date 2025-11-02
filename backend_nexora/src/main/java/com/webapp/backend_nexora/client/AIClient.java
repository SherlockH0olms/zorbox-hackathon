package com.webapp.backend_nexora.client;

import com.webapp.backend_nexora.dtos.AIResultDto;
import com.webapp.backend_nexora.dtos.SandboxResultDto;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class AIClient {
    private final WebClient webClient;

    @Value("${ai.api.url}")
    private String aiUrl;

    @Value("${ai.api.key}")
    private String aiKey;

    public AIResultDto analyzeWithAI(SandboxResultDto sandboxResult) {
        String prompt = """
                Analyze the sandbox output and return a JSON like:
                {
                  "job_id": "%s",
                  "ai_score": 0-100,
                  "confidence": 0-1,
                  "explanation": {"macro_detected": bool, "entropy_high": bool, "encoded_strings": int},
                  "summary": "brief explanation"
                }
                Use the sandbox details to estimate risk.
                """.formatted(sandboxResult.getJobId());

        return webClient.post()
                .uri(aiUrl)
                .header("Authorization", "Bearer " + aiKey)
                .bodyValue(Map.of("prompt", prompt))
                .retrieve()
                .bodyToMono(AIResultDto.class)
                .block();
    }
}
