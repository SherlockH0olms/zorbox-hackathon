package com.webapp.backend_nexora.client;

import com.webapp.backend_nexora.dtos.SandboxResultDto;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.client.WebClient;

@Service
@RequiredArgsConstructor
public class SandboxClient {
    private final WebClient webClient;

    @Value("${sandbox.api.url}")
    private String sandboxUrl;

    public SandboxResultDto analyzeFile(MultipartFile file, String password) {
        return webClient.post()
                .uri(sandboxUrl + "/analyze/file")
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .bodyValue(file)
                .retrieve()
                .bodyToMono(SandboxResultDto.class)
                .block();
    }

    public SandboxResultDto analyzeUrl(String url) {
        return webClient.post()
                .uri(sandboxUrl + "/analyze/url")
                .bodyValue(url)
                .retrieve()
                .bodyToMono(SandboxResultDto.class)
                .block();
    }
}
