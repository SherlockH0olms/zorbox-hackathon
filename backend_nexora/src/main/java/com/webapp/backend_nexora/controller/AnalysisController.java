package com.webapp.backend_nexora.controller;

import com.webapp.backend_nexora.dtos.AnalysisRequest;
import com.webapp.backend_nexora.dtos.AnalysisResponse;
import com.webapp.backend_nexora.service.AnalysisService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/analysis")
@RequiredArgsConstructor
public class AnalysisController {
    private final AnalysisService analysisService;

    @PostMapping
    public ResponseEntity<AnalysisResponse> analyze(
            @RequestParam(required = false) MultipartFile file,
            @RequestParam(required = false) String url,
            @RequestParam(required = false) String password) {

        AnalysisRequest request = AnalysisRequest.builder()
                .file(file)
                .url(url)
                .password(password)
                .build();

        return ResponseEntity.ok(analysisService.analyze(request));
    }
}
