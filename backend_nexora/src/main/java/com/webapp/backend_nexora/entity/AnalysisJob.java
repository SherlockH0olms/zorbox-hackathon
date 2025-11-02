package com.webapp.backend_nexora.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "analysis_jobs")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AnalysisJob {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String jobId;
    private String fileName;
    private String sha256;
    private String mime;
    private double ruleScore;
    private double aiScore;
    private double finalScore;
    private String riskLevel;
    private String summary;
}
