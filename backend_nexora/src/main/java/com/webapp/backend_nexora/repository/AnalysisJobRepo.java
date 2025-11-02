package com.webapp.backend_nexora.repository;

import com.webapp.backend_nexora.entity.AnalysisJob;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AnalysisJobRepo extends JpaRepository<AnalysisJob, Long> {
    AnalysisJob findByJobId(String jobId);
}
