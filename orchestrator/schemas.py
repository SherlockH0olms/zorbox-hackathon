#!/usr/bin/env python3
"""
Data schemas and models for ZORBOX Orchestrator
This file defines the data structures used across all services for seamless integration.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
from datetime import datetime
import json


class JobState(str, Enum):
    """Job state enumeration - matches backend expectations"""
    PENDING = "pending"
    DOWNLOADING = "downloading"
    STATIC_ANALYSIS = "static_analysis"
    SANDBOX_ANALYSIS = "sandbox_analysis"
    AI_SCORING = "ai_scoring"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RiskLevel(str, Enum):
    """Risk level enumeration"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class SandboxType(str, Enum):
    """Supported sandbox types"""
    STRELKA = "strelka"
    NATIVE_ENGINE = "native_engine"
    CUCKOO = "cuckoo"
    CAPE = "cape"


@dataclass
class FileInfo:
    """File information schema - used by Backend when submitting files"""
    file_id: str
    file_name: str
    file_path: str
    file_size: int
    file_type: str
    sha256: str
    md5: str
    upload_timestamp: float
    uploaded_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "file_id": self.file_id,
            "file_name": self.file_name,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "sha256": self.sha256,
            "md5": self.md5,
            "upload_timestamp": self.upload_timestamp,
            "uploaded_by": self.uploaded_by,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileInfo':
        """Create FileInfo from dictionary"""
        return cls(**data)


@dataclass
class StaticAnalysisResult:
    """Static analysis results schema - from Strelka/Native Engine"""
    file_type: str
    file_hash: str
    entropy: float
    yara_matches: List[str] = field(default_factory=list)
    suspicious_imports: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_type": self.file_type,
            "file_hash": self.file_hash,
            "entropy": self.entropy,
            "yara_matches": self.yara_matches,
            "suspicious_imports": self.suspicious_imports,
            "suspicious_strings": self.suspicious_strings,
            "metadata": self.metadata
        }


@dataclass
class SandboxAnalysisResult:
    """Sandbox analysis results schema - from Cuckoo/CAPE/Native Engine"""
    sandbox_type: str
    task_id: Optional[str] = None
    risk_score: int = 0
    network_activity: bool = False
    file_modifications: int = 0
    processes: List[Dict[str, Any]] = field(default_factory=list)
    network_hosts: List[str] = field(default_factory=list)
    signatures: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_behaviors: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "sandbox_type": self.sandbox_type,
            "task_id": self.task_id,
            "risk_score": self.risk_score,
            "network_activity": self.network_activity,
            "file_modifications": self.file_modifications,
            "processes": self.processes,
            "network_hosts": self.network_hosts,
            "signatures": self.signatures,
            "suspicious_behaviors": self.suspicious_behaviors,
            "metadata": self.metadata
        }


@dataclass
class AIScoringResult:
    """AI scoring results schema - from AI Service"""
    ai_score: int  # 0-100
    confidence: float  # 0.0-1.0
    explanation: List[str] = field(default_factory=list)
    feature_importance: Dict[str, float] = field(default_factory=dict)
    model_version: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ai_score": self.ai_score,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "feature_importance": self.feature_importance,
            "model_version": self.model_version
        }


@dataclass
class AnalysisJob:
    """Complete analysis job schema - stored in Redis and shared with Backend"""
    job_id: str
    file_info: FileInfo
    state: JobState = JobState.PENDING
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    updated_at: Optional[float] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    error_message: Optional[str] = None
    
    # Analysis results
    static_analysis: Optional[StaticAnalysisResult] = None
    sandbox_results: Dict[str, SandboxAnalysisResult] = field(default_factory=dict)
    ai_scoring: Optional[AIScoringResult] = None
    
    # Final aggregated results
    final_risk_score: int = 0
    final_risk_level: RiskLevel = RiskLevel.UNKNOWN
    
    # Progress tracking
    progress_percentage: int = 0
    current_step: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Redis storage"""
        return {
            "job_id": self.job_id,
            "file_info": self.file_info.to_dict(),
            "state": self.state.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error_message": self.error_message,
            "static_analysis": self.static_analysis.to_dict() if self.static_analysis else None,
            "sandbox_results": {k: v.to_dict() for k, v in self.sandbox_results.items()},
            "ai_scoring": self.ai_scoring.to_dict() if self.ai_scoring else None,
            "final_risk_score": self.final_risk_score,
            "final_risk_level": self.final_risk_level.value,
            "progress_percentage": self.progress_percentage,
            "current_step": self.current_step
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisJob':
        """Create AnalysisJob from dictionary (from Redis)"""
        job = cls(
            job_id=data["job_id"],
            file_info=FileInfo.from_dict(data["file_info"]),
            state=JobState(data["state"]),
            created_at=data.get("created_at", datetime.now().timestamp()),
            updated_at=data.get("updated_at"),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            error_message=data.get("error_message"),
            final_risk_score=data.get("final_risk_score", 0),
            final_risk_level=RiskLevel(data.get("final_risk_level", "UNKNOWN")),
            progress_percentage=data.get("progress_percentage", 0),
            current_step=data.get("current_step")
        )
        
        if data.get("static_analysis"):
            static_data = data["static_analysis"]
            job.static_analysis = StaticAnalysisResult(**static_data)
        
        if data.get("sandbox_results"):
            for k, v in data["sandbox_results"].items():
                job.sandbox_results[k] = SandboxAnalysisResult(**v)
        
        if data.get("ai_scoring"):
            job.ai_scoring = AIScoringResult(**data["ai_scoring"])
        
        return job


# API Request/Response Schemas for Backend Integration

@dataclass
class JobStatusResponse:
    """Response schema for Backend GET /api/jobs/{job_id}/status endpoint"""
    job_id: str
    state: str
    progress_percentage: int
    current_step: Optional[str]
    created_at: float
    updated_at: Optional[float]
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "state": self.state,
            "progress_percentage": self.progress_percentage,
            "current_step": self.current_step,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "error_message": self.error_message
        }


@dataclass
class JobResultResponse:
    """Response schema for Backend GET /api/jobs/{job_id}/result endpoint"""
    job_id: str
    file_info: Dict[str, Any]
    final_risk_score: int
    final_risk_level: str
    static_analysis: Optional[Dict[str, Any]]
    sandbox_analysis: Dict[str, Any]
    ai_scoring: Optional[Dict[str, Any]]
    report_pdf_url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "file_info": self.file_info,
            "final_risk_score": self.final_risk_score,
            "final_risk_level": self.final_risk_level,
            "static_analysis": self.static_analysis,
            "sandbox_analysis": self.sandbox_analysis,
            "ai_scoring": self.ai_scoring,
            "report_pdf_url": self.report_pdf_url
        }


# AI Service Request/Response Schemas

@dataclass
class AIScoringRequest:
    """Request schema for AI Service POST /score endpoint"""
    static_analysis: Dict[str, Any]
    sandbox_analysis: Dict[str, Any]
    file_info: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "static_analysis": self.static_analysis,
            "sandbox_analysis": self.sandbox_analysis,
            "file_info": self.file_info
        }


@dataclass
class BackendNotification:
    """Schema for notifying Backend about job status updates"""
    job_id: str
    state: str
    progress_percentage: int
    results: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "state": self.state,
            "progress_percentage": self.progress_percentage,
            "results": self.results
        }
