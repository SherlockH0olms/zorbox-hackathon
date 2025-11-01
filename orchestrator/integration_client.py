#!/usr/bin/env python3
"""
Integration client for communicating with Backend and AI Service
Provides standardized interfaces for all external service calls.
"""

import requests
import logging
import time
from typing import Optional, Dict, Any
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from .config import Config, BackendConfig, AIServiceConfig
from .schemas import (
    AnalysisJob, JobStatusResponse, JobResultResponse,
    AIScoringRequest, AIScoringResult, BackendNotification
)

logger = logging.getLogger(__name__)


class BackendClient:
    """Client for Backend API communication"""
    
    def __init__(self, config: BackendConfig):
        self.config = config
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.config.retry_attempts,
            backoff_factor=self.config.retry_delay,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "PATCH"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        if self.config.api_key:
            session.headers.update({"Authorization": f"Bearer {self.config.api_key}"})
        
        session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        
        return session
    
    def notify_job_status(self, job: AnalysisJob) -> bool:
        """
        Notify Backend about job status update
        Endpoint: PUT /api/jobs/{job_id}/status
        """
        try:
            url = f"{self.config.base_url}/api/jobs/{job.job_id}/status"
            
            notification = BackendNotification(
                job_id=job.job_id,
                state=job.state.value,
                progress_percentage=job.progress_percentage,
                results=job.to_dict() if job.state.value == "completed" else None
            )
            
            response = self.session.put(
                url,
                json=notification.to_dict(),
                timeout=self.config.timeout
            )
            
            if response.status_code in [200, 204]:
                logger.info(f"Successfully notified backend about job {job.job_id} status: {job.state.value}")
                return True
            else:
                logger.warning(f"Backend notification failed: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error notifying backend: {e}")
            return False
    
    def update_job_result(self, job: AnalysisJob) -> bool:
        """
        Update Backend with final job results
        Endpoint: PUT /api/jobs/{job_id}/result
        """
        try:
            url = f"{self.config.base_url}/api/jobs/{job.job_id}/result"
            
            result_data = {
                "job_id": job.job_id,
                "file_info": job.file_info.to_dict(),
                "final_risk_score": job.final_risk_score,
                "final_risk_level": job.final_risk_level.value,
                "static_analysis": job.static_analysis.to_dict() if job.static_analysis else None,
                "sandbox_analysis": {k: v.to_dict() for k, v in job.sandbox_results.items()},
                "ai_scoring": job.ai_scoring.to_dict() if job.ai_scoring else None,
                "completed_at": job.completed_at
            }
            
            response = self.session.put(
                url,
                json=result_data,
                timeout=self.config.timeout
            )
            
            if response.status_code in [200, 204]:
                logger.info(f"Successfully updated backend with results for job {job.job_id}")
                return True
            else:
                logger.warning(f"Backend result update failed: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error updating backend results: {e}")
            return False
    
    def get_job_info(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get job information from Backend
        Endpoint: GET /api/jobs/{job_id}
        """
        try:
            url = f"{self.config.base_url}/api/jobs/{job_id}"
            response = self.session.get(url, timeout=self.config.timeout)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to get job info: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting job info: {e}")
            return None
    
    def health_check(self) -> bool:
        """
        Check if Backend is healthy
        Endpoint: GET /api/health
        """
        try:
            url = f"{self.config.base_url}/api/health"
            response = self.session.get(url, timeout=5)
            return response.status_code == 200
        except:
            return False


class AIServiceClient:
    """Client for AI Service communication"""
    
    def __init__(self, config: AIServiceConfig):
        self.config = config
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.config.retry_attempts,
            backoff_factor=self.config.retry_delay,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        
        return session
    
    def calculate_score(self, static_analysis: Dict[str, Any], 
                       sandbox_analysis: Dict[str, Any],
                       file_info: Dict[str, Any]) -> Optional[AIScoringResult]:
        """
        Request AI scoring
        Endpoint: POST /score
        """
        try:
            url = f"{self.config.base_url}/score"
            
            request_data = AIScoringRequest(
                static_analysis=static_analysis,
                sandbox_analysis=sandbox_analysis,
                file_info=file_info
            )
            
            response = self.session.post(
                url,
                json=request_data.to_dict(),
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                result_data = response.json()
                logger.info(f"AI scoring completed: {result_data.get('ai_score')}/100")
                
                return AIScoringResult(
                    ai_score=result_data.get("ai_score", 0),
                    confidence=result_data.get("confidence", 0.0),
                    explanation=result_data.get("explanation", []),
                    feature_importance=result_data.get("feature_importance", {}),
                    model_version=result_data.get("model_version")
                )
            else:
                logger.error(f"AI scoring failed: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error(f"AI scoring timeout after {self.config.timeout}s")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling AI service: {e}")
            return None
    
    def health_check(self) -> bool:
        """
        Check if AI Service is healthy
        Endpoint: GET /health
        """
        try:
            url = f"{self.config.base_url}/health"
            response = self.session.get(url, timeout=5)
            return response.status_code == 200
        except:
            return False
