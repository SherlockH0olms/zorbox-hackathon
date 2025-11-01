#!/usr/bin/env python3
"""
Improved Orchestrator with proper error handling, async support, and integration
This version provides production-ready orchestration capabilities.
"""

import redis
import json
import time
import logging
from typing import Optional, Dict, Any
from datetime import datetime
from .schemas import AnalysisJob, JobState, FileInfo
from .config import Config, RedisConfig
from .integration_client import BackendClient, AIServiceClient
from .logger_config import setup_logging

# Setup logging
logger = logging.getLogger(__name__)


class OrchestratorError(Exception):
    """Custom exception for orchestrator errors"""
    pass


class JobNotFoundError(OrchestratorError):
    """Job not found in Redis"""
    pass


class Orchestrator:
    """
    Improved Orchestrator with:
    - Proper error handling and recovery
    - Backend integration
    - Health checks
    - Job state management
    - TTL management
    """
    
    def __init__(self, redis_config: Optional[RedisConfig] = None, 
                 backend_client: Optional[BackendClient] = None,
                 ai_client: Optional[AIServiceClient] = None):
        """
        Initialize orchestrator
        
        Args:
            redis_config: Redis configuration (uses config from environment if None)
            backend_client: Backend client (creates new if None)
            ai_client: AI service client (creates new if None)
        """
        self.config = Config.load()
        self.redis_config = redis_config or self.config.redis
        self.backend_client = backend_client or BackendClient(self.config.backend)
        self.ai_client = ai_client or AIServiceClient(self.config.ai_service)
        
        # Initialize Redis connection with retry logic
        self.redis = self._create_redis_connection()
        
        logger.info(f"Orchestrator initialized - Redis: {self.redis_config.host}:{self.redis_config.port}")
    
    def _create_redis_connection(self) -> redis.Redis:
        """Create Redis connection with proper error handling"""
        try:
            conn = redis.Redis(
                host=self.redis_config.host,
                port=self.redis_config.port,
                db=self.redis_config.db,
                password=self.redis_config.password,
                decode_responses=self.redis_config.decode_responses,
                socket_connect_timeout=self.redis_config.socket_connect_timeout,
                socket_timeout=self.redis_config.socket_timeout,
                retry_on_timeout=self.redis_config.retry_on_timeout
            )
            # Test connection
            conn.ping()
            logger.info("Redis connection established")
            return conn
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise OrchestratorError(f"Redis connection failed: {e}")
    
    def create_job(self, file_info: FileInfo) -> str:
        """
        Create a new analysis job
        
        Args:
            file_info: File information from Backend
            
        Returns:
            job_id: Unique job identifier
            
        Raises:
            OrchestratorError: If job creation fails
        """
        try:
            job_id = f"job_{int(time.time() * 1000)}_{file_info.file_id}"
            
            job = AnalysisJob(
                job_id=job_id,
                file_info=file_info,
                state=JobState.PENDING,
                progress_percentage=0,
                current_step="Job created"
            )
            
            # Store in Redis with TTL
            job_key = f"{self.config.orchestrator.job_prefix}{job_id}"
            self.redis.setex(
                job_key,
                self.config.orchestrator.job_ttl,
                json.dumps(job.to_dict())
            )
            
            # Add to job queue
            self.redis.lpush(self.config.orchestrator.job_queue_name, job_id)
            
            logger.info(f"Created job {job_id} for file {file_info.file_name}")
            
            # Notify backend
            try:
                self.backend_client.notify_job_status(job)
            except Exception as e:
                logger.warning(f"Failed to notify backend about job creation: {e}")
            
            return job_id
            
        except redis.RedisError as e:
            logger.error(f"Redis error creating job: {e}")
            raise OrchestratorError(f"Failed to create job: {e}")
        except Exception as e:
            logger.error(f"Unexpected error creating job: {e}")
            raise OrchestratorError(f"Job creation failed: {e}")
    
    def get_job(self, job_id: str) -> Optional[AnalysisJob]:
        """
        Get job by ID
        
        Args:
            job_id: Job identifier
            
        Returns:
            AnalysisJob or None if not found
        """
        try:
            job_key = f"{self.config.orchestrator.job_prefix}{job_id}"
            job_data = self.redis.get(job_key)
            
            if not job_data:
                return None
            
            return AnalysisJob.from_dict(json.loads(job_data))
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse job data for {job_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error getting job {job_id}: {e}")
            return None
    
    def update_job_state(self, job_id: str, state: JobState, 
                        progress_percentage: Optional[int] = None,
                        current_step: Optional[str] = None,
                        error_message: Optional[str] = None,
                        results: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update job state and optionally progress/step
        
        Args:
            job_id: Job identifier
            state: New job state
            progress_percentage: Progress percentage (0-100)
            current_step: Current processing step description
            error_message: Error message if state is FAILED
            results: Partial results to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            job = self.get_job(job_id)
            if not job:
                logger.warning(f"Job {job_id} not found for update")
                return False
            
            # Update job fields
            job.state = state
            job.updated_at = time.time()
            
            if progress_percentage is not None:
                job.progress_percentage = progress_percentage
            
            if current_step:
                job.current_step = current_step
            
            if error_message:
                job.error_message = error_message
            
            if results:
                # Update results based on state
                if state == JobState.STATIC_ANALYSIS and "static_analysis" in results:
                    from .schemas import StaticAnalysisResult
                    job.static_analysis = StaticAnalysisResult(**results["static_analysis"])
                
                if state == JobState.SANDBOX_ANALYSIS and "sandbox_results" in results:
                    from .schemas import SandboxAnalysisResult
                    for sandbox_type, result_data in results["sandbox_results"].items():
                        job.sandbox_results[sandbox_type] = SandboxAnalysisResult(**result_data)
            
            # Set timestamps
            if state == JobState.STATIC_ANALYSIS and not job.started_at:
                job.started_at = time.time()
            
            if state in [JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED]:
                job.completed_at = time.time()
            
            # Save to Redis
            job_key = f"{self.config.orchestrator.job_prefix}{job_id}"
            self.redis.setex(
                job_key,
                self.config.orchestrator.job_ttl,
                json.dumps(job.to_dict())
            )
            
            logger.info(f"Updated job {job_id}: {state.value} ({job.progress_percentage}%)")
            
            # Notify backend
            try:
                self.backend_client.notify_job_status(job)
            except Exception as e:
                logger.warning(f"Failed to notify backend: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating job {job_id}: {e}")
            return False
    
    def complete_job(self, job_id: str, final_results: Dict[str, Any]) -> bool:
        """
        Complete job with final results
        
        Args:
            job_id: Job identifier
            final_results: Complete analysis results
            
        Returns:
            True if successful
        """
        try:
            job = self.get_job(job_id)
            if not job:
                logger.error(f"Job {job_id} not found for completion")
                return False
            
            # Update final results
            job.final_risk_score = final_results.get("final_risk_score", 0)
            from .schemas import RiskLevel
            job.final_risk_level = RiskLevel(final_results.get("final_risk_level", "UNKNOWN"))
            
            if "ai_scoring" in final_results:
                from .schemas import AIScoringResult
                job.ai_scoring = AIScoringResult(**final_results["ai_scoring"])
            
            # Update state
            job.state = JobState.COMPLETED
            job.progress_percentage = 100
            job.completed_at = time.time()
            job.current_step = "Analysis completed"
            
            # Save
            job_key = f"{self.config.orchestrator.job_prefix}{job_id}"
            self.redis.setex(
                job_key,
                self.config.orchestrator.job_ttl,
                json.dumps(job.to_dict())
            )
            
            logger.info(f"Completed job {job_id} with risk score {job.final_risk_score}")
            
            # Notify backend with results
            try:
                self.backend_client.update_job_result(job)
            except Exception as e:
                logger.error(f"Failed to update backend with results: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error completing job {job_id}: {e}")
            return False
    
    def fail_job(self, job_id: str, error_message: str) -> bool:
        """
        Mark job as failed
        
        Args:
            job_id: Job identifier
            error_message: Error description
            
        Returns:
            True if successful
        """
        return self.update_job_state(
            job_id,
            JobState.FAILED,
            error_message=error_message,
            current_step=f"Failed: {error_message}"
        )
    
    def get_next_job(self) -> Optional[str]:
        """
        Get next job ID from queue (non-blocking)
        
        Returns:
            job_id or None if queue is empty
        """
        try:
            job_id = self.redis.rpop(self.config.orchestrator.job_queue_name)
            return job_id
        except Exception as e:
            logger.error(f"Error getting next job from queue: {e}")
            return None
    
    def requeue_job(self, job_id: str) -> bool:
        """
        Requeue a job (for retry scenarios)
        
        Args:
            job_id: Job identifier
            
        Returns:
            True if successful
        """
        try:
            self.redis.lpush(self.config.orchestrator.job_queue_name, job_id)
            logger.info(f"Requeued job {job_id}")
            return True
        except Exception as e:
            logger.error(f"Error requeueing job {job_id}: {e}")
            return False
    
    def health_check(self) -> Dict[str, bool]:
        """
        Perform health checks on all dependencies
        
        Returns:
            Dictionary with health status of each component
        """
        health = {
            "redis": False,
            "backend": False,
            "ai_service": False
        }
        
        # Check Redis
        try:
            self.redis.ping()
            health["redis"] = True
        except:
            health["redis"] = False
        
        # Check Backend
        health["backend"] = self.backend_client.health_check()
        
        # Check AI Service
        health["ai_service"] = self.ai_client.health_check()
        
        return health
