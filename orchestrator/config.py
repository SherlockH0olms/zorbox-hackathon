#!/usr/bin/env python3
"""
Configuration management for ZORBOX Orchestrator
All configuration values are externalized and can be set via environment variables.
"""

import os
from typing import Optional
from dataclasses import dataclass


@dataclass
class RedisConfig:
    """Redis configuration"""
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    decode_responses: bool = True
    socket_connect_timeout: int = 5
    socket_timeout: int = 5
    retry_on_timeout: bool = True
    
    @classmethod
    def from_env(cls) -> 'RedisConfig':
        """Load from environment variables"""
        return cls(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=int(os.getenv("REDIS_DB", "0")),
            password=os.getenv("REDIS_PASSWORD"),
            decode_responses=True,
            socket_connect_timeout=int(os.getenv("REDIS_CONNECT_TIMEOUT", "5")),
            socket_timeout=int(os.getenv("REDIS_SOCKET_TIMEOUT", "5")),
            retry_on_timeout=True
        )


@dataclass
class BackendConfig:
    """Backend API configuration"""
    base_url: str = "http://backend:8080"
    api_key: Optional[str] = None
    timeout: int = 30
    retry_attempts: int = 3
    retry_delay: int = 2  # seconds
    
    @classmethod
    def from_env(cls) -> 'BackendConfig':
        """Load from environment variables"""
        return cls(
            base_url=os.getenv("BACKEND_API_URL", "http://backend:8080"),
            api_key=os.getenv("BACKEND_API_KEY"),
            timeout=int(os.getenv("BACKEND_API_TIMEOUT", "30")),
            retry_attempts=int(os.getenv("BACKEND_RETRY_ATTEMPTS", "3")),
            retry_delay=int(os.getenv("BACKEND_RETRY_DELAY", "2"))
        )


@dataclass
class AIServiceConfig:
    """AI Service configuration"""
    base_url: str = "http://ai-service:5000"
    timeout: int = 60
    retry_attempts: int = 3
    retry_delay: int = 2
    
    @classmethod
    def from_env(cls) -> 'AIServiceConfig':
        """Load from environment variables"""
        return cls(
            base_url=os.getenv("AI_SERVICE_URL", "http://ai-service:5000"),
            timeout=int(os.getenv("AI_SERVICE_TIMEOUT", "60")),
            retry_attempts=int(os.getenv("AI_SERVICE_RETRY_ATTEMPTS", "3")),
            retry_delay=int(os.getenv("AI_SERVICE_RETRY_DELAY", "2"))
        )


@dataclass
class SandboxConfig:
    """Sandbox configuration"""
    strelka_enabled: bool = True
    native_engine_enabled: bool = True
    cuckoo_enabled: bool = False  # Resource intensive
    cape_enabled: bool = False
    
    strelka_timeout: int = 60
    native_engine_timeout: int = 120
    cuckoo_timeout: int = 600  # 10 minutes
    cape_timeout: int = 600
    
    cuckoo_api_url: str = "http://cuckoo-api:8090"
    cape_api_url: str = "http://cape:8000"
    
    @classmethod
    def from_env(cls) -> 'SandboxConfig':
        """Load from environment variables"""
        return cls(
            strelka_enabled=os.getenv("STRELKA_ENABLED", "true").lower() == "true",
            native_engine_enabled=os.getenv("NATIVE_ENGINE_ENABLED", "true").lower() == "true",
            cuckoo_enabled=os.getenv("CUCKOO_ENABLED", "false").lower() == "true",
            cape_enabled=os.getenv("CAPE_ENABLED", "false").lower() == "true",
            strelka_timeout=int(os.getenv("STRELKA_TIMEOUT", "60")),
            native_engine_timeout=int(os.getenv("NATIVE_ENGINE_TIMEOUT", "120")),
            cuckoo_timeout=int(os.getenv("CUCKOO_TIMEOUT", "600")),
            cape_timeout=int(os.getenv("CAPE_TIMEOUT", "600")),
            cuckoo_api_url=os.getenv("CUCKOO_API_URL", "http://cuckoo-api:8090"),
            cape_api_url=os.getenv("CAPE_API_URL", "http://cape:8000")
        )


@dataclass
class OrchestratorConfig:
    """Main orchestrator configuration"""
    max_workers: int = 4
    job_queue_name: str = "job_queue"
    job_prefix: str = "job:"
    result_prefix: str = "result:"
    health_check_interval: int = 30  # seconds
    job_ttl: int = 86400  # 24 hours in seconds
    
    # Analysis configuration
    parallel_sandbox_analysis: bool = True
    require_all_sandboxes: bool = False  # If False, continue even if some fail
    
    @classmethod
    def from_env(cls) -> 'OrchestratorConfig':
        """Load from environment variables"""
        return cls(
            max_workers=int(os.getenv("ORCHESTRATOR_MAX_WORKERS", "4")),
            job_queue_name=os.getenv("JOB_QUEUE_NAME", "job_queue"),
            job_prefix=os.getenv("JOB_PREFIX", "job:"),
            result_prefix=os.getenv("RESULT_PREFIX", "result:"),
            health_check_interval=int(os.getenv("HEALTH_CHECK_INTERVAL", "30")),
            job_ttl=int(os.getenv("JOB_TTL", "86400")),
            parallel_sandbox_analysis=os.getenv("PARALLEL_SANDBOX_ANALYSIS", "true").lower() == "true",
            require_all_sandboxes=os.getenv("REQUIRE_ALL_SANDBOXES", "false").lower() == "true"
        )


class Config:
    """Main configuration class"""
    def __init__(self):
        self.redis = RedisConfig.from_env()
        self.backend = BackendConfig.from_env()
        self.ai_service = AIServiceConfig.from_env()
        self.sandbox = SandboxConfig.from_env()
        self.orchestrator = OrchestratorConfig.from_env()
    
    @classmethod
    def load(cls) -> 'Config':
        """Load configuration from environment"""
        return cls()


# Global configuration instance
config = Config.load()
