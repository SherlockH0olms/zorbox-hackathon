#!/usr/bin/env python3
import redis
import json
import time
from enum import Enum

class JobState(Enum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    STATIC_ANALYSIS = "static_analysis"
    SANDBOX_ANALYSIS = "sandbox_analysis"
    AI_SCORING = "ai_scoring"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"

class Orchestrator:
    def __init__(self, redis_host='localhost', redis_port=6379):
        self.redis = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
    
    def create_job(self, file_info):
        """Yeni analiz job-u yarat"""
        job_id = f"job_{int(time.time() * 1000)}"
        job_data = {
            "job_id": job_id,
            "state": JobState.PENDING.value,
            "file_info": file_info,
            "created_at": time.time(),
            "results": {}
        }
        
        # Redise elave zad eledik
        self.redis.set(f"job:{job_id}", json.dumps(job_data))
        self.redis.lpush("job_queue", job_id)
        
        return job_id
    
    def update_job_state(self, job_id, state, results=None):
        """Job state-i yenilə"""
        job_data = json.loads(self.redis.get(f"job:{job_id}"))
        job_data["state"] = state.value
        job_data["updated_at"] = time.time()
        
        if results:
            job_data["results"].update(results)
        
        self.redis.set(f"job:{job_id}", json.dumps(job_data))
    
    def get_job(self, job_id):
        """Job məlumatını al"""
        job_data = self.redis.get(f"job:{job_id}")
        return json.loads(job_data) if job_data else None